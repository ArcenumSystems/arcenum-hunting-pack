# F5 WAF Hunts (Cortex XQL)

Hunts for web exploit scanning and exploitation attempts using F5 ASM / Advanced WAF logs ingested into Cortex.

> **Status:** Unvalidated. F5 syslog is usually `key="value"` (`ip_client`, `uri`, `response_code`, `request_status`, `attack_type`), but key names depend on the logging profile. Run `| limit 3` and read a real `_raw_log` before relying on any regex. If columns come back blank, the log is probably CSV or JSON and the regex needs adjusting.

## Placeholders
| Placeholder | Meaning |
|---|---|
| `<F5_DATASET>` | Your F5 dataset (Dataset Management, search `f5`). Cortex dataset names use underscores, for example `f5_f5_raw` |
| `<CLIENT_IP>` | Client IP under investigation |

## Behind a CDN or proxy
If a CDN or reverse proxy sits in front of the WAF, `ip_client` is the proxy address and the real client is in the `X-Forwarded-For` field. When a filter on the alerting client IP returns 0 rows, filter on the proxy IP or on the scanner path instead, and read the XFF value.

---

## WAF-01. Client IP summary and verdict
**MITRE:** T1190 Exploit Public-Facing Application
**Description:** Summarizes everything one client did and decides whether the scan was rejected or reached something real. Escalates on any non-404 response to a scanner path, any 5xx, or any POST.
```
config timeframe = 7d
| dataset = <F5_DATASET>
| filter _raw_log contains "<CLIENT_IP>"
| alter uri = arrayindex(regextract(_raw_log, "uri=\"([^\"]*)\""), 0),
        status = arrayindex(regextract(_raw_log, "response_code=\"(\d+)\""), 0),
        method = arrayindex(regextract(_raw_log, "method=\"([A-Z]+)\""), 0),
        rstatus = arrayindex(regextract(_raw_log, "request_status=\"(\w+)\""), 0),
        attack = arrayindex(regextract(_raw_log, "attack_type=\"([^\"]*)\""), 0)
| alter sus = if(uri contains "phpunit" or uri contains "eval-stdin" or uri contains ".env" or uri contains ".git" or uri contains "cgi-bin", 1, 0)
| alter sus_ok = if(sus = 1 and status in ("200", "201", "202", "204", "301", "302"), 1, 0),
        srv_err = if(status in ("500", "502", "503"), 1, 0),
        is_post = if(method = "POST", 1, 0),
        blocked = if(rstatus = "blocked", 1, 0)
| comp count() as requests, count_distinct(uri) as paths, sum(sus) as scanner_paths, sum(sus_ok) as scanner_success, sum(srv_err) as server_errors, sum(is_post) as posts, sum(blocked) as waf_blocked, values(status) as statuses, values(attack) as attack_types, min(_time) as first_seen, max(_time) as last_seen
| alter verdict = if(scanner_success > 0 or server_errors > 0 or posts > 0, "ESCALATE - non-404, 5xx or POST", "BENIGN SCAN - all rejected or 404")
```

## WAF-02. Request timeline for one client
```
config timeframe = 7d
| dataset = <F5_DATASET>
| filter _raw_log contains "<CLIENT_IP>"
| alter uri = arrayindex(regextract(_raw_log, "uri=\"([^\"]*)\""), 0),
        status = arrayindex(regextract(_raw_log, "response_code=\"(\d+)\""), 0),
        method = arrayindex(regextract(_raw_log, "method=\"([A-Z]+)\""), 0),
        rstatus = arrayindex(regextract(_raw_log, "request_status=\"(\w+)\""), 0)
| fields _time, method, uri, status, rstatus
| sort asc _time
| limit 200
```
Look for: which paths were tried, any `200` or `5xx`, any `POST`, and whether the user agent stays constant.

## WAF-03. Campaign scope: every client sending the same scan
```
config timeframe = 7d
| dataset = <F5_DATASET>
| filter _raw_log contains "eval-stdin" or _raw_log contains "/vendor/phpunit"
| alter cip = arrayindex(regextract(_raw_log, "ip_client=\"([\d\.]+)\""), 0),
        status = arrayindex(regextract(_raw_log, "response_code=\"(\d+)\""), 0),
        rstatus = arrayindex(regextract(_raw_log, "request_status=\"(\w+)\""), 0)
| comp count() as requests, values(status) as statuses, values(rstatus) as waf_action, min(_time) as first_seen, max(_time) as last_seen by cip
| sort desc requests
```

## Reading the results

| Result | Meaning |
|---|---|
| All `404` or `blocked`, no POST, no 5xx | Opportunistic scan, exploit failed. Block the IP, close with notes |
| Scanner path returned `200` | Escalate. The file or path exists. Notify the backend owner immediately |
| `POST` or `5xx` | Escalate. Payload may have executed. Check the backend host for process spawns (php to sh, curl or wget) |
| Many clients, same path | Botnet-wide scanning, not targeted. Still block |

## Context checks outside the query
- Is the WAF in detection or prevention mode? In detection mode the request reaches the backend, and a 404 is the backend's answer.
- Does the scanned path exist on the backend? If a dev dependency such as `/vendor/phpunit` is deployed to production, that is a separate finding even when the scan failed.
- Scanner alerts often carry a wrong MITRE mapping. Exploit attempts against public apps belong to **T1190**, not T1048.
- The scanner string in the user-agent field (for example `libredtail-http`) is a user agent, not a username.

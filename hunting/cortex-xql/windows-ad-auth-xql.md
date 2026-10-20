# Windows / Active Directory Authentication Hunts (Cortex XQL)

Hunts for brute force, password spray, credential stuffing and stale-credential noise using Domain Controller events.

> **Status:** Not validated against a production tenant. Run `| limit 3` first and inspect `action_evtlog_message` to confirm the regex patterns match your event format.

## Placeholders
| Placeholder | Meaning |
|---|---|
| `<SOURCE_IP>` | Source IP or host under investigation |
| `<USERNAME>` | SamAccountName under investigation |

## XQL gotchas (learned the hard way)
- `regextract()` returns an **array**. Wrap it: `arrayindex(regextract(...), 0)`, otherwise `coalesce()` and comparisons fail with "Expected string but received array".
- Enum filters need the prefix: `event_type = ENUM.EVENT_LOG`. Without `ENUM.` the filter can silently return 0 rows.
- Zero results do not mean "nothing happened". Confirm the Domain Controller logs are ingested into the dataset first.

## Event IDs

| Event ID | Meaning |
|---|---|
| 4771 | Kerberos pre-authentication failed (`0x18` = bad password, `0x6` = unknown user) |
| 4776 | NTLM credential validation (failure code `0xC000006A` bad password, `0xC0000064` unknown user) |
| 4625 | Logon failure |
| 4624 | Logon success |
| 4740 | Account locked out |
| 4648 / 4672 | Explicit credentials / special privileges assigned |

---

## AD-01. Source IP verdict: brute force, spray, stuffing or stale credential
**MITRE:** T1110.001, T1110.003, T1110.004
**Description:** Aggregates by source IP, then classifies using user count, failures per user, and the share of nonexistent usernames. IP-agnostic: no IP input needed.
**Verdict logic**

| Pattern | Verdict |
|---|---|
| 5+ users, mostly nonexistent usernames | Credential stuffing |
| 5+ users, few tries each | Password spray |
| 5+ users, other | Multi-user failures, review |
| 1 to 4 users, high failures, successes present | Single-source failures with success: stale credential/automation or brute force, verify with AD-03 |
| 1 to 4 users, high failures, no success | Brute force or stale credential |
| Below thresholds | Low (below threshold, not proof of benign) |

```
config timeframe = 3d
| dataset = xdr_data
| filter event_type = ENUM.EVENT_LOG and action_evtlog_event_id in (4771, 4776, 4624, 4740)
| alter eid = action_evtlog_event_id,
        usr = if(action_evtlog_event_id = 4624, arrayindex(regextract(action_evtlog_message, "New Logon:[\s\S]*?Account Name:\s+(\S+)"), 0), arrayindex(regextract(action_evtlog_message, "(?:Account Name|Logon Account):\s+(\S+)"), 0)),
        src_ip = arrayindex(regextract(action_evtlog_message, "(?:Client Address|Source Network Address):\s+(?:::ffff:)?([\d\.]+)"), 0),
        code = lowercase(arrayindex(regextract(action_evtlog_message, "(?:Failure Code|Error Code|Status):\s+(0x[0-9A-Fa-f]+)"), 0)),
        ts = to_epoch(_time, "SECONDS")
| filter src_ip != null and src_ip != "" and src_ip != "-" and src_ip != "::1" and src_ip != "127.0.0.1"
| filter usr != null and usr != "-"
| alter fail = if(eid in (4771, 4776), 1, 0), ok = if(eid = 4624, 1, 0), lockout = if(eid = 4740, 1, 0),
        badpw = if(code in ("0x18", "0xc000006a"), 1, 0), nouser = if(code in ("0x6", "0xc0000064"), 1, 0)
| comp sum(fail) as fails, sum(ok) as success, sum(lockout) as lockouts, sum(badpw) as badpw, sum(nouser) as nouser, min(ts) as t0, max(ts) as t1 by src_ip, usr
| comp count_distinct(usr) as users, sum(fails) as total_fails, sum(success) as total_success, sum(lockouts) as total_lockouts, sum(badpw) as total_badpw, sum(nouser) as total_nouser, max(fails) as max_per_user, min(t0) as t0, max(t1) as t1, values(usr) as user_list by src_ip
| alter duration_sec = subtract(t1, t0)
| alter avg_per_user = divide(total_fails, users), nouser_ratio = divide(total_nouser, add(total_fails, 1)), fails_per_min = divide(total_fails, divide(add(duration_sec, 60), 60))
| alter verdict = if(users >= 5 and nouser_ratio >= 0.5, "CREDENTIAL STUFFING",
                  if(users >= 5 and avg_per_user <= 5, "PASSWORD SPRAY",
                  if(users >= 5 and total_fails >= 10, "MULTI-USER FAILURES - REVIEW",
                  if(users <= 4 and total_fails >= 20 and total_success > 0, "SINGLE-SOURCE FAILURES WITH SUCCESS - VERIFY STALE CRED VS BRUTE FORCE",
                  if(users <= 4 and total_fails >= 20, "BRUTE FORCE OR STALE CREDENTIAL - NO SUCCESS", "LOW (below threshold)")))))
| filter total_fails > 0
| sort desc total_fails
| limit 100
```

**Reading the output**
- `max_per_user` close to `total_fails`: failures concentrated on one account (not a spray).
- `total_nouser = 0`: no nonexistent usernames, which argues against stuffing.
- `fails_per_min` low and steady over days: machine retry (stale credential). Very high in a short burst: attack tool.
- `total_lockouts = 0` with thousands of failures: account is exempt from lockout policy (common for service accounts). Verify, do not assume.
- Thousands of successes alongside failures: a job or service is alternating between old and new credentials. Strongly points to stale credential.

---

## AD-02. Failure/success sequence per user (classic vs interleaved)
**Description:** Tells whether all failures came before the first success (guess then hit), success came first, or both are mixed (automation retrying).
```
config timeframe = 3d
| dataset = xdr_data
| filter event_type = ENUM.EVENT_LOG and action_evtlog_event_id in (4771, 4776, 4624)
| filter action_evtlog_message contains "<SOURCE_IP>"
| alter eid = action_evtlog_event_id,
        usr = if(action_evtlog_event_id = 4624, arrayindex(regextract(action_evtlog_message, "New Logon:[\s\S]*?Account Name:\s+(\S+)"), 0), arrayindex(regextract(action_evtlog_message, "(?:Account Name|Logon Account):\s+(\S+)"), 0)),
        ts = to_epoch(_time, "SECONDS")
| alter is_fail = if(eid in (4771, 4776), 1, 0), is_ok = if(eid = 4624, 1, 0)
| alter fail_ts_min = if(is_fail = 1, ts, 9999999999), fail_ts_max = if(is_fail = 1, ts, 0), ok_ts_min = if(is_ok = 1, ts, 9999999999), ok_ts_max = if(is_ok = 1, ts, 0)
| comp sum(is_fail) as fails, sum(is_ok) as success, min(fail_ts_min) as first_fail, max(fail_ts_max) as last_fail, min(ok_ts_min) as first_success, max(ok_ts_max) as last_success by usr
| alter pattern = if(fails = 0, "NO FAILURES",
                 if(success = 0, "FAILURES ONLY, NO SUCCESS",
                 if(last_fail < first_success, "CLASSIC: ALL FAILURES THEN SUCCESS",
                 if(first_success < first_fail, "SUCCESS FIRST, THEN FAILURES",
                 "INTERLEAVED: FAILURE AND SUCCESS MIXED"))))
| sort desc fails
```

| Pattern | Interpretation |
|---|---|
| Classic: all failures then success | Credential guessed. Highest concern, check post-logon activity |
| Interleaved | Automation or two processes with different credentials. Typical stale credential |
| Success first, then failures | Password changed, old session or cached credential now failing |
| Failures only | Brute force or misconfiguration |

---

## AD-03. Which process on the source host is authenticating
**Description:** Identifies what is generating the authentication traffic. This is the most decisive check for stale credentials versus attack tooling. Requires a Cortex agent on the source host.
```
config timeframe = 3d
| dataset = xdr_data
| filter event_type = ENUM.NETWORK and action_local_ip = "<SOURCE_IP>" and action_remote_port in (88, 389, 445)
| comp count() as hits, min(_time) as first_seen by agent_hostname, actor_effective_username, actor_process_image_name, actor_process_command_line
| sort desc hits
```
- Normal service, scheduled task, build agent, mapped drive, mail client: stale credential.
- `powershell`, `python`, `kerbrute`, `hydra`, `crackmapexec` or unknown binaries: investigate as an attack.
- No agent on that host: the host is unmanaged, which is a finding in itself.

---

## AD-04. Per-user, per-event breakdown for one source
**Description:** Shows which accounts, event IDs and Domain Controllers are involved.
```
config timeframe = 3d
| dataset = xdr_data
| filter event_type = ENUM.EVENT_LOG and action_evtlog_event_id in (4771, 4776, 4624, 4740)
| filter action_evtlog_message contains "<SOURCE_IP>"
| alter eid = action_evtlog_event_id,
        usr = if(action_evtlog_event_id = 4624, arrayindex(regextract(action_evtlog_message, "New Logon:[\s\S]*?Account Name:\s+(\S+)"), 0), arrayindex(regextract(action_evtlog_message, "(?:Account Name|Logon Account):\s+(\S+)"), 0))
| comp count() as events, min(_time) as first_seen, max(_time) as last_seen by usr, eid, agent_hostname
| sort desc events
```

---

## AD-05. Post-logon activity for an account (lateral movement check)
```
config timeframe = 3d
| dataset = xdr_data
| filter event_type = ENUM.EVENT_LOG and action_evtlog_event_id in (4624, 4648, 4672, 4768, 4769)
| filter action_evtlog_message contains "<USERNAME>"
| alter src_ip = arrayindex(regextract(action_evtlog_message, "(?:Client Address|Source Network Address):\s+(?:::ffff:)?([\d\.]+)"), 0)
| comp count() as events, min(_time) as first_seen, max(_time) as last_seen by action_evtlog_event_id, src_ip, agent_hostname
| sort asc first_seen
```
Logons from new hosts, `4648` (explicit credentials) or `4672` (privileged) after a failure burst indicate compromise.

---

## Decision guide

| Evidence | Verdict |
|---|---|
| Spray or stuffing verdict, or success followed by new-host logons | Malicious, escalate |
| Single account, steady low-rate failures, normal process in AD-03, recent password change | Stale credential, benign |
| Classic failures-then-success with unknown source process | Treat as compromise until disproven |
| Source host unmanaged or unknown | Finding on its own, identify the owner |

## Tuning
- Thresholds (`users >= 5`, `total_fails >= 20`) assume a mid-size AD environment.
- Exclude known service accounts only after confirming each one with its owner.
- Convert local time to UTC before setting time windows.

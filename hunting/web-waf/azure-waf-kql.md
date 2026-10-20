# Azure Application Gateway WAF Hunts (Sentinel / Log Analytics KQL)

> **Status:** Unvalidated. Field names (`requestUri_s`, `httpStatus_d`, `userAgent_s`, `clientIP_s`) belong to the legacy `AzureDiagnostics` schema. In resource-specific mode the table is `AGWAccessLogs` with columns `ClientIp`, `RequestUri`, `HttpStatus`, `HttpMethod`, `UserAgent`. Confirm with `| take 10`.

## AZ-01. Scanner activity by client IP
**MITRE:** T1190
```kql
AzureDiagnostics
| where TimeGenerated > ago(7d)
| where Category == "ApplicationGatewayAccessLog"
| where requestUri_s has_any ("eval-stdin.php", "/vendor/phpunit", "/.env", "/wp-login.php", "/cgi-bin", "/.git/")
     or userAgent_s has_any ("libredtail", "zgrab", "masscan", "nikto")
| summarize Requests = count(), Paths = make_set(requestUri_s, 10),
            Statuses = make_set(httpStatus_d) by clientIP_s
| order by Requests desc
```

## AZ-02. Scanner requests that were not rejected (escalate these)
```kql
AzureDiagnostics
| where TimeGenerated > ago(7d)
| where Category == "ApplicationGatewayAccessLog"
| where requestUri_s has_any ("eval-stdin.php", "/vendor/phpunit", "/.env", "/.git/")
| where httpStatus_d in (200, 500, 502)
| project TimeGenerated, clientIP_s, httpMethod_s, requestUri_s, httpStatus_d, userAgent_s
```

## AZ-03. Full request history for one client
```kql
AzureDiagnostics
| where TimeGenerated > ago(7d)
| where Category == "ApplicationGatewayAccessLog"
| where clientIP_s == "<CLIENT_IP>"
| project TimeGenerated, clientIP_s, httpMethod_s, requestUri_s, httpStatus_d, userAgent_s
| order by TimeGenerated asc
```

## Interpretation
Same decision table as `f5-waf-xql.md`: all 404 or blocked is a failed opportunistic scan, a 200 on a scanner path or any POST or 5xx is an escalation.

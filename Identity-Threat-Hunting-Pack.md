# Arcenum Identity & Web Threat Hunting Pack

Hunting queries for Microsoft Entra ID, Microsoft 365 and Azure WAF, ordered from basic to advanced.
Primary language: **Sentinel KQL**. Cortex **XQL** equivalents for the core hunts are at the end.

> **Status:** Queries are written from standard Microsoft table schemas and have **not been run against a live tenant**. Validate field names (`limit 10`) and tune thresholds before using in production or delivering to a client.

## Data sources

| Source | Sentinel table | Notes |
|---|---|---|
| Entra interactive sign-ins | `SigninLogs` | Most hunts start here |
| Entra non-interactive sign-ins | `AADNonInteractiveUserSignInLogs` | Token and session activity; often not ingested by default |
| Entra audit | `AuditLogs` | MFA changes, app consent, role changes |
| Exchange / M365 audit | `OfficeActivity` | Inbox rules, mailbox access |
| Azure Application Gateway WAF | `AzureDiagnostics` | `Category == "ApplicationGatewayAccessLog"` |

## Key Entra result codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 50126 | Wrong password |
| 50034 | User does not exist (enumeration / spray) |
| 50053 | Account locked |
| 50074 / 50076 / 500121 | MFA required / MFA failed |
| 70043 | Refresh token rejected by sign-in frequency policy (possible token replay) |
| 50057 | Account disabled |

---

# LEVEL 1: BASIC

## H01. Password spray from a single IP
**MITRE:** T1110.003 Password Spraying
**Description:** One source IP failing against many distinct accounts. Spray keeps attempts per user low to avoid lockout, so detect by distinct users, not volume per user.
**False positives:** Corporate NAT/VPN egress IPs (hundreds of users, normal typos). Mitigated by H06, which needs no allowlist.
```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType in ("50126", "50034")
| summarize Users = dcount(UserPrincipalName), Attempts = count(),
            FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
            by IPAddress, AutonomousSystemNumber
| where Users >= 5 and Attempts >= 10
| order by Users desc
```

## H02. Brute force against a single account
**MITRE:** T1110.001 Password Guessing
**Description:** Many password failures against one user.
```kql
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType in ("50126", "50053")
| summarize Failures = count(), IPs = make_set(IPAddress, 10) by UserPrincipalName
| where Failures >= 10
| order by Failures desc
```

## H03. Success after failures (same user and IP)
**MITRE:** T1078.004 Valid Accounts: Cloud Accounts
**Description:** Password failures followed by a success from the same IP. The strongest simple indicator of a guessed credential.
**False positives:** A user mistyping their own password. Prioritize rows with unmanaged device, new IP or foreign country.
```kql
let lookback = 7d;
let Fails = SigninLogs
    | where TimeGenerated > ago(lookback)
    | where ResultType in ("50126", "50053")
    | summarize FailCount = count(), FirstFail = min(TimeGenerated) by UserPrincipalName, IPAddress;
let Success = SigninLogs
    | where TimeGenerated > ago(lookback)
    | where ResultType == "0"
    | summarize SuccessTime = min(TimeGenerated), Apps = make_set(AppDisplayName, 10),
                DeviceIds = make_set(tostring(DeviceDetail.deviceId), 5),
                OS = make_set(tostring(DeviceDetail.operatingSystem), 5)
                by UserPrincipalName, IPAddress;
Fails
| join kind=inner Success on UserPrincipalName, IPAddress
| where SuccessTime > FirstFail
| project UserPrincipalName, IPAddress, FailCount, FirstFail, SuccessTime, Apps, DeviceIds, OS
| order by FailCount desc
```

## H04. Username enumeration
**MITRE:** T1589.002 Gather Victim Identity Information: Email Addresses
**Description:** Code 50034 means the account does not exist. Employees rarely mistype their own username, so repeated 50034 from one IP is almost always an attacker working a list.
```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == "50034"
| summarize NonExistentUsers = dcount(UserPrincipalName), Sample = make_set(UserPrincipalName, 5) by IPAddress
| where NonExistentUsers >= 3
| order by NonExistentUsers desc
```

## H05. Legacy authentication sign-ins
**MITRE:** T1078.004
**Description:** IMAP/POP/SMTP/EWS and other legacy protocols bypass MFA. Successful legacy auth is a high-value finding in itself.
```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where ClientAppUsed in ("IMAP4", "POP3", "SMTP", "Exchange ActiveSync", "Exchange Web Services", "Other clients", "Authenticated SMTP")
| summarize Attempts = count(), Success = countif(ResultType == "0"), IPs = dcount(IPAddress)
            by UserPrincipalName, ClientAppUsed
| order by Success desc
```

---

# LEVEL 2: INTERMEDIATE

## H06. New (user, IP) pair, no corporate IP allowlist needed
**MITRE:** T1078.004
**Description:** Builds a 30-day baseline of IPs each user normally signs in from, then shows successful sign-ins from IPs outside that baseline in the last 7 days. Corporate/VPN IPs drop out automatically because every employee has used them before. Unmanaged device is flagged.
**False positives:** Travel, new ISP, mobile networks, new joiners.
```kql
let baseline = SigninLogs
    | where TimeGenerated between (ago(30d) .. ago(7d))
    | where ResultType == "0"
    | summarize by UserPrincipalName, IPAddress;
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == "0"
| join kind=leftanti baseline on UserPrincipalName, IPAddress
| extend DeviceId = tostring(DeviceDetail.deviceId),
         OS = tostring(DeviceDetail.operatingSystem),
         Country = tostring(LocationDetails.countryOrRegion)
| summarize FirstSeen = min(TimeGenerated), Events = count(), Apps = make_set(AppDisplayName, 5)
            by UserPrincipalName, IPAddress, Country, DeviceId, OS
| extend DeviceStatus = iff(DeviceId == "", "UNMANAGED", "managed")
| order by FirstSeen desc
```

## H07. New country for a user
**MITRE:** T1078.004
**Description:** Successful sign-in from a country the user has not used in the previous 30 days.
```kql
let baseline = SigninLogs
    | where TimeGenerated between (ago(30d) .. ago(2d))
    | where ResultType == "0"
    | summarize KnownCountries = make_set(tostring(LocationDetails.countryOrRegion)) by UserPrincipalName;
SigninLogs
| where TimeGenerated > ago(2d)
| where ResultType == "0"
| extend Country = tostring(LocationDetails.countryOrRegion)
| join kind=inner baseline on UserPrincipalName
| where not(set_has_element(KnownCountries, Country))
| project TimeGenerated, UserPrincipalName, IPAddress, Country, KnownCountries, AppDisplayName
```

## H08. MFA fatigue
**MITRE:** T1621 Multi-Factor Authentication Request Generation
**Description:** Many MFA prompts or failures for one user in a short window, often followed by a success after the user finally approves.
```kql
SigninLogs
| where TimeGenerated > ago(2d)
| where ResultType in ("500121", "50074", "50076") or ResultType == "0"
| summarize MFAPrompts = countif(ResultType in ("500121", "50074", "50076")),
            Successes = countif(ResultType == "0"),
            IPs = make_set(IPAddress, 5)
            by UserPrincipalName, bin(TimeGenerated, 1h)
| where MFAPrompts >= 5
| order by MFAPrompts desc
```

## H09. Token replay: 70043 and non-interactive anomalies
**MITRE:** T1528 Steal Application Access Token, T1550.004 Web Session Cookie
**Description:** 70043 means a refresh token was presented but rejected by sign-in frequency. The token existed, so a prior authentication happened somewhere. Second query finds non-interactive successes from IPs that never signed in interactively for that user.
```kql
// A) Rejected token presentations
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(14d)
| where ResultType == "70043"
| summarize Events = count(), FirstSeen = min(TimeGenerated) by UserPrincipalName, IPAddress
| order by Events desc
```
```kql
// B) Non-interactive success from an IP not seen interactively for the user
let interactive = SigninLogs
    | where TimeGenerated > ago(30d) | where ResultType == "0"
    | summarize by UserPrincipalName, IPAddress;
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(7d)
| where ResultType == "0"
| join kind=leftanti interactive on UserPrincipalName, IPAddress
| summarize Events = count(), Apps = make_set(AppDisplayName, 5) by UserPrincipalName, IPAddress
| order by Events desc
```

## H10. Unmanaged device for a user who normally uses a managed one
**MITRE:** T1078.004
**Description:** User historically signs in from a registered device, but a recent success has no device ID.
```kql
let managedUsers = SigninLogs
    | where TimeGenerated between (ago(30d) .. ago(2d))
    | where ResultType == "0"
    | summarize ManagedRatio = countif(tostring(DeviceDetail.deviceId) != "") * 1.0 / count() by UserPrincipalName
    | where ManagedRatio > 0.9;
SigninLogs
| where TimeGenerated > ago(2d)
| where ResultType == "0" and tostring(DeviceDetail.deviceId) == ""
| join kind=inner managedUsers on UserPrincipalName
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, ClientAppUsed,
          OS = tostring(DeviceDetail.operatingSystem), Country = tostring(LocationDetails.countryOrRegion)
```

## H11. Impossible travel (simple form)
**MITRE:** T1078.004
**Description:** Successful sign-ins from more than one country within the same hour.
**False positives:** VPN and proxy users. Exclude known egress countries.
```kql
SigninLogs
| where TimeGenerated > ago(2d)
| where ResultType == "0"
| extend Country = tostring(LocationDetails.countryOrRegion)
| summarize Countries = make_set(Country), CountryCount = dcount(Country), IPs = make_set(IPAddress, 5)
            by UserPrincipalName, bin(TimeGenerated, 1h)
| where CountryCount > 1
```

---

# LEVEL 3: ADVANCED

## H12. Security info (MFA method) registered after a risky sign-in
**MITRE:** T1098.005 Account Manipulation: Device Registration
**Description:** Attackers register their own MFA method to keep access after a password reset. Joins new-IP sign-ins with MFA registrations from the same IP.
```kql
let newIPSignins = SigninLogs
    | where TimeGenerated > ago(7d) | where ResultType == "0"
    | project SigninTime = TimeGenerated, UserPrincipalName, IPAddress;
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName in ("User registered security info", "Admin registered security info", "User deleted security info")
| extend UserPrincipalName = tostring(TargetResources[0].userPrincipalName),
         IPAddress = tostring(InitiatedBy.user.ipAddress)
| join kind=inner newIPSignins on UserPrincipalName, IPAddress
| project TimeGenerated, UserPrincipalName, IPAddress, OperationName, SigninTime
```

## H13. Suspicious inbox rules (BEC persistence)
**MITRE:** T1114.003 Email Forwarding Rule
**Description:** Forwarding, redirecting or deleting rules created in a mailbox. Classic business email compromise persistence and evidence hiding.
```kql
OfficeActivity
| where TimeGenerated > ago(14d)
| where Operation in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
| where Parameters has_any ("ForwardTo", "RedirectTo", "ForwardAsAttachmentTo", "DeleteMessage", "MoveToFolder")
| project TimeGenerated, UserId, ClientIP, Operation, Parameters
```

## H14. Risky OAuth application consent
**MITRE:** T1528
**Description:** User or admin granted an app broad mail or file permissions. Gives persistent access that survives password reset.
```kql
AuditLogs
| where TimeGenerated > ago(14d)
| where OperationName in ("Consent to application", "Add delegated permission grant")
| extend App = tostring(TargetResources[0].displayName),
         Permissions = tostring(TargetResources[0].modifiedProperties),
         Actor = tostring(InitiatedBy.user.userPrincipalName),
         ActorIP = tostring(InitiatedBy.user.ipAddress)
| where Permissions has_any ("Mail.Read", "Mail.ReadWrite", "Mail.Send", "Files.ReadWrite.All", "offline_access")
| project TimeGenerated, Actor, ActorIP, App, Permissions
```

## H15. Low-and-slow distributed spray by ASN
**MITRE:** T1110.003
**Description:** Attackers rotate IPs within one ASN to stay under per-IP thresholds. Aggregate by ASN per day instead.
```kql
SigninLogs
| where TimeGenerated > ago(30d)
| where ResultType in ("50126", "50034")
| summarize Users = dcount(UserPrincipalName), IPs = dcount(IPAddress), Fails = count()
            by AutonomousSystemNumber, Day = bin(TimeGenerated, 1d)
| where Users >= 10 and IPs >= 3
| order by Day desc, Users desc
```

## H16. Full kill-chain correlation: spray, success, post-compromise action
**MITRE:** T1110.003, T1078.004, T1098, T1114
**Description:** Finds spray source IPs, the accounts that succeeded from them, then any follow-on audit actions by those accounts. Output is a ready-made incident timeline.
```kql
let SprayIPs = SigninLogs
    | where TimeGenerated > ago(7d)
    | where ResultType in ("50126", "50034")
    | summarize Users = dcount(UserPrincipalName) by IPAddress
    | where Users >= 5
    | project IPAddress;
let Compromised = SigninLogs
    | where TimeGenerated > ago(7d)
    | where ResultType == "0" and IPAddress in (SprayIPs)
    | summarize FirstSuccess = min(TimeGenerated),
                DeviceIds = make_set(tostring(DeviceDetail.deviceId), 5),
                OS = make_set(tostring(DeviceDetail.operatingSystem), 5)
                by UserPrincipalName, IPAddress;
Compromised
| join kind=leftouter (
    AuditLogs
    | where TimeGenerated > ago(7d)
    | where OperationName has_any ("security info", "Consent to application", "Reset password", "Add member to role")
    | extend UserPrincipalName = tostring(InitiatedBy.user.userPrincipalName)
    | project ActionTime = TimeGenerated, UserPrincipalName, OperationName
  ) on UserPrincipalName
| where isempty(ActionTime) or ActionTime > FirstSuccess
| project UserPrincipalName, IPAddress, FirstSuccess, DeviceIds, OS, ActionTime, OperationName
| order by FirstSuccess asc
```

## H17. Azure WAF: exploit scanners and successful responses
**MITRE:** T1190 Exploit Public-Facing Application
**Description:** Known scanner paths and user agents (for example Libredtail botnet probing CVE-2017-9841 `eval-stdin.php`). Part A lists probing IPs. Part B keeps only requests that returned 200 or 5xx, which is where real escalation is needed.
**Note:** Fields (`requestUri_s`, `httpStatus_d`, `userAgent_s`, `clientIP_s`) can vary by diagnostic setting. Check with `limit 10`.
```kql
// A) All scanner activity
AzureDiagnostics
| where TimeGenerated > ago(7d)
| where Category == "ApplicationGatewayAccessLog"
| where requestUri_s has_any ("eval-stdin.php", "/vendor/phpunit", "/.env", "/wp-login.php", "/cgi-bin", "/.git/")
     or userAgent_s has_any ("libredtail", "zgrab", "masscan", "nikto")
| summarize Requests = count(), Paths = make_set(requestUri_s, 10),
            Statuses = make_set(httpStatus_d) by clientIP_s
| order by Requests desc
```
```kql
// B) Scanner requests that were NOT rejected: escalate
AzureDiagnostics
| where TimeGenerated > ago(7d)
| where Category == "ApplicationGatewayAccessLog"
| where requestUri_s has_any ("eval-stdin.php", "/vendor/phpunit", "/.env", "/.git/")
| where httpStatus_d in (200, 500, 502)
| project TimeGenerated, clientIP_s, httpMethod_s, requestUri_s, httpStatus_d, userAgent_s
```

---

# Cortex XDR (XQL) equivalents

Same logic for the core hunts. Written to match the field pattern (`to_string(status -> errorCode)`) that was confirmed working. Dataset name may differ per tenant (`msft_azure_ad_raw` here). Novelty detection (H06) is done by comparing `first_seen`, since time-math functions vary by version.

## X01. Spray source IPs, no IP input needed
```
config timeframe = 7d
| dataset = msft_azure_ad_raw
| alter ip = to_string(ipAddress), usr = to_string(userPrincipalName), err = to_string(status -> errorCode)
| alter ok = if(err = "0", 1, 0), spray = if(err in ("50126","50034"), 1, 0), tok = if(err = "70043", 1, 0)
| comp count_distinct(usr) as users, sum(spray) as spray_fails, sum(ok) as success, sum(tok) as token_fail, min(_time) as first_seen, max(_time) as last_seen by ip
| filter users >= 5 and spray_fails >= 5
| sort desc success
| limit 100
```

## X02. Failure then success per user and IP, with device
```
config timeframe = 30d
| dataset = msft_azure_ad_raw
| alter ip = to_string(ipAddress), usr = to_string(userPrincipalName), err = to_string(status -> errorCode), dev = to_string(deviceDetail -> displayName), devid = to_string(deviceDetail -> deviceId), os = to_string(deviceDetail -> operatingSystem), app = to_string(appDisplayName)
| alter ok = if(err = "0", 1, 0), bad = if(err != "0", 1, 0)
| comp sum(ok) as success, sum(bad) as failed, values(err) as error_codes, min(_time) as first_seen, max(_time) as last_seen by ip, usr, dev, devid, os, app
| filter failed > 0 and success > 0
| sort desc failed
| limit 100
```

## X03. Novelty approach (run twice)
Run X02 with `config timeframe = 30d`, then again with `config timeframe = 7d`. Rows present in the 7-day run whose `first_seen` is inside the last 7 days and whose (usr, ip) pair is absent from the older window are new pairs. Corporate IPs show an older `first_seen` and can be ignored without an allowlist.

---

# Triage playbook

1. **Confirm success.** Spray alone is internet noise. Only successful sign-ins from the source IP are compromised accounts.
2. **Contain (Entra/IAM team):** disable account, revoke sessions and refresh tokens, reset password, review and remove unknown MFA methods.
3. **Scope:** run H12 (MFA changes), H13 (inbox rules), H14 (OAuth consent) for every compromised user.
4. **Block:** source IP and, if no legitimate traffic, the ASN or country, via Conditional Access named locations.
5. **Endpoint:** check the user's device in EDR/XDR for infostealer or session theft if token replay (70043) was seen.
6. **Document:** IPs, ASN, timestamps, affected users, device IDs, actions taken.

## Tuning notes
- Thresholds (`>= 5` users, `>= 10` attempts) assume a mid-size tenant. Raise for large tenants, lower for slow-spray hunts.
- Do not treat reputation scores (AbuseIPDB) as proof. They are IP-level context for prioritization.
- Two unrelated sources with similar reputation are not one campaign. Correlate on user agent, timing, username lists and ASN neighbors before merging incidents.

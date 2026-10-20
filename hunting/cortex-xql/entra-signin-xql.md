# Entra ID Sign-in Hunts (Cortex XQL)

For tenants that ingest Entra ID sign-in logs into Cortex (dataset commonly `msft_azure_ad_raw`, name varies per tenant).

> **Status:** EN-01 follows a pattern confirmed working in a live tenant. EN-02 and EN-03 are adaptations and are unvalidated. Large single queries with `windowcomp`, infix math or nested conditions failed in testing, so every hunt here is deliberately small. Add one line at a time when extending.

## Placeholders
| Placeholder | Meaning |
|---|---|
| `<IP>` | Source IP under investigation |
| `<UPN>` | User principal name under investigation |

## Entra result codes
`0` success, `50126` wrong password, `50034` user not found, `50053` locked, `50074/50076/500121` MFA, `70043` refresh token rejected by sign-in frequency (possible token replay).

---

## EN-01. Everything one IP touched: users, outcome, device, OS
**Description:** For a suspicious IP, lists each user, outcome, device and app, and flags successful sign-ins. Blank `devid` means an unregistered/unmanaged device.
```
config timeframe = 30d
| dataset = msft_azure_ad_raw
| alter ip = to_string(ipAddress), usr = to_string(userPrincipalName), err = to_string(status -> errorCode), dev = to_string(deviceDetail -> displayName), devid = to_string(deviceDetail -> deviceId), os = to_string(deviceDetail -> operatingSystem), browser = to_string(deviceDetail -> browser), app = to_string(appDisplayName)
| filter ip = "<IP>"
| alter ok = if(err = "0", 1, 0), bad = if(err != "0", 1, 0)
| comp sum(ok) as success, sum(bad) as failed, values(err) as error_codes, min(_time) as first_seen, max(_time) as last_seen by usr, dev, devid, os, browser, app
| alter compromised = if(success > 0, "YES - CONTAIN", if(error_codes contains "70043", "SUSPICIOUS - TOKEN", "no success"))
| sort desc success
```
`os` tells device type: Windows or macOS is a laptop, iOS or Android is a phone.

## EN-02. IP-agnostic: failure then success per (IP, user, device)
**Description:** No IP input. Lists every IP/user/device combination with both failures and successes.
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
Corporate NAT/VPN egress IPs will dominate. Do not build an allowlist first. Use EN-03.

## EN-03. New (user, IP) pairs without an allowlist
**Description:** Corporate IPs are old pairs for every employee. Attacker IPs are new pairs. Run the same query over two windows and compare.
1. Run EN-02 with `config timeframe = 30d` and note each pair's `first_seen`.
2. Pairs whose `first_seen` falls in the last 7 days are new. Pairs older than that are normal baseline.
3. Prioritize new pairs that have blank `devid`, a foreign country, or failures before success.

## EN-04. Token replay: who got 70043
```
config timeframe = 14d
| dataset = msft_azure_ad_raw
| alter ip = to_string(ipAddress), usr = to_string(userPrincipalName), err = to_string(status -> errorCode)
| filter err = "70043"
| comp count() as events, min(_time) as first_seen, max(_time) as last_seen by usr, ip
| sort desc events
```
70043 means a refresh token existed and was presented. A prior authentication happened somewhere. Revoke sessions and tokens, not only the password. Investigate the user's endpoint for infostealers or session theft.

## EN-05. All activity for one user (find the real device)
```
config timeframe = 30d
| dataset = msft_azure_ad_raw
| alter ip = to_string(ipAddress), usr = to_string(userPrincipalName), err = to_string(status -> errorCode), devid = to_string(deviceDetail -> deviceId), dev = to_string(deviceDetail -> displayName), os = to_string(deviceDetail -> operatingSystem)
| filter usr = "<UPN>"
| comp count() as events, min(_time) as first_seen, max(_time) as last_seen by ip, err, devid, dev, os
| sort asc first_seen
```
The row with a populated device ID and a familiar IP is the user's genuine asset. Compare against the suspicious IP's row.

## Troubleshooting
- Field names differ per tenant. Run `| limit 3` and read the actual columns. If columns are flat (for example `status_errorCode`), use them directly instead of `->`.
- Blank device ID is expected for unmanaged devices and browser sessions, and is itself an indicator.
- This dataset usually holds interactive sign-ins only. Non-interactive (token) activity needs the non-interactive log from the Entra side.
- Inbox rules, MFA changes and OAuth consent are not in sign-in logs. Use the audit logs and Unified Audit Log (see `entra-id/identity-hunting-kql.md`, H12 to H14).

# Triage Playbook

Short decision flows for the alert types covered by this pack. Queries referenced here live in the sibling folders.

## 1. Cloud identity: spray or credential stuffing against Entra ID
1. **Confirm success.** Spray alone is internet noise. Only successful sign-ins from the source are compromised accounts (EN-01, H03, H16).
2. **Contain (identity team):** disable account, revoke sessions and refresh tokens, reset password, remove unknown MFA methods.
3. **Scope:** MFA registrations (H12), inbox rules (H13), OAuth consent (H14) for every compromised user.
4. **Block:** source IP, and the ASN or country if there is no legitimate traffic from it, via Conditional Access named locations.
5. **Endpoint:** if token replay (`70043`) appears, inspect the user's device for infostealers or session theft.
6. **No Entra access?** Hand the identity team: IP, ASN, timestamps, the affected-user list and the failure-then-success evidence.

## 2. Internal AD: Kerberos or NTLM failure burst
1. Run AD-01 for the source and read the verdict, plus `max_per_user`, `total_nouser`, `fails_per_min`, `total_lockouts`.
2. Run AD-02 to see whether failures and successes are classic, interleaved or reversed.
3. Run AD-03 to identify the process on the source host.
4. Decide:
   - Spray or stuffing verdict, or new-host logons after the burst (AD-05): **escalate**.
   - Single account, steady low rate, interleaved with successes, normal process, recent password change: **stale credential**. Ask the account owner or AD team for `pwdLastSet` and compare with the first failure time.
5. Unmanaged or unknown source host: identify the owner regardless of verdict.

## 3. WAF: web exploit scan
1. Run WAF-01 (F5) or AZ-01 (Azure) for the client.
2. All rejected, 404 or blocked, no POST, no 5xx: block the IP, close with notes.
3. Any scanner-path `200`, any POST, any 5xx: escalate and inspect the backend host.
4. Run WAF-03 to see whether many clients sent the same scan.
5. Separate finding: if the scanned path exists on the backend, the application deployment needs fixing.

## 4. Correlating separate alerts
Do not merge incidents because two IPs share a bad reputation. Correlate only on shared user agent, matching timing, adjacent IP ranges or the same username lists. Otherwise record "no direct correlation found" and track them separately.

## Ticket template
- **What triggered:** rule, time (state timezone), source, target.
- **Evidence:** queries run, key counts, verdict signals.
- **Verdict:** malicious, stale credential, benign scan, or needs verification, with the reason.
- **Actions:** containment requested, blocks added, owners notified.
- **Open items:** what is still unverified.

## Notes
- Reputation scores (AbuseIPDB and similar) are IP-level context for prioritization, not proof of an incident.
- Zero results can mean the log source is not ingested. Confirm ingestion before concluding nothing happened.
- Verify the alert's own mapping. Rule metadata (MITRE IDs, field labels) is often wrong.

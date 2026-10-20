# Arcenum Threat Hunting Pack

Practical threat hunts for identity, Active Directory and web-facing attacks, from basics to advanced. Each hunt has a description, MITRE mapping, false-positive notes and tuning guidance.

## Contents

| Path | Platform | Covers |
|---|---|---|
| [`entra-id/identity-hunting-kql.md`](entra-id/identity-hunting-kql.md) | Sentinel KQL | Spray, brute force, success after failure, new IP/country, MFA fatigue, token replay, MFA registration, inbox rules, OAuth consent, kill-chain correlation (H01 to H17) |
| [`cortex-xql/entra-signin-xql.md`](cortex-xql/entra-signin-xql.md) | Cortex XQL | Entra sign-in hunts, device and asset lookup, token replay |
| [`cortex-xql/windows-ad-auth-xql.md`](cortex-xql/windows-ad-auth-xql.md) | Cortex XQL | Kerberos/NTLM brute force, spray, stuffing, stale-credential verdicts (AD-01 to AD-05) |
| [`web-waf/f5-waf-xql.md`](web-waf/f5-waf-xql.md) | Cortex XQL | F5 WAF exploit-scan triage |
| [`web-waf/azure-waf-kql.md`](web-waf/azure-waf-kql.md) | Sentinel KQL | Azure Application Gateway WAF scan triage |
| [`playbooks/triage-playbook.md`](playbooks/triage-playbook.md) | Any | Decision flows and ticket template |

## Status and validation

These queries are written from documented schemas and from patterns confirmed in testing. **Treat them as starting points and validate in a lab or test tenant before production or client delivery.** Field names and dataset names vary per environment. Every file lists its own caveats.

## How to use

1. Pick the hunt matching your alert or hypothesis.
2. Replace placeholders (`<SOURCE_IP>`, `<USERNAME>`, `<F5_DATASET>`) with your values.
3. Run `| limit 3` first to confirm the field names in your tenant.
4. Tune thresholds to your environment size.
5. Follow the matching section of the playbook for the decision.

## Contributing and data hygiene

Before committing, remove anything from a real environment:
- internal and public IP addresses, hostnames, domains, subscription and resource IDs
- usernames, account names, service account names
- ticket numbers, client or employer names

Use placeholders such as `<SOURCE_IP>` and `<USERNAME>`. Never commit alert screenshots or raw log samples.

## Languages

KQL (Microsoft Sentinel / Defender), Cortex XQL. SPL (Splunk) and FQL (CrowdStrike) versions are planned.

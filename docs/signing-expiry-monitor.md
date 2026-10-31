# Offline signing-certificate expiry checks

Before a release, inspect the independently authenticated public certificate export at an explicit UTC time:

```bash
python3 -B scripts/maintenance/signing_expiry.py \
  --certificate release-public.asc --fingerprint FULL_UPPERCASE_PRIMARY_FINGERPRINT \
  --as-of 2026-10-19T20:00:00Z --warning-days 30 --output expiry-review
```

The fresh private output directory retains the exact original public export and a JSON report with its byte count and SHA256. The report lists primary and own signing-subkey deadlines and concrete renewal/rotation actions. Primary aggregate uppercase capabilities do not count as the primary's own signing capability. An expired primary blocks the exported signing time window even if a subkey has a later expiry. Certificate expiry is distinct from expiry of package signatures already retained as historical evidence.

Renew and redistribute the public certificate before the shown deadline, or use the reviewed planned signing-key rotation procedure. A future-dated certificate, expired/revoked/disabled key, or lack of usable signing capability requires investigation before another release. The tool does not renew keys, change trust, enroll a repository, publish, schedule work or contact a service.

GPG inspects only the supplied export in a disposable private home, with user configuration, agents and automatic key retrieval disabled. Secret exports and multiple primary certificates are refused. The report excludes user IDs and raw GPG errors. Exported revocation information is reported, while current revocation, custody, trust and client acceptance remain UNKNOWN. A cached export cannot attest present revocation status; an evaluation at a supplied time is not a historical-state attestation. This report supplies no repository, ARM or hardware acceptance.

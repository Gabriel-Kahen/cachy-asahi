# Stateless public-key inspection successor

The frozen5415 verifier's first public `gpg --show-keys` actor returned0 and created a1200-byte `public-state/trustdb.gpg`. Its strict empty-state guard correctly stopped before any of207 signature actors. `--no-auto-check-trustdb` disables automatic Web-of-Trust updates; it does not prevent creating the database.

This successor whole-pins the original27132-byte verifier (`be6c793d39975f044a5626650f5ed641e0a4df2f809fe0a13524e73499018dc5`) and applies exactly two reversible literal changes: adjust the root path for this nested entry, and use `--no-keyring --trust-model always` only for public `--show-keys` inspection. The installed GnuPG2.4.9 primary manual documents `--no-keyring` as overriding all keyring options and `always` for external validation schemes, while retaining expired/revoked/disabled-key refusal. This invocation already has separately reviewed current official trust, exact pinned public bytes and explicit primary/subkey/UID/time/usability checks. No Web-of-Trust validity was an acceptance requirement: the unchanged parser accepts unknown validity. This change does not apply to any `gpgv` invocation.

The one separately authorized actual inspection control returned the exact same360-byte colon status/SHA256d3048b39e5708fdaa354302ab5de3449db45599c17e7855738d139209d21b458 as the failed predecessor's inspection, with stderr empty and fresh public-state empty before/after. Original `key_status` accepted it. It retired naturally0/REAPED/EMPTY_TWICE without signals in0.10844s. It did not verify package signatures or issue Root adoption.

All other code remains the whole-pinned predecessor:207 unchanged normal `gpgv` checks,422 whole public operands before/after, current Root trust review, exact key/signature checks, empty-state safety, held FD identities,900s run/60s actor caps, owned natural retirement, no signing/import/agent/autostart/network/private key use. The failed actual output is preserved. No filesystem cleanup or empty-state waiver is introduced.

`SELECTION.TEMPLATE.json` remains UNISSUED. Root must issue a fresh exact selection for this new entry and builder-lock path, fresh absent output, actual tool pins and still-current trust review. The old entry selection is refused. The full207 signature run has not been repeated. Default invocation returns HOLD without input or actor entry. After separate Root authorization the CLI remains:

```text
python3 -I -B successor_v2/verify.py --execute-public-verification --selection <Root-file> --selection-sha256 <whole-SHA256>
```

Five focused DATA controls run on both Python3.12 and3.14: complete predecessor inverse and unchanged non-inspection AST, unissued/old-entry refusal before actors, unusable/foreign key refusals, exact422/207 input contract, and retirement/actor-fence refusals. They never launch GPG. Native, installation, M2 and release acceptance remain unissued.

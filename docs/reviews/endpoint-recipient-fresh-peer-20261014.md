# Endpoint recipient fresh Source review

**PASS within the documented local, controlled-storage scope.** The author
receipt `829db3aac5ff2127928cafee00f75d102e83909a237b99f1025e65489f0b09a9`
authenticates nine owned files and20 inputs. All three product files match their
held author copies exactly: `scripts/client/endpoint.py`,
`scripts/client/test_endpoint.py` and `docs/release/endpoint-client.md`. No Source
file was edited. Commit/publication, production/native/hardware acceptance and
full-port completion are not established by this review.

The unsigned inventory hash identifies exact canonical snapshot bytes. It is
not a signer, freshness or installation credential. The independently supplied
fingerprint and copied public certificate drive actual release/package/database,
promotion and withdrawal signature checks. Selected releases reuse complete
release/dependency/platform/provenance/source-delivery checks and the existing
promotion/hardware verifier. There is no product gate override. Withdrawal-only
generations contain valid signed incident pairs and return no repository route.
The original development-envelope client remains unchanged and development-only.

Canonical single-slash paths, no-symlink traversal, single-link files, managed
directory ownership/permissions, bounded inventory and signatures, cooperative
locking, final complete file/alias recheck and root inode identity are present.
The public keyring is copied into a private temporary home; caller GPG home and
configuration, key discovery/retrieval/import, agents and dirmngr startup are
excluded by the existing verification invocation and temporary configuration.
Success and failure controls confirm temporary-home removal and unchanged
caller keyring bytes. The code executes metadata/signature tools, not package
hooks, source material or installation bodies.

Fresh validation: **20 author tests and eight independent countermodels pass,
with no skips**. The countermodels test:

- Replacement of the generation directory with an identical-byte new inode
  after signature checks is refused.
- Invalid supplied certificate bytes cannot fall back to the real ambient
  signing home.
- A detached signature exceeding64 KiB is refused before crypto.
- Genuinely signed naive/non-UTC withdrawal timestamps are refused.
- Post-signature withdrawal drift is detected.
- Verification of an older valid generation does not claim newer withdrawals,
  freshness, production acceptance or installation authority.
- Empty directories are permission/bounds checked rather than hash-inventoried.
- The private keyring home is removed after a signature refusal.

Actual TEST-key signatures, synthetic signed bundles, exporter materialization
and temporary filesystem operations run. Only positive promotion/hardware gate
admission is modeled, as explicitly declared by the fixtures. The unchanged real
gate refuses synthetic stable input through both API and CLI; withdrawal-only
API/CLI consumption succeeds without a gate seam. The author's separately
sealed48 unchanged-client test log is authenticated, not rerun in this peer turn.

No blocking defect was found in that bounded contract. Two limits are explicit:
an older valid snapshot can omit a newer withdrawal/revocation, and same-owner
hostile storage can ignore locks. The final checks detect the tested persistent
drifts but confer no authority on paths after return. Inventory completeness
means files and aliases; an unlisted empty directory is accepted if its ownership,
permissions and bounds pass. Directory names/shapes are not authenticated by
`export.json`; the documentation's “unknown members” wording should be read in
that file/alias scope. This inheritance grants no trust, freshness or installation
authority and is recorded rather than promoted to a broader guarantee.

The [new peer capsule](../../artifacts/reviews/endpoint-recipient-fresh-peer-20261014/)
contains authentication, exact input pins, independent countermodels and logs,
Source review facts, an immutable receipt and read-only verifier. No network,
Git/API, host trust, package, service or native/M2 actor mutation occurred.

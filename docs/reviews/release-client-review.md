# Offline development client independent review

October 11, 2026. Final source-freeze and local fixture review. This
review owns only this document. `AGENTS.md`, `goal.md`, the roadmap and package
inventory were read before review. No implementation, shared manifest, CI or Git
state was changed.

## Result

No remaining material acceptance bypass was reproduced for the consumed signed
targets, freshness/sequence checks, fingerprint pin, private checkpoint or
explicit apply boundary in the final frozen snapshot. The signature replacement
gap reported by the owner's separate reviewer is closed as described below.
This is a bounded development prototype review, not
stable-release acceptance or completion of R1–R5.

The client authenticates exact envelope bytes, the exact release-record bytes,
the spec hash, both database hashes and each declared package hash/identity. All
release-declared payload entries are checksum checked. Database and package
signatures are independently checked against the same pinned primary fingerprint;
a cryptographically bound signing subkey is allowed. Invalid, expired, revoked,
missing and SHA1 signatures fail; GPG exit zero alone cannot pass.

UTC issuance/expiry, maximum seven-day lifetime, an independently supplied floor,
lower sequence, same-sequence changed envelope bytes, namespace/signer replay,
backward issuance and clock movement behind an applied checkpoint are checked.
First-use state is explicitly cold-started; read-only verification intentionally
does not advance rollback history.

Paths use canonical names, component-wise no-follow directory opens and retained
directory descriptors. Consumed files must be regular and singly linked. State
requires caller ownership and exact 0700/0600 modes; a cooperative directory
flock excludes an applying client. Checkpoints use a private temporary file,
file sync and atomic replacement. Pre-replacement failure preserves checkpoint
bytes; final directory-sync failure is reported as an already-applied checkpoint
with durability uncertainty. Stable scope cannot pass and no install, transport,
trust bootstrap, key rotation or publication operation exists.

## Executed evidence

On the initial snapshot, this reviewer ran
`python3 -B scripts/client/test_client.py`: **33 PASS**, including the real
ephemeral-GPG cases and adapter consuming an actual synthetic bundle produced by
the existing release-stage tests. All package/repository data are synthetic.
The initial sandbox run passed the 17 portable checks but could not start the
ephemeral gpg-agent; the complete suite passed with a narrowly authorized rerun
outside the socket-restricted sandbox.

The coordinator independently reported **37 PASS, no skips** on the final
frozen implementation/test hashes below. This reviewer inspected the added
regressions and ran the focused final signature-race, invalid-database-signature
and full-call precommit-failure cases: **3 PASS**. The precommit test exercises
cleanup, fsync and replacement failures with an existing checkpoint; its bytes
and private-directory inventory remain unchanged. An initial command used an
incorrect precommit test selector; the corrected exact selector passed. Unchanged
cases were not repeatedly run by this reviewer.

An independent `/tmp/client-independent-review.py` reproduction generated a
second TEST ONLY signing primary B in the fixture's temporary GPG home. It
re-signed the synthetic package with B, updated its signature hash in the release
record, and re-signed the release record and envelope with pinned primary A. The
supplied public keyring included both A and B. Verification rejected B on the
exact-primary check and left the checkpoint absent. This exercises primary
identity beyond merely testing a bad signature or a wrong caller argument.

That reproduction also added an unrecorded regular file and an unused symlink to
the copied synthetic bundle. Verification accepted the consumed signed targets,
without changing state. This is a scope limit: the client does **not** replace
`release.py verify_release()` checks for complete directory inventory, repository
aliases, archive `.PKGINFO`, database contents, provenance or dependency closure.
Signed package identity here is the release record's assertion bound to archive
bytes; it is not independently extracted from the archive. The client document
now states this distinction explicitly, requires the separate release semantic
gate, and distinguishes implementation/local tests from native/production work.
This documentation concern is resolved. No installation authority is transferred
to bundle paths.

## Resolved signature replacement gap

The owner's separate reviewer reproduced a race in the initial source: after
`describe()` checksum-checked the declared payload map, `Verifier.bundle()` read
a database/package signature again without comparing those consumed bytes with
the signed release map. Replacing it with another valid signature for unchanged
target bytes could therefore escape the declared signature hash binding.

The frozen fix passes the release map's expected signature SHA256 to
`Verifier.bundle()` and checks the exact consumed signature bytes before passing
that immutable byte snapshot to GPG. Both database references and every package
reference use this same path. Target snapshots continue to be hash-bound to the
signed envelope; the release-record snapshot remains the exact authenticated
record from which the map was derived. Checkpoint mutation still occurs only
after all these checks and temporary verification cleanup.

This reviewer independently exercised the race on **both database archives and
the package archive** using `/tmp/client-freeze-race-review.py`. For each case,
the fixture first applied sequence 1, then signed sequence 2; a bounded mock
replaced the target's signature after `describe()` with a real SHA512 signature
under the same TEST primary. Explicit fixture-home GPG verification established
the replacement signature was valid. The frozen client rejected all three with
`signature bytes changed after release payload inspection`, and each existing
checkpoint remained byte-identical. **3 independent race checks PASS.** No new
path, state or atomic-commit regression was found from this minimal fix.

All generated keys, public-key copies, signatures and checkpoints were confined
to temporary TEST ONLY fixture directories under `/tmp`, with their GPG agents
stopped and fixture directories cleaned. No host default keyring/trust import,
host package installation, network, publication or native dispatch was used.

## Snapshot and limits

Reviewed SHA256:

| Input | SHA256 |
| --- | --- |
| `scripts/client/client.py` | `3025aa0e167c836e31c949e0915d4ee82a1007dc0fada598b4895240c82f5f97` |
| `scripts/client/test_client.py` | `a1a6a844ad4c0fd394a407529c5c7039f2a9e2bb43b63ee90a4e1e925701e144` |
| `docs/release/client.md` | `7c0bf5010c78cd6dab89728e52214816d9fba091b1b284c5501d4061b449125a` |
| `docs/workstreams/release-client.md` | `9c4f4b48b4d1fd665f12a1d92e10be5b41eb5db912e79a5eaed636089fa5d906` |

Execution host: **x86_64**. Native ARM, a supported Asahi package transaction,
M2 physical behavior, performance, production signing custody, publication and
stable promotion remain **NOT RUN** by this review. The real-GPG tests establish
local fixture behavior only. The client remains a foundation for R1/R5; it
cannot satisfy the required complete maintained port, R1–R5, by itself.

Caller-authenticated fingerprint/namespace/floor, a trustworthy local clock and
retained private state remain prerequisites. Offline revocation freshness,
withheld newer metadata, local-user state reset, input changes after observed
snapshots and noncooperative same-user mutation are not solved. The documentation
identifies these limits. Native client execution remains excluded from the first
virtual-integration pipeline. Status: **source/local development review complete;
no open blocker within this client's documented scope**. Integration must retain
the independent semantic, native, hardware and production gates.

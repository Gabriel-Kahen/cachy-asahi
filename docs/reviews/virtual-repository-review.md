# Virtual repository independent review

October 11, 2026, America/New_York. Interim review; final controller/source freeze
and native execution are pending. This reviewer owns only this document.
Roadmap and package inventory were read first. Reproductions use temporary data
and mocked commands only: no host pacman, key generation/import, trust mutation,
installation, session operations, dispatch, or Git commands.

## Open reproduced finding

### R1 — Rejected transactions can conceal an owned-file type change

`scripts/integration/repository.py:281-293` snapshots owned payloads using
`is_file()`, `stat()`, and SHA256 reads, which follow symlinks. The comparison at
lines 329-331 can therefore accept a regular file being replaced by a symlink
whose target has the same bytes, permissions, and owner.

Bounded reproduction used one temporary owned payload and a second temporary
regular file with identical content/mode. Mocked pacman returned the unchanged
inventory for `-Q`; the mocked rejected transaction replaced the owned payload
with a symlink to that second file. Repository selection was also mocked.

```text
case: rejected-symlink-mutation
result: PASS
expected_signature_rejection: true
before_equals_after: true
owned_payload_is_symlink: true
```

This does not show that pacman actually performs that mutation. It demonstrates
that the negative-case assertion fails to establish the claimed unchanged
owned-file state. Positive installed checks correctly reject symlink payloads,
but those checks do not run for rejected transactions.

Required correction: record filesystem type using lstat without following
symlinks, require contained regular owned payloads where present, and distinguish
missing, symlink, directory, and regular-file states in the before/after check.
Add a regression where a rejected command changes an owned payload to a symlink
with identical target bytes/mode/owner and verify no PASS case is recorded.

Observed runner SHA256 for this reproduction:
`01ffe2e67d4e794abcff6d0804c79812b517f6002e6a1d6c3336f2bd548d3966`.

### R2 — Successful upgrade can pass with a non-executable setup CLI

`metadata()` at lines 190-219 discards archive mode/uid/gid when constructing
the payload map. `installed()` at lines 295-317 verifies version, ownership
path, regular-file containment, and bytes but does not enforce the reviewed
archive's modes/owners. Captured after-snapshot modes are not compared to any
expected successful state.

An independent mock transaction updated all four expected package versions and
payload bytes and retained the complete base inventory. A temporary setup
archive specified CLI mode 0755; the installed temporary CLI had mode 0600.
The transaction still recorded PASS. A second bounded check copied the four
actual generated fixture designated payloads and used their manifest versions
and hashes: `installed()` accepted CLI mode 0644, also non-executable. All package
queries/transactions were mocked; no real original package was installed.

Required correction: preserve full expected file metadata from the reviewed
archive, enforce installed mode/uid/gid against it using lstat, and reject
inconsistent positive transactions before recording PASS. Test changed setup
execute permission and ownership separately; retaining correct version/hash
must not hide either failure. The existing lifecycle archive/installed checks
already show a compatible archive-derived mode binding; this repository stage
needs its own enforcement.

## Current verified source behavior

- Both input sets require exactly the four original package names. Actual
  archives are checked against row SHA256, ALPM version, and complete regular
  payload maps. The separate synthetic probe does not replace the originals in
  the implemented install/upgrade/rollback transactions.
- Each original must have a greater upgrade version, changed archive and
  payload bytes, and unchanged dependency/provides/conflict/replaces relations.
- Positive transactions require an expected all-four package map. They compare
  the complete base-plus-overlay inventory, original versions, archive-derived
  payload hashes, ownership containment, and obsolete payload absence. The
  rollback call uses the actual baseline map and `-Syyuu`.
- The prior exit-zero/no-upgrade false PASS has a regression and is rejected.
- Package and database signatures require TrustedOnly in the explicit private
  pacman configuration. TEST A bootstrap, unknown B rejection, B certification,
  retained A rollback, stale package signature, tampered database, separately
  missing signatures, A revocation, and final B upgrade have distinct cases.
- Private TEST homes and revocation input remain in container tmpfs; cleanup
  failure cannot retain overall PASS. Actual cleanup still requires native
  receipts and destruction of the disposable container.

## Pending producer/consumer review

The runner accepts reviewed archive/version/payload rows. It does not itself
load `fixture-manifest.json` or bind those rows to its expected designated
installed payload changes, baseline versions, generator/source/recipe pins, or
rollback hashes. This binding must be checked in the forthcoming CI adapter
before acceptance; merely naming four tiny substitute archives as the originals
must not satisfy the all-four integration gate.

At the first review snapshot, no repository CI controller/adapter exists under
`scripts/ci` or the workflows. Its absence during active development is recorded
as unfinished integration, not a completed implementation defect. Final review
will require the frozen adapter and its public export projection.

The current runner exports repository file aliases as regular copies and
directory aliases in a signed JSON map. Its portable export regression passes.
An independent mock export containing `.db` and `.db.sig` aliases plus the
directory `active` alias emitted zero symlinks and was accepted by
`log_evidence.bundle()` (five regular members). The previously reported raw
symlink incompatibility is **resolved in current source**; signing the alias map
and actual repository signature verification were mocked/unrun here.
Raw command receipts still include key-generation arguments and binary/archive
material, so they must not be passed wholesale to `integration_export.py`.
That filter rejects such material; an independent temporary raw export returned
FAIL for the database/signature files and synthetic `--passphrase` command
record, as required. Deliberately public JSON/log/text receipts
and any separately authorized hash-bound public artifacts need an explicit
controller path. Generic bundler/exporter symlink rules must remain intact.

## Actual checks and limits

`python -B -m unittest discover -s scripts/integration -p test_repository.py -v`:
**20 PASS**, after reading the tests' mocks/temp paths. Test source SHA256:
`c014b9eb1a1ce70194d427731076b8e4f8c154440cb3f3e980be486686b8c8f8`.
R1 and R2 were independently reproduced outside those tests using only
temporary files and mocks. No native package/signature/repository transaction
was run.

Status: **changes required for R1/R2; controller binding/export review pending**.
After the coordinator-reported roadmap integration at
`506f2596d674a26de8c947ef44728118cd9e2455`, the relevant runner hash remains the
same as this review's reproduced source, and no repository CI controller is
present under `scripts/ci`. R1/R2 remain open. The expanded full-port roadmap does
not change these bounded findings or convert this review into native acceptance.
Native repository execution, actual upgrade/rollback and trust lifecycle remain
NOT RUN. Generic container success cannot mark exact-M2, Asahi dependency,
hardware, performance, production signing/publication, or stable promotion gates
passed.

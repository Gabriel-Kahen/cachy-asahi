# Explicit setup and configuration migration candidate

Development successor **cachy-asahi-setup 0.3.0-1**, in the separate setup8 recipe
directory. Accepted Setup7 is0.1.0-7; the task also names an older0.2.0-7 identity.
This candidate reuses neither archive identity. Native builds, actual package
installation and physical M2 validation for this revision are NOT RUN.

The package retains explicit per-user setup/status/remove/recover and the separate
repository enrollment/disable helper. It adds `/usr/bin/cachy-asahi-config-migrate`
and a private original engine/contract under `/usr/lib/cachy-asahi/setup8/`.
No hook, package lifecycle action or default invokes a per-user command. No login
shell, skeleton, session, service, repository trust or Asahi platform component
changes automatically. The payload is exactly the10 files in payload-map.json.

The migration launcher uses isolated Python and its fixed installed usr/bin→
usr/lib sibling layout; no PYTHONPATH or user module lookup is required. Package
removal leaves every home, owned configuration, state journal and version ledger
untouched. Reinstallation restores the same CLI/code, without replaying a journal.

## Explicit migration

Run as the intended ordinary user. Supply a reviewed raw manifest and its exact
SHA256, plus immutable retained old/new template roots and hashes. This package
installs no migration default, template tree or manifest. `preview` and `status`
are read-only; **apply writes immediately**, and recover explicitly completes
pending work. A hash is an identity check, not release authentication.

```sh
cachy-asahi-config-migrate preview --manifest /absolute/reviewed.json --sha256 "$REVIEWED_SHA256"
cachy-asahi-config-migrate apply --manifest /absolute/reviewed.json --sha256 "$REVIEWED_SHA256"
cachy-asahi-config-migrate status --manifest /absolute/reviewed.json --sha256 "$REVIEWED_SHA256"
cachy-asahi-config-migrate recover --manifest /absolute/reviewed.json --sha256 "$REVIEWED_SHA256"
```

Use the same home/config/ZDOTDIR/state options throughout. Only existing finite
setup components and exact ownership blocks/files are eligible. User changes
outside shell blocks survive; edited owned content, incorrect versions, unsafe
paths or changed inputs refuse rather than overwrite. Recovery is forward
completion, not rollback or three-way merge; preserve both immutable input roots
and the exact manifest. The configuration ledger records declared configuration
versions and does not establish package database installation/version.

After successful migration, ordinary setup remove recognizes the new owned
content and preserves outside user bytes and migration history. Removing an
owned component does not authorize migration to recreate it. Explicit activation
of the exact new source permits a repeat check. Retain/review journals before
removing this CLI; package uninstall itself does not recover or reset them.

`cachy-asahi-setup status` now recognizes only the header of migration-owned
intent and directs the user to this explicit migration CLI with the original
manifest and hash. It reports `migration-owned`, `can_resume:null` and
`validated_by_setup:false`; only the migration CLI validates readiness. Setup
apply/remove/recover continue refusing a migration-owned journal. This bounded
status correction is separate from accepted immutable Setup7 bytes.

The installed migration guide is the original source handoff guide, including
source-checkout examples and its source-only historical validation statement.
This README documents the added delivered CLI. The repository guide retains
source-checkout examples; rotation requires a separately reviewed checkout and
no rotation CLI is installed here.

## Source and fixture checks

`source-provenance.json` pins all original/current source, license and adapted
29-test bodies. Only the original test's contract-directory lookup is adapted to
its packaged sibling; no assertion or case is removed. `check-sync.py` checks
canonical copies in a checkout; `--snapshot` checks all pinned recipe inputs
without executing helpers. Actual recipe prepare/check retain those source and
29-test gates. No third-party dependencies or compiled payload are bundled.

`test_delivery.py --root ABSOLUTE_STAGE` runs the delivered executables against
fresh private fixtures. `--root /` targets the actual installed layout in the
future disposable native consumer; it does not install packages. With explicit
`--work FRESH --keep-fixtures`, four profiles are retained for the external ALPM
remove/reinstall check; `--verify-reinstall --work EXISTING` checks byte/metadata/
ledger preservation and genuine reinstalled CLI repeat/status. The caller owns
final fixture cleanup. Host fixture results are not installed/native/M2 acceptance.

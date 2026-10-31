# Per-user configuration migrations

`scripts/setup/config_migrate.py` provides explicit `preview`, `apply`, `status`
and `recover` commands for M6/M8 configuration upgrades. This implementation is
host-tested with disposable homes. It is proposed source until integrated and
packaged; native ARM, installed-package, VM and physical M2 validation remain
**NOT RUN**. It does not establish M6/M8 acceptance.

The engine reuses `scripts/setup/setup.py`: the same per-user component paths,
guarded shell markers, setup ownership state, descriptor-relative safe file
operations, exclusive flock and atomic fsynced replacement. Run as the intended
non-root user. Nothing changes a login shell, `/etc/skel`, system configuration,
a package, a service or a running shell/compositor. Preview/status do not create
locks, directories or journals. Apply/recover may create private state storage.

## Supported changes and preservation

A manifest names a finite subset of the existing setup components (`fish`, `zsh`,
`hyprland` and the six supported shell modules). It cannot name arbitrary target
paths, commands or transformations. Unknown/duplicate components and fields,
duplicate JSON keys, noninteger schema values and path traversal are refused.

* Shell changes replace exactly one unedited, recorded guarded source block with
  the canonical block sourcing a new, exact template root. User bytes outside the
  block survive byte-for-byte. Multiple components sharing `.zshrc` or Fish's
  config are prepared together and replaced once, in existing setup source order.
* The Hyprland change replaces the whole owned file only when it still matches
  the exact old template hash. Edited whole files, edited/duplicated markers,
  missing ownership and conflicting recorded versions cause a visible failure.
  No partial new migration starts when preflight finds a conflict.
* No arbitrary three-way merge is attempted. Keep user customization outside
  managed shell blocks; review customized Hyprland files manually.

Both old and new template trees must remain available and hash-identical until
recovery and lifecycle verification finish. Use immutable version-specific roots
when content changes. Two different template versions cannot occupy the same
path simultaneously. This engine does not create those roots; package/release
integration must supply and retain them. Sources are never executed by this tool.

Each manifest binds one package name and exact old/new version strings. Every
entry binds old/new template roots and SHA-256 content digests. The required
`--sha256` separately pins the manifest's raw bytes to a reviewed release record;
a digest computed from an untrusted download is not release authentication.
Package database installation/version verification belongs to the release
workflow. The migration ledger records configuration versions, not proof that
those package versions were installed.

## Manifest and commands

This example shows the schema; substitute actual SHA-256 digests from retained
package artifacts before use. A release can list several components belonging
to the same package. Each component appears once.

```json
{
  "schema_version": 1,
  "id": "fish-0.1.0-2-to-0.2.0-1",
  "package": "cachy-asahi-fish-config",
  "from_version": "0.1.0-2",
  "to_version": "0.2.0-1",
  "entries": [
    {
      "component": "fish",
      "old": {
        "root": "/usr/share/cachy-asahi/versions/0.1.0-2",
        "sha256": "REPLACE_WITH_64_LOWERCASE_HEX_DIGITS"
      },
      "new": {
        "root": "/usr/share/cachy-asahi/versions/0.2.0-1",
        "sha256": "REPLACE_WITH_64_LOWERCASE_HEX_DIGITS"
      }
    }
  ]
}
```

Hashes cover the corresponding `setup.TEMPLATES` input, for example
`fish/config.fish`, not the user file or generated shell block. First activate the
old version using existing setup with the same root options. The first migration
can adopt the declared old configuration version only after validating existing
setup ownership and the exact retained old template hash. Later migrations also
require the recorded configuration version, package, root and hash to match.

```sh
python -B scripts/setup/config_migrate.py preview \
  --manifest /absolute/path/fish-migration.json --sha256 "$reviewed_manifest_sha256"
python -B scripts/setup/config_migrate.py apply \
  --manifest /absolute/path/fish-migration.json --sha256 "$reviewed_manifest_sha256"
python -B scripts/setup/config_migrate.py status \
  --manifest /absolute/path/fish-migration.json --sha256 "$reviewed_manifest_sha256"
```

`apply` writes immediately; `recover` explicitly finishes a pending migration.
There is no implicit recovery on `apply`. `status` reports `ready`,
`already-applied` or `pending`, or fails with a visible error if validation cannot
establish one of those states. A successful repeat validates content and returns
`already-applied` without rewriting anything. Reports include hashes, versions
and fixed target paths, never user configuration contents. Exit codes are 0 for
success/ready, 2 for a pending read-only observation and 1 for a conflict/error.

Like setup, explicit `--home /absolute/temp/home` isolates caller XDG variables.
For a real home, `XDG_CONFIG_HOME`, `ZDOTDIR` and `XDG_STATE_HOME` inside that home
are honored. `--config-home`, `--zdotdir` and `--state-dir` can pin explicit
absolute locations inside the home. Always reuse the original root options for
recovery/removal. Symlinked directories/files, multiple hard links, special files,
unsafe ownership/permissions, invalid UTF-8 and oversized content are refused.
Existing target modes, group ownership and xattrs are preserved by setup's writer.

## Transaction and recovery

The existing setup `lock` excludes simultaneous setup/migration writers. The
shared `journal.json` is a durable migration intent recorded before target
writes. Its `migration-...` transaction ID deliberately falls outside legacy
setup's accepted transaction identities: existing setup activate/remove/recover
refuse it before touching managed files. This interlock requires no setup change.
Do not bypass it or delete the journal to force removal.

The journal contains the manifest digest, exact metadata hashes, prior ownership
and version records, and before/after target hashes. It contains no copies of
user file contents. Replay revalidates all pinned inputs, metadata and every
target before resuming. It derives allowed deltas from the finite manifest and
canonical ownership records. Each file must be at its exact before or after
hash; writes compare those snapshots again. Changed targets or metadata cause
refusal with the journal retained. Replacement is atomic per file, not across
all files: interruption can leave some targets upgraded until recovery completes.
This relies on normal local-filesystem fsync/rename/flock semantics, not tested
storage power-loss guarantees or coordination with editors ignoring the lock.

```sh
python -B scripts/setup/config_migrate.py status \
  --manifest /absolute/path/fish-migration.json --sha256 "$reviewed_manifest_sha256"
python -B scripts/setup/config_migrate.py recover \
  --manifest /absolute/path/fish-migration.json --sha256 "$reviewed_manifest_sha256"
```

Recovery finishes target writes, commits setup ownership, commits private
`migrations.json`, then removes the journal. Recovery is repeatable after any of
those steps. An interrupted setup transaction must first be recovered with
`setup.py`; migrations will not adopt it. A different manifest, digest or root
selection cannot recover this migration.

If a user edits a target during interruption, preserve that edited file in a
user-chosen private backup. Review the reported conflict and restore the exact
interrupted before/after bytes before retrying recovery; reapply desired edits
outside managed blocks afterward. The engine cannot reconstruct arbitrary prior
user edits from hashes. There is no automatic rollback, journal discard or
conflict override. Retain exact inputs and review conflicts before proceeding.

## Removal, reinstall and integration limits

After successful migration, ordinary `setup.py remove` uses the updated ownership
records: it removes the new guarded blocks, preserves surrounding user bytes and
removes a clean owned Hyprland file. If a migration is interrupted, recover it
before removal. Removal does not erase version history. Applying an old manifest
after removal refuses to infer activation; reinstalling/activating the same new
version permits the idempotent check again. Reinstalling an older version cannot
silently reset the ledger; a separately reviewed version transition and matching
owned inputs are required. User-edited managed content is preserved/refused even
after a previously successful migration.

Integration needs the two scripts beside existing `setup.py`, the documentation,
reviewed per-package migration manifests and retained version-specific template
roots. No recipe, workflow, shared manifest or existing setup file changes are
part of this proposal. Package hooks must not run per-user configuration mutation
as root. Native/installed integration must prove template layout/retention and
both supported M2 models must exercise the documented lifecycle before acceptance.

Run the focused tests from the repository root:

```sh
python -B scripts/setup/test_config_migrate.py -v
```

Before integration, run the proposal's test file at its artifact path. It finds
the existing canonical setup contract without copying or changing it. A direct
proposal CLI invocation needs `PYTHONPATH` pointing at the repository's
`scripts/setup` directory; after integration the sibling import works directly.
Tests use only temporary filesystem trees, including real shared shell-file
writes, content/version conflicts, unlink/write failures, metadata edits,
interruption at durable boundaries, SIGKILL after a target write, shared locking,
symlink/hardlink/FIFO rejection and removal/reinstall interactions.

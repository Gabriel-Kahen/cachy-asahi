# Caller-scoped immutable update scale support

This adds an opt-in backend for one changed signed archive on a copied root with
exactly 587 installed packages. It does not establish an update of the real
587-package composition. The default tiny caller and installer limits remain
unchanged; no hooks, scriptlets or ldconfig execution is authorized.

## Implementation

`bound_update.apply(args, adapter=...)` retains its checkpoint lock, actual ALPM
lock, prepared handle, input rechecks, protected ownership checks, actual
post-observations and checkpoint truth. The default remains the existing installer
adapter. The scaled adapter supplies the matching ALPM pointer type for prepare
and commit; it does not reload the handle or mutate imported installer globals.

`scale_update.py` requires a separately pinned scale JSON in addition to the
existing release/settings/platform-policy inputs. It fixes installed inventory to
587, selected archive count to one, and requires the before and expected/actual
after inventory SHA256s. Only an existing package with a changed version qualifies;
the other 586 package versions are held. It retains signature verification and
rejects downgrades, unexpected prepared changes, protected transitions and drift.
Existing client/release authentication limits remain in force.

`full_root.py` subclasses only ALPM inventory/ownership observation, with explicit
per-caller limits. Filesystem traversal opens directories and files relative to
retained descriptors without following symlinks. It streams file hashes and bounds
bytes, individual files, node count, depth and deadline. Observation reports logical
and allocated bytes, largest file, database size/count, link counts, filesystem
free bytes/inodes, completeness and unsupported shapes. Absolute/escaping/cyclic
links, hardlinks, special nodes, cross-device subtrees, incomplete reads and any
ldconfig path/alias remain transaction-ineligible. The installed root may be much
larger than the original 128MiB/20,000-node limit, but incoming data cannot raise
its externally selected budgets.

`archive_stream.py` inspects gzip, xz and zstd without extraction or whole-archive
decoding in RAM. It streams member hashes and bounds compressed bytes, aggregate
compressed/decoded bytes, file sizes, headers including PAX/GNU extensions, decoder
memory/window and deadline. It requires one complete compressed frame and complete
tar end padding; truncation, trailing/concatenated data, bombs, sparse/hardlink/
special payloads, unsafe paths/links and ldconfig/aliases are refused. It uses
Python 3.14's `compression.zstd` for zstd; this is additional coverage, while the
recorded 574 reference archives are xz. The focused memory check concerns Python
allocations for a synthetic payload, not total native decoder RAM or performance.

`capacity.py` groups future allocation demand by filesystem, combining root and
workspace demand when they share a device. It checks free bytes and inodes before
prepare and again immediately before commit. New payload, conservative old selected
payload/database allowances, declared reserves and future workspace demand are
counted. Already allocated snapshots are excluded from future demand. Unknown inode
availability is a refusal, not an inferred unlimited supply. Final real-root budgets
still require the actual measurements and peak-space review.

`supervision.py` bounds the owned worker's time and combined output, sends TERM/KILL
only to its allocated process group, and reaps the leader once after group signals.
WNOWAIT keeps that identifier reserved; no group signal follows reaping. Setup
failure, timeout and pipe-holding descendants are covered. Timeout does not prove
package rollback: the parent reports commit/checkpoint UNKNOWN and requires disposal
or recovery of the owned root/container. It never removes an ALPM lock file to
pretend recovery. This supervises the updater worker; it grants no auxiliary policy.

## Explicit platform selection

The scale JSON requires `platform_mode` to be either `apple` or
`generic-development`. It never retries a failed Apple authorization as generic.

- `apple` uses the unchanged Apple evaluator and required actual asahi-audio,
  speakersafetyd and package-owned module observations. A complete protected view
  is derived from the independently checked full inventory; version, ownership,
  release-evidence and model/kernel requirements remain enforced.
- `generic-development` requires a separately named pinned policy and
  `settings.model = "generic-development-only"`. It holds actual selected base,
  declared protected versions, owned paths/modules, trust and required unit names.
  Protected packages must exactly match the authenticated release selection and
  include pacman, glibc and declared kernels. Before/after lock hashes must agree
  across the scale selection, policy and actual observations. Generic success
  explicitly establishes no Apple acceptance or hardware behavior.

The generic policy's exact keys are `schema_version` (1), `purpose`
(`cachy-asahi-generic-development-update-policy`), `release_id`,
`protected_packages`, `protected_versions`, `platform_roles` (only `kernel`),
`protected_units`, `before_lock_sha256`, and `after_lock_sha256`. Unit names must
match the existing required protected unit sets. No production policy is shipped.

## Selection and commands

The scale JSON has exact keys: `schema_version` (1), `purpose`
(`disposable-bound-update-scale`), `platform_mode`, `before_lock_sha256`,
`after_lock_sha256`, `limits`, and `capacity`.

`limits` requires positive integers for `root_nodes`, `root_bytes`, `file_bytes`,
`package_files`, `archive_bytes`, `archive_total_bytes`, `decoded_bytes`,
`archive_members`, `window_bytes`, and `seconds`. Runtime ceilings are finite:
64GiB byte-related limits, four million root nodes, one million archive headers or
owned package files, 1GiB decoder window, and 3,600 seconds. These are hard ceilings,
not accepted production budgets. The stream backend requires at least a 32KiB
window; xz also needs enough memory for its decoder/dictionary overhead.

`capacity` requires positive declared `root_reserve_bytes`, `root_reserve_inodes`,
`workspace_future_bytes`, and `workspace_future_inodes`.

For a transaction, invoke `scripts/update/scale_update.py` with all existing bound
updater flags plus `--scale FILE --scale-sha256 SHA256`. The parent supervises a
fresh worker. `--measure-only` needs only root/workspace/scale flags and performs
filesystem observation without a package transaction or checkpoint change.
Existing isolated copied-root guards apply to both modes. No live-root invocation
or AUR/Flatpak/cleanup/restart/platform-upgrade operation is accepted.

## Measuring the actual composition before container cleanup

`scripts/update/measure_copy.py` is an ordinary data-copy/measurement entry for the
next actual native composition. It requires a marked native ARM root container,
network none, a private owned workspace, and a SHA-pinned exact 587-package lock.
It reads the actual installed inventory before copying and afterward, and checks
the copied database identities against it. It does not manufacture 587 names.

Run it after the actual composition has finished its package operations, using
clean PATH `/usr/bin:/bin` and a fresh 32-hex `CACHY_ASAHI_BOUND_UPDATE` marker:

```
python3 -B scripts/update/measure_copy.py --workspace /owned/private-measurement \
  --expected-lock /inputs/actual-selected-587.lock --expected-lock-sha256 SHA256 \
  --max-bytes FINITE_LIMIT --max-nodes FINITE_LIMIT --max-file-bytes FINITE_LIMIT
```

Use the actual reviewed post-composition lock, including the selected setup/updater
versions. The values above must be selected as finite copy upper bounds; the helper
checks free capacity for maximum data plus per-node metadata/reserve and inodes
**before allocating the copy**. It refuses insufficient or unknown capacity.
Provide an explicitly owned Docker volume or host-disk bind for the workspace;
the composition's 1 GiB `/tmp` tmpfs is not a suitable copy destination. Root must
choose the finite budget and include workspace removal in scoped cleanup.

The helper reads the owned container filesystem and copies data into
`workspace/root`, excluding runtime paths and every mounted path, then measures the
copy. Source operations are read-only. A mutable source mount is allowed and
reported: consistency is per-file identity plus stable actual/copied inventory,
not an atomic snapshot. Directories/files retain modes and UID/GID; internal
hardlinks and symlinks remain data and are never followed during traversal.
Special nodes are counted and skipped. Xattrs and timestamps are not copied.

The result retains source logical/allocated counts, copied-root footprint,
exclusions, unsupported counts and bounded reason/path examples (at most 64 by
default, each path at most 4096 characters), completeness, source-root mount mode and exact
inventory pin. It sets `whole_root_copy=false` and no transaction acceptance.
Examples omit symlink targets, file bytes and the internal node map.
Runtime/mount exclusions or omissions must never be described as a complete root
clone. Keep the copied filesystem private and delete only its owned workspace at
container cleanup; export only the bounded JSON footprint, not its files or keys.

## Verification and remaining inputs

Local checks include actual TEST-signed gzip/xz/zstd libalpm commits on synthetic
587-record databases, holding 586 synthetic versions; generic policy acceptance
without fabricated Apple audio packages; protected/lock/configuration/capacity
refusals; streaming decoder limits; scalable filesystem data observations; bounded
copy behavior; and worker cleanup. These are x86_64 fixture results, not the actual
587-package composition or a native ARM scale result. This host's Btrfs reports
unknown free inode capacity. Successful transaction/copy fixtures explicitly inject
a synthetic inode budget while retaining actual free-byte checks; production has
no such fallback, and fixture results carry that injection flag. Original tiny
snapshot/platform/transaction checks still pass with their original semantics.

Genuinely missing before a real scaled update:

- The exact expanded current composition footprint/shape/capacity measurements;
  the previous native job removed its images, and none is retained locally.
- A complete authenticated immutable candidate/base/provenance bundle and the
  exact before/after lock pair for the selected one-package transition. Measure
  base metadata against the unchanged authentication JSON/total limits too.
- Externally pinned real-root budgets and generic protected selection, based on
  those actual inputs rather than fixture values.
- Explicit reviewed handling of genuine ldconfig. The real composition contains
  it, so this implementation correctly refuses its transaction. No binary is
  removed/renamed/stubbed, and no auxiliary command is silently enabled.
- Review of any actually needed absolute-link/hardlink/special shapes, followed
  by actual native ARM scaled execution. Observation counts do not authorize them.

The existing tiny caller's separate native 39-case success remains its own evidence.
Full scaled native composition update, production publication, Apple transitions,
M2 hardware, boot/session and recovery validation remain **NOT RUN** here.

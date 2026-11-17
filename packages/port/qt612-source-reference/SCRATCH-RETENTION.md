# Serial experiment scratch retention

This is a proposed retention contract for the new `6.12.0-2` serial experiment,
not a cleanup implementation, resource measurement, Root grant or native result.
The coordinator owns the recipe. The C executor and its original owner job own
all runtime custody and retirement. No build or cleanup was run for this note.

The separate experiment proposes an inner builder limited to 4 GiB, one CPU and
one build job; a 6 GiB daemon; 12 GiB storage; minimum 14 GiB free disk and 10 GiB
available RAM. These are proposed limits, not proof Qt fits. The prior 18 GiB RAM /
72 GiB disk proposal remains historical and unchanged. Preserve the selected
Source93 confinement, owner, mount, process and retirement guards. Neither this
file nor the older C preparation selects an operational runtime.

## Retain both attempts completely

For each distinct `build-1/` and `build-2/` evidence directory, retain:

| Paths relative to the attempt | Purpose |
| --- | --- |
| `provenance.json` | Final outcome, image, inputs, clean environment identity, artifact and evidence hashes. Pin this final record externally; it does not hash itself. |
| `build.log` | Complete normal builder stdout/stderr, including failures. |
| `validation.json` | Actual package validation report, including errors. |
| `expected-packages.lock` | Reviewed exact builder inventory. |
| `inputs/**` | Complete exported recipe snapshot; every `recipe_inputs` entry must remain at its recorded path with exact bytes. |
| `artifacts/environment.txt` | Actual uname, page size, makepkg and package observations. |
| `artifacts/packages.lock` | Actual builder inventory, equal to the reviewed lock on success. |
| `artifacts/config.sha256`, `artifacts/makepkg.conf`, `artifacts/pacman.conf` | Actual build configuration. |
| `artifacts/generated.SRCINFO` | Isolated generated recipe metadata. |
| `artifacts/cachy-asahi-qt612-base-source-reference-6.12.0-2-aarch64.pkg.tar.xz` | Whole actual package, including payload, metadata, license notices and ELF files. Its presence alone is not success. |
| `artifacts/*-check.log` and every other actual phase log/output | Real check-phase evidence and all generated retained output. Expected current check log: `cachy-asahi-qt612-base-source-reference-6.12.0-2-aarch64-check.log`. |
| `source-material/**`, when offline source staging is bound | Every staged source and receipt already included in `provenance.files`. |

The offline tree includes `source-plan.json`, `source-catalog.json`,
`selection.json`, `srcdest/qtbase-everywhere-src-6.12.0.tar.xz`,
`receipts/<material-id>.json` and `notices/<sha256>`. Its absence in a failed
attempt is recorded as failure, never filled with another attempt's output.
Retain **every** entry in the actual `provenance.files`, not merely this table.
Keep both complete archives and recipe snapshots; do not retain only their hashes.

Retain the surrounding operation's actual command outputs/retirement records,
image and inventory bindings, source/recipe selections, resource observations,
`comparison.json`, Qt pair-finisher output when implemented, `report.json`,
`cleanup.json` and the complete evidence manifest. Preserve partial records when
later records were never produced. Retention must not overwrite a failed attempt
or turn its failure into a successful attempt.

`compare_v2.verify()` rehashes every `provenance.files` entry, every artifact and
every recorded recipe input. Removing any referenced file breaks verification.
Offline `source_material` selections must also agree between attempts. A separate
cache copy does not replace either attempt's referenced `source-material` paths.
No hard-link, symlink or shared mutable replacement is authorized to save space.

## Disposable scratch and its boundary

In the normal builder, `/inputs`, the entry script, expected lock and offline
source mount are read-only. The builder copies its work under its own `/tmp`:

- `/tmp/work/src/qtbase-everywhere-src-6.12.0/`: extracted and patched source.
- `/tmp/work/src/build/`: CMake/Ninja products and caches.
- `/tmp/work/src/smoke-source/`, `smoke-build/`, `smoke-home/`: smoke work.
- `/tmp/work/pkg/`: package staging trees.
- `/tmp/offline-sources/`: writable copy of the immutable offline source inputs.
- `/tmp/build-home/` and other unreferenced files inside that builder's tmpfs.

These are disposable working copies, not the retained input snapshots, staged
source evidence or archives. `container-entry-v2.sh` already uses
`makepkg --cleanbuild --clean --force --log --noconfirm`, sends phase logs directly
to `/out` with `LOGDEST` and copies archives to `/out`; `build_v2.py` starts
the container with `--rm`. Thus a normally completed first container retires its tmpfs before the
second starts. There is no need to retain its compiler objects for pair comparison.
This statement describes the existing lifecycle, not a new deletion permission.

The current recipe writes `$srcdir/stage-contract.json`. The existing entry does
not export this file separately, and normal makepkg cleanup can remove it.
`compare_v2` does not consume that raw report. Do not claim it was retained. If a
future Qt finisher requires it or any smoke/configure diagnostic, C must first
provide a reviewed evidence export before cleanup, or a reviewed equivalent
archive-based check. An evidence requirement cannot be satisfied by deleting its
only copy and citing a successful shell exit.

Before any additional scratch retirement or starting attempt two, C must establish
that attempt one's required retained records have their final hashes, normal
checks and package validation succeeded, the command naturally retired, and the
exact owned `--rm` container is absent. Attempt two uses fresh writable state and
a distinct clean environment identity with the same reviewed immutable inputs.
A failed or incomplete first attempt stops the pair; retirement may clean the
already-failed owned actor but cannot satisfy attempt one's success gate.

## Custody and comparison remain the executor's responsibility

The original C owner job must preserve the admitted nonce, PID/start identity,
original PIDFD, cgroup and twice-empty retirement joins. Filesystem and mount
custody must identify the original owned scratch mount and backing device; do not
infer ownership from a reusable pathname. Bind retained ordinary files to their
actual descriptors/inodes and whole hashes, and recheck the selected owner's
stable identity rules through retention. Evidence copies are new inodes and need
explicit copy/readback pins; they are not proof of the source inode's continuity.
Do not replace, unlink or mutate original retained evidence while comparison or
its readers still hold it. No shared host directory, daemon, cache or unrelated
container is scratch owned by this recipe.

Keep unchanged strict pair checks: whole archive bytes, payload, PKGINFO,
BUILDINFO, recipe/source/image/inventory equality and real `check()` in both clean
attempts, followed by the reviewed Qt-specific finisher. The normal comparator's
`contents-reproduced` result alone does not require BUILDINFO equality; the final
Qt pair gate must require it explicitly as well as byte identity. Failure,
timeout, cancellation, missing evidence, nonempty custody or uncertain cleanup
stays HOLD, regardless of recovered storage.

## Limits of the inspected producer

This review read C commit `1cb3eba9797f4dd7082100af7421d60f951e15f7`, its pinned
`build_v2.py`, `compare_v2.py`, `container-entry-v2.sh` and retained llhttp entry.
That C constructor has no operational Qt entry: its native gate always refuses.
The retained normal builder still has its original CPU/tmpfs command constants;
it is not an implemented executor for the new serial experiment envelope.

The inherited llhttp `retain()` copies all `build-1/`, `build-2/` and command files
under a 15 MiB input / 16 MiB encoded-evidence budget. A Qt offline source copy
alone exceeds that inherited retention cap. A future C executor must account for
the complete retained evidence under a separately reviewed bounded retention path.
Dropping archives, staged sources, logs or snapshot files to fit the old encoder
is not an acceptable adjustment. Neither 12 GiB storage sufficiency nor any
larger retention capacity is established by this note.

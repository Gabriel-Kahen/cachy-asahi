# Three tools: native builds and package lifecycle, 2026-10-15

[GitHub run 38765227491](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38765227491),
attempt 1, succeeded on `ubuntu-24.04-arm`. It records **six current native package
builds, three exact-byte comparisons, three test-only upgrade fixture builds and
the disposable installed lifecycle as PASS**. The tested packages are Zsh
autosuggestions, Fish bang-bang and Topmem. This is generic ARM development
evidence; release signing, Asahi installation and M2 acceptance remain open.

## Source and retained evidence

- Product Source: `4ee5a99e6ce7a83e2e5a5bdf4b71a1080e91d21c`.
- Workflow commit: `1588ebc22245ee11b2c1d86754b9c2cfa0f3776f`; the workflow checks out
  the separate product Source and builds the original four once before this batch.
- Tools implementation: [run.py](../../scripts/ci/tools-batch/run.py),
  [lifecycle.py](../../scripts/ci/tools-batch/lifecycle.py) and the fixed
  [recipe input map](../../scripts/ci/tools-batch/inputs.json).
- Recorded builder image:
  `sha256:c7a2f6a39e128983128a3c10cb2c6ba1ffcad0ade6917a1dfc041e8b9324ba25`.
- Builder package inventory SHA-256:
  `fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25`.
  Builds record native `aarch64`, network `none`, source epoch `1791748800` and a
  **4,096-byte** kernel page size.

The existing [logs.zip](../../artifacts/development/tools-run38765227491/logs.zip)
passed ZIP CRC and declared member-length checks. Its ordinary `log_evidence.py`
frame declares 437,181 compressed bytes and SHA-256
`05ac35a2c613fced89b723fd5dff161fb3f3c4152ff16779d83ee84429e467ce`.
Decoding that existing frame reproduces both declarations exactly. The retained
[tools-evidence.tar.gz](../../artifacts/development/tools-run38765227491/tools-evidence.tar.gz)
contains 284 regular files totaling 1,126,229 uncompressed bytes, including the
nine build-output package archives, their six lifecycle-input copies, recipe
snapshots, build provenance, validation reports, comparisons and lifecycle log. No recollection, rebuild or lifecycle
replay was performed for this document.

The 12 Zsh, 12 Fish and 7 Topmem recipe inputs in both current build snapshots
match the fixed map, committed Source and canonical
`9dca67f8114c70308bc05b744e754f9cb3b222fa` exactly. The actual working files also
match those hashes at this audit. This result applies to the current recipe
bytes, including licenses, notices and `.SRCINFO`, rather than only an older
candidate description. Later edits require a new comparison.

## Actual packages and comparisons

Each current version was built in two fresh, distinctly named native containers
on the same builder. Both archives for each package are retained and compare
equal locally. All three retained comparator reports also have empty errors and
`bytes_equal`, `installed_contents_equal`, `pkginfo_equal` and
`buildinfo_equal` true.

| Current package | Bytes per archive | SHA-256 of both actual archives | Payload files |
| --- | ---: | --- | ---: |
| `cachy-asahi-zsh-autosuggestions-0.7.1-1-any.pkg.tar.xz` | 13,652 | `ff59a185f52e80dc4fd08c666d093cccefa3e57f2513085c900602da597f29b9` | 6 |
| `cachy-asahi-fish-bang-bang-0.1.0-1-any.pkg.tar.xz` | 7,540 | `9d5a043691152b7555acafc877eb960750c85417ceef4c41b5f91382645f4b1c` | 7 |
| `cachy-asahi-topmem-0.1.0-1-any.pkg.tar.xz` | 8,092 | `583ffacd614bd741722486d5fbc64b79bb283d62c87974063fc1484dfcbe199b` | 4 |

All nine provenance records report `built-package-static-pass` and exit 0 with
nine different build-container names. Ninety declared provenance file hashes
were independently recomputed from retained bytes. The actual compressed
packages, contained regular-file payload hashes/modes/root ownership and the
copies supplied to lifecycle match their declarations. The packages declare
`arch=any`; these are native ARM shell/Python package builds, not compiled M2
binary or performance results. Distinct builds on one builder do not establish
independent-machine reproducibility.

One additional native build per package supplies a **test-only** upgrade:
Zsh `0.7.1-2`, Fish `0.1.0-2` and Topmem `0.1.0-2`. Only PKGBUILD and `.SRCINFO`
`pkgrel` change from 1 to 2; all installed payload files remain identical,
including their archive metadata. These three fixtures are retained for the
changed-version transaction and are not release candidates. They were each
built once; no fixture build pair is claimed. Their archive sizes/hashes are in
[local-validation.json](../../artifacts/development/tools-run38765227491/local-validation.json).

## Installed lifecycle and its limits

The actual [lifecycle log](../../artifacts/development/tools-run38765227491/lifecycle.log)
records `install: PASS`, `changed-version-upgrade: PASS`, `remove: PASS`,
`reinstall: PASS`, a second `remove: PASS` and `TOOLS_LIFECYCLE_PASS`.
The outer tools step then emits `TOOLS_BATCH_PASS` and succeeds. The following
details follow the exact Source's enforced checks and that observed PASS;
individual shell output, Topmem JSON values and user-file fingerprints are not
separately exported.

| Check | Actual result and bounded scope |
| --- | --- |
| Install, changed-version upgrade, removal, reinstall, final removal | PASS in one disposable offline ARM Docker container. Current packages install together; the pkgrel-only fixtures upgrade them; those fixture versions are reinstalled after removal. This does not test changed upstream payload migration, failed upgrades or rollback. |
| Installed package checks | PASS for expected versions, `pacman -Qkk`, file owner lookup, all 17 regular payload files' bytes/modes/root ownership. After each removal their files are absent and the full baseline package inventory is restored. |
| Explicit Zsh/Fish opt-in | PASS as the image's unprivileged `alarm` account in both minimally seeded and existing-user fixture homes. Each installed wrapper is sourced twice, and the expected functions must exist. Fresh shells after removal use guarded source checks and require the functions to be absent. This checks loading/function availability, not actual ZLE suggestions, Fish history expansion, PTY key behavior or every plugin combination. |
| User configuration/history preservation | PASS for fixture file bytes, mode, UID/GID and mtime across all transactions/probes. Both homes contain a seeded Fish config; the existing fixture additionally contains `.zshrc`, Zsh history and Fish history. This is not preservation evidence for a real user's complete home or directory metadata. |
| Installed Topmem | PASS for the installed `--json --limit 1` command running as `alarm`, requiring its reported UID to match that account, `scope=current-real-uid`, and at most one returned process. Actual PIDs/RSS values and whether the list was nonempty are not retained; no memory-saving or performance result is implied. |
| Package trust during lifecycle | Local development packages are unsigned. The temporary offline pacman config explicitly uses `SigLevel=Never` and `LocalFileSigLevel=Never`, with scriptlets disabled and existing builder hook masks retained. Signed release trust, repository publication and release-key handling are not tested here. |

## Cleanup and unfinished acceptance

All nine successful build commands record Docker `--rm`. The lifecycle Source
also uses `--rm`, returns normally, and attempts a final named `docker rm -f`
before emitting the successful batch result. That final removal command ignores
its exit status; no separate lifecycle-container absence observation or global
owned-resource cleanup report is retained. Therefore this result establishes
the normal disposable-container execution path and restored package inventory
inside it, **not an independently verified absence audit**. The batch does not
remove or prune its shared base builder image. The job's final log reports normal
orphan-process cleanup without an exported resource inventory.

No host package installation was part of this batch: package transactions are
inside the disposable container and its input binds are read-only. Actual
Asahi target install/remove/upgrade/recovery, both M2 Air sizes, physical
16KiB-page behavior, terminal interaction, signed releases and measured
performance/power remain NOT RUN by this evidence. The successful normal path
does not establish cancellation, interrupted package recovery or boot/session
recovery.

[Comparison reports](../../artifacts/development/tools-run38765227491/comparisons.json)
and [local byte validation](../../artifacts/development/tools-run38765227491/local-validation.json)
are readable derivatives of the retained log bundle. Root owns inventory
reconciliation and release selection; this document changes neither.

# Installed interactive tools on native ARM, 2026-10-15

[GitHub run 38769320390](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38769320390),
attempt 1, succeeded on generic `ubuntu-24.04-arm`. The retained evidence records
**six installed interactive-helper passes, 18 real PTY sessions and 18 Topmem
CLI snapshots**, alongside the existing package build/lifecycle checks. This
closes the representative native software checks below; it does not establish
either M2 Air terminal workflow, Asahi installation or performance gains.

## Source and retained bytes

- Product Source: `b183388a2bce3ccf9ec0cdbe90539bc4d2c07f82`.
- Workflow: `b885128888d555329cc7e1d1760248fbcd465d48`, which checks out that Source.
- [Interactive helper](../../scripts/ci/tools-batch/interactive.py) SHA-256:
  `c70d4bc4e8f105619b4846ec4c66db5b863f28ddbe8b997489ee2564736750f7`.
- Recorded builder image:
  `sha256:bba246c7bb7cc3e7db24ffba0dd6087b83ab0628ade6ead10a4eb53bea78942e`.
- The build environment records `aarch64`, network `none` and **4,096-byte**
  kernel pages.

The existing [logs.zip](../../artifacts/development/tools-interactive-run38769320390/logs.zip)
passes ZIP CRC checks. Its retained tools frame decodes to exactly **437,788
bytes**, SHA-256
`35d33bbd00e46cf8f371853d77e5a8783d5559429804a736aa3b2c6f9845e5fe`,
matching the frame's declared size/hash. The decoded
[tools-evidence.tar.gz](../../artifacts/development/tools-interactive-run38769320390-review-20261015/tools-evidence.tar.gz)
contains 284 regular files totaling 1,132,121 uncompressed bytes. This audit
reads those existing bytes; it performs no download, rebuild, shell replay or
additional CI dispatch.

All 31 current recipe inputs (12 Zsh, 12 Fish, 7 Topmem) and the four tools-batch
implementation/input-map files match Source, canonical
`29c5e47ba8a0a2be3d94dc784fb69116a5c1c6cc` and working files at the audit.
All nine build provenance records pass their retained hash checks, including 90
declared output-file hashes. Six current native builds, three single pkgrel-only
upgrade fixture builds and three exact-byte comparisons pass. Each current pair
has identical actual compressed bytes locally, with matching metadata/payload/
BUILDINFO comparisons. The current package archive hashes are unchanged from
the [earlier native batch](tools-batch-native-20261015.md); these are `arch=any`
shell/Python packages, not compiled M2 binaries.

## Actual installed terminal behavior

The [lifecycle log](../../artifacts/development/tools-interactive-run38769320390-review-20261015/lifecycle.log)
contains six distinct JSON reports, not twelve tests: workflow logging also
prints a duplicate tail of that same log. The six reports cover minimally
seeded and existing-user fixture homes during installation, changed-version
upgrade and reinstall. Each helper runs as unprivileged `alarm`, UID **1001**,
inside the offline disposable lifecycle container.

Each report contains the following actual operands:

| Check | Observed result in all six reports |
| --- | --- |
| Zsh suggestion | Typed buffer `printf '%s\n' CAA_`; actual POSTDISPLAY `SUGGESTION`. The helper also waits for that suffix to be displayed on the PTY before taking the ZLE snapshot. |
| Zsh right-arrow acceptance | BUFFER becomes `printf '%s\n' CAA_SUGGESTION`; POSTDISPLAY becomes empty. |
| Zsh backspace editing | BUFFER becomes `printf '%s\n' CAA_SUGGESTIO`. |
| Fish `!!` | The actual command buffer expands to `printf '%s\n' CAA_FISH_PREVIOUS`. |
| Fish `!$` | Typed `printf '%s\n' !$` becomes `printf '%s\n' "two words"`, preserving the quoted final argument. |
| Existing user binding | Zsh and both Fish sessions produce `CAA_USER_WIDGET` through the existing custom key binding. |
| Repeated opt-in | `repeated_opt_in=true` for Zsh and both Fish cases. Source requires function/binding equality across the second source, followed by successful actual editing checks. |
| Preserved configuration/history | `user_files_preserved=true`. Source compares each fixture file's hash, mode, UID/GID and mtime before/after; the dedicated Zsh synthetic history must also remain unchanged. |
| Expanded command execution | Every report has `expanded_enter=false`. Only the fixed setup-source and fixed exit commands are submitted; expanded history buffers receive no Enter. Histories contain controlled harmless printf markers. |

Zsh uses its history strategy with async explicitly disabled for this finite
case. Fish uses private in-memory history, default emacs bindings and captured
real `commandline -b` state through a custom widget. The state/terminal
acknowledgments drive the checks; a delay alone is not accepted as success.
The minimally seeded home includes a Fish config file. The existing fixture
also contains Zsh configuration/history and Fish history. These are synthetic
fixtures, not reads or preservation tests of a real user's complete home.

## Actual controlled Topmem process probes

Each helper starts one owned Python process, allocates/touches **100,663,296
bytes (96 MiB)** and waits for its announced PID. Source independently reads
that process's real UID and VmRSS from `/proc` before running the installed
Topmem command. All six reports record UID 1001. The actual PID and independent
resident-size operands are retained:

| Lifecycle stage | Home | Helper PID in container | `/proc` RSS bytes |
| --- | --- | ---: | ---: |
| Install | Minimally seeded | 64 | 113,311,744 |
| Install | Existing | 100 | 113,188,864 |
| Changed-version upgrade | Minimally seeded | 160 | 113,520,640 |
| Changed-version upgrade | Existing | 195 | 113,364,992 |
| Reinstall | Minimally seeded | 268 | 112,848,896 |
| Reinstall | Existing | 304 | 113,381,376 |

For every helper, Topmem limits **50, 1 and 2** return **3, 1 and 2** rows
respectively. That helper PID is present in all three retained snapshots, and
its reported RSS equals the corresponding independent `/proc` value exactly
in this run. Each value exceeds the touched allocation. Source also requires
current-real-UID scope, positive RSS and descending order. This demonstrates
the installed command's representative PID/RSS/limit behavior; it is not a
memory-saving, throughput, latency or power measurement. It does not exhaust
all `/proc` races, permission conditions, filtering cases or large process sets.

The actual operands are available in
[interactive-results.json](../../artifacts/development/tools-interactive-run38769320390-review-20261015/interactive-results.json).

## Lifecycle, cleanup and remaining limits

The log finishes with `install: PASS`, `changed-version-upgrade: PASS`,
`remove: PASS`, `reinstall: PASS`, a final `remove: PASS` and
`TOOLS_LIFECYCLE_PASS`; the outer step emits `TOOLS_BATCH_PASS`. The existing
version, installed-file ownership/integrity, 17 payload-file checks and restored
baseline inventory remain enforced. Upgrade versions change only pkgrel and
retain identical payloads. They test a changed-version transaction, not changed
upstream behavior migration. These fixtures remain development-only.

No concrete functional failure appears in the requested finite PTY/process
cases. The following acceptance gaps remain explicit:

- Source requires natural zero shell exits, bounded PTY closure, owned group
  TERM/KILL cleanup even after the leader exits, and reaping of the allocated
  helper. This successful normal path exports no separate post-cleanup process
  inventory. Earlier host negative tests are not newly claimed native negative,
  cancellation or descendant-fault tests.
- Build/lifecycle containers use normal Docker `--rm`; the outer final named
  removal still ignores its status. There is no separate retained container
  absence audit, and the shared builder image is retained. This preserves the
  [previous cleanup scope](tools-batch-native-20261015.md#cleanup-and-unfinished-acceptance).
- Package transactions use the temporary offline unsigned-development policy
  (`SigLevel=Never`, scriptlets disabled, existing hook masks). Signed release
  trust, repository publication and release recovery are not established.
- Async/completion autosuggestions, other Fish modes, empty/interrupted histories,
  every plugin/keybinding combination, real user migrations and failed-upgrade
  recovery remain outside these finite cases.
- Actual Asahi target installation, physical 16KiB-page operation, both M2 Air
  terminal workflows, Apple hardware integration and measured final-system
  performance/power remain NOT RUN by this evidence.

[Local validation](../../artifacts/development/tools-interactive-run38769320390-review-20261015/local-validation.json)
and [comparison reports](../../artifacts/development/tools-interactive-run38769320390-review-20261015/comparisons.json)
are readable derivatives of the retained bundle. Inventory/roadmap decisions
remain with Root; this document changes neither.

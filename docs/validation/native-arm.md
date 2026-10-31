# Native ARM execution record

October25: [Apps14 full606 native lifecycle](apps14-current606-native-20261025.md), [Apps15 native pairs/finite577 lifecycle](apps15-native-20261025.md), [Apps16 native pairs/finite577 lifecycle](apps16-native-20261025.md) and the [Apps10/Boot1/Doctor2/KSM2/Setup6/Welcome8 finite installed composition](current607-six-tool-native-20261025.md) are Root accepted. The composition passes32 transactions,65 fresh graphs,33 auxiliary observations and four whole240-source suites; it does not qualify Apps15/16 in606 or in that composition. Generic16K, GUI, Asahi/both M2 sizes, performance and supported release remain separate. Existing Apps14/15 selection flags remain false; no Apps16 manifest row is added here.

Coordinator execution, October 12, 2026 UTC (October 11 local). Source snapshot
`f4fc643192468526367f1ca34b96f78176cc5c8b`, published to the project repository.
This record concerns a hosted Linux ARM builder, not a Mac installation.

## Security maintenance finite native component (2026-10-31)

Root accepts the finite native ARM 4K TEST-signed component for
`cachy-asahi-security-maintenance 0.1.0-2` at
[Source b6a02f11648738ded90084f7dcdcd4ea77c194fa](https://github.com/Gabriel-Kahen/cachy-asahi/commit/b6a02f11648738ded90084f7dcdcd4ea77c194fa),
[run 41179285419](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/41179285419),
[job 124473189670](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/41179285419/job/124473189670).
[Artifact 13034143037](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/41179285419/artifacts/13034143037)
is 914,324 bytes, SHA256
`85927fa799425fbcd37b015c28fa81d50eeecde6d3ec8d6e4a09a0f7bcd58120`.
The [public evidence record](security-native-component-v5-20261031.json) binds the
Root decision, exact source/map and evidence hashes.

Two distinct clean aarch64 / 4096-byte-page builds produce identical 94,166-byte
`arch=any` archives, SHA256
`897fee33c0ee97fc5d529ed9aae6a576cac0fa1010eefe127aabc28e15a7f2d2`.
All 29 payload body/mode pins and 349 `.BUILDINFO` package identities match. Scoped
ephemeral TEST authority exercises Required/Required unknown-key and untrusted
installation refusals without changing inventory, signed installation and 29 ALPM
owner checks, ordinary-user installed and moved-prefix offline workflows, and
removal restoring the 349-package baseline while preserving user data. Each
workflow exports aggregate results for 17 source-defined semantic controls and 23
commands; removed inner workflow trees/logs were not independently reconstructed.
All 10 inner lifecycle flags and exact source-bound outer retirement qualify from
original joined receipts, rather than a new live host inspection.

The full matching reader API completed once. Its first worker subsequently
exited 1 during an optional DATA projection; that failure remains retained. A
separate corrected projection and independent package DATA decode exited 0 without
replaying the reader API. This is not an all-workers-pass claim.

Upgrade is **NOT EXERCISED**: the source performs one installation and removal,
without a distinct version transition. Generic 16K is NOT QUALIFIED; installed
Asahi and physical M2 are NOT RUN, performance is NOT MEASURED, production trust
and release are NOT ADMITTED, and ARM remediation is NOT ESTABLISHED. No release
selection or broader security assurance follows from this finite component.

## Static validation

[Run 38189008536](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38189008536)
completed successfully. Ubuntu ran source/sync/build/collector/benchmark/CI checks
and inspected four recipes. The real-shell setup integration test skipped because
Fish/Zsh were absent; the release test class skipped because repo-add, bsdtar and
vercmp were absent. The coordinator's local Arch host separately passed all 177
tests with no skips. The green Ubuntu job does not establish release-tool execution.

## Native probe

[Run 38189013510](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38189013510)
completed successfully on GitHub's standard public-repository `ubuntu-24.04-arm`
runner. Actual observations: four Neoverse-N2 CPUs, Linux/aarch64 userspace,
4096-byte pages, non-root UID/GID 1001, aarch64 Docker daemon at the local UNIX
socket, Ubuntu ARM image `20261004.142.1`. No QEMU setup occurred. This is provider
and execution evidence, not independent physical hardware attestation.

The logged probe bundle's SHA-256 is
`58fdb394a78f03b9c75f54dac2a9fe86b3c5672aa2ed619318bceab0ba2df815`,
1768 bytes. Coordinator verified digest/size and decoded only bounded regular
files. Full log, archive and decoded JSON are retained under
`artifacts/ci/38189013510/`. Independent review is
[the native execution review](../reviews/native-execution-review.md).
Probe result is `native-runner-probe-pass`; package build and hardware fields
remain `NOT RUN`. The input/build step was explicitly skipped in this probe.

## Four-package native build

[Run 38189058133](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38189058133)
executed the frozen four-recipe build at that exact source commit and failed at the first desktop package before assembly.

- Input lock SHA-256: `7d53775b2de6136d531a7f20059088def7bbb11ad8baef58e75cd5826e3a2b41`.
- Recipe lock SHA-256: `8906c36f5cbcdb0e1e70798e6db23be1d30f45385d57af0094a1cd509c7a89d0`.
- Required result: authenticated inputs, isolated offline native bootstrap,
  exact installed inventory, two fresh native builds per package, artifact checks
  and strict byte comparison for all four.

**First build result: FAIL; no package acceptance yet.** All 249 payload
signatures (rootfs plus 248 packages) authenticated. Native scratch bootstrap
provisioned immutable image
`sha256:d2ab65321238d7d8809d18de9703f184514e4a462ca8dbfa3df6b03e2d856b90`
and matched the expected 341-package inventory, lock SHA-256
`7f40e51da419514c3ffe4fc9ed5bd9d6f242e576a585347c4799cd20bfd32104`.
The first desktop build then rejected checked-in `.SRCINFO` ordering: it put
`arch` before `url`, while native makepkg generated `url` before `arch`.
No dependency or payload was substituted, no package was skipped, and the strict
comparison remains enabled. Desktop owner has a narrow metadata correction;
coordinator will review/refreeze and rerun the complete set.

The failed run's native-evidence log bundle is 762192 bytes, SHA-256
`56c9a66bbd3734aacff420dd7e2bd476cd3a7f13c0415c7c80dddb51ef2f91dd`.
Verified log, bundle, signature/input/bootstrap/build diagnostics are retained at
`artifacts/ci/38189058133/`. Later packages and byte comparisons did not run.
Both M2 Air models, 16K-page execution, install/removal, platform transaction,
performance, real signed updates and full-goal acceptance remain `NOT RUN`.

## Corrected full rerun

Desktop owner changed only `.SRCINFO` ordering to the observed native output,
SHA-256 `feeb68da93a0a81f274125e00588c98ad5e7b9772377172a0973c06d5cf94c89`.
All effective metadata and PKGBUILD/payload hashes are unchanged. The unchanged
strict checker rejects the original and accepts the correction. Source/static
inspection passed; coordinator re-froze the complete set.

[Run 38189520114](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38189520114)
executes source `ebd5812640b0b69f5c09a47752b739e37e338754`, the same signed
input lock and corrected recipe lock
`20d846cdf289bfc233b0051bf33b677fd6e94e9f05d91a33595a2829a196fa63`.
Result: **PASS for native package builds and byte comparison**. All four
packages completed two fresh native container builds. Every pair has identical
archive bytes, installed contents, `.PKGINFO` and `.BUILDINFO`. All eight
container IDs are distinct. Coordinator rechecked the downloaded records,
retained snapshot/evidence hashes, archive inspection and strict comparisons;
results match the job's recorded comparisons. These local rechecks are not
additional native builds. This rerun does not erase the first failed attempt.

The actual resulting builder image is
`sha256:7a3a68aef1b1cbb2aa8ae81e05b08fd1e9c948c222053ae4957f57554fe4d4f0`,
with the same exact 341-package inventory. The image is generated in the hosted
job; its recorded immutable ID is not a published/pullable registry image.
Across-job image byte reproducibility is not asserted; each package pair used
one identical image and fixed source-date epoch.

Native-evidence bundle: SHA-256
`8797f4f8b52d0f2a84dbbce3589f331b1a913f1fad413877bb1a861775f287e3`,
1232758 bytes. Full workflow log, verified bundle, source snapshots, raw build
logs, provenance, comparison reports and all eight original archives remain in
`artifacts/ci/38189520114/`. A compact public receipt is
[native-arm-summary.json](native-arm-summary.json). The signed original build
input bytes remain in the private retained cache documented above.

These are `arch=any` original data/stdlib-script packages, built on native ARM.
They introduce no ELF objects. This result does not validate the chosen Asahi
target transaction, M2/16K runtime, installation/removal, desktop session,
performance, release trust or hardware gates. No supported release is selected.

Independent final review accepted all four native package builds and exact archive
rebuilds after checking the logged bundle, all eight provenance records, source
and installed inventory bindings, artifact contents and comparisons. No material
inconsistency was found. See [final native review](../reviews/native-execution-review.md).
This acceptance is limited to the documented hosted ARM package execution.

## Current desktop and setup native builds

[Run 38683309592](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38683309592),
at Source `465bf53545e1d83053bf3c412e210493961b74ae`, passed eight native ARM
builds and four exact original-archive comparisons. Root verified and admitted
retained review `a5bef078ad21c0f76cbb8fa14ddba5e0e345805316cd73f451d42128ff55e289`.
The input lock is `beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f`;
the recipe lock is `a5fb287b4dda2a90bf61d4fa8cbbc5d666dad8bb450a70544d00545b091f36e3`.

| Package | Version | Bytes | SHA256 of each original archive |
| --- | --- | ---: | --- |
| cachy-asahi-fish-config | 0.1.0-1 | 5396 | `38e766158d13a0e13b8f811766119d10c018ccc256f5d99c3561b74c99d12705` |
| cachy-asahi-hyprland-settings | 0.1.0-2 | 12740 | `0b22b778ec83d8b98d98d06fa4f016bd4e3f581b69efa83d6526c5265c2adf5e` |
| cachy-asahi-setup | 0.1.0-3 | 14496 | `85ab7b964cd628ef21f5df6133aa9d046d32ea35cd6af3de0e5b888341550f0c` |
| cachy-asahi-zsh-config | 0.1.0-1 | 6244 | `be2ef8ed4f0263720ed6290bff9992d5df53c7bf689a40478f2be329ba2d50e7` |

The retained records contain 501 successful checksum acquisitions, 249 successful
detached-signature GPG checks, and the selected 341-package builder inventory
`fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25`.
Root verified package metadata, source payload joins and matching comparison
reports through the bounded retained-evidence review. This review did not rerun
GPG or package builds. [Detailed evidence review](../reviews/setup-current-native-build-run-38683309592-20261015.md).

This establishes native build and byte-comparison acceptance for these versions.
Installation, upgrades, removal, recovery, Asahi target dependency/trust
transactions, both M2 Air sizes, 16K-page execution and performance remain open.
Final container/image/daemon/cache absence is not established; retained-cache
finish records a handoff. Historical integration snapshots remain unselected
and must be refreshed explicitly before accepting the current package set.


## Welcome7 GUI pair and KSM 16K sharing (2026-10-21)

Welcome7 `0.1.0-7` passed both generic native ARM **4K** GUI profiles at source
`4bbf44cd6962c17956bce7dc2dfcc50801cd0634`:
[minimal39358836494](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/39358836494)
and [overlay39358896031](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/39358896031).
Original collections and full passive replays pass, joining 348 source files,
138 artifact members and 13 frames per profile. Root qualified the pair after
source and visual review. Installed actions include navigation, terminal/files
launch, Doctor1 reports, Orphans2 assessment/lock refusal, stored-only DNS2,
missing helpers and close-during-helper retirement. Doctor/Orphans removal and
restoration gives **595 → 593 → 595**, preserving user configuration and stored
DNS state. The failure report is fully visible; long reports exceed the captured
viewport, with hidden text checked separately.

KSM2 passed owned anonymous-page sharing and unmerge in a generic ARM **16K** VM:
[source0fc2af64f741b9dc2adf708f82f7bf3f4b1beb1f/run39356862528](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/39356862528).
The signed package lifecycle is **574 → 575 → 574**. Two children each hold2MiB
(128 pages), with per-child merging counts **0 → 128 → 0** and unchanged contents.
Shared/sharing counters reach128/128 then zero after synchronous unmerge; scan
counts correctly reset for that epoch. Both children exit/reap and original KSM
settings return. Root's independent original-byte replay passes against the pinned
diagnostic kernel and628-file source.

These are finite software results. Preservation/security and retirement claims
come from the bound source and original recorded evidence; private full maps were
not exported and this is not a fresh live host inspection. The GUI pair gives no
Doctor2/current606, installed Boot-history or16K GUI credit. Neither result qualifies
interrupted recovery, Asahi integration, either M2 Air size, performance gains,
production trust or release selection. Earlier failures remain failed. Detailed
local decisions: `artifacts/development/welcome7-gui-pair-acceptance-root-20261021/Root-pair-acceptance.json`
and `artifacts/development/ksm16k-counter-epoch-native-actual-20261020/Root-component-acceptance.json`.


## Boot607 and controlled KSM interruption (2026-10-21)

[Boot607 run39567514315](boot607-native-component-20261021.md) qualifies the finite
native-container606/607 installation lifecycle and six offline synthetic fixture
executions. It does not qualify real boot history or recovery.

[KSM run39573487748](ksm16k-controlled-interruption-20261021.md) additionally
qualifies controlled SIGTERM after actual owned-page sharing in a generic16K VM:
unmerge, contents, settings and process retirement pass. Installed scalar-command
interruption remains NOT RUN. Both records preserve their original artifacts and
complete reader predicates. Neither supplies M2, performance or release acceptance.

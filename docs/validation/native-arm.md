# Native ARM execution record

Coordinator execution, October 12, 2026 UTC (October 11 local). Source snapshot
`f4fc643192468526367f1ca34b96f78176cc5c8b`, published to the project repository.
This record concerns a hosted Linux ARM builder, not a Mac installation.

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

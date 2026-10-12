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

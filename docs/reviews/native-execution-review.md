# Independent native runner execution review

Reviewed October 11, 2026 local time; execution occurred October 12, 2026 UTC.
This review accepts the observed hosted native ARM runner probe for its bounded
purpose. It does not accept a builder bootstrap, package build, reproducibility
result, installation, M2 hardware requirement or milestone.

## Execution identity and integrity

Independently inspected retained local logs/evidence and read-only GitHub run/job
metadata for [run 38189013510](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38189013510):

| Field | Observed result |
| --- | --- |
| Event / attempt | `workflow_dispatch` / 1 |
| Source commit | `f4fc643192468526367f1ca34b96f78176cc5c8b` |
| GitHub run / job conclusion | Completed / success |
| Job runner label | `ubuntu-24.04-arm` |
| Runner group | GitHub Actions |
| Run created / updated | `2026-10-12T00:42:01Z` / `2026-10-12T00:42:16Z` |
| Input authentication / container build step | Explicitly skipped |
| Probe status | `native-runner-probe-pass` |
| Native package build / hardware validation | `NOT RUN` / `NOT RUN` |

The committed/local `scripts/ci/native_arm.py` SHA-256 matches both recorded
bootstrap-script hashes:
`1a48dfe768fa40595d84648750b1ada3c2a0c56fb2f00fa961e0e6d8fa6034ef`.
The recorded repository, commit and run ID match the independently retrieved
GitHub run metadata. The workflow log records all 45 CI boundary tests passing
on the runner before the probe; these remain bounded tests, not package builds.

Independently reconstructed the base64-framed bundle directly from
`artifacts/ci/38189013510/workflow.log`, verified its recorded size/hash, matched
the retained `native-probe.tar.gz`, and read archive members without extraction.
The archive contained exactly two regular files with safe relative paths, whose
bytes matched the retained decoded records:

| Retained object | SHA-256 |
| --- | --- |
| Bundle, 1,768 bytes | `58fdb394a78f03b9c75f54dac2a9fe86b3c5672aa2ed619318bceab0ba2df815` |
| `native-probe/result.json` | `be4bf6c2aed772278f09592db259c8cc0150f38919ad4987e1875a9afd0005f9` |
| `native-probe/runner.json` | `2553f5c374823db38548f5da0829b7f81ec9c4c78f2c18a899ec3b540f25df43` |

Local retained decoded directory:
`artifacts/ci/38189013510/decoded/native-probe/`. These ignored local copies and
the workflow log are execution evidence; the framing checksum is an integrity
check, not a package signature or independent hardware attestation.

## Accepted native runner observations

The actual runner record reports:

- Linux `aarch64`, kernel `6.17.0-1022-azure`; GitHub `RUNNER_ARCH=ARM64`,
  `RUNNER_OS=Linux` and image `ubuntu24-arm64` version `20261004.142.1`.
- Four ARM Neoverse-N2 logical CPUs according to `lscpu`.
- Page size 4,096 bytes.
- Non-root coordinator UID/GID 1001.
- Docker client/server `linux/arm64`; server architecture `aarch64`, Docker
  28.0.4, default local endpoint `unix:///var/run/docker.sock`.

These observations, the expected GitHub runner label and the successful checked
probe support **actual execution and availability of the intended hosted native
ARM VM route for this run**. This advances the runner-resource observation from
a source proposal to a recorded successful probe. It does not yet establish that
the signed ALARM builder image can be bootstrapped or execute the recipes.

The source probe rejects non-ARM host/daemon reports, root coordination and
remote Docker endpoints. No QEMU/binfmt setup or cross-build path ran in this
workflow. The evidence is normal provider/runtime provenance; no separate
cryptographic attestation of physical processors was obtained or claimed.

## Limits and pending execution

`result.json` correctly has `mode=probe`, null reviewed input/recipe hashes,
`native_build=NOT RUN` and `hardware_validation=NOT RUN`. The GitHub step record
and log independently confirm input authentication/build did not run. Therefore
this probe does not authenticate the frozen rootfs/dependency inputs, resolve
the builder transaction, produce an immutable builder image, build any package
or compare two artifacts.

The observed 4 KiB Neoverse VM is not an Apple M2 machine or a 16 KiB-page target.
It cannot pass M2 graphics/audio/input/networking/sleep, user lifecycle,
installation, public repository trust, boot/session recovery, performance/power,
both-size support, onboarding or maintenance acceptance. No package or hardware
status should be promoted from this result.

Build run `38189058133` was separately dispatched by the coordinator. Its
execution/artifacts are not assessed in this probe review. Review its actual
input/signature/bootstrap/package/rebuild evidence before accepting any native
package result; queued/dispatched state and a passed runner probe are insufficient.

No material inconsistency was found in the retained probe provenance. The
reviewer performed only local read/verification and read-only GitHub metadata
requests, edited only this document, and did not dispatch workflows, mutate Git,
download package/image/rootfs inputs or change the host system.

## First native build attempt: completed stages and strict failure

Independently reviewed [run 38189058133](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38189058133)
after completion. Read-only GitHub metadata confirms attempt 1, dispatched at
source commit `f4fc643192468526367f1ca34b96f78176cc5c8b`, the fixed
`ubuntu-24.04-arm` runner label, and overall **failure**. Created/updated times
were `2026-10-12T00:42:44Z` / `2026-10-12T00:45:27Z`. The input/build step failed;
bounded evidence retention succeeded. Native package acceptance is not granted.

### Independently checked retained evidence

Reconstructed the `native-evidence` bundle from the actual workflow log, verified
its framing checksum/size, matched the retained archive and compared all decoded
member bytes without extracting new files:

```text
bundle SHA-256: 56c9a66bbd3734aacff420dd7e2bd476cd3a7f13c0415c7c80dddb51ef2f91dd
bundle bytes: 762192
safe, regular file members checked: 33
```

Local decoded records are under
`artifacts/ci/38189058133/decoded/native-evidence/`.

The input lock bytes match the exact committed input file at the run's source
commit. Its hash matches the run result and bootstrap record. Independently
hashed the committed recipe lock and checked the run's recorded review pin:

| Reviewed input | SHA-256 |
| --- | --- |
| Input lock | `7d53775b2de6136d531a7f20059088def7bbb11ad8baef58e75cd5826e3a2b41` |
| Recipe lock | `8906c36f5cbcdb0e1e70798e6db23be1d30f45385d57af0094a1cd509c7a89d0` |

The retained cache-checksum map exactly matches all rootfs, package, signature
and keyring pins derived from that input lock. The recorded bootstrap-script hash
matches the committed source. The first container entry-script hash also matches
the committed script:
`89723f0a0b2ef80391160f451e877f15fb1e0c4d9a4fec6dbbb8e0d66d8d0f24`.

### Signed-input audit stage

Checked every retained signature receipt against the locked payload set:

- Exactly 249 receipts: the rootfs and all 248 dependency packages; none missing
  or extra.
- Every GPG command returned zero and names the matching payload/signature pair.
- Every receipt contains exactly one complete `VALIDSIG` for pinned primary
  `68B3537F39A313B3E574D06777193F152BDBE6A6`, with the same primary/signing
  fingerprint.
- No receipt reports bad/error/missing, expired-key/signature or revoked-key
  statuses. Recorded digest IDs are SHA-256/SHA-512 (`8`/`10`).
- All 248 retained signed-package metadata records match their locked names,
  versions, architectures, licenses, dependencies, provides, conflicts and
  replacements. The retained 165-package rootfs inventory matches its locked
  inventory exactly.

This supports the **actual runner-executed signed-input audit stage**. The
reviewer independently verified receipt completeness, identity, status and
cross-record bindings; original large input binaries were deliberately excluded
from the bundle, so this review did not independently rerun cryptographic
verification or rehash those original payloads. Their validation executed on the
runner through the hash-matched source and is recorded in these receipts.

### Native image/bootstrap stage

Bootstrap records and the actual Docker export log agree on:

```text
status: image-provisioned
image: sha256:d2ab65321238d7d8809d18de9703f184514e4a462ca8dbfa3df6b03e2d856b90
installed package count: 341
package lock SHA-256: 7f40e51da419514c3ffe4fc9ed5bd9d6f242e576a585347c4799cd20bfd32104
Dockerfile SHA-256: 629df4f94ef72a41e7ba1d7a9c6deabd152eca0de66848c46d03a14dfc2d7984
```

Derived the expected final name/version map independently from the 165 rootfs
records plus 248 transaction records. Its exact sorted 341-line inventory matches
`packages.lock`; its checksum matches bootstrap/provenance. The first container's
expected and actual inventories are byte-identical to that lock.

The recorded build is offline `docker build --network=none --pull=false
--platform=linux/arm64`. The subsequent first recipe container used this exact
immutable image ID, native mode, non-root `1001:1001`, network disabled,
read-only root, dropped capabilities and no-new-privileges. Its actual environment
reports `aarch64`, 4,096-byte pages and `makepkg (pacman) 7.1.0`. These runtime
observations and completed export support **actual native userspace bootstrap
and inventory checking**, subject to the existing provider/recorded-execution
limits. They do not certify an Asahi target transaction or an M2 boot image.

### Package gate failure

The first desktop attempt's nine retained recipe-input files match their recorded
hashes and review map. Its build log fails the strict reviewed-versus-generated
`.SRCINFO` check on `arch`/`url` line ordering:

```diff
- arch = any
  url = https://github.com/Gabriel-Kahen/cachy-asahi
+ arch = any
```

The container and build driver exit 1. There are **zero package archives** in
the retained bundle, and no second build/comparison or remaining-package attempts
are recorded. The overall result correctly remains `status=failed`,
`native_build=NOT RUN`, `hardware_validation=NOT RUN`. Successful input/image
stages do not turn this into a passed package build.

The coordinator routed the narrow source-metadata correction to the desktop
owner and retained strict comparison. This reviewer did not change source,
comparison policy, recipe/input locks, Git state or workflow dispatch. Corrected
and newly pinned source needs another actual complete run before package/native
milestone acceptance. No further material inconsistency was found in the reviewed
stage records; all target/M2/release acceptance gates remain separate.

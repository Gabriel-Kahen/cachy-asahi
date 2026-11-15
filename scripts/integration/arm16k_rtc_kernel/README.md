# RTC-enabled generic ARM16K reference: held source

This separate successor adds builtin PL031 RTC clock seeding to the exact
generic7.1.13 reference. **No configure, compiler, kernel build, container, native
dispatch or guest was run by this worker.** Root owns separate admission and
actual execution. The existing kernel, Asahi platform, guest/controllers,
workflows and manifests are unchanged. This is not M2 or release acceptance.

The original config disables RTC_CLASS. Root's actual serial instead reports
systemd advancing time to its2026-07-24 built-in epoch. A real RTC/current-UTC
prerequisite is missing. This does not establish the cause of the KSM import
failure. Its expired October TEST certificate also cannot be repaired by RTC;
fresh separately authorized signatures and actual diagnostic proof remain needed.

## Pinned derivation

Original Source `4056e2505ed7081674e949e0460258672cce14ff`, run39156901928,
is retained in `data/kernel-input.json` and the exact original build/source
receipts. Source archive: AsahiLinux tag `asahi-7.1.13-3`, revision
`94fb23346d522edf53722357c426a3e58030beea`,262965559 bytes,
SHA256 `874ef68d04ac8c831b90bb01a387cfabb58fceb60842c49a0d0e58bcd6c146ad`.
It already exists at
`artifacts/platform/kernel-history-20261012/linux-asahi-7.1.13-3.tar.gz`.
Original config:68789 bytes,
SHA256 `e97d54d4852eceb6cba28c38f78d4a00aacbfdb0c1523cb96366590f7eaa915b`.

`contract.py` preserves every unrelated config byte in the requested seed and
provides its exact byte inverse. The eight effective changes are RTC_CLASS,
RTC_LIB, RTC_HCTOSYS, RTC_INTF_SYSFS and RTC_DRV_PL031 to `y`,
RTC_HCTOSYS_DEVICE to `"rtc0"`, RTC_I2C_AND_SPI to `y`, and LOCALVERSION to
`"-generic16k-managed-gui-rtc1"`. Explicit `n` settings suppress SYSTOHC clock
writes, RTC_NVMEM and unnecessary proc/device interfaces. Exact retained Kconfig
proves RTC_CLASS selects RTC_LIB, PL031 depends on already-enabled ARM_AMBA and
sysfs depends on already-enabled SYSFS. All16K/MMIO/ext4/PAM prerequisites and
`MODULES=n` remain held. No PC bootloader or hardware detection is introduced.

The original native-aarch64 Ubuntu LLVM18 executable/provenance receipt remains
historical. This proposal uses a **NEW HOST_CROSS_ARM64 LLVM22.1.8 environment**;
there is no original-toolchain or reproducibility claim. Compiler-generated
facts must be captured by separately admitted configure-only, explicitly
reviewed/pinned by Root, then matched before/after compile. Every before value
is from ORIGINAL config; compiler facts are disjoint from RTC/LOCALVERSION.
No prefix-wide exemption or unprofiled config drift is accepted.

Actual Root configure r2 completed owned makeolddefconfig successfully and
closed HOLD on18 observed deltas. Exact upstream source classifies them as15
compiler/auxiliary probe facts, two prompted features that must remain off,
and one derived RTC helper. Explicit original-semantic-n seeds keep
ARM64_LSUI and WARN_CONTEXT_ANALYSIS off, without duplicate assignments or
inverse drift. Hidden RTC_I2C_AND_SPI cannot honor a user off-seed: held I2C=y
(SPI remains n) derives helper y. It selects/implies no driver and has no
Makefile object binding; only RTC_DRV_PL031 is enabled. This is the explicit
11th RTC prerequisite and eighth semantic feature change, not a compiler fact.

`data/configure-r2-facts.json` pins all18 Kconfig definitions,16 source-file
identities and relevant scripts. The allowlist contains exactly15 observed
probe names. CC_CAN_LINK y→n concerns cross-linked userspace, not the kernel
link. LD_CAN_USE_KEEP_IN_OVERLAY and OPENSSL_SUPPORTS_ML_DSA are real linker/
openssl capability probes; PAHOLE_VERSION0→132 comes from the actual auxiliary
tool. Explicit pahole/openssl/pkg-config executable, library and ALPM source
pins now join the pre/post guard. No installation or tool execution by this
worker was needed; Root must still capture/review fresh configure output.

## Small isolated host-/usr route

`actor-proposal.json` fixes the proposed domain. Reuse retained rootless image
`sha256:fcee73ea1b96e236248f53a213f71276cc9072d9025b58bce9915e32f19963ae`;
do not build a new tool image or change7052. Mount host `/usr` readonly, the exact
hash-pinned `/etc/ld.so.cache` readonly, and only the signed extracted ordinary
`bc` at `/tools/bin/bc` readonly. No host `/etc` directory, home, devices, caches,
package DB directory, credentials, signing homes or network are exposed.

The finite inventory records116 actual host ALPM dependency/source records,
their desc/files/mtree hashes,18 actual tools including bc,72 recursively
resolved ELF/interpreter/library files, cache provenance and architecture.
Five cached LLVM22 archive/signature pairs independently pass real `gpgv`.
The host package set is provenance for the readonly `/usr` bind, not a claimed
package transaction inside the older runtime image. No `--nodeps` or installation
occurs. Missing cached linux-api-headers/lz4/pahole archives are unnecessary in this
domain: their existing host `/usr` bytes/metadata are used and guarded.

Root authorized exactly two HTTPS GETs/no retries for official Arch bc1.08.2-1:
94205-byte archive SHA256
`b9e5f0d61a674c9be1a0608f3fcab766d989d9a002c37e55a74ccfc8e87027ab`;
119-byte signature verified under signing fingerprint
`E75CD4814A77AD943C7AB5A3E0959FEA8B550539`. Extracted bc is88760 bytes,
SHA256 `47b8f03536b5da0f5d5bf15d572ada3842b0e217a82eeb4bb0315cf7aef57dd9`.
Its four recursively resolved runtime dependencies are already in the72-file
host set. Only DATA was inspected; bc was not executed or host-installed.
Exact inputs/receipt are under this worktree's
`work/arm16k-rtc-bc-input-20261114/`; `data/bc-input.json` binds them.

Before and after **each** actual stage Root runs `host_guard.py`. Any changed
tool/library/cache/bc or116 ALPM metadata/file-table pin refuses. Root must
serialize host package changes: readonly bind protects against actor writes,
not concurrent host mutation. This is a distinct explicit bind domain, not an
immutable whole-host snapshot or an alias for the LLVM18/native context.

Use cap0/NNP/read-only root/networknone,2CPU/8GiB/256PIDs and a fresh8–16GiB
hard-capped exec/nodev/nosuid `/work` tmpfs. Source/objects remain there; only
bounded reports/config and the eventual bundle persist through `/outputs`.
Original source is bound readonly without copying. Additional home footprint
is under1MiB of new public bc/source metadata; no image layer/full116-package
rootfs is needed. The existing263MB source remains retained. Persistent stage
output is capped64MiB; command output16MiB each, whole source work3600s, outer
proposal3800s. Tmpfs counts against the8GiB memory cap and may honestly OOM;
Root reviews actual global memory/headroom and custody before admission.

## Root-only two stages

Source/DATA controls:

```sh
python3 -I -B -Werror::ResourceWarning scripts/integration/arm16k_rtc_kernel/test_controls.py
python3 -I -B scripts/integration/arm16k_rtc_kernel/test_interop.py \
  --consumer /absolute/corrected/arm16k_project_lifecycle_rtc/contracts.py \
  --consumer /absolute/corrected/arm16k_c01_workflow_rtc/contracts.py
```

Actual40 actor-fenced controls and eight producer-to-corrected-consumer modeled
joins pass. The model's synthetic Image is test DATA, never a compiled artifact.
The corrected consumer body is pinned at7464 bytes,
SHA256 `e7d3d8f0ecc6e4991ffaf3e2459a2034acf46609de6416376a74573477143fe2`;
the C01 counterpart is8015 bytes,
SHA256 `c78861dbf1b1cde14484a7c335468174f78547399034022cffc5a4a97e458ebb`.

Root's actual configure r1 subsequently closed **HOLD**: source extraction
completed100117 members/1589202874 logical bytes, but the original wrapper
passed a regular log file as the held helper's pipe/socket-only `log_fd`.
The helper refused after Popen; no natural child retirement or accepted
configuration is credited. Root independently removed the owned container and
passed its full host pre/post guards. The closed r1 output remains unchanged.

The correction prevalidates helper parameters before Popen, supplies
`log_fd=None`, captures at most16MiB in memory and writes the regular log only
after supervision. An exceptional pre-transfer refusal retires the same child
through the held helper; it never reruns argv or reenters released ownership.
Command retirement is recorded before potentially failing log writes.
Root authorized the bounded ordinary-host smoke; it passed before and after
the final exception-scope refinement (four benign children total). Each run uses
two benign isolated Python-print
children,34 combined bytes/0.137s, both reaped with `EMPTY_TWICE`; the injected
pre-transfer refusal remains a failed command. Limit5s/64KiB. This exercised no
kernel/package/configure/VM payload and grants no new configure admission.

```sh
python3 -I -B scripts/integration/arm16k_rtc_kernel/test_helper_smoke.py \
  --owned-process /absolute/pinned/owned_process.py --output /absolute/FRESH-smoke.json
```

Root first captures fresh host provenance and a **pending** profile:

```sh
python3 -I -B scripts/integration/arm16k_rtc_kernel/host_guard.py \
  --output /absolute/FRESH-before.json --profile-template /absolute/FRESH-profile.json
```

Root independently reviews/adopts the explicit domain/resource/mount tuple,
sets actual profile `status=ROOT_REVIEWED_NEW_TOOL_ENVIRONMENT` and
`runtime_closure_reviewed=true`, pins its exact SHA and retains the unchanged
environment digest. Those fields alone grant no resource/actor authority.
Inside the separately admitted exact container, the literal configure command is:

```sh
/usr/bin/python3 -I -B /recipe/build.py --allow-kernel-source-execution \
  --stage configure --archive /inputs/linux.tar.gz \
  --tool-profile /inputs/tool-profile.json --tool-profile-sha256 ROOT_ACTUAL_SHA \
  --owned-process /inputs/owned_process.py --output /outputs/FRESH-configure
```

Retain `config`, `configure-result.json`, observed config/delta, logs and complete
owned-command retirement; Root retires its container and runs the post-guard.
Even rejected config DATA is retained outside ephemeral `/work`. Root then
reviews the finite candidate compiler facts and pins the exact actual result.
Compile uses a fresh container/workspace and updated profile, with unchanged
image/tool/package environment; its new pre-guard report can have a fresh time.

```sh
/usr/bin/python3 -I -B /recipe/build.py --allow-kernel-source-execution \
  --stage compile --archive /inputs/linux.tar.gz \
  --tool-profile /inputs/tool-profile.json --tool-profile-sha256 ROOT_ACTUAL_SHA \
  --configured-result /inputs/configured-result.json \
  --approved-config /inputs/approved.config \
  --owned-process /inputs/owned_process.py --output /outputs/FRESH-compile
```

It reruns configure in the new stage, requires exact approved config bytes/facts,
then runs only `make -j2 Image`, checks final config/release/16K header and emits
exactly `Image`, `config`, `bundle.json` under `bundle/`. There is no install,
modules_install, guest, workflow dispatch, private key or implicit retry.
Existing pinned owned-process supervision is imported unchanged; Root also
enforces whole-container ownership, outer cancellation/retirement and cleanup.

`bundle-contract.json` matches the separate RTC lifecycle consumer. It projects
source.archive to bytes/SHA only and preserves separate exact RTC+LOCALVERSION
and reviewed compiler deltas. New build/configure/guest and resource fields
remain **NOT RUN/NULL** until Root's genuine corresponding acts complete.
Guest current-UTC/RTC/PAM behavior, KSM trust cause, native16K, M2, performance
and release remain unqualified. Kernel GPL-2.0 source notices/licenses are
retained separately from MIT implementation code; no distribution/legal approval
is inferred from a local build proposal.

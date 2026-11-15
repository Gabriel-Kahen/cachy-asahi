# Held C01 correctness journey for the ARM16K reference

This finite successor is **source/preparation support, not a guest result**.
It uses the already qualified111-package generic ARM16K systemd reference,
installs the two retained C01 baseline/LTO packages with normal signature-required
ALPM, runs UID1000 correctness checks, removes them and verifies restoration.
No compilation, new upstream acquisition, raw preparation, VM launch or retained
package execution occurred during this implementation.

## Exact packages and separate TEST signing

The [historical native4K result](../../../docs/validation/arm-c01-installable-native-20261027.md)
remains on Source `d33e595a10acf2d148752ea382ae607283fc0b73`, run40468241048.
Its project packages were **unsigned**: delivered `package_variants.py` sets
`BUILDENV=(!distcc !color !ccache check !sign)` and `SigLevel = Never` /
`LocalFileSigLevel = Never`. Upstream bootstrap signature evidence does not
authenticate signatures on these produced packages. That original evidence and
its private-prefix correctness result are preserved unchanged.

| Selected retained member | Ordinary archive name | Bytes | SHA256 |
| --- | --- | ---: | --- |
| `package-output/baseline-r1-1.pkg.tar.xz` | `cachy-asahi-zlib-baseline-1.3.2-1-aarch64.pkg.tar.xz` |1730592| `30a5de643b71603d1158982163a0560841fda50c2bd68f7cbbfea81403451924` |
| `package-output/lto-r1-1.pkg.tar.xz` | `cachy-asahi-zlib-lto-1.3.2-1-aarch64.pkg.tar.xz` |2136328| `0bf11d89052f419546ea43d922b1d5eb36ca2f2e6612971750442f77ff57a084` |

Root created **fresh disposable TEST signatures over those unchanged bytes**,
without rebuild or backdating. Only the detached signatures and public key enter
this family; the worker never generated or accessed a private signing key.
Signer: `28883796E039C3CC08603F3EFD56E30AF1115613`. The public Root receipt is
`artifacts/development/orchestrator-resume-20261114/c01-new-test-signatures-r1/Root-signing-receipt.json`.
`inputs.lock.json` pins every public material, that receipt, original native
association, successful base boot, raw/kernel inputs and unchanged reference
controller/process sources. No original-CI project-signature claim follows.

Each package has14 regular payload files, no scriptlet/hook and only `depend =
glibc`. The signed-rootfs111 selection already contains
glibc2.43+r22+g8362e8ce10b2-2. All six runtime ELF64 AArch64 files have16K-compatible
LOAD geometry; each uses `/lib/ld-linux-aarch64.so.1` and exactly `libc.so.6` /
`ld-linux-aarch64.so.1`, without RPATH/RUNPATH. No extra dependency package,
compiler, Python or system-zlib replacement is needed: **111→113→111**.
Structural ELF checks are not runtime execution proof.

## Journey and held prerequisite

The KSM signed-lifecycle trial has an unresolved actual GPG/trust HOLD. Both
`prepare.py` and `boot.py` require an explicit SHA-pinned **genuine successful
Root KSM signed install/remove report**, including111 restoration, ordinary
hooks/scriptlets and private TEST-trust removal. HOLD/missing/changed receipts
refuse before output/raw creation or first-use markers. A supplied receipt is
not itself resource authority; Root separately reviews/adopts this source and
admits its preparation and fresh boot. Never manufacture or relabel a result.
If the diagnosis requires a functional trust-path correction, that correction
must also be reviewed for this successor before admission; a successful receipt
does not silently update these frozen source bytes.

Preparation sparsely clones the original raw only after those gates, uses a fresh
nonce/password/machine ID/filesystem UUID and injects bounded fixture DATA.
The old raw/first-boot marker and prior KSM inputs remain untouched. The owned
offline container uses existing exact tool image
`sha256:ee1aa3da22a5d89dc1bc273fa818b1d996b7e62851f50d7b629144f6bba9f207`,
read-only input/code mounts, no network/devices/capabilities, NNP,2CPU/3GiB/256PIDs,
64MiB scratch,360s stage/600s outer deadlines and800MiB output cap. No tool image
build or new cache layer is required. Public package materials total about4MB;
corpus DATA is under512KiB. The retained base raw is1.5GiB logical, about617MB
allocated. Root must account for retained attempts and separate host/tmp reserves.

The guest oneshot imports only this public TEST key into private guest trust,
requires exact signature status, and uses `Required TrustedOnly` for ordinary
`pacman -U` / `pacman -R`. There is no `--nodeps`, assumed dependency, clock
backdating, signature exception, hook masking or scriptlet suppression.

The UID1000 workload performs two installed-prefix probes (21 roundtrips and42
internal negatives each),42 encodes over seven deterministic inputs including
empty/binary and16383/16384/16385-byte boundaries,84 cross-variant strict decodes,
42 independent system-GNU-gzip decodes and six exact exit2 invalid-input checks.
Invalid outputs must still equal the114688-byte reference; exit3/timeouts fail.
All outputs use exact binary equality, including NULs/trailing newlines. Every
command has a timeout; the workload has180s and service240s outer bounds. A private
UID1000 temporary directory is removed by its ownership-checked trap.

The preserved lifecycle records exact113 inventory,28 payload hashes/modes/owners,
full original package DB/payload/xattrs and user configuration/data sentinels.
Removal must restore111 and remove exclusive payload paths. Ordinary ldconfig
hooks run; only known unowned generated caches are restored afterward. Private
TEST trust is removed on success. Failure remains HOLD and earns no inverse claim.

`boot.py` imports the unchanged ARM16K controller/actor/custody and checks a
distinct fresh operation/marker plus exact28-field C01 result. It does not create
a new supervisor. Normal PAM login/logout and QEMU/container retirement remain
mandatory. Existing limits remain virt/TCG2CPU1536MiB, no NIC/display/KVM/passthrough,
480s actor/420s controller,1MiB serial and256MiB overlay. QMP quit after logout
does not qualify guest poweroff.

## Actual checks and Root-only future commands

Twenty actor-fenced DATA controls pass on Python3.14.7. They exercise complete
frames/counts, every result invariant, each restoration category, duplicate/stale
frames, unsigned/missing/changed materials, unresolved/wrong trust receipts,
binary boundary/invalid fixtures and custody/trust ordering. Python AST and
`bash -n` checks pass. No package bytes execute in these controls.

Actual `inspect.py` independently verifies both new signatures with real host
`gpgv`, exact archive/28-file/6ELF metadata and dependency closure. An actual
read-only audit of the exact signed-rootfs selection verifies all34 baseline
external tools, their selected package ownership and symlink resolution. These
DATA results are not a guest GPG/ALPM/runtime result.

```sh
python3 -I -B -Werror::ResourceWarning scripts/integration/arm16k_c01_workflow/test_controls.py
python3 -I -B scripts/integration/arm16k_c01_workflow/inspect.py \
  --materials /absolute/public-C01-materials \
  --base /tmp/cachy-asahi-arm16k-preparation-20261114-r5/assembly \
  --output /absolute/fresh-data-report.json
```

Only after Root resolves/reviews the prerequisite and resource contract:

```sh
python3 -I -B scripts/integration/arm16k_c01_workflow/prepare.py \
  --allow-prepare-project-lifecycle \
  --reference-root /absolute/unchanged/arm16k_systemd_tcg_guest \
  --trust-prerequisite /absolute/Root-successful-KSM/project-lifecycle-report.json \
  --trust-prerequisite-sha256 ROOT_ACTUAL_RECEIPT_SHA256 \
  --materials /absolute/public-C01-materials \
  --rootfs /tmp/cachy-asahi-arm16k-inputs-20261114/rootfs.tar.gz \
  --base /tmp/cachy-asahi-arm16k-preparation-20261114-r5/assembly \
  --base-first-boot-report /tmp/cachy-asahi-arm16k-first-boot-root-20261114/report.json \
  --output /tmp/FRESH-C01-PREPARATION
python3 -I -B scripts/integration/arm16k_c01_workflow/boot.py \
  --allow-first-arm16k-project-lifecycle \
  --reference-root /absolute/unchanged/arm16k_systemd_tcg_guest \
  --trust-prerequisite /absolute/Root-successful-KSM/project-lifecycle-report.json \
  --trust-prerequisite-sha256 ROOT_ACTUAL_RECEIPT_SHA256 \
  --prepared /tmp/FRESH-C01-PREPARATION/assembly \
  --prepared-sha256 ROOT_ACTUAL_PREPARED_SHA256 \
  --output /tmp/FRESH-C01-FIRST-BOOT
```

These preparation/boot commands have **NOT RUN**. Actual emulated16K correctness,
native16K, M2, performance, supported composition and release acceptance remain
unqualified. No speed comparison, optimization selection or timing gain is claimed.

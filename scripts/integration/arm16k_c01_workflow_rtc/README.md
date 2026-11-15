# RTC-gated ARM16K C01 correctness successor

This NEW source family is **not prepared or booted**. It preserves the frozen
C01 source and closed KSM trials. No image build, kernel compile, VM/native actor,
package payload, private signing key or external publication ran during this task.

The existing native C01 packages were originally unsigned. The new Root TEST
signatures are a separate current lineage over their unchanged bytes, without a
rebuild, backdating or production-trust claim. The exact two archives remain:

| Archive | Bytes | SHA-256 |
| --- | ---: | --- |
| cachy-asahi-zlib-baseline-1.3.2-1-aarch64.pkg.tar.xz |1730592|30a5de643b71603d1158982163a0560841fda50c2bd68f7cbbfea81403451924|
| cachy-asahi-zlib-lto-1.3.2-1-aarch64.pkg.tar.xz |2136328|0bf11d89052f419546ea43d922b1d5eb36ca2f2e6612971750442f77ff57a084|

`inputs.lock.json` pins the five public materials and2169-byte Root signing
receipt SHA `f9a815180eb224972fcf8a331cba29455d80b8093ee54b5663690f47ddeaf600`.
The417-byte public certificate signer is
`28883796E039C3CC08603F3EFD56E30AF1115613`. Its actual creation1794713061 and
expiry1795317861 were read as DATA using trusted host GPG show-only/dry-run in a
fresh private keyring. The public receipt pins that certificate but does not
itself declare key dates. The source records this distinction explicitly.
Host current UTC is checked against those dates at preparation, admission and
actor start. Ordinary guest GPG/ALPM temporal/trust policy remains enforced.
Private operator paths from the public signing receipt are projected out.

The exact read-only archive audit in this task reconfirmed28 regular payload
files, six runtime AArch64 ELF objects with16K LOAD geometry and existing
glibc2.43+r22+g8362e8ce10b2-2 as the only declared dependency:111→113→111.
This is DATA inspection, not execution, signature authentication or native16K.

## Mandatory genuine KSM prerequisite

Preparation and boot require a separately SHA-pinned, actual successful Root RTC
KSM receipt. `authority.template.json` leaves that receipt and actual RTC kernel
bundle null and refuses. The new authority kind is
`ARM16K_C01_RTC_AUTHORITY_V1`; it binds the actual KSM receipt, built kernel
bundle.json, distinct actor and unchanged host-tool image. No actual KSM PASS
receipt was supplied or manufactured in this implementation.

The accepted KSM receipt is schema_version1 with exact status
`PASS_EMULATED_ARM16K_RTC_SIGNED_PROJECT_INSTALL_REMOVE_ONLY`. All39 project
fields pass the frozen KSM RTC parser:30 original lifecycle/restoration
invariants plus nine current-clock/durability fields, including integer actual
clock fields. Actual ordinary UID1000 PAM/systemd/logind/DBus session, logout,
QMP quit, reaped QEMU, empty group census, complete output and owned-container
removal/absence are required. Cancellation/cleanup errors refuse. A successful
status with HOLD project data refuses; old bare status/HOLD receipts cannot be
relabelled. These are content checks; genuine provenance comes from Root's
independent exact receipt pin and admission, not the modeled unit fixtures.

Both prerequisite and RTC/signing gates precede output creation or first-use
markers. A later boot authority may change allow_prepare/allow_boot flags while
keeping every checked kernel/tool/actor/clock/KSM receipt contract identical.

## Pinned RTC actor and unchanged workload

`origin.json` pins the frozen C01 source snapshots under `frozen/c01/` and all
referenced RTC KSM source bytes through the exact helper-corrected per-file pins. The latter explicitly
allows exactly the LOCALVERSION metadata transition
`"-generic16k-managed-gui"`→`"-generic16k-managed-gui-rtc1"`, separate from eleven RTC
options and finite externally reviewed compiler facts. Non-RTC feature drift
still refuses; no compiler-prefix exception exists.

The built RTC kernel remains an external exact three-file bundle. No old Image
fallback exists. RTC0 must actually initialize the clock (hctosys1), identify the
PL031 device and advance while matching system and live host UTC **before**
crypto. The informational command-line host epoch never sets guest time.

The C01 actor is explicitly separate: mounted `/inputs/rtc_actor.py`, distinct
C01 environment/operation/labels/marker and `-rtc base=utc,clock=host`. Its exact
new source pin is required by Root authority and prepared files. OwnedContainer
first requires that mounted actor Cmd, then reuses the frozen exact custody and
resource validator; it does not accidentally admit `/opt/vm_actor.py`.
Frozen owned process supervision, cancellation and cleanup remain mandatory.

The byte-identical UID1000 C01 workload retains two installed probes (21
roundtrips/42 internal negatives each),42 encodes,84 cross-decodes,42 independent
GNU-gzip decodes and six strict exit2 invalid-input checks. Inputs include empty,
binary and16383/16384/16385-byte boundaries. Exact binary equality, invalid-output
preservation and cleanup remain required; timeouts/exit3 refuse. No performance
comparison or gain is measured.

The fixed four GPG operations are import, ownertrust, baseline verification and
LTO verification. Only this current public key is imported. Status/stderr/key
receipts remain private and≤32KiB per leaf. Capture and failure metadata use
actual sync-f; the final bounded disk summary/nonce and durability field are
flushed before publishing terminal state. A sync failure prevents terminal PASS.
Normal Required/TrustedOnly ALPM hooks/scriptlets run; removal must restore111,
all package DB/payload/mode/owner/xattr categories and user-owned sentinels.

## Commands and current results

Actual source verification:

```sh
python3 -I -B -Werror::ResourceWarning scripts/integration/arm16k_c01_workflow_rtc/test_controls.py
```

39 actor-fenced DATA/model controls pass. `RESULTS.json` records this source
profile and keeps the earlier control counts as historical profiles. Subprocess, socket, CDLL, fork and exec
actors are blocked during this suite. Bash syntax checks pass separately. Tests
use ephemeral modeled receipts only and publish no actual admission receipt.
RTC KSM controls remain a separately reported source/host-shell profile.

Future commands below are **Root-only and NOT RUN**. Supply actual independently
reviewed pins and a genuine completed KSM RTC receipt; pending template values
must not be replaced with modeled results.

```sh
python3 -I -B scripts/integration/arm16k_c01_workflow_rtc/prepare.py \
  --allow-prepare-project-lifecycle \
  --authority /path/to/Root-C01-prepare-authority.json --authority-sha256 ACTUAL_SHA \
  --kernel-bundle /path/to/actual-built-rtc-bundle \
  --signing-receipt /path/to/c01-new-test-signatures-r1/Root-signing-receipt.json \
  --trust-prerequisite /path/to/actual-Root-RTC-KSM/report.json \
  --trust-prerequisite-sha256 ACTUAL_KSM_RECEIPT_SHA \
  --materials /path/to/unchanged-public-C01-materials \
  --rootfs /tmp/cachy-asahi-arm16k-inputs-20261114/rootfs.tar.gz \
  --base /tmp/cachy-asahi-arm16k-preparation-20261114-r5/assembly \
  --base-first-boot-report /tmp/cachy-asahi-arm16k-first-boot-root-20261114/report.json \
  --output /dev/shm/NEW-C01-RTC-PREPARATION

python3 -I -B scripts/integration/arm16k_c01_workflow_rtc/boot.py \
  --allow-first-arm16k-c01-rtc-workflow \
  --authority /path/to/Root-C01-boot-authority.json --authority-sha256 ACTUAL_SHA \
  --kernel-bundle /path/to/actual-built-rtc-bundle \
  --baseline-config /tmp/cachy-asahi-arm16k-preparation-20261114-r5/assembly/kernel.config \
  --signing-receipt /path/to/c01-new-test-signatures-r1/Root-signing-receipt.json \
  --trust-prerequisite /path/to/actual-Root-RTC-KSM/report.json \
  --trust-prerequisite-sha256 ACTUAL_KSM_RECEIPT_SHA \
  --prepared /dev/shm/NEW-C01-RTC-PREPARATION/assembly --prepared-sha256 ACTUAL_SHA \
  --output /dev/shm/NEW-C01-RTC-ROOT-RUN
```

Resource proposal is unchanged: rootless cap0/NNP/read-only/network-none host
container2CPU/3GiB/256PIDs; virt/TCG2CPU1536MiB guest;600s preparation Runner,
360s assembly,420s controller/480s actor;800MiB preparation cap and256MiB overlay.
Require≥3GiB free on the explicit output parent filesystem before preparation,≥2GiB reserve afterward and2GiB plus
overlay reserve before boot. No NIC/KVM/host services/devices or host trust
mutation. Originals are read-only; nonce/password/machine ID/filesystem UUID and
attempt marker are fresh. Root owns aggregate resource and actual actor admission.
Actual RTC boot/correctness, native16K, Apple/M2, source/legal completeness,
maintained composition and release acceptance remain separate open gates.


RTC_I2C_AND_SPI=y is now an explicit derived11th RTC requirement. Its pinned
hidden Kconfig default follows the existing held I2C=y; SPI remains off. It has
no select/imply or rtc.Makefile object binding and enables no additional driver.
`inputs.lock.json` binds those original source hashes and the expected eight-field
feature delta. The frozen C01 workload and all genuine RTC KSM PASS prerequisites
are unchanged; this correction supplies no actual PASS/kernel/prepare receipt.

Producer→both-consumer interoperability also passes the producer's actor-fenced
`test_interop.py` (four controls per consumer): complete RTC11/8-feature bundle,
extra archive field refusal, omitted LOCALVERSION refusal and wrong compiler
before-value refusal. A separate pure construction check restores the exact full
baseline bytes through the producer inverse. Synthetic temporary Image headers
are model DATA only; no actual built kernel or admission receipt is produced.


Preparation accepts an explicit fresh private leaf under exactly `/tmp` or
`/dev/shm`, using the established RTC KSM path/capacity helper unchanged. It does
not choose a fallback root or create missing parent trees. Existing outputs,
relative paths, `..`, prefix lookalikes, symlink ancestors/leaves and nonprivate
or wrong-owner nested parents refuse. The leaf is created0700 under the existing
077 umask; nested parent directories must already be user-owned and private.
The3GiB gate measures the actual existing output parent filesystem, preserving
the2GiB reserve,800MiB preparation cap and separate512MiB /home Docker reserve.
Root must verify its exact rootless daemon can read the selected private bind.

The genuine RTC KSM PASS prerequisite still runs before output validation or
creation; a new actor-fenced HOLD control proves that ordering. Built bundle,
current UTC/signing/Source gates, all seven exact mounts, resource limits,
credentials/nonces/markers and actor bytes are unchanged. No output directory,
raw image, preparation or VM was produced in `/dev/shm` by this source task.
The destination remains Root's explicit choice and actual preparation/boot still
requires separate genuine Root admission.

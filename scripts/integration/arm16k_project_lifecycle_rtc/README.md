# ARM16K RTC project lifecycle successor

This separate source successor is **not prepared, built or booted**. It preserves
`arm16k_project_lifecycle/`, its consumed markers and all old results. The closed
trial established `NO_PUBKEY`, an initial July clock and unavailable persisted
receipt data; it did **not** establish the cause of the failed import. Old TEST
key/signature bytes remain historical, including their actual expired validity.

The intended workload is unchanged: the exact signed KSM0.1.0-1 archive plus
Python3.14.8-1 and mpdecimal4.0.1-3; ordinary Required/TrustedOnly ALPM install and
remove, real hooks/scriptlets,111→114→111 package inventory, exact baseline
payload/metadata/xattr/database restoration and user-owned sentinels. KSM help,
version/status/report and unprivileged mutation refusal are diagnostic software
checks. No KSM sysfs tuning, kernel-functionality or performance claim is made.

## Required independent inputs

`inputs.lock.json` pins the original passed111-package guest, signed ALARM
packages, unchanged17,244-byte KSM archive, historical lineage and new public
Root signing receipt. Fresh TEST signer is
`C98720061248F50811843544A8EC89D416F7A112`, created1794716090,
expires1795320890. Receipt1481bytes SHA-256
`fc30ea436c2541d626953ab221a4885a0d4041777aba1cabf216370a18ab5362`
binds the new417-byte public certificate and119-byte detached signature. No
private signing home is accepted. The receipt's operator paths are projected out
of actor inputs. Real host UTC must still fall within key validity at preparation,
admission **and** actor start; a stale preparation date cannot authorize a run.

A **built** external RTC bundle is mandatory, exactly `Image`, `config`,
`bundle.json`, using `ARM16K_RTC_REFERENCE_KERNEL_BUNDLE_V1` from the separate
`arm16k_rtc_kernel/` constructor. There is no old-Image fallback. The controller
independently checks file pins, little-endian ARM64/16K header, source lineage,
original baseline config and exact feature delta. Required built-ins are
RTC_CLASS/LIB/HCTOSYS/DRV_PL031/INTF_SYSFS/I2C_AND_SPI, HCTOSYS_DEVICE="rtc0";
SYSTOHC/NVMEM/INTF_PROC/INTF_DEV remain off.16K/AMBA/MMIO/ext4 and module-free
baseline remain held. Compiler facts must match a finite, externally reviewed
Root table; a compiler-prefix exception is not supported.

`authority.template.json` deliberately refuses. Root must independently supply
and SHA-256-pin an external authority with the actual built bundle.json pin,
exact `rtc_actor.py` pin, unchanged exact host-tool image ID, reviewed compiler
facts and the fixed clock policy. Preparation requires `allow_prepare:true`;
boot requires a separate explicit `allow_boot:true`. A later boot authority may
change these two flags while preserving every checked kernel/actor/tool/clock
contract. Pending fields are not invented here.

## Separate actor and clock contract

The host-tool image remains exact
`sha256:ee1aa3da22a5d89dc1bc273fa818b1d996b7e62851f50d7b629144f6bba9f207`.
This is an **explicit new actor variant**, mounted read-only at
`/inputs/rtc_actor.py`; it is not the old image's `/opt/vm_actor.py` entry.
The frozen owned-container cancellation/custody/cleanup methods and exact
owned-process reaper are reused read-only. Only this variant adds
`-rtc base=utc,clock=host` and an informational live-host UTC epoch to the kernel
command line. That epoch never sets guest time.

Immediately before container creation, the controller records actual host UTC
and monotonic time. Before QEMU starts, the actor requires≤30seconds elapsed,
UTC/monotonic agreement within5seconds and current TEST key validity. The guest
requires a genuine rtc0 with full sysfs name `rtc-pl031 9010000.pl031`,
hctosys=1, advancing RTC/system time,
RTC/system agreement within2seconds and actual-host agreement within the fixed
480-second actor budget plus5seconds. This runs **before** GPG/import/ALPM.
No date-setting, ignore-time, faked-time or trust relaxation option exists.
The full sysfs name includes driver and parent-device identity in the [exact
kernel source](https://github.com/AsahiLinux/linux/blob/94fb23346d522edf53722357c426a3e58030beea/drivers/rtc/sysfs.c#L22),
with the PL031 parent at0x09010000 in [pinned QEMU virt](https://github.com/qemu/qemu/blob/v11.1.3/hw/arm/virt.c#L195).
The expected full name is source-derived; actual guest confirmation is NOT RUN.

GPG status/stderr/key metadata remain fixture-private,≤32KiB per leaf, under the
five fixed operations. `sync -f` flushes each capture and derived failure receipt.
At finish, bounded summary and nonce are copied into the private disk directory,
byte-compared and flushed, then a durability field/final summary is flushed
again. Only after those actual syncfs calls succeed is `/run` terminal state
published for the ordinary user proof. A sync failure prevents terminal PASS;
the normal bounded controller cleanup remains mandatory. Whitelisted categories
and dates are exported; arbitrary stderr, UIDs, raw keys and credentials are not.

## Root-only future invocation

No command below was run as preparation or boot during this source task. Keep
all old inputs/markers closed. Use separate fresh output paths and actual Root
pins, never substitute the pending template.

```sh
python3 -I -B scripts/integration/arm16k_project_lifecycle_rtc/prepare.py \
  --allow-prepare-project-lifecycle \
  --materials /tmp/cachy-asahi-arm16k-project-lifecycle-inputs-20261114 \
  --rootfs /tmp/cachy-asahi-arm16k-inputs-20261114/rootfs.tar.gz \
  --fresh-signatures /path/to/ksm-new-test-signatures-r1 \
  --signing-receipt /path/to/ksm-new-test-signatures-r1/Root-signing-receipt.json \
  --kernel-bundle /path/to/actual-built-rtc-bundle \
  --authority /path/to/Root-prepare-authority.json --authority-sha256 ACTUAL_SHA256 \
  --base /tmp/cachy-asahi-arm16k-preparation-20261114-r5/assembly \
  --base-first-boot-report /tmp/cachy-asahi-arm16k-first-boot-root-20261114/report.json \
  --output /tmp/NEW-rtc-lifecycle-preparation

python3 -I -B scripts/integration/arm16k_project_lifecycle_rtc/boot.py \
  --allow-first-arm16k-rtc-project-lifecycle \
  --prepared /tmp/NEW-rtc-lifecycle-preparation/assembly \
  --prepared-sha256 ACTUAL_PREPARED_SHA256 \
  --authority /path/to/Root-boot-authority.json --authority-sha256 ACTUAL_SHA256 \
  --kernel-bundle /path/to/actual-built-rtc-bundle \
  --baseline-config /tmp/cachy-asahi-arm16k-preparation-20261114-r5/assembly/kernel.config \
  --signing-receipt /path/to/ksm-new-test-signatures-r1/Root-signing-receipt.json \
  --output /tmp/NEW-rtc-lifecycle-root-run
```

Preparation stages fresh public signing materials in its own directory and
reads the original guest/materials read-only. The actor receives only its sealed
prepared directory read-only and owned output read-write. There is no NIC, KVM,
host service/device or host trust mutation. Fresh nonce, password, filesystem
UUID and machine ID are independent of the consumed base.

## Resource proposal and verification

Each preparation or run: rootless cap0/NNP/read-only/network-none container,
2CPU/3GiB/256PIDs. Guest1536MiB/2TCG CPU; controller420seconds/actor480seconds;
overlay256MiB. Preparation Runner600seconds, assembly360seconds. Additional
preparation cap800MiB (sparse clone,14MiB materials and logs); future overlay is
separate. Require≥3GiB free before preparation and preserve≥2GiB free; boot
requires2GiB plus its256MiB overlay reserve. Root must review live aggregate RAM,
/tmp capacity, the actual built kernel and fresh actor contract before admission.
No preparation, kernel compile, image build, VM launch or package payload ran
in this source task. Prepared/kernel/guest result fields remain null or NOT RUN.

Run source controls:

```sh
python3 -I -B scripts/integration/arm16k_project_lifecycle_rtc/test_successor.py
python3 -I -B scripts/integration/arm16k_project_lifecycle/test_lifecycle.py
```

The43 successor controls include modeled bundle/clock/result/custody refusals,
actual private-host summary byte preservation and syncfs, sync-failure terminal
refusal, bounded mock GPG receipt/privacy checks and fresh signing date handling.
The46 unchanged legacy controls separately pass. Modeled RTC checks do not
establish an actual RTC boot. Native16K, Apple/M2, legal/source completeness,
release acceptance and KSM kernel functionality remain separate gates.


The11th required RTC state is the derived `CONFIG_RTC_I2C_AND_SPI=y` helper.
The pinned original `drivers/rtc/Kconfig` stanza949 is a hidden tristate with
`default y if I2C=y` (or SPI_MASTER=y), no select/imply. The held baseline already
has I2C=y and SPI=n; these buses stay unchanged. The pinned rtc.Makefile has no
helper object binding. This adds no bus or RTC driver; actual r2 configured only
RTC_DRV_PL031=y. The full expected feature delta is eight symbols, including
LOCALVERSION metadata. Any additional RTC driver/helper or bus drift refuses.
Producer source pins are rtc.Kconfig63685bytes/SHA
`de2295831bb5dace08e2823d136cf2e4995c499332e4f95dcd8a7e7fb161f403`
and rtc.Makefile8845bytes/SHA
`b4da20cbc38022dbd55356311867624b11564c7c96d8df4252471a4e3528dce0`.
Root's producer owns actual configuration/build; this consumer correction ran
source/model controls only and preserves all old trials.

Producer→both-consumer interoperability also passes the producer's actor-fenced
`test_interop.py` (four controls per consumer): complete RTC11/8-feature bundle,
extra archive field refusal, omitted LOCALVERSION refusal and wrong compiler
before-value refusal. A separate pure construction check restores the exact full
baseline bytes through the producer inverse. Synthetic temporary Image headers
are model DATA only; no actual built kernel or admission receipt is produced.

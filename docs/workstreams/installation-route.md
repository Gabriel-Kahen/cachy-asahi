# Installation route workstream

Ownership: `docs/port/installation-route.md`, this report, and any subsequently
assigned isolated `scripts/platform/` candidate. No shared manifests, frozen
integration sources, CI or Git state are owned here.

## Source audit result

October 11, 2026 local / October 12 UTC: completed the
[M8/R5 route audit](../port/installation-route.md). It proposes the established
Asahi installer plus an authenticated, release-defined Asahi ALARM/project
transaction. It records each boot/first-login/recovery responsibility, separate
trust boundaries, both model identifiers, upstream support limitations and the
remaining full-port acceptance gates. This is source-audited documentation;
installation, platform boot and physical recovery remain NOT RUN.

Reviewed current primary Asahi distribution/boot/platform/feature/device/FAQ/
partition documentation, the community ALARM site and pinned source repository,
upstream installer v0.9.2 source, and Apple's current firmware recovery guide.
The route document links sources at the corresponding claims. Refreshed served
bootstrap/data/latest hashes and the pinned bootstrap/tag source in read-only
Python HTTPS requests. Did not execute downloaded sources. The 16-MiB installer
archive probe refused its larger response, so it established no complete archive
hash or served-source correspondence. Later HEAD observed 22,215,962 archive
bytes; follow-up capture results are recorded separately below.

Live upstream bootstrap still follows mutable `latest` and unversioned rootfs
URLs, without explicit digest/signature checks in the reviewed bootstrap/data.
Hashes here establish observed identities, not independent authentication.
Reference tag source equality cannot be inferred for the served installer.
The source normal macOS floor is 13.5; expert 12.3 is excluded from the proposal.

Read the updated goal/roadmap, package audit inventories, acceptance contract,
existing overlay setup and release/client interfaces, and broader desktop/tool
coverage records. Documentation-only changes require link/consistency review,
not implementation tests. Current generic metadata/build evidence was kept
distinct from a target Asahi package inventory and physical runtime.

## Next data-only capture scope

Coordinator's follow-up assigns non-mutating retained installer/platform input
capture, with isolated new `scripts/platform/` ownership if implementation is
needed. This report records that candidate scope before adding files; frozen
initial sources and CI remain untouched. No production trust or installation
authority is introduced.

Observed disk budget: 106 GiB available in the workspace filesystem. Minimal
`asahi-base.zip` HEAD advertised 1,341,634,634 bytes. A strict HTTP 206 tail probe
found seven ZIP entries: directory markers, `esp/EFI/BOOT/BOOTAA64.EFI`,
`esp/m1n1/boot.bin` and `root.img`. Declared root image size is 3,680,501,760
bytes. Retaining the complete ZIP and an offline regular root-image copy needs
about 4.68 GiB plus installer/metadata/receipts; propose an 8-GiB hard ceiling and
private mode-0700 ignored `artifacts/` storage. No image was mounted/executed or
downloaded completely by this probe. Its range bytes are unauthenticated and
are not a retained baseline.

Capture must check limits/space first; stream hashes; retain source pins, licenses
and transport observations; read package descriptors/selected boot files without
installing or mounting; and distinguish source key identity, signature validity
and independently established owner trust. Read-only source review found an
available detached community repository DB signature; actual verification and
retained-input observations are reported below, separate from target acceptance.

## Candidate capture implementation and executed checks

[`capture.py`](../../scripts/platform/capture.py) and
[`sources.json`](../../scripts/platform/sources.json) are an isolated data-only
candidate. All 31 small source/metadata inputs have explicit HTTPS origins,
bounds, and source pins where observed. New capture destinations are restricted
to previously absent private workspace `artifacts/` directories. Worst-case
retention, including optional ZIP/decoded image, is checked against 8 GiB before
downloads. Individual transfers, decoded archives, member counts, metadata and
read-only subprocesses have limits. Source recipes and scriptlets remain data.
No installer, image binary, package transaction, mount, service, disk/boot write
or host keyring operation is performed.

Commands (absolute private paths required):

```sh
python3 -B scripts/platform/capture.py capture --output /ABSOLUTE/REPO/artifacts/platform/NEW --capture-upstream-data --capture-image
python3 -B scripts/platform/capture.py validate --directory /ABSOLUTE/REPO/artifacts/platform/NEW
python3 -B scripts/platform/capture.py complete-image-metadata --directory /ABSOLUTE/REPO/artifacts/platform/INCOMPLETE
python3 -B scripts/platform/test_capture.py
```

Without `--capture-image`, capture retains sources/installer/repository metadata
only. `validate` rechecks the source manifest, exact file set, retained hashes,
repository signatures, selected installer source correspondence and, when
present, ZIP-to-root/ESP derivation and image package metadata. Verification uses
fresh private GPG scratch and the explicitly pinned public certificate; it never
imports/trusts keys in a default home. `complete-image-metadata` is limited to an
incomplete capture that already retained the full ZIP/root/ESP and every source
input. It revalidates those bytes before rebuilding metadata, preserves the
original failure receipt, and atomically replaces the capture receipt. It does
not resume network transfers or claim power-loss recovery/durability. Failures
retain inspectable private data; no silent promotion occurs.

**51 owned fixture tests PASS**, plus Python syntax compilation. Tests include
HTTP limits/short responses/hash mismatches/cleanup, descriptor and source input
refusals, strict small ZIP handling, cryptographic status refusals, receipt
tampering/source-pin completeness, real `debugfs` listing syntax, flattened
installer layout, ZIP derivation and interrupted metadata completion. They use
tiny fixtures and mocked cryptographic/`debugfs` execution; actual source capture
and signature commands are separate observations below. No fixture certifies a
target installation or hardware behavior.

Actual retained source observations:

| Observation | Result |
| --- | --- |
| Complete served installer archive | 22,215,962 bytes; SHA256 `b35fdd7e5e700003bf4f43d2a484eca618ad971dd4266207315cbfa6fe826fad` |
| Decoded installer | 70,686,720 bytes / 1,369 logical tar members; never extracted/executed as a program |
| Flattened `./main.py` | Matches pinned upstream v0.9.2 main SHA `894fb8cd2ffc672bb96a14969ee9de2879d250c8c5990fee122ccf66d9b50024` |
| Community `.db` and `.files` signatures | Actual GPGV cryptographic verification PASS against pinned `12CE6799A94A3F1B5DDFFE88F576553597FB8FEB`; independent owner trust/freshness remains unaccepted |
| Key certificate source | `asahi-alarm/asahi-alarm-keyring` commit `5103f1eb621b54d7e6fe87070042c2d297878456`; SHA256 `bd5a05085bc9ec99bc17156e60f5c7f1cd29f2b550bb80f652e0ba4a4820d5b2` |
| Recipe source | `asahi-alarm/PKGBUILDs` commit `1c6daffd905c1b8f76202949ed48b80a4759ab73`; selected raw recipes/config retained as data |

The first complete-installer capture stopped at the initial 64-MiB decoded cap
and recorded `capture-incomplete`. The real decoded archive is about 67.4 MiB;
the reviewed cap is now 128 MiB. The served layout uses `./main.py`, with bundled
Python library `main.py` files that must not be mistaken for installer source.
Independent review also found `debugfs` directory entries use empty size fields;
fixtures and parser were corrected. The already-running fresh capture retained
the full image but reached its previously loaded parser and recorded the real
`malformed image package listing` refusal. The corrected
`complete-image-metadata` command revalidated all retained inputs and completed
metadata without another download. The exact prior failure receipt is preserved.

The actual community installer fork tag resolves to
`3cfef52bc372a7b84b59823027c75327e129d6ec`. Read-only raw commit downloads confirmed
its main/license hashes match the audited upstream files. This resolves the
source repository's identity; it does not prove complete archive provenance.

### Concrete source/rebuild issues

At the pinned kernel recipe revision, `linux-asahi/config` actually hashes to
`a8412899bac7e09fa870a382e3cb97264bc071e9714c509800fa36f256633e2b`, while the recipe
requires `d8769170a86c16d29ae7537c77d49c9b20074617ce3f10996cd8624b52b0f6f0`.
This revision is not claimed rebuild-ready. Its 16K-page/Apple DRM declarations
are source declarations, not execution evidence. Reconcile source/config and
then reproduce the signed package build before using it as port provenance.

The current community Mesa recipe explicitly builds x86 FEX overlays and
`mesa-dummy`; native aarch64 Mesa now comes from ALARM `extra`. Never use
`mesa-dummy` as the target graphics provider. Select the actual installed native
provider and compatible version in the target transaction rather than assuming
the builder's Mesa selection proves compatibility.

Source notices for installer, kernel, m1n1, U-Boot, audio, speaker protection and
Asahi scripts are retained. Complete third-party/copyleft obligations remain
unresolved: selected upstream binary package notice placement, bundled installer
Python/runtime components, keyring license source, firmware redistribution and
all transitive packages need review. Cryptographic agreement with the same
organization's fetched certificate is not independent custody/identity approval.

### Retained signed platform archives

Additional data-only capture under private
`artifacts/platform/signed-platform-20261012/` retained seven current upstream
archives and detached signatures, selected by the checksum-bound signed
community DB. All archive hashes match that DB; actual GPGV verification of each
archive returned the pinned primary fingerprint. Total archive bytes:
**32,081,160**. The receipt SHA256 is
`c0f093e209cc4bb94b6057380e444670232f0452768c71e6bd5201e59e290f7a`.
No package was installed or its scriptlets executed.

| Published package | Version | Archive bytes |
| --- | --- | --- |
| `linux-asahi` | `7.1.13.asahi3-2` | 29,795,800 |
| `m1n1` | `1.6.1-1` | 182,964 |
| `uboot-asahi` | `2026.07.asahi2-1` | 297,216 |
| `asahi-scripts` | `20260127.1-1` | 12,472 |
| `asahi-fwextract` | `0.9.2-1` | 51,208 |
| `asahi-audio` | `4.1-1` | 1,397,792 |
| `speakersafetyd` | `2.0.1-1` | 343,708 |

Actual bounded archive metadata inspection retained `.PKGINFO`, `.INSTALL` where
present, notice-file hashes and `.BUILDINFO` as data. Each decoded archive was
below 256 MiB and 20,000 logical members. `package-metadata.json` SHA256:
`910ffee18475e5e1bb2e56b8f4f568af267f66e24c0d7dce2f45029a8c9fb2bf`;
`buildinfo.json` SHA256:
`e98accda10711f0cf55a815550ac9208a7d72cfdfa3d1c911271c40aa643e986`.
The fwextract and Asahi scripts archives contain scriptlets; they were never
sourced/executed. Firmware extraction/ESP-writing behaviors need actual target
transaction review, not suppression in an installation guide.

Six packages' declared `.BUILDINFO` recipe hashes match the retained pinned
recipes. The published kernel declares recipe hash
`3d0f09f2ca7e579c1881b9b862f4f176f67f0227e6cfd7705a70d078e8379198`, while the
current pinned recipe hashes to
`721eb9a425d53739bebc4f74c5cf891151e190c5286d5131240a5e22c6ac8da0`.
At original capture this was an unresolved source-correspondence task. The
follow-up below identifies the matching historical recipe/config; a controlled
rebuild remains unexecuted. It does not prove the published binary was built
from the inconsistent current recipe. `.BUILDINFO` is signed-payload declared
metadata, not independent observation of its build execution.

These seven archives are a retained platform subset, not the complete base,
desktop/audio dependency closure or an accepted transaction. Missing conventional
notice paths do not alone decide legal compliance; retain and review full notices,
common-license dependencies and source obligations before redistribution.

### Complete minimal-image data capture

Actual x86_64 host inspection completed October 12, 2026 local,
`2026-10-12T04:28:39Z`. No aarch64 image binary or installer was executed. The
private directory is `artifacts/platform/m8-minimal-20261012-b/`, mode 0700; all
retained files are mode 0600. Total checksum-bound retained inputs/metadata:
**5,051,624,359 bytes** (about 4.70 GiB), below the 8-GiB ceiling. The earlier
failed installer capture and signed-platform subset add about 52.4 MiB. Total
actual retained directory bytes are 5,106,534,341 (about 4.76 GiB), below the ceiling.

| Retained data | Bytes | SHA256 |
| --- | --- | --- |
| `asahi-base.zip` | 1,341,634,634 | `42df228b8bb7a3fc980a94d1eca01bc44a4e29efaf002bf77ffac2fbc08bbbd7` |
| Offline regular `root.img` | 3,680,501,760 | `76f95dae6180bc4a45ffdeaccec26681d75b2207b90062064fcd2a845adbf9db` |
| `esp/m1n1/boot.bin` data copy | 6,212,622 | `566227f96ea94bafac65ee6c997da0ba98be6f20479c3619ba1b8b739d156f33` |
| `esp/EFI/BOOT/BOOTAA64.EFI` data copy | 221,184 | `17fb5f45a3eb340a8918bd3fdee92ebd3ec2c91d6ad186da427d59d7e1c6176a` |
| Image package inventory | 340,100 | `5c1630b5cdf07898118979895682c3a3b705e416c9840ada4e1a5193dccd6941` |
| Completed capture receipt | 17,366 | `9bb0a65b3b818dab1f271c41328b9c6dd1ee7cf636534c8669cfd262be26361b` |
| Preserved failed capture receipt | 16,915 | `fd3d6918b83eb659b1486bdb770b7547807e0b240295abdec8e9cdabfc49bb53` |

Read-only `debugfs` observed **261 unique installed package descriptors**, all
declaring `aarch64` or `any`. Their metadata/descriptor hashes are retained in
`image-inventory.json`, bound to the complete root image and ZIP. This is an
image inventory, not a physical-machine inventory or solved project transaction.

| Observed image platform package | Version |
| --- | --- |
| `linux-asahi` | `7.1.13.asahi3-2` |
| `m1n1` | `1.6.1-1` |
| `uboot-asahi` | `2026.07.asahi2-1` |
| `grub` | `2:2.16-3` |
| `asahi-scripts` | `20260127.1-1` |
| `asahi-fwextract` | `0.9.2-1` |
| `asahi-alarm-keyring` | `20241216-1` |
| `asahi-meta` | `5-6` |
| `asahi-configs` | `20251217-1` |
| `alsa-ucm-conf-asahi` | `10-1` |
| `tiny-dfr` | `0.3.7-1` |

The minimal image has **no Mesa, PipeWire, WirePlumber, `asahi-audio` or
`speakersafetyd`**. Their published availability or separately retained archives
cannot stand in for their presence or configuration. Add the complete protected
audio/graphics/desktop closure through the reviewed target transaction; do not
call this minimal image a complete desktop or speaker-safe session.

Actual final command:

```sh
python3 -B scripts/platform/capture.py validate --directory /home/gabe/Documents/ChatGPT/cachy-asahi/artifacts/platform/m8-minimal-20261012-b
```

Returned exit 0, `retained-bytes-and-repository-signatures-verified`, with
`installation_accepted: false` and `hardware_accepted: false`. It rehashed every
retained file, reverified both repository signatures, recomputed strict ZIP member
hashes/bindings and reread the image package metadata. Image authenticity remains
observed HTTPS bytes without an independently authenticated image signature;
current installed-package signatures/content and complete target ownership/hook
transactions were not verified by this image scan.

Candidate source hashes after 51 tests and syntax checks:

- `capture.py`: `ce73314eb5a75b8afb963217fba15065106ae3f6ee081599a1ba7ab620b044c8`
- `test_capture.py`: `84d4dcc47518978ae918dd8b72ab5390a2230686ad2c076862ab427917ea5da6`
- `sources.json`: `b327091970b391d41ffd2f30566a05758d13cc3a170cf1ddaf5e18f1e3edc8a6`

The small coordinator handoff
[`capture-observation.json`](../../scripts/platform/capture-observation.json)
records receipt locations/hashes, the observed image tuple, signed package subset
and explicit unaccepted gates. SHA256:
`a678585ad53d5271b558a2a7b279eb1505c6c00cd58a00a090c818dae7d7da38`.
The binary/source inputs remain private ignored workspace data; no release,
upload or Git commit was made.

The coordinator can now reconcile a finite target transaction against an actual
Asahi image inventory, rather than the 341-package generic builder. First
authenticate/accept the base inputs, recover signed exact-version package inputs
and file/hook ownership, resolve platform providers/full desktop closure and
review source/license/maintenance obligations. That next transaction remains
unaccepted. Physical boot, firmware provisioning, first login, audio protection,
installation/update recovery and both-model acceptance remain NOT RUN.

Frozen lifecycle SHA `e408a540765ede2350a57abd311e8814d516ab379351fe28751a20250a3a8461`
and setup SHA `a6251142b9c7e54796285c1a301fb590599d8aaa1625ea0bfebd7fc21622fdc2`
were rechecked unchanged. No initial frozen source, shared manifest, CI or Git
state was edited by this workstream. Root owns subsequent integration/commits.

## Historical kernel correspondence follow-up

October 12, 2026: the coordinator assigned a bounded primary-history audit and
protected tuple comparison. Findings correct the earlier source-gap description;
the original signed capture/image receipts remain unchanged. Upstream recipe and
config contents remain only in private ignored artifacts. Reports publish
original analysis, hashes and source references; no source lacking reviewed
distribution grants was published.

### Resolved recipe/config history

The signed package `.BUILDINFO` declares recipe SHA256
`3d0f09f2ca7e579c1881b9b862f4f176f67f0227e6cfd7705a70d078e8379198`.
This exactly matches
[`d585b07f4526f6c2d263ec8270387e684545a57f`](https://github.com/asahi-alarm/PKGBUILDs/commit/d585b07f4526f6c2d263ec8270387e684545a57f),
September 19, 2026, 16:02:37 UTC. The archive declares its build at 16:04:41 UTC;
time proximity supports chronology but does not prove build execution.

| History input | SHA256 / relevant result |
| --- | --- |
| September 19 recipe | `3d0f09f2ca7e579c1881b9b862f4f176f67f0227e6cfd7705a70d078e8379198`; matches signed `.BUILDINFO` |
| September 19 supplied config | `a66145c1b93002e47ae6a9ab09698b4ae4f202cdad09da5e87a6abad080a66aa`; SHA256 and BLAKE2b match historical recipe |
| September 29 recipe | `721eb9a425d53739bebc4f74c5cf891151e190c5286d5131240a5e22c6ac8da0` |
| September 29 config | `d8769170a86c16d29ae7537c77d49c9b20074617ce3f10996cd8624b52b0f6f0`; both checksums updated correctly |
| October 6 / original captured pin config | `a8412899bac7e09fa870a382e3cb97264bc071e9714c509800fa36f256633e2b`; recipe checksums stale |

September 29 commit
[`356454b49e45059b1dca34089c5a5ddba3dd29fe`](https://github.com/asahi-alarm/PKGBUILDs/commit/356454b49e45059b1dca34089c5a5ddba3dd29fe)
changed pahole version 131→132 and shared GPIO proxy module→built-in, updating
both config checksums without changing `pkgver`/`pkgrel`. October 6 commit
[`b6c99b08e5f6d9bad8e23b88db69570436471961`](https://github.com/asahi-alarm/PKGBUILDs/commit/b6c99b08e5f6d9bad8e23b88db69570436471961)
enabled the SN201202X Type-C driver without updating checksums. The original
captured recipe pin contains that latter mismatch. Between the historical and
later recipes only their two config checksum declarations differ. The historical
recipe/config pair is now retained and coherent; the later source pin remains
not rebuild-ready.

Actual commit-addressed raw downloads were checked against SHA256 and Git blob
IDs in private `artifacts/platform/kernel-history-20261012/`. Historical recipe
blob is `92f5c56a355b8bae965cdc6c5d8a03b167b20f36`; config blob is
`8d2a0a316bd3755e5962cb656fa7837affaff4e7`. The history capture receipt hashes to
`245e729e0623b6e879c36202f976e735c242d211482e7089508de322b1bf3f16`.

### Retained original source and binary/config observations

Retained the actual 262,965,559-byte kernel source archive named by the recipe.
Its SHA256 is
`874ef68d04ac8c831b90bb01a387cfabb58fceb60842c49a0d0e58bcd6c146ad`; computed
BLAKE2b also matches the historical recipe. Read-only `git ls-remote` resolved
tag object `c7f124eff1b928ae3e35aa0ca18356c4e2d15dce` to source commit
[`94fb23346d522edf53722357c426a3e58030beea`](https://github.com/AsahiLinux/linux/tree/94fb23346d522edf53722357c426a3e58030beea).
Source-archive receipt SHA256:
`befff441fdb8d63392a7276463f62b42c61173efe462d58eef7aadcf1521ebb2`.
No kernel build command or source/archive program was executed.

Reverified the signed kernel archive against the retained public certificate,
decoded the archive as bounded data, and read its `vmlinuz` member. Read the
matching image path with bounded read-only `debugfs` without mounting. The two
35,834,368-byte binaries are exactly equal, SHA256
`c9764582601a847d64943d1a19008c589e87b9e79c5ad416773dee6a8a05a17c`.
This proves that specific image kernel file equals the signed package member;
it does not verify every installed module, hook or firmware file.

The binary's embedded IKCONFIG decodes to 240,677 bytes, SHA256
`ae1d4ce855bd435b62c8fb213cbcf2d4eefd47b62274792c4a6bf299848b3876`.
It differs from the historical supplied config in exactly one line:
pahole version 131→132. `.BUILDINFO` declares pahole `1:1.32-1`. This is consistent
with generated configuration changing during preparation, but that preparation
has not been reproduced. GPIO proxy remains a module; the newer Type-C config
change is absent from this binary. No hardware capability is inferred from it.

The binary ARM64 header has magic `ARMd`, flags `12`, with page-size bits declaring
16K pages under the
[pinned Linux boot protocol](https://raw.githubusercontent.com/AsahiLinux/linux/94fb23346d522edf53722357c426a3e58030beea/Documentation/arch/arm64/booting.rst).
This is static binary metadata, not an observed 16K running kernel or M2 boot.

[`kernel-correspondence.json`](../../scripts/platform/kernel-correspondence.json)
binds all those source hashes, revisions, checksum comparisons and remaining
false acceptance gates. SHA256:
`5aa4a7efcd821cd497655072f9e04c71ed01480b2860a2bb7d8c72b610fb49d5`.
The additive updated [capture observation](../../scripts/platform/capture-observation.json)
hash is `a258431d65e9a5e15c7c61f0758e21867d3b0013d8a716408fdf7ab7bd2ddda7`;
its original `a678...` bytes are preserved privately as
`kernel-history-20261012/capture-observation-before.json`.

### Corrective steps and remaining external gates

- Use the exact historical recipe/config and retained checksum-matched source
  as the baseline reconstruction inputs. Do not silently use the later stale
  recipe with the same package version.
- Reproduce generated config and a controlled native build using the declared
  build environment/toolchain. Compare the resulting kernel/modules to the
  retained signed archive, recording limits. This was not run in this task.
- If choosing newer GPIO/Type-C changes, first reconcile checksums, use a distinct
  reviewed package revision, and integrate/test the complete compatible platform
  transaction. Do not edit the old published-package provenance to describe it.
- Image authentication/independent signer identity, complete installed payload
  verification, full target dependency/file/hook transaction, source distribution
  obligations, and ongoing release custody still need completion.
- Machine-specific firmware/stub/ESP provisioning, boot, runtime peripherals,
  first desktop, failed updates and recovery remain physical-target work on each
  Air size. Source correspondence and static 16K declarations cannot pass them.

### Protected tuple and finite transaction preparation

Implemented a separate offline, checksum-bound
[`tuple_audit.py`](../../scripts/platform/tuple_audit.py) and
[`test_tuple_audit.py`](../../scripts/platform/test_tuple_audit.py), both original
MIT project material. **26 tests PASS**, plus syntax checks. It uses only the
preinstalled libalpm version-comparison API; it does not initialize a package
manager handle or select/prepare/install a transaction. New report outputs require
an existing mode-0700 user-owned directory, exclusive mode-0600 creation and an
8-MiB serialization bound. Nothing is downloaded or installed by this audit.

Actual CLI:

```sh
python3 -B scripts/platform/tuple_audit.py \
  --image /home/gabe/Documents/ChatGPT/cachy-asahi/artifacts/platform/m8-minimal-20261012-b/image-inventory.json \
  --signed /home/gabe/Documents/ChatGPT/cachy-asahi/artifacts/platform/signed-platform-20261012/capture.json \
  --metadata /home/gabe/Documents/ChatGPT/cachy-asahi/artifacts/platform/signed-platform-20261012/package-metadata.json \
  --repository /home/gabe/Documents/ChatGPT/cachy-asahi/artifacts/platform/m8-minimal-20261012-b/asahi-alarm.db \
  --output /home/gabe/Documents/ChatGPT/cachy-asahi/artifacts/platform/kernel-history-20261012/tuple-report.json
```

Exit 0 produced a 489,978-byte report, SHA256
`92c53bc28d5442ac1780c0b54094a3bd99eb5a3dd89d069e94da82a2e8fc0030`. The four input
checksums are fixed in the CLI and retained in the report. Verification repeats
the `.PKGINFO` text checksums and compares the seven archives' identity,
dependency/provision/conflict/replacement fields to their retained repository
metadata. It does not repeat cryptographic signature verification; those actual
checks are separate retained capture evidence.

| Package | Minimal image version | Signed archive version | Metadata relation |
| --- | --- | --- | --- |
| `linux-asahi` | `7.1.13.asahi3-2` | `7.1.13.asahi3-2` | Same |
| `m1n1` | `1.6.1-1` | `1.6.1-1` | Same |
| `uboot-asahi` | `2026.07.asahi2-1` | `2026.07.asahi2-1` | Same |
| `asahi-scripts` | `20260127.1-1` | `20260127.1-1` | Same |
| `asahi-fwextract` | `0.9.2-1` | `0.9.2-1` | Same |
| `asahi-audio` | Absent | `4.1-1` | Addition required |
| `speakersafetyd` | Absent | `2.0.1-1` | Addition required |

Thus the five present packages are not older than this retained signed snapshot.
Their matching versions do not prove all installed bytes match archives; only
the kernel `vmlinuz` comparison above establishes that specific byte equality.

The 261-package image has **1,020 declared runtime dependency relations**, all
with name/version/provides witnesses in that same inventory. Two relations have
multiple witnesses: `ca-certificates` and `dbus-units`. The report retains every
witness and does not hide those choices behind a claimed solved transaction.
No file ownership, hook/service behavior or runtime ABI result follows.

The proposed protected roots are the observed `asahi-meta 5-6` platform set,
`grub 2:2.16-3`, `mkinitcpio 42.1-1`, `lzfse 1.0-1`,
`alsa-ucm-conf 1.2.16.1-1`, firmware set `20260916-1` and the installed
ALARM/Arch keyrings. Their all-witness installed dependency graph has **201
exact-version package records**, including the five boot/firmware packages,
Asahi keyring/config/radio/bless/fix helpers, UCM, tiny-dfr and split firmware.
Preserve this proposed baseline until the coordinator reviews any permitted
change. The graph is deliberately a metadata preservation proposal, not a
minimal installation closure or an independently authenticated platform policy.

Adding the seven-archive set includes the two absent audio packages, but still
needs audio dependencies. Signed community repository metadata identifies
`bankstown 1.1.0-2` and `triforce-lv2 0.3.2-1` as further candidates; their
archives were not retained/authenticated in this step. With those metadata
candidates, requirements still missing are `alsa-lib`, `lsp-plugins-lv2>=1.2.15`,
`lv2`, `pipewire>=1.0`, and `wireplumber>=0.5.1`. Full desktop preparation also
needs native Mesa/libdrm/Wayland/Vulkan/BlueZ and the broader release roots.
Do not substitute `mesa-dummy` or suppress dependencies to make a smaller
apparent transaction.

The small public original-analysis
[`protected-tuple-proposal.json`](../../scripts/platform/protected-tuple-proposal.json)
retains those exact proposed versions, comparisons, missing requirements, input
hashes and full report reference. Every transaction/authentication/installation/
hardware gate stays false. This is concrete input for the next signed complete
target transaction review, not permission to change a machine or shared manifest.
Proposal SHA256:
`2fbfe509dd851c201db9bb836078bf14c571e3a4c5336b29fc2fd102732f30c9`.

Frozen candidate source hashes:

- `tuple_audit.py`: `e2fde6832d57f33aca1b215f03350edab67d9b3c66d31b7062bc4b0df8d92b5d`
- `test_tuple_audit.py`: `c654f4d1d1cb932e192797175c5cee547168f2705f55532b3932157fdbca3aa8`

Independent read-only peer review repeated the kernel signature, source/config
hashes, Git blob IDs, source archive checksums, image/binary equality and embedded
config comparison, with no defect found. The source archive PAX comment also
names the pinned source commit. Actual retained platform workstream data after
this follow-up totals **5,370,984,945 bytes**, still below 8 GiB. Original capture,
setup and lifecycle source hashes remain unchanged; no shared manifests, CI or
Git state were edited.
The tuple report/proposal was also independently recomputed byte-for-byte and
reviewed for count/version/graph/limitation consistency, with no defect found.

Next source/metadata work can retain authenticated core/extra snapshots, select
explicit native graphics/audio providers and desktop roots, recover baseline
exact-version package archives/file lists/hooks, and perform a real read-only
libalpm transaction preparation with explicit platform-change policy. Full
source/build reconstruction, licensing, independent trust/custody and maintained
repository decisions remain required. Physical firmware provisioning, ESP
identity and actual boot/session/failure recovery cannot be inferred here.

## Remaining blockers

- Independent authentication/acceptance of the retained installer/image, complete
  source/license correspondence and signed target file/hook/dependency transaction.
- Complete M5–M7 package/function integration, production endpoint/trust and
  named ongoing maintainers/custodians.
- Independent macOS-to-desktop installation and normal/failure recovery on each
  physical M2 Air size, full acceptance and subsequent maintained release.

These are implementation/acceptance tasks, not reasons to reduce R5 to an
existing-system configuration overlay.

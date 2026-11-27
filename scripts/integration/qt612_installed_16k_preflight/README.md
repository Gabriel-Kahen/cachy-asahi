# Qtbase installed 16 KiB trial

This source-only preflight binds a future offline installation of
`cachy-asahi-qt612-gui-server-source-reference 6.12.0-2` to the exact original
Q3 scratch, configure closure, and 356-package inventory. Use a new writable
child of the Q3 scratch. The separate package build and staging guest supplies
the archive and never serves as the install target. The plan records the
expected clean 356 → 357 → 357 → 356 → 357 → 356 inventory.
[Q3 evidence](../../../docs/validation/qtbase612-emulated-arm16k-configure-20261118.md)
· [Packaging handoff](../qt612_full_16k_preflight/PACKAGING.md)

```sh
lane=scripts/integration/qt612_installed_16k_preflight
python3 -I -B "$lane/preflight.py" \
  --q3-terminal "$Q3_TERMINAL" --q3-scratch "$Q3_SCRATCH" \
  --q3-inventory "$Q3_INVENTORY" --nonce "$FRESH_NONCE" > "$PRIVATE_PLAN"
python3 -I -B "$lane/preflight.py" --emit-consumer-cmake > "$PRIVATE_CONSUMER/CMakeLists.txt"
python3 -I -B -Werror::ResourceWarning "$lane/test_preflight.py"
```

Add `--output "$PRIVATE_STAGE"` to the first command to stage the exact
plan and original inventory, both consumer sources, and the loader probe
under `inputs/`. The command places the emitted ALPM configuration at
`work/pacman.conf` and prints the six file pins. Use a fresh path under an
owned private directory. The original Q3 inputs are inspected before
staging and stay in their original locations.

Set the consumer's `smoke.cpp` to the exact pinned source shipped with the
GUI-server recipe. The projected CMake consumer discovers Qt 6.12.0 under
`/usr`, checks the actual imported public and private targets and scanner,
and links the same bounded offscreen and local Wayland server API smoke.
It uses an empty private home and runtime directory, standard loader search,
and no build RPATH. Retain the loaded offscreen plugin's actual mapping and
join it to the archive and ALPM ownership. The plan pins both consumer files.
[Reference fixture](../../../packages/port/qt612-gui-server-source-reference/SmokeCMakeLists.txt)

Before invoking a mutation, a future admitted actor must bind the retired
packaging receipt, archive and detached signature, current public TEST
certificate, full primary and signing fingerprints, and original verification
receipts. Use a separate private keyring and the emitted signature-required
pacman configuration inside the disposable guest. The two sibling controls
must exercise normal pacman with a tampered signature and with the selected
key absent, respectively. Both require the precise signature refusal and an
unchanged stopped local-database snapshot. Do not use production trust or copy
secret keys into the guest.
[Public signature verifier](../../port/qt612-gui-native-v1/trust.py)
· [Stopped ALPM database snapshot](../../install/overlay583_trial/trial.py)

After the package scope has retired, join its independent offline readback,
post-scope observation, original actor report and naturally retired fsck
receipt to the separately recovered exact unsigned archive.

```sh
python3 -I -B "$lane/package_handoff.py" \
  --archive "$ARCHIVE" --actor "$PACKAGE_ACTOR_RESULT" \
  --retirement "$PACKAGE_RETIREMENT" --retirement-sha256 "$PACKAGE_RETIREMENT_SHA256" \
  --readback "$PACKAGE_READBACK" --readback-sha256 "$PACKAGE_READBACK_SHA256"
```

The output gives the exact archive and `packaging_receipt` pins for the
separately admitted signing and installed selection. Use its original
handoff to derive the package payload and Q3 provider maps before launch.

```sh
python3 -I -B "$lane/selection_maps.py" --stage "$PRIVATE_STAGE" --plan-sha256 "$PLAN_SHA" \
  --archive "$ARCHIVE" --handoff "$PACKAGE_HANDOFF" --handoff-sha256 "$PACKAGE_HANDOFF_SHA"
```

The reader hashes the finalized archive and original Q3 scratch. It resolves
the 18 Qt libraries, offscreen plugin, Wayland server and interpreter using
archive and Q3 ELF metadata. Each non-Qt provider is bound to its original
ALPM owner, version and file digest. Use independently reviewed supplementary
SONAME roots with `--supplementary-roots` and its separate SHA-256 when the
consumer loads providers outside that static closure. The output is unissued.
The installed guest compares its actual provider set with the selected map.

At each installed stage, confirm the exact new inventory, database consistency,
all package-owned files and symlink leaves, and the 40 runtime dependencies.
Check the types of directories reported by pacman outside the shared
`/usr`, `/usr/lib`, `/usr/share`, and `/usr/bin` roots.
`qt6-base=6.12.0-2` and the upstream-version consumer must resolve. The exact
official `qt6-base=6.12.0-3` demand must return solely the unsatisfied demand.
Check every Qt SONAME with the regular loader using RTLD_NOW/LOCAL and bind
all actual transitive provider paths and bytes to the selected installed owners.
Check all plugin and tool owners and exercise the ordinary-user offscreen
consumer. Both removals must restore the baseline package database byte map,
selected configuration paths and original provider bytes and metadata.
Require the package-owned leaves to be removed and every new Qt SONAME to
stop resolving. The llhttp
guest's existing loader and restore checks illustrate the independent receipts.
[Installed loader and restore example](../llhttp_overlay583/guest.py)

The preflight emits unissued data and consumer source. It performs no ALPM,
signature or VM operations. A separate TEST signature covers the archive
recovered from the retired package guest.
An official Qt provider replacement needs a separate admitted image, a
current trusted rollback archive and its own consumer requirements.

### First installed attempt

The first positive guest completed all six lifecycle observations. Its
retired writable child held the callback result and 629 command files.
Direct readback of the child found all 4,635 expected payload leaves,
18 resolved Qt SONAMEs and the exact 67 Q3 providers at each installed
stage. All Qt SONAMEs were absent at baseline and after each removal.
The worker result SHA-256 was
`b7a9185b0d61d8a0fdaa6aa31d7c18fcde27fc99f6c615fb9ad80d6ebdb59062`.

The outer guest held before exporting that evidence. The boot image
lacked the `/dev/fd` path used by the evidence listing, and its bare
`poweroff` command was unavailable after the disks unmounted. The
coordinator retired the owned scope and container.

### Corrected installed trial, November 26, 2026

The corrected positive case used the same 356-package Q3 baseline and
the exact TEST-signed Qtbase 6.12.0-2 archive. The guest exported a complete
result disk, unmounted its disks and shut down naturally. Independent
readback verified 646 original result files, including 629 command files.
The package counts were `356 → 357 → 357 → 356 → 357 → 356`. Each of the
three installed stages matched all 4,635 selected file and symlink leaves,
18 loaded Qt SONAMEs and 67 original Q3 providers. The same ordinary-user
consumer passed the offscreen and local Wayland server API checks at all
three stages. Both removals restored the stopped package database byte map
and the original selected paths. All 18 Qt SONAMEs were absent at baseline
and after each removal.

Separate guests rejected a tampered signature and a valid signature whose
signing key was absent from the keyring. Each pacman refusal preserved the
356-package inventory and the stopped ALPM database byte map. All three
guests exited zero, passed independent result-disk readback and had their
scope and container absence confirmed twice.

| Case | Independent readback SHA-256 | Retirement SHA-256 |
| --- | --- | --- |
| Signed lifecycle | `af046aaa3d100ebc335a8fac0fe97ec3a8b215c9ec32d96d2962daac1f7f369b` | `4f1aa19572e046085e7b11e82185841e54e8958716b4dd0e7e359773f21482e3` |
| Tampered signature | `ce5bc4bc662e20cf7f6bf3ea5e2ddd453bb8a3ca51af815521ab32ee821c5dd0` | `ccd44fc2aa157c088e5d60a95396e198534979ea3efc7143996113b1760a4d06` |
| Unknown signer | `4bc333cc2ad8c8b3d8ec1a7f982e1b5c7aadbfdb453090b83a543e43beb2db38` | `8fc1352e36fb9821805c6bf619657962459394738711bc221c01ae02b8bea0da` |

The three-case qualification returned `PASS_EXACT_EMULATED_INSTALLED_LIFECYCLE`.
The joined receipt SHA-256 is
`b1aefe78d48646727cf820874b52002a289ac086d85142aefeda73883b34f8de`.
The trial used the corrected runner at `def071cda32d3dcde42caa74fdc414385a821a16`
and the package archive SHA-256
`0c6ad9610086bfb7b2a88f9cb8794b88d2432dd53436fbc18eec808af01ea315`.
The result covers the Q3 emulated AArch64 baseline with 16 KiB pages,
the TEST trust configuration, and the selected package and path checks.
Official provider replacement, the supported Asahi composition, production
trust and physical M2 validation remain open.

### Official provider replacement on R132

The retained R132 emulated AArch64 inventory with 16 KiB pages includes
official `qt6-base 6.12.0-3`. Offline verification accepted its original
detached signature using the pinned public ALARM key
`68B3537F39A313B3E574D06777193F152BDBE6A6`.
[R132 maintenance result](../../../docs/validation/asahi626-maintenance-emulated-arm16k-20261118.md)

| Compared input or receipt | SHA-256 |
| --- | --- |
| Official Qt archive | `2777135b375ba82250896fa9a993926bf3c05b59dd22217f63d6a1391c1b4c31` |
| Official detached signature | `8db1bcda35923c7e719b2b82162521e59edc4aeb0ec45a270e94f0327a2673f5` |
| Q3-tested project archive | `0c6ad9610086bfb7b2a88f9cb8794b88d2432dd53436fbc18eec808af01ea315` |
| R132 independent terminal receipt | `7ef472629ca77ad94fd30c94268d747982c1971be96a2ecb118acfc7a1a968d8` |
| R132 626-package rollback inventory | `671526351a35f00582e4fab2b0fb66d40832144adb72eb44aa412d6af7ce942c` |
| Offline replacement comparison | `7d43e3a6cfdf4d47b22b731004865b0784b76772f79f203338be9864372d7d33` |

The R132 package set fails the replacement dependency check. On a disposable
metadata-only local database, ordinary `pacman -T` accepted all 812 dependency
expressions for the retained inventory. Substituting the exact project archive
metadata left `md4c<0.6` as the sole unsatisfied expression. R132 carries
`md4c 0.6.0-2`; Q3 carries `0.5.3-1`. The five R132 packages that require
the Qt provider use the bare `qt6-base` name.

Archive ELF readback found the same 18 top-level Qt SONAMEs in both providers,
with 4,405 common payload leaves. The retained official
`qt6-declarative 6.12.0-1` has six strong Vulkan-related symbol references in
`libQt6Quick.so.6.12.0` and three in `libQt6QuickWidgets.so.6.12.0` that
official QtGui exports and the project archive omits. The affected symbols
include `QWindow::setVulkanInstance` and `QVulkanDefaultInstance::instance`.
The project recipe disables Vulkan. The R132 replacement remains **HOLD**
with both the dependency and ELF blockers. No replacement or restoration
transaction ran. The Q3 installed result above retains its original scope.

The retained ALARM recipe's Qt patch `032643f99e090e0304ef935c2ee11c109d55c8a1`
applied to the nine affected Qt 6.12.0 source paths. The patched Markdown
importer compiled to an x86_64 object with the exact official Qt headers and
the header from signed R132 `md4c 0.6.0-2`. The unpatched source compiled
against 0.5.3 and stopped at the dialect assertion against 0.6.
The archived official Qt build lists Vulkan headers
`1:1.4.363.0-1`. The verified ALARM archive has SHA-256
`a9a8b1226aad787e8a3931da08cadc6b459d6efa73f86cc585de20aae1e45dab`.
Those headers and official Qt 6.12 headers also compiled an x86_64 consumer
object retaining the six affected Qt Quick imports. The probe receipt SHA-256
is `7b105dcb1da34196eb471e8a4a53340d7a2b8b904410af20dcd27fa48cf5b351`.
The [Vulkan and md4c 0.6 successor](../qt612_vulkan_md4c_successor/README.md)
stages a separate recipe from these inputs. Normal Qt CMake and Ninja linked a host
QtGui with all six distinct required versioned Vulkan exports and the
`md_parse` relocation through `libmd4c.so.0`. An emulated AArch64 16 KiB
build completed makepkg. The archive recovered from its retired scratch
passed independent payload, metadata and QtGui ABI checks. The original
guest recorded HOLD during evidence export. A separate signed R132 migration
and restoration remain open.
[ARM64 build and recovery evidence](../qt612_vulkan_md4c_successor/README.md#november-27-build-and-offline-package-recovery)
[ALARM Vulkan headers](https://archlinuxarm.org/packages/aarch64/vulkan-headers)

## Guest supervisor callbacks

`worker.py` rederives the selected preflight plan before invoking any
callback. It checks the closed independently pinned selection, the public-only
certificate packets, original detached signature, exact signature-required
configuration, and the proposed guest boundary. It then uses the existing
TEST status parser and normal ALPM commands for the five mutations. It joins
each installed stage to the signed payload and pinned normal-loader provider
closure. It builds the independent consumer once, then reruns that same
consumer after both reinstalls. After each removal it compares the stopped
database and protected observations with the recorded baseline.

The [guest entry](guest.py) connects the callbacks to the existing [Perl
command recorder](../arm16k_perl5423_vm/runtime.py). The guest owner self-binds
`/qtwork/root` on the fresh Q3 ext4 child before chrooting into it and passes
`cachy_qt_install_nonce=<plan nonce>` at boot. Stage the exact plan
`PLAN.json`, independent `SELECTION.json`, `expected356.lock`, signed archive
and public inputs, consumer sources, and [loader probe](loader_probe.py) on
the read-only `/qt-install-inputs` mount. Create a fresh root-owned
`/qt-install-work` with mode `0755` and place the emitted `pacman.conf` there.
The workspace and ALPM database reside on the disposable child.

Mount the pinned sources with their repository paths intact and read-only.
They include both preflights, the package metadata projection, Qt recipe inputs
and checker, the Overlay583 database recorder, the llhttp and Fish trust
readers, and Perl's `runtime.py`, `contracts.py`, `helper-origin.json` and
`frozen/owned_process.py`. Inside the admitted chroot, invoke the entry with
the externally selected plan and selection hashes, the guest uptime deadline,
and one `--protect` per selected path.

```sh
python3 -I -B "$READONLY_SOURCE/scripts/integration/qt612_installed_16k_preflight/guest.py" \
  --plan-sha256 "$PLAN_SHA256" --selection-sha256 "$SELECTION_SHA256" \
  --deadline-uptime "$OWNED_UPTIME_DEADLINE" --protect "$SELECTED_PATH"
```

The observer reads the three trust operands, uses the existing stopped
database recorder, and joins actual
`pacman` inventory and file ownership to the mapped files. Provider
observations resolve ELF dependencies only through the actual standard-loader
maps. For the original consumer command, the observer enables glibc's
`LD_DEBUG=files` diagnostic and records which library the consumer process
initialized and opened. Loader search paths remain unchanged.

The entry retains the original bounded command streams, map probes and
consumer trace under `/qt-install-work/evidence/commands`. It stores each
protected view and stopped database map with its stage observation, and
reserves time for the worker's existing GPG retirement command. It drops
privileges to UID/GID 1000 before setting `LD_DEBUG` in the environment of the
consumer's final exec. Earlier wrappers run without that diagnostic. The
observer refuses traces with multiple program initializations in the consumer
PID. The guest owner still owns boot, read-only staging, scope retirement, and
evidence export.
The separate sibling validator takes original ALPM diagnostics and stopped
database observations from independently retired sibling clones.

## Owned Q3 launch

`media.py` seals one case from the unissued stage, the current installed
selection, the exact signed package and the retired package handoff. It
reuses the existing boot partition and result format. Each case receives
a fresh PARTUUID, a read-only operands disk, and a writable child backed
directly by the original Q3 raw scratch. The container, scope and result
are owned by the existing Qt lifecycle code. PID 1 verifies the boot
identity, selected source, present RTC and offline device roles before
starting an installed worker.

```sh
python3 -I -B "$lane/media.py" --stage "$PRIVATE_STAGE" --plan-sha256 "$PLAN_SHA" \
  --selection "$SELECTION" --selection-sha256 "$SELECTION_SHA" \
  --handoff "$PACKAGE_HANDOFF" --handoff-sha256 "$PACKAGE_HANDOFF_SHA" \
  --retirement "$PACKAGE_RETIREMENT" --retirement-sha256 "$PACKAGE_RETIREMENT_SHA" \
  --archive "$ARCHIVE" --certificate "$CERT" --signature "$SIGNATURE" \
  --runner "$CANONICAL_RUNNER" --boot-template "$RETIRED_BOOT" --image "$Q3_IMAGE" \
  --format-tools "$FORMAT_TOOLS" --format-tools-sha256 "$FORMAT_TOOLS_SHA" \
  --case main --clone "$PLAN_NONCE" --protect "$PROTECTED_PATH" --output "$CASE_MEDIA"
```

Use the exact original archive filename, the pinned Qt actor runner from
the retired handoff, and the 1,611,661,312-byte retired full-build boot
template with SHA-256 `951bdc40ec6d3c4735d688acda30f153a22019862bc255059b874d9c27e0a858`.
The main case records the exact `--protect` selection and whether each
selected path existed in the baseline. Its preservation result covers
those paths and separately checked providers.

The tampered-signature case takes a fresh clone and a distinct
`--tampered-signature` of the same length with one detached signature
packet. The owned GPG command must verify that the selected key rejects
this signature before ALPM runs. The unknown-key case takes another fresh
clone, the original signature and an empty disposable keyring. Omit
`--protect` for both siblings and use distinct nonzero first eight hex
digits for all three clone identities.

Use the unissued site description to select the original capsule and
control directory identities independently before issuing an owner grant.

```sh
python3 -I -B "$lane/site.py" describe --media "$CASE_MEDIA" --media-sha256 "$MEDIA_SHA" \
  > "$CASE_SITE"
```

Independently pin a canonical authority containing kind
`ROOT_QTBASE16K_INSTALLED_OWNER_V2`, issuer `Root`, approved `true`,
scope `cachy-asahi-qtbase16k-installed-trial.scope`, the exact case,
clone, `media_sha256`, `site_sha256`, and integer `created_utc` and
`expires_utc` spanning at most one hour. The pinned installed selection
separately binds the signed archive, public TEST certificate, payload
ownership and Q3 provider maps.

```sh
site=(--media "$CASE_MEDIA" --media-sha256 "$MEDIA_SHA"
      --site "$CASE_SITE" --site-sha256 "$SITE_SHA"
      --authority "$AUTHORITY" --authority-sha256 "$AUTHORITY_SHA")
python3 -I -B "$lane/site.py" preflight "${site[@]}"
systemd-run --user --scope --unit=cachy-asahi-qtbase16k-installed-trial.scope \
  --property=KillMode=control-group --property=KillSignal=SIGTERM \
  --property=SendSIGKILL=yes --property=TimeoutStopSec=360s \
  python3 -I -B "$lane/site.py" run "${site[@]}"
python3 -I -B "$lane/site.py" observe "${site[@]}" > "$LOCAL_RETIREMENT"
python3 -I -B "$lane/readback.py" --media "$CASE_MEDIA" --media-sha256 "$MEDIA_SHA" \
  --site "$CASE_SITE" --site-sha256 "$SITE_SHA" --authority-sha256 "$AUTHORITY_SHA" \
  --retirement "$LOCAL_RETIREMENT" --retirement-sha256 "$LOCAL_RETIREMENT_SHA" \
  > "$CASE_READBACK"
```

The offline case reader reopens the original host custody, inputs and
child chain, natural QEMU and fsck receipts, and owned guest commands and
output from the retired result disk. Each case receipt qualifies just
that case. Combine all three independently selected case receipt hashes
to verify matching plans, installed selections, Q3 scratch and baseline
database, with distinct clone, media, site, authority and retirement
identities.

```sh
python3 -I -B "$lane/qualify.py" \
  --main "$MAIN_READBACK" --main-sha256 "$MAIN_SHA" \
  --tampered-signature "$TAMPERED_READBACK" --tampered-signature-sha256 "$TAMPERED_SHA" \
  --unknown-key "$UNKNOWN_KEY_READBACK" --unknown-key-sha256 "$UNKNOWN_KEY_SHA"
```

```sh
python3 -I -B -Werror::ResourceWarning "$lane/test_worker.py"
python3 -I -B -Werror::ResourceWarning -m unittest discover -s "$lane" -p test_observer.py
python3 -I -B -Werror::ResourceWarning -m unittest discover -s "$lane" -p test_guest.py
```

These controls feed inert fixtures through the actual worker. They exercise
command ordering, protected-configuration preservation, failed or unretired
commands, bad trust and guest boundaries, distinct signature-refusal clones,
and exact inventory, loader and database restoration. The guest run records
cover actual signature checks and package transactions.

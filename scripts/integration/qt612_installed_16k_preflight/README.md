# Qtbase installed 16 KiB trial preflight

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
separately admitted signing and installed selection. The owner still
supplies signed media, the payload and provider maps, and the distinct
main and signature-refusal guests.

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
configuration checks and original provider runtime. Require the package-owned
leaves to be removed and every new Qt SONAME to stop resolving. The llhttp
guest's existing loader and restore checks illustrate the independent receipts.
[Installed loader and restore example](../llhttp_overlay583/guest.py)

The preflight emits unissued data and consumer source. It performs no ALPM,
signature or VM operations. Package assembly, signed installation, loader
checks and restoration remain unrun. An official Qt provider replacement needs
a separate admitted image, current trusted rollback archive and its own
consumer requirements.

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
and exact inventory, loader and database restoration. Live signatures and
installation remain unrun.

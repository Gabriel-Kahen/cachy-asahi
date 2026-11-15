# ARM16K UI-seat diagnostic kernel source

**READY_SOURCE_ONLY.** No configure/olddefconfig, compiler, container, image,
preparation, VM, native role or authority was run/issued by this task. This is a
separate generic emulated UI-seat experiment, not a target Asahi kernel change.
The passed RTC KSM/C01 kernel, consumers and closed trials remain unchanged.
See [the port note](../../../docs/port/arm16k-ui-seat-kernel.md).

## Exact missing feature

`data/rtc-built.config` is the actual71589-byte Root-built RTC config, SHA-256
`020243b2d55a0c093280581a70f337baa01d9822ab4075588ad74fca8857f1c9`.
Its exact8988-byte built-only bundle receipt is retained unchanged, SHA-256
`68f3ff68c78fa3aa8b3d66c3b301472c846a7eb8d2a830ba565d61547029492f`.
VT/VT_CONSOLE, EVDEV, virtio-MMIO, virtio GPU/KMS, fbdev and framebuffer console
already are built in. Only `CONFIG_VIRTIO_INPUT` is missing for the proposed
MMIO keyboard. The final config must differ from that actual RTC config by
exactly:

| Symbol | Before | After |
| --- | --- | --- |
| CONFIG_VIRTIO_INPUT | n | y |
| CONFIG_LOCALVERSION | "-generic16k-managed-gui-rtc1" | "-generic16k-managed-gui-rtc-uiseat1" |

No INPUT_KEYBOARD/ATkbd/i8042 or PC bootloader is added. Pinned original Linux
`drivers/virtio/Kconfig` makes VIRTIO_INPUT a tristate depending only on already
enabled VIRTIO and INPUT, with no select/imply; its Makefile binds virtio_input.o.
The driver registers with the input subsystem. `VT` selects INPUT and the VT
Makefile builds keyboard.o, so INPUT_KEYBOARD=n is not a reason to add a PC-style
keyboard driver. Existing CONSOLE_TRANSLATIONS=n remains held; this source
adds no character translation feature. Exact source operands/URLs/hashes are in `inputs.lock.json`.
They were read as DATA, never executed.

`device-plan.json` declares only `-device virtio-keyboard-device` and
`-device virtio-gpu-device` on QEMU virt/MMIO, with console=tty0 plus the existing
PL011 observer console, and stock tty1 login. QEMU11.1.3 source pins the keyboard
name `QEMU Virtio Keyboard`, BUS_VIRTUAL, device types and virt's MMIO transport.
It declares no input passthrough, NIC, host display or KVM. This is a future
actor's finite device contract, **not an implemented guest actor**. Exact tool
binary device availability, actual MMIO enumeration, framebuffer/evdev delivery,
udev input-parent seat tags, active seat0/tty1 PAM and UI rendering remain null.
The x86 reference used i8042/Bochs and cannot establish ARM device identity.

## Frozen build seam and config proof

`origin.json` pins every unchanged RTC producer/data byte copied under
`frozen/rtc/` from producer commit1d8e0f29351e28415fe9e38bce91dbf38575a9aa.
The adapter verifies these pins before using the original tool/confinement and
source guards. New `build.py` preserves the producer's build flow with only five
explicit textual substitutions: docstring, frozen toolchain import path, owned
workspace name, KBUILD host metadata and distinct terminal status. A control
requires that exact five-substitution derivation; supervision, first-failure
retention, deadlines, extraction, pre/post config and header bounds are intact.

The seed still derives from the original68789-byte kernel config through the
frozen RTC constructor, then applies VIRTIO_INPUT and new LOCALVERSION. Its exact
original-byte inverse is checked. The final normalized RTC projection must pass
the original RTC guard and match the actual RTC reference plus exactly the two
changes above. The same fifteen historical-original→Clang22.1.8 compiler facts
are required byte-for-value; no new probe is implicitly admitted. If real
configure changes any other feature/fact it retains observed.config and holds.
Root must separately review any genuinely necessary new fact before changing
this source. `non_ui_seat_features_unchanged` covers the actual reference delta;
the old blanket non-RTC flag is deliberately not exported for this UI successor.

The new operation is `arm16k-ui-seat-reference-kernel-v1`, release
`7.1.13-generic16k-managed-gui-rtc-uiseat1`; successful future output kind is
`ARM16K_UI_SEAT_REFERENCE_KERNEL_BUNDLE_V1`, status
`BUILT_ONLY_UI_SEAT_BOOT_NOT_RUN`. Existing RTC consumers do not accept it. Root
must explicitly pin a future consumer/actor; no old kernel fallback or unchanged
actor assumption is supported. The built-only RTC receipt is not rewritten into
this candidate's acceptance evidence.

## Source checks and Root-only future stages

Actually run source/DATA commands:

```sh
python3 -I -B -Werror::ResourceWarning scripts/integration/arm16k_ui_seat_kernel/test_controls.py
python3 -I -B scripts/integration/arm16k_ui_seat_kernel/inspect.py
```

The38 actor-fenced controls pass. They cover complete modeled config/bundle,
exact inverse/frozen derivation, missing/modular input, wrong release/16K/RTC/VT/
EVDEV/DRM, i8042/unrelated bus drift, extra/missing/wrong compiler facts, duplicate
config, source tamper/omission/symlink, unsafe device plans and header failures.
The modeled Image is256bytes of synthetic test DATA, never a compiled kernel.
`inspect.py` prints verified recipe DATA and pending fields; it prepares nothing.

Root may reuse the existing exact host-/usr readonly cross-build domain after
its current heavy job retires and live resources/source pins are reviewed.
`host_guard.py` reuses the frozen116-package/18-tool/72-runtime-file guard and
emits a **new operation's pending** profile. Original RTC profiles refuse by
operation identity. The same actual environment is intended, not assumed.
Root must capture/recheck tools/ALPM/runtime/cache/bc pre/post, serialize host
package changes, review the pending profile and independently admit each stage.

Future commands, **not run here**, inside Root's newly admitted domain:

```sh
/usr/bin/python3 -I -B /recipe/build.py --allow-kernel-source-execution \
  --stage configure --archive /inputs/linux.tar.gz \
  --tool-profile /inputs/tool-profile.json --tool-profile-sha256 ROOT_NEW_SHA \
  --owned-process /inputs/owned_process.py --output /outputs/NEW-configure

# Only after actual configure review/pinning and a fresh separate admission:
/usr/bin/python3 -I -B /recipe/build.py --allow-kernel-source-execution \
  --stage compile --archive /inputs/linux.tar.gz \
  --tool-profile /inputs/tool-profile.json --tool-profile-sha256 ROOT_REVIEWED_SHA \
  --configured-result /inputs/configured-result.json \
  --approved-config /inputs/approved.config \
  --owned-process /inputs/owned_process.py --output /outputs/NEW-compile
```

`actor-proposal.json` fixes the proposed finite mounts/resources, not authority:
existing image sha256:fcee73ea1b96e236248f53a213f71276cc9072d9025b58bce9915e32f19963ae;
rootless cap0/NNP/read-only/network-none,2CPU/8GiB/256PIDs, private8–16GiB exec/
nodev/nosuid tmpfs; whole3600s/outer3800s,16MiB command logs,64MiB persistent
output. Original263MB source is bound RO, not copied/downloaded. Only the new
recipe, pinned source/reaper/profile/host provenance, exact RO/usr/cache and
signed extracted bc are read binds; /outputs is the owned write bind. Compile
adds only reviewed config/result RO binds. No host home/device/trust exposure,
image build, package installation or general process framework is introduced.
Tmpfs consumes the8GiB memory cap and may honestly OOM; fresh global RAM/disk and
canonical lease/resource admission remain Root prerequisites.

Licenses: project adapters MIT (`LICENSE.packaging`); retained Linux operands
GPL-2.0-only/individual SPDX terms, QEMU operands GPL-2.0-or-later or individual
file terms. Frozen kernel COPYING/GPL texts remain present. Exact corresponding
source/compiler/runtime/legal completeness, native16K, Apple/M2, hardware,
performance and release gates remain separate. The package closure is owned by
the installation worker, not asserted complete here.

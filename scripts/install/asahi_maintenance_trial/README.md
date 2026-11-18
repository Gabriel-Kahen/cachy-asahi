# Disposable Asahi 626-package maintenance rehearsal

The retained Asahi Minimal root is a whole 3,680,501,760-byte ext4 image
with SHA-256 76f95dae6180bc4a45ffdeaccec26681d75b2207b90062064fcd2a845adbf9db.
The original root supplies the transaction target and remains an ordinary
read-only input. The existing qualified generic AArch64 16 KiB control root,
QEMU kernel, offline owner and raw-disk reader remain the boot path. The
control boot uses its existing read-only mount and the VM gets one writable
copy of the exact Asahi image. This path exercises pacman on the original
Asahi package database and filesystem copy. It does not boot the installed
Asahi kernel or attach Apple firmware, physical disks or host devices.

The captured filesystem has 514,011,136 free bytes. Its disposable backing
file is extended to 16 GiB. PID 1 uses the existing guest e2fsck and resize2fs
against the selected virtual disk only, after checking its UUID, writable
state and exact size. The Asahi root mounts without device nodes or setuid
execution. The inherited target API mount callback supplies readonly proc
and sys, a guest tmpfs run directory and a minimal dev without block nodes
for the ordinary package hooks and scriptlets. The trust directory and
transaction logs stay on a separate bounded guest tmpfs.

The candidate is explicitly unapproved under the original protection
policy. It starts at the exact 261 names and versions, previews and applies
all 368 selected local archive operands, and checks the full 626-package
result. It previews and applies one inverse package transaction that
reverses NetworkManager, Perl and Python to their original versions.
The final inventory is still 626 packages. Policy and release acceptance,
Apple hardware behavior and supported-device installation remain open.
The controller checks the preserved seed bytes, all five inventory and
preview locks, raw signature status, ordinary ALPM actions, boot-file and
mount-configuration snapshots, and natural QEMU retirement. Both the
original result disk and writable clone remain under the selected output.

The normal mkinitcpio hook regenerated `/boot/initramfs-linux-asahi.img`
in the first rehearsal and emitted warnings about firmware, a skipped
aarch64 microcode hook, a missing DRM symbol, and console font setup. The
controller now retains that hook's generated image and exact output for
each phase that regenerates it, then restores the pinned original file
with its root ownership, mode and modification time before checking the
whole boot and mount-configuration snapshot. The two generated-image
leaves are each capped at 14 MiB within the existing 32 MiB evidence
budget. The regenerated images remain rehearsal evidence. Apple boot,
firmware and device qualification remain open.

## Passive transport and future Root selection

Generate the [passive maintenance plan](../../port/supported-composition/README.md#prepare-the-disposable-asahi-maintenance-guest-inputs)
from this checkout. Set `preflight` to the resulting `guest-plan.DATA.json`,
`preflight_sha256` to its reviewed whole-file digest, and `overlay` to the
known Overlay583 stage supplying the frozen guest Python runtime. Choose a
fresh `transport` directory. This passive command copies only selected
public, pinned inputs.

    repo="$(git rev-parse --show-toplevel)"
    trial="$repo/scripts/install/asahi_maintenance_trial/controller.py"

    python3 -I -B "$trial" prepare-transport \
      --preflight "$preflight" --digest "$preflight_sha256" \
      --runtime-stage "$overlay" --output "$transport"

Use the `manifest.sha256` emitted by that command as `media_digest`. The
manifest records the whole plan pin and checks the exact reviewed archive,
signature, key, runtime and lock selection. Moving the passive plan to
another staging location changes its provenance pin. The reviewed
selection and all file bytes stay fixed.

Use the standard cap-zero, no-new-privileges, no-network, read-only qualified
controller container. Mount the code, transport, seed, kernel, config and
generic control root read-only. Give only the selected new output parent
a writable mount. Use the kernel, config and generic control root pinned
by the plan's `boot` references and the raw Asahi seed from
`original_root.seed`. The controller validates their whole pins.

    python3 -I -B "$trial" bind --staging "$transport" --seed "$asahi_seed" \
      --kernel "$kernel" --config "$kernel_config" --baseline "$control_root" \
      --output "$new_private_output" --nonce "$fresh_32_hex_nonce" \
      --media-digest "$media_digest"

This returns an unissued selection. A later Root owner may issue the exact
development selection with issuer Root after reviewing the current public
TEST key lifetimes and resource and execution windows. Use the existing
owned container scope pattern and verify container absence twice after
scope retirement. The required actor flags are
CACHY_ASAHI_OVERLAY583_ACTOR=1 and CACHY_ASAHI_MAINTENANCE_ACTOR=1.

    python3 -I -B "$trial" run --authority "$root_issued_selection" \
      --authority-sha256 "$root_issued_selection_sha256"

The command keeps the bounded inherited TCG profile, 2 GiB readonly input
disk, 16 GiB disposable target and 64 MiB result disk. A failure leaves raw
retained evidence and a HOLD when the guest offers a valid held receipt.
A failure before guest evidence leaves the original available output and
cannot be accepted as a completed trial.

## Source checks

    python3 -I -B scripts/install/asahi_maintenance_trial/test_trial.py

The portable controls project the separate disk and resize path, check
offline QEMU arguments and signature handling, and verify refusal at the
actor boundary. The test module fences subprocess and socket calls.

Supply the reviewed passive plan and stage to exercise the actual 626-package
selection, both ALPM transaction models and all 371 signature receipt
models. These controls read the five locks and public keys without
materializing the 653,469,760-byte transport or starting a guest.

    CAA_ASAHI_MAINTENANCE_PREFLIGHT="$preflight" \
    CAA_ASAHI_MAINTENANCE_PREFLIGHT_SHA256="$preflight_sha256" \
    CAA_OVERLAY583_STAGING="$overlay" \
      python3 -I -B scripts/install/asahi_maintenance_trial/test_trial.py

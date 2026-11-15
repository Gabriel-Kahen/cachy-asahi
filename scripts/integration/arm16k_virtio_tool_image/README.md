# Offline virtio-GPU tool-image successor

READY SOURCE ONLY. The exact official package was acquired and statically
verified; no Docker start/build/install, guest, lease or candidate-device probe
ran in this task. The actual successor image ID and device-help fields remain
NULL. The old ee1 image and every historical guest/result remain unchanged.

Root's actual device-help r2 established that ee1 contains virtio-blk-device and
virtio-keyboard-device but lacks virtio-gpu-device. Its QEMU 11.1.3 executable is
not missing virtio-MMIO support: Arch splits the non-GL GPU into the matching
qemu-hw-display-virtio-gpu 11.1.3-1 package. The exact retained 2026-11-09 catalog
pins one new archive, 38829 bytes / 121232 installed bytes. Its only dependencies
are already installed glibc, pixman/libpixman-1.so=0-64 and qemu-common=11.1.3-1.
No GL, virglrenderer, rutabaga, PCI GPU or PC bus fallback is introduced.

`inputs.lock.json` pins the complete 17 ordinary archive members, PKGINFO,
module ELF/NEEDED/ABI stamp, parent QEMU, both actual library provider files,
all 178 parent ALPM descriptions/versions and the three borrowed runtime files.
`data/static-audit.json` records actual static observations. Payloads/public
keyrings are external inputs, not copied into this source directory. The
upstream package licenses remain those in PKGINFO and its seven shipped notices;
project adapters are MIT. No source-reproduction or release license-completeness
claim is made for the official split binary package.

## Material preparation and static verification

Use only the exact archive and 119-byte detached signature in the lock. The
signature is the base64-decoded PGPSIG in the held official catalog descriptor.
The actual acquisition made one HTTPS request, no redirect/retry, and kept the
original bytes. The exact current host public Arch keyring was ASCII armor;
initial direct gpgv failed, then dearmoring that public input and gpgv succeeded.
No private/signing key was used, no host keyring/package was changed, and no
signature/time policy was weakened. Keep the failed diagnostic receipts private.

```sh
python3 -I -B scripts/integration/arm16k_virtio_tool_image/inspect.py \
 --archive /ABSOLUTE/PACKAGE.pkg.tar.zst --signature /ABSOLUTE/PACKAGE.pkg.tar.zst.sig \
 --binary-keyring /ABSOLUTE/archlinux.binary.gpg \
 --qemu-binary /ABSOLUTE/parent-qemu-system-aarch64.DATA
python3 -I -B -Werror::ResourceWarning scripts/integration/arm16k_virtio_tool_image/test_controls.py
```

The inspection runs only bounded gpgv and passive archive/ELF reads. The 14
actor-fenced controls cover exact snapshot signature/dependencies, parent and
one-package membership, wrong versions/extra packages, tampered input pins,
expired/revoked/wrong/duplicate signer status, exact device names, absent GPU,
ELF architecture/bounds, and ownership/mount/resource confinement. Synthetic
help/inspect fixtures test parsers and do not establish actual GPU availability.

Three never-started, uniquely labelled owned containers retrieved parent ALPM
and exact libc/pixman files. They were removed and absence checked. A second
copy in the first container failed with a Docker overlay mount error; it does
not establish any module-directory observation. The two provider retrievals
used distinct never-started containers. No existing container was altered.

## Root-only offline construction

Root first creates a fresh private directory containing ONLY the archive and
its signature. Do not point --packages at a broad cache, source tree or home.
Use the existing arm16k_systemd_tcg_guest/frozen directory as --runtime-root;
its reference_controller.py, command_runtime.py and owned_process.py must match
all exact lock pins. These unchanged helpers provide owned-container recovery,
independent bounded cleanup, command supervision and cancellation behavior.
They introduce no new VM/guest entry in this route.

Root separately issues `authority.template.json`, replacing its NULL fields.
It binds the exact full source manifest, two public material pins, output path,
resources and once/no-retry policy. Fill source_manifest with build.py's pure
`source_manifest()` return value from the final reviewed directory; it includes
the NULL template, so do not edit that source template into an actual authority.
Write the actual authority elsewhere. A fresh output directory is the one-role
marker: once created, preserve any failure and use no automatic retry.

The Root outer controller must independently admit and retain its existing
canonical exclusive lease and pass its inherited FD. build.py only checks the
borrowed same-FD/path identity and existing exclusive flock before commands;
it never acquires, unlocks or reissues resource authority. Root owns any stronger
PIDFD/live-conflict custody. There is no claim that this new route performed a
namespace-specific admission or replayed an old once role.

```sh
python3 -I -B scripts/integration/arm16k_virtio_tool_image/build.py \
 --allow-offline-image-build --packages /ROOT/FRESH/TWO-FILE-MATERIALS \
 --runtime-root /ROOT/REVIEWED/arm16k_systemd_tcg_guest/frozen \
 --authority /ROOT/NEW/authority.ACTUAL.json --authority-sha256 ROOT_SHA \
 --lock-fd ROOT_INHERITED_EXCLUSIVE_FD --output /ROOT/NEW/virtio-tool-output
```

The install container has one CPU, 512 MiB memory/combined-swap cap, 64 PIDs,
no network/capabilities/devices, NNP and a 32 MiB /tmp. Only its own image root
is writable; package/source/reaper binds are read-only and receipts are the only
host write bind. It requires the exact 178-package parent, verifies the real
signature, runs dependency-checked `pacman -T` and normal signature-required
`pacman -U`, masks hooks and refuses scriptlets. Only the one audited split
package may be added. It verifies the unchanged parent ALPM plus that package,
module and QEMU bytes. The archive has no scriptlet or hook members.

After natural install completion, a unique new image is committed, preserving
parent layers and the parent's default entrypoint/CMD. Maximum image delta is
32 MiB. A separate read-only container checks the same QEMU/module/provider
bytes, real QEMU version and actual `-device help` for all three literal device
names. Both stages use the exact owned-process supervisor, bounded in-memory
output followed by durable logs, natural exit 0/EMPTY_TWICE and twice-empty
container PID namespace. Docker/actor logs are retained before cleanup even on
failure. Exact owned-container cleanup/absence is mandatory. Failure attempts
to remove only the exact newly created image, without force; cleanup uncertainty
is retained as HOLD, not treated as successful retirement.

The 360-second controller uses at most 8 MiB output and proposes at most 256 MiB
additional disk (32 MiB image plus RW-copy allowance, materials and receipts).
Require 1 GiB free disk reserve and 1 GiB available RAM beyond the 512 MiB actor
cap. No raw/overlay guest disk is created. Root must serialize this admitted
actor with other heavy work; these bounds are a proposal until actual issuance.

## Qualified receipt boundary

Only an actual successful Root build/probe emits kind
`ARM16K_VIRTIO_TOOL_IMAGE_V1`, status
`TOOL_IMAGE_DEVICES_QUALIFIED_NO_GUEST`, with distinct `image_id`, ee1
`parent_image_id`, package/module/QEMU/provider pins, actual device_help pin,
three true required_devices and owned_containers_absent=true. The separate Root-device-help.json carries the exact ARM155 consumer schema
ROOT_OBSERVED_ARM_QEMU_DEVICE_HELP_V1, actual tool/help pins and timezone-aware
actual_observed_utc sampled immediately after the real help command. It is
created only after successful probe and owned-container retirement. Root must retain
and externally pin the whole receipt plus actual new image ID for a new guest
consumer. No default selector is edited and no old consumer silently accepts it.

Actual guest MMIO enumeration, framebuffer, keyboard/evdev delivery, tty/PAM/
seat/UI, native ARM, M2, performance and release acceptance all remain NOT RUN.

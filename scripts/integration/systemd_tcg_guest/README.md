# Full-system x86 TCG login reference

This small constructor prepares a stock x86 reference VM with systemd, logind,
D-Bus, a real serial getty and normal PAM login. It supplies a genuine login
substrate for later NM/Polkit work without an M2. **No VM was launched during
preparation.** Boot, serial PAM authentication, logind/session creation, NM/Polkit
integration and guest shutdown remain NOT RUN until Root executes the first boot.
This reference never qualifies ARM, Asahi/M2, real networking or release gates.
Previous actors, results, ARM guards and project package/default manifests are
unchanged. q35 belongs only to this x86 fixture; no OS bootloader is installed.

## Preparation

```sh
python scripts/integration/systemd_tcg_guest/prepare.py \
  --allow-prepare-x86-reference \
  --catalogs work/supported-composition-ci-runtime-20261114 \
  --output work/systemd-tcg-reference-20261114/new-preparation
```

Use an ordinary host user and rootless Docker. The source pins in
`selected-inputs.json` bind the retained official Arch base OCI digest and exact
2026-11-09 core/extra DB hashes. A genuine offline `pacman -Sp` resolves exact
QEMU/kernel/tool targets against that base. The official Arch default
Required+DatabaseOptional policy applies to checksum-bound metadata; DB signature
acceptance is not established. Every actual package/signature and local `-U`
installation is Required TrustedOnly. Official PGPSIG bytes are retained, and
independent GPG VALIDSIG output is recorded under the retained image keyring.
No dependency bypass, key acquisition, host install or package/script hook
execution occurs. HTTPS retrieval is bounded per-object/aggregate/time; the
container build and assembly use network-none. No sandbox/capability fallback
is provided.

Actual preparation resolved/fetched **40 exact official archives**, including:

- QEMU system-x86/common/img/firmware `11.1.3-1`.
- Stock Linux `7.2.14.arch1-1` (`7.2.14-arch1-1` kernel).
- mkinitcpio `42.2-1`, fakeroot `1:2.1.4-1`, Python `3.14.9-1`,
  e2fsprogs `1.47.4-1` and declared dependencies.

Real PKGINFO/BUILDINFO, package/signature hashes, official URLs, license metadata,
keyring hash and VALIDSIG lines remain in the private `tool-provenance.json`.
BUILDINFO recipe hashes are retained as actual binary metadata; corresponding
source recipes/source rebuilds, full license delivery, production trust/freshness
and native/hardware acceptance are not inferred.

The guest base is the exact official OCI userspace (systemd `262.1-1`, D-Bus
`1.16.2-2`/broker `37-3`, pambase `20260616-1`, real login/agetty). The constructor
copies it as data, adds stock signed kernel/modules and generates an initramfs
with explicit virtio-pci/virtio-blk/ext4 modules and base/udev hooks. Host hardware
autodetection, kernel rewrites and guest-code execution are absent. Offline
fakeroot ownership plus `mkfs.ext4 -d` builds the disk without mount/device
privileges. Read-only `e2fsck`, required-file pins and offline debugfs UID/GID
checks pass; builder's home is genuinely encoded UID/GID 1000 in the filesystem.

The guest has a fixture-only ordinary `builder` account (no wheel grant), private
random TEST password, stock PAM, enabled serial-getty@ttyS0, D-Bus socket and a
real systemd default target. The credential file and disk are private mode0600;
plaintext is never put into an image build, argv, environment or console report.
The user shell's marker provides synchronization after normal login; it does
not fabricate a logind session. The probe requires UID1000/PID1 systemd and reads
actual loginctl service/type/class/user/session fields and real service state.

## Root's first boot

Preparation never invokes `boot.py`. Root must supply explicit first-boot opt-in,
the exact prepared-manifest hash and exact retained tool-image identity. The
actual command and input pins are in `validation.json`/the Root handoff.

The controller requires a fresh output directory and an exclusive first-attempt
marker. It starts one uniquely named rootless container with read-only root,
capabilities ALL dropped, no-new-privileges, network-none, no KVM/devices, 2 CPUs,
3 GiB RAM and 256 PIDs. Its only caller mounts are the owned prepared directory
read-only and a fresh owned output directory writable. No host system/service/bus
mount is accepted.

QEMU uses direct stock-kernel boot, q35, TCG only, 2 vCPUs and 1536 MiB guest RAM,
virtio-pci block storage, no NIC/display, serial/QMP owned Unix sockets and its
seccomp sandbox. The immutable raw disk gets a newly created qcow2 overlay;
overlay file growth is capped at256MiB. No PC bootloader enters the target.
The [QEMU direct Linux boot documentation](https://www.qemu.org/docs/master/system/linuxboot.html)
describes the kernel/initrd boot interface; exact installed QEMU version is
verified independently during preparation without creating a VM.

A bounded serial protocol performs the ordinary password login, invokes one
fixed guest probe, parses the exact nonce-framed real session fields and logs
out. Console bytes/deadline are bounded to1MiB/420s; the QEMU actor has a480s
budget and existing exclusive-child supervision/retirement. SIGINT/SIGTERM enter cleanup; further cancellation is deferred through report writing. An independent35s cleanup budget survives a Docker wait timeout and preserves the original failure alongside secondary errors. A private cidfile, unique-name absence preflight and exact labels/image/entrypoint/mount/resource checks recover ambiguous creation before disposal. Root mismatches are retained as ownership errors. No Docker-init binary is injected: Python PID1 directly waits for qemu-img and the existing exclusive-child helper reaps QEMU, whose sandbox denies spawning processes. Owned Unix sockets
have checked ownership; a short private symlink avoids AF_UNIX pathname limits.
Passwords are redacted. Root's controller requests QMP emulator quit after PAM
logout; this does not qualify normal guest shutdown. Failures retain bounded
console/QEMU reports and retire only the owned container/process/overlay.

## Resource/result boundary

The final disk is1.5GiB logical/sparse, about636MiB allocated. Temporary extracted
root uses a1GiB tmpfs under the3GiB assembly memory limit; assembly exited0 with
no OOM. The initial observed filesystem-free delta to final preparation was
about2.975GiB, including build cache/concurrent activity; this is not a measured
per-process RAM peak. Runtime overlay is separately bounded at256MiB. No broad
shared Docker/cache pruning is performed. Roughly7GiB remained free on /home.

Initial metadata-policy and cross-filesystem hardlink adapter refusals are
retained. A COPY-only q35/serial refresh reused verified tool inputs; the earlier
unbooted raw prototype was removed for the disk budget with its manifest retained.
The ordinary-readable PID1 check was updated offline and e2fsck passed again.
No superseded disk or static check is credited as boot/session evidence.

```sh
python -m unittest discover -s scripts/integration/systemd_tcg_guest -p test_controller.py -v
```

Seven serial/cleanup controls pass without starting Docker/QEMU, including SIGTERM during ambiguous create, missing-CID exact-contract recovery, wait-timeout removal/report preservation, foreign-contract/CID mismatch refusal and deferred cleanup cancellation. Root owns the
first actual VM boot and its resulting session decision.

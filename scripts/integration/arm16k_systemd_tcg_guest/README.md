# Emulated ARM16K systemd guest

This separate constructor prepares an aarch64/16K full-system guest for future
package and user-session development. Actual offline assembly passed; **guest
boot, PAM login, logind operation and runtime page-size checks have not run**.
Nothing here accepts native ARM, Apple hardware, M2, performance or release gates.
No shared manifest, accepted kernel, platform stack or prior actor is changed.

`prepare.py` never invokes a VM. `boot.py` is a separate, explicit first-use
controller for Root's fresh actor admission. Preparation does not consume its
`arm16k-first-boot-attempt.json` marker. There is no autostart or host install.

## Exact inputs and selection

The retained Image is 9,019,400 bytes, SHA-256
`cd8053ebdb83302015efbad97ab1cc53fcd5a2353bf3f37ba208f4e6360946ec`.
Its 68,789-byte config hashes to
`e97d54d4852eceb6cba28c38f78d4a00aacbfdb0c1523cb96366590f7eaa915b`.
Both come from the preserved
`artifacts/development/updater607-generic16k-kernel-data-root-20261026/source/`
material, together with exact `kernel-input.json` (1,138 bytes,
`4194ad7212e07a5b96c8bd6c95fc23482524bdd6ba340d12a77fc193a9ee3db1`).
That descriptor records build-only provenance for
`7.1.13-generic16k-managed-gui`, source
`4056e2505ed7081674e949e0460258672cce14ff`, run39156901928. It is not a
new boot result. No kernel source retrieval or compilation was needed.

The ARM64 Image header independently declares little-endian/16K. The config has
the built-in virtio-MMIO/block/ext4/PL011 console, cgroups, namespaces, seccomp,
devtmpfs and systemd baseline interfaces checked by `inspect_inputs.py`.
`AUDIT`, `FANOTIFY` and `CFS_BANDWIDTH` are absent. This is a bounded reference,
not the complete recommended feature profile or proven login compatibility.
The requirements are checked against [systemd v261.2](https://github.com/systemd/systemd/blob/v261.2/README),
not newer main-branch requirements; Image parsing follows the
[ARM64 boot protocol](https://docs.kernel.org/arch/arm64/booting.html).

The exact official ALARM rootfs was retrieved as DATA from
<https://ca.us.mirror.archlinuxarm.org/os/multi/ArchLinuxARM-2026.08-aarch64-rootfs.tar.gz>:
829,367,415 bytes, SHA-256
`42a4eeaa038994ffd31fa173256ef2f0ef511358eeb41b9ea1f8626391b9b319`.
Its retained 566-byte detached signature hashes to
`0157d8cd6261c85205931c766b754d6d56112b28800666fb64add1de192ebe11`;
the retained armored public key is 3,098 bytes,
`6ce771e853f04a38a5b533cb33e61f877b9b06b58b6db051eb8a15d737a2332f`.
Private dearmor plus real `gpgv` verification requires signer
`68B3537F39A313B3E574D06777193F152BDBE6A6`. No host trust or keyserver changes.
The initial attempt to use the armored key directly as a binary gpgv keyring
failed; both the failure and corrected verification are retained privately.

Selection recomputes a dependency graph from the signed archive's 165 installed
package records, using host libalpm16 version comparisons. It selects 111 **whole
packages**, including systemd261.2-1, PAM1.7.2-2, pambase20260616-1,
dbus1.16.2-1, dbus-broker37-3, shadow4.20.0.arch1-1 and util-linux2.42.2-1.
The 31,097 selected paths contain603,406,725 logical regular-file bytes.
Unselected stock kernels/modules/firmware and the base metapackage are excluded
as whole packages. Selected payloads and their installed package DB entries are
copied together; this is not a new guest ALPM transaction or frozen349 image.
Whole-rootfs authentication is real; per-package `%VALIDATION%` fields are
inherited DATA, not newly verified individual archive signatures.

The custom extractor refuses linked host-write ancestors, special files,
unrecognized extended metadata and incomplete selected payloads. It preserves
UID/GID/modes/hardlinks and the two original file capabilities, verifying the
latter byte-for-byte from ext4. It also preserves the original journal ACL
permissions, tags and named numeric groups998/999. Original PAX ACL entries and
the actual ext4 xattrs are recorded separately: e2fsprogs exports ignored IDs on
non-named ACL entries as0. Only those ignored fields may differ; changed named
IDs or permissions refuse. See [Linux ACL handling](https://github.com/torvalds/linux/blob/v6.18/fs/posix_acl.c)
and [libarchive's PAX reader](https://github.com/libarchive/libarchive/blob/v3.8.7/libarchive/archive_read_support_format_tar.c).

The fixture replaces only the original `alarm` UID1000 account with a new
`builder` UID/GID1000 account, removes its supplementary memberships, locks root,
and generates a fresh private TEST password/machine ID/nonce. Stock PAM and login
programs remain. The image enables only the ordinary serial getty and D-Bus
socket needed by the selected multi-user target. No autologin or login stub.
The account/password are fixture-only; `credentials.json` stays private0600.

## Host tools and confinement

The unchanged x86 reference's existing tool image is the read-only parent:
`sha256:c6bd2d0ed8c437a74b3e1713b7bfcb023b7446f1abe3c0d27a6a5b4fd734f925`.
Its tool provenance is preserved inside the successor image. The real offline
dependency transaction adds only qemu-system-aarch6411.1.3-1 and
edk2-aarch64202608-1 (161.07MiB installed). The latter is an ordinary package
dependency; the guest uses direct `-kernel`, without UEFI or a PC bootloader.
Frozen official Arch2026/11/09 core/extra DB hashes are source-pinned. Each exact
archive/hash and DB-provided detached signature is retained, checked by ordinary
dependency-checked pacman and separately verified with the retained official-image
keyring. `.PKGINFO`, `.BUILDINFO`, keyring digest and real `VALIDSIG` records are
retained in `/opt/tool-provenance.json` and the private preparation report.
This is not source/legal/freshness acceptance for the tools or guest packages.

Tool installation occurs only in an owned rootless container with zero caps,
no-new-privileges, no network, no devices, no scriptlets and masked hooks.
Only bounded host HTTPS acquisition retrieves pinned host tool archives.
Assembly uses x86 host fakeroot/mke2fs tools, read-only ARM inputs, a private
1GiB noexec scratch tmpfs,2CPU/3GiB/256PID limits and a420s stage deadline.
No ARM artifact/upstream program runs during preparation. The operation has an
1800s outer deadline and a3GiB additional-storage cap, counting retained inputs,
checkout, prior attempt outputs, scratch and both the committed tool delta and
its potentially retained install layer. `/tmp` and `/home` reserve checks refuse
before further work. No host package/service changes or extra capabilities.

The admitted boot profile would use QEMU virt/TCG,max CPU,2vCPU,1536MiB,
ttyAMA0,virtio-MMIO `/dev/vda`, no NIC/display/KVM/passthrough, read-only raw input
and a private256MiB-capped qcow2 overlay. The cap0/read-only host container is
limited to2CPU/3GiB/256PIDs; the actor is bounded480s, controller420s, serial1MiB.
The controller authenticates a real normal PAM serial login/logout and requires
PID1systemd, active logind/D-Bus, matching loginctl/XDG session, `uname -m=aarch64`
and `getconf PAGESIZE=16384`. Completion requests QMP quit after logout; guest
poweroff remains unqualified. Existing owned-process retirement, serial and
ownership-checked container recovery/cleanup primitives are copied byte-for-byte
from commitf7aaff34; their exact origins/hashes are in `frozen/origin.json`.
The old x86 consumed marker and actors are never read or replayed by this lane.

## Commands and actual result

Run controls without Docker or any guest execution:

```sh
python3 -I -B scripts/integration/arm16k_systemd_tcg_guest/test_guest.py
```

Actual24 controls pass. They cover material tampering/missing providers, metadata
preservation, unsafe ancestors, resource accounting, architecture/page-size and
PAM/session refusals, serial bounds, ambiguous create, foreign-name/CID rejection
and SIGTERM cleanup. These are source/modeled controls, not a boot result.

The actual preparation used the commands below, plus `--prior-output` for each
retained r1–r4 attempt. Inputs live in a private0700 directory and comprise the
exact rootfs, detached signature and public key named above. The constructor
regenerates selection and fills its small kernel/material manifest files.

```sh
python3 -I -B scripts/integration/arm16k_systemd_tcg_guest/prepare.py \
  --allow-prepare-arm16k \
  --inputs /tmp/cachy-asahi-arm16k-inputs-20261114 \
  --kernel-data /home/gabe/Documents/ChatGPT/cachy-asahi/artifacts/development/updater607-generic16k-kernel-data-root-20261026/source \
  --catalogs /home/gabe/Documents/ChatGPT/cachy-asahi-install-completion-20261114/work/supported-composition-ci-runtime-20261114 \
  --output /tmp/cachy-asahi-arm16k-preparation-20261114-r5
```

Actual r5 output is `PREPARED_NOT_BOOTED`. The raw ext4 image passes read-only
e2fsck, UID/GID1000 layout checks and independent capability/ACL checks. It is
1,610,612,736 logical/617,082,880 allocated bytes, SHA-256
`f69d74fbb0043793c96424d0f91ad2f6fb2d8cf3a72fb94024ea9cc40dae4cd3`.
`assembly/prepared.json` is58,179 bytes, SHA-256
`f7b3073f58acce8ab5e21ff61f2182779d24046e1582cda6adb0a3db66b7036e`.
`preparation.json` is33,233 bytes, SHA-256
`bc02a220993c95afad229f6d692d14d2784dc670709f41f75081305f5b436b54`.
The final tool image is
`cachy-arm16k-systemd-tools:7e5ee6e20df840958b2f2657`, ID
`sha256:ee1aa3da22a5d89dc1bc273fa818b1d996b7e62851f50d7b629144f6bba9f207`.
All5 final preparation containers and18 across the retained attempts were
independently checked absent. The first-boot admission marker is absent.

Earlier real refusals are retained: r1 tool-size allowance; r2 duplicate xattr
format; r3 journal ACL format; r4 ext4's ignored-ACL-ID encoding. The owned failed
r4 raw image was hashed and retired to respect capacity; original inputs and
failure logs remain. After r5, final accounting was tightened to include both
tool layers and cleanup aggregation gained per-container records/independent
image-cleanup time. That outer bookkeeping refinement was unit checked and the
new budget check run read-only against actual outputs; no second payload build
is claimed. Its conservative2,902,337,233-byte estimate remains below3GiB.
`validation.json` records the actual handoff and distinguishes this refinement.

Root must review these pins/resource bounds before separately invoking first
boot. This exact future command has **not run**:

```sh
python3 -I -B scripts/integration/arm16k_systemd_tcg_guest/boot.py \
  --allow-first-arm16k-systemd-boot \
  --prepared /tmp/cachy-asahi-arm16k-preparation-20261114-r5/assembly \
  --prepared-sha256 f7b3073f58acce8ab5e21ff61f2182779d24046e1582cda6adb0a3db66b7036e \
  --tool-image cachy-arm16k-systemd-tools:7e5ee6e20df840958b2f2657 \
  --tool-image-id sha256:ee1aa3da22a5d89dc1bc273fa818b1d996b7e62851f50d7b629144f6bba9f207 \
  --output /tmp/cachy-asahi-arm16k-first-boot-root-20261114
```

Further gates remain separate: actual emulated boot/session, current supported
composition/frozen349, complete source/compiler/legal correspondence, native16K,
both M2 Air workflows, hardware/performance and release policy.

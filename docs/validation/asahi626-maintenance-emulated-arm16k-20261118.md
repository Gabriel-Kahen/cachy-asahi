# Asahi 626-package maintenance on emulated ARM16K

On November 18, R132 completed the signed forward and reverse transactions on
a writable copy of the exact Asahi Minimal filesystem. The offline QEMU TCG
guest ran AArch64 with 16,384-byte pages using the generic control kernel.
The [maintenance runner](../../scripts/install/asahi_maintenance_trial/README.md)
was exercised from source commit `68ac95b97d92d2b9ec59484d53dfece865941fdb`.

| Checkpoint | Installed packages | Verified archive/signature pairs |
| --- | ---: | ---: |
| Asahi Minimal baseline | 261 | — |
| Forward maintenance | 626 | 368 |
| Reverse of the three version changes | 626 | 3 |

The original ALPM log records 365 installations, three upgrades and three
downgrades. Python, NetworkManager and Perl returned to their original
versions. All 365 additions remained installed.

## Boot and mount preservation

R131 reached 626 packages but remains **HOLD** at `check-forward`.
Independent comparison found one changed file across the 362 boot and
mount-configuration entries. The normal pacman mkinitcpio hook had regenerated
`/boot/initramfs-linux-asahi.img`.

R132 captured the hook output and warnings, retained the 13,450,791-byte
forward-generated image, and restored the original initramfs bytes, ownership,
mode and modification time on the writable copy. All 362 entries matched the
baseline after the forward and reverse transactions. The reverse transaction
left the restored image in place.

The R132 controller recorded a successful guest run and exited 0. The initial
outer observer exited 1 because duplicated regex escaping prevented it from
reading the ALPM actions. A corrected reader independently checked the
original result disk and the restored initramfs on the writable copy without
rerunning the VM.
The scope and both owned containers were observed absent twice.

| Retained evidence | SHA-256 |
| --- | --- |
| R131 terminal HOLD | `734efcc0f648939bac9ce687d643328232b2097f4f9d03d2b2306b95838a9d1e` |
| R131 boot and mount comparison | `b89b1dab126d517e49eb8f555c114a35efce9bf1161b43a75aef564962470918` |
| R132 independent terminal receipt | `7ef472629ca77ad94fd30c94268d747982c1971be96a2ecb118acfc7a1a968d8` |
| R132 reader correction receipt | `fd3b2c2649f3754f7d25e98faa1ec0b9f848426790d2e69decb2695187024ba6` |
| Original and restored initramfs | `17e38d82a14af39492427e4c66d61e9ed64094871227630ec84e2efdaa134f4f` |
| Forward-generated initramfs | `47085056b95e7e7cf4a5c1d3950f57b9eb10fa3c8b3273fd9a5d8b38aa56b0e5` |
| Raw R132 result disk | `446ef3b0547fbc55e6fb9cd8cfd4e46481a6c1e1bc68d341c4b01b7ce5263ed6` |

## Stock boot feasibility on QEMU

A later read-only inspection streamed the retained R132 seed into an anonymous
file and verified the 3,680,501,760-byte raw filesystem and both stock boot
files. The seed's embedded kernel configuration matched the configuration
retained from the signed `linux-asahi 7.1.13.asahi3-2` package.
[Embedded configuration](../../scripts/port/kernel-native-stage/embedded-config.txt)

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| R132 raw seed | 3,680,501,760 | `76f95dae6180bc4a45ffdeaccec26681d75b2207b90062064fcd2a845adbf9db` |
| `/boot/vmlinuz-linux-asahi` | 35,834,368 | `c9764582601a847d64943d1a19008c589e87b9e79c5ad416773dee6a8a05a17c` |
| `/boot/initramfs-linux-asahi.img` | 13,429,845 | `17e38d82a14af39492427e4c66d61e9ed64094871227630ec84e2efdaa134f4f` |

The R132 QEMU `virt` launch uses the PL011 `ttyAMA0` console and
`virtio-blk-device` disks. The stock kernel enables 16 KiB pages, ext4 and the
VirtIO block driver, but disables PL011 and the generic PCI host controller.
Its VirtIO MMIO transport is a module. The original initramfs contains 17
kernel modules and none for VirtIO, so the stock pair cannot reach the R132
root disk or report through the selected serial console. A PCI disk would
still require a compatible host controller driver.
[R132 QEMU arguments](../../scripts/install/overlay583_trial/controller.py#L323)
[QEMU `virt` devices](https://www.qemu.org/docs/master/system/arm/virt.html)

An adapted software trial could use the same kernel with an auxiliary
initramfs that loads the seed's `virtio_mmio` module and an MMIO VirtIO console
on `hvc0`. QEMU would load the stock kernel directly, bypassing m1n1 and the
Apple firmware boot path.

### Direct stock-kernel boot with an auxiliary initramfs

On November 26, a local offline QEMU guest directly booted the exact stock
`Image` above. It used an auxiliary initramfs with the stock `virtio_mmio`
module and the stock initramfs's `kmod`, mount tools and library layout. The
first two launch configurations produced an empty `hvc0` stream. Bounded
QMP diagnostics distinguished a PID 1 exit during dynamic loading from an
early guest shutdown before MMIO initialization. Restoring `/lib -> usr/lib`
and using the original `kmod` applet resolved both failures.

The successful AArch64 guest opened `hvc0` and mounted the exact stock seed
using `ext4` with `ro,noload`. The seed's installed `getconf` and `pacman`
reported 16,384-byte pages and all 261 expected package names and versions.
The inventory SHA-256 was
`279fba6cfd35bee27b8ba2d42337bd51be8258ed137e3b814b2a18e1bda4f34d`.
The read-only package query exited zero with a GPGME engine warning. The
guest unmounted the seed and powered off. The stock inputs kept their
original hashes, QEMU exited zero and the owned container was absent twice.

| Retained evidence | SHA-256 |
| --- | --- |
| Auxiliary initramfs | `89ad8ec64b3b025d26fa10cb912044b8a59f9be0aaead42f448b6e0e867211e6` |
| Raw VirtIO console | `fc19ff781f4d6afb0781858ac070618d447a82dc8557cdb98ed3f21d070147e3` |
| Read-only boot receipt | `0731bb350c4710b65eda5ee700d5f94f7f818af3ecfd7c920f068bd1bec0d53c` |

### Installed systemd on a disposable overlay

A separate direct-boot probe used the same kernel, stock `switch_root` and
a writable QEMU snapshot over the pinned read-only seed. It switched into
the installed Asahi root and verified that `/proc/1/exe` matched the seed's
systemd SHA-256
`cd491657ea73f75cede21e84c59a585178756d32c262699899910f2b07b36be7`.
The guest reported AArch64 with 16,384-byte pages, `basic.target` active and
an ext4 root writable through the snapshot. It requested normal poweroff
through the installed systemd. QEMU exited zero, the owned container was
absent twice and the pinned input bytes were unchanged.

The probe used a dedicated systemd target and `fstab=no`. The retained
ext4 seed lacks the EFI volume required by its normal `/etc/fstab`, a VFAT
filesystem with UUID `2ABF-9F91`. Default boot, login, the Apple firmware
path, the original initramfs and recovery remain separate checks.

| Retained evidence | SHA-256 |
| --- | --- |
| Installed probe console | `8c101b636f117deee70508474ce328a6e2f7f9203a62ffc8548f2b37a8fd2778` |
| Installed probe receipt | `5818efd2059285795cb7532177fd4ddf0d2509ee395f4dcbd92005d197e5f402` |

The [maintenance proposal](../workstreams/supported-composition-maintenance.md)
remains **UNAPPROVED**. Physical M2 device validation and release acceptance
remain open.

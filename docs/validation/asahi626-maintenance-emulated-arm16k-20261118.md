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

The [maintenance proposal](../workstreams/supported-composition-maintenance.md)
remains **UNAPPROVED**. Booting the installed Asahi kernel, physical M2 device
validation and release acceptance remain open.

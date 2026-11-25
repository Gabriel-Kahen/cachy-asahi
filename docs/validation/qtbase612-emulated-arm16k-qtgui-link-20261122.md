# QtGui 6.12 link on emulated AArch64 with 16 KiB pages

The November 22 run linked `libQt6Gui.so.6.12.0` and QtDBus in the
offline Q3 guest under AArch64 QEMU TCG. The serial build ran 318
incremental steps in 8,343.745 seconds with a peak child RSS of 834,464
KiB. Ninja scheduled zero QtCore steps. The guest verified the original
QtCore library and aliases, the pinned Q3 command streams, and the exact
356-package inventory before and after the build. QEMU powered off
naturally after unmounting both writable disks. The actor exited zero and
the container and scope were observed absent twice.

On November 25 the original reader refusal was reproduced with the
byte-exact overlay restored from its retention archive in a read-only
mount namespace. GNU ld recorded the unversioned undefined `md_parse`
import with a GNU version index of zero. The pinned provider's defined
symbol has index one. The corrected reader accepts both unversioned
encodings for the import and retains the existing checks on versioned
symbols, the provider pin, and the dynamic relocation.

The corrected reader replayed the sealed source and original host and
guest receipts in the same namespace. It verified the clean result disk,
the original QtCore library, and the AArch64 QtGui, QtDBus and md4c
libraries. QtGui has SONAME `libQt6Gui.so.6`, has two load segments
aligned to 65,536 bytes, directly needs QtCore, QtDBus and system md4c,
and contains an `R_AARCH64_JUMP_SLOT` relocation for `md_parse`. The
pinned `libmd4c.so.0.5.3` exports that function. The guest evidence in
the replay matched the previously retained corrected guest receipt.

| Original or replayed evidence | SHA-256 |
| --- | --- |
| Sealed QtGui handoff | `635695d627d3181583830c44969ca1b0cef679755554e54f92be32267c0cbfc4` |
| Original actor receipt | `1cabdc4c9618efaa033db62812f81eb75f5e2639fb9c10ea17955da4798a2b5a` |
| Original post-scope observation | `c6f0b9e8bb5cd029df1785aaef38390c4479777779f2c9b6b389879b8db29aaa` |
| Original result disk | `e0454e095db663c949b82c405996c124fe10280d5c9737f71026aaf0ad0ba3a9` |
| Original QtGui overlay, restored from the byte-exact archive | `26afc11e8581afe2556be6ae0171c88cd64e755dcff6f9253cdd3cbb26d25ef4` |
| QtGui library | `bc73b419fcc9f2e8d07d8454d867e5e2dad34beae4e3d32f29c601dfec767ad8` |
| QtDBus library | `c64174251bacb101fe466b3f07a00a9b82c628e054a3a6447ab8af735852ebe6` |
| Corrected independent readback | `fe12a973f212ee92cb849a155fdf834a5ac1aad98dff549576f5763c65415d9c` |

The replay returned `PASS_EXACT_QTGUI_LINK_ONLY`. Full Qt build and
installation, native Qt validation and physical M2 validation remain open.

A fresh capsule was also prepared from the byte-exact Core archives and
original receipts in a disposable mount namespace. The host formatting
tools were exact copies of the pinned binaries under namespace-local
root ownership. The sealed capsule passed passive preflight, and the
November 22 execution supplied the guest evidence for this record.

[QtCore checkpoint](qtbase612-emulated-arm16k-qtcore-link-20261118.md)
· [QtGui checkpoint and controls](../../scripts/integration/qt612_gui_16k_link_checkpoint/README.md)

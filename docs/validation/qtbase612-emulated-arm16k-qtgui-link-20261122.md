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

## Full-build preflight evidence

A local Ninja `-t commands` and `-t graph` readback of the exact flattened
Q3 graph (SHA-256
`2df5cefe432f58d19af7c9f7bd394990ef35b169d40a79a01b1223cceff23f55`)
found 1,855 default target commands, 1,385 C/C++ compile edges and 18
shared-library links. Subtracting the retained 639-command QtGui closure
leaves 1,216 commands and 788 compile edges. The complete command stream
hash is `e9bdd7b241d2c28d035e3a084ca7fbeefd7d90f64748e0c0c356e1ea9baff628`.
The remaining command stream hash is
`3147ef87084e1075d35abd18d27ed97f47ae0a9287df3c8a7ba4f3b9d2a71f97`.
This is the default Qtbase graph. Package checks, staging, installation
and the other Qt family repositories need separate coverage.

The Q3 QtGui run reached its 6 GiB cgroup memory limit and grew the overlay
to 750,845,952 bytes. The existing 14,400-second guest cap covers the
bounded QtGui checkpoint. A full-Qtbase producer needs its own bound target
graph, measured memory, scratch and deadlines, a pinned output package
plan and a signed installed rehearsal. The native five-stage route also
needs the selected md4c archive and current scoped signature, clean build
pairs, and installed consumer and rollback cases. Its previous GUI-only
native attempt stopped during base image assembly with
`IMAGE_BUILD_NO_SPACE`. [Native family contract](../../scripts/ci/qt612-complete-family-native-source/README.md)

The passive GUI dependency parser currently checks 16 KiB geometry for
staged Qt entries only. A model external provider with 4 KiB-only load
geometry passed the metadata join. The full installed qualification needs
static geometry across every selected external provider and a 16 KiB
loader run. [Runtime dependency reader](../../scripts/port/qt612-gui-native-v1/runtime.py)

The R132 vendor Qt6 Base `6.12.0-3` archive and the source-built Q3 QtGui
libraries have distinct provenance. In the R132 graphics archive sample,
the Asahi Vulkan ICD names `libvulkan_asahi.so`, and the Apple and Asahi
DRI aliases resolve to `libdril_dri.so`. The sampled Mesa, Asahi Vulkan,
GLVND and Vulkan-loader DSOs passed static AArch64 16 KiB load checks.
The Mesa DRI object also needs `libLLVM.so.23.1`. Installed closure,
physical GPU acceleration and both M2 Air gates remain open.
[R132 package selection](../workstreams/supported-composition-maintenance.md#november-25-offline-selection-and-custody)

[QtCore checkpoint](qtbase612-emulated-arm16k-qtcore-link-20261118.md)
· [QtGui checkpoint and controls](../../scripts/integration/qt612_gui_16k_link_checkpoint/README.md)

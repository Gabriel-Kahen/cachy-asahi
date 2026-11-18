# QtCore 6.12 link on emulated AArch64 with 16 KiB pages

On November 18, the offline QtCore continuation linked
`libQt6Core.so.6.12.0` in the 356-package Q3 guest under AArch64 QEMU TCG
with 16,384-byte pages. The ordinary guest user ran the 321-command Ninja
target with the original Q3 configuration. The complete package inventory
and declared command graph matched before and after the build. The last two
commands linked the versioned library and created both aliases.
[Q3 configure validation](qtbase612-emulated-arm16k-configure-20261118.md)

The 8,819,928-byte ELF has SONAME `libQt6Core.so.6` and two load segments
aligned to 65,536 bytes. Its AArch64 loader interpreter is intentional. The
retained linker command specifies `-shared` and
`-Wl,-e,qt_core_boilerplate`. The function is present at the ELF entry
address in an executable load segment, and the dynamic table names the
same AArch64 loader. The first independent reader required every shared
library to omit an interpreter. A replay qualified this exact executable
library from the original result disk and preserved the initial refusal.

| Retained evidence | SHA-256 |
| --- | --- |
| Independent link and retirement receipt | `62abf64821e9a9f7f6f23450c5caae045e150a36150122ab0dd86d22b2819193` |
| Original result disk | `5d17dee9a8b33db3b8acf1420193fbe90453e0bfb0e67a70ce0c788c1a0a8c4f` |
| QtCore library | `50f2365b3238ccbc4f70b19d4fb0ec9a24462e0cd752a862030e3ed002877558` |
| Original Ninja commands | `1836d53ff5aa42d6d115b8c5301938ccccdd8e3d1fffc29e52d524e44a701769` |
| Post-scope observations | `3eb230cbf28213fee50c1038cb34a7f56b8735b58250827e6ce9314bdd357d3e` |

The serial build took 6,212.764 seconds. The peak guest child RSS was
629,152 KiB. The host actor reported a 6 GiB cgroup memory peak and the
checkpoint overlay used 267,325,440 allocated bytes at peak. QEMU
powered down naturally and was reaped with two empty process-group
observations. The container and scope also exited cleanly and were
observed absent twice.

This qualifies the QtCore link checkpoint. The QtGui link, full Qt package
and installation checks, and physical M2 validation remain pending.
[QtCore checkpoint](../../scripts/integration/qt612_base_16k_link_preflight/README.md)
· [QtGui checkpoint](../../scripts/integration/qt612_gui_16k_link_checkpoint/README.md)

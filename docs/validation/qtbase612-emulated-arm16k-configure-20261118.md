# Qt 6.12 base offline configure on emulated AArch64 with 16 KiB pages

On November 18, Q3 ran offline on AArch64 QEMU TCG with 16,384-byte
pages from source `ed458826d8a55b7b73461adafdfaaefb669ce4a9`. It verified the
detached rootfs signature and all 263 package archive signatures. Two ALPM
transactions took the exact inventory from 165 seed packages to the
349-package baseline and then to 356. The seven-package addition included
the previously qualified md4c archive with its scoped TEST signature.
[Native md4c qualification](native-fish-md4c-reproducibility-20261118.md)

An ordinary guest user ran Qtbase preparation and configure. The profile
validator checked 113 settings. Pkg-config, ALPM ownership, the dynamic
loader, and CMake confirmed the installed system `md4c 0.5.3-1`. The QEMU
process, container, and owner scope exited naturally with code 0. Two
successive checks found the container and scope absent. The independent
readback joined all 27 original evidence files to the retained result disk.

Q2 stopped at signed-rootfs verification because `gpgv` received an armored
keyring. Its host exporter also reused a filesystem check receipt label.
Q3 used a temporary dearmored keyring and distinct receipt labels. The first
Q3 independent replay refused a mutable GPG status token. Converting the
token to `bytes` in the reader let it complete against the unchanged original
evidence.

The 3,084-byte terminal receipt records `CLOSED_QTBASE16K_Q3_PASS` with
SHA-256 `f60a619b67c097cb90cbcbdd24ba35dc23c367a735c26430583685e4d1729f21`.
This result covers dependency installation and configure in the emulator.
The full Qt build, native 16 KiB hardware, and physical M2 validation remain
unrun. [Portable rehearsal](../../scripts/integration/qt612_base_16k_rehearsal/README.md)

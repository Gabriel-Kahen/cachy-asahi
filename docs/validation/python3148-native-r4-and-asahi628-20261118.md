# Python 3.14.8 native build and Asahi ARM16K rollback

Python `3.14.8-1.1` passed one full-profile native AArch64 build with 4 KiB
pages. Independent readback verified the exact builder inventory, package
metadata, AArch64 interpreter and shared library, and `_tkinter` extension.
The 12,909,216-byte package has SHA-256
`45b1f1791eaf19412c0bb151dc23daa00318d235e5624d433ce4b32ed2209049`.
[Native run](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/44406021140) · [Build source](https://github.com/Gabriel-Kahen/cachy-asahi/tree/1e246317a5c990f846d910e799e88ee4a807df75)

The earlier native run provisioned its signed builder and stopped when the
ordinary build process requested read access to a search-only ancestor.
The Python build source now opens those ancestors for traversal and still
requires the final cache directory to be readable. The ordinary-user
regression test reproduced the failure and verified that the corrected
code stages the exact CPython source archive.
[Earlier native run](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/44393779214)

## Disposable Asahi guest rehearsal

An emulated AArch64 guest with 16 KiB pages repeated the signed stock
[Asahi maintenance rehearsal](asahi626-maintenance-emulated-arm16k-20261118.md)
on a disposable filesystem copy. The stock phase verified 371 signatures,
the 261 → 626 → 626 package inventories, and restoration of the original
initramfs and the complete boot and mount inventory. A separate candidate
phase verified the exact Python package with a scoped TEST signature and
the two original Arch Linux ARM Tcl and Tk signatures.

| Python phase | Packages | Ordinary-user result |
| --- | ---: | --- |
| Baseline | 626 | The installed Python 3.14.7 library runs the consumer compiled against Python 3.14.7. |
| Candidate | 628 | The same consumer runs on Python 3.14.8. `_tkinter` loads and the headless Tcl check passes. |
| Rollback | 626 | Python 3.14.7 returns with the original mapped library bytes. Tcl and Tk are removed and all 626 package versions match the baseline. |

Independent readback checked both candidate records in the original result
disk and confirmed twice that the guest scope and both owned containers
had retired. The full local receipt has SHA-256
`33ae542f82c9e4cb05c986870540bcb6878785e5563f211fd6c299f2d3f7c213`.
The coordinated maintenance proposal remains unapproved. A second native
build, physical M2 validation, and release approval are pending.

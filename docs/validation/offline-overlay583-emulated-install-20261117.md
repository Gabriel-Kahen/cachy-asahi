# Offline 583-package installation on emulated ARM16K

On November 17, the disposable QEMU TCG guest completed a fresh offline pacman
transaction on AArch64 with 16 KiB pages. The selected staging contained 574
authenticated historical ALARM packages and nine TEST-signed overlay packages.
The guest mounted its package repositories and boot inputs read-only and
installed into an empty root on a separate guest scratch disk.

- Pacman refreshed the two local repositories with signature checks enabled
  and resolved every expected name, version and repository.
- The install ran with normal scriptlets and hooks. The guest queried all 583
  installed packages and passed its local ALPM database check.
- The controller verified 21 retained evidence files. An independent readback
  matched the complete installed inventory byte for byte to the selected lock
  and verified retirement of the VM, bind container and run container.

| Evidence | SHA-256 |
| --- | --- |
| Retained authenticated preflight | `efbd1147613ab68721a05268c7973282936b5b61de09268c84f473b02566a3c7` |
| Exact guest plan | `8a2ec6532f0a80b230a3b646f9c083b069f15271b77de1a16e4b9a18fef8d1f6` |
| Target and installed inventory, 11,450 bytes | `12e5f0d74f8530fee9cc2b10ad7887748c2f9d5fdfed259b498f4b3db87167ba` |
| Controller report | `c574efc6b4f75944f752053edc5b6514fa87741608a87ade48a2838242b174b5` |
| Independent terminal receipt | `4b7c82367da60a32c512cf55c188462a88976f42e0d22bdeb5968d84a1e7af1d` |

The first trial booted the ARM kernel and held before installation because the
early init script depended on process substitution. The corrected script reads
mount metadata directly, and the fresh second trial produced the result above.
The source used in that trial is identified by controller commit `44806f32`.

## Removal and signed reinstall

A separate fresh 16 KiB AArch64 VM ran the opt-in lifecycle from controller
commit `42765466`. It installed the selected 583-package set, previewed and
removed the nine overlay packages, and verified the exact 574-package base.
It then previewed and reinstalled the same repository-qualified versions
from the signed local staging with a fresh package cache. Pacman passed its
local database check at each of the three checkpoints.

| Checkpoint | Packages | Inventory SHA-256 |
| --- | --- | --- |
| Fresh install | 583 | `12e5f0d74f8530fee9cc2b10ad7887748c2f9d5fdfed259b498f4b3db87167ba` |
| Overlay removed | 574 | `cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac` |
| Signed overlay reinstalled | 583 | `12e5f0d74f8530fee9cc2b10ad7887748c2f9d5fdfed259b498f4b3db87167ba` |

The independent terminal check rehashed all 39 retained evidence files,
compared each complete inventory against the selected lock, and observed the
scope and both owned containers absent twice. Its receipt SHA-256 is
`f76e909c4054a0ca9ead3fdf43117ecdc9891ac4adf648f936f6033c647080fe`.
The controller report SHA-256 is
`ef06917ac13e89ecdb5aecdb2c71bfaeddae8a4cddc2a936183eaa9fd4c3b6ba`.

These runs cover the selected test staging in a generic emulated guest. A
previous-release upgrade, Asahi boot and desktop, physical M2 validation and
production release acceptance remain pending.
[Offline installer trial source](../../scripts/install/overlay583_trial/README.md)

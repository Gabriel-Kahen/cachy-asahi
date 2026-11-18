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

The evidence covers the fresh package transaction in a generic emulated guest.
Integrated removal, reinstallation, Asahi boot and desktop behavior, physical
M2 validation and production release acceptance are separate milestones.
[Offline installer trial source](../../scripts/install/overlay583_trial/README.md)

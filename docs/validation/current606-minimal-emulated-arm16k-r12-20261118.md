# Current606 R12 desktop rehearsal on emulated ARM16K

The minimal Welcome8 case reached all 15 desktop frames and opened the stored
DNS report. The final verifier completed both installed-system scans within
its budget, then rejected the difference from the pre-session snapshot. The
original evidence identifies the failed comparison and does not identify the
changed entries. The minimal case remains held.
[GitHub Actions run](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/44411345458)

| Input or phase | Verified result |
| --- | --- |
| Source | `37f9d059da1880336de1618b095a2e5eaf918d06`, attempt 1, job `135180012205` |
| Builder and guest | Job-built reference kernel, 574-package builder, 590-package controller, and 606-package guest with 16 KiB pages. The missing FDK and updater packages built before the guest step. |
| Desktop | Independently checked and visually reviewed all 15 original 1024×768 frames. The full DNS preview showed the stored connection profile. The report described a read-only query with no live DNS changes. The frames also show the ordinary terminal and file manager, management reports, and the installed Stop and retry behavior. |
| Installed-system verifier | Payload scan finished at 610.825 seconds with 114,247 nodes and 4,918,288,238 payload bytes. The final recheck ended at 648.942 seconds. The exact comparison of inventory, payload, hardlink and nonselected package database records exited with status 1. |
| Retirement | The managed user units stopped, the runtime directory disappeared, and the guest owner exited and was reaped. The hosted cleanup step succeeded before the Original was uploaded. |

The independent failure reader authenticated the retained Original once after
terminal completion. The artifact is 28,276,175 bytes with SHA-256
`63399139902c690dbabe98df9de4534e1d14cba89f8fff7ca02ec67efd466384`.
The overlay case and physical M2 validation remain unrun.

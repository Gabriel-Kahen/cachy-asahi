# Current606 R10 desktop rehearsal on emulated ARM16K

The corrected reference kernel built in the same native AArch64 job and booted
the emulated 16 KiB guest. The guest used the exact 606-package inventory,
completed the desktop interactions, and captured all 15 required frames. The
run remains held because the final installed-package recheck exceeded the
verifier's 600-second timeout.
[GitHub Actions run](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/44381877511)

| Input or phase | Verified result |
| --- | --- |
| Source | `0afeca85d406ef23a170c38fad49add9270c0720`, attempt 1, job `135076058418` |
| Kernel | Job-built reference with virtio keyboard and built-in IPv6. The guest reached the DNS and session-retirement checks. |
| Package inventories | Exact 574-package builder, 590-package controller, and 606-package guest. |
| Desktop | Independently verified and visually inspected all 15 original 1024×768 frames. They show the launched terminal and file manager, Welcome guides and management actions, DNS profile readback, and the installed Stop and retry behavior. |
| Installed-package verifier | Completion of the first payload traversal at 585.893 seconds, covering 114,247 nodes and 4,918,288,238 payload bytes. The final recheck started at 585.938 seconds and was still running when the parent timed out at 600 seconds. The completion receipt is absent. |
| Retirement | All 15 ordered runtime cleanup records passed before the separate producer retirement. |

The held artifacts were read once after the job reached its terminal state.
The independent failure reader checked their identities and reported the
timeout. The overall minimal case remains held. The same-source overlay and
physical M2 validation remain unrun.

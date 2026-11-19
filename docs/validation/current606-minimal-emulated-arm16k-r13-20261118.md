# Current606 R13 desktop rehearsal on emulated ARM16K

The minimal Welcome8 case completed all 15 desktop frames and displayed the
stored DNS report. The final whole-system comparison identified one different
entry, the target of the package-owned `/etc/mtab` symlink. The minimal case
remains held. [GitHub Actions run](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/44423846562)

| Input or phase | Verified result |
| --- | --- |
| Source | `5b1b053cedad53529fd8497797008757039f1406`, attempt 1, job `135223460149` |
| Builder and guest | Reference kernel built in the same native ARM job. The 574-package builder, 590-package controller and 606-package guest ran with the selected inputs. The guest reported 16 KiB pages. |
| Desktop | The independent reader checked all 15 original 1024×768 frames, and each frame was visually reviewed. They show the guides, ordinary terminal and file manager, management reports, the read-only DNS result, and the installed Stop and retry. |
| Installed preservation | The payload scan finished at 571.258 seconds and the recheck at 610.721 seconds. The observer covered 114,247 nodes and 4,918,288,238 payload bytes. It reported one changed node and zero added or removed nodes. The hashed path matched `etc/mtab` from the exact `filesystem` package. |
| Retirement | The managed user units stopped and the runtime directory disappeared. The runtime owner exited and was reaped. All 15 runtime cleanup records passed before producer retirement. |

The Original is 28,820,008 bytes with SHA-256
`7d1901021f4537872d81013c850bf542068e66b9b6020023c0cd301ebf49dd1d`.
The independent failure reader verified it after terminal completion. The
stock rootfs and package both specify `../proc/self/mounts` for `/etc/mtab`.
The exact systemd boot rule enforces that target. The run retained the field
and path identity of the change, and the raw pre- and post-boot targets
remain unobserved. The overlay case and physical M2 validation remain unrun.

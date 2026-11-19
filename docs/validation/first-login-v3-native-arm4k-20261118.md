# First Login 0.1.0-3 native AArch64 build pair

On November 18, 2026, Root accepted the R5 reproducible build pair for
`cachy-asahi-first-login 0.1.0-3`. Two distinct clean, network-disabled
containers on one hosted AArch64 runner with 4,096-byte pages produced
byte-identical unsigned `cachy-asahi-first-login-0.1.0-3-any.pkg.tar.xz`
archives. Each was 11,464 bytes with SHA-256
`c3f3621f2db2a104197882a601e6191b76aec8f2f106f5955902d6325ee7bc97`.
[Exact Source](https://github.com/Gabriel-Kahen/cachy-asahi/commit/f21f8f9e3a84006b13ee1106351c27dca21f5fc3)
· [Run 44380483393, attempt 1, job 135071026498](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/44380483393/job/135071026498)

Both builds matched the same 342-package input lock. Each passed all 14
First Login tests and six package-delivery tests. The independent reader
verified 882 retained evidence files, both archive bodies, the package
metadata, the six delivered files and their modes, and the recorded build
inventory. It verified removal of the owned containers, images and storage
and confirmed the hosted controller scope was empty on two checks.

R4 reported hosted success. The job-log client refused the Original
because it contained terminal escape bytes, leaving R4 on HOLD. R5 used a
corrected private collector and retained its own Original once before the
independent reader verified the pair. [R4 hosted run](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/44375489742)

| Retained evidence | SHA-256 |
| --- | --- |
| 342-package input lock | `50adb6e881a2b717de486ce487e0f1bfcdecce36e028313566a2a1d10c6b34b3` |
| Original job log, 1,901,836 bytes | `5080df3d58e23521fe1a3aaedfa766fdc39f3c7aef475f97796f3c5e60315e8a` |
| Independent reader result | `70546c85cd333dc23ab753d8aa2f5a59929495070b29f5f6e78703ad6b791b24` |
| Root terminal acceptance | `4afc71772b6fdb5c1598f2a656130dd1fc910cc63be46d3ac2daa3f5f6b37289` |

## Signed install and shell lifecycle on emulated ARM with 16 KiB pages

On November 19 UTC, a local AArch64 guest with 16,384-byte pages installed
the exact build-pair archive with its detached TEST signature. The ordinary
user ran First Login with Setup8 and completed ten shell startups. The
rehearsal checked rejection of the ambient test interpreter, preserved the
user's Fish and Zsh edits, and removed the package. The complete inventory
matched the expected 583 → 584 → 583 package sequence, with identical
before-installation and after-removal locks. The guest, both owned
containers and the temporary isolation fixture retired.

The first attempt stopped before candidate installation because the test
fixture put its interpreter on a `noexec` mount. The second attempt moved
the complete fixture to an owned executable path, retained the mount
protections, and used the identical archive, detached signature and TEST
certificate. Independent closure passed with terminal SHA-256
`2fd1b9f7b00c3ddd24ad58214a1bdd1a9d48209754614214142c9cbf46eb6a17`.

Graphical first login, native 16 KiB execution, physical M2 testing and
production release acceptance remain open.

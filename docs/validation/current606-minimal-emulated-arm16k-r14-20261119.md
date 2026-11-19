# Current606 R14 desktop rehearsal on emulated ARM16K

The minimal Welcome8 guest passed the complete installed-state comparison after
its desktop session. The outer validator then rejected the guest record with
`foreign or missing profile event`. Minimal acceptance remains held. [GitHub Actions run](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/44434774541)

| Input or phase | Verified result |
| --- | --- |
| Source | `caefc14a686f3fa7aaa6d76cfa7df764da478498`, attempt 1, job `135260775692` |
| Builder and guest | Job-built AArch64 reference kernel, 574-package builder, 590-package controller, and 606-package guest with 16 KiB pages |
| Desktop | All 15 original 1024×768 frames verified and visually reviewed, including Terminal, Files, management reports, stored DNS, and the installed Stop and retry |
| Installed preservation | All 606 package identities, 114,247 payload nodes, 4,918,288,238 payload bytes, hardlinks, capabilities, and nonselected package database bytes matched the baseline. The final recheck ended at 672.211 seconds and the verifier exited zero. |
| Retirement | All seven post-session markers completed, the managed user units stopped, and the runtime directory disappeared. The 15 runtime cleanup records passed before producer retirement. |

The retained Original is 27,503,398 bytes with SHA-256
`dc05ce97c7ea76d2c8e5e177880362ab61963416d0c2d488258b6e978fe8815d`.
It contains 551 guest events. Of the records that used a `stage` field, 63
identified the minimal profile and seven named post-session diagnostic phases.
The inherited check treated all seven phase names as foreign profiles. An
offline replay with those diagnostic records validated independently passed
the application contracts on the same retained events. The hosted result
remains held. The overlay case and physical M2 validation remain unrun.

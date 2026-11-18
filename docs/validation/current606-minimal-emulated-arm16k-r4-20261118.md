# Current606 minimal desktop rehearsal on emulated AArch64 with 16 KiB pages

November 18, 2026. The minimal case booted an AArch64 guest with 16,384-byte
pages. The signed runtime inputs joined the exact 574-package native builder,
590-package controller and 606-package guest inventories. The native builder
completed the FDK AAC and updater builds before the guest entered the desktop.
[Run 44316744292, attempt 1](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/44316744292)
· [Native job 134844769340](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/44316744292/job/134844769340)

The trial used source `ddfe829c6ea053d4cb47f47e1652599954bfdfc0`. The
earlier run stopped at the **Assess orphan packages** control. This run
activated that control, opened its report and captured the result. A later
**View report** action in the deliberate package-manager lock refusal case
failed because the accessibility helper could not confirm a focused control.
The refusal itself returned the expected read-only result. The desktop
verifier did not reach the installed-inventory check.
[Earlier run 44302338878](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/44302338878)

Ten retained frames had matching original hashes and were reviewed. They
showed Welcome, First Steps, Updates, System, Recovery, the terminal and
file actions, the unavailable management state, Doctor and the orphan
assessment. The remaining five required views were unobserved. The guest
runtime exited with status 1. All 15 ordered cleanup checks passed before
the original build producer retired.

| Retained evidence | SHA-256 |
| --- | --- |
| Original artifact 14434294544, 27,046,393 bytes | `e883e40b807479cc7e7e34bc7c459859f364c1feb7539c242ba49ae0ed5f5cce` |
| Original workflow logs | `0824faafb998474758953dc8a0de93213aa99b11009a8459ead6ef2e3a4a3472` |
| Independent artifact replay | `fa77b7bfda5e284b08066ba9b94f28a42692f2649ec65a2379b5a62b5d833300` |
| Independent terminal review | `44ebc389dc94006acffc93110f2d92cf649b6c84fa183435dae21fec702bea96` |

The desktop result remains held. A passing minimal case is required before
starting the matching overlay case. Physical M2 and production release
validation remain open.

# Updater 4.4.2-3 native build and installed Check

Hosted run `45715088356` passed on November 25, 2026, at source commit
`96a3848c4c4e7d88a2ac979d27066f99b150315a`. The run enabled retained inputs
and installed Check. Source authentication, acquisition of all 527 pinned
inputs, and the 354-package builder inventory passed. [Workflow run](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/45715088356)

Two clean AArch64 worker launches on the same authenticated image and Docker
daemon built `cachy-asahi-update` `4.4.2-3` for `aarch64`. The package
archives were byte-identical, and the installed file contents and package
metadata matched. The archive SHA-256 was
`44b89959b768c80e82d1e32b29348bdd4b58bfb1fabfba393b14794178d086dc`,
the same digest observed in run 45710280143. [Prior native pair](updater-native-45710280143.md)

## Installed Check

The network-disabled disposable ARM container installed the exact native
package with signature and dependency checks enabled. Native `pyalpm`
imported successfully. The installed `arch-update --check` exercised a
local fixture repository signed with a disposable test key. The stage
verified preservation of the pacman database, updater files, and Apple
policy files. The stage allowed a pass only after checking the exact set
of 15 case names and integer exit codes. The public terminal receipt
records the aggregate result and count.

| Case | Verified exit |
| --- | ---: |
| `pending-versioned` | 0 |
| `invalid-signature-preserves-pending` | 20 |
| `missing-signature-preserves-pending` | 20 |
| `no-updates-clears-pending` | 0 |
| `pending-no-version` | 0 |
| `missing-signature-preserves-no-version` | 20 |
| `optional-pending` | 0 |
| `optional-aur-failure` | 20 |
| `optional-user-discovery-failure` | 20 |
| `optional-system-discovery-failure` | 20 |
| `optional-appstream-failure` | 20 |
| `optional-mask-failure` | 20 |
| `optional-remote-failure` | 20 |
| `optional-empty` | 0 |
| `unconfigured-full-update` | 21 |

All 15 cases passed their expected outcome. Five exited with `0`, nine
returned the expected failure code `20`, and the unconfigured full-update
refusal returned `21`.

## Retirement and recovery

Retained-input retirement, scoped Docker, GPG and process cleanup, private
data removal, and independent recovery all passed. The stage verified
retirement of the disposable test signing state. Stage and recovery receipts
agree on the source commit and controller digest and record private data
removal within the retention budget. The three public evidence frames and
their manifest entries matched the emitted hashes and byte counts.
[Job log and public frames](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/45715088356/job/139559003037)

This run qualifies the native build and signed disposable installation and
Check for this exact revision. The real update transaction, 16 KiB runtime
execution, and physical M2 lifecycle are still open. Production publication
remains unaccepted.

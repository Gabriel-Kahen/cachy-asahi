# Controlled KSM sharing interruption — 2026-10-21

[Run39573487748](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/39573487748)
passed at source `de21d6c25e0fbf5ac83c71965bae3ffa23390461`, ref
`codex/ksm16k-interrupted-sharing-v1`, attempt1. Root accepted the finite result
after sole original collection and complete strict passive replay.

The disposable generic ARM16K VM installed and removed KSM2 through
**574 → 575 → 574**. Original scalar restore/foreign-edit refusal and normal owned
sharing/unmerge checks also passed. The new controlled case delivered SIGTERM to
the owned sharing controller **after real sharing and before run2 unmerge**.
Its explicit handler entered the original cleanup block.

Two children each held2MiB/128 pages. Each child's merging count was
**0 → 128 → 0**; all bytes retained SHA256
`1f06c0f47739edc659beac15e6373441f7693cbf0cd050052d6e089fce6a5f81`.
The controller issued run2, restored run0/pages_to_scan100/sleep_millisecs20 and
zeroed the original sharing counters. Children and controller exited, were reaped
and were absent in fresh outside-parent observations. QEMU exited naturally in
2536.28 seconds within the unchanged3000-second limit.

The original artifact is718,174 bytes, SHA256
`50268d51d15076d2866b8df0a6b298f830375350362e1c41f402cb2727ea8b1f`.
Its bound kernel is aarch64,16K, modules disabled, with Image SHA256
`039fbeaff5942de2317f47feec30a5c073691edf5f8cef8849b25d08006d4ddb`.
The maintained controlled-interruption factory was integrated through PR171;
portable process controls and hosted source checks are separate from this VM result.

Local full replay and decision are
`artifacts/development/ksm16k-interrupted-sharing-native-actual-20261021/Root-strict.json`
and `Root-component-acceptance.json` in that directory.

This qualifies the owned test controller's controlled interruption only. Installed
scalar-command interruption remains NOT RUN. Arbitrary crash recovery, foreign
memory rollback, either M2 Air size, performance and release acceptance remain
unqualified. Full private maps and host retirement are source-enforced recorded
observations; Root did not rerun GPG or inspect a live retired host.

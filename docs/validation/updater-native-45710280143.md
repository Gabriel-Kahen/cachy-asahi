# Updater installed Check provenance limit

[Hosted run 45710280143](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/45710280143)
ran the retained-input installed Check lane at
`7ecf6af33c1504732c7ab316064205f50368e4c0`. Both clean native AArch64
builds passed and reproduced package SHA-256
`44b89959b768c80e82d1e32b29348bdd4b58bfb1fabfba393b14794178d086dc`.

The stage stopped at `installed-prepare`, with `archive-metadata` and
`invalid-input` in the bounded diagnostic. The installed container never
launched. Stage cleanup, private-data retirement, and independent recovery
passed.

The worker provenance includes per-file output hashes from the retained
source closure. Its vendor entries alone exceed the 64 KiB limit used by
capsule preparation. The corrected capsule and broker use the existing 4 MiB
worker evidence limit and still require the exact archive digest. The local
regressions exercise oversized historical reads and digest mismatch refusal.
The installed Check cases and full-update qualification remain open.

## Subsequent scanner interruption

[Run 45713473375](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/45713473375)
stopped in the first native worker before capsule preparation. Its bounded
diagnostic reported `OPEN_FD_IDENTITY`, `DESCENDANT`, and `MODE` during the
private scan. The exact path and mode change were unavailable. Input
retirement and recovery passed.

The scanner now allows mode changes on the same descendant directory inode
when all observed modes satisfy the existing permission policy. It still
checks the root mode, path and descriptor identity, owner, type, mount,
permissions and storage limits. Local tests cover both stat windows and
refusal of unsafe permission changes. A hosted retry is needed to exercise
the installed capsule after both fixes.

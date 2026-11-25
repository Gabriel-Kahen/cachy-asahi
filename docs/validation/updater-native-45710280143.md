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

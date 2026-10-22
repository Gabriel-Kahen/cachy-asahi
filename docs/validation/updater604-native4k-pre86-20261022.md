# Native ARM4K updater pre-commit interruption

Root accepted [39776814384](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/39776814384), source `c75911fe09fb5ceba1e54a6456d5b9c4721960b6`, for the finite precommit-exit86 case after its complete 1442-file validator and all10 source/1442 reader/original-evidence postpins passed. This is a disposable native Linux/aarch64 container with4096-byte pages. It copied125358 nodes, retained604 packages with603 protected, started no package commit, committed zero transactions, preserved the source and unchanged checkpoint, and disposed its owned copy.

Private node/hash/ownership/user maps and the exit86 fault witness remain unexported; their assertions are enforced by the frozen original implementation and retained receipts. Cleanup uses original source-bound receipts, without fresh queries of retired actors. The result qualifies owned-copy disposal for this pre-commit interruption. It does not qualify package rollback, boot recovery, the separate16K path, M2 hardware, performance or a supported release.

The immutable [sixteen-file record](https://github.com/Gabriel-Kahen/cachy-asahi/tree/9d2322f3bf88dcd427227c0d6449ccff296cddd6) retains4144216 bytes: the issued decision, full result, post-validation pins, six once-acquired original transport/custody roles and four source-publication receipts. Replay still requires the original pinned source, signed inputs and full inspector prerequisites. No private rootfs, raw private graph or key secret is included.

The separate [postcommit-exit87 result](updater604-native4k-post87-20261022.md) covers the case after one Apps5→6 commit. Neither case transfers a boot-rollback claim. Both M2 Air sizes remain NOT RUN; release remains NOT ADMITTED.

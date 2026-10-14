# Native ARM queue topology and future P0 reservation

The repository-wide `native-arm-build` group is the concrete reason independent non-kernel trials serialize. All eight selected non-kernel workflow Sources use that literal group with `queue:max` and cancellation false. GitHub permits one running workflow per group; queue expansion preserves pending entries rather than adding execution slots. [GitHub concurrency documentation](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency).

Root's retained repository observation at 2026-10-14 19:28:37 UTC records two active runs: Library and Kernel. Its selected-run observation at 19:28:40 UTC records the seven other runs pending. This review authenticated those local records and exact Source workflow bytes using read-only Git; it did not independently poll live API state.

| Lane | Run | Selected Source | Group/status at observation |
| --- | --- | --- | --- |
| Library | 38610255544 | `32dea27b8c3ea0b8fc618eb5db9761b5291d428f` | native-arm-build / active |
| Pair | 38611783071 | `0e886ca6c3daa35e33b61829c8041770f36d6350` | native-arm-build / pending |
| Zsh | 38611787402 | `ce7af5efbe5d200793d58203f0ce2dea996d2911` | native-arm-build / pending |
| Composed | 38614475627 | `1794d046724681408462beff297de7ba03fc651f` | native-arm-build / pending |
| Updater | 38617063734 | `842a821eceaa8448f5081a2b0db39a1025dd3e54` | native-arm-build / pending |
| KSM | 38618847844 | `a90db716e353f9c6907b7b20c598d50445dd0b05` | native-arm-build / pending |
| CLI | 38620204222 | `4c388cc74bbef1113908f99a1bacafc656746e39` | native-arm-build / pending |
| Kernel | 38620355690 | `3bec0e2e300a0fc9ee11abb3b20866cfb7508c7a` | native-arm-kernel / active |
| FDK | 38623533412 | `220b4eb2beb7d57e7e9e487a8a2f7a9cdc4776bc` | native-arm-build / pending |

Every selected job uses standard `ubuntu-24.04-arm`, not a self-hosted/shared builder label. GitHub documents a new VM per such job, nominally four CPUs, 16 GB RAM and 14 GB SSD for public repositories. Identical `/run/docker.sock`, workspace or temporary paths therefore refer to separate job VMs. [Runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).

The inspected Source boundaries select local Unix Docker sockets and runner-local owned cache/source/output/process/GPG resources. Library/Pair/Zsh/Composed/CLI have distinct Root-plan variable pairs; workflow code reads them. Updater/KSM/Kernel use their existing pinned manual inputs. Git and upstream/archive/secrets inputs are reads. All workflows grant contents:read; no selected workflow publishes Actions caches, changes repository variables, pushes Git/container releases or grants contents/packages writes. Pair/Zsh and KSM artifact uploads use run/attempt-specific names. Those uploads share service/storage allowances, not a mutable builder workspace. This is a bounded inspection of captured entry bodies and workflows, not a universal Python graph proof.

The project policy already permits independent clean ARM builds within capacity, while serializing changes on each reference Mac and reserving uninterrupted measurement windows. The earlier global queue review deliberately held serialization pending a fresh reservation review; it did not demonstrate that these hosted jobs shared a daemon. Its old seals remain unchanged. Real same-lane plan/ref registration, future shared signing/release writers, hardware and controlled measurements still need their respective coordination.

The next safe action is to prepare and independently review the **new unpublished NativeCI P0 workflow** with this future-only scheduling block:

```yaml
concurrency:
  group: native-arm-p0
  cancel-in-progress: false
  queue: max
```

Reserve at most three project hosted jobs for that pilot: one existing global job, one existing dedicated kernel job and one P0 job. Preserve every existing queued/running Source, execution ref, variable, grant and dispatch. The new group is scheduling only: exact published Source/Code/Data/Root bindings, actor grants, first-cause/cancellation, original clocks/limits, cleanup and publication gates must still pass the existing review and validators. NativeCI owns the concrete P0 Source freeze; this review supplies no prospective commit or new authority boolean.

Before one future Root-owned manual admission, check the fresh repository active-run observation against that three-job reservation, retain standard public runner labels, keep queue:max/cancellation false and validate the exact P0 Source and plans after independent peer review. Do not introduce a default-single entrant into the existing global max queue. Do not raise paid runner or storage settings. Root then records actual queue wait/runtime before any wider rollout. No new dispatcher, watcher, framework or universal resource gate is proposed.

Official limits list 20 standard hosted concurrent jobs for Free, with other plan limits; actual account-wide available headroom and service availability were not measured here. The provider may queue the pilot. Root separately verified this repository PUBLIC at 19:24 UTC; standard hosted compute is free for public repositories, while artifact/Packages storage remains a shared allowance. No storage-headroom or blanket zero-cost claim is made. [Actions limits](https://docs.github.com/en/actions/reference/limits), [billing documentation](https://docs.github.com/en/billing/concepts/product-billing/github-actions).

Seven group-only workflow examples are retained under `proposed-future-workflows/` as later alternatives, with exact inverse checks preserving every other workflow byte. They do not migrate any current entrant. Any later adoption needs real successor Source pins and the existing per-lane Source-bound Data/peer/Root-plan/freeze cascade; old Data cannot be assumed reusable merely because actor bodies stay held. No old run result/cause is reclassified, no current queue was changed, and throughput improvement remains potential rather than measured.

Evidence: [observed reservation](../../artifacts/reviews/native-arm-queue-topology-20261014/reservation.json), [pinned topology](../../artifacts/reviews/native-arm-queue-topology-20261014/topology.json), [FDK addition](../../artifacts/reviews/native-arm-queue-topology-20261014/fdk-topology-addition.json), [future alternatives](../../artifacts/reviews/native-arm-queue-topology-20261014/future-scheduling-plan.json), [receipt](../../artifacts/reviews/native-arm-queue-topology-20261014/receipt.json).

# Provider-bound native build batch — October 27, 2026

Root accepts this finite two-package native ARM failure/resume trial, with status `ROOT_ACCEPTED_FINITE_NATIVE_TWO_PACKAGE_REAL_FAILURE_AND_RESUME_ONLY`. Its independent full strict replay exits 0 with `MATCHED_FINITE_NATIVE_TWO_PACKAGE_FAILURE_AND_RESUME_ONLY`; see the [Root qualification](../../artifacts/development/provider-batch-startup-fix-native-actual-20261027/Root-complete-projection-independent-20261027/Root-native-qualification.json) and [strict result](../../artifacts/development/provider-batch-startup-fix-native-actual-20261027/Root-complete-projection-independent-20261027/strict.stdout).

## Exact identity

| Item | Bound value |
| --- | --- |
| Source | [`29c3980a27d0e939cbc2a1e7bb84b40d47a051f3`](https://github.com/Gabriel-Kahen/cachy-asahi/commit/29c3980a27d0e939cbc2a1e7bb84b40d47a051f3) |
| Ref | `codex/provider-batch-startup-fix-v2` |
| Run / attempt | [40459874118](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/40459874118), attempt 1 |
| Job | [122041674073](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/40459874118/job/122041674073) |
| Workflow | `.github/workflows/native-arm-build.yml`, ID `381664314` |
| Artifact | `12714515653`, `batch-native-trial-40459874118-1`, 617360 bytes |
| Artifact SHA256 | `0a05d7794f62cdc3d9880078bf678a39092ce9afd70957ba1751998084f46c32` |

The [once-collected originals](../../artifacts/development/provider-batch-startup-fix-native-actual-20261027/Root-provider112-originals/collection-complete.json) bind source, run, attempt, job and artifact. Root's corrected strict replay uses those same originals. The source qualification covers all 112 files; the observed generic ARM environment has 4096-byte pages.

## Actual result

Fish attempt 1 targeted an inspected, running, owned container, `cachy-asahi-393786167d41c695`; `docker kill --signal=KILL` succeeded and that build failed. Zsh attempt 1 succeeded independently. Resume retried only Fish, whose attempt 2 succeeded: three attempts total, with the original failed Fish record and successful Zsh record preserved.

Both checkpoints bind the same admission SHA256, `8e8af1fc0f8692cb3b7aa567a4182785083082fa062340de29944bdb15d2b93d`. The final state is `COMPLETE`, kind `PINNED_OCI_BUILD_PY`.

| Successful archive | Bytes | SHA256 |
| --- | ---: | --- |
| `cachy-asahi-fish-config-0.1.0-1-any.pkg.tar.xz` (attempt 2) | 7204 | `ab7eb806f7a074623fc8757249cf255bfc56a3b234d27d7d84f24889d7546c70` |
| `cachy-asahi-zsh-config-0.1.0-1-any.pkg.tar.xz` (attempt 1) | 8044 | `d653c12aef4684aa098786f0053d619ebb3e73712dffc8e002e8fff6b61e86db` |

Both archives retain exact source-matched payloads and recipe metadata. Each `.BUILDINFO` contains all 574 installed name/version/architecture identities, including epochs. The image-bound provider capture records `curl → ca-certificates` and `systemd → dbus-broker-units`, preserving both candidates for each query and unchanged database snapshots.

Cleanup receipts cover all three build attempts and three capture/planner containers before the original 574-package producer. Producer receipts record probe and image absence. Hosted step logs establish cleanup before retention. These are passive receipt/order joins; the reader performs no live daemon inspection.

## Preserved history and limits

[Initial run 40453098607](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/40453098607) remains failed and unaccepted: its observer treated not-yet-created provenance as fatal, so fault/resume was not established. Its [failure DATA](../../artifacts/development/provider-bound-build-batch-native-actual-20261027/Root-provider112-failure-DATA.json) remains retained.

The successful run's historical reader refusals also remain intact: [builder recipe metadata](../../artifacts/development/provider-batch-startup-fix-native-actual-20261027/Root-provider112-strict.stdout) and [full574 BUILDINFO](../../artifacts/development/provider-batch-startup-fix-native-actual-20261027/Root-strict-full-metadata.stdout). Exact source/evidence comparisons corrected the reader's `.SRCINFO` projection and architecture-qualified installed identifiers; original evidence was unchanged.

Public retention excludes the original 574 baseline archives, so their recipe-pin extraction cannot be independently replayed. Other database files and the ALPM library use retained identity/hash records rather than retained bodies. This trial grants no independent build-pair/reproducibility, installation, sustainable-capacity, 16K, physical M2, performance or release acceptance. It completes no roadmap milestone or full-port requirement.

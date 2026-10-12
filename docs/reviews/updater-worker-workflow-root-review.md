# Updater worker workflow: independent cross-receipt review

**Current disposition: BLOCKED at corrected hold `83d4fbc9e2babfafc134b2df436e0bdb34b233502aea92edf9e2ee50741959c7` on the requested separate-compile-proof boundary (UWC4). UWC1–3 are independently CLOSED; see the final-hold recheck below.**

Historical disposition: **BLOCKED at held workflow `99a20d4ebd85f6d7d531c4f4820e293cd7647dc3d8ae65b8850e4a5d1db31973`.** The original failed/missing-worker defect is closed. Three remaining correlation defects reproduced false workflow PASS and were accepted by the coordinator for a workflow-only correction. Do not register or dispatch this held candidate as accepted source.

## Exact source and validation scope

Read the current roadmap/inventory, author review, actual package parent/projector contracts and the changed workflow consumer. Before imports, verified all seven held helper/workflow hashes and the coordinator source85 map `f9fb96b4075a504d8bc468dfb2e96d2710f8342348e38daf3c26d8ed70fc7cab`: **85 files, 4,044,082 bytes**, exact current bytes/modes. Made a fresh 86-file copy including the workflow. Ready map remains `be72334e4108dddfaaf51b59f7fb27d410a7543f6c3f8e98eb5f0ed971608089`.

| File | SHA256 |
| --- | --- |
| `.github/workflows/native-arm-updater.yml` | `99a20d4ebd85f6d7d531c4f4820e293cd7647dc3d8ae65b8850e4a5d1db31973` |
| `packages/tools/cachy-asahi-update/public-evidence.py` | `26adacbba6fa16b8ca10aaef1fefd8b74ba2604e3b0f0435d669ee9fa4037d1b` |
| `scripts/port/updater-native-stage/stage.py` | `b872fb47c03cb3c9124df5056cc34fb9e02ffcbe49753447676585862e840a7a` |
| `scripts/port/updater-native-stage/broker.py` | `9a2a1efc63cbd8b78dacd242065a0e5e77605fdd0d6e13b2dcdb561976b18d31` |
| `scripts/port/updater-native-stage/public_worker.py` | `73c8e85b229ea41e6ad48bd7feac2dfae36d433eeed2ff95f97b0433b2759278` |
| `scripts/ci/integration_export.py` | `1ae8aded5ab461b280ca1ff82047f6766d58efacf7a09c83dc84515ac7d2216c` |
| `scripts/ci/log_evidence.py` | `a25f0089759c12afae3eea23bab8b22fa05cf5bbaa9eddc1611ce78b0405f8f5` |

The exact extracted consumer hash is `a505d809b43dc120729c8025949e82505bb24dabeacbc1a9796029e5554bd2ee`. Five author evidence hashes were independently verified, including the 452-consumer, before/after, source audit and independent review receipts. Their reported 452 consumer/22 independent/40 clock checks are prior evidence, not newly rerun here.

Independently executed **20 causal consumer cases** against the fresh copied actual projector, exporter, bundler and exact workflow heredoc. Sixteen met the required outcomes; four exposed the three defects below. Four retained counterexamples also independently replayed after relocation with the same exit-zero/three-bundle/global-PASS result. The fixture substitutes source/controller authentication with a bounded stage stub; projection, canonical manifests, bundle/terminal digests, receipt validators and consumer logic remain actual captured code. This isolates the receiver mechanism without claiming real controller authentication, a native build or a hosted failure cause. No Docker, network, signing, installation, system or Git mutation occurred.

## Original defect: closed

The historical consumer accepts a coherently rehashed pair PASS with present worker FAIL/client125 or missing worker2: exit zero, three bundles and `updater_workflow: PASS`. The held consumer refuses both failed-worker selectors, either missing selector, removal of both workers under the current authenticated parent context, incomplete cleanup, mismatched observed controller/image, explicit pair cancellation/error and false comparison. Refusal occurs before emitting any bundle.

A valid complete pair still emits three bundles and exits zero. A legitimate worker/client125 failure with observed container exit zero publishes finite FAIL diagnostics, emits three bundles and exits one; successful cleanup/recovery does not promote it. Actual process return, observation and image/controller binding remain separate. Raw custom error text does not become a new public diagnostic field.

## UWC1 — duplicated execution identity accepted as two clean workers (P2)

Copy the complete `build-1/provenance.json` bytes into `build-2/provenance.json`, retaining pair PASS and equal comparison. Both worker receipts individually attest client zero, complete observation, accepted exited-zero/non-OOM state and four positive cleanup booleans. Both selectors now contain the **same controller hash, container ID, nonce hash and name hash**.

The actual projector accepts both, and the current consumer emits all three public bundles and exits zero/global PASS. This contradicts the actual unchanged parent's `compare_pair`, which requires distinct worker nonces before returning comparison success. The receiver verifies each identity internally but does not reconcile the pair's distinct execution identities.

For modern pair PASS, require independent execution identities where present; at least identical controller/nonce/container identity cannot attest two clean workers. Preserve ordinary different controllers/nonces and truthful failed-pair diagnostics. This does not require comparing the two controller hashes for equality: each actual controller includes a distinct nonce.

Retained exact fixture: `counterexample-duplicate-worker-identity-pair-PASS/`.

## UWC2 — explicit incomplete stages accepted alongside completed PASS (P2)

Two independently projected and rehashed variants still exit zero/global PASS with three bundles:

- Native result: `native_pair: PASS` with `stage: worker-1`.
- Worker1: successful package/complete observation with `stage: input-snapshot`.

The actual parent always sets terminal native and worker receipts to `stage: finalized`. The current consumer checks `failed_stage` and successful observation fields but ignores an explicitly present unfinished stage. Sparse omission compatibility need not be removed; a present incomplete-stage assertion must not accompany accepted pair/worker completion. This is a receiver consistency failure, not proof that the unchanged parent generated these contradictions in a hosted run.

Retained fixtures: `counterexample-pair-PASS-present-worker-1-stage/` and `counterexample-worker-PASS-present-input-snapshot-stage/`.

## UWC3 — explicit cleanup FAIL ignored beside positive booleans (P2)

Add the projector's admitted finite field `container_cleanup: FAIL` to otherwise complete worker1 provenance. The four cleanup booleans remain true. Every receipt and wrapper hash validates, but the consumer emits all three bundles and exits zero/global PASS.

The success receiver must reconcile an explicitly present cleanup outcome rather than treating the positive booleans as overriding a known failure assertion. Likewise, no correction should require new fields in legitimate failed receipts or export raw exception strings.

Retained exact fixture: `counterexample-worker-PASS-explicit-container-cleanup-FAIL/`.

## Disposition and reproducibility

The coordinator accepted these findings and routed a narrow workflow-only correction. Source, shared maps/pins, Git and native dispatch remain untouched by this reviewer. Historical raw counterexample directories and their actual consumer output are retained unchanged. Stop further test breadth until a new held workflow hash is supplied; then replay the original worker/missing-worker regressions, these distinct-identity/stage/cleanup cases, valid complete-pair and finite FAIL controls.

Owned evidence is under `artifacts/reviews/updater-worker-workflow-root-peer-20261012/`: `capture.json`, `fixture.py`, `probes.py`, `probe-results.json`, `consumer.py`, `historical-consumer.py`, `replay-counterexample.py`, the fresh selected source copy and four `counterexample-*` directories. Replay one retained counterexample without regenerating its evidence:

```sh
python3 -B artifacts/reviews/updater-worker-workflow-root-peer-20261012/replay-counterexample.py duplicate-worker-identity-pair-PASS
```

Corrected native execution, compilation, Docker cleanup/disposal, installation, hardware and performance acceptance are **NOT RUN** by this review. Trial `38251407975`'s hosted cause remains **UNPROVEN** and compiler invocation **NOT ATTESTED**. Current source85 byte proof is independent of committed Git/controller proof, which remains the coordinator's separate gate.


## Corrected 83d4 hold: focused final recheck

Verified workflow **83d4fbc9e2babfafc134b2df436e0bdb34b233502aea92edf9e2ee50741959c7**, author review **4ca72bc9d2b1ea0daaaf3bd60dd1c26ebc73d222b9086f23a23cc9935b33d699** and new extracted consumer **a0b4f346ca270368017f43d82f2632c9c7e43ce9202c124b4fe868a25eb8f0e1**. Created another fresh 86-file copy and verified source85/map/ready/stage and all six held helper/test pins unchanged. All current copied/live bytes, sizes and modes matched after the checks; no retained PYC. All workflow bytes outside the final consumer heredoc remain identical to99. Five final author evidence hashes were verified; 478 author cases, 41 other-independent cases and40 deadlines are their reported retained evidence, not newly executed counts here.

Preserved the original blocked review and receipt byte-for-byte under `held83/historical-blocked-{review.md,receipt.json}` and left the original four counterexample directories intact. Replayed those exact four retained fixtures: every one now exits one with zero emitted bundles. Because the old seed also reused a name hash, separately isolated each new predicate using a corrected modern seed with genuinely distinct container/name/nonce/controller identities. All three incomplete-stage/cleanup assertions and all four singly duplicated execution identity fields refuse before publication. This confirms UWC1–3 closure rather than attributing every refusal to the newly added name-hash check.

The valid modern pair and present finalized/PASS cleanup fields still emit three bundles and exit zero. A finite failed worker with incomplete-stage/cleanup diagnostics emits three truthful bundles and exits one. Missing or failed worker1/2 remain refused. Guard metadata `native_compilation: NOT RUN` with a separate compile PASS is accepted; separate compile FAIL or NOT RUN are refused.

**Actual focused result: 22 consumer cases, 21 required outcomes met and one false-PASS counterexample.** These are actual captured-helper consumer executions with only source/controller authentication stubbed; no native or daemon execution.

### UWC4 — NOT RUN precompile guard accepted without separate compiler proof

The coordinator's final review task explicitly requires that precompile NOT RUN remain a guard observation while separate compile proof is required. Add actual-projector-admitted worker metadata `{native_compilation: NOT RUN, build_script_execution: NOT RUN, controller_sha256: <matching>, image_id: <matching>}` to an otherwise valid modern/current-source pair, **omit `build-1-compile-result.json`**, and coherently regenerate every projection, manifest, archive and terminal digest.

The held83 consumer emits three bundles, exits zero and prints global updater workflow PASS. It permits NOT RUN in `-worker.json` but never requires a separate compile-result selector when making that exception. A present compile FAIL/NOT RUN is checked; a missing compile proof is silently optional. Parent package/pair PASS assertions are present in this synthetic fixture, so this finding concerns the coordinator's explicit separate-proof contract and the receiver's completeness, not proof that the actual parent skipped a compiler in a hosted run.

For the requested contract, condition the NOT RUN guard exception on the matching worker's present successful compile receipt (including existing identity/status/cancellation/stage checks). Preserve valid modern metadata with actual compile PASS and truthful finite FAIL diagnostics; do not invent compile work from precompile metadata or relax opaque/raw error export rules. If a different authority policy intentionally permits parent-only compilation attestation, the coordinator must state that distinction before source acceptance.

Exact retained counterexample: `artifacts/reviews/updater-worker-workflow-root-peer-20261012/held83/counterexample-precompile-NOT_RUN-without-separate-compile-proof/`. The original source/probe captures are in `held83/{capture.json,closure-probes.py,closure-results.json,final-source-stability.json}`. No wider historical suite was repeated. Source acceptance remains blocked pending the narrow correction or explicit contract disposition; native execution is NOT RUN by this review.

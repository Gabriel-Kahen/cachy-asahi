# Updater worker-observation workflow review and correction

2026-10-12. **CORRECTION IMPLEMENTED; CONSUMER, SYNTAX, DEADLINE AND INDEPENDENT FINAL CHECKS PASS.** The historical adopted consumer accepted a present failed worker while claiming workflow PASS. The corrected final consumer rejects contradictory positives before publication, requires both observed workers for the authenticated current source contract, and preserves truthful typed failure diagnostics. No native acceptance follows from these fixtures.

## Held scope

The corrected captured workflow is `9fb111d778fb065dfbcc7c7baf3803fc96548ee7b614d06a33305a744b3ea885`; its adopted literal-only baseline is `c3f800b7fb3365c9cb7007fca501e98365b49c88a83d759b6faa35da05a3a27b`. Stage is `b872fb47c03cb3c9124df5056cc34fb9e02ffcbe49753447676585862e840a7a`; ready map is `be72334e4108dddfaaf51b59f7fb27d410a7543f6c3f8e98eb5f0ed971608089`. Their literals agree. The projector is `26adacbba6fa16b8ca10aaef1fefd8b74ba2604e3b0f0435d669ee9fa4037d1b`; captured stage projection functions, public-tree helper, generic exporter and bundler are exercised. The exact seven final captured file hashes are recorded in `compile-proof-correction/captured-hashes.json`.

All six implementation/test hashes match the prior held receipt. Independently rehashing the coordinator's final input map confirms 85 files and 4,044,082 bytes. This checks current bytes and modes recorded in that map's inputs; committed-source collection, Git proof and controller/host authentication remain coordinator responsibilities. Only the final workflow public-consumer heredoc, this review document and owned fixture/evidence files changed. All workflow bytes outside that heredoc, source helpers, packages, shared pins and Git state remain unchanged by this correction.

## Implemented final-consumer correlation

The consumer reconciles every claimed native-pair PASS with successful comparison fields and both fixed worker selectors. The authenticated current 85-file contract contains the parent adapter; that context requires both complete worker observations even if receipt fields are removed. An immutable native image or any present observation group also triggers this requirement. Each worker must attest parent package PASS, launch and cleanup completion, client zero, complete/no failure, no explicit cancellation and a validated exited-zero/non-OOM/error-free state. Its state must match its own controller and image; both workers and any present bootstrap/child image fields must match the pair image. Worker controller hashes are not compared to each other because each controller includes a distinct nonce.

Any present package validation must contain one successful artifact; every reported top-level, artifact and ELF error count must be zero. Explicit package digests must agree with their parent and the byte-equality claim. Present input, entry, compile and worker receipts cannot contain explicit failure, cancellation or inconsistent image/controller identities when the pair claims PASS. The actual entry receipt has no compiler status; none is invented or required. A terminal public-compilation PASS PRIVATE NATIVE PAIR requires a present native-result PASS even if the terminal itself reports FAIL.

Sparse legacy pair receipts remain compatible when the source context does not identify the current parent adapter and no image/new observation group claims current-format success. Explicit present failures or an unattempted worker still block that claim. The live authenticated current source contract cannot enter that sparse fallback by removing receipt fields. Native-pair FAIL diagnostics do not acquire unrelated new requirements, so a successfully compiled child followed by parent package failure remains publishable as a failure.

The four-case exact old/new replay now refuses a present worker FAIL/client125 and a missing second worker, both previously accepted. Valid complete-pair success still passes, and typed worker failure still emits all three diagnostic bundles with exit one. Contradictory positives emit no bundles.

## Historical P2: present worker failure was not correlated

The historical c3f800 workflow at lines 272–275 requires native-pair PASS and successful comparison fields. Every selected receipt is independently checked against its current projector, but the success predicate does not reconcile present worker status receipts with the pair result.

The additional case first passes a worker FAIL observation through the captured actual projector and exporter: client 125, worker-run-result, worker-nonzero-returncode, observed container exit zero and OOM false. It then supplies native-pair PASS, equal comparison results, original/recovery terminal PASS and successful step exits, coherently regenerating projection/manifest/bundle hashes. Every receipt is individually valid. The exact captured consumer emits all public bundles, exits zero and prints `updater_workflow: PASS` despite the worker failure. The expected invariant result is refusal and exit one.

For a claimed successful pair, reconcile each present worker receipt with success before emitting: a present new observation must have successful parent package status, complete check, zero broker/client result, no failure/cancellation and an accepted observed terminal state. Preserve sparse historical compatibility without allowing an explicitly present contradictory worker outcome to pass. Add this coherently rehashed fixture to the workflow-consumer regressions. This historical finding is corrected by the bounded final-consumer change above.

A second reviewer independently reproduces the same exit-zero/global-PASS outcome; `syntax/cross-review.json` records the P2 finding and exact captured helper hashes. `cross-receipt-result.json` records the failed invariant and exact worker fields; `cross-receipt-probe.py` reproduces it. The synthetic selected inputs, manifests and consumer output are retained under `cross-receipt-inputs/`. These fixtures contain no actual private build logs or package payloads.

## Passing checks

The final corrected consumer passes **507 cases**: 381 preserved cases, 29 observation roundtrips/poisons, 42 initial correlation cases, 26 identity/lifecycle cases and 29 conditional compile-proof cases. The 381 preserved consumer cases comprise 147 original cases and 234 storage/cleanup cases. Their historical harness and storage extension remain unchanged. A fresh owned harness extracts the exact adopted consumer and uses captured actual helpers. Only fixture source/controller authentication is replaced, and the fixture ready literal is updated to the adopted value.

The 29 new cases comprise one completed successful roundtrip, ten valid failure roundtrips and eighteen poisoned projections. Valid failures cover client 125 with container zero, client 137 without inferred OOM, actual observed OOM/container 137, unaccepted state, inventory mismatch, symlink output, malformed/foreign inspection, launch failure and cancellation. Normalized ValueError and BuildCancelled outcomes remain publishable as failures; recovery does not promote them. Poison cases cover custom/unbounded public error types, contradictory parent PASS, boolean/out-of-range return codes, cross-phase/private causes, partial groups, malformed/extra state fields, outer image mismatch, launch false, raw exception text and cancelled native success. Recomputed wrapper hashes do not bypass refusal, and poisoned bundles are not emitted.

Four exact Bash blocks pass `bash -n`; three Python heredocs and four inline clock expressions compile. Forty controlled-clock cases preserve historical acceptance/refusal and emitted seconds. Clock expressions, deadline/timeout/kill boundaries and the full stage budget remain unchanged. YAML/actionlint validation, actual run-block execution, physical deadline enforcement, daemon disposal and storage-fit tests were not performed here.

The correlation cases additionally check both failed/missing workers, cleanup failure or missing attestation, coherent image/controller drift, package error/status/digest contradictions, explicit child failures, current-source sparse downgrade, positive terminal compilation against failed/missing native results, and legitimate omission of cancellation/compiler status. All are synthetic actual-helper transformations with source/controller authentication mocked.

## Historical evidence preserved

All paths below are under `artifacts/reviews/updater-worker-workflow-review-20261012/`.

| Receipt | SHA256 |
| --- | --- |
| `consumer-results.json` | `fec5e054b9d91709fdf2f5dd2ec575c294990a73e910484de785562f19faff92` |
| `source-audit.json` | `b5f4c167a06ad51439609dd369c995762fabbbb0a6e8fad578be364a3e040860` |
| `syntax/results.json` | `79b46da4fb2d7572e700bffd5d8ffaa928f0b2dfbbe9769a3ca3ce5fd6ee8198` |
| `syntax/cross-review.json` | `ee978aafd8f69fe5e16a9ac5f5b7e31ae3b09baced76e7c0dcbccb9b17d1792c` |
| `cross-receipt-result.json` | `6cd7828a9d196fcd43b34181e9a10a98ff7c238784f643ea0a1059517453fe76` |
| `cross-receipt-probe.py` | `3076c87745fd9c3b132e8f3958b7a462b928dc7310bbe8db5500f45eecddd988` |

No native build, Docker, network, installation, hardware or performance execution occurred. Trial `38251407975`'s exact cause remains UNPROVEN and compiler invocation remains NOT ATTESTED. Passing fixtures do not grant native-overlay acceptance.

## Root-peer residual findings and final correction

The peer's broader review of 99 found three residual classes: a copied worker could stand for both executions, explicit nonterminal native/parent stages could coexist with PASS, and an explicit container-cleanup FAIL could coexist with true cleanup booleans. These were missed in the prior bounded review; the prior 99 receipt remains historical and is superseded.

The 83d4 consumer requires distinct container IDs, name hashes, nonce hashes and controller hashes for the two modern workers. A present native or parent stage must be finalized. Present child stage assertions must be complete/finalized, and present container-cleanup assertions must be PASS. Absent legacy fields remain absent; truthful FAIL diagnostics are unaffected. The source-audited precompile worker metadata explicitly declares native compilation NOT RUN, which the consumer now preserves as a guard observation independently of the separate compile receipt. It does not infer compiler work from that metadata.

The valid synthetic second worker seed now has a distinct name hash; the old seed mistakenly reused the first name hash even while assigning distinct nonce/container/controller hashes. Four exact retained root-peer counterexamples pass on the old99 consumer and are refused without emission on 83d4. Nine isolated old/new cases prove each separate identity/lifecycle check causally, preserve valid success, and show that actual-producer NOT RUN metadata plus a separate compile PASS is accepted. The unchanged worker-metadata producer was source-audited, not executed.

Independent final verification passes 41 workflow cases, syntax and 40 exact historical deadline fixtures on 83. All six helper/test files, stage, ready map and 85 source-file bytes/modes remain held. Root-peer original fixtures and all prior review artifacts remain unchanged. Final source/Git proof and native dispatch remain coordinator responsibilities.

## Conditional compile proof after a precompile observation

The peer's 83d4 closure review found one remaining conditional gap: current-source worker metadata could explicitly report NOT RUN, omit the separate compile receipt, and still publish workflow PASS. The prior 83d4 bounded review is superseded; its exact retained counterexample and evidence remain unchanged.

For a modern claimed successful pair, any present precompile worker metadata reporting NOT RUN now requires its fixed separate compile-result selector. The receipt must report actual producer PASS, match the immutable worker image, and contain all five input digests exactly matching the metadata's five-input vector. Metadata controller identity must match the parent/state controller. Five required producer output digests cover the binary, compiler output/diagnostics, ELF inspection and compilation units; the producer's static 16K ELF result is required. Existing cancellation, failure, stage and cleanup refusal checks apply. Any declared controller/entry identity must agree with its parent; actual compile receipts do not declare those two fields, so neither is invented or required when absent. This binds projected assertions without attempting to recompute private hashes from lossy projections.

This requirement is conditional on modern positive claims and a present NOT RUN guard observation. Honest native-pair FAIL diagnostics and unrelated sparse historical context do not acquire a new compile requirement. Metadata remains a precompile guard observation and never becomes compiler-work evidence by itself.

The exact peer counterexample changes from exit zero/three bundles on 83d4 to exit one/no emission on 9fb111, with retained controller and selected evidence bytes unchanged. Its temporary fixture root was not retained by the peer; replay reconstitutes identical captured helper bytes and the bound authentication stub. Six isolated old/new cases prove missing/bare/incomplete or input-drifting proof refusal, retain complete producer-shaped positive success and preserve honest FAIL diagnostics. The prior valid positive fixture's bare PASS placeholder was expanded to the actual producer image/input/output/static-result fields; prior records remain immutable.

Independent verification passes 88 workflow cases, syntax and 40 historical deadline fixtures on 9fb111. Both compile and metadata producers were source-audited through AST and exact hashes, not executed. These synthetic digest checks do not attest a real native build, physical VM deadline enforcement, M2 behavior or performance.

## Final correction evidence

Fresh final source captures, scripts, causal replays, receipts and the 83d4-to-9fb111 patch are under `compile-proof-correction/`. All prior correction, blocked review and peer records remain unchanged. The final packet is `compile-proof-correction/final-review.json`, independently supported by `syntax/compile-proof-review/review.json`. Earlier 99/83d4 packets are historical. Final source/controller Git proof, workflow binding and native dispatch remain coordinator responsibilities.

| Prior 99 correction receipt (superseded) | SHA256 |
| --- | --- |
| `correction/consumer-results.json` | `b81a1f6adc553d701ad89eebeb62b3a6704caf57b0fb096916e89f52ca034126` |
| `correction/before-after-results.json` | `51ac080e453efa649b0e7ba0983dcdc9c8f78fcd2269690cacdf1bab0d22b3b9` |
| `correction/source-audit.json` | `21a05d30ed8bb65ae5d8869fa8e5f3303879ad533bb4dc52e62a8dfdf2381661` |
| `syntax/correction-review/review.json` | `3624f97013b76ed91436010c7fb2470831a75518b59a6729763825caef0cbfdc` |

| Prior 83d4 evidence (superseded) | SHA256 |
| --- | --- |
| `terminal-identity-correction/consumer-results.json` | `e7a883f780652f5ec5a45755f40fc13f013c5e3a45e3bd4484f7d42e34484d72` |
| `terminal-identity-correction/exact-peer-replay-results.json` | `b81fbedc22867a26699d2f7ad3eabd37fbb57f8330790b8d2a78e3eef30b3e40` |
| `terminal-identity-correction/causal-before-after-results.json` | `92a3adf19fa65abfdca26479dfe5e8d4b9e1e48a6142155337aeaf32fceb23c4` |
| `terminal-identity-correction/source-audit.json` | `4674ae8605b805a714b026860435e596932e6c9443fac1895c54803c95b35854` |
| `syntax/terminal-identity-review/review.json` | `791078750554595fbe9d0ed6a028e694f53d5e3152625a6e91cd361c5feb94a4` |

| Final 9fb111 evidence | SHA256 |
| --- | --- |
| `compile-proof-correction/consumer-results.json` | `ff63094513c5c9070347961368deafdda7d0e76ff135273ea92cc7a4039e72d1` |
| `compile-proof-correction/exact-peer-proof-replay.json` | `6f1e83acf1d34aa70f1a6738df9008730f35fc220332eec1c03d0c79f2723be4` |
| `compile-proof-correction/causal-proof-before-after.json` | `a74494d43390852abcc56ee72019a79e4e483406cf647507d2a995bd00272ccc` |
| `compile-proof-correction/source-audit.json` | `98b8b80a4845cd55a72ddf8b2aa513811f42fd0898b5d8c8bf88371df50e6b6e` |
| `syntax/compile-proof-review/review.json` | `31c6027d1bb55132c7687a1d4a1a68547d39beb8e844689ea40af9ca69d9aa3e` |

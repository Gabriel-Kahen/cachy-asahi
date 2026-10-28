# Updater worker-inspection diagnosis and correction

2026-10-12. **PARENT OBSERVATION AND SCOPED NO-PRUNE CORRECTIONS IMPLEMENTED; DATA-ONLY CHECKS PASS; ACTUAL HOSTED CAUSE UNPROVEN.** Trial `38251407975` failed at worker-1/worker-inspection with ValueError. Its historical receipts do not distinguish the failing parent guard or attest compiler invocation. The correction adds finite parent observations without changing carried child workers. No native build, installation, M2 hardware test or performance measurement occurred in this work.

The shared ready map remains held at `ff879da588419fc0f90ef6a27c8afc528c3f6a557ef2c060544d1b5e99ade4e2`. Its 63 package pins now have exactly four intentional differences; all eight root pins still match. The ten historical stage pins have exactly two intentional differences, broker and its tests. Shared maps/locks, workflow, PKGBUILD, SRCINFO, Git and dispatch were not changed. Other workstreams remain outside this ownership.

## Actual public evidence

The coordinator dispatched exact source commit `90d8a242b7759631b6fe0c454bb473289ff5f815`; it reports terminal failure at 12:52:54 UTC. Its exact consumer/source verification is `artifacts/ci/38251407975/root-public-verification.json`. This review independently rehashed all fourteen decoded files against that record; it does not claim to have rerun the coordinator's source/Git or workflow-consumer checks.

Inspected receipts establish materializer PASS and acquisition PASS for all 527 objects, zero pending/failures. Bootstrap binds image `sha256:c82d89b7c381c5247beb6026f69f2ee327c0458aa0bb823e753dac50253ae83f`; bootstrap, inventory and tool projection bind exact 354-package inventory `d5e2b02a4af36b763c24c0eded8d4b7326874448996f94126fbfc3f787946271`. The worker input/status bind the same image, reviewed entry `4be3120d02edc747c59cda7ca9b0b5779f04555115fab7ee92567b61f6564c9b` and controller digest `1fb3f7539c1edfcf0576f933416b66fbdd0d2f4890873bd5cd0b0bde5c5af46b`. Projected controller data omits private fields, so its original private-byte digest cannot be recomputed from that projection alone.

`build-1-status.json` records worker launch attempted true, native compilation FAIL, failed_stage worker-inspection, error_type ValueError and cancellation false. Container removal/absence and cleanup completion are all true. The native pair records FAIL/worker-1/ValueError. Outer terminal is FAIL/RuntimeFailure, native-pair/process-failed/return code 1, cancellation false, elapsed 226 seconds; its native compilation remains NOT RUN. That code 1 is the outer helper process result, not an exported Docker run or container exit code.

All four cleanup scope statuses PASS, cleanup reasons empty and private-data removal true. Recovery PASS explicitly reports native compilation NOT ATTESTED BY RECOVERY. Daemon/cache disposal remains NOT ATTESTED. Shared storage was unlatched: baseline 115,212,570,624 available bytes, last observed 102,425,341,952, peak growth 12,787,228,672, growth cap 17,179,869,184 and reserve 2,147,483,648. This finite observation proves neither compilation fit nor a future peak.

The public projection reports PASS with no rejected selections, but marks build-1 entry, worker metadata, selected closure, compile result, compilation units and package result missing. Those files were missing at selection; no compiler invocation or completion is attested. The signature-verification receipt is not public. Acquisition hashes and later bootstrap progress do not substitute for an independently inspected signature-verification receipt. No native package pair, installation, hardware or performance acceptance follows.

## Historical exact source classification (031d parent; db3a selector)

`packages/tools/cachy-asahi-update/updater-native.py:334–341` waits for Docker run to return, then sets worker-inspection, captures Docker inspect bytes and executes three explicit ValueError guards:

| Site | Guard | Meaning of a failure |
| --- | --- | --- |
| 339 | `result.returncode == 0` | Docker broker/client returned nonzero; it does not locate the failing child phase |
| 340 | Actual `packages.lock` bytes equal expected bytes | Worker inventory output differs |
| 341 | No artifact descendant is a symlink | Worker output shape is refused |

Inspection JSON is written privately and is not parsed by this function. Ordinary inspect command failure is CalledProcessError; ordinary inspection-write I/O failure is OSError. Missing inventory is ordinarily FileNotFoundError. These have different public types from the actual ValueError and should not be asserted as its cause without additional evidence.

Nine independent mocked launch cases include return codes 1/125/137, inventory mismatch and output symlink. Those five ValueError cases have indistinguishable normalized public provenance, each with successful container cleanup. Inspection command/I/O failures retain different error types. Two controlled-parent fixtures accept invalid JSON or incorrect inspection Env/Image/HostConfig/State when successful output and package checks are mocked. This establishes that the parent does not inspect those observations; it does not establish a bypass of real fixed Docker options or the in-worker guard.

`broker.py:638–652` enforces fixed worker command/options, mounts and controller bindings. Its inspected Name/nonce-label checks establish scoped ownership, not worker capability or compiler-stage acceptance. Seven finite captured-JSON ownership fixtures confirm that distinction. The broker cannot identify which child check caused a nonzero return.

`native-entry.py:20–23` performs observation, worker guard and controller verification before copying/running package commands. Subsequent steps are private source copy, inventory, generated SRCINFO, source verification and makepkg. Its entry-result receipt is success-only; no durable entry-stage failure receipt covers the early checks. `worker-metadata.py` separately checks native nonroot/capability/mount/network/device/cgroup bounds and exact controller/tool/recipe bindings. Fresh metadata precedes the compile gate and Cargo build in `worker-build.py`. The compile receipt's try/finally starts only after metadata and gate checks, so its absence does not locate an earlier failure or prove that a process never started.

The exact held pure public selector discards exception text and unrecognized worker return-code fields. Three additional synthetic projection cases—nonzero exit, inventory mismatch and output symlink—remain byte/object-equivalent to the actual public worker status. The private failure messages cannot be recovered from the projected generic type.

## Implemented parent observation

The parent durably records `worker_run_returncode` immediately after the broker/client returns, before inspection. It is nullable or an exact integer from -64 through 255; a boolean is refused. This is the broker/client return code. Actual container exit and OOM observations come separately from validated Docker State fields; client 137 alone cannot establish OOM.

Two independent inspection queries share one 60-second deadline. Each captures at most 1 MiB and parses at most 8192 values with duplicate keys, nonfinite numbers and malformed UTF-8 refused. Name, immutable image and five required environment bindings must match the launch. The first valid expected identity anchors its immutable container ID; the second query must resolve to that same ID. The broker's fixed argv remains unchanged, so this does not claim a prelaunch CID-file binding. Query pipes close and spawned clients receive bounded termination/reaping on failure or cancellation.

The optional public ABI is an all-or-none group: `worker_run_returncode`, `worker_check`, `worker_failure_code`, `worker_container_state`. Checks are not-started, worker-run, container-inspection, worker-run-result, worker-inventory, worker-artifact-shape and complete. Failure codes are fixed and bound to their phases; the first failure survives cleanup. The exact code table is in `public-evidence.py:WORKER_CAUSES` and is exhaustively covered by the selector tests.

Container summaries have a closed version-1 schema: container/image/controller identities, hashes of name and nonce, finite status, exact running/paused/restarting/dead/OOM flags, bounded exit code and an error-present boolean. Raw inspection JSON, names, nonce, environment, argv, mounts, paths and error strings remain private. The outer image and controller must match the summary. Later inventory/artifact/complete phases require client zero and a stopped, exited-zero, non-OOM, error-free observed state. Native PASS additionally requires complete/no failure and no cancellation; launch false cannot coexist with a later worker phase. Historical sparse receipts remain accepted. A completed parent observation is not a compiler or child-stage attestation.

The parent distinguishes nonzero client return, inventory mismatch and output symlink, and refuses malformed/mismatched inspection. Exact WorkerObservationError is normalized centrally to public ValueError in worker provenance and the outer native-result receipt. Independent review reproduced two initial bugs (contradictory PASS acceptance and unnormalized outer error), then confirmed both corrected on the final helper bytes, including full mocked parent launch/build/public projection.

## Scoped image removal correction

The sole broker behavior change is `rmi image` to `rmi --no-prune image`; force and global prune are absent. The finite image-graph fixture shows the historical implementation could report cleanup PASS while deleting a foreign untagged ancestor. The correction retains that ancestor while removing the owned image. It establishes behavior against the explicit fixture, not a hosted daemon disposal result. The AST comparison reports zero other changes. Storage budgets, process cleanup, Docker ownership checks and recovery policy remain held.

## Verification and held implementation

Final local verification ran 47 native-parent tests and 34 public-selector tests, zero skips, with resource warnings treated as errors. The stage suite passes 203 tests (source 23, runtime 33, broker 56, public worker 13, stage 78). Mocked parent/container/build outcomes and actual finite private-process signal tests establish these source contracts; no Docker daemon, Cargo, compiler, GPG or build script was executed.

The exact old/new four-case parent regression proves three historical ValueError/worker-inspection aliases now have distinct codes with saved client 125, and invalid inspection JSON previously accepted by mocked static checks is now refused. Its final receipt is `parent-tests/regression.json`, SHA256 `d1810f13e31c2ff708067bfbd6ce81099b7452772f34b6914d1fb0feedbcfe50`. The public fresh-copy receipt is `public-tests/receipt.json`, SHA256 `fef6a8b3c58630a0020a7b1c35ac9c4a722b158ff3ec73138ac2bedbece5732a`. No-prune proof is copied to `implementation/no-prune-regression.json`, SHA256 `b0e1555f49380279818356f12f102053b66fda2d78e2bd0f29d9b7f256eaf89f`.

| Held implementation file | SHA256 |
| --- | --- |
| `packages/tools/cachy-asahi-update/public-evidence.py` | `26adacbba6fa16b8ca10aaef1fefd8b74ba2604e3b0f0435d669ee9fa4037d1b` |
| `packages/tools/cachy-asahi-update/test-native.py` | `9bfe524ae3a0428e6f2fa341d210e22f9cd26b113d87ec0f3b7db1314ff0e826` |
| `packages/tools/cachy-asahi-update/test-public-evidence.py` | `d7a9eb5182ddd5846e20120bb73dd4d2586de1eb5f856f4404fcf435a07091d6` |
| `packages/tools/cachy-asahi-update/updater-native.py` | `369964fc1153b9384a8028357efbb6a941c6f60e69aa7fb4f24ed20f37117387` |
| `scripts/port/updater-native-stage/broker.py` | `9a2a1efc63cbd8b78dacd242065a0e5e77605fdd0d6e13b2dcdb561976b18d31` |
| `scripts/port/updater-native-stage/test_broker.py` | `d911485c118027d56932062fde29a51daa831f6ee6f492baba0a1e22e8b3be9b` |

All artifacts above live under `artifacts/reviews/updater-worker-inspection-diagnosis/`. Original read-only evidence remains historical: `peer/receipt.json` (`ff6a9f8fc0d07e5732063e493db73454f63f8e291adaea86bb4d4710dd04fb91`), `observability/receipt.json` (`34c1a5f5961ae5e193408614f947d66d49fe778826be2dc51cca4b813be0304b`) and `hold-check.json` (`4020d5ed6f0623cc9c01b3fdfa9ede03629622d95fd4767fec672a9b30b5d396`). Their original zero-drift claim predates the authorized correction; it is not a current workspace assertion.

## Proposed pin adoption; no trial dispatched

`implementation/proposed-runner-ready-pins.json` changes only the four helper/test digests, retaining the 63+8 structure; proposed bytes hash to `be72334e4108dddfaaf51b59f7fb27d410a7543f6c3f8e98eb5f0ed971608089`. `implementation/pin-proposal.json` is a data-only 85-file input map totaling 4,044,082 bytes, SHA256 `3af85fd337c61f468a131f994dbb38493ae516f8887cb609630ba5caab379db6`. It records all old/new digests and required transitive changes. It is not an adopted ready map or committed source contract: its stage bytes still refer to historical READY_SHA, and its historical dispatch prose must be reviewed before adoption.

The coordinator must adopt the ready map, rebind stage READY_SHA and workflow consumer literals, regenerate the final 85-file source contract after those bytes are frozen, and authenticate the final source/controller/consumers before any native trial. Those subsequent edits will change transitive hashes and totals. Neither current source.collect nor Git/controller verification is claimed. Recipe-carried workers and all PKGBUILD source hashes remain unchanged; no PKGBUILD/SRCINFO regeneration is required by this parent-only correction.

## Child diagnostics remain proposed

An authenticated atomic child entry-status receipt could distinguish guard/controller acceptance, input copy, inventory, SRCINFO, source verification, makepkg, metadata and compile-gate checkpoints. No such checkpoint is implemented here. Preserve refusal before an authenticated output destination; a missing or malformed checkpoint never implies a phase passed. A callback after Cargo Popen returns could attest Cargo spawn, but rustc work requires validated unit/build records. Carried-worker changes would require their own review, tests and recipe/source-hash regeneration.

Actual hosted worker causation remains UNPROVEN. Compiler invocation, a native package pair and hardware compatibility remain NOT ATTESTED by this correction.

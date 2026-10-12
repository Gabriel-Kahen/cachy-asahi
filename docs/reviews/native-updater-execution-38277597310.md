# Native updater attempt 38277597310

Attempt **38277597310 failed**. The new observations establish that worker 1's Docker run client returned **1** and its bound container was observed **exited with code 1**. Inspection succeeded before the parent rejected the nonzero return. The first internal worker failure and actual compiler invocation remain **NOT ATTESTED**. Recovery PASS does not promote this attempt to native success, and no identical native repeat is selected by this review.

This is a read-only source/data diagnosis. Only this document and `artifacts/reviews/updater-fourth-actual-diagnosis-20261012/` were written. Runtime sources, maps, workflows, Git state, historical reviews and the held KSM peer packet were not changed. Read AGENTS, roadmap and the updater package inventory; the four earlier development package pairs do not establish updater or full-port acceptance.

## Source and retained evidence

Source commit: `ed76c11573a382c23db7b35233f4ab8394205508`. Independently authenticated **85 committed source files, 4,044,082 bytes**, including Git blob modes, against the held map and current source bytes. The committed workflow is `9fb111d778fb065dfbcc7c7baf3803fc96548ee7b614d06a33305a744b3ea885`; stage is `b872fb47c03cb3c9124df5056cc34fb9e02ffcbe49753447676585862e840a7a`; ready map is `be72334e4108dddfaaf51b59f7fb27d410a7543f6c3f8e98eb5f0ed971608089`.

Retained `run-logs.zip` is 117,901 bytes, SHA256 `511986c1f2ba3a75e8adbc45ab60b4936142912a3d3625442c365fae59471756`. All ten captured log files match their recorded hashes and ZIP contents. Three evidence frames in the recovery-step log match the retained compressed archives and their **14 regular JSON members**. Strict JSON parsing, export manifests and projection hashes pass. Projection accepts eight source receipts and reports fifteen missing selectors, with none rejected.

The terminal's `public_bundle_sha256=866a8785e5d821e80414b1b5fd599a0daf61eac85bb69dba07b99cfa29b1ea99` refers to the original private stage bundle. The log-emitted `guarded.tar.gz` is a rebuilt bundle with SHA256 `5197016b1b490014621efc3669cfb136bee30f1a9256130f0ccf23ffd339cf3e`. The receiver checks the original bundle hash and member bytes before rebuilding public output. Original compressed stage-bundle bytes and the private controller bytes are unavailable locally; they are not equated with the log archive or recreated as authentic evidence.

## What ran and what failed

| Evidence | Actual observation and limit |
| --- | --- |
| Bootstrap/materializer | Bootstrap receipt and 354-row inventory/tool bindings validate; materializer reports PASS. This does not attest tray compilation. |
| Worker launch/state | Launch attempted; client return 1. Full 64-digit CID, controller/image bindings and entry hash validate. State is exited/code 1; running, paused, restarting, dead, OOM and state-error flags are false. |
| Parent predicate | `worker_check=worker-run-result`, `worker_failure_code=worker-nonzero-returncode`, enclosing `failed_stage=worker-inspection`, `error_type=ValueError`. This is the parent's rejection after validated inspection, not an identified child ValueError or inspection-parser failure. |
| Native pair/stage | Pair FAIL at worker 1; stage FAIL at native-pair with `RuntimeFailure`, `runtime_reason=process-failed`, return code 1. Build 2 and comparison evidence are absent. |
| Inner evidence | Entry, compile result, compilation units, worker metadata and package evidence are missing. Missing receipts do not prove the compiler was never invoked. |
| Cleanup/recovery | Worker removal and absence fields are true. Terminal reports Docker, process, GPG and private cleanup PASS, `private_data_removed=true`. Recovery reports PASS and `native_compilation=NOT ATTESTED BY RECOVERY`. These are scoped recorded results; daemon disposal remains NOT ATTESTED. |
| Storage | Shared peak growth 12,787,642,368 bytes, approximately 11.91 GiB, below the 16 GiB growth limit; latch false/reason none. This failed partial path is not proof that the complete compiler/build pair fits. |

At `updater-native.py:498–512`, the adapter stores the returned client code, validates bound container inspection, then rejects the nonzero return before successful-state validation, inventory equality and package inspection. No compiler scheduling or duration claim follows from these stage labels.

## Why the first internal predicate is unavailable

The exact child path first imports `worker-metadata.py`, observes and guards its worker boundary, verifies controller/entry/tool/recipe identities, creates scratch/home, compares pacman inventory, compares generated SRCINFO, verifies sources and invokes makepkg. The recipe's build phase invokes `worker-build.py`; that helper verifies controller, resolves fresh metadata and runs the independent compile gate before invoking Cargo. Later recipe checks and packaging still have their own predicates.

`native-entry.py:63` writes `entry-result.json` only on full success. `worker-build.py:65–100` performs metadata and compile-gate prerequisites before entering the try/finally that writes a compile result. Metadata itself writes `worker.json` only after its repeated prerequisites. The fixed public selectors omit Docker `build.log`, command JSON, stdout/stderr and makepkg logs. Projection marks the inner receipts missing, and actual cleanup then removes private data. Several different failures therefore produce this same retained evidence. Neither the new parent code nor absent inner receipts identifies the first internal cause. The earlier **38251407975** first ValueError remains unproven too.

## Minimal next diagnostic correction

Propose one bounded, failure-path `worker-diagnostic.json` selector; this review implements none of it. Write the record from entry startup through a finally path, issue a closed failure code at each guarded predicate, and retain the first failure across enclosing makepkg errors and cleanup. Propagate nested metadata/compile-gate/recipe failures into that same record where instrumented; an uninstrumented child failure must remain UNKNOWN rather than being assigned a guessed predicate.

The minimal public fields are schema version; controller, image and entry hashes; whether controller validation completed; a closed operation/predicate code; a fixed command-kind enum; nullable bounded return code; closed error/timeout/output-limit code; and bounded stdout/stderr byte counts and SHA256 when available. Record compiler launch attempted separately from compilation accepted. An operation boundary is not itself the first failing predicate, and a hash does not explain diagnostic text. Include a separate diagnostic-write failure state so it cannot replace the original failure.

The parent must validate these bindings against its authenticated launch and observed container. Only hash fixed, regular, single-link, bounded private files. Export no argv, paths, environment, tracebacks or raw diagnostics. Add the finite projector and workflow selector while preserving existing compile-proof, cancellation, cleanup and public-acceptance gates. Before another trial, source controls should cover failure before metadata, nested makepkg failure, preserved first failure, missing/invalid diagnostic, cancellation and source/controller mismatch. Root owns implementation, pin adoption and any later dispatch.

## Independent verification

Four captured-consumer data replays pass: actual failed receipts retain three public bundles and FAIL; outer success flags cannot promote them; missing recovery retains original FAIL diagnostics; coherently rehashed wrong-source evidence is refused before emission. The replay substitutes only the unavailable private `stage.authenticate` call with the authenticated 85-row data envelope and omits the unavailable original private bundle. It does not replay genuine controller authentication. All actual receipt bytes are preserved in the unchanged case.

Two independent peers add eight captured-projector rejection controls and fourteen original pure-gate controls. All local controls use strict ResourceWarnings and zero source bytecode. No compiler, Docker, GPG, package installation, network access or native repeat occurred in this review. These data/source checks validate the diagnosis and refusal behavior; they do not turn this failed attempt into a successful build or establish M2, runtime, distribution or performance acceptance.

The owned evidence directory contains `source-binding.json`, `actual-log-binding.json`, `consumer-replay-results.json`, `inner-peer/receipt.json`, `receipt-peer/receipt.json` and the final binding `final-review.json`.

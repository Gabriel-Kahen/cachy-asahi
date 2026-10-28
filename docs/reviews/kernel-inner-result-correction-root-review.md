# Kernel inner-result correction: independent root review

**PASS within the held source and finite model scope.** The two findings from the blocked `2ddc9c0e…` review are closed by the exact correction receipt `abbd20d104dd0fbd57022c5b173df07be80dff433299b30709c1dd68b6ee8ea7`. No new finding remains in this correction scope. This verdict does not adopt source maps, authorize a producer or Kernel8 run, reinterpret Kernel7, or establish native, installation, M2, 16K, performance, release or full R1–R5 acceptance.

The review reads the roadmap and package inventory and preserves the Asahi platform scope. Root owns only this document and `artifacts/reviews/kernel-inner-result-correction-root-peer-20261012/**`. Worker, schema and selected-test lanes have separate frozen subdirectories; root integrates their evidence without editing their files, primary source, shared manifests, workflows or project Git.

## Authenticated hold and preservation

The sealed author receipt is 111,144 bytes; its source-index SHA256 is `482e9ae61c12cf64bc79429f125377d0fb757742ea2c727693f907830d9e0e7d`. Initial authentication passes all 386 references. Post-run conservation passes 685 references, including the author index, eleven owned source files, the 121-file captured dependency tree, protected primary files, frozen peer indexes and historical entrypoints.

Relative to the original eleven-file candidate, four files change and seven remain byte-identical:

| Corrected source | SHA256 |
| --- | --- |
| `worker.py` (0755) | `a9f6aba96bbb636c7bd3289c165a4ebe545e72e660b132c291d5be768070ed05` |
| `test_worker.py` (0644) | `a6677cd11b3890294bde5f56cceb4ed1415a7c59d5818d8b560dec1d72cd9a17` |
| `inner_result.py` (0644) | `54f3f9fe9e6884b6eb4e754804da3755239ac4c23257e41db96535c0950658df` |
| `test_inner_result.py` (0644) | `327d953138dd042199cafdf23cf1c2515abe3cc820ebdbcd9b48910da1117af4` |

The original author `9b1e1e19…`, blocked root `2ddc9c0e…` and Updater9 root `1bb0930c…` entrypoints remain exact. The earlier correction's 159-test wrapper candidate and its blocked caller-entry evidence remain historical; this verdict applies only to the final inline-guard correction.

## WORKER-F1: observer acquisition and entry

All 48 independent mocked worker controls pass, including the six retained old-red/new-green causal pairs and positive observation through COMPLETE. Four module-attribute acquisition faults and two observer-entry faults reproduce the old worker replacing the pending original `ValueError("command failed: kernel")` and skipping original log copy and FAIL save. The final correction keeps that cause, copies the log and saves FAIL for the same injected faults.

Six observation sites now acquire and enter the optional callable inside direct inline guards: initial business-failure recording, FINALIZATION, each of the two deferred-cancellation records, COMPLETE, and original finalizer-failure recording. Ordinary observer errors invalidate the diagnostic. Observer cancellation, KeyboardInterrupt and SystemExit are recorded and deferred through original finalization. No new observer wrapper is acquired before those guards.

Controls cover acquisition and callback entry, first business-cause preservation, ordinary invalidation, no-business observer faults, positive completion, and original finalizer acquisition/copy/save/disposal failures. Original finalizer error precedence is preserved: an original finalizer OSError can replace an earlier business ValueError just as before diagnostic observation existed. The correction preserves business cause against **observer faults**; it does not change the original finalizer's semantics.

Five worker static checks pass. Removing only the six inline guard nodes restores the complete prior worker AST. Original commands, argv, environment, profile, inputs, code-hash gates, resource limits, deadlines, PASS predicates and cleanup behavior remain unchanged. Runtime and common helper bytes are unchanged. Twenty-four root stage static checks also pass, including unchanged business gates, schema-3 success requirement, single capture read and absence of new Runner/Docker queries.

These are explicit callback/code-object fault models, not proof of authenticated helper corruption, actual signal delivery, arbitrary-instruction interruption safety or CLI admission. A modeled propagated SystemExit(0) still has a saved FAIL report; it is not a full job PASS.

## INNER-J1: full-report finite JSON

All 246 bounded schema/data checks pass, including 38 diagnostic mutation cases and nine finite numeric compatibility controls. The exact historical 652-byte reproducer, SHA256 `891cfdf9c3bb25a171a7539c7f1c27c7ddda5b69cfb00f824edf217d2456d293`, retains `unused.nested=1e999`. The old helper yields VERIFIED/OBSERVED; the corrected helper yields REFUSED/INVALID with the same raw SHA and null diagnostic.

AST normalization shows only `import math`, `_finite`, and `parse_float=_finite` added to the parser. Floating-point tokens in unused fields therefore receive the same finite check. Unused overflow, NaN and ±Infinity refuse; finite nested integers, fractions, ±1e308 and ±1e-999 remain compatible. The underflow check claims finite compatibility, not decimal precision.

All three group validators remain unchanged. Existing malformed-type, duplicate-key, binding, cancellation and privacy refusal controls pass. Schema 4 remains failure-only, with one diagnostic attached to an original nonzero command; it cannot satisfy healthy schema-3 success or upgrade it to PASS. Schema-3 success and historical failure projections remain byte-equivalent. No private path, error text, argv, nonce or ignored raw field is exported. Private capture remains one held read of at most 4 MiB with a closed diagnostic of at most 2,048 bytes; no new worker State/exit query is introduced.

The schema peer preserves an initial harness correction: Python 3.14.7 accepts depth-1200 unused finite JSON, and the contract has no explicit private nesting cap. Final controls retain that compatibility, refuse malformed selected nested fields and model caught parser RecursionError. No new depth ceiling is claimed.

## Fresh tests and actual-outcome conservation

Fresh selected **160 methods pass**, with zero failures, errors or skips and four process exits of zero: worker/helper 30, evidence 22, stage 27, public 81. All 156 prior selected method IDs and bodies are AST-identical, including the original 26 worker/helper methods. Exactly four methods are added. The selected evidence, stage and public test modules remain byte-identical to the earlier audited packet.

Selection excludes the existing actual-TERM and isolated-CLI stage methods explicitly; they are not counted as skips. Public tests use tiny private Git/Python-help fixtures. Other process, command, finalizer, filesystem-operation and signal behaviors are mocked or bounded owned fixtures. There is no actual Docker, daemon, native compiler, GPG, mount, network, service, package-install or hardware execution.

Each selected group runs with CPU 30 seconds, memory 512 MiB, wall 60 seconds and file size 4 MiB; stage alone retains the declared 5 MiB allowance for its existing 4 MiB+1 refusal fixture. Logs retain a 4 MiB cap. All 121 copied source files and modes are unchanged afterward; no fixture or bytecode survives. Worker/schema controls use the same CPU/memory/wall bounds and 4 MiB file cap. Commands, environment, process results and source/test audits are retained in their frozen lanes.

Root reruns five pure retained Kernel7 public projections, each equal to the original receiver's result; the actual failure projection is byte-exact. **Kernel7 `38308563102` remains FAIL at baseline START CLI exit 1.** Its worker State.ExitCode, compiler entry, raw inner report and actual inner cause remain UNKNOWN. No missing observation is reconstructed from a source/model test. Kernel8 has not run in this review.

## Pending coordinator reconciliation

The captured FDK helper is `27d16ce1a89d949075b0fe85072575883de6e9021a4902747c4b8ed44ed71b27`. Separate modern-completion primary work is `fbf2b9ebce35ed6d075b51865349e997cf283f669f2e7a5e28a0f91f51913d98`. The held correction tests the former dependency; it does not substitute or adopt the latter.

Pure set recomputation verifies the held proposal: stage 26 → 29 and packet 117 → 120, adding exactly `inner_result.py`, `test_inner_result.py` and `test_stage_inner.py`, with no removed paths. Six existing stage rows and eight existing packet rows differ from the historical maps. The proposed packet set equals the held 120-file closure. Both actual maps and their historical stage-lock digest remain unchanged.

Before registration, the coordinator must recompute the actual final dependency union and derived digests, including the independently reviewed FDK dependency binding. This review writes no proposed or live manifest. Adoption, registration, producer validation, a separately authorized actual native run and hardware acceptance remain unfinished.

Frozen evidence: `artifacts/reviews/kernel-inner-result-correction-root-peer-20261012/final-review.json`, with `tests/receipt.json`, `worker/receipt.json`, `schema/receipt.json`, `stage/static.json`, `stage/legacy.json` and `post-authentication.json`.

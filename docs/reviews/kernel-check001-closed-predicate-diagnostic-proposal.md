# Closed CHECK_001 conjunct diagnostics proposal

This proposal makes a future CHECK_001 refusal distinguish its first false conjunct using eight fixed public labels. It preserves the verifier's accepted input set, operand order, ValueError type, existing schema4 shape and business/cleanup paths. It does not repair a kernel output or identify the cause of any retained native failure. Only review copies are authored; Root owns integration, publication and any later diagnostic trial.

## Actual observation and proposal base

Root's retained public/status report for run `38620355690` is Source `3bec0e2e300a0fc9ee11abb3b20866cfb7508c7a`, packet `329078ba3f3ebf1ce0b580a562cd2f01aa8f9cd60dbdee15420956863f097494`, completion `8062415fb3b7b835d225583f81ea516f00a827ca79d4c15f5664d3f0b9921cd0`. It reports acquisition and producer exit zero, probe PASS, baseline worker exit1 and candidate NOT RUN. The inner kernel command returned naturally with code0; OUTPUTS then refused with `DATA_REFUSAL`, `VERIFY_OUTPUTS` / `CHECK_001`. Which conjunct failed, its operand values and the responsible segment are **UNKNOWN**. Cleanup, owned absence and daemon preservation report PASS separately, with cancellation false. Both parallel children exited normally with zero, so no parallel-failure label was emitted.

This review reads those public/status facts and retained Source only. It does not independently reacquire the completion, replay private kernel output or reinterpret the earlier `385839` CHECK_001 failure. Kernel command return0 is not accepted output verification, hardware compatibility or full build acceptance.

Proposal preimages are Source `1ed00455eb3d3027c57b738bb3ee3d8ecda4adab` / packet `9307d5bbb60e10fb9ece9603e15f1ca273b445564b3973a2e9f4457e39724584`, authenticated against Root's committed-source proof. That later fixture-only successor is not the Source of run386203. The relevant verifier/inner/evidence/worker/public production preimages match the retained run Source byte-for-byte. No `1ed` test result is attributed to that native run.

## Exact diagnostic change

The original PT_LOAD conjunction becomes eight ordered `harness.need` calls. Every operand is the same AST in the same order; these consume only already-unpacked integer fields and add no IO, clocks or conditions. Passing a load now makes up to eight pure guard calls instead of one. A refusal still raises an exact ValueError, with the original static message prefix plus one fixed suffix. That suffix is projected to a closed code:

| Closed predicate | Required expression |
| --- | --- |
| `CHECK_001_ALIGN_MIN` | `align >= 4096` |
| `CHECK_001_ALIGN_POWER_TWO` | `align & (align - 1) == 0` |
| `CHECK_001_VA_ALIGN` | `va % align == off % align` |
| `CHECK_001_PA_ALIGN` | `pa % align == off % align` |
| `CHECK_001_VA_16K` | `va % 16384 == off % 16384` |
| `CHECK_001_PA_16K` | `pa % 16384 == off % 16384` |
| `CHECK_001_PERMISSIONS` | `perm in (4, 5, 6)` |
| `CHECK_001_MEMORY_SIZE` | `memsz > 0` |

The future label means the first false conjunct of the first failing PT_LOAD encountered in program-header order. It does not enumerate all false terms, expose a segment index, or establish an upstream cause. In particular, PERMISSIONS does not identify the actual flag value or prove writable/executable flags7. Zero alignment still refuses before any modulo operation. Earlier segment range checks retain priority.

`inner_result.OUTPUT_CHECKS` receives eight exact literal-message mappings. All113 existing mappings, legacy CHECK_001, prefix mappings and OTHER fallback remain unchanged. Child evidence and final public projection receive precisely the same eight allowlist values. The existing two-field `output_failure` remains `{call_boundary: VERIFY_OUTPUTS, predicate: closed-code}`; no schema/key expansion occurs. Unknown suffixes, raw operand values, addresses, headers, paths and extra keys are not exported. `worker.py` retains its exact-ValueError catch and bare rethrow; the same error object and first business failure propagate. Diagnostic failure/control, deadline, output-bound, grant, cancellation and cleanup logic are held.

## Frozen copies and closure

The new namespace is `artifacts/reviews/kernel-check001-closed-predicate-diagnostic-proposal-20261014/`. `copylist.json` identifies ten exact before/after copies: verifier; inner/evidence/public consumers; existing inner/public/verifier tests; stage lock; packet loader; packet lock. The verifier unit test is an extra Source file outside the selected runtime packet, as before.

The stage retains29 rows: four digest changes and25 held. The Source packet retains124 rows: eight changed and116 held. The loader changes only its stage digest. Workflow bytes and bootstrap minimum, runtime/worker/job/stage/broker/dependency controls remain held. Proposed stage SHA256 is `40780ba06a966bcf1d13125a7dcfcb481557e94f5a59f17524fa2f73700af420`; proposed packet SHA256 is `d33fc24e2db613dab364d6ff0c8130cb643426d7c6369e93bd398b322325a227`.

## Validation and limits

`audit.py` passes334 Source/closure/public-status assertions, including recombination of the eight new calls to recover the whole original verifier AST, exact124/29 joins and held actor/control bytes. `analysis-peer/` independently pins the original eight operand ASTs and propagation design. `peer/` independently exercises43 complete synthetic ELF pairs /86 parser executions and960 assertions, including every label through inner capture, child evidence and final public projection across five outcomes. Synthetic cases are fixtures, not native kernel output or hardware evidence. The peer's exact frozen input pins, report and receipt are retained alongside its controls.

| Author suite | Result |
| --- | --- |
| Verifier | 44 tests run:43 pass, one pre-existing optional fixture skip |
| Inner diagnostic | 12 pass |
| Child evidence | 22 pass |
| Public projection | 68 pass;14 BootstrapTests deliberately excluded because they create Git fixtures |
| Worker | 19 tests run; two subtest assertion failures in `DiagnosticExecute.test_business_return_and_failure_projection`, identically reproduced on unchanged baseline for business7 and SystemExit7 |

Both worker failure logs are retained; the worker and its test remain byte-identical. No unrelated fixture correction is proposed and no full-suite-green claim is made. The test wrapper blocks external process launch and runs only the selected inert Python suites in an owned merged Source tree. General verifier fixtures mock source identity; the optional real archive fixture was skipped. No private output or archive body was read.

The actual CHECK_001 operand remains UNKNOWN until new diagnostic evidence exists. This is a proposed Source diagnostic, not an installed change, accepted native build or measured improvement. No canonical Source, Git ref/index/object, API/variable/CI/native/package actor, target system or hardware state was mutated. Prior seals remain unchanged. Full workflow Source coverage and R1–R5/M5–M9 acceptance remain required.

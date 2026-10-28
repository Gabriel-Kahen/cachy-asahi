# Kernel failed-command inner result diagnostic

This implementation adds a bounded diagnostic to the existing private worker result and captures it when the original Docker START command returns nonzero. It is source-tested work awaiting coordinator registration. No native build, Docker execution, installation, kernel boot, M2 hardware check, or performance measurement ran for this change.

Kernel7 (`38308563102`, commit `25b0213e73c67efbed758af7c32f6c1057850052`) remains failed at baseline START CLI exit1. Its independent worker `State.ExitCode`, compiler invocation, raw inner result, and inner cause remain **UNKNOWN**. These new fixtures do not reconstruct that missing evidence.

## Private and public interface

`inner_result.py` implements a closed diagnostic of at most 2048 encoded bytes. Its exact keys are `schema_version`, `binding`, `phase`, `command`, `attempt`, `natural_return`, `first_failure`, `cleanup_failure`, `cancelled`, and `write_failed`. Binding requires the original nonce and action, exact contract SHA256, and authenticated worker SHA256. Actions are only probe, baseline, and candidate; provision is unchanged.

Phases are NONE, PRECHECK, PROFILE, INVENTORY, TOOLS, SOURCE, CONFIG, CONFIG_DELTA, PAIRED_CONFIG, GENERATED_CONFIG, KERNEL, OUTPUTS, FINALIZATION, COMPLETE. Commands are NONE, INVENTORY, CONFIG, KERNEL, or TOOL_0 through TOOL_17. Attempt is NOT_ISSUED or ISSUED. A natural return is UNOBSERVED/null or RETURNED with an exact integer from -64 through 255; booleans are refused. Error kinds are DATA_REFUSAL, IO, IMPORT, TIMEOUT, DEADLINE, OUTPUT_BOUND, PROCESS_CLEANUP, CANCELLED, OTHER. Failures contain only phase, command, and error kind.

Attempt records the source issuance boundary of the original Runner call. Natural return is observed only from that call's original `CompletedProcess`, before the original log hashing. Neither field proves actual compiler entry, instruction execution, or Docker worker state. Phase can advance through finalization while retaining the last original command/return. The first business failure is frozen separately from cleanup failure. Observed cancellation and diagnostic write failure remain sticky in memory. Ordinary observer faults invalidate the diagnostic while preserving original business behavior; observation controls pass through original finalization with earlier business exception precedence retained.

The stage freezes its original nonzero START cause, then reads the existing `result.json` once. Capture requires owned mode 0700 private directories, an owned mode 0600 single-link regular file, no final symlink, stable file/ancestry identity, and at most 4 MiB of private report bytes. The same captured bytes supply the raw SHA256. Duplicate keys, nonfinite values, wrong binding, malformed enums, incoherent cancellation, and `write_failed` refuse projection. Failed-START capture requires private outer status **FAIL**. Healthy PASS snapshots refuse even if a later save fault caused the START failure.

The public group contains exactly `availability`, `reason`, `raw_sha256`, and `diagnostic`. Valid pairs are NOT_RUN/NOT_RUN, UNAVAILABLE/MISSING, REFUSED/INVALID, VERIFIED/OBSERVED. Missing/pre-capture refusal can have no raw hash. VERIFIED replaces private binding with its canonical SHA256; it exports no nonce, message, path, argv, log, or raw private report. It authenticates an as-of-write source snapshot. A null cleanup failure means none was observed at that write; later save/finalization faults may be absent. Early failures before original report setup can be UNAVAILABLE. There is no postmortem or atomic process-completion claim.

Failure-only child diagnostic schema4 adds `inner` groups for probe/baseline/candidate, with at most one observed failure group. Attachment is transactional. Legacy child schemas 1–3 keep their exact closed parsing. Original success still requires schema3; schema4 cannot satisfy PASS. Top-level job public schema stays unchanged. No additional Docker inspect or stopped State projection was added.

## Owned source change and registration

Eleven source/test paths changed:

* New stage `inner_result.py`, `test_inner_result.py`, `test_stage_inner.py`.
* Existing stage `worker.py`, `test_worker.py`, `stage.py`, `test_stage.py`, `evidence.py`, `test_evidence.py`.
* Existing job `public.py`, `test_public.py`.

The exact final rows, original ownership hold, registration proposal, isolated snapshot, and receipts are under [kernel-inner-result-diagnostic-20261012](../../artifacts/reviews/kernel-inner-result-diagnostic-20261012/). The original ten-path ownership hold is retained; the parent capture tests add the eleventh path. Both runtime modules, broker, image, common, acquisition, regression, dependency audit, packet code, shared lock files, and workflow remain unchanged.

The coordinator must reconcile the stage map 26 → 29 and packet map 117 → 120, refresh the stage-lock row after its new digest exists, rebind receiver/bootstrap/workflow hash literals as required, and run the independent producer/admission gates. The proposed row sets are inputs for registration, not adopted lock files. Existing shared maps deliberately refuse the changed source closure. This worker made no project Git commit/push or registration change.

## Validation and limits

The final isolated 120-row snapshot passed 156 methods: worker/helper 26, sender/receiver evidence 22, stage 27, public 81. Stage selects 16 original inert methods and 11 capture controls; the two original actual SIGTERM/CLI subprocess methods are explicitly excluded. Tests run with isolated Python, bytecode disabled, no site imports, and ResourceWarning promoted to an error. The public suite does use owned fixture Git repositories and Python `--help` subprocesses; it does not alter project Git. Syntax parsing authenticates 43 Python files. The retained Kernel7 public result reprojects byte-exactly, and all five CI outcomes equal the original projector.

Independent review retained and corrected three initial defects: observer control skipped original finalization, unguarded error classification replaced first business failure, and a partial issued callback could remain trusted after interruption. Its final source hold passed 112 fault schedules, 78 schema/privacy poisons, 8 old/new causal schedules, and 9 static checks. A later four-class after-effect save model exposed healthy stale PASS capture; the final helper restricts capture to FAIL. The independent additive recheck passed all 17 cutoff/status cases and repeated the 112 fault schedules and 78 projection poisons. Author controls now cover 9 old/new/mock causal schedules. Exact peer receipts preserve the red and corrected holds separately.

Original profile, inputs, source authentication, command argv/env, deadlines, Runner cleanup, nonzero refusal, PASS predicates, and daemon preservation gates are retained. Source AST and causal comparisons support that finite claim; they do not grant ARM or M2 compatibility. R1–R5 and the full roadmap acceptance gates remain required. Package-overlay completion, hardware success, runtime admission, performance gains, and release selection are not established by these diagnostics.

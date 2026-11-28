# Paired retained zlib sessions

Current source execution uses the [owned-retirement v2 layer](owned-retirement-v2.md). Historical `benchmark.py` and `paired_zlib.py` files and their frozen plans remain byte-held; their legacy workload execution is retired. Redeclare fresh v2 plans for new runs; do not edit or rebind historical plans. Offline historical comparison remains available.

`paired_zlib_v2.py` composes the existing `zlib_workload.py` artifact/corpus checks and `benchmark_v2.py` freeze/run/compare APIs. It never builds programs, trains PGO, installs packages or changes system controls. Native M2 performance remains NOT RUN. The local Python/gzip fixture records are CONTROL_ONLY and do not measure ARM compiler variants.

The real generic16K correctness gate is already accepted for all four cases in [the October 17 record](../validation/arm-retained-generic16k-20261017.md). This runner addresses paired performance sessions; it does not repeat or reinterpret that correctness admission.

A session first executes the whole verified workload once per variant. Each original zlib workload independently decompresses its output with Python's zlib and compares exact payload bytes. Only after both correctness passes does the session execute one or two excluded warmup blocks, followed by the entire frozen measured order. Timed workloads retain the same independent verification. Elapsed time includes Python, subprocess startup, file I/O, verification and telemetry; it is not isolated codec CPU time.

Use at least six measured trials per variant. The default twelve-slot schedule is `A B B A | B A A B | A B B A`; additional blocks alternate in the same pattern, up to forty slots. Every correctness, warmup and measured invocation receives a new empty work directory and separate raw output. No failed slot is retried or silently removed. A failure, interruption or session deadline stops the session and preserves completed/partial evidence. The Linux signal deadline uses the existing workload cleanup path; OS stalls, SIGKILL and escaped descendants retain the harness's documented limits.

## Exact inputs and physical preparation

Run `stage` against the retained input cache containing the original archive and manifest paths from `scripts/ci/arm-experiments-generic16k/retained-inputs.json`. It reuses `prepare.select` and the existing ELF parser to authenticate the whole bundle, every original member and the finite final selection. It copies exactly 30 selected files plus the original archive manifest to a fresh root. No training program is selected. All 48 selected executable ELFs across C01–C04 keep their original bytes, interpreter and ISA. A missing original input is an acquisition requirement; do not substitute a rebuild.

```sh
python3 -B scripts/benchmarks/paired_zlib_v2.py stage \
  --experiment ARM-C01 --input-root /absolute/retained-input-cache \
  --output /absolute/new-staged-C01
```

For target execution, prepare real baseline/candidate state records with the existing baseline collector and the operator file described by [the benchmark CLI](cli.md). The operator file supplies `experiment_id`, `machine_id`, `base_id`, `execution_context`, `hardware_gate_evidence`, `order`, `minimum_trials`, `timeout_seconds`, `sample_seconds`, `controls`, `thresholds`, and optionally `power_domains`. The context is `physical`; the plan must describe the exact M2 Air and 16384-byte pages. Baseline-functional and recovery gates must be reviewed PASS evidence for the same machine/base. Use the same installed state for both variants: only the selected standalone executable differs.

```sh
python3 -B scripts/benchmarks/paired_zlib_v2.py prepare \
  --experiment ARM-C01 --artifact-root /absolute/new-staged-C01 \
  --archive-manifest /absolute/new-staged-C01/archive-manifest.json \
  --operator-config /absolute/actual-operator.json \
  --baseline-state /absolute/actual-baseline.json \
  --candidate-state /absolute/actual-candidate-state.json \
  --payload-bytes 33554432 --iterations 8 --output /absolute/new-plan
```

These paths describe future operator inputs, not supplied hardware evidence. Preparation invokes the original exact-artifact config adapter, pins the paired wrapper as an additional source input, and freezes the plan with `paired_zlib: "exact-arm"` through the existing hardware/state gate checks. The augmented config explicitly binds the driver, archive manifest, corpus manifest and held-out corpus file with `argv_file_operands`. Payload size and iteration operands remain literal. Preparation runs no workload and retains the original config next to the augmented config and plan.

## Run and interpret

Start with an empty, separate conditions directory. The runner publishes one `awaiting_conditions` request at a time in its output `session.json`. The request includes a filename such as `correctness-00.json` or `measured-00.json`, the session ID, phase, index, variant, and a timezone-aware `requested_at`. Wait for the request, let the machine settle within the declared bands, then observe the conditions for that slot.

Use the [normal conditions fields](cli.md#record-conditions-and-execute-the-declared-order) and add an `observation` object. Copy `session_id`, `phase`, and `index` from the request and set `observed_at` to the actual observation time in ISO 8601 with a timezone. Record the instruments and settling procedure in `notes`. Write the JSON to a temporary file in the conditions directory, then rename it to the requested filename once complete.

Physical sessions require this observed mode. The runner accepts a receipt of at most 64 KiB, checks its order from request to receipt and launch, and checks that the observation is at most 30 seconds old immediately before calling the workload runner. Waiting ends when the session has only the frozen trial timeout plus two seconds left. Stale, invalid, or missing receipts stop the session with the request retained. Raw receipts and their hashes remain in the trial evidence for replay. These timestamps and readings are operator observations. They do not independently establish ambient temperature, cache state, background load, or thermal settling.

```sh
python3 -B scripts/benchmarks/paired_zlib_v2.py run \
  --plan /absolute/new-plan/plan.json --conditions-root /absolute/actual-conditions \
  --warmup-blocks 1 --session-seconds 7200 --output /absolute/new-session
```

Default execution refuses nonphysical or non-aarch64 plans before actors. `--control-only` requires a nonphysical plan frozen with `paired_zlib: "control-only"` and explicitly labeled fixture output. For synthetic fixtures, pass `--conditions-mode prewritten` with `--control-only` to use the original conditions fields in files prepared before the session. Prewritten mode checks each file again at its slot. Control-only records carry no target acceptance. Both modes refuse loader/emulation overrides.

The session retains a copied plan, exact actual schedule, workload reports, condition/trial bindings, environment identity (CPU fields, affinity, kernel, Python, page size), raw output, elapsed boundaries and telemetry. A valid `trial.json` is published atomically after the complete stdout report passes artifact, payload and iteration checks. A refused report leaves an invalid trial and raw evidence. An interruption before publication leaves raw evidence without an admissible trial.

Offline `benchmark_v2.py compare` revalidates the retained stdout and checks the trial's report against it. Supply all measured directories from one session. Correctness and warmup directories, mixed session IDs and missing or failed slots are refused. Retain the plan and its pinned input paths for replay.

Root RSS is the actual live leader's sampled RSS. The original-group sum remains separate. Missing or partial data stays unavailable. V2 keeps the shared owner's bounded combined output in `stdout.txt`, with `stderr.txt` empty and the scope declared in the raw receipt. The trusted zlib driver must produce a complete valid JSON report. Diagnostic contamination fails validation. Working payload and per-artifact stderr files remain in each owned work directory. Allow disk space for one payload per invocation (18 payloads with the default schedule).

`COMPLETE_PAIRED_MEASUREMENT_PENDING_REVIEW` means the execution flow completed, including a legitimate negative or incomplete timing comparison. Read `preliminary_result`, `comparison_exit_code` and `comparison.json`. A `FAIL` timing result is never promoted to an improvement. Optimization acceptance, hardware acceptance and release remain NOT RUN/NOT ADMITTED even if a preliminary timing rule is met. Independent repeat sessions, exact model-specific latency/power/battery/thermal/recovery evidence and final-system measurements remain required by [the methodology](README.md).

# Optional platform capture in the benchmark harness

`benchmark.py run --platform-metrics` is an explicit, frozen instrumentation mode.
It runs the trusted argv workload, samples the pinned read-only platform collector
concurrently, and stores raw readings plus a summary clipped to that workload's
same-boot monotonic window. It starts no collector subprocess, changes no system
settings and makes no optimization or M2 acceptance decision.

This mode requires the exact reviewed `scripts/benchmarks/platform_metrics.py`
SHA256 `bf3d80c3e5a7d8e8a67c393e2cabf19c2a45945fd023628bdb5dcb5b03b2b4f2` and
`scripts/virtual/owned_process.py` SHA256
`80547f753dc7d13819d727783c669d10a56b7bf832dc05084b5c4b5302cb79d9`.
The first collector packet and shared owned-process packet remain separate,
unchanged inputs. Only the explicit mode imports these modules; ordinary
benchmark and paired_zlib APIs retain their existing dispatch and behavior.
New plans pin the modified harness source, as before; old source-bound plans
must be redeclared rather than bypassing their source checks.

## Declare, freeze, run, compare

Add this field to the existing complete experiment config *before* freezing:

```json
"platform_metrics": {"interval_seconds": 0.1}
```

Use the established state, conditions and workload preparation procedure:

```bash
python3 -I -B scripts/benchmarks/benchmark.py prepare-plan \
  --config experiment.json --baseline baseline.json \
  --candidate-state candidate.json --output frozen-plan.json
python3 -I -B scripts/benchmarks/benchmark.py run \
  --plan frozen-plan.json --slot 0 --state baseline.json \
  --conditions conditions.json --cwd /existing/private-workload-dir \
  --output /existing/private-parent/fresh-trial-0 --platform-metrics
```

Run the complete predeclared interleaved order, choosing each slot's frozen state
and independently retained conditions. Then use the existing `compare --plan ...
--runs ... --output ...` interface. The flag must match the plan: adding or
omitting it relative to the frozen declaration refuses execution. `paired_zlib`
was not changed and does not silently opt in; its existing six-argument `run`
calls continue using ordinary plans. Do not put this declaration into a paired
plan without a separately reviewed paired-driver adaptation.

Freeze pins the adapter, collector and owned-process source in addition to the
existing harness/workload/memory inputs. Compare checks the frozen interval and
its gap policy, all nested raw hashes, capture and trial source pins, same-machine
boot identity, argv/cwd binding, exact workload boundaries, clock progression and
clock origins. It regenerates the clipped summary from raw observations and
rejects a substituted or inconsistent capture/summary. These checks bind local
bytes and provenance; they do not authenticate operator declarations.

## Result layout and time scope

Each fresh trial contains the normal `started.json`, `trial.json`, logs and
`telemetry.jsonl`, plus a private mode-0700 `platform-metrics/` directory:

- `started.json`: capture intent and dependency identities.
- `inventory.json`: fixed discovered sensor identities, raw units and status.
- `samples.jsonl`: bounded raw, sequential observations with per-read times.
- `capture.json`: actual boot/kernel/architecture/page identity before/after,
  source/input pins, exclusive-wait result and sampler status.
- `summary.json`: offline summary selected within the trial's monotonic bounds.

The first snapshot completes before launch; a final snapshot follows workload
retirement and sampler shutdown. Neither is extrapolated into the workload.
Per-source midpoint samples inside the window are selected; edges, gaps,
invalid/missing readings and partial accepted intervals remain explicit. The
collector's reset, charge-state, unit and gap rules are unchanged. There is no
invented power/energy when a source is absent, no averaging-window energy estimate
and no whole-system/domain attribution.

Elapsed time covers spawn through observed owned-group retirement. Concurrent
sensor reads/logging, scheduler effects and supervision are inside that window;
inventory/setup and the final snapshot are outside. Snapshot durations are
retained as instrument context. This is not a measured with/without-logging
correction, nor evidence that overhead is negligible. Freeze an interval only
after an exact-target overhead/update-rate pilot. Overlapping host activity in
component controls is uncontrolled and cannot establish performance differences.

## Workload ownership and explicit limits

The optional path calls the pinned shared `prepare()` before spawning and
transfers the fresh-session child to `supervise()` without `Popen.poll`, `wait`,
`communicate` or a context-manager reap. The leader remains reserved through all
final signals; only a real raw wait supplies exit status. ECHILD is UNKNOWN,
never exit zero, and no later numeric signal/probe follows it. A sampler receives
no child PID. Its sysfs reads cannot race numeric cleanup. A known unresolved raw
wait remains retained and blocks subsequent optional launches; an uninterruptible
child cannot be forced to retire by userspace.

The helper captures at most 512 KiB of **combined stdout/stderr**. `stdout.txt`
contains that observed stream; `stderr.txt` is empty, with this scope recorded in
the capture. Output overflow invalidates the workload. Do not use this mode for a
protocol that requires separate stdout/stderr without a reviewed helper change.

The shared supervisor has no safe in-flight PID sampling hook. Consequently this
mode emits a clearly unknown legacy telemetry placeholder: root/process-group
RSS and old thermal/power guardrail fields remain unavailable. Actual platform
thermal/power records live in the separate capture. Existing RSS or old sensor
regression guardrails yield INCOMPLETE (or FAIL if another budget fails), while
optimization acceptance remains NOT RUN. This avoids treating one early RSS
reading as full workload coverage. The default runner and memory sampler are
held; restoring those guardrails in this mode requires a separate owner-aware
sampling interface, not an unguarded PID thread.

Sampling is bounded by the collector's attribute/file/sample caps, an interval of
0.1..10 seconds and a timeout/sample-count admission bound. The owned run budget
is the frozen workload timeout plus a separate 0.5-second retirement allowance;
spawn/setup and OS syscall stalls are not hard real-time bounded. A worker that
does not stop within 0.25 seconds leaves an incomplete, unsealed capture and
prevents another optional launch while alive. No valid trial is emitted from
that failure. Sampling errors also preserve raw partial evidence and refuse a
complete bound capture. No sampler thread can signal or reap a workload.

## Qualification scope

The integration controls run genuine short owned Python workloads and actual
host sysfs reads through the existing freeze/load/run/compare APIs. To avoid
package queries, their live state check is explicitly replaced with a fixture
identity; ambient/charge fields are labeled placeholders, not observations.
They establish host component behavior, not verified package/base identity or
physical conditions. A retained complete 12-trial block reaches compare and
correctly reports its missing RSS guardrail without granting acceptance.

Pure controls reject boot, clock/boundary/origin, argv/cwd, source, config, raw hash,
summary, completion and wait-result mismatches. Natural exit, owned timeout,
genuinely stolen wait, sampler failure, blocked sampler and output freshness are
separate software controls. The existing collector's 32 controls remain applicable.
Native ARM, 16K, installed Asahi, physical M2, calibrated energy, logging overhead
comparisons, sustained thermals, battery life and optimization/release acceptance
remain **NOT RUN**. The exact-machine pilot procedure is in
`docs/benchmarks/platform-metrics.md`.

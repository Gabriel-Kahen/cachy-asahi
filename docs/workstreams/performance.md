# Performance workstream

October 11, 2026. Scope: `scripts/benchmarks/`, `docs/performance/`, this report.
**Tested source framework; M4 hardware/optimization acceptance NOT RUN.** No ARM
build, installation, improvement, battery-life or M2 compatibility claim.

## Delivered

- [`benchmark.py`](../../scripts/benchmarks/benchmark.py): frozen-plan preparation,
  individual scheduled workload trials, and conservative preliminary comparison.
- [`test_benchmark.py`](../../scripts/benchmarks/test_benchmark.py): meaningful
  refusal/failure tests and an actual 12-trial CLI roundtrip on the development host.
- [Methodology](../performance/README.md), [CLI/schema guide](../performance/cli.md),
  [experiment supplement](../performance/experiment-template.md),
  [instrumentation plan](../performance/instrumentation.md), and
  [illustrative nonacceptance config](../performance/config-example.json).

Plans pin the retained before/after environment records, workload inputs and
review evidence by SHA-256. Trial execution checks the live machine/base identity
before and after, runs exact argv without a shell in a caller-selected directory,
and saves stdout/stderr, exit/timeout status, monotonic timing and raw per-sample
JSONL. Available thermal-zone, hwmon power, power-supply battery and proc memory
readings retain paths, labels, units and unavailable values. No sensor availability
is inferred from an upstream specification. Original material is MIT; no upstream
code was copied or packaged. Runtime dependency: Python 3.9+ standard library;
ordinary read access to available Linux proc/sysfs and executable workload inputs.
No system installation paths, package hooks or services are introduced.

Comparisons require the entire predeclared interleaved order (at least five
trials/variant), successful work, matching input/machine/base/workload bindings,
control declarations, environment and sensor identities, intact raw outputs and
consistent durations. An optional single environment-key change supports compiler
flags or two retained compiler artifacts through a fixed pinned driver. Allowed
package deltas must exactly match declared package names; unrelated changes are
refused. Kernel/package differences require pinned review evidence.

Results report median/min/max/MAD/range and useful elapsed thresholds with optional
sampled root-RSS, thermal and hwmon-power regression budgets. Missing planned
guardrail telemetry yields INCOMPLETE. CLI success is MEETS_TIMING_RULE_ONLY;
`optimization_acceptance` is always NOT RUN. Physical trial plans require declared,
reviewed baseline-functional and recovery evidence for their exact machine/base.
Declarations and hashes do not independently prove hardware facts.

## Actual validation

Executed on the existing x86_64 Linux development host (kernel
`7.2.7-1-cachyos`, Python `3.14.7`), **nonacceptance**:

```sh
python3 -m unittest discover -s scripts/benchmarks -p 'test_*.py' -v
python3 scripts/benchmarks/benchmark.py --help
```

Latest full suite: **28 tests PASS** (4.168 seconds reported by unittest). The
roundtrip prepares a live development-host-bound plan, executes twelve real
subprocess trials in temporary isolated directories, compares retained raw results,
and asserts optimization acceptance remains NOT RUN. Timing is not an optimization
measurement: both variants run the same tiny smoke workload with a distinct
environment label to exercise the one-key variant mechanism. Temporary test
artifacts are removed after the tests; no fabricated hardware record is published.

Failure coverage includes changed workload/baseline inputs and retargeted symlinks, unrelated package
updates, root/privilege escalation refusal, literal shell metacharacters, nonzero
exits, timeout and original-process-group cleanup, slow-sampling deadline overrun,
missing sensors, thermal/battery unit distinctions, partial sensor coverage,
threshold regressions, differing bindings/environment/controls, modified raw
outputs, missing/duplicate trials, inconsistent duration and overlapping order.
The illustrative JSON passes schema validation; placeholder files prevent actual
freezing. All local performance-document links resolve.

A separate read-only agent review found unchecked retained baseline hashes,
sampling that could mask deadline overrun, overbroad child-cleanup wording and
missing duration checks. These were corrected and relevant regressions added.
Documentation was drafted in a separately owned bounded subagent scope. No shared
manifest, root documentation or Git state was changed by this worker.

## Limits and next gates

- Exact M2 Air 13-inch and 15-inch baseline capture, physical measurements,
  functional/recovery evidence and independent review remain NOT RUN; no target
  machine or verified native builder is available in this workstream.
- Root-process RSS is sampled context, not process-tree peak. Elapsed time includes
  asynchronous telemetry/observed-completion overhead. The workload deadline is
  monitored independently of sensor reads; cleanup waits are bounded. This is not
  a hard real-time guarantee under OS stalls. Workloads must wait for all children
  and must not detach: cleanup covers the original process group only. SIGKILL of
  the harness cannot run Python cleanup; uninterruptible tasks may remain unreaped.
- Workloads are trusted inspected code, not sandboxed. The harness applies no
  kernel/sysctl/service/power changes, installation, suspend or speaker playback.
  Output/build files belong in the caller's isolated directory. Apply/remove
  reviewed experiments separately through the hardware/recovery procedure.
- Ambient/start-temperature/SOC/display/cache/background controls and sole-variable
  review require real observations. File pins do not recursively inspect manifests,
  preserve downloadable repository artifacts or authenticate operator declarations.
- Frame/presentation and physical input latency, process-tree memory, integrated
  idle/load energy, battery lifetime, suspend drain, sustained thermals, correctness,
  hardware regressions and actual removal/recovery need separate instrumented
  physical evidence. Independent repeat sessions and release budgets remain open.

Coordinator integration proposal: link `docs/performance/README.md` and this report
from the shared M4/implementation record (and the outline's future
`docs/performance.md` entrypoint if retained). No package-inventory change is
proposed. Preserve M4 as incomplete; use the framework after accepted exact-machine
baselines and recovery, freeze calibrated model-specific budgets, then publish
sanitized baseline/final raw measurements even if no experiment wins.

## Peer-review follow-up

Resolved the six reproduced findings in
[`performance-framework-review.md`](../reviews/performance-framework-review.md)
without editing that reviewer-owned record:

| Finding | Implemented response and regression coverage |
| --- | --- |
| Input symlink retargeting | Pins retain declared absolute path, resolved target and content hash. Retargeting to different or identical contents is refused; retained state/evidence files use the same binding. |
| SIGTERM skips cleanup | The main-thread signal handler records interruption; normal cleanup runs, failure evidence remains, and the former handler is restored. A bounded external wrapper fixture verifies its workload is reaped after SIGTERM. |
| Power identity lacks channel labels | Raw readings separate chip name, power channel label and readable device path. Every snapshot's identity must match. Optional power guardrails require declared matching domain/reviewer/evidence; missing review is INCOMPLETE. CPU-to-GPU label drift is refused. |
| Blocking telemetry stalls deadline | A daemon sampler publishes completed snapshots to a bounded queue; the main thread monitors the workload independently. Each workload-reap and sampler-stop wait is bounded to 0.25 s. A blocked sampler, dropped samples, sampling errors or unreaped workload invalidate the trial; another same-process workload is refused while the sampler remains alive. A short self-expiring blocked-read fixture verifies bounded return and workload cleanup. |
| Live RSS nulls silently filtered | Coverage counts live, missing live, excluded exited and unknown lifecycle samples. Any missing live or unknown sample makes the RSS guardrail unavailable; only observed exited samples are excluded. Full comparisons exercise live/unknown INCOMPLETE and legitimate exit exclusion. |
| Trials predate frozen plan | Timezone-aware trial timestamps must follow the frozen plan and remain ordered. Pre-freeze and naive-clock fixtures are refused; clock inconsistencies require a new plan. |

The final 28-test run and a separate read-only follow-up source review found no
additional material defects. Source-framework verification remains x86/nonacceptance.
The review record's old snapshot hashes/findings remain historical; coordinator
and reviewer must reconcile them against the final source before closing review.

Final SHA-256 (`sha256sum` executed after the passing suite):

```text
07d6489d104bea7c526c1a7ac20be14433933e70fc9ec6863cdc5d55babbd6e1  scripts/benchmarks/benchmark.py
adc3aba0f2a852b554a7faa3b2bee6c19d860df5e0ce4aadb004e54fcc73754f  scripts/benchmarks/test_benchmark.py
```

Residual limits: a blocked daemon sensor read may persist until this CLI process
exits; stopping Python or uninterruptible kernel I/O cannot be guaranteed by the
harness. Original-group cleanup cannot reach detached children. Unsigned hashes,
UTC chronology, sensor labels and reviewer declarations do not authenticate
physical controls, power domains or predeclaration. Referenced power-review files
must be included in `inputs` to pin their contents. No M2 workload, tuning,
installation, power change, suspend or audio operation was performed.

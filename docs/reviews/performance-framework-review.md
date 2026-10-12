# Performance framework peer review

Reviewed October 11, 2026. **Source review with small synthetic fixtures only.**
No M2 measurements, tuning, suspend, audio, service changes, installation,
performance certification or optimization acceptance. The only new review output
is this file; performance implementation/docs and Git were not changed.
Desktop-owned follow-up recipe fixes are recorded separately in its workstream.

## Scope and snapshot

Reviewed `scripts/benchmarks/benchmark.py`, its tests, and all four
`docs/performance/` documents. Because the owner was still implementing them,
review used a stable temporary snapshot; SHA-256 values are below. Snapshot
`benchmark.py` hash: `bc435aeca2c456e582f7eda5a8fe36b927e5d721c01a469b0bfbaaef26326ae9`.
A later working-code check had hash `2005d2b4f2a5571c12dd929bd55972a0c834dcaf0182aed096468911851cf09a`; its additions checked
exact changed package names and broadened CLI validation-error handling.
The code underlying the findings below was unchanged at that check. Line
numbers refer to the snapshot (the new package-delta checks shift later lines
by 16). Reverify against the owner's final revision before closing findings.

18 existing tests passed in **3.602 seconds**, including the small real CLI
roundtrip, literal argv, timeout cleanup of attached descendants, state/input
file drift, bad numeric/control/binding rejection, full slot coverage, raw hash
checks, incomplete power guardrail, and the constant NOT RUN acceptance field.
This is development-host test evidence, not a measured baseline.

## Reproduced findings

### P2: Preserve the declared input path and symlink binding

Snapshot `benchmark.py:190-193,212-223,346-362`. `freeze()` resolves each input
symlink and retains only its target path/hash. `load_plan()` rehashes that old
target, while the workload uses the original argv path. Retargeting a driver
symlink after plan freeze passes input validation and executes an unpinned file.
This also affects an executable symlink; changing a venv/tool alias need not
change package inventory.

Fixture: `active.py -> A.py` was in `argv` and pinned `inputs`; both A.py/B.py
were temporary print-only files. After freeze, retargeted `active.py -> B.py`
without changing A.py. `load_plan()` accepted; `run()` exited **0** and stdout
was **`B unpinned`**. Its recorded pin remained A.py. Live identity was patched
to the synthetic baseline solely to isolate input binding; no M2 claim.

Retain the declared absolute path plus target/content identity; validate the
original path's resolution and content at run/compare, or reject symlinks
explicitly. Executing a frozen canonical argv could also work for executable
aliases, but driver/data paths and intentional variant inputs still need the
same contract. Add a retargeted-input regression fixture.

Reproducer from repository root, using the existing temporary fixture helpers:

```python
import importlib.util, sys
from pathlib import Path
from unittest.mock import patch
spec = importlib.util.spec_from_file_location(
    "fixtures", Path("scripts/benchmarks/test_benchmark.py"))
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)
b, case = t.b, t.BenchmarkTests()
case.setUp()
try:
    a, z, link = [case.root / n for n in ("A.py", "B.py", "active.py")]
    a.write_text("print('A pinned')\n")
    z.write_text("print('B unpinned')\n")
    link.symlink_to(a)
    case.config["argv"] = [sys.executable, str(link)]
    case.config["inputs"] = [sys.executable, str(link)]
    plan = case.freeze()
    link.unlink()
    link.symlink_to(z)
    b.load_plan(case.plan)  # accepted despite retarget
    with patch.object(b, "live_identity", return_value=plan["states"]["baseline"]):
        print(b.run(case.plan, 0, case.state, case.conditions,
                    case.root, case.root / "symlink-run"))
    print((case.root / "symlink-run/stdout.txt").read_text())
finally:
    case.doCleanups()
```

### P2: SIGTERM bypasses workload cleanup

Snapshot `benchmark.py:278,295-304`. `execute()` starts a new workload session,
and handles KeyboardInterrupt/OSError with a `finally` process-group kill.
Ordinary SIGTERM uses Python's default immediate termination and does not enter
that cleanup. A terminal/CI cancellation can leave the measured workload alive,
affecting later measurements and host resources.

A bounded temporary harness called `execute()` on a print-PID/sleep-0.8-second
child, then received SIGTERM. Harness return code was **-15**; the child remained
**`State: S (sleeping)`**. The fixture explicitly killed the child's group in
its own `finally`, and waited for the harness. No workload was left running.
The regression can use that short self-expiring workload with a 0.4-second
harness timeout, wait for stdout PID, terminate the harness, and inspect `/proc`.
Do not test cleanup using an unlimited daemon.

Handle SIGTERM through an interruption path which preserves failure evidence
and executes group cleanup. Keep the documented scope: descendants which detach
into a different session are outside current cleanup; trusted workloads must
not detach. SIGKILL is inherently outside Python cleanup and is a limitation,
not the defect reported here.

### P2: Power-channel identity omits the channel label

Snapshot `benchmark.py:251-252,426-429`. Power records call the hwmon chip
`name` their `label`, but ignore `powerN_label`. Comparator identity is
`(path, label, unit)`, so a channel reassigned to another power domain can
compare as the same instrument. Matching numeric values/path alone does not
establish matching power domain.

Temporary sysroot fixture had `hwmon0/name=fixture-chip`, `power1_input=100`,
and `power1_label=CPU`; changed only the label to GPU and sampled again.
Both recorded power lists were **identical**, with `label=fixture-chip`,
unit uW and value 100. The CPU/GPU label was absent. No actual sensor changed.

Preserve chip and channel labels separately, and stable device identity when
readable. Bind the whole identity per sample/trial, handle absent labels
explicitly, and require reviewer-confirmed domains before accepting a power
comparison. Add a CPU-to-GPU channel-identity fixture.

### P2: The deadline is soft while telemetry reads are synchronous

Snapshot `benchmark.py:281-288`. The timeout is checked only after telemetry
returns. A mocked 120 ms read with a 30 ms timeout returned after **121 ms**;
it correctly reported `error=timeout`, but the workload could run beyond the
configured deadline. An indefinitely blocked driver read would prevent the
check/group cleanup indefinitely. The existing slow-sampling test checks the
error result, not a bounded cleanup deadline.

Either isolate sampling behind an independent workload deadline/cleanup
mechanism, or explicitly document this as a soft deadline and impose bounded
sensor reads. Retain telemetry-overhead timing disclosure. This finding does
not claim that any M2 driver blocks; the synchronous control-flow limit is
reproduced with a tiny fixture.

### P3: Define RSS coverage exclusions before claiming a complete guardrail

Snapshot `benchmark.py:313-314`; snapshot `docs/performance/cli.md` says partial
or missing readings invalidate a required guardrail. RSS aggregation silently
filters nulls while thermal/power aggregation invalidates partial coverage.

A full synthetic twelve-slot comparison with RSS `[10, null]` in every trial,
a declared `root_rss_kib_pct: 0` guardrail, updated raw hashes and recomputed
summaries returned **0**, **MEETS_TIMING_RULE_ONLY**, RSS regression **0**, and
an empty missing-telemetry list. `optimization_acceptance` stayed **NOT RUN**.
This is a documented-coverage mismatch, not process-tree memory measurement.

A normal final sample after the root exits may have no RSS, so rejecting every
null blindly would reject ordinary successful trials. Record process lifecycle
state, define legitimate post-exit/pre-start exclusions, and expose missing
live-process observations and coverage. Align the guardrail/docs with that
explicit scope and add a partial-live-coverage fixture.

### P3: Comparison does not enforce the recorded freeze chronology

Snapshot `benchmark.py:403-407,437-439`. Comparison validates a trial's own
timestamps and nonoverlap/order, but not that trials began after the plan's
`frozen_at`. The synthetic fixture's October 11 UTC trial timestamps were
accepted against a plan frozen October 12 UTC. This is an evidence-consistency
gap in the documented predeclaration protocol, not proof of retrospective
manipulation of any real measurement.

Reject an obvious pre-freeze trial or explicitly surface a clock discontinuity
for review. Wall-clock timestamps remain operator/clock evidence, and this
check cannot prove predeclaration cryptographically. Keep the unsigned-record
limitation disclosed even after adding a chronology check.

## Boundaries which are correctly preserved

- Base/state/input file hashes are retained; live state is checked before and
  after actual execution. Variant state differences are predeclared; current
  additional code limits package-name deltas. Model/page/kernel/repository
  differences are distinct from a reviewed candidate change.
- Controls and elapsed/variability/guardrail thresholds are declared before
  ordinary runner execution; finite/bounded numeric validation, at least five
  samples per variant, complete unique slots and interleaved order are enforced.
  Conditions are operator observations, not certified physical controls.
- Direct argv execution avoids shell interpolation. Workloads remain trusted
  executable code rather than a sandbox. No harness host tuning/install/
  suspend/audio/service actions were observed.
- Raw stdout/stderr/telemetry hashes, summary/raw consistency, monotonic
  duration/sample boundaries, state consistency and plan links reject accidental
  edits. Unsigned JSON and hashes within it are expressly not tamper-proof
  attestations; an operator can rewrite records and hashes. Do not present that
  documented trust limit as a cryptographic guarantee.
- Missing thermal/power data correctly produce INCOMPLETE for required
  guardrails. Parent RSS is named narrowly; power is per-trial sampled median,
  thermal per-trial sampled maximum. Neither is battery energy/runtime or
  whole-workload memory. No confidence interval/significance is inferred.
- Range/median is the enforced elapsed dispersion rule; MAD is reported only.
  The docs explicitly leave independent repeat-session/MAD rules to the
  supplement. Frame/input latency, energy/battery, suspend, sustained thermals,
  correctness, regression and recovery need separate physical evidence.
- Every trial/plan/comparison has `optimization_acceptance=NOT RUN`.
  Successful comparison yields MEETS_TIMING_RULE_ONLY, never M4 PASS.
  Synthetic threshold success cannot become native/hardware acceptance.

Remaining operator trust limits: machine ID is a declaration, matching model/
hostname is not unique physical identity; inputs/manifest completeness is
reviewed rather than discovered; working-directory reset/cache/warmup/control
truth is external; state evidence/PASS declarations need independent physical
review. Only explicitly supplied trial directories are compared, so omitted
failed/rerun slots require the external ledger/protocol review. None of these
limitations is silently counted as passed hardware validation.

## Reviewed file hashes

| Snapshot file | SHA-256 |
| --- | --- |
| `scripts/benchmarks/benchmark.py` | `bc435aeca2c456e582f7eda5a8fe36b927e5d721c01a469b0bfbaaef26326ae9` |
| `scripts/benchmarks/test_benchmark.py` | `7484bf8b658ef10e594f0d81d69883d77519b4d629df93d91757e5d78fe2ac47` |
| `docs/performance/README.md` | `56f21d6d8b611b7bbfdf9b9f9f68a7561b8e86df72f55b451a7f521ab7b17443` |
| `docs/performance/cli.md` | `ec36af42a0c5c18080bd2c518a98afdc7eb50628514fe5478814c1555ef6c3bb` |
| `docs/performance/experiment-template.md` | `d0f1440a378fc8067174c9894f3aacd6bf80f5134700cfc104171d9f5f7d130a` |
| `docs/performance/instrumentation.md` | `62af52a6ed7ba63c437bc88884bde01f5a6df22906cb14f56c658a2e9e645cec` |

The coordinator should send concrete findings to the implementation owner,
then rerun focused fixtures against the final source revision. Peer review
remains open until those fixes or explicitly accepted documented limits are
reviewed. No real machine or performance result is certified here.


## Targeted final-fix verification — all six findings resolved

Independent rerun on October 11, 2026 against frozen source SHA-256
`07d6489d104bea7c526c1a7ac20be14433933e70fc9ec6863cdc5d55babbd6e1`. Working source still matched this hash after the fixtures.
Test-helper snapshot SHA-256:
`adc3aba0f2a852b554a7faa3b2bee6c19d860df5e0ce4aadb004e54fcc73754f`.
Updated CLI-guide snapshot SHA-256:
`48e3828800fdc79a09d26017b95ac0363d1d331d17d4b8adaee6ef03fc9193a2`.
Only this review file was appended; no performance implementation, desktop
source, Git state or target system was changed.

The earlier open-findings statement describes the original reviewed snapshot.
**All six findings are now closed for this exact source revision.** The owner
reported 28 passing tests; this follow-up independently executed the original
bounded reproductions, rather than treating that report as the result of a new
28-test run. Fixtures used temporary directories, print-only/self-expiring
workloads, fake hwmon channels, synthetic records, and mocked sensor delays.
Every fixture passed its explicit expected outcome; all child processes were
reaped/killed and the temporarily blocked sampler was released and joined.

| Original finding | Independent final-source result | Outcome |
| --- | --- | --- |
| Retargeted input symlink | Original `active.py -> A.py -> B.py` fixture is refused by `load_plan()` with `input changed after declaration`. Retargeting to equal-content B.py is also refused. The unpinned workload never executes. Original path and resolved identity are retained. | RESOLVED |
| SIGTERM cleanup | Same short print-PID/sleep fixture: wrapper completes with return 0 after receiving SIGTERM, retained execution result says `interrupted by SIGTERM`, workload return code is -9, `/proc/PID/status` is absent, and `workload_reaped=true`, `worker_stopped=true`. Wrapper return 0 means it successfully wrote the interrupted fixture result, not successful workload/benchmark acceptance. | RESOLVED |
| CPU/GPU power-channel identity | Fake `power1_label` CPU->GPU changes recorded `channel_label` while `chip_name=fixture-chip` and unavailable device stays null. Full synthetic comparison refuses it with `sensor source/chip/channel/device/unit changed within or between trials`. | RESOLVED |
| Synchronous telemetry defeating deadline | Original 120 ms sample/30 ms timeout fixture returned in **122.157 ms**, but the workload's `/proc` entry was already absent at the sensor's **60 ms** checkpoint. It returns `error=timeout`, workload reaped and sampler stopped. Cleanup wait is explicitly separate from workload deadline. A blocked-reader surrogate with 50 ms cleanup allowance returned in **81.342 ms**, `worker_stopped=false`, `workload_reaped=true`; next execution was refused as `previous telemetry sampler still blocked`. Reader event was released/joined in fixture cleanup. | RESOLVED |
| Partial RSS guardrail | Full twelve-slot `[10, null]` fixture with explicit lifecycle: missing **live** and **unknown** observations both return 2/INCOMPLETE and `root_rss_kib_pct:root_rss_kib` missing. Explicit **exited** null returns 0/MEETS_TIMING_RULE_ONLY with one excluded-exited sample. Coverage counters expose each case; acceptance remains NOT RUN. | RESOLVED |
| Trial before freeze | Starting slot 0 one second before `frozen_at` is refused with `trial predates frozen plan; clock discontinuity requires a new declaration`. A timezone-naive timestamp is also refused as `timezone-aware evidence timestamps required`. | RESOLVED |

The timing numbers above describe cheap synthetic process-control fixtures on
the development host, not M2 performance results or timeout guarantees under
all possible operating-system stalls. The updated guide documents asynchronous
sampling, bounded cleanup, incomplete sampler status, and RSS lifecycle rules.
Power guardrails additionally require a reviewer-declared matching power domain;
channel names alone do not certify a physical measurement domain.

For reproducibility, the temporary independent fixture script hash was
`552b4d78949d1cf5b5ff23be10bcfd71d33e35a267f0a406fd640a16ee19bc18`. Its variants reproduce the earlier symlink, SIGTERM,
fake-channel, 120 ms delayed-sampling, partial-RSS and pre-freeze cases; the
blocked-reader case uses a self-expiring Event with explicit release/join.
No actual benchmark workload, host tuning, suspend, audio, service change or
hardware acceptance was performed. Raw test outputs were inspected and the
concrete results are retained in the table above.

Residual limits remain explicitly acknowledged rather than counted as PASS:
SIGKILL/OS stalls and detached sessions cannot promise Python cleanup; an
unresponsive sampler leaves incomplete evidence and requires ending that
process; unsigned records and operator declarations do not attest real physical
identity, controls, calibration, correctness, recovery or M4 acceptance.
These are not residual reproductions of the six corrected defects.

**Source-review closure only:** successful fixture/comparison outcomes still
retain `optimization_acceptance=NOT RUN`; clean ARM, installed-base, exact-M2,
physical performance and release gates remain outside this peer review.

# Predeclared experiment and hardware decision record

Copy this template to a new experiment record and freeze it, alongside the runner
JSON plan, **before candidate trials**. This document supplements the CLI schema;
it is not itself a machine-readable plan. Fill every required field, derive
budgets from a separate baseline characterization and intended use, and record
the review/date/hash. Unfilled fields prevent hardware acceptance. Changes to
thresholds, workload or controls require a new experiment ID and fresh trials.

Status: PROPOSED / SOURCE-AUDITED / MEASURED-PRELIMINARY / HARDWARE-REVIEWED.
Hardware acceptance: NOT RUN / FAIL / PASS, with reviewer and linked evidence.
Current template: PROPOSED, hardware acceptance NOT RUN.

## Question and identity

- Experiment ID, operator, independent reviewer, freeze time and plan SHA-256:
- Target question and expected mechanism:
- One changed variable, reference value, candidate value and artifact hashes:
- Explicit allowed package/configuration difference; inventory diff evidence:
- Machine ID, physical execution evidence, M2 Air size, RAM/storage/page size:
- Baseline JSON path/hash; accepted base/version fingerprint:
- Source/toolchain/dependency snapshots and retained input artifact locations:
- Harness version/hash; release/revision and dirty-state record:
- Baseline hardware and exercised recovery evidence:
- Workload source/input hashes, argv, declared environment, concurrency:
- Isolated working directories and output artifact correctness checks:
- Cache mode, reset of workload output and warmup procedure:

## Frozen controls and schedule

- Power source/charging state; permitted battery charge band:
- Display brightness (actual reading/measurement), mode, refresh, scaling:
- Lid position, peripherals, audio state, network mode and background workload:
- Ambient instrument/location and permitted ambient band:
- Starting thermal sensor identity/instrument and permitted band; settling rule:
- Sustained-work duration and definition of steady-state analysis window:
- Telemetry interval, required sensors, sensor domains and missing-data policy:
- Reviewed power-channel chip/name/label/device identity and evidence; live RSS
  coverage requirement, post-exit exclusions and sampler failure policy:
- Trial timeout and operator safety/abort condition:
- Warmups per variant; measured trials per variant (minimum five):
- Frozen order/block schedule and second independent repeat-session schedule:
- Invalidating events, replacement-trial rule and maximum reruns:

## Numerical decision contract

Every metric needs an instrument/method, unit, aggregation, baseline reference,
useful-effect or regression bound, variability/uncertainty rule and required trial
count. Required missing measurements are NOT RUN. Do not fill gaps with estimates
from elapsed time or another machine. Record an absolute use budget as well as a
relative regression budget where the requirement demands both.

| Metric | Method / unit / trial aggregation | Frozen useful-effect or regression bound | Variability / uncertainty rule | Required count |
| --- | --- | --- | --- | --- |
| Correct output | Workload-specific tests/checksums | All required checks pass | Any correctness failure fails candidate | Every trial |
| Elapsed fixed workload | Monotonic elapsed seconds; median | Improvement at least ___%; absolute use limit ___ s | Relative MAD at most ___%; same outcome in independent session | ___ per variant, >=5 |
| Interactive latency under fixed load | Physical input-to-display ms; per-trial p95 | p95 <= ___ ms and increase <= ___ ms | ___ events/trial; camera/trigger uncertainty ___ ms | ___ trials/variant |
| Frame behavior | Presentation timestamps; per-trial late-frame fraction | Fraction <= ___%; increase <= ___ percentage points | Define late-frame deadline; trace validity and sampling rule | ___ trials/variant |
| Workload memory | Defined process-tree metric in MiB; per-trial peak | Peak <= ___ MiB; increase <= ___% | Missing children/short-lived peaks invalidate this gate | ___ trials/variant |
| Idle/load power | Named domain W; fixed-window average | Increase <= ___ W or ___%; absolute use limit ___ W | Instrument resolution/error must resolve budget | ___ windows/variant |
| Workload energy | Named domain Wh or J per correct task | Increase <= ___% or reduction >= ___% | Same domain/window endpoints; integrated error ___ | ___ tasks/variant |
| Battery behavior | Battery Wh per fixed-duration session | Energy increase <= ___%; runtime budget ___ | Same charge band, age/health record; fuel-gauge resolution ___ | ___ sessions/variant |
| Suspend drain | Battery Wh per hour over operator-led window | Drain <= ___ Wh/h; increase <= ___ Wh/h | Endpoint resolution, actual sleep time, no unplanned wakes | ___ windows/variant |
| Sustained thermal behavior | Named sensor/skin instrument Celsius; fixed window | Increase <= ___ C; absolute limit ___ C | Same start/ambient band; sensor accuracy ___ C | ___ sessions/variant |
| Hardware and recovery | Linked exact-machine regression/lifecycle checks | All required checks pass; rollback restores usable system | Preserve every failure; no CLI substitution | Counts from accepted hardware plan |

Concrete illustration only, **not adopted M2 budgets or measured results**: a
throughput experiment could predeclare >=5% median elapsed reduction, <=5%
relative MAD in both variants, six measured trials each in counterbalanced order
and a second independent session with the same outcome. It could allow <=5%
process-tree memory increase, <=5 ms p95 input-latency increase and <=0.5
percentage-point late-frame increase. Energy and thermal budgets must still be
chosen from actual target baseline and instrument uncertainty before running.
These example numbers cannot supply a PASS or be copied after inspecting a
candidate's results. Five elapsed samples do not suffice for p95 latency; define
enough input events inside every independent interactive trial.

## Actual trial ledger

| Session/block/position | Variant | Raw run directory/hash | Start controls and telemetry | Exit/correctness | Validity and reason |
| --- | --- | --- | --- | --- | --- |
| | | | | | |

Append failed/aborted trials and protocol deviations here. Preserve their raw
files; assign replacement positions according to the frozen rule. The ledger
must expose actual order, including install/reboot/settling transitions.

## Hardware review and removal

- Raw traces, power/thermal logs, calibration records and analysis method:
- All medians/dispersion/counts, required external metrics and uncertainty:
- Rejected comparisons or breached budgets with reason:
- Independent repeated-session result:
- Hardware regression record for this exact machine/version:
- Candidate removal command/procedure, executed recovery evidence and outcome:
- Per-metric PASS / FAIL / NOT RUN and evidence:
- Optimization acceptance decision, reviewer, date and rationale:
- Publication location, evidence-bundle hash and scope of any allowed claim:

CLI timing threshold results remain preliminary. PASS belongs only to this
independently reviewed complete hardware decision, never to missing evidence or
an x86 smoke run. Keep the second Air size and final combined-release comparison
as separate required records.

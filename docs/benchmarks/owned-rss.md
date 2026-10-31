# Optional owner-aware benchmark RSS

Declare both instrumentation fields in the complete experiment config before
freezing, and use the existing `benchmark.py run ... --platform-metrics` flag:

```json
"platform_metrics": {"interval_seconds": 0.1},
"owned_rss": {"interval_seconds": 0.5}
```

`owned_rss` is separately optional. Without it, platform capture retains the
existing unavailable legacy RSS fields. Default execution and paired_zlib
interfaces are unchanged; this adds no implicit PID sampler or new command-line
flag. Plans must predeclare instrumentation and pin the actual sources before
trials; neither retrospective changes nor mixed instrumentation are accepted.

This feature requires Root's separate adoption of the prepared shared core,
SHA256 `83444522f4dfede67f6965ea75de8411b9e34510c04d40571fe439c223294e8f`, and
the platform adapter's pin-only update, SHA256
`863442bfeb274b7dcfec540c33fd4632498e58a5672a3b466aca6bc6fc46b9bd`.
This packet changes neither dependency. Freeze refuses the wrong core. The
benchmark passes the built-in `rss_interval` through a temporary owner facade;
that facade is restored in `finally`. Only the owner scans numeric PIDs while
holding exclusive non-reaping wait ownership. No sensor thread receives a PID,
no arbitrary observation callback is added, and no benchmark code probes or
signals a retired group. Existing output/retirement behavior stays with the
shared supervisor and platform adapter.

## Meanings and strict replay

`root_rss_kib` is the sampled live **leader** maximum, derived from actual member
VmRSS observations. It is the truthful quantity for the existing
`root_rss_kib_pct` regression budget. It never contains a group sum or wait4
usage. `process_group_sampled_rss_kib` remains a separate original-group sum;
the new `process_group_sampled_rss_kib_pct` budget compares that quantity.
For example, declare both under `thresholds.maximum_regression`:

```json
{"root_rss_kib_pct": 5, "process_group_sampled_rss_kib_pct": 5}
```

Each group snapshot verifies actual member identities and RSS; shared pages are
counted in every process. Detached/new-session descendants and forks/exits between
snapshots remain outside the observed evidence. These are sampled quantities,
not unique physical memory or a true workload peak. An equal root/group value
is legitimate for an observed group containing only its leader; it is not a
leader-only substitute for group collection.

The trial retains the unchanged legacy `telemetry.jsonl` placeholder and adds
`owned-rss.json`, containing all bounded raw owner observations, actual read
clocks, exact core identity, interval and workload boundaries. The same raw RSS
object is also bound to `platform-metrics/capture.json` supervision. Trial metrics
project both quantities from these records. Compare verifies the additional raw
file hash, source/config/window binding, membership identities, nonnegative RSS,
exact sums, scope, clocks and cached summaries. It requires all successful
supervision predicates, including `passed`, no error/timeout/signals, complete
output and `RESERVED_LEADER_ONLY` census, plus usable complete RSS evidence.

Incomplete reads, membership churn, unknown wait ownership and failed/partial
coverage retain diagnostic observed maxima separately. They never yield a usable
leader/group peak, a fake zero or a successful memory guardrail. Missing or
inconsistent raw data rejects replay. A completed raw reap does not repair a
failed observation. The new raw artifact and all workload/source/condition/order
checks remain mandatory even if an experiment omits a memory regression budget.

The core caps 4096 records and 8192 total member rows. Configuration additionally
admits only finite RSS intervals of 0.01..60 seconds within the retained-sample
budget. The platform adapter currently replays capture metadata at a 512-KiB
bound. If embedded RSS makes capture metadata exceed that bound, the benchmark
retains the raw files and returns an explicit failed trial before admission.
Increasing that shared limit is outside this adoption; no larger capture is
silently treated as replayable. RSS observation and logging overhead are inside
recorded execution time and have not been measured against an uninstrumented
baseline.

## Actual bounded host evidence

The retained source-only composition uses `/usr/bin/python3` 3.14.7, the exact
prepared core and the exact pin-only adapter update. Live state checks and
physical conditions are explicit fixtures to avoid package queries; ambient/
charge zeros are placeholders, not measured conditions. Workloads, allocation,
proc/sysfs reads, clocks and owned retirement are genuine host operations.

A control without `owned_rss` leaves both usable RSS values null. The final
allocation case records 18,168 KiB for a verified one-member group and leader.
A complete ABBA-interleaved 12-trial block executes fixed work/output with
baseline 2-MiB versus candidate 10-MiB scratch allocation. All 12 have one usable
owner-held RSS snapshot. Median sampled root/group RSS is 16,128 versus 24,318
KiB; neither guardrail is missing. Both 5% budgets correctly fail the intentional
memory-regression control, so the comparator returns FAIL, with optimization
acceptance NOT RUN. This demonstrates measurement/comparator behavior and makes
no performance gain or population/target-machine claim.

The descendant startup case is **not accepted**: the first snapshot observes
group membership changing during fork, triggers bounded owned retirement, and
retains null usable peaks with the actual error. The terminal-transition failures
from the initial 50/100-ms pilot are also retained. A 500-ms pilot interval avoids
that terminal overlap for the stable short paired controls; that interval
produces one snapshot per trial and does not prove a true peak or general fork-
heavy workload coverage. Do not select only successful observations or call the
failed descendant case a positive group measurement. A stable-group readiness/
observation-start boundary remains necessary for positive admission of that
specific fork-at-start case; this packet does not modify the shared core to add it.

Eleven focused integration controls pass, covering real allocation, explicit
churn refusal, disabled behavior, root/group separation using a labeled pure
fixture, partial-data nonpromotion, source/config/clock/member/sum tampering,
contradictory supervision, capture bounds and raw/capture replay. The full default
suite and native/physical acceptance were not run. Exact raw evidence and hashes
are provided by the development packet's handoff. Native ARM, 16K, installed
Asahi, physical M2, calibrated energy, overhead/performance comparisons, sustained
thermal/battery behavior and optimization/release acceptance remain NOT RUN.

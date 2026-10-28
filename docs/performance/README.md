# M4 measurement framework

Current source execution uses the [owned-retirement v2 layer](owned-retirement-v2.md). Historical `benchmark.py` and `paired_zlib.py` files and their frozen plans remain byte-held; their legacy workload execution is retired. Redeclare fresh v2 plans for new runs; do not edit or rebind historical plans. Offline historical comparison remains available.

Status: methodology prepared; exact M2 native baseline, measurements, recovery
and optimization acceptance are **NOT RUN**. Development-host smoke runs and
automated tests are x86/nonacceptance evidence only. This framework does not
establish an improvement, ARM build, installation, battery-life or hardware claim.

Use the [baseline contract](../baseline.md), [hardware validation record](../hardware-validation.md),
[experiment template](experiment-template.md), [CLI guide](cli.md) and [instrumentation plan](instrumentation.md)
together. The outline's final-system measurements are required even if no tuning
experiment wins. Keep a separate record for each M2 Air size; neither emulation
nor a result on another machine substitutes for its record.

## Preconditions and provenance

Source research and harness testing can begin now. Target experiments require an
unmodified reference captured before changes, the accepted machine/version set,
functional baseline, and an exercised removal/recovery path. Experimental kernel
work additionally requires the M3 recovery gate and a retained, working Asahi
kernel recovery option. Preserve boot integration, graphics, audio and speaker
protection throughout testing.

Freeze a plan before candidate measurements. Bind it to the SHA-256 of the exact
baseline JSON file and retain that file. Also retain retrievable package/source
inputs: hashes of repository databases alone cannot reproduce a base. Record:

- Physical machine identity, Air size, RAM/storage, page size, execution context,
  operator and test session. Use a local pseudonymous machine ID, not a serial.
- Base/repository snapshots, kernel/firmware, graphics/compositor/audio versions,
  installed packages and protected-component fingerprints.
- Exact reference and candidate revisions, artifacts and hashes, build provenance,
  compiler/toolchain and flags. Identify the sole allowed difference explicitly.
- Workload source revision and input hashes; exact executable/argv, environment
  relevant to the workload, concurrency, output verification and cache policy.
- Harness revision/hash, plan hash, instrument versions/calibration, actual
  timestamps, controls and links to the raw evidence and recovery record.

A candidate binary's hash may differ because that binary is the experiment;
unrelated machine, base, workload or input changes invalidate comparison. Review
before/after inventories to show the difference is limited to the declared
variable. A plan bound to a baseline is evidence bookkeeping, not proof that the
running machine still matches it. Check runtime state and independently review
operator declarations.

## One variable and useful workloads

Define a falsifiable question, such as whether one compiler flag reduces the
elapsed time of a fixed native build without increasing interactive latency,
memory, energy or thermal costs beyond frozen budgets. A scheduler change plus
compiler flags plus a desktop reconfiguration is three experiments. Measure
accepted changes separately, then re-test their combination as a new candidate.

Select representative work and freeze its inputs and success criteria:

| Workload | Reproducible definition | Additional evidence |
| --- | --- | --- |
| Native development build | Pinned source/toolchain/dependencies, offline inputs, fixed jobs, fresh output tree, verify build artifacts | Correctness checks and process-tree memory measurement |
| Interactive desktop under load | Same editor/terminal/browser actions, fixed background native build, identical display settings | End-to-end input latency and presentation traces |
| Memory pressure | Fixed allocation/access pattern and duration within a declared safe headroom budget; fixed swap/zram configuration | System memory/swap/pressure observations and responsiveness |
| Graphics activity | Pinned application/scene, rendering API, size, refresh, scaling and duration; confirm hardware renderer | Presentation timing, correctness and load energy |
| Idle and battery use | Fixed session/apps/network/display and steady settling period; repeated fixed windows | Defined energy domain and battery state |
| Sustained work and suspend | Fixed long-running work; separately, operator-led sleep windows | Thermal history, drain and functional resume evidence |

The runner executes argv directly with no shell. Workload code is still executable
code: inspect it and its build hooks before use. It may create build products only
inside the caller-selected isolated working directory. Use pinned offline inputs
and workloads that wait for all their children. The runner's lack of host setup
commands does not make an arbitrary supplied workload safe.
Cleanup reaches only the workload's original process group. Detached or `setsid`
descendants are unsupported; trusted workloads must not detach or leave children
running after the parent exits. The workload deadline is monitored independently
of asynchronous sensor reads. This is not a hard real-time or guaranteed cleanup
deadline: OS scheduling/stalls, SIGKILL and uninterruptible tasks remain limits.
SIGTERM follows the interruption/cleanup path and invalidates the trial.
Bounded cleanup or sampling failures invalidate a trial; preserve their evidence
and inspect remaining workload state before proceeding.

Never use the harness to install packages, write sysctls/sysfs, change services or
power profiles, clear host caches, suspend, play speaker sounds, or invoke root
commands. An operator applies a reviewed experiment through the project's
installation/recovery procedure outside measurement scripts. Serialize all work
on each target; do not benchmark during another worker's installation or test.

## Controls, order and repetitions

Set the display brightness/mode/scaling, lid position, peripherals, power source,
battery charge band, network mode, background applications/services, ambient
temperature and support surface before each session, then observe and record
them. Separate battery from external-power results. Record charging transitions
and interference as invalidating events, not as a favorable sample selection.
The harness observes available sensors; it cannot certify ambient temperature,
brightness, lack of background work or a correct machine declaration.

For these fanless targets, predeclare a starting-temperature band and settling
rule based on actual sensor availability. Wait naturally for the band before each
trial; no cooling/thermal-control changes. If temperature is unavailable, use a
documented external instrument or leave the thermal-control gate NOT RUN. A
fixed delay alone does not demonstrate equal thermal starts. Measure a separate
sustained-work session rather than averaging hot and cold runs into one number.

Use at least five valid measured trials per variant, plus predeclared warmups
excluded from the result. Six per variant permits three counterbalanced blocks:

```text
A B B A | B A A B | A B B A     A = reference, B = candidate
```

Record each trial's block and position. Cool/settle and restore the declared
working-tree/cache state between trials. If changing a candidate requires a
reboot or install, treat each variant session as a block and counterbalance those
sessions. Document transition time and recheck inventories. Never compare one
complete cold reference batch with a later hot candidate batch and call it
controlled. A runner invocation is only part of the schedule; use separate fresh
output directories for each scheduled invocation.

Choose cold or warm cache behavior explicitly. A clean build directory is not a
cold filesystem cache. Do not drop host caches; use fresh isolated output trees
for each full build and a consistent predeclared warmup for warm-cache trials.
Record boot/session history for a cold-start study. Retain all failed trials,
timeouts, invalidations and reruns. Stop under the predeclared safety condition;
record the experiment failure rather than deleting the evidence. A failed
correctness or recovery check cannot be repaired by averaging more trials.

## Analysis and decision

Report raw elapsed values, sample count, median, minimum/maximum and median
absolute deviation (MAD). State the measured metric and units; elapsed time is
different from CPU time, completed tasks per second and frame latency. For a
fixed correct workload, elapsed improvement is:

```text
100 * (median_reference - median_candidate) / median_reference
```

Round conclusions to precision justified by repeatability and instrument
resolution. Do not present nanosecond clock representation as measurement
accuracy, five samples as a precise tail distribution, or overlapping noisy
medians as a reproducible gain. A frozen variation limit, effect threshold and
independent repeat session determine whether a timing result merits hardware
review; report an inconclusive result honestly. Quantiles require sufficient
events per trial and a declared quantile definition. Aggregate per-trial metrics
first; thousands of correlated frames in one trial are not thousands of
independent experiments.

The CLI's `maximum_elapsed_range_pct` limit is
`100 * (maximum - minimum) / median` for each variant. It reports MAD but does
not enforce a MAD budget, confidence interval or independent-repeat requirement.
Declare any additional variability/repeat rule in the operator supplement and
review it against raw results. Timing includes observed completion, bounded
cleanup and asynchronous telemetry overhead; it is not instrument-free subprocess
execution time. Completed samples come through a bounded queue. A stuck sampler,
dropped snapshots, sampler errors or an unreaped workload make the trial invalid.
Tiny workloads can have no live RSS observation; that is missing memory evidence
rather than a zero-memory result.

Reject comparison when the plan/baseline binding, machine, base, workload/input
identity, allowed candidate delta or declared controls differ; when observations
are missing for required controls; when order is uncontrolled; when a workload
fails; or when fewer than the declared valid trials exist. Do not pool models or
machines to reach a minimum sample count. Missing thermal, battery, power or
memory observations remain unavailable with a reason, never zero.

CLI output is a **preliminary timing comparison**. It cannot earn an optimization
acceptance PASS, including when an elapsed threshold is met. A human hardware
review must link measured latency/frame behavior, memory, idle/load energy,
battery/suspend behavior, sustained thermals, hardware regressions and actual
removal/recovery evidence. Each retained change must meet every frozen budget
on its advertised model. Missing evidence means NOT RUN; a breached requirement
means FAIL. Final release evaluation repeats the full suite against the retained
unmodified reference on both Air sizes, independently of individual tuning wins.

## Evidence bundle and publication

Retain the frozen plan and its operator supplement, bound baseline, before/after
inventory, artifact/input hashes, correctness logs, raw stdout/stderr and exit
codes per trial, sampled telemetry with timestamps/units/errors, actual trial
schedule, invalidation log, external traces/calibration, summary, and independent
review. Hash the bundle and identify release/commit/dirty state. Publish sanitized
raw measurements and tradeoffs with exact model/version scope; preserve the
original evidence privately. Review output for usernames, paths and application
content before sharing. No performance claim exists until that evidence exists.

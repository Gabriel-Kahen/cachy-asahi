# Instrumentation and exact-machine measurements

Status: source-audited interface plan, reviewed October 11, 2026. No target sensor,
instrument, frame/latency result, power result or suspend test has been verified.
The runner collects only interfaces actually readable on its host. Availability
in Linux documentation does not establish availability on an M2 Air.

## Read-only Linux observations

Store raw value, source path, device/type/label, unit, monotonic sample timestamp
and status/error. A disappearing file, denied read or absent class is unavailable,
not zero. Do not infer CPU/package power from an unnamed sensor. Record sampling
interval and sensor update rate when readable; polling faster cannot create
independent sensor measurements. Compare sampling overhead with and without
logging in a separate pilot, then freeze the interval.

The runner samples asynchronously; raw records are completed snapshots rather
than simultaneous measurements across sensors. Record observed intervals and
coverage, not just the requested interval. Dropped queue snapshots, sampler
errors or incomplete bounded cleanup invalidate a trial. A blocked sampler does
not block deadline monitoring, but OS scheduling/stalls and process termination
remain limits. Very short workloads may have no completed live memory sample.

| Interface | Interpretation | Limits |
| --- | --- | --- |
| `/proc/PID/status` `VmRSS`, `VmHWM` | Resident memory / high-water mark; preserve reported kB and convert to KiB/MiB explicitly | Parent process only unless descendants are separately measured; async accounting and polling can miss short-lived peaks |
| `/proc/meminfo` `MemAvailable`, swap fields | System memory context in reported kB | System-wide background activity included; not workload allocation or process-tree peak |
| `/sys/class/thermal/thermal_zone*/temp`, `type` | Thermal-zone reading in millidegrees Celsius with zone identity | Not necessarily CPU or skin temperature; zone enumeration can differ across boots |
| `/sys/class/hwmon/hwmon*/name`, labels, `temp*_input` | Usually millidegrees Celsius with chip/channel identity | Some documented channels use millivolts; driver interpretation must be checked |
| hwmon `power*_input`, `power*_average` | Instantaneous / averaged domain power in microwatts | Domain may omit display or include only one component; do not sum overlapping domains |
| hwmon `energy*_input` | Cumulative domain energy in microjoules | Check reset/wrap behavior, domain and time endpoints |
| power_supply `energy_now`, `charge_now`, `capacity` | Micro-watt-hours, micro-amp-hours and percent respectively | Energy and charge differ; percent is coarse fuel-gauge state, not power |
| power_supply `voltage_now`, `current_now`, `temp`, `status`, `online` | Microvolts, microamps, tenths Celsius and categorical power state | Battery temperature units differ from thermal zones; charging/discharging transitions matter |

The [Linux proc documentation](https://docs.kernel.org/filesystems/proc.html)
describes asynchronous RSS accounting; high-frequency parent polling is not a
reliable process-tree peak. Use a separately reviewed instrument that includes
the entire build process tree if a memory acceptance budget depends on that
metric. Document shared-memory double counting and instrument overhead. Do not
rename parent RSS to whole-workload memory.
The harness additionally records `process_group_memory` from the workload's
original session/process group, including ordinary child processes. A bounded
read-only `/proc` scan records each process's PID, start ticks, group/session,
state and `VmRSS`; it checks identity while reading and rechecks membership.
Observed forks, exits, PID reuse, unreadable live RSS, session changes, scan limits
or sampling-budget failures make that snapshot incomplete. Threads are counted
once through their thread-group leader. No cgroup, process, service, kernel
setting, or host cache is changed by this sampler.

`process_group_sampled_rss_kib` is the maximum RSS sum only when every applicable
snapshot is complete and the leader identity is stable. Missing/incomplete
snapshots leave that field null. `process_group_observed_rss_kib` separately
retains the maximum among completed snapshots, with explicit coverage counts;
it cannot substitute for missing coverage. The original `root_rss_kib` fields
and existing guardrails retain their original meanings. The new observations
do not add an acceptance guardrail or grant optimization acceptance. New frozen
plans also pin the harness and memory-sampler source files.

Summed RSS double-counts shared pages and is not unique physical memory. The
snapshot is sequential, not atomic: a process can fork/exit between scans, and
short-lived peaks can remain unseen. Detached/new-group descendants are outside
the supported workload contract and measurement scope. The sampler has a
100 ms per-snapshot budget, at most 4096 visible process entries and 512 group
members. Actual collection can overrun that budget if a proc read stalls; the
existing asynchronous sampler and workload timeout/cleanup still apply. Record
sampling overhead and coverage before choosing a measurement interval. This is
useful compiler/workload memory instrumentation, not a true process-tree peak
or a replacement for a separately justified memory acceptance instrument.

The runner's RSS summary requires every observed live-process reading and at
least one live sample. It exposes missing live observations, unknown lifecycle
and excluded exited samples in `rss_coverage`; unknown lifecycle makes RSS
unavailable. Post-exit exclusions cannot conceal a missing reading while the
process was observed live. Sampling still cannot prove the true peak between
observations.

Power records preserve `chip_name`, `channel_label` and resolved `device` path
separately, with explicit nulls when unavailable. The comparator refuses identity
changes within or between trials. For a usable power guardrail, freeze
`power_domains[path]` with the matching identity and reviewer-confirmed domain,
reviewer and evidence strings. Missing labels/device identity do not establish
CPU, package or system power; reviewers must justify the domain from driver/
instrument documentation. Missing or mismatching domain review is INCOMPLETE.
Retain and pin referenced source evidence files explicitly; a textual evidence
reference alone is not a preserved artifact.

The [Linux thermal ABI](https://github.com/torvalds/linux/blob/master/Documentation/ABI/testing/sysfs-class-thermal)
defines thermal-zone units. [The hwmon interface](https://docs.kernel.org/hwmon/sysfs-interface.html)
defines optional channels and power/energy units and warns that channels need
appropriate labeling and conversion. The [power-supply class](https://docs.kernel.org/power/power_supply_class.html)
distinguishes energy, charge and percent and allows absent attributes; the
[power-supply ABI](https://github.com/torvalds/linux/blob/master/Documentation/ABI/testing/sysfs-class-power)
defines current sign conventions and battery/supply temperature units. Check the
driver shipped on the actual target against these source references.

Where a driver exposes `power_now`, verify its documented unit and domain before
conversion. A derived instantaneous battery power estimate can use
`voltage_now * current_now / 10^12` watts, with raw sign and status preserved.
Label it derived: readings are not necessarily simultaneous, and battery power
is different from wall/USB input power. Do not take absolute values to hide a
charging transition. Retain unavailable derived power if either input is missing.

For discharge windows, `energy_start - energy_end` in micro-watt-hours divided by
`10^6` yields Wh; divide by actual hours for average watts. Report gauge resolution
and drift, transitions and missing endpoints. Charge alone cannot yield measured
Wh without a separately justified voltage integration. No desktop timer proves
an eight-hour battery-life claim.

## Frame behavior and interactive latency

Fix the physical display, refresh, mode, scaling, brightness, compositor version,
application scene and background build. Use actual presentation timing from an
instrumented client/compositor when supported; preserve frame sequence IDs,
timestamps, clock ID, discard events and trace version. Verify protocol support
and hardware acceleration on the target before selecting the method. An FPS
counter or render/submit duration alone cannot prove displayed frame cadence.

Wayland's [core protocol specification](https://wayland.freedesktop.org/docs/html/apa.html)
documents frame callbacks and output modes. Those interfaces do not measure the
whole physical input-to-display path. State whether a trace measures client
rendering, compositor presentation, scanout or physical display response.

For end-to-end latency, use a repeatable physical keyboard/button trigger with
an observable marker and high-speed camera or calibrated light/trigger sensor.
Record instrument frame/sample rate, exposure, synchronization, onset definition
and analysis error. At 240 camera frames/s, one frame is about 4.2 ms; that
illustrates quantization, not a promised accuracy. Keep raw clips/trigger traces
and annotated event IDs. Disable audio in this measurement workload; never use
speaker playback as a timing trigger. Operators inspect recordings for private
screen content before publication.

Freeze actions (typing response, window switch, terminal scroll, editor motion),
event count, workload load level and late-frame definition before measuring.
Compute latency quantiles and late/discarded-frame fractions per independent
trial, then compare trials; include tails and stalls rather than only average
FPS. If this instrumentation is absent, responsiveness/frame gates remain NOT
RUN regardless of subprocess timing improvement.

## Idle/load power, battery and sustained thermals

Select and name the energy domain: battery discharge, USB input or wall input.
An external calibrated meter requires model, firmware, sample rate, accuracy,
range, placement and raw logging. A USB/wall meter includes charger/conversion
behavior and may include battery charging; it is not directly interchangeable
with battery or component telemetry. Ensure meter resolution resolves the frozen
regression budget. Meter/display/network/software changes are new conditions.

Before idle windows, record a fixed settling interval and confirm the planned
idle apps/state; before load windows, use identical correct work. Integrate power
over actual time to get energy/task; document integration method and gaps. An
instantaneous power snapshot is context, not a runtime or energy comparison.
For battery windows, fix charge band, display and workload, record battery
age/health information that is available, and repeat sessions under comparable
conditions. Do not automatically change charge limits or power services.

For sustained fanless behavior, log a declared continuous workload and defined
steady-state window, not a single short build. Record ambient temperature with an
external thermometer and stable sensor locations; use an external skin probe
for comfort limits if required. Pair throughput history with temperature history
and documented throttling indicators where available. A frequency drop alone
does not identify thermal throttling. Retain protection behavior and operator
abort observations; do not raise thermal thresholds or bypass protection.

## Operator-led suspend drain and recovery

The harness must never initiate suspend. Reserve the physical machine for these
tests and use the accepted hardware plan's fixed lid-close/resume repetitions
(currently 20 cycles, split across battery and external power). Separately freeze
long-window drain counts/durations and initial charge band. Verify the actual
sleep state and timestamps through available target logs and operator evidence;
record unintended wakes. A command merely requesting sleep is not proof it slept.

Read battery energy immediately before sleep and after wake, recording read time
and actual sleep duration. Include endpoint/gauge uncertainty and awake overhead;
use a long enough window to resolve the frozen drain budget. Logging programs do
not continuously sample a suspended system. If energy counters or sufficiently
accurate instrumentation are absent, drain is NOT RUN. Never label missing drain
zero. Percent/hour can be a coarse supplemental observation with its quantization,
but cannot replace a Wh/hour requirement without revising the plan before trials.

After each resume, operators check lock state, applications, hardware rendering,
network/input/audio service status and logs according to the hardware plan.
Speaker protection checks require their dedicated exact-machine procedure;
benchmark scripts do not exercise speakers. After candidate tests, execute and
record removal/rollback and usable boot/session recovery. Sensor readings and a
successful workload exit cannot supply any of these functional PASS results.

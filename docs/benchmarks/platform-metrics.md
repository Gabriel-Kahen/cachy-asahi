# Read-only platform metrics sidecar

`python3 -I -B scripts/benchmarks/platform_metrics.py` collects Linux sysfs
observations without root, subprocesses, package queries or system changes.
It neither launches nor controls a workload. Python 3.12+ and Linux's
`CLOCK_BOOTTIME` are required. This is instrumentation for R2/M7; source controls
and host observations do not accept native ARM, 16K, installed Asahi, physical M2,
battery life, sustained thermals, performance gains or release gates.

## Capture and replay

From an integrated clean checkout, with an existing private parent directory:

```bash
python3 -I -B scripts/benchmarks/test_platform_metrics.py
python3 -I -B scripts/benchmarks/platform_metrics.py capture \
  --machine-label 'development-machine-A; operator inventory identifier' \
  --duration 10 --interval 1 --output /private/measurements/pilot-001 \
  --note 'Read-only pilot; conditions and background load recorded separately.'
python3 -I -B scripts/benchmarks/platform_metrics.py summarize \
  --capture /private/measurements/pilot-001 \
  --output /private/measurements/pilot-001-replay.json
```

Every output must be fresh; the parent must exist. Capture creates a mode-0700
directory and mode-0600 files. `started.json` records intent before sampling;
`inventory.json` records sources/units; `samples.jsonl` retains bounded raw
readings; `capture.json` records completion, source SHA256, architecture, kernel,
page size, device-tree model/compatible when readable, DMI product name when
readable, boot ID and input pins. `summary.json` is derived only after a complete
capture. Interruptions and bounded read failures preserve earlier raw samples
and an incomplete receipt when the filesystem remains writable. Offline replay
refuses incomplete captures or changed inventory/sample hashes. Hashes bind
bytes and detect accidental mutation; they do not authenticate an operator.

Sampling is sequential. Each attribute has monotonic start/end times; each
snapshot additionally has monotonic, boottime and realtime boundaries. JSON
retains the exact bounded driver text, parsed integer or null, status, errno,
identity before/after, and state before/after. No missing reading becomes zero.
Run `capture --help` or `summarize --help` for the full argument contract.

## Identity, states and units

Discovery enumerates actual names under `/sys/class/power_supply`,
`/sys/class/thermal/thermal_zone*` and `/sys/class/hwmon/hwmon*`. It assumes
neither `BAT0` nor a CPU/vendor sensor. Records include resolved directory paths,
supply type/manufacturer/model/technology or chip/zone name, channel labels,
optional sensor type and update interval, and available battery full/design
capacity and cycle-count metadata. Inventory is fixed at start; devices appearing
later are outside this capture. Required name/type must be readable. A resolved
path or identity change invalidates the reading. Matching paths/labels alone
cannot prove that no same-identity physical replacement occurred between reads.

States are explicit: `absent` for missing/removed attributes or devices; `denied`
for permission errors; `unavailable` for other OS read failures, disabled/faulted
channels; `unknown` for unstable/unreadable identity or context; `invalid` for
malformed/out-of-bound values; and `ok` for accepted raw readings. Class/device
inventory retains failed enumeration. hwmon enable/fault and supply presence/
status/online are observed without writes. Signs of current are preserved;
negative unsigned power/energy/capacity is rejected conservatively. Integers are
bounded to signed 64-bit; capacity must be 0..100 and boolean state 0..1.

| Source | Retained unit | Interpretation |
| --- | --- | --- |
| thermal-zone `temp` | `mC` | Zone temperature, without CPU/skin attribution |
| power_supply `temp` | `tenths_C` | Supply temperature, a different scale |
| hwmon `temp*_input` | `unreviewed_hwmon_temp` | Raw channel; unit review required before claiming Celsius |
| hwmon `power*_input`, supply `power_now` | `uW` | Instantaneous source power |
| hwmon `power*_average` | `uW` | Driver-averaged context, not integrated |
| hwmon `energy*_input` | `uJ` | Cumulative energy counter |
| supply `energy_now` | `uWh` | Stored energy, not a cumulative use counter |
| supply `charge_now`, `current_now`, `voltage_now` | `uAh`, `uA`, `uV` | Separate quantities; never synthesized into energy |
| supply `capacity` | `percent` | Coarse gauge context; not power or energy |

[Linux power-supply documentation](https://docs.kernel.org/power/power_supply_class.html)
distinguishes charge, stored energy and percent.
[Linux hwmon documentation](https://docs.kernel.org/hwmon/sysfs-interface.html)
defines optional power/energy channels and warns about channel interpretation and
thermistor/ADC temperature channels exported as millivolts. This collector leaves
hwmon temperature units unreviewed rather than assuming all are millidegrees.
Thermal-zone units follow the
[thermal ABI](https://github.com/torvalds/linux/blob/master/Documentation/ABI/testing/sysfs-class-thermal).
Review the actual target driver and calibrated instrument before using a source
as an acceptance instrument. All energy domains start `unreviewed`: there is no
CPU/package/system inference, summing of overlapping sources or external-meter
claim. Missing channels require separate instrumentation, not a substitute value.

## Offline energy and coverage

For accepted consecutive readings at per-read midpoint times `t0`, `t1`:

- Instantaneous power: trapezoid `(p0+p1)/2 * (t1-t0) / 1e6` joules, with seconds
  and raw microwatts. It is an estimate from sampled power, not a hardware counter.
- Cumulative energy: `(e1-e0)/1e6` joules from microjoules. A decrease is a
  reset/wrap gap; no modulus or synthetic correction is guessed.
- Stored battery energy: `(e0-e1)*0.0036` joules from microwatt-hours. Both
  endpoints must identify a battery and report `Discharging`; increases/reset
  signs are gaps. The gauge may be quantized or recalibrated; this is not
  power integration or a battery-life projection.

Battery `power_now` also requires confirmed discharging endpoints; charging
magnitudes are retained raw and excluded from energy. Supply state transitions
and an explicitly offline supply invalidate energy intervals. Charging and
unobserved transitions are never hidden using an absolute value. Transitions,
resets or wraps that occur entirely between reads can remain undetected.

An invalid/missing endpoint, read/observation interval exceeding the frozen
`min(120,2.5*requested_interval)`-second gap threshold, or a boottime/realtime
versus monotonic discontinuity over 50 ms is a gap. The 50 ms threshold is an
instrument policy, not proof that smaller suspend/time changes did not occur.
Clock reversal, overlapping/out-of-sequence snapshots, reversed/outside read
timestamps, cached value/status inconsistencies, unit mismatches and altered
file pins reject replay. Clock adjustments can therefore require a fresh run.

`accepted_interval_energy_j` is explicitly partial: the sum of accepted adjacent
intervals only, alongside `covered_seconds`, span, coverage fraction and every
gap. `contiguous_observed_span_energy_j` and `observed_span_average_w` are null
unless there are at least two readings, all selected readings are valid and all
internal intervals pass. These fields cover first-to-last observed midpoint,
not the requested duration. `boundary_unobserved_ns` exposes both uncaptured
edges; there is no endpoint extrapolation. No source or fewer than two useful
readings yields no energy, even when the capture command itself completes.
Raw extrema use valid observations only and retain their raw unit.

Replay supports `--start-monotonic-ns N --end-monotonic-ns N` for a window within
the capture. It selects only source midpoints inside that window and does not
interpolate crossing intervals. Use the workload's retained `trial.json`
`monotonic_start_ns` and `monotonic_end_ns` from `benchmark.py` for a same-boot
join after checking exact machine, source/plan/conditions and boot provenance.
Start this bounded sidecar before the controlled trial and reserve sufficient
time for a final sample after it. It remains optional: `benchmark.py`,
`paired_zlib.py`, `process_group_memory.py` and their acceptance logic are
unchanged. A telemetry window alone cannot attribute background power to a task.

## Exact-machine M2 collection procedure — NOT RUN

Reserve the actual supported Asahi machine and retain its hardware baseline,
release/package/platform record, frozen benchmark plan and conditions (including
ambient instrument, power source, charge band, display, background load and
warmup). Pilot logging overhead and sensor update rates before freezing sampling.
Do this separately on the 13-inch `apple,j413` and 15-inch `apple,j415`; neither
identifier implies that any particular power or thermal channel exists.

For example, on the *actual 13-inch machine*, with the three named existing JSON
records and a fresh private output (replace record paths and operator machine
identifier with the retained exact-machine values):

```bash
python3 -I -B scripts/benchmarks/platform_metrics.py capture \
  --machine-label 'M2-Air-13-j413-machine-A; inventory record machine-A' \
  --reference /private/measurements/machine-A-hardware-baseline.json \
  --reference /private/measurements/machine-A-frozen-plan.json \
  --reference /private/measurements/machine-A-conditions.json \
  --note 'Exact-machine pilot; verify recorded device-tree identity and domains before analysis.' \
  --duration 60 --interval 1 --output /private/measurements/machine-A-metrics-001
```

`--reference` pins up to sixteen ordinary existing files (2 MiB each), before
creating the output. Retain those input files separately; the sidecar neither
parses them as acceptance evidence nor copies potentially private records.
Use a separately named 15-inch machine baseline and label for that model.
Inspect availability, identities, bounds, gap coverage and gauge resolution in
these outputs before proposing a longer idle/load protocol. This command does
not assert successful M2 execution or sensor availability. It makes no suspend,
display, charge-limit or power-policy changes. Suspend drain and recovery remain
operator-led tests under the established hardware-validation procedure.

Limits are at most 128 devices/class, 1024 directory entries, 128 sensors,
10000 samples, 512 bytes/attribute, 512 KiB/sample and 128 MiB/raw capture;
duration is 0.1..3600 seconds and interval 0.1..60 seconds. Exceeding a bound
fails visibly. A blocking kernel/sysfs read or stalled filesystem can overrun a
wall-clock budget despite nonblocking opens; this single-process reader cannot
promise a hard deadline. Raw reads are sequential and non-atomic, sensor update
rates/quantization/calibration are driver properties, and logging overhead has
not been measured on M2. Benchmark budgets and release admission require the
separate exact-machine evidence described in `docs/performance.md`.

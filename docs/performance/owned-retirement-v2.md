# Owned-retirement benchmark v2

New source benchmark execution uses `scripts/benchmarks/benchmark_v2.py`.
The original `benchmark.py` is retained for pinned historical consumers and
offline comparisons. Its legacy run branch polled/waited before a numeric
process-group signal; that execution route is retired. Do not use it for new
workloads. The frozen measurement 0.1 private package is unchanged: its launcher
already refuses legacy execution and selects its separately pinned safe platform
mode. This proposal neither repacks that package nor rewrites its profile/pins.

V2 changes the source and timing/instrumentation contract, so prepare a fresh
plan and a fresh complete trial block. Do not edit a historical plan, replace a
pinned file in place, mix v1/v2 trials, or relabel an old block. V2 plans bind the
new execution layer and shared owner; loading a historical plan for execution
through v2 is refused. Historical offline comparison uses the matching retained
original entrypoint and exact original inputs.

New plans use schema version 2 and `record_type="frozen-experiment-plan-v2"`.
The original entrypoint refuses these plans too, so a v2 plan cannot accidentally
select its old legacy executor. The v2 execution binding pins the new runner,
retirement adapter and exact shared owner; moving or changing them requires a
fresh declaration. Original inputs are never rewritten to satisfy those pins.

| New work | Entrypoint |
| --- | --- |
| Freeze ordinary or optional platform benchmark config | `benchmark_v2.py prepare-plan` |
| Execute a declared slot | `benchmark_v2.py run` |
| Compare a complete v2 block | `benchmark_v2.py compare` |
| Stage/prepare/run paired exact-zlib work | `paired_zlib_v2.py stage`, `prepare`, `run` |

Use the existing argv/config/state/conditions schema and the revised [CLI guide](cli.md).
The same root refusal, trusted argv/no-shell contract, exact inputs, single change,
state checks, controls, order and complete-block comparison requirements apply.
Preparation and stage commands do not execute workloads or grant hardware credit.
The unchanged zlib artifact adapter can still prepare its exact config; the new
paired adapter adds and pins its own v2 harness/runner dependencies before freeze.
The retained historical benchmark pin in an original zlib config records the
unchanged artifact adapter's preparation/import dependency, not permission to
execute its retired run branch.

The coordinator retains exclusive wait ownership while using the shared
`owned_process.py`: WNOWAIT reserves the leader through the last possible group
signal, then one raw reap supplies actual status. No logger/sensor thread signals
the child or receives a child PID. ECHILD/lost custody is UNKNOWN, not exit zero;
no later numeric child probe/signal can repair it. Unresolved waits and blocked
samplers block another workload in that process. SIGTERM/cancellation and timeout
produce failed retained evidence. The original group/session scope cannot reach
detached children; trusted workloads must not detach and must wait for their own
children. OS scheduling/stalls and uninterruptible tasks prevent hard real-time
or guaranteed cleanup claims.

Legacy-shaped measurement in v2 uses actual owned in-flight RSS and a separate
PID-free asynchronous sensor sampler. Root RSS remains the actual live leader's
sampled RSS. Original-group RSS remains a per-process sum that can double-count
shared mappings and is an observed maximum, not a true peak. It excludes members
that leave the original group/session. Missing, exited-only, partial or failed
observations never become zero or usable guardrail data. Sensor readings retain
their units, identity and missing-data rules; missing thermal/power data cannot
satisfy a declared guardrail. The comparator replays the raw evidence rather
than accepting a caller-written summary.

The owner bounds combined stdout/stderr to 512KiB. V2 records that combined
observed-order stream in `stdout.txt`, an empty `stderr.txt`, and an explicit log
scope in the receipt. This differs from historical separate unbounded file
logging and is another reason to rebaseline with new plans. Keep all raw files
listed by the trial's hash map, including the ownership/RSS receipt. A tiny trial
may have no usable live RSS observation and remain incomplete/failed. Elapsed
time includes the new owner/sampling/retirement overhead; no gain or overhead
equivalence is claimed.

The new raw file is `owned-retirement.json`. The writer and offline replay enforce
4096 sensor rows, 128KiB per sensor line, 16MiB total sensor bytes, a 16MiB owned
receipt, and ordinary no-symlink files; FIFOs are rejected without blocking.
The shared owner's separate RSS sample/member/time limits still apply. Partial
capture or a blocked writer never becomes usable telemetry. The sampler owns and
eventually closes its log FD even if a bounded join reports it still blocked.

Comparison keeps FAIL, INCOMPLETE and `optimization_acceptance="NOT RUN"`
distinct. A successful preliminary timing comparison is never optimization,
native ARM, M2 hardware, energy, final-system or release acceptance. Physical
work still requires real reviewed baseline/recovery records, supported model
identity, controlled target conditions and the remaining project gates.

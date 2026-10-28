# Benchmark CLI and record boundaries

Current source execution uses the [owned-retirement v2 layer](owned-retirement-v2.md). Historical `benchmark.py` and `paired_zlib.py` files and their frozen plans remain byte-held; their legacy workload execution is retired. Redeclare fresh v2 plans for new runs; do not edit or rebind historical plans. Offline historical comparison remains available.

Use the verified Python 3.12 or 3.14 standard-library runtime. Read the [methodology](README.md)
and inspect the workload before running. The source harness is
[`scripts/benchmarks/benchmark_v2.py`](../../scripts/benchmarks/benchmark_v2.py).
It runs one declared slot per invocation, refuses root execution and creates
fresh output paths. No invocation applies or removes the experiment for you.

## Prepare a frozen plan

Prepare baseline and candidate-state records with the baseline collector, before
candidate measurement. Both are immutable JSON files. Preparation binds their
hashes and pins workload inputs. A declared package/kernel difference requires a
reviewable pinned `state_change_evidence` file. That evidence must demonstrate
one changed variable; permitting the whole packages field in a JSON schema does
not authorize unrelated package updates.

```sh
python3 scripts/benchmarks/benchmark_v2.py prepare-plan \
  --config artifacts/experiment-config.json \
  --baseline artifacts/baselines/reference.json \
  --candidate-state artifacts/baselines/candidate.json \
  --output artifacts/frozen-plan.json
```

These paths are caller-created examples, not existing target measurements. Keep
the frozen plan and both states at their retained paths; loading a plan rechecks
both state hashes, as well as all pinned inputs. Modifications invalidate bindings.
Pins retain the declared access path, resolved target and content hash. Retargeting
a symlink is refused even if its new target has identical bytes. Keep inputs and
aliases stable throughout the run; validation is not a filesystem sandbox against
concurrent writers.

The config has these fields:

| Field | Contract |
| --- | --- |
| `experiment_id`, `machine_id`, `base_id`, `workload_id` | Nonempty stable identifiers for this experiment and exact machine/base/workload |
| `execution_context` | `physical`, `virtual`, `emulated` or `unknown`; nonphysical runs are nonacceptance |
| `change` | Nonempty strings `variable`, `baseline`, `candidate`, `rationale`; reference/candidate values differ |
| `argv` | String array; first item is absolute executable path; no shell interpolation |
| `inputs` | File paths including the executable, workload driver, source/data manifests and other necessary inputs, pinned by SHA-256 |
| `env` | Explicit string-to-string environment overrides; inherited environment is also fingerprinted per trial |
| `variant_env` | Optional object with `baseline` and `candidate` mappings; each changes exactly the sole `change.environment_key` to its declared `change.baseline` or `change.candidate` string |
| `variant_inputs` | Optional mapping from `baseline`/`candidate` to artifact file-path lists; all artifacts are pinned and retained |
| `order` | `baseline`/`candidate` slot array; at least declared trials per variant; no three identical adjacent slots |
| `minimum_trials` | Integer >=5; comparison requires every slot, not just this minimum |
| `timeout_seconds`, `sample_seconds` | Finite numbers, >=0.01 and >=0.02 respectively; choose an appropriate pilot-tested interval |
| `controls` | Exact string fields `power_source`, `display_config`, `brightness`, `cache_mode`, `background_load`, `warmup`; ranges `ambient_C`, `thermal_start_C`, `battery_soc_percent` as `[minimum, maximum]` |
| `thresholds` | `minimum_elapsed_improvement_pct` and `maximum_elapsed_range_pct`; optional `maximum_regression` guardrails below |
| `allowed_state_changes` | Empty, or declared `packages`/`kernel` changes matching actual variant inventory difference; never an unrelated base/machine change |
| `changed_packages` | When a package inventory difference is allowed, list exactly the package names changed between the two recorded inventories |
| `state_change_evidence` | Existing pinned file required when allowed state changes are nonempty |
| `hardware_gate_evidence` | Physical-only required pinned JSON record of independently reviewed baseline-functional and recovery PASS evidence for this machine/base |
| `power_domains` | Optional mapping from each hwmon power path to reviewer-confirmed domain and observed chip/channel/device identity; required for a usable declared power guardrail |

Use absolute input paths for repeatability. A pinned source manifest must identify
retrievable sources/artifacts; hashing a manifest does not inspect its listed
files automatically. Pin all required executable/data files, or a reviewed
immutable artifact containing them. The baseline file records versions but does
not capture installed file contents or configuration changes by itself.

A fixed pinned driver can consume one declared `CFLAGS` value, or one `CC` value
pointing to an immutable compiler per variant. The driver, common argv and inputs
remain identical; pin variant artifact files with `variant_inputs` and retain
both. The driver must interpret flags without a shell and place build products
in the isolated working directory. All environment variables except that sole
declared variant key must match across trials; the comparison fingerprint excludes
only that key. Replacing a pinned compiler file in place still invalidates the
plan.

[`config-example.json`](config-example.json) is a nonacceptance source template
with twelve slots and one `CFLAGS` change. Its `/ABSOLUTE/REPLACE/` paths must be
replaced with inspected pinned inputs. Its numerical thresholds and condition
ranges are illustrations, not calibrated M2 budgets or observations. It cannot
be frozen unchanged because its placeholder files do not exist. No fabricated
physical gate record is supplied.

Physical plans also require the exact M2 record and package inventory. The
`hardware_gate_evidence` JSON must contain matching `machine_id` and `base_id`,
`baseline_functional` and `recovery` both equal to `PASS`, and nonempty `evidence`
and `reviewer`. Populate these from executed checks with linked raw records;
never manufacture PASS values to permit a run. The harness checks the declaration
and pins its file, but cannot verify its real-world truth. An operator declaring
`physical` does not attest execution by itself.

## Record conditions and execute the declared order

Each conditions JSON repeats the six control strings exactly and supplies numeric
`ambient_C`, `thermal_start_C`, `battery_soc_percent` inside their ranges, plus
nonempty `operator` and `notes`. Notes link actual instrument/start/cache/warmup
evidence. Values are operator-supplied; the CLI does not measure ambient
temperature, brightness or battery charge for the control checks.

For slot 0, whose variant is determined by the frozen `order` array:

```sh
python3 scripts/benchmarks/benchmark_v2.py run \
  --plan artifacts/frozen-plan.json --slot 0 \
  --state artifacts/baselines/reference.json \
  --conditions artifacts/conditions-slot-00.json \
  --cwd /absolute/path/to/isolated-workload-directory \
  --output artifacts/trial-00
```

Restore/apply the correct reviewed variant outside the harness before each slot.
The runner compares the live architecture/kernel/package/repository identity to
the frozen variant and verifies the supplied state-file hash. It also verifies
pinned inputs, so replacing a pinned executable in place invalidates the plan;
use a reviewed driver and variant arrangement compatible with the chosen
one-variable experiment. Prepare controls, warmups, settling and working-tree
reset outside the measurement interval according to the frozen plan.

Use a fresh output directory for every slot and keep its `started.json`,
`trial.json`, `stdout.txt`, `stderr.txt`, and `telemetry.jsonl`. Check workload
correctness separately: exit code zero is not sufficient for a correct native
build or rendered scene. Raw filenames and units remain explicit. `root_rss_kib`
is sampled root-process RSS, not process-tree peak. `rss_coverage` counts live
samples, missing live samples, excluded exited samples and unknown lifecycle
samples. All observed live RSS samples must be available and there must be at
least one; unknown lifecycle makes the metric unavailable. Exited samples are
excluded explicitly. Tiny workloads may finish without a live RSS sample.
Elapsed timing includes asynchronous sampling and bounded cleanup overhead.
Timeouts/failures return a failing result and retain
evidence; comparison refuses them. Preserve the failed block and declare a new
complete block instead of cherry-picking successful replacements into it.
The v2 sensor sampler receives no child PID and has no signaling responsibility.
Original-group RSS comes from the shared owner's bounded in-flight observations,
with the actual live leader's RSS kept separate from the group sum. The main
thread owns the workload through the last possible signal and raw reap. Sensor
errors, unavailable/incomplete RSS, unresolved waits and failed cleanup remain
invalid evidence. A blocked sampler or unresolved wait prevents another workload
in the same Python process. See the [v2 evidence/cleanup contract](owned-retirement-v2.md)
for the changed raw receipt, output and timing scope. Inspect retained evidence
before proceeding after a failure.

SIGTERM records interruption and attempts cleanup of the original process group.
Detached/`setsid` descendants are unsupported; workloads must wait for all
children and never detach. SIGKILL, OS scheduling/stalls and uninterruptible
tasks prevent guaranteed cleanup or a hard real-time deadline. An unreaped root
process remains an explicit invalid result rather than a successful trial.

## Compare and review

Pass all trial directories from the frozen order explicitly:

```sh
python3 scripts/benchmarks/benchmark_v2.py compare \
  --plan artifacts/frozen-plan.json \
  --runs artifacts/trial-00 artifacts/trial-01 artifacts/trial-02 \
         artifacts/trial-03 artifacts/trial-04 artifacts/trial-05 \
         artifacts/trial-06 artifacts/trial-07 artifacts/trial-08 \
         artifacts/trial-09 artifacts/trial-10 artifacts/trial-11 \
  --output artifacts/preliminary-comparison.json
```

The example assumes twelve declared slots; change the list to match the frozen
plan. The comparator checks plan/state/workload identity, raw output hashes,
control values, successful exits, raw/summary telemetry consistency, complete
unique slots, and matching hostname/comparable environment. It also verifies
monotonic start/end and sample ordering, elapsed-boundary consistency and
chronological nonoverlap, and refuses reversed UTC trial timestamps.
Trial start UTC must also be at or after plan `frozen_at`; apparent clock
inconsistency requires a corrected clock and new plan, not editing old evidence.
This chronology check does not cryptographically prove predeclaration.
It summarizes median/min/max/MAD/range, useful elapsed improvement and declared
guardrails. Rejected comparisons exit nonzero; required missing guardrail
telemetry is INCOMPLETE. A threshold breach is FAIL. Successful CLI exit means
`MEETS_TIMING_RULE_ONLY`, with `optimization_acceptance` always `NOT RUN`.

Optional guardrails are `root_rss_kib_pct` (increase in median sampled root RSS),
`thermal_raw_mC` (increase in median per-trial sampled maximum for every thermal
path) and `power_raw_uW_pct` (increase in median per-trial sampled median for
every hwmon power path). The latter is not integrated workload energy, idle
power, wall power or battery lifetime. Partial/missing readings invalidate a
required guardrail. A power guardrail additionally requires `power_domains[path]`
with nonempty `domain`, `reviewer`, `evidence` strings and `chip_name`,
`channel_label`, `device` matching the observed identity. Record unavailable
identity fields explicitly as JSON `null`. The channel label is distinct from
the chip name; missing labels do not identify a physical domain. An absent or
mismatching domain review is INCOMPLETE, regardless of numeric agreement. Add
referenced evidence files to `inputs` if their contents must be hash-bound; an
`evidence` string alone does not pin an external file. No absent guardrail means
its corresponding hardware gate passed. Review sensor labels/domains and external instruments using the
[instrumentation plan](instrumentation.md).

Hashes guard against accidental drift; JSON is not a signed attestation and an
operator can edit records. Independent review checks actual controls, candidate
delta, correctness, hardware and recovery evidence. The CLI cannot enforce the
full experimental protocol or grant a supported release/performance claim.

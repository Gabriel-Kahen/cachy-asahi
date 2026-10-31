# Measure the retained zlib compiler variants on M2

Current source execution uses the [owned-retirement v2 layer](owned-retirement-v2.md). Historical `benchmark.py` and `paired_zlib.py` files and their frozen plans remain byte-held; their legacy workload execution is retired. Redeclare fresh v2 plans for new runs; do not edit or rebind historical plans. Offline historical comparison remains available.

This entry supplies the missing workload for the existing [benchmark CLI](cli.md). It does not replace that harness, collect a physical baseline, manufacture hardware-gate records or grant optimization acceptance. No M2 measurement or host benchmark has been performed for this preparation.

Use a separate plan/session for each compiler experiment and for each 13-inch or 15-inch M2 Air. The artifact-only comparison changes `ZLIB_MINIGZIP` between two immutable executables; installed packages, kernel and platform state must remain identical. The driver performs fixed level-6 compression/decompression roundtrips on repeated, pinned **held-out README bytes**, verifies gzip/payload correctness, and writes only in the fresh workload directory. C03's original repeated-text training corpus is not used for timing.

Elapsed time includes Python startup, artifact/input validation, payload preparation, subprocess startup, filesystem I/O and correctness checks as well as compression/decompression. This is an end-to-end roundtrip workload, not isolated zlib kernel throughput. Artifact sizes and hosted CI build times do not establish gains. The existing harness still records preliminary timing only; responsiveness, memory, energy/battery, sustained thermals, suspend and recovery need their own required evidence.

## Exact retained artifact choices

Use the existing native export archive and its original `archive-manifest.json`, without editing either. Transfer these already-retained files through the project's ordinary reviewed file transfer; no network fetch or build is part of this adapter. Verify the known archive SHA256 before extracting it into a new directory. The adapter also pins the exact original manifest bytes and verifies the two selected executable hashes and held-out data.

| Experiment | Native run / exact product | Candidate prefix | Output archive SHA256 |
| --- | --- | --- | --- |
| ARM-C01 | 38772803597 / `288f19f4459ea0aa7c8bfac217c3cc649933f999` | `lto-1` | `9195b3feaed061012600fac707a61f5b0f4c769894240a2c5742de99e784e573` |
| ARM-C02 | 38775950466 / `98a7fea506bda1e69abb0fa7c8a9b23cbcb6c3a8` | `o3-1` | `018d87e9037611b5fe85c4476aaab9a21dd29beacfad784c3fa0f36d7d3b4e54` |
| ARM-C03 | 38783836486 / `8e6d0c46b5f6ca0789e2b3da45b456599f832b7b` | `pgo-1` | `80a6d4d420260f308780f2867b36665255c0685360d656f1b9ccd41fb4f2f3b2` |
| ARM-C04 | 38784996204 / `330deff795cd53373c45e6677fb9dd3fd74658ad` | `m2-1` | `b78cdadff4d63fb9bf69a1a33c3c4ff0a342756cc80385b790e851fe2b53182c` |

Every pair uses its own `baseline-1/minigzip`. The selected candidate is the prefix above plus `/minigzip`. C03 selects the exact executable built from its retained **hosted** profiles; this does not establish an approved M2 distribution profile or a maintained profile-update procedure. Combining optimization variants is a separate experiment.

The exports statically include local libz, but still depend on their recorded dynamic libc/loader closure. Confirm compatibility and actual 16 KiB execution on the exact target before accepting a comparison. Missing loader/symbol support or a failed roundtrip is a failure; the adapter neither substitutes another binary nor silently rebuilds it. Preserve the Asahi kernel, firmware, graphics, audio and speaker protection. No installation, root command, service/sysctl change or host-cache drop belongs to this entry.

## Prepare the actual machine records and config

First follow [the methodology](README.md), [instrumentation plan](instrumentation.md) and the existing baseline/recovery process. Capture actual baseline and candidate-state records on the same target, and retain reviewed functional/recovery evidence. An operator declaration alone is not attestation. Use actual ambient/thermal/battery observations, fixed display/power/cache/background conditions and pilot-reviewed workload size, warmups, timing/sample limits and usefulness/variation budgets. None can be inferred from the hosted results.

Copy [zlib-operator-template.json](zlib-operator-template.json) to the target evidence directory and fill every `null` from those real records and reviewed choices. The twelve-slot counterbalanced order has six measured slots per variant. It can be changed only before freezing while satisfying the existing harness's repetition/order checks. Do not fill hardware evidence with invented PASS values to enable execution. The unchanged harness checks the actual M2 model identity, package/state bindings and reviewed gate file when freezing, then live state again at run time.

The following commands are to run on the prepared target after source adoption, from the project checkout. Set `TASK_ARTIFACTS` to the new extraction directory, `TASK_MANIFEST` to its original native export manifest, and `TASK_EVIDENCE` to the target's reviewed session directory. The named operator/state/conditions files are machine evidence the physical operator supplies, not generated placeholders:

```bash
python3 -B scripts/benchmarks/zlib_workload.py prepare-config \
  --experiment ARM-C04 --artifact-root "$TASK_ARTIFACTS" \
  --archive-manifest "$TASK_MANIFEST" \
  --operator-config "$TASK_EVIDENCE/operator.json" \
  --payload-bytes 33554432 --iterations 8 \
  --output "$TASK_EVIDENCE/config.json"

python3 -B scripts/benchmarks/benchmark_v2.py prepare-plan \
  --config "$TASK_EVIDENCE/config.json" \
  --baseline "$TASK_EVIDENCE/reference.json" \
  --candidate-state "$TASK_EVIDENCE/candidate.json" \
  --output "$TASK_EVIDENCE/frozen-plan.json"
```

Config preparation only validates inputs and writes an ordinary harness config. It executes no artifact, benchmark or baseline collector. It pins the interpreter, adapter, imported harness, original export/corpus manifests, held-out bytes and both variant executables. The generated config admits no package/kernel state change. The default workload is 32 MiB repeated held-out bytes and eight iterations; this is an explicit workload definition, not a calibrated usefulness threshold. Bounds are 64 MiB and 32 iterations, with 60 seconds per child command; the existing harness's frozen overall deadline controls the trial.

## Execute and compare through the existing harness

Prepare a fresh empty workload directory outside the harness output directory, settle to the declared controls, and follow the frozen order. Warmups and cache/thermal preparation are operator steps outside measured slots. Do not execute the workload on an unrelated development host to manufacture M2 evidence.

```bash
mkdir -m 700 "$TASK_EVIDENCE/work-00"
python3 -B scripts/benchmarks/benchmark_v2.py run \
  --plan "$TASK_EVIDENCE/frozen-plan.json" --slot 0 \
  --state "$TASK_EVIDENCE/reference.json" \
  --conditions "$TASK_EVIDENCE/conditions-00.json" \
  --cwd "$TASK_EVIDENCE/work-00" --output "$TASK_EVIDENCE/trial-00"
```

Repeat with the actual state file, conditions, fresh cwd/output and slot number in the exact declared order. The harness selects the binary through its sole variant environment key; do not edit the plan or replace files between slots. The driver waits for its children and keeps them in the harness process group, so the existing timeout/interrupt cleanup can reach them. Failures, mismatched bytes, timeouts or missing observations invalidate a trial; retain the evidence rather than choosing favorable replacements.

```bash
python3 -B scripts/benchmarks/benchmark_v2.py compare \
  --plan "$TASK_EVIDENCE/frozen-plan.json" \
  --runs "$TASK_EVIDENCE/trial-00" "$TASK_EVIDENCE/trial-01" \
         "$TASK_EVIDENCE/trial-02" "$TASK_EVIDENCE/trial-03" \
         "$TASK_EVIDENCE/trial-04" "$TASK_EVIDENCE/trial-05" \
         "$TASK_EVIDENCE/trial-06" "$TASK_EVIDENCE/trial-07" \
         "$TASK_EVIDENCE/trial-08" "$TASK_EVIDENCE/trial-09" \
         "$TASK_EVIDENCE/trial-10" "$TASK_EVIDENCE/trial-11" \
  --output "$TASK_EVIDENCE/preliminary-comparison.json"
```

The driver retains its payload and child stderr in the workload cwd and prints per-iteration correctness hashes to the harness stdout record. Verified encoded/decoded scratch files are removed between iterations; failures retain available partial files. Retain these records and the harness raw evidence. Review preliminary statistics against the frozen budgets and the broader physical evidence; a reported elapsed difference cannot alone earn performance acceptance. Repeat independently on each advertised Air size. The software entry is prepared; actual target availability, baseline/recovery records, compatible 16 KiB userspace, conditions, instruments and measurements remain the machine boundary.

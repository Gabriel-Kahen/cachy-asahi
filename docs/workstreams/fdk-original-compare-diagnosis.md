# FDK trial 38248011223: original-comparison boundary diagnosis

The actual failure remains **unresolved**. The public code
`producer-after-original-compare-failed` identifies a retained diagnostic
`{phase: original-compare, outcome: pass}` followed by producer rejection. It
is not evidence that the comparator returned nonzero. Five bounded source
fixtures reproduce the distinction; none recovers the private trial cause.

This is a read-only diagnosis of the 2026-10-12 trial, after reading the
[roadmap](../roadmap.md) and [development inventory](../../manifests/packages.toml).
No source fixes, source locks, Git operations, dispatch, FDK archive changes,
Docker commands, compilation, installation or hardware tests were performed.
The roadmap's complete-port and exact-M2 acceptance requirements remain open.

## Actual public evidence

The seven regular files in the retained public bundle were independently
compared with their decoded copies. All four producer manifest entries match
their actual file hashes. The bundle SHA256 is
`0a10aef3d6aa30bb647033e9ab304963faa472cb815a859df2ea33b0da7b15be`.
The independent receipt is
`/tmp/fdk-original-compare-diagnosis/public-review.json`.

| Public observation | What it establishes |
| --- | --- |
| Source commit `85e4af5df4f3ff3b10568087c0e4e99e9523ebeb`; packet `309fcd6fbec8b7e96c83ea049804ae3134e7190d2145e81afc66d28563097f44` | The published failure is tied to this source trial. |
| Acquisition: 501 PASS, zero FAIL or PENDING | Recorded transport and pinned-byte acquisition completed. This is not a public signature-verification receipt. |
| Input and recipe hashes `3c16c37d1b12cc84a88572e82ab8ad59e7f3b5ed0d08f09ddf72a69f4711d650` and `20d846cdf289bfc233b0051bf33b677fd6e94e9f05d91a33595a2829a196fa63` | The published source input and original-recipe sets are unchanged. |
| Job status FAIL, `cancelled=false`, `owned_image_absence=true` | The final outer job reports failure and owned-image absence. It does not expose the producer worker's container cleanup result. |
| Producer summary: `producer-evidence-incomplete-or-invalid`, native build NOT ACCEPTED | Acceptance was not established; the summary cannot identify which private gate failed. |
| FDK status NOT RUN / NOT ACCEPTED; child fallback phase preflight | No FDK native compilation or acceptance is established. |
| No signatures, original comparison reports, worker receipt or private build files in the bundle | Those private facts cannot be independently revalidated from these seven files. |

`acquisition.signature_authentication=NOT RUN` is the acquisition schema's
fixed value: `native_arm.audit()` performs signatures afterward without
updating that receipt. Neither this field nor the omitted public signatures
file proves that private authentication failed. The exporter includes
signatures only after producer validation succeeds.

Actual records are under `artifacts/ci/38248011223/decoded/public/`;
`root-public-verification.json` and
[the trial review](../reviews/native-fdk-execution-38248011223.md) retain the
coordinator's independently checked failure evidence.

## Held-source interpretation

The six inspected files match their exact rows in the held 128-file packet:

| Source | SHA256 |
| --- | --- |
| `producer.py` | `e01ea63606b044e71cfb159d156c3a92fb6f31004f23923557bee8fa745b65a1` |
| `job.py` | `1b6c95b1cf8c428671fa2c4636def9e41a494bc600b4a24f7d9de455dee64ef4` |
| `native_arm.py` | `a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898` |
| `compare.py` | `d75d9177cb741d7ae8e13466aa4b9e96587470b88749735ef2923f9a4446748d` |
| Job `evidence.py` | `03f803aede7367c22199468961a0463b2fe688f637271fd2760692967796a75c` |
| `base_broker.py` | `64c6fefc67c92e945d90e7b32794f0f798dd5239c17750760b12adbf5c9c877a` |

Full paths, byte lengths and modes are in
`/tmp/fdk-original-compare-diagnosis/source-bindings.json`.

The control-flow distinction is concrete:

- `ProducerCommands.run()` records `command-failed` for a nonzero returned
  comparator result and `pass` for zero. An exception while the operation is
  still started records `delegate-refused`.
- `producer_failure_code()` maps the last diagnostic's **pass** outcome to
  `producer-after-<phase>-failed`. The diagnostic survives later worker
  finalization, cleanup and outer acceptance failures.
- `producer.execute()` can change worker status to FAIL during cleanup without
  changing the earlier comparison diagnostic. `job.execute()` also checks
  worker exit/status/cancellation/cleanup and producer receipts after the
  command diagnostic was recorded.

Relevant held-source locations are `producer.py:169`, `producer.py:272`,
`producer.py:326`, `job.py:178`, `job.py:184`, and `evidence.py:95` under
`scripts/port/fdk-native-job/`. The original comparator's CLI return handling
is `scripts/build/compare.py:90`.

The last retained diagnostic does not contain a recipe identity or completed
comparison count. It cannot establish which of the four original pairs was
last compared or that all four pairs passed.

## Reproduced source counterexamples

Replay:

```sh
python -B /tmp/fdk-original-compare-diagnosis/replay.py
```

The replay checks the held source pins, exercises actual producer diagnostic
and finalization code, and replaces native production and the broker with
bounded fixtures. The failing-comparator case runs the actual comparator CLI
against deliberately absent temporary receipts. Successful-comparison cases
substitute its comparison result; they are not real archive/build passes.
No external command runs. All writes remain under the diagnosis directory.

| Fixture | Retained outcome | Finite classification |
| --- | --- | --- |
| Actual comparator CLI rejects absent temporary evidence | `command-failed` | `producer-original-compare-command-failed` |
| Synthetic successful comparison, worker cleanup returns FAIL | `pass` | `producer-after-original-compare-failed` |
| Synthetic successful comparison, worker cleanup raises | `pass` | `producer-after-original-compare-failed` |
| Synthetic successful comparison, native delegate later returns failure | `pass` | `producer-after-original-compare-failed` |
| Worker returns PASS after synthetic successful comparison; outer receipt validation rejects absent receipts | `pass` | `producer-after-original-compare-failed` |

All five cases passed their expected assertions. Results are retained in
`/tmp/fdk-original-compare-diagnosis/counterexamples.json`. These demonstrate
aliasing, not which path occurred in run 38248011223.

Two additional source-only diagnostic gaps were confirmed:

1. Evidence accepts a `complete/pass` diagnostic, but producer `PHASES` omits
   `complete`; its setter rejects that label with `producer-diagnostic`.
   There is no durable completion boundary replacing the last compare alias.
   This gap does not itself prove an execution failure.
2. `job.execute()` assigns `state['image']` only after the worker acceptance
   gate. If that gate fails, publication receives an empty image and
   `validate_producer()` refuses with `producer-identity` before reading
   producer receipts. Thus the generic summary may describe the missing
   accepted image binding rather than a defect in private comparison data.
   This does not establish the trial's actual missing/private state.

The predicate proofs are in
`/tmp/fdk-original-compare-diagnosis/boundary-gaps.json`.

## Proposed next finite observability

Do not loosen native acceptance or export raw logs, error strings, command
paths, GPG diagnostics, caches, source archives or package binaries. Before
another reviewed trial, retain one small typed boundary receipt with:

- Last original recipe enum, command kind, returned-zero flag and completed
  comparison count bounded to 0–4.
- Native delegate completion enum, followed by worker finalization and
  worker-cleanup status/absence/cancellation booleans.
- Outer rejection gate enum: worker exit, worker status, worker cancellation,
  worker cleanup, producer receipts, or original-result retention; an
  allowlisted predicate/error-type code only.

Preserve these fields through final cleanup and whitelist them in the public
failure exporter. A separately authenticated immutable image identifier may
support **recorded candidate** receipt diagnosis after worker failure; it
must not bypass worker cleanup or promote native acceptance. The authoritative
job status must continue to invalidate cancelled or unfinished candidates.

This is an observability proposal only. No implementation, source rebind or
new native trial is included in this diagnosis. Private comparison output,
worker cleanup state and the actual failure cause remain unavailable.

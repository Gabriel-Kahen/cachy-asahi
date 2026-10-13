# Bounded producer cleanup diagnostic

The source candidate adds a separate finite `cleanup_diagnostic` to the private `producer-worker.json` receipt. It preserves the acquisition/driver diagnostic and the existing producer boundary. Cleanup still calls `broker.cleanup(remove_image=False)` once at the same point; its return, exception, cancellation, PASS, privilege, source and timeout rules remain unchanged. Root must register the source and any public projection separately before adoption.

## Why this observation is needed

Actual FDK9 failed acquisition on four pinned HTTP 404 rows before signature authentication, bootstrap or FDK execution. It reported producer worker cleanup FAIL/absence false while Root separately verified owned-image absence. The detailed worker cleanup reason was not exported, so its actual cause remains UNKNOWN. FDK8 retains its earlier FAIL and UNKNOWN inner function/compiler cause.

Source inspection identifies a possible pre-bootstrap path: `BaseBroker.initialize()` creates the image journal, while the container journal is first created by `_set_image()` after bootstrap. `BaseBroker.cleanup(remove_image=False)` delegates to accepted container cleanup, which constructs its cleanup runner and reads that container journal. A missing journal can yield a caught OS error and returned cleanup FAIL before container discovery. This is a source-audited candidate path, not a retrospective attribution of FDK9's cleanup failure.

## Private observation

The new field has exactly these keys:

| Field | Meaning and finite values |
| --- | --- |
| `schema_version` / `scope` | `1` / `producer-containers` |
| `phase` | Driver phase captured at cleanup entry; existing `PHASES` or `UNOBSERVED` on observation failure |
| `call` | Last observed `not-run`, `started`, `returned`, `raised`, or `UNOBSERVED` |
| `journal` | Pre-cleanup leaf `lstat` metadata: `ABSENT`, `REGULAR`, `OTHER`, `UNOBSERVED` |
| `reason` | First exact allowlisted reported cleanup error, finite exception class, `none`, `returned-failure`, `malformed-result`, or `unknown-error` |
| `boundary_error` | Finite error class/code if existing boundary observation/write fails after cleanup returned; otherwise `none` |
| `observation_error` | Finite error class/code for diagnostic preparation/projection failure; otherwise `none` |
| `status` | Strict returned `PASS` / `FAIL`, or `UNOBSERVED` |
| `absence_verified` / `cancelled` | Strict returned boolean, or `UNOBSERVED`; integers are not coerced |

Only exact returned error labels in the existing `BASE_PROBE_POLICY_CODES` plus `docker-cleanup-cancellation-uncertain` survive as reasons. Unknown returned text stays `unknown-error`; OS errno, filenames, messages, reprs and paths are not parsed or copied. Raised errors use the existing finite exception classifier. The guarded classifier only retains existing `BASE_PROBE_REFUSALS`; classifier faults or unexpected values become `unknown-error`. Existing raw private cleanup data is unchanged; this new projection does not reproduce it.

The journal observation uses the fixed run-owned `base-image-containers.json` leaf. It does not follow a leaf symlink, decode content, create a journal, change permissions, enumerate Docker state or invoke a process. `REGULAR` does not prove a valid bound journal. `ABSENT` does not prove that no container was created, that no process launched, or that cleanup verified container absence. The existing broker-returned absence and parent acceptance predicates remain authoritative.

Preparation and projection are best effort. Their faults record `observation_error` and cannot bypass the original cleanup call, change its return/raise predicates or invent absence. A cleanup return remains distinct from a later boundary/write error. The phase is captured before cleanup; the acquisition error is not replaced with a cleanup phase.

There are no new receipt writes or checkpoints. `started` is assigned in memory before the original cleanup call, with observations persisted through existing writes. An abrupt kill can leave an older durable `not-run` snapshot; it is a last-observed state, not proof that cleanup was never attempted. No process-launch/reap, PID, container identity or scheduler claims are added. Tests distinguish zero-launch fixtures and explicit mock launch/reap sequences without promoting those model events into production observations.

## Proposed public projection for Root

Root owns `job.py`, the public evidence schema, workflow and maps. This candidate changes none of them. A proposed optional public field is:

```json
"producer_cleanup": {
  "availability": "OBSERVED",
  "observation": {
    "schema_version": 1,
    "scope": "producer-containers",
    "phase": "acquisition",
    "call": "returned",
    "journal": "ABSENT",
    "reason": "unknown-error",
    "boundary_error": "none",
    "observation_error": "none",
    "status": "FAIL",
    "absence_verified": false,
    "cancelled": false
  }
}
```

This is synthetic example data, not FDK9 evidence. Missing, invalid or unretained private observations should project as `{"availability":"UNOBSERVED","observation":null}`. Root should independently validate the exact eleven-key observation schema, exact string enums and strict boolean types after its bounded regular-file read. Reject extra fields and raw reported cleanup data. Treat every call/journal value as a last-observed snapshot; a durable default cannot become an absence/no-launch/no-attempt proof. The new field must never satisfy existing cleanup, complete-worker, native or publication admission predicates. Register any new public field and its source/consumer pins in a separate Root-owned successor; the current public schema still ignores this private observation.

## Validation and registration boundary

The baseline capture holds all 133 source files plus packet/workflow bytes before editing, and preserves actual FDK9's 189 indexed observations and FDK8's eight public rows. Only `scripts/port/fdk-native-job/producer.py` and `test_producer.py` change. Original four recipes, 71 input pins and 159 initial source byte/mode records are retained. Stage44, template24, reviewed25, recipe23 and the workflow are unchanged.

The first candidate passes 52 inert tests: all 40 original test method ASTs unchanged and 12 new cases. Independent source review then identifies a diagnostic-prelude failure that could skip cleanup, plus an incomplete malformed-result classification for `cancelled`. Those findings and the first candidate's green result and proposed packet are retained. The corrected candidate guards observation failures, strictly classifies missing/nonboolean cancellation and adds three fault-injection cases. The final replay passes all 55 tests with zero errors, failures or skips, and the independent source recheck passes. Original test bodies and failed counters are not weakened.

The replay uses a project-owned TMPDIR, no PYC, strict ResourceWarning handling and process/socket/prctl tripwires. The two existing self-SIGTERM tests use direct inert installed-handler delivery. This is source/fixture evidence, not actual signal scheduling, Docker cleanup, GPG, native build, cache recovery, installation, hardware or performance proof.

The primary job packet remains unchanged at `42fd54ae73c57e47898ca9e7b293ca0dae1d4e57ac2836292f0cdf42b79dffcf` and is stale for the two candidate rows. Proposed replacement metadata lives only under `artifacts/reviews/fdk-producer-cleanup-diagnostic-20261013/`; Root must review and rebind it, then separately prove committed Git bytes and any actual native execution. This diagnostic does not resolve the four HTTP 404s or grant cleanup acceptance. R1–R5 and M5–M9 remain mandatory, including the complete input/build lifecycle and exact-target release evidence.

The final source pins are producer `0f747baaaa3e4ca0b5e5efa370f97dae9313136bc8594c964a989c634b89b613` (26,562 bytes) and test `e5aa52e7855d6745fdaca57d4ac1df13ce1f3da04018e386667144f0fca4e697` (57,626 bytes), both mode 0644. The proposed packet is `c528ce3e0c3e5e30d4ad54ba48f668423cb8ee2538a0c65acc5f8e32bbb71351`, still 133 rows, totaling 2,313,886 source bytes. Exactly two rows change and 131 retain their original bytes and modes; no manifest source row is added.

The final source pins, proposed two-row manifest delta, causal controls, peer findings/recheck and all owned evidence are indexed by `artifacts/reviews/fdk-producer-cleanup-diagnostic-20261013/receipt.json`.

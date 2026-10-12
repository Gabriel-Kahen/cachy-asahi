# Independent FDK native probe diagnostic review

The held 110-test diagnostic enhancement has **no concrete implementation blocker** in this bounded source and fixture review. It adds a closed probe identity and refusal category, with durable before/after records and a public fixed-code projection. It does not identify or fix the hosted failure. Coordinator packet rebinding and a separately reviewed publisher consumer remain required before another diagnostic trial.

Read the current roadmap, package inventory and [producer failure audit](../workstreams/fdk-producer-failure-audit.md). Actual run [38230760444](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38230760444), source `ee9797812cb454e413b5900d8262f1015fe863f1`, remains **FAIL** with `producer-base-probe-runner-failed`, all 501 acquisitions PASS, FDK NOT RUN, cancellation false and verified owned-image absence. Independently re-read those retained public receipt fields and acquisition count. The old diagnostic establishes a raised delegated base-probe call; it does not establish which call, predicate, timeout or GPG condition failed. This review does not repeat decoding or reauthenticate that trial's entire bundle.

## Held source

All five current source/test hashes match the author's checkpoint:

| File under `scripts/port/fdk-native-job/` | SHA256 |
| --- | --- |
| `producer.py` | `e01ea63606b044e71cfb159d156c3a92fb6f31004f23923557bee8fa745b65a1` |
| `evidence.py` | `03f803aede7367c22199468961a0463b2fe688f637271fd2760692967796a75c` |
| `test_producer.py` | `b546eb3bb040923a0c18f7feec5f6c020f22d371cbe9d94bec96001ed0f5dcaa` |
| `test_job.py` | `d4f7af33449048427d4fe2801910459dcdf746926ece7812dcba18d7c9ecb640` |
| `test_evidence.py` | `00a99d62faaca4541485b2e2cafa768c0afb4cbeefb2d71e609d932aad77bd3a` |

Read-only comparison against the actual trial commit shows production changes only in `producer.py` diagnostic handling and `evidence.py` sanitizer/code derivation. The rest of their production behavior is unchanged. `job.py` remains `1b6c95b1cf8c428671fa2c4636def9e41a494bc600b4a24f7d9de455dee64ef4`; `base_broker.py` remains `64c6fefc67c92e945d90e7b32794f0f798dd5239c17750760b12adbf5c9c877a`; `job_runtime.py` remains `99077fde24d060a3b73649f0d45803ec2d155ebc41e21d0de54be635c24cf631`; original `native_arm.py` remains `a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898`.

The accepted packet `76e475f63332c66de123481b77c904254c8f0c988bdf73b0787c732d3ae70449` still contains 128 entries. Independently compared their complete bytes, size and mode against the workspace: exactly the five entries above differ; the other 123, including the accepted adapter and original helper inputs, match. The accepted adapter map remains `a7048064c0c20abd246a466035313abaf65590f3ed10d0f7927b21a346200ad6`. A stale packet cannot authorize the changed executable sources.

## Mapping and durability

Exact Docker info/version/context arguments map to three fixed identities. Image inspection and the constrained read-only inventory command map only when their argument list uses the broker's current image. Changed arguments, unknown images and unknown tools become `unclassified`; no argument list is retained in the diagnostic. The ordinary broker retains independent immutable-image, command and deployment checks.

`base-probe` diagnostics contain exactly `phase`, `outcome`, `call` and `refusal_code`. Historical diagnostics and other phases retain exactly `phase` and `outcome`. Successful, started and not-run detailed states require `refusal_code: none`. Exact string policy arguments select one of 108 fixed labels; a separate/private second exception argument is discarded. Appended text, newline variants and nonstring arguments select the fixed exception category. Cancellation takes precedence, Unicode errors precede ValueError matching, and other exceptions select one of the eight fixed categories. No exception is stringified for this projection.

Delegated exceptions record `runner-failed`; policy/decode failures outside the delegated call record `delegate-refused`; nonzero command returns record `command-failed`; cancellation records `cancelled` and remains a failure. An inventory nonzero exit additionally raises the existing producer predicate, yielding `command-failed/value-error`; the detailed public code selects that fixed refusal category. These labels identify the observed wrapper boundary/category, without proving a more specific external cause.

The callback persists the copied marker through the unchanged atomic receipt writer: temporary file, flush/fsync, replacement and parent-directory fsync. It completes before the delegate begins. The parent recovers only a sanitized durable marker after an outer worker failure, then performs the unchanged owned cleanup and public finalization. Cancellation, failed cleanup and incomplete producer acceptance continue to block FDK and public PASS.

Public status still has exactly 14 fields. No diagnostic, raw error, command, path, image hash, response, environment or credential field is added. The existing 70 phase/outcome codes plus 732 detail codes produce exactly 802 fixed codes. Unknown keys/types/values or detail fields attached to another phase fall back to `fdk-native-job-failed`. Accepted jobs keep a null error code; unrelated FDK/source failures retain the generic code. Producer/GPG verification, raw import-byte logging, original result preservation, full signature/package validation, cleanup and installation/hardware/binary-publication NOT RUN labels are unchanged.

## Independent checks

- Full wrapper suite: **110 tests PASS, zero skips**, 16.796 seconds, using `python3 -B -m unittest discover -s scripts/port/fdk-native-job -p 'test_*.py'`. Owned temporary Unix socket/fake CLI fixtures required scoped sandbox escalation. No actual Docker daemon, native compiler, network, installation or default trust was used.
- Independently executed the retained exact-call control through actual `ProducerCommands` and unchanged `native.run`: four initial forms including local lscpu, plus image inspection and the post-bootstrap inventory form, all PASS; one fixture test, 0.996 seconds. Docker responses, image creation and cleanup were provided by a fake CLI and bounded temporary Unix HTTP daemon. The fixture endpoint under `/tmp` cannot satisfy the helper's actual deployment endpoint guard; that guard was not waived. This is delegate compatibility evidence, not a native daemon or hosted-cause reproduction.
- Independent matrix harness reached **all 802 codes**, accepted 2,896 phase/call/outcome/refusal combinations and rejected 106,663 invalid/poison combinations, including 104,562 missing/extra-key and private-value schedules. Every projection retained the exact 14 public fields, FAIL and NOT RUN constraints. All 108 policy labels appear literally in the held broker/runtime source files. Success and unrelated-failure controls retained their existing behavior.
- Four independent atomic before/after receipt schedules exercised success, a known policy refusal with an extra private argument, OSError and cancellation through actual command/receipt code with mocked delegates. Each delegate read the durable started marker; its final receipt contained only the fixed result. The nonzero inventory control retained `command-failed/value-error` and refused the probe.

The matrix/durability harness is retained privately at `/tmp/fdk-native-probe-diagnostics-independent-review.py`, SHA256 `621510df1a1b72e31063b9ef885ed48291d7d5c42a3573a592cecc66e15551c4`. The retained exact-call fixture is `/tmp/fdk-producer-base-probe-repro.py`, SHA256 `9aaab2becb438cf16e34547c13f03096ad1b0c79e3e441ffd9fd8d3f488f61ea`. Neither is a native execution receipt or published executable input.

## Integration bounds

The actual trial's accepted workflow is `6eecc3235b91dfeb326f497f6fe0984ce7525db860739b2c0083b0f8271e37b1`, independently hashed from its committed bytes. Its 70-code consumer cannot accept the new detail codes. A consumer adaptation is in flight outside this ownership scope; no current consumer signoff is implied by this review. Root owns coherent packet refresh, source/commit binding, consumer acceptance and any dispatch.

Only this review document was edited. Hosted producer success, native FDK build, installation/lifecycle, binary publication, Asahi/M2/16K hardware and performance remain unaccepted. The previous actual failure and unknown cause are preserved.

## Coordinator source acceptance

The coordinator independently passes all 110 wrapper tests without skips in
16.550 seconds. The refreshed 128-file packet is SHA256 `6884fcfed5bb2577b4420e0676512df8aeb0a232680c38a240144581c2f40194`.
Exactly the five reviewed source/test rows changed; the remaining123 rows,
all39 adapter pins and original recipes stay intact. The source enhancement
only improves fixed diagnostics; no causal runtime correction is claimed.
Committed source proof and802-code workflow review precede another native
trial. Historical38230760444 remains FAIL with unknown underlying cause.

# Kernel Docker compatibility transitive rebind review

**Canonical source proposals PASS; actual committed Git/copy proof pending.** The independently regenerated 24-file kernel lock and 115-file job packet exactly match the coordinator's proposed bytes. A concrete public diagnostic loss should be resolved or explicitly accepted before the first long native run. It does not weaken FAIL enforcement or manufacture PASS.

Read current roadmap/package inventory and kernel compatibility/stage/job source/workflow. Only this review document and owned `artifacts/kernel-native-job/review-api148-rebind-20261012/` evidence were written. No shared lock, source, Git or workflow mutation, actual Docker operation, native compilation, installation or hardware test occurred.

## Independent canonical proposals

`/tmp/kernel-transitive-rebind-independent.py` creates a fresh isolated copy of all 115 selected source files in the owned review directory. It calls the actual kernel `stage.freeze()` on that copy and actual `packet.preview()` after replacing only the historical `KERNEL_SHA` literal in its private packet.py copy. Shared source/metadata files remain unchanged by this reviewer.

| Proposed binding | SHA256 |
| --- | --- |
| New 24-file stage map | `e47d873cd1f8ff542ec1ffd3a5de4b51db4d890f28bc6f1dddbc27d989db0d5a` |
| New 115-file packet, 1,782,305 source bytes | `062e026abdc1ee4c5ee4460c8c9ab122f177e84c12debf03166f1ee70d7f5e9e` |
| Job packet.py with only literal change | `0afe993fa321e08cd1c3de1ebd13e4d708ff9586b31b199a478a5b6f2c31890f` |

Both regenerated JSON byte strings equal the coordinator's actual working proposals exactly. Compared with the actual Git-retained historical stage map SHA256 `53d5c0dba0102413256552da3534b553ce5591ceaa747980e579d4fa1359bc5d`, only the four expected source/test rows below change. **Other 20 rows and every non-file stage field are identical.** Stage membership remains 24, job membership 115, modes unchanged. Source-input/recipe/helper pins, fixed budgets and native/platform acceptance limits are not changed by this transitive rebind.

| Changed 24-map row | Bytes | Mode | SHA256 |
| --- | ---: | --- | --- |
| `kernel-native-stage/image.py` | 9256 | 0644 | `09f737f54afaaeff475a1dfe7811dae4705b465aca1b1fce33d5dc4a69a49be9` |
| `kernel-native-stage/test_image.py` | 13506 | 0644 | `fe3fd91867c216fc71bfee9aae63f68af4fda98074e6ea767e7f1b2477aa03b4` |
| `kernel-native-stage/broker.py` | 26096 | 0644 | `7623948ff99aeef29dc9dbff32b2a9f0d7eeb8f1276e80d80d76e8c359de7592` |
| `kernel-native-stage/test_broker.py` | 13940 | 0644 | `87c1b01b4a42ab6c0044eafe3b082c2de2a901c32f6349745ba735008b824756` |

Private proof `proposal-review.json` records canonical equality and the exact delta set. `historical-stage.lock.json`, `proposed-stage.lock.json`, `proposed-job.lock.json`, `isolated-source/` and `reviewed-source-bytes.json` preserve all relevant input bytes and metadata. The coordinator's three adoption files are currently working/uncommitted. Full source Git binding and actual runtime snapshot/copy verification await its committed checkpoint; canonical equality alone does not authorize dispatch.

## Existing public observability

The workflow preflight captures/authenticates source/map/Git identity before running declared tools. It emits only `KERNEL_PREFLIGHT_PASS` or fixed `KERNEL_BOOTSTRAP_REFUSED`; prerequisite failures do not receive specific public refusal enums. This is bounded and avoids raw diagnostic leakage, but gives limited cause information.

Native execution's stdout/stderr are redirected to `/dev/null`. Original-producer/acquisition logs and kernel/controller logs remain private. The job public record has an exact 19-field allowlist with status, phase, cancellation, producer/probe/baseline/candidate states, cleanup and fixed NOT RUN platform/performance fields. Its private record stores `error_type`, but discards the exception reason. Final cleanup overwrites the failure phase with `cleanup`. No public failure-phase/reason enum or per-parallel-child outcome exists. The initial status is durably FAIL; phase assignments during work are not independently published as progress receipts.

The kernel stage itself retains a finite last-work phase and private error type; validated partial-stage inspection can preserve accepted probe/baseline/candidate results in the outer record. This usefully distinguishes some late build failures. It does not distinguish producer vs acquisition failure before kernel work, API/commit failure before variants, source refusals, or the precise finite failure reason. Raw private logs remain excluded from hosted publication.

### Confirmed diagnostics-collapse reproduction

`/tmp/kernel-observability-independent.py` invokes actual job execution/persistence with only controlled subprocess/daemon/source observations. One fixture returns original producer exit 1/acquisition 0; another producer 0/acquisition 1. Both execute branches fail, retain private `ValueError`, and produce **identical public JSON**: phase=`cleanup`, producer=`NOT RUN`, no reason or attempted child outcomes. Proof: private `observability-reproduction.json` in the owned review directory. No native workload or actual daemon was invoked.

This is a reviewability/diagnostic gap, not unsafe PASS. Before consuming a long native trial, recommend fixed source-bound failure-phase/reason enums and finite per-child return classifications, persisted before risky work and retained across cleanup/finalization. Keep public output status-only and validate the same enums in the public projector/workflow snapshot. Do not publish arbitrary exception text, private paths, logs, binaries or caches. Implementation decisions and any expanded source-map rebind are coordinator-owned; this reviewer made no source change.

## Verification and pending gates

Independently ran **30 public projection tests PASS, zero skips**, 0.747 seconds. Actual canonical freeze/preview and source-copy/hash/mode checks above also passed. The reviewed compatibility correction's native/source unit evidence is separate; this task did not repeat native compilation or claim parser/HTTP fixtures establish real daemon provisioning/commit/disposal.

Observability checkpoint source hashes: job.py `0a35909fe9cdef5ec0a25c77441739810d73afe1696661c29231b01e9f1cd7dc` (25711 bytes, 0755), public.py `d305fca9375ef9f9ee71b600a17111ae7d38d86c0073aabf07aad681c48356bf` (4961 bytes, 0644), workflow `40a16f84d2a52f0574b71bb1baffdc6069429b2e27345870795f0351c34d0e4c` (13372 bytes, 0644). API 1.48/start compatibility source maps are reviewable; actual native execution, both full kernels, kernel runtime, source/compile attestation, physical 16K/M2/Asahi recovery and measured performance remain pending/NOT RUN. All five roadmap responsibilities remain required.

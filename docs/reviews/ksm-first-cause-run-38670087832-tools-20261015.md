# KSM single-trial terminal review: run 38670087832

The [single trial](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38670087832) failed. The retained public record reports an earlier boundary than the prior CALL_ASDICT route: `ValueError`, stage `PRODUCER`, kind `UNKNOWN`, ordinal 0, zero RPC requests, `started: false`, producer `NOT RUN`, and producer mutation `NOT_STARTED`. It exports no `producer_route`. These are emitted state and diagnostics; with ownership uncertain, they do not independently establish that no process ever forked. No inner predicate, exception message, driver entry, probe entry or CALL_ASDICT cause is established.

## Exact retained trial

- Source: `c843b30e2af499e270144a94d4a9b9e027cd9cda`, sole parent `afae76af6616f4651237b59933fcfcbb8dac5341`.
- Packet SHA-256: `2bbb884e4e103155f52a00f58453042968ea7fbd5aba22a53724f57acca009a8`.
- Workflow ID `382226345`, `.github/workflows/native-arm-ksm.yml`; `workflow_dispatch`, branch `codex/ksm-current-native-recovery`, attempt 1.
- ARM job `116210925243`, label `ubuntu-24.04-arm`, completed at `2026-10-15T02:17:54Z`; GitHub conclusion `failure`, emitted status `FAIL`, phase `producer`.
- Strict retention: `artifacts/native-arm-ksm-tools-current/run-38670087832/`, 12 indexed retained leaves, zero API artifacts and zero frames. The retainer ran once. Its only adaptation from the previous retainer is CONFIG; AST comparison excluding CONFIG passes.
- Completion SHA-256: `c1ee0fe91c0ed376aa0b691949425c3293df14433eb88f9b210c699199ef7722` (2218 bytes, mode 0600).

`audit_retained.py` joins preflight and postflight terminal metadata, completed ARM job membership, strict retained file membership and hashes, and the one public JSON record at retained log line 280. `emitted-public.json` preserves that record; `retained-facts.json` records the bounded interpretation. The public `source_gate: pipeline-source-verification` label does not identify the failing inner predicate; `source_failure_reason` is null.

## Primary diagnostics and cleanup are separate

The first and last RPC failure records both report `ValueError / PRODUCER / UNKNOWN / 0`; requests are zero, current request and CLI/request return fields are null. Producer before-cleanup state is unavailable, all return/poll/reaped codes are null, and reaping is `NOT RUN`. No exported route supports a claim that the corrected driver reached its inline exception scopes. The underlying cause remains unknown. The previous run's CALL_ASDICT cause also remains unknown; this trial's earlier label must not be backfilled into it.

Outer cleanup is `FAIL`, ownership is uncertain, and diagnostics report `owner_failed: true`. Both `containers_absent` and `owned_image_absent` are true, with null cleanup error category. Those scoped absence results do not upgrade overall cleanup or establish its cause.

The daemon baseline reports `PASS` and preservation `PASS`, with zero initial containers, six initial/protected images, two observations and last stage `after_cleanup`, using `inventory-and-reference`. It reports `unowned_images: NOT VERIFIED` and legacy build-cache absence `NOT ESTABLISHED`. Container/image observations returned exit 0 with zero/six lines respectively. This is bounded inventory evidence, not a clean-host or cache-absence claim.

## Source authentication and admission limits

The independent authentication child verifies the selected commit and parent, 92 recursive tree objects, complete 1470-file Source/base membership, all 160 selected Source roles, the exact three-file delta and 157 held roles. All selected roles match the sealed correction postimages. The correction, semantic peer and actual Source peer seals and their bounded external pins were checked. `verify_source.py` rehashes the committed graph and these seals without importing or executing product Source.

Active native Source remains `7209d1f6a0a1acd38644a053d8956f3a1e17292122aef84d171368c984838924`, distinct from historical donor `a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898`. Kernel expression mapping remains lines 300/301, CALL_UNAME/CALL_ASDICT. Mapping identifies Source regions only. The eight inline primary-preservation scopes are Source-authenticated; this trial provides no runtime validation of them or cleanup success. Hardening remains partial, including loss of suppressed secondary diagnostics and the documented limits on exact exception types.

Both builds, comparison, lifecycle, management, public export, performance and hardware are `NOT RUN`; `published` and `cancelled` are false. No native acceptance, package acceptance, performance gain or hardware compatibility is established. Root admission remains separate.

## Review artifacts and verification

Review capsule: `artifacts/reviews/ksm-first-cause-run-38670087832-tools-20261015/`. Authentication and boundary reviews have separate child seals. The main index seals owned leaves and pins this guide plus external evidence. Run `python artifacts/reviews/ksm-first-cause-run-38670087832-tools-20261015/verify.py` for read-only verification.

Review activity retained and inspected the already-authorized trial using read-only GitHub/Git operations. It did not retry, cancel or dispatch a run, change variables, modify Git refs, run product actors, or replay providers. No causal fix is proposed by this terminal review.

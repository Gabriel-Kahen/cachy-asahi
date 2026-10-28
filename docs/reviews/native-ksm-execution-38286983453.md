# KSM3 native execution 38286983453 — bounded independent diagnosis

Disposition: **PASS for retained source/log attribution and the bounded diagnosis controls; actual execution remains FAIL.** Source startup progressed through `pipeline-source-verification`; producer acceptance, both KSM builds, comparison, lifecycle and public export did not pass. The underlying hosted `BrokenPipeError` cause and owned-resource absence remain unresolved. No native compilation, installed lifecycle, management, KSM activation, M2, 16K or performance acceptance follows.

## Exact authority

The run uses commit `f7ee4a7e0cf1145e15970f13daa1ec76ef5f567e`, packet SHA `0623a4d68b736c85128b55686347921ab50fc45c9105785c54f8b74206177435` (152 rows), and unchanged workflow SHA `ae2dc0adace61812c4fcf6396dfec2a219dbef66813a00c28852ca6d156f34ae`. Read-only `git show` and tree metadata independently authenticate every packet row's exact length, SHA and mode. The owned snapshot adds the packet itself: 153 files, 2,288,409 bytes; packet-authorized source bytes are 2,257,813. Shared checkout bytes were not substituted for committed authority. The exact captured files, Git blob IDs and modes are indexed in `artifacts/reviews/native-ksm-38286983453-root-peer/source-capture.json` (39,372 bytes, SHA `ed5700091c4b2fdc39a4607592f6a21fb0c2cef5b0134c69ffb9c9c62d7ca228`). All source hashes/modes and absence of PYC are rechecked at finalization.

The coordinator's strict ZIP index records seven regular log members and ZIP digest `4fa212df0d128646519f0ecf3d1c532ade707b3166c13235246dca72e6f0b9d4`. Independently, all seven retained members match that index's lengths/hashes, and `workflow.log` equals the combined log exactly: 26,046 bytes, SHA `14992dabbda102607ad331e836ce3a19f843fe25fc2faa34979188586827942b`. The compressed ZIP itself is not retained here, so its decoder/ZIP-validation authority remains the coordinator's evidence rather than an independent reread of compressed bytes.

The sole terminal JSON was independently parsed from the combined log and compared with retained `terminal-status.json`. Checkout/log references and terminal commit/packet fields agree with the committed authority. Root's `root-public-verification.json` and bootstrap proof SHA `053b1e27141d23ceac249b8ddcd37f74b77286cfdb0a5f631d1ffb39877b3b2f` were rehashed. The actual inline workflow Python was independently replayed from the exact current f7ee source, with only final `os.execve` replaced by a source-only stop. All 152 Git blob/mode checks and fresh bootstrap byte/mode inventories PASS. This is local source/bootstrap evidence, not another hosted producer or daemon execution. The replay's only artifact-destination change writes into this review's owned directory.

## Actual terminal boundary

The terminal line occurs at **2026-10-12T17:58:36.4455969Z**, and the native step records exit **1** immediately afterward; job completion is later. Exact terminal facts are:

| Field | Actual value |
|---|---|
| status / phase / failure category | FAIL / producer / BrokenPipeError |
| source gate / source failure reason | pipeline-source-verification / null |
| producer / producer mutation | NOT RUN / UNCERTAIN |
| builds / comparison / lifecycle | NOT RUN, NOT RUN / NOT RUN / NOT RUN |
| cleanup / ownership uncertain | FAIL / true |
| cancellation / public export / published | false / NOT RUN / false |
| hardware / management / performance | NOT RUN / NOT RUN / NOT RUN |

`producer: NOT RUN` is the initial unaccepted phase value. Source sets `producer_mutation: UNCERTAIN` immediately before the supervised producer call, and advances acceptance only after returned exit zero plus original receipt/journal checks. This combination **does not prove that the producer never started**, nor prove its returned exit, successful acquisition/bootstrap/build completion, image identity or ownership. No private producer output, operation journal, private status file or log archive is exported. The public terminal schema therefore cannot establish an exact daemon operation, response, timeout or RPC peer that caused the failure.

## Baseline preservation and cleanup are separate

The baseline summary records initial image query exit zero/six lines, initial container query exit zero/zero lines, six protected image IDs, nine observations, and final `after_cleanup` observation mode `inventory-and-reference`. Preservation and baseline status are PASS, with baseline identity SHA `61880dd195d4d1dd3af31b5a18a58da666755c050ed75385c5e7d9a41736c457` and private receipt SHA `db99fa3aa8b7903dd71183e571b46a01c25d8268dfe5397a9bb70d9b61dbac08`. Nine unowned image IDs are reported, marked NOT VERIFIED; legacy build-cache absence is NOT ESTABLISHED.

These are declarations by the authenticated executor, whose source requires a full final cooperative baseline observation before preservation PASS. The private baseline inventory/reference projections and journal bytes are unavailable for independent replay. Preservation of the six protected baseline identities does not establish ownership, deletion, cleanup or absence for any created or unowned objects. The source explicitly leaves unowned images untouched; the nine are not assigned to a particular actor, successful builder, cache, leak or immutable owned image.

The executor's exception path marks the owner failed. Broker cleanup can return FAIL solely because that sticky failure is set, even when its own absence booleans are true; it can also return FAIL from a cleanup exception with false absence booleans. Those underlying booleans/errors are not in the exported terminal. Thus cleanup FAIL does not independently prove a surviving object, and final baseline preservation PASS cannot clear uncertain owned cleanup. VM teardown would not settle this scoped ownership gate.

## Source-capable BrokenPipeError paths and causal controls

Relevant exact source hashes are:

| File | SHA256 |
|---|---|
| executor.py | `5dda4fed77274aacc523a30aa5c97033ca9defdc8928faedcb495b80655f228c` |
| broker.py | `b1f6383da59a40f3eadd19bd8544b795c738566889f397e544fbcaba90531c27` |
| runtime.py | `1d695acda2a7161510a161034278999cc05063526c0ba33c99e27580321e6354` |
| shim.py | `fc3a6fcbf14b78982b4ff04f4105ff82ffdd36d3f4f6344331abbf43d4fc62ca` |

In `broker.Service.handle`, the request/call portion is caught and converted to a finite response; the final `send(connection, ...)` is **outside** that catch. `send` performs one framed `connection.sendall`. A response transport failure can therefore escape `Service.poll` into the producer runner's callback. That runner's finally reaps the producer process group, drains bounded output and closes its log; executor then records the outer exception class, poisons the owner and attempts disposal. This path alone explains how the reported class is source-capable; it does not identify the hosted path or say the producer originally failed first.

Four exact AST-captured `Service.handle`/`send` controls are retained in `rpc-send-control.json` (SHA `1acdf21a4294d3e6ae2971b122385655f98452291ccf493e1721fb33f6138821`). Synthetic request/backend/connection fixtures use an actual tiny closed local `os.pipe` write to supply EPIPE; no Unix socket, daemon or package actor is executed. A normal response after a successful request returns code 0. A broken response after that completed request escapes `BrokenPipeError`. A refused request with normal response returns 125 and keeps the broker poisoned. A refused request followed by a broken response also escapes `BrokenPipeError`, masking the request's original `ValueError` at the outer category boundary. All four causal controls PASS. The controls demonstrate ambiguity, not a hosted timeout/disconnect cause or actual completed Docker operation.

The shim separately writes its request through `sendall` and its decoded response to stdout. Its caught ordinary transport error returns 125; by itself this does not directly explain the coordinator's exception category. Parent terminal printing could also encounter a closed output pipe, but the actual category is already inside a successfully printed report, so that final print is not evidence of the original producer-phase error. Private checked regular-file writes are not ordinary pipe transport; no private descriptor or log observations permit an alternative attribution here. Original producer calls have finite 60-second probe/inventory and 1,800-second bootstrap bounds; the shim has a 2,600-second response wait and the broker response socket a five-second timeout. Elapsed wall time and these constants do not identify the actual request or prove a timeout mismatch.

## Finite next observation proposal

Preserve the sticky FAIL/uncertainty and original producer. Before another accepted native trial, record a bounded source-bound request ordinal and closed command-kind label; separate request received/validated, broker result returned (actual code and bounded output length/hash), response send begun/completed or finite exception category, and actual producer observed exit versus supervisor reaping outcome. Preserve the first request/broker refusal category when a later reply fails. Keep raw arguments, commands, socket paths, daemon identities, credentials and raw error strings private. An exact finite public projection and receiver grants must be independently reviewed and map-rebound.

Also expose the actual bounded cleanup result's owned-container/image absence flags and cleanup-error category separately from baseline preservation and the sticky overall result; missing observations remain unknown/FAIL. This is a diagnosis proposal, not permission to promote an uncertain request or invent ownership from inventory differences. A disconnected-reply control should remain red for acceptance even if a fake request completed. No transport retry, timeout increase, broad catch-and-continue, image-selection or cleanup redesign is warranted by this receipt alone.

The current source provenance is accepted for this review, the actual execution is FAIL, and its causal information is insufficient for a specific native fix. No source, packet, workflow, Git, host, Docker or package mutation was performed. Historical logs and the terminal failure are preserved.

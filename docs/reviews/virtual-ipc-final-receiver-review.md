# Virtual IPC final receiver review — 2026-10-12

Disposition: **held source correction accepted for coordinator integration; no confirmed code blocker.** The required guest/CORE and source-packet pin rebind remains pending. The corrected native controller/QEMU guest trial is **NOT RUN**. Actual run 38259350917 remains FAIL with no frames; its actual private compositor log is unavailable.

## Exact held bytes

The eight files match the final author receipt `/tmp/virtual-ipc-receiver-parent-vezczup1/held-receipt.json` and its separate held copies byte-for-byte, including sizes and modes. A fresh 214-path peer tree captures the 211 current packet source paths, two new diagnosis documents and the packet itself, without PYC/cache files. Exactly six mapped source rows differ from the current packet and 205 remain unchanged. These stale coordinator pins are intentional integration work, not a code defect.

| Path | SHA-256 | Bytes | Mode |
| --- | --- | ---: | --- |
| `docs/workstreams/virtual-guest-ipc-diagnosis.md` | `65f75fe72f9b606634ea82af751801fa023fdb2e81404a7d4ee26c1c00776d45` | 16,405 | 0644 |
| `docs/workstreams/virtual-ipc-receiver-integration.md` | `1986e3f617118bccb79665c7ada504fb1cf079d2baf1ecccd5bf0323a939be7e` | 5,327 | 0644 |
| `scripts/ci/development/test_virtual_stage.py` | `525939d5f33a7d0f9af0cdb068b11aa409e5349bc021bafd00ddc7e9d0c4215d` | 123,795 | 0644 |
| `scripts/ci/development/virtual_stage.py` | `0673893986bca97958d0cfab83e5caaf76844671484b471fc88a4cb7e68f562b` | 60,397 | 0644 |
| `scripts/virtual/controller.py` | `d4fb7ea34fb5b06b202c4ecd49a7a6c02f48148137eb7a16791b47142df36966` | 46,370 | 0644 |
| `scripts/virtual/guest.py` | `3ca0e95ed89cd21edc96b09e1bc98138e0addbd4b99fc9a3ba41f22ea562ddda` | 15,001 | 0644 |
| `scripts/virtual/test_controller.py` | `82a1b23a86440189ea839c6b5aaa502088f796757e98af3ce9a58fb7cdacc33f` | 33,451 | 0644 |
| `scripts/virtual/test_virtual.py` | `b2064b20a05c89b690d14d30819dbcacf9fc1de6fe9f13106900f0f0693161f9` | 48,148 | 0644 |

## Failure retention and receiver boundary

The exact earlier peer reproducer was replayed against the historical guest and against the captured correction. Historical source raised `BrokenPipeError` instead of the original IPC `ValueError`; corrected source propagates the **same original exception object**, with the compositor reaped. Five focused diagnostic tests confirm closed fallback and summary channels cannot replace the active phase failure, and a clean phase still raises its first cleanup/capture/log-channel failure. Closed channels do not prove delivery; a working channel retains only the fixed hash-bound capture-failure diagnostic.

The receiver admits only the eight-field `ipc_probe` schema with exact integer types, closed stage/error values, attempts 1–24, bounded elapsed/exit ranges and a combined 1 MiB UTF-8 output cap. Boolean/float substitutes, duplicate/unknown fields and raw or control-normalized credentials refuse. Successful protocols require minimal then overlay, consecutive attempts from 1, nondecreasing times strictly below 180000 ms, the exact exit-6 retry response, and final exit-zero JSON `[]` with null error/empty stderr. The immediately following command must have the exact fixed argv and identical response bytes. Failed, late or interrupted probes cannot grant successful frames.

Independent receiver controls accepted two complete synthetic protocols, including attempt 24 at 179999 ms, and refused 25 poison cases covering shape/types, ordering/correlation, deadline/fatal retries, UTF-8 expansion, private content, duplicate fields and log identity/encoding/hash/size. The new log names are only stage-bound `minimal-compositor.log` and `overlay-compositor.log`; both retain the exact five-field, strict base64, SHA-256 and 1 MiB policy. Aggregate 4 MiB events and the controller's existing output bounds remain intact. No arbitrary private instance tree is exported.

Against the previously reviewed virtual87 source, the adapter's only changed functions are `read_events` and `event_protocol`; its only other AST change adds three closed diagnostic codes. Acquisition, receipt/source/capability acceptance, captured-byte publication, frame validation/retraction, cleanup and cancellation functions are unchanged. The controller's only changed function is `project`, adding the fixed event kind. Focused frame-copy, second-frame rollback and final-unmask cancellation tests pass.

## Independent checks and integration requirements

From the fresh capture, **10 adapter tests PASS** in 6.497 seconds and **15 guest/controller tests PASS** in 0.836 seconds, zero failures/errors/skips, with ResourceWarning treated as error. Guest fixtures use authorized owned temporary AF_UNIX sockets, real tiny bounded subprocesses where specified, and mocked native actors. The author's whole 94/61 suites are reported evidence and were not repeated here. Initial peer harness import-name collisions were corrected by separate processes; a sandbox socket refusal was rerun with narrow approved escalation. Both failed harness logs remain retained and are not counted as implementation failures.

The current controller CORE guest pin still points to `8a31f3d251e6e60db7c0c33bfebb8d9e37fea7924a72fdce493a9388ccde143f`; root must replace it with reviewed guest `3ca0e95ed89cd21edc96b09e1bc98138e0addbd4b99fc9a3ba41f22ea562ddda`. The independently calculated controller SHA after **only that literal substitution** is `879b72ecbd3803e8745e99baa99c4e42c441af209234579620f50840b681614b`. Root must bind that resulting controller and all six changed code/test rows in the accepted broader packet and verify actual committed preflight before dispatch. This review changes no source, shared pin, packet, workflow or project Git.

Historical ten-event bytes remain diagnostic FAIL with no frame promotion in the focused replay. Host fixture success does not prove eventual readiness of the actual compositor, generic software-rendered frame usability, M2/16K compatibility or performance. Those remain unrun acceptance gates.

Evidence is retained in `artifacts/reviews/virtual-ipc-final-root-peer-20261012/`; `final-review-receipt.json` binds all eight held hashes, focused logs, causal reproducer/results and the independent receiver proof.

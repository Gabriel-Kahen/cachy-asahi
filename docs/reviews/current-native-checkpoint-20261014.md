# Current native checkpoint, October 14, 2026

The complete R1–R5/M5–M9/A01–A15 goal remains active under the current roadmap.
The authorized recovered ARM CI input upload is complete. This checkpoint
records implementation, actual CI evidence and unfinished validation separately.

| Lane | Current Source | Exact run | Current result |
| --- | --- | --- | --- |
| Screenshot candidate | `92a3f061` | `38571648129` | CI success; candidate-specific independent review underway |
| Kernel | `a311de55` | `38583969397` | Running after reviewed schema4 propagation correction |
| Updater | `2ce49ea1` | `38564810704` | Failure retained; native-pair process return 1; exact inner reason under review |
| Composed integration | `993487a4` | `38566446597` | Failure retained; startup initial-failed; independent review underway |
| Pair | `eef0710d` | `38572139973` | AttributeError at Docker result observation; dictionary/object contract correction assigned |
| Zsh pair | `cb645f34` | `38573732820` | Same exported result-shape mismatch in its separate exact run |
| FDK | `7c51adff` | `38574961503` | Running |
| Library CLI | `ad2ed5eb` | `38578019953` | Queued; manual dispatch performed once |
| Library materialization | `9f37d693` | `38560924092` | JBIG length mismatch, 109999 expected / 109846 observed; new builds not reached |
| KSM | `4f9bbf3c` | `38561918431` | TypeError at NATIVE_ENTRY, zero RPC, ownership-uncertain cleanup |

Terminal runs retain run/job identities, logs, regular-file manifests and
artifact/frame digests under their exact `artifacts/native-arm-*` namespaces.
The Pair/Zsh traceback establishes a result-shape mismatch, not a Docker
return-code failure. The library native compressor and exact KSM TypeError
operand remain unknown. Source countermodels do not backfill earlier trials.

Installer P0 entry and two bridge/caller fixes are published on
`codex/signer-native-runtime-v1`, Source `92d00c29`, in draft PR23. Independent
P0 review retains the original 60-second limit and a live SDK Session. Routing
is being implemented. External runtime review `a84e08c5` identifies one early
selected cancellation classification defect in the separate keyless adapter;
a corrective successor is required. The static native signer compile result
remains six-command static evidence only. No signer runtime, native 26-case
matrix, real screenshot execution or physical M2 acceptance is claimed.

# Camera receiver correction: root peer follow-up

October 12, 2026. **PASS-source-only** against correction handoff SHA-256 `59dfcfd0e4cfa2de56e757189bd2049ae660219d815101f946b3fd3bc8950689`. The prior P2 open-before-type-check blocker is closed for this corrected receiver under its documented trusted Linux procfs assumption. Camera capture, firmware, runtime preview, native execution, physical 16K/M2 validation and the core camera gate remain **NOT RUN / OPEN**.

The roadmap and package inventory were read before review. This follow-up owns only this new document and `artifacts/reviews/camera-feature-route-root-followup-peer-20261012/`. No receiver, installer, shared map, historical artifact, package, Git or protected platform file was changed.

## Bound inputs and preserved history

All 24 correction index references passed size, SHA-256 and mode checks. All three current source files match the corrected held copies. All 91 prior artifact references and the original handoff `13c90c746b50ffd68320514c923c0604cc8e3037288e6b843022b8ed91072dd6` remain byte-identical. These checks were repeated after controlled execution.

| Current source | SHA-256 |
| --- | --- |
| `scripts/port/camera-probe/probe.py` | `0703071e7e6dcdc7929eb38af74bd5bcf733cc8883cb705dad5c3418e32ecddd` |
| `scripts/port/camera-probe/test_probe.py` | `278e9edbc5ef8e9811b6734147be0306a10899179aeadd5589b48ea5e5710967` |
| `docs/workstreams/camera-feature-route.md` | `e847d49c9e42922d9c575094a04082b9a39c9d27358571174b1c4ec646768f5f` |

## Descriptor and privacy result

`read_at()` now acquires the selected entry using `O_PATH | O_NOFOLLOW | O_CLOEXEC`. It checks the held inode for regular type, one link and positive bounded size before any read-capable open. The derived reader uses `/proc/self/fd/<held-pointer>`, never the mutable metadata basename. Its snapshot and the no-follow named entry must match the held pointer before payload reading; post-read checks compare the reader, pointer and name again. Snapshots retain device, inode, size, mode, link count, mtime and ctime. Nested finalizers attempt pointer closure even when reader closure raises. Missing O_PATH refuses before acquisition.

The directory walk still refuses links component by component and retains ancestor/directory snapshots. Observation and expectation bytes are reread and hash-bound. The exact finite schema, count/type/rational-rate bounds, duplicate-key/nonfinite rejection and finite error projection remain intact. Metadata origin, identity, nonce and driver labels remain caller-bound claims, not hardware attestation or evidence of camera frames.

Trusted Linux procfs must resolve FD magic links to the held ordinary inode. The review accepts that explicit environment assumption; it does not establish behavior under a counterfeit procfs or arbitrary mount namespace. The workstream now uses upstream V4L2 API commit `05f7e89ab9731565d8a62e3b5d1ec206485eeb0b` without relying on the unproved v6.19 release label. Original primary source/license bodies and the distinction between research kernel 7.1.9 and protected 7.1.13.asahi3-2 are retained.

## Controlled verification

All **23 receiver tests** passed from a new owned capture with bytecode disabled and ResourceWarning treated as an error. Actor/network/special-node tripwires prohibited subprocesses, shell actors, sockets, mknod and mkfifo. Every type fixture was an ordinary owned file with mocked metadata; path-custody controls used owned directories, symlinks or hardlinks. Actual proc-FD derivation occurred only for already-held ordinary fixture files.

All **14 fully mocked controls** also passed in a new owned copy. They cover ordinary success, character/block/FIFO/socket/symlink rejection before derived read-open, link and size bounds, name and derived-inode replacement, post-read pointer/link drift, close-error cleanup and missing O_PATH. These mocks do not validate a kernel implementation.

The historical FIFO-containing run remains superseded and unchanged; it was not executed here. No real device, FIFO or socket node was created or opened. No camera tool, pipeline, package acquisition, network request, install, service, module, capture or preview ran. The result closes only the receiver source blocker; it cannot accept an integrated camera on either Air size.

Evidence is retained in `input-bindings.json`, `run-receipt.json`, `ordinary-suite.log`, `fully-mocked/receipt.json` and the final `review-receipt.json` beneath the new peer artifact namespace.

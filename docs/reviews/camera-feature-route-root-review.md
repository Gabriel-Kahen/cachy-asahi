# Camera route and metadata receiver review

Disposition: **BLOCKED on a P2 receiver device-open ordering defect**. The pinned route is useful source evidence; capture, preview and hardware validation remain NOT RUN.

This review binds handoff SHA256 `13c90c746b50ffd68320514c923c0604cc8e3037288e6b843022b8ed91072dd6`. All 91 referenced artifacts and three current source files match the retained byte/size pins and held copies:

| File | SHA256 |
| --- | --- |
| `scripts/port/camera-probe/probe.py` | `48dbcfc388edf7731a5572385a55c75899bb0cbdc9f5063597d0cf104d4c5916` |
| `scripts/port/camera-probe/test_probe.py` | `8ff0c106ea54afffa8db911a8826feb6cbe77457c2f0ea1dc0e05bf081442607` |
| `docs/workstreams/camera-feature-route.md` | `d67df5dc66bfc438b17c27925b4888d8ecde519c78e38370b825c5698e3dc33f` |

**[P2] `read_at()` opens a special file before rejecting its type.** At `probe.py:140–143`, `os.open(..., O_RDONLY|O_NOFOLLOW|O_NONBLOCK)` precedes the regular-file `fstat` check. A character or block device placed under an allowed metadata directory can reach the driver's open operation before refusal, while output claims `device_access=false`. `O_NONBLOCK` does not prevent that operation. The [inert reproducer](../../artifacts/reviews/camera-feature-route-root-peer-20261012/source-check/open-before-typecheck.json) uses ordinary scratch files and mocked type results; no real device was accessed. First bind a path-only descriptor and prove its inode ordinary, single-link and bounded, then derive a read descriptor bound to that exact inode. A separate pathname stat followed by open leaves a swap race.

Seventeen existing receiver tests and 137 additional memory-only cases passed. Exact schemas, finite key/type/count bounds, rational frame-rate limits, duplicate JSON and nonfinite refusal, descriptor-relative directory traversal, NOFOLLOW, hardlink refusal, snapshots and reread guards are supported by these controls. Labels remain caller-supplied bounded strings; this structural output policy does not promise semantic redaction. Identity, nonce and hash matching binds caller expectations, not hardware attestation or freshness. The [source review receipt](../../artifacts/reviews/camera-feature-route-root-peer-20261012/source-check/source-review.json) separates controls from the reproduced defect.

The retained primary sources support the proposed route for `Mac14,2/J413AP/apple,j413/T8112` and `Mac14,15/J415AP/apple,j415/T8112`: Asahi docs commit `0d1f8917fa88745d62a4c05d802c4a7298c8616b`, research kernel `77cb8f24c2381a8abb7272d7bbdec548d6426a8a`, T8112 ISP/DT matching, imx558cfg0 platform IDs 14/15 and V4L2 NV12/NV12M STREAMING/MMAP registration. The research Makefile is 7.1.9; correspondence to protected package `7.1.13.asahi3-2` is unproved. Published Asahi webcam support and its Fedora availability legend do not count as project physical validation.

The 40 retained pipeline source records support PipeWire 1.6.9 (`8fa27cabdc6c0c1350c69c026af5850ef0af1e26`), GStreamer 1.28.8 (`1b2a95a1b72787cda146b46df9605b168e5b683b`) and libcamera 0.5.2 (`aa0a91c48ddb38c302390d5c4899cb9e093ddd24`). Selected license records are consistent with retained notices. Linux V4L2 API commit `05f7e89ab9731565d8a62e3b5d1ec206485eeb0b` is bound, but the packet's v6.19 label lacks retained Makefile/tag proof. Keep that API claim commit-specific until the release label is evidenced. Source pins and notices do not authenticate firmware or installed binaries.

No device/tool/capture/preview command, network acquisition, package installation, native pipeline, 16K execution, privacy LED, quality, suspend/resume or exact-machine firmware validation ran in this review. Backend maintenance ownership and the core camera gate remain open. No shared source, manifest, acceptance map, Git metadata or historical evidence was edited. Receiver correction and a fresh bounded peer check remain necessary before any device-facing step is considered.

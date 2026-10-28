# Camera feature route and metadata receiver

October 12, 2026. **Source-audited and fixture-tested receiver; actual camera, generic preview and hardware validation remain NOT RUN.** This records the missing core camera workflow without changing shared acceptance/coverage maps. A synthetic preview cannot waive the camera requirement. The roadmap and package inventory were read; the Asahi platform stack remains protected.

## Exact target and source route

| Physical target | Apple model | Asahi board / DT | SoC |
| --- | --- | --- | --- |
| 13-inch M2 MacBook Air (2022) | Mac14,2 | J413AP / apple,j413 | T8112 |
| 15-inch M2 MacBook Air (2023) | Mac14,15 | J415AP / apple,j415 | T8112 |

The official [Asahi M2 matrix](https://asahilinux.org/docs/platform/feature-support/m2/) marks Webcam `linux-asahi` for both Airs. Its legend describes mostly stable support available in Fedora Asahi Remix. This published claim does not validate this project's ALARM tuple, establish mainline support or pass either physical target. Apple specifies a 1080p internal camera on the [2022 Air](https://support.apple.com/en-us/111867) and [2023 Air](https://support.apple.com/en-us/111346); product specifications do not prove Linux frames.

The pinned primary route is sensor → Apple ISP firmware/calibration → T8112 kernel driver → processed **NV12/NV12M V4L2 capture**. Both board DT files include `isp-imx558-cfg0.dtsi`; their ISP platform IDs differ. The inspected driver registers a streaming/MMAP capture endpoint. Endpoint identity must be established at runtime; no guessed `/dev/video0` or external USB camera can satisfy integrated-camera acceptance. The sensor config includes crop/scale presets for 1920×1080, but mode workarounds and calibration TODOs prevent an Apple-quality parity claim. Firmware presence, subtype, rights, hash and initialization remain unverified.

| Audited source | Exact revision | Boundary / license |
| --- | --- | --- |
| Asahi docs | `0d1f8917fa88745d62a4c05d802c4a7298c8616b` | Published support/model claims; CC-BY-3.0 |
| Asahi Linux | `77cb8f24c2381a8abb7272d7bbdec548d6426a8a` | ISP/DT/config; selected ISP GPL-2.0-only, DT GPL-2.0+ OR MIT |
| PipeWire 1.6.9 | `8fa27cabdc6c0c1350c69c026af5850ef0af1e26` | Synthetic route properties; selected source MIT, repository exceptions retained |
| GStreamer 1.28.8 | `1b2a95a1b72787cda146b46df9605b168e5b683b` | Synthetic source/PNG encoder; LGPL notices and bundled LGPL-2.1 retained |
| libcamera v0.5.2 | `aa0a91c48ddb38c302390d5c4899cb9e093ddd24` | Camera/pipeline boundary only; core/plugin LGPL-2.1-or-later |
| Linux V4L2 API (commit-specific) | `05f7e89ab9731565d8a62e3b5d1ec206485eeb0b` | V4L2 API evidence; dual-license UAPI, GFDL documentation |

The Asahi research commit's Makefile is **7.1.9**, distinct from protected `linux-asahi 7.1.13.asahi3-2`. No correspondence to the selected package source/config/DTB/firmware has been established; no kernel replacement is proposed. [Issue 616](https://github.com/AsahiLinux/linux/issues/616) is an open user proposal about libcamera adaptation, including a reporter without Apple hardware. It is not maintainer acceptance or frame evidence. Installing libcamera cannot establish a matching Apple ISP pipeline. Direct V4L2, selected libcamera and selected PipeWire/browser routes require separate results.

The research lanes retain original bounded source/API bodies, hashes and license texts: `artifacts/reviews/camera-feature-route-20261012/asahi/` (25 files, 317,467 bytes; 55 offline checks) and `pipeline/` (40 source records). Mutable Apple pages retain facts plus response digests rather than full page bodies. Tag signatures, binary packages and firmware were not authenticated. The Asahi lane's unavailable libcamera web endpoint is distinct from the pipeline lane's successful official GitLab API/source capture.

## Read-only receiver

`scripts/port/camera-probe/probe.py` accepts **two caller-selected ordinary metadata files** under a canonical absolute evidence namespace: observation and expected identity. It invokes no camera/tool/package command and reads no device, sysfs, module or service state. It refuses `/dev`, `/proc`, `/sys`, linked paths/files and nonregular or multiply linked files. Descriptor-relative directory traversal refuses links at every component. Linux O_PATH binds each candidate inode without invoking a device driver open; regular-file type, single-link count and byte bounds must pass before a read descriptor is derived through /proc/self/fd for that exact held inode. Derived, path-only and named inode snapshots (including link count) are compared before and after bounded reads and rereads, with ancestor and directory identities retained. A separate pathname stat/open sequence is not used. This requires trusted Linux procfs FD magic links; missing O_PATH/proc-FD support fails closed. Duplicate JSON keys, nonfinite constants, changed evidence and hash mismatches fail. It writes only its finite JSON result to stdout.

CLI: `python -I -B probe.py --namespace ABSOLUTE_EVIDENCE_DIR --record observation.json --record-sha256 SHA256 --expected identity.json --expected-sha256 SHA256`. This command receives metadata only. The caller must bind evidence origin independently: hashes prove the selected bytes, not that observations came from hardware. A nonce/run ID is compared to the explicit expectation but is not cryptographic freshness or remote attestation.

The schema binds board, T8112 SoC, aarch64/16K identity, kernel release/source revision/image hash, probe source hash, run ID and nonce. Origin is `controlled-fixture` or `captured-target-metadata`, with hardware/capture fields fixed to `NOT RUN`. At most eight devices contain safe opaque IDs/driver labels, finite capture capabilities and sixteen format/size/rational-frame-rate records. Driver strings are caller claims; the receiver cannot establish built-in camera ancestry. Only complete available V4L2 metadata passes; no-device, unsupported, unknown, missing usable formats/capabilities, identity mismatches and libcamera backend claims fail this selected receiver route. This says nothing about the global availability of other backends.

Bounds are 64 KiB observation, 4 KiB expectation, 64 path components, eight devices, sixteen modes/device, 8192×8192 maximum dimensions and 120 fps maximum. All outcomes retain `device_access=false`, with hardware, firmware, capture and runtime preview `NOT RUN`. A `PASS-metadata` result means caller-bound metadata passed the schema, never that a camera works. Controlled fixtures and captured metadata cannot close the physical gate.

## One future generic ARM preview

Exactly one proposal is retained in `pipeline/proposal.json`: **synthetic GStreamer → private PipeWire graph → one private PNG** inside a coordinator-selected disposable aarch64 guest. A finite 160×120 RGB test pattern provides at most 250 frames; a nonce-bound consumer requests one frame through `pipewiresrc autoconnect=false`, and `pngenc snapshot=true` emits one image. A single `pw-link` links verified owned ports. A reviewed minimal private daemon configuration runs no device monitor or session manager. This remains PROPOSED-NOT-RUN; negotiation and cleanup have not been demonstrated.

The future supervisor must enforce 60 seconds total including ten seconds cleanup, twenty seconds consumer, thirty seconds actors, one link, 2 MiB PNG and 1 MiB per log/registry snapshot. It must stop and reap owned actors and record cleanup signals separately from normal EOS. No host camera/audio/display nodes or sockets, V4L2/libcamera source, loopback, device enumeration, screen/microphone input or network video export belongs to this route. Its maximum acceptance is software transport and a private synthetic image; GUI preview, 16K behavior and physical camera remain separate gates.

Required row/package proposals for the coordinator:

| Proposed decision | Current evidence / unfinished work |
| --- | --- |
| Explicit core camera acceptance row | Separate J413/J415 integrated capture, privacy/application and lifecycle results; workflow/backend/source owner and maintainer UNASSIGNED |
| `gst-plugin-pipewire 1:1.6.9-1` for future synthetic route | Absent retained 624 payload; declares pipewire-audio and pipewire-session-manager plus GStreamer/base/core libraries; full mandatory closure remains required even if services are not started |
| `gst-plugins-good 1.28.8-1` for PNG encoder | Absent retained 624 payload; broader media/libpng/v4l-utils closure unresolved |
| Existing PipeWire/GStreamer utilities | Retained inventory observes pipewire/libpipewire 1:1.6.9-1, gstreamer/base 1.28.8-1, libpng 1.6.59-1, v4l-utils 1.32.0-2; inert presence is not installed or accepted tuple proof |
| libcamera / IPA | Boundary research only; no package selection or Apple pipeline acceptance |

Before any future tool invocation, bind exact executable, plugin, library, package and source identities and review authenticated dependency/license closure. No user PATH/plugin fallback or package acquisition is authorized by this research packet. Optional multimedia packages cannot waive the core camera gate, and the 341 builder cannot be presumed to contain this route.

## Physical acceptance, separately on both Airs

1. Record exact model/board/DT, 16K page size, installed kernel/config/DTB and firmware hashes while preserving the reviewed Asahi stack.
2. Bind the endpoint to apple-isp and board DT ancestry; record successful firmware/sensor/calibration initialization. External UVC capture cannot substitute.
3. Enumerate advertised formats, sizes and frame intervals, then capture each selected negotiated mode for 60 seconds, including 1920×1080 if advertised. Retain frame/timestamp/drop/error summaries and user-reviewed image quality; public evidence need not contain private frames.
4. Run ten open/capture/close cycles and five suspend/resume cycles; verify activation indication, resource release and subsequent frame delivery.
5. Validate the selected application/browser, permission denial and privacy behavior. Record separate exact backend identities/results for any libcamera/PipeWire route.
6. Record per-model/kernel/backend/application/mode PASS or FAIL. A result on one model, source/build success or synthetic frames cannot pass the other model.

Implementation and controlled validation results are bound by the root handoff and tests receipts beneath the assigned camera artifact namespace. No real camera was opened or captured; no host devices, modules, services or privileged loopback were touched. Actual target/runtime/firmware/hardware/performance acceptance remains NOT RUN.

## Receiver correction hold

The independent `camera-feature-route-root-review.md` blocked the initial `13c90c74…` packet because its ordinary read open preceded type refusal. That old handoff, all91 artifacts and the old source/test/document copies remain unchanged. The new `correction/` packet fixes only descriptor acquisition/type ordering and strengthens the retained link-count snapshot. Mocked character/block/special-file and race fixtures use ordinary owned metadata files; no actual device is opened or queried. PASS-metadata remains caller-claim validation with capture, firmware, preview and hardware NOT RUN.

The historical pipeline lane labels API commit `05f7e89ab9731565d8a62e3b5d1ec206485eeb0b` as v6.19 without retained tag/Makefile proof. This corrected document makes only the commit-specific V4L2 API claim. Historical source bodies/maps are preserved; no release label, source acquisition or selected-kernel correspondence is inferred.

The final correction passes **23 receiver tests** (original17 plus6 new) and **14 independent fully mocked source controls**. The authoritative full test run uses ordinary metadata files plus mocked special-file types/races and no real device, FIFO or socket node. An earlier full run inherited the legacy owned-FIFO fixture; that superseded test/source/log/receipt is retained explicitly, and the final test replaces it with an ordinary-file mocked FIFO type. No actual camera/device driver operation occurred in either run.

Controls confirm path-only binding and type/link/size refusal precede derived read open; the derived descriptor refers to the held inode and a replaced basename cannot select another read inode; named/derived/pointer/link-count drift fails; close-error cleanup still attempts both descriptor closures; missing O_PATH fails before read_at opens anything. The independent review assumes trusted Linux procfs FD-link behavior; it exercises mocked ordering/identity checks, not a kernel implementation or camera support.

| Corrected receiver hold | SHA-256 |
| --- | --- |
| probe.py | `0703071e7e6dcdc7929eb38af74bd5bcf733cc8883cb705dad5c3418e32ecddd` |
| test_probe.py | `278e9edbc5ef8e9811b6734147be0306a10899179aeadd5589b48ea5e5710967` |
| Authored test receipt | `a694e3db2dca72da941716c2cbde8f599298198c91096470f9ce96f4df2fd1d3` |
| Independent source receipt | `6f2c1ba4b2f41a1eb0c468a74170382c3c369f411aa73eed6ff8d5a34cad6661` |

The new correction handoff is held for the same root peer recheck. Capture, firmware, generic preview, installed source/package correspondence,16K and physical model acceptance remain NOT RUN; this receiver correction cannot close the core camera gate.

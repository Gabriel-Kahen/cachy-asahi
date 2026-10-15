# Native offline LSP interface and DSP-property validation — 2026-10-15

Run [38804130326](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38804130326) completed successfully. The retained public projection reconciles to **one exact native package rebuild, successful RTLD_NOW loading, and all 48 fixed offline property cases in 96 fresh instances**. This advances the bounded software trial from source-audited to native compiled/linked/executed. It establishes neither active compressor/loudness algorithm fidelity nor full Asahi graph, installed-system, acoustic, speaker-protection or M2 acceptance.

## Identity and evidence boundary

Root bound Source `9ed7162ccdf71ea937f95777726e3c68aa04d638`, isolated Workflow `a1a84d01043b668b4dd5e68b77e8996b016e4316`, and ref `codex/asahi-lsp-offline-v1`. Retained checkout logs confirm the Source and unchanged product API `db1010de321cc056a01672f006e6cc25d3c8a8b7` and 574 preparation source `8d8e2f5d5a94ab3ebee2d8b1cc20aecf98e435e2`. The review uses Root's once-collected logs; it performs no online recollection, build, plugin execution or source/binary extraction.

- Retained `artifacts/development/asahi-lsp-offline-run38804130326/logs.zip`: 85,659 bytes, SHA256 `1ea4d02de51343417c3772c311fcf2a09539bad484a45ee076aa6790c7c2120f`.
- Decoded the dedicated public-observation step exactly once: 24,985-byte compressed frame, SHA256 `2d67cc9d9d056bcc9f101422663aae625cb511c335cdbcfc68cea4f70e5d322e`. The identical frame in combined logs was not decoded again.
- The frame contains exactly three regular JSON files: `build-1.json` (86,801 bytes, SHA256 `17b666cfa3c3b1e303b5853745cda48f0a19ea1fdd5472ef968ce40c8417dd6f`), `result.json` (3,665 bytes, SHA256 `57aab3b7be604b574cc9406e62d06a465df4156b1ce041dbe2df6c09dd86d0f4`), and `runtime.json` (43,379 bytes, SHA256 `9cf49786791437b006502fb84b737e98faa27859e102e3d0d6f0fe5a427d3dde`). Copies are in that run directory's `public-review/`.

[projection-receipt.json](../../artifacts/development/asahi-lsp-offline-run38804130326/projection-receipt.json) pins transport and files. The passive [audit.py](../../artifacts/development/asahi-lsp-offline-run38804130326/audit.py) independently checks those retained JSON files against accepted hashes, inventory reconstruction, exact profiles/grid, finite metrics and cleanup structure; its [review-readout.json](../../artifacts/development/asahi-lsp-offline-run38804130326/review-readout.json) records PASS. It executes no trial actors. Runtime controller hashes match all eight previously reviewed source files exactly, including C host `c5c571e50987d6acc1fdbb279a2131d4ddf97b1f6b057c49d1b6075b4df7f168`, container `b1af113aaadcc9ca828e501b963e666cdd2dc79f421cf59c7915f63a82f35542` and caller `07d0a0fb495c422dc392a28b516b63c6fd5cac617c7ede5e32f7e80b4464d8d1`.

Public evidence contains selected metadata, hashes and metrics. Actual package/library/host bytes, TTLs, samples, raw compiler/plugin/readelf diagnostics and private signature receipts were not exported. Their hashes and runtime checks are runner observations validated by the frozen code; this review cannot independently rehash removed binaries or reconstruct per-sample output from the public projection.

## Exact rebuild and unchanged environment

`native_rebuilds=1`, `package_pair_repeated=false`; only `build-1` appears, with 15 bounded prerequisite/stage markers and no failed marker. Standard `build.py`, the adopted recipe, upstream source SHA256 `2c95ec7bb219d561ea3db36051b6c732133bcd76426fb836b1dd850dc4b5bb6c` and epoch `1787491172` remain held. Effective flags show LV2 only, generic `-march=armv8-a -mtune=generic`, O2 and no LTO/mcpu substitution.

| Object | Observed result |
| --- | --- |
| Package archive | 2,297,536 bytes; SHA256 `8fbd603732c505a36cf57be2163cb96b5bd0a13171d64c6104ea6a6c8b1a8791` |
| LV2 library | 11,050,096 bytes; SHA256 `b11bb9851ac3153ffe8b423d591133d4f48bd12cb9508c8c7080f93b6a906a84` |
| Package contents | 215 members: 7 directories, 3 package-metadata files and 205 regular payload files; one library, 199 TTLs and five notices; payload 24,305,211 bytes |
| Runtime inventory | 574 packages before and after; unchanged; SHA256 `cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac` |

Archive and library hashes match the accepted native build pair from run38797402321. This new trial is a single matching rebuild, not another package pair or independent-machine reproducibility result. Payload ownership/modes/epoch match the held contract. Independently normalizing all 574 `.BUILDINFO` installed entries reproduces the same inventory hash as both runtime inventories and owner/base record.

The 574 preparation record reports the unchanged required pinned-keyring offline transaction, native build PASS and 1153 authenticated input objects. That count includes the helper's acquired object set; it is not 1153 separate package-signature receipts. Raw verification receipts stay private. No package installation or runtime package-database change occurred in this trial's reviewed path.

## Host, loader and actual candidate interface

The generic AArch64 C host compiled and linked against the pinned system Lilv/LV2 headers without adding dependencies. Host binary SHA256 is `cf5becf81ce16db8e047a566561cc633ccf09e86e6ec361396dd9a3fe9380fc5`; public observations retain compiler/pkg-config/readelf/lilv.pc hashes and compile flags. All three audited header hashes match. The isolation stage passed the frozen ordinary-user, read-only mount/database, no capabilities/no-new-privileges, loopback-only and `/dev/snd`-absent assertions. The caller supplied network none, no audio/runtime sockets or devices, two CPUs/1 GiB/128 pids and the fixed deadlines. These are software-container observations, not measurements of a Mac's audio environment.

The exact library's separate `RTLD_NOW|RTLD_LOCAL` probe passed symbol-origin and bounded descriptor checks: 198 descriptors enumerated, three selected literal URIs found, no instance created by the loader. There are 39 normalized loaded identities: one exact candidate, 37 system libraries and virtual vDSO. Observed canonical paths were hashed privately before normalization. This includes transitive Cairo/X11 libraries; it does not imply a UI/display/session test. The loader inventory is not a complete claim about optional dependencies that might load during later processing paths.

Host and candidate ELF observations report ELF64/AArch64, two PT_LOAD segments, no RPATH/RUNPATH, and structural 16 KiB checks PASS. Candidate DT_NEEDED is `ld-linux-aarch64.so.1`, `libc.so.6`, `libcairo.so.2`, `libm.so.6`, `libsndfile.so.1`, `libstdc++.so.6`; host needs the loader, libc, liblilv and libm. Version requirements are recorded, including candidate GLIBC_2.43. This proves loading in the exact selected environment, not compatibility with an arbitrary older userspace or actual 16 KiB/M2 execution.

| Selected suffix under `http://lsp-plug.in/plugins/lv2/` | Actual ports | Asahi control bindings | Audio channels |
| --- | ---: | ---: | ---: |
| `loud_comp_mono` | 23 | 4 | 1 in / 1 out |
| `mb_compressor_stereo` | 319 | 21 | 2 in / 2 out |
| `compressor_stereo` | 68 | 6 | 2 in / 2 out |

The host validated all 31 selected URI/symbol bindings as control inputs, actual defaults/ranges/enums and the exact Asahi overrides. The projection matches the reviewed profile data; unspecified input controls retain actual TTL defaults, including multiband band7. Required-feature lists contain only `urid:map`; a real stable bounded URID map was supplied. Actual `in_ui/out_ui` metadata permits NULL connections. This evidence concerns the three individual plugins, not the full speaker or microphone graphs.

## Fixed numerical cases

Four profiles × rates 44100/48000/88200/96000 Hz × zero/bypass/synthetic fixtures make exactly 48 unique cases, all PASS; each ran in two fresh sequential instances, 96 total. Each instance used 96 blocks × 256 frames = 24,576 frames (32 settling, 32 stimulus, 32 flush). No case or rate was skipped or retried.

| Profile | Reported latency at 44100 / 48000 / 88200 / 96000 Hz | Largest reported synthetic peak |
| --- | --- | ---: |
| Loudness `volume=0` | 7680 / 7680 / 7680 / 7680 frames | 0.000900018553 |
| Loudness `volume=-47.5` | 7680 / 7680 / 7680 / 7680 frames | 0.000036226917 |
| Asahi woofer multiband | 220 / 240 / 441 / 480 frames | 0.001322969794 |
| Asahi woofer limiter | 220 / 240 / 441 / 480 frames | 0.000899999985 |

Every latency is finite, integral and within the declared 0…8192 bound; the hash-bound host asserts stability after settling and equality between fresh runs. All 16 silence cases report peak/RMS exactly zero, within the ≤1e-7 gate. All 16 channel-correct latency-shifted bypass cases report maximum error zero, within `1e-7 + 1e-5*abs(expected)`. Every configured-synthetic case has finite audio, positive post-settle energy above 1e-20 and no all-sample runaway violation of peak 16. Reported peaks/RMS are post-settle metrics; the C runaway guard additionally covers settling samples. Peak 16 is an engineering bound, not an acoustic safe level.

All 48 case pairs report maximum full-buffer repeat error zero, meeting `1e-6 + 1e-5*abs(reference)`. Each pair's FNV1a64 identifiers also match; these identifiers are noncryptographic and do not replace the numeric comparison. Buffer/control guards and audio/control input immutability are runtime assertions in the frozen host. Retained metrics permit independent finite/grid/threshold checks; samples are deliberately absent, so the reviewer does not recompute the elementwise oracle from output waveforms.

These checks establish bounded silence, delayed bypass, finite/nonzero synthetic output, validated Asahi control compatibility and same-platform repeatability. **Active compressor/loudness algorithm fidelity remains NOT ESTABLISHED**: no reviewed transfer-function, gain-reduction/frequency-response or golden-reference oracle was added. Small synthetic signals and a PASS do not exercise or establish the limiter's protective behavior at real speaker drive levels.

## Scoped cleanup and remaining acceptance

Caller cleanup PASS verifies absence of exact build container `cachy-asahi-e78f1585f7c848e1` and runtime container `cachy-asahi-lsp-offline-316b456c50394274`, plus removal of private trial data. The caller preserves its borrowed builder; owner cleanup subsequently verifies removal of its newly owned image `sha256:25a04124c6da5e76edfc088fdf4d19536ef2e875d08011f1f4147d53c465088c` and private job tree. Seed/build/trial phases and owner cleanup all PASS; no cancellation is reported. These are exact-resource normal-completion observations, not whole-daemon/cache cleanup claims.

The unchanged 8d8 bootstrap/inventory-probe cancellation ownership gap remains **UNKNOWN/FAIL**. This successful normal run does not prove cleanup after cancellation or eliminate unnamed daemon-side work in that failure branch.

Full Asahi graph routing, Bankstown/Triforce/convolvers/FIR adaptation, PipeWire volume policy, speakersafetyd, installation/removal/recovery, actual 16 KiB/M2 hardware, acoustic safety and performance remain NOT RUN. Distribution/provenance/license closure is not advanced by this private runtime trial. `selected_for_release=false`; no manifest or release selection is changed by this record.

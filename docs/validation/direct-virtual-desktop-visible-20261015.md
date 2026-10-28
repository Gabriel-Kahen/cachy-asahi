# Direct generic ARM desktop visible-client trial — 2026-10-15

**Both actual captured clients pass independent visual review by the worker and Root.** Minimal and packaged-overlay frames each show a full, readable Wofi window with the expected prompt and both supplied rows. Runtime mapping, acknowledged clean compositor shutdown and cleanup also passed. This is a bounded generic ARM software-rendering result, not target-system or hardware acceptance.

## Exact trial

- [Actual run 38792647293](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38792647293), attempt 1; automated job SUCCESS as reported by Root.
- Product `6e7d18a1c79e27fc6a236777a944ae2389dc259c`; workflow `8774d35b63a77cff50588ae10c75ba81b06f925f` (Root's frozen dispatch identity).
- Native host and Docker daemon aarch64; generic aarch64 guest under QEMU TCG, virtio GPU, kernel `7.2.10-1-aarch64-ARCH`,4096-byte pages.
- Mesa 26.2.4/LLVM 23.1.1 llvmpipe, explicit guest `LP_NUM_THREADS=0`, `GALLIVM_PERF=nopt`, shared by the GBM correctness probe and both phases. This is a diagnostic software-rendering profile, not measured optimization.

The product requires an exact own-PID mapped client with strict visible=true and hidden=false plus valid positive integer goal dimensions. It refreshes j/clients once at the existing capture point after 5s, under the original 15s live-window end, and emits only the fresh ready observation. The original 45s mapping and shared 15s acknowledged shutdown/reaping budgets remain held. Geometry, animations/effects, backend and expected content were preserved. The additional query consumes existing capture time; no new host-capture completion guarantee was added.

## Original-frame evidence

Root collected public logs once at `artifacts/development/virtual-run38792647293/logs.zip`. The review used only those retained bytes. The aggregate log contains line-leading UTF-8 BOMs on three lines; normalization removed those prefixes before CI timestamps. Every decoded selected bundle still matched its declared compressed byte count and SHA256. Safe regular tar members were read without path extraction. Each original PPM then matched the result's SHA256, P6 header,1024×768 dimensions and exact RGB payload length before preview generation. All nine executing runner hashes match the exact product via local git show.

Verified originals, lossless PNG conversions, sanitized public results/events, source/bundle checks and decoded/hash-verified session logs are retained under `artifacts/development/virtual-run38792647293-review-20261015/`. The PNGs only convert the original pixel format. They were opened through view_image for the actual visual decisions below.

| Phase | Fresh mapped client | Actual visual assessment |
| --- | --- | --- |
| Minimal Lua fixture | PID 298, mapped=true, visible=true, hidden=false, goal position302,274 and size420×220 | PASS for this frame: full readable Wofi, prompt “Generic ARM software proof”, selected “cachy-asahi software proof” row and “No Apple hardware claim” row, against the rendered wallpaper. |
| Packaged overlay Lua configuration | PID 356, same strict flags and goal geometry | PASS for this frame: same full readable client and both expected rows, against the rendered wallpaper. |

Both originals contain 2,359,312 bytes. Minimal SHA256: `a6d7da6a4f9c2fd31d9ad5cfe6ac955ec98b7a29ec60f7f5c5235595060e8190`. Overlay SHA256: `b80fb0fe66dbe234649c80901d124fa35d64f69a8838c9e9f6f8ff77db855312`. Their 2963 and 3099 distinct RGB values are supplementary metadata, not the visual acceptance criterion.

Public JSON remains `CAPTURED_REQUIRES_VISUAL_REVIEW`/`visual_review: NOT RUN`: it was produced before manual inspection and is preserved unchanged. This document records the later review separately. Root independently opened both exact PNG previews and confirmed the full readable Wofi prompt and both expected rows in each frame.

## Runtime, lifecycle and cleanup

Both frame_ready, phase_pass and final guest_pass events are retained. The exact executing source emits phase_pass only after fixed Lua exit `/dispatch hl.dsp.exit()` receives exact ok plus EOF and the compositor exits 0 within the shared 15s budget. Raw acknowledgement/exit values are not separately exported; that conclusion combines the retained phase events with verified source. Client health and bounded logs remain checked through the live window, followed by intentional termination. Cleanup occurs before the next phase.

The public event list is an explicit sanitized projection; client_ipc records are excluded by the controller allowlist. Its absence from the projection does not mean queries were skipped or that the list is complete raw telemetry.

The 64×64 magenta GBM correctness probe passed. Fixed installed SVG decode passed at 128×128 with expected MIME cache. The private tooling inventory contains 366 packages, SHA256 `7c7748169b459eec23df92fb8e732a574b30f9d54b1bf052e3fb116a5d6dcc72`. Package-only fixture, signer, lifecycle, repository and desktop checks passed. Onboarding and source-suites were explicitly not selected.

All four owned containers and the private tooling image/tag have absence verified. Private workspace cleanup passed. The outer installed image also has absence verified with no cleanup uncertainty. The development signer/package trust scope is unchanged.

## Integration and limits

Relative to Root's integrated baseline `14f5dd23157b934d0700b0514559826175bb5412`, the tested product differs in exactly six virtual files: controller.py, guest.py, test_capture_shutdown.py, test_clients_ipc.py, test_run387645.py and test_tcg_shader_profile.py. The exact paths and both revisions' SHA256 values are in the owned `integration-files.json`; `integration.patch` contains only those six diffs. This document is the additional validation record. Root adopted these exact six tested files into the integration branch alongside this record.

The earlier run 38784585311 remains visually failed; run 38788251513 retains overlay-only visual credit and overall failure. This trial supplies the previously missing two-phase visible-client evidence, without turning any prior failure into a pass. It is one trial, not a repeatability or causal attribution study. Source and 13 focused readiness checks were reviewed before dispatch; no broad suite or unchanged runtime actor was rerun during this evidence review.

Reported guest elapsed 294.289s is an uncontrolled observation. No performance improvement is claimed. Goal geometry and visible flags do not expose animation completion or presented output; original pixels supply this trial's additional evidence. Client-only NO_AT_BRIDGE=1 remains an accessibility isolation, so accessibility acceptance is NOT established. Generic 4K-page frames do not establish Apple/M2 compatibility, 16K pages, hardware acceleration, target installation/removal, the full supported package transaction, hardware/user workflows, production trust or full-port completion. The separate GSettings-cache proposal remains held and was not needed to classify these two captured clients.

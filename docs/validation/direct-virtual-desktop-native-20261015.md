# Direct generic ARM desktop trial — 2026-10-15

**Runtime gates passed; overall visible-client acceptance failed.** Both Wofi clients mapped and both compositor phases exited cleanly, but the minimal capture shows only a small, very dark Wofi window and the overlay capture shows no visible Wofi. The GitHub job's success is not a two-phase visual rendering pass.

## Exact run and scope

- [Actual run 38784585311](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38784585311), attempt 1.
- Product `f7dbaa4e8211747c76a2b3bfd679096865025a3c`; workflow `cd9dcf7f00476914d2d9328dcf31b8693f597a47`.
- Native host and Docker daemon: aarch64. Guest: QEMU TCG generic aarch64, kernel `7.2.10-1-aarch64-ARCH`, 4096-byte pages, virtio GPU and llvmpipe. This is not an Apple machine emulator or hardware trial.
- Mesa 26.2.4/LLVM 23.1.1 software profile: `GALLIUM_DRIVER=llvmpipe`, `LP_NUM_THREADS=2`, `GALLIVM_PERF=nopt`; the explicit profile applies to the GBM correctness probe and both phases.
- The disposable Wofi client uses `NO_AT_BRIDGE=1` to isolate the observed AT-SPI startup problem; accessibility activation is not accepted by this run. The packaged product defaults are not changed by that client-only setting.
- The original 45s mapping deadline, 15s client live/capture window (capture requested after 5s), and shared 15s acknowledged shutdown/reaping budget remained held.

Root retained ordinary public logs once at `artifacts/development/virtual-run38784585311/logs.zip`. Verification/extraction used those existing bytes; no recollection, repeated runtime actor or synthesized image was used. All nine actual runner hashes match the frozen product, including guest SHA256 `7cda59c7c37bccc389d13b65a7fa4eb7f0e2aa72125b1f9a31f76b6afe03be38`.

## Runtime observations and visual decision

| Phase | Actual mapped client | Captured frame | Root's actual-frame visual review |
| --- | --- | --- | --- |
| Minimal Lua fixture | Wofi PID 320, mapped=true, size 420×220 | 1024×768, 178 RGB values | Limited visibility: very dark Wofi/text row around x 465–558, y 358–409, approximately 94×52 physical pixels. This does not establish the expected full visible client. |
| Packaged overlay Lua configuration | Wofi PID 380, mapped=true, size 420×220 | 1024×768, 94 RGB values | FAIL: cursor/footer/dark desktop only; no visible Wofi window. |

Both frame_ready events satisfy the strict own-PID, mapped-is-True and exactly-two-positive-integer size predicate. The pending clients socket query therefore succeeded in both phases inside the held mapping budget. These reported dimensions are distinct from actual visible pixel bounds.

Both phase_pass events and guest_pass are retained. The verified executing guest emits phase_pass only after the fixed Lua exit request `/dispatch hl.dsp.exit()` obtains exact `ok` plus EOF and the compositor is reaped with return code 0 within the shared shutdown deadline. Phase cleanup finishes before the next phase starts. Raw acknowledgement/exit-code values are not independently exported as events; this conclusion combines the retained phase events with the exact verified source. Client health/log checks span the live capture window, with intentional client termination afterward.

The GBM correctness probe passed. The fixed installed SVG again decoded at 128×128 with its expected MIME cache. These smaller checks do not establish Wofi presentation. Frame color counts also do not prove expected client content: cursor/footer pixels account for colors in a background-only capture.

Root visually inspected lossless PNG conversions of the verified original PPMs and supplied the decision above. The conversions change only the file format; original pixels/PPM bytes remain held.

| Original | Bytes | SHA256 |
| --- | --- | --- |
| minimal.ppm | 2,359,312 | c7080a46ce567472a780c672815e528156817d8afab26f562fc2a69438974270 |
| overlay.ppm | 2,359,312 | 334c0fbd8fb744665bfbffbae5dddaaaf18799ecb39340d222d31a3662ed0ea5 |

Originals, display conversions, verified frame paths and retained event/result JSON are under `artifacts/development/virtual-run38784585311-review-20261015/`. Extraction checked public bundle byte counts/SHA256, then each original's report hash, PPM header, dimensions and exact RGB payload length before writing the frame.

## Package lifecycle, cleanup and remaining limits

The package-only integration reports PASS for fixtures, signer, lifecycle, repository and desktop package checks. Onboarding and source suites were explicitly NOT RUN by this selection. The private tooling image contained 366 packages, inventory SHA256 `7c7748169b459eec23df92fb8e732a574b30f9d54b1bf052e3fb116a5d6dcc72`. Existing exact base/tooling inputs and signature rules remained held.

Cleanup passed with absence verified for all four owned containers and the private tooling image/tag. Private workspace cleanup passed. The outer installed image also has absence verified with no cleanup uncertainty. The run reported `CAPTURED_REQUIRES_VISUAL_REVIEW` for the virtual consumer; Root's later visual decision prevents claiming overall visual acceptance.

The evidence leaves presentation/animation/render timing unresolved. Mapping plus a fixed 5s delay did not guarantee expected visible Wofi content. The missing default GSettings source is independently observed and has a separate staged-cache proposal; its relationship to rendering is unproven. No unchanged runtime actor was replayed to obtain this record.

This single result establishes neither a performance gain nor repeatability. Guest elapsed 300.057s is an observation without a controlled comparison. Hardware acceleration, Apple/M2 behavior, 16K compatibility, performance acceptance, production trust and supported target-system completion remain NOT RUN or unaccepted. A subsequent source-reviewed correction must produce both expected visible clients without weakening the visual requirement or silently increasing deadlines.

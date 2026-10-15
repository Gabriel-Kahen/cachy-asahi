# Generic ARM VM installer barrier — 2026-10-15

[Run 38809298514](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38809298514), attempt 1, produced a source-bound **PASS_BARRIER_ONLY**. Source was `551b024230c6961811a7f8b71d25072bc15d91e6`; Root's workflow freeze names `28813de53e23e599be9b34cd7367d2f128e72bb9`. Checkout logs and the owner result agree on Source. Workflow success alone is not this validation: the retained public owner result, guest events, handoff receipts and cleanup records were checked together.

The fixture remains the exact three files from `d4313163538f51d85bc03e6a4adfde0c850cbc30`, including worker SHA256 `966aedf602511bedfc8ee8e12c29f21a7ff6b79523e4c5800b2a22a2af826eca`. The real selected VM-contract digest was used only for the maintained test's aarch64 routing. Its assertions and worker guards were unchanged.

Exactly `BarrierTests.test_actual_isolate_keeps_host_readonly_and_only_evidence_persistent` ran: **1 test, 0 failures, 0 errors, 0 skips**, no first failure. The ordinary guest parent was UID/GID 23001; the mapped child reported UID 0 and actual namespace changes. The exact selected report records:

- Effective, permitted and bounding capabilities `0x400cb`; inheritable and ambient 0; NoNewPrivs 1.
- All seven selected aarch64 service-IPC/io_uring syscall probes returned EPERM (1).
- The outside write was refused with EROFS (30); outside bytes and parent namespaces stayed unchanged.
- Guest-only bytes were absent from the parent view and the owned evidence marker persisted.
- The barrier initialized no libalpm handle and committed no package.

The nonce and proof-contract digest match the boot, barrier result, child-exit record and owner result. The retained boot reports generic aarch64 kernel `7.2.10-1-aarch64-ARCH`, 4096-byte pages. The ordinary child exited naturally 0. The source-bound owner result reports QEMU group retirement PASS with cleanup uncertainty false; selected Source requires natural QEMU exit 0 before this status, but does not export a separate QEMU exit-code field. All four exact virtual containers, its private tooling image/tag, private workspace and the outer lifecycle-installed image have matching scoped successful cleanup records. Outer cancellation is false. This does not establish daemon-wide absence or erasure of parent image layers.

The upstream development lifecycle handoff also joins: 166 lifecycle checks PASS, 361 committed-handoff checks PASS, 345 installed baseline packages and the 366-package prepared guest inventory. The four baseline versions were fish 0.1.0-1, zsh 0.1.0-1, Hyprland settings 0.1.0-2 and setup 0.1.0-3. Receipt bytes, image identities, complete original payload maps and inventory digests match the VM owner's selected inputs. This review did not decode original package/source/binary frames or independently redo package-signature/native-build verification.

Owner elapsed time was 169.768s; guest proof 99.368s; preparation 61.028s. These are execution durations, not comparative performance measurements.

Evidence: [readout](../../artifacts/development/installer-barrier-virtual-run38809298514/review/readout.json), [public frame index](../../artifacts/development/installer-barrier-virtual-run38809298514/review/frame-index.json), [Root freeze](../../artifacts/development/root-resume-20261015/virtual-barrier-freeze.json). Retained logs ZIP: 4,410,120B, SHA256 `7fd01d9671230fb1f767fb9854ab2670317c30de09b4819ec7600b0e88e4b614`. Selected public frame digests and bounded payloads match both the native-step and aggregate log copies. No network, VM, signing, package or P0 actor was replayed during review. Workflow conclusion/OID remain Root's captured observation/freeze; no new API check was made.

This is **generic 4K QEMU TCG barrier validation**. Native-container P0 remains failed on its separate PROC_MOUNT route. No ALPM entry/transaction by the barrier, full installer matrix, desktop rendering, hardware acceleration, performance improvement, 16K compatibility, Asahi target transaction or M2 validation is established. Production trust and release selection remain NOT RUN/false.

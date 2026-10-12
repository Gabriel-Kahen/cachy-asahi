# Independent held virtual adapter 86-test review

2026-10-12. **BLOCKED by one newly reproduced P2 late-cancellation defect on the exact held source.** The three preceding publication defects are closed on this checkpoint. The fresh copied suite passes **86 tests, zero skips**. Corrected native guest execution, visual review, M2/16K hardware and performance acceptance remain **NOT RUN**.

This review owns only this document and `artifacts/reviews/virtual86-root-peer/`. No implementation, locks, pin metadata, Git state, workflow dispatch, Docker/QEMU, installation or network acquisition was changed or executed. The roadmap and development-only package inventory remain applicable.

## Exact held source and independent checks

Verified `/tmp/virtual-adapter-cleanup-fix-j7st5art/held-receipt.json` against actual bytes, sizes and mode0644:

| Input | SHA256 |
| --- | --- |
| `scripts/ci/development/virtual_stage.py` | `cdc616710b1f5e7b3d9652e887e24802aa1bbe1d4ee2e35a863a41551980a378` |
| `scripts/ci/development/test_virtual_stage.py` | `00a9edba0a21275179f7eeec7888b0d1f8f8b15fe2f329794c8a175f640d3f84` |
| `docs/workstreams/virtual-qemu-adapter.md` | `143dde58b087f9732554458e9c6b2cf89efc387e5dc48a84a34a1f445868b3e7` |

Copied the adapter, test, development common helper, generic exporter and nine virtual packet files into a fresh independent **13-file tree**, without links to the checkout. Ran unittest discovery under `python3 -I -B -Werror::ResourceWarning`: **86 discovered/run, zero skips/failures/errors, 6.119 seconds**. Post-test rehash/mode comparison found no drift, symlinks or bytecode files. The suite contains mocked acquisition/owner/native/signing fixtures and actual temporary-file and bounded subprocess/signal checks; it establishes no new native or cryptographic execution result.

I independently verified all six separately held virtual owner source/test hashes and both metadata hashes against the actual committed Git blobs in **`ec96e2b08a8873d9615e6c2758ebeec39a5d9d13`**, with exact equality. The tooling lock remains `a8060f5dab01277de200fb7c9a4418b565984eb6d1cfb4971f0a3bd013ee8073`; the audit remains `cd11a837b29e5c757b482a79b375f65170881d73f80db4ae645ed600a45378cd`. The captured source-packet, 21-package/45-object closure, 341/345/362/366 inventories, canonical capability digest and all-four-PASS prerequisite remain enforced. This is a read-side closure check for those inputs, not approval of a new complete development packet or native dispatch.

## Three preceding P2 findings closed

The [preceding independent review](virtual-adapter-publication-final-review.md) remains historical evidence about source `8ee546cf…`. Its producer/transport/native authority mocks were retained when adapting its probe entrypoints to this exact held copy; only expected hashes, copy paths and post-fix assertions changed.

- **Frame integrity and inventory:** replayed all ten real mutations immediately before or after the minimal-frame rename: changed PPM bytes, changed receipt bytes, and extra file/directory/symlink. Every schedule now returns adapter FAIL, refuses selection of the frame directory and retracts the owned target. Captured bytes, canonical complete receipt and exact two regular children are checked before and after rename.
- **Complete quarantine and cancellation:** the exact overlay rename/SIGINT/first-quarantine-deletion-OSError schedule now quarantines both owned frames before deletion attempts. The mutated overlay is absent from `public_paths()`, and cancellation propagates as cancelled FAIL even when private deletion fails. Repeated INT/TERM text and frame deletion-error schedules also preserve cancellation and restore handlers. Foreign replacement/existing quarantine preservation is covered by the fresh suite.
- **Transactional handler entry/restoration:** the original actual TERM-after-first-INT-handler-install schedules now restore caller handlers and produce final acquisition/result receipts for outer finalization. The copied suite also exercises INT and TERM during direct/outer installation and restoration, preserving the caller's mask and cancelled FAIL. The distinct final-unmask gap below is not closed by these tests.

The complete replay contains **31 publication schedules and eleven bounded signal-child schedules**. It also reconfirms prior immutable raw result/event snapshots, all seven failed-capability guest success/review claim refusals, twelve accepted/refused text member-injection schedules and four real INT/TERM rename-before-registration schedules. No unvalidated mutated frame completed PASS in the ten frame schedules.

## P2 — TERM at final mask restoration retains a saved PASS receipt

Location: `virtual_stage.py` `defer_finalization()` final `signal.pthread_sigmask(SIG_SETMASK, mask)` and `run_virtual()` outer finalization immediately after that context.

The helper restores the caller's handlers, collects pending originally-unblocked INT/TERM into `events`, then restores the mask. A signal queued **after pending collection and immediately before this final mask restoration** executes the restored caller's raising handler. `KeyboardInterrupt` escapes the context, so `run_virtual()` never reaches the following `if events` FAIL reseal. The already-written result stays **PASS / phase complete / visual review REQUIRED**, despite the cancellation exception propagating.

Independent `final-unmask-probe.py` uses a bounded isolated child, the held fixture's normal successful synthetic owner response, the same raising caller signal handler used by the development controller, and **actual SIGTERM**. It injects only when the stack contains the outer `defer_finalization`, both final receipts already exist, and the caller handler has been restored. Earlier acquisition or publication mask restoration is excluded. The final receipt is captured before temporary cleanup.

Actual outcome in `final-unmask-probe.json`: TERM injected; `KeyboardInterrupt` escaped; both handlers and original mask restored; **saved receipt status remains PASS** with owner `CAPTURED_REQUIRES_VISUAL_REVIEW`, cleanup PASS and visual review REQUIRED. Public result/events/frames remain selected. Transport, owner and native identities are mocked; the signal delivery, receipt writes and filesystem observations are actual. This is not an observed hosted incident or a native guest PASS.

Required correction: ensure cancellation escaping the **outer context restoration itself** seals cancelled FAIL before it propagates, including repeated signals during the reseal. Preserve prior handler/mask restoration, originally blocked signals, finite public grants and all publication retraction checks. Aggregate-controller failure is not a substitute for the adapter's promised authoritative cancelled-FAIL receipt. This finding was sent to the coordinator immediately; source remains held for correction.

## Retained evidence and limits

All paths below are within `artifacts/reviews/virtual86-root-peer/`:

- `copy-manifest.json`, `source/`, `tests.log`, `review-receipt.json`: exact copy, all eight committed owner/metadata pins, 86-test result and post-run checks.
- `publication/probes.py`, `publication/receipt.json`, `publication/replay.log`: 31 original mutation/claim schedules against corrected bytes.
- `signals/probe.py`, `signals/receipt.json`, `signals/replay.log`: eleven original bounded signal schedules with corrected expectations.
- `final-unmask-probe.py`, `final-unmask-probe.json`: the new actual TERM counterexample and saved receipt.

The owner's 16 causal pre-fix failures and working/copied 86-test passes are retained in its handoff, separately from the actual independent checks above. This review closes the three specified prior mechanisms but **does not sign off source freeze or dispatch** while the final-unmask counterexample remains reproducible. Historical broader native failures are unchanged. Corrected native ARM/QEMU guest execution, independent visual review, accelerated Apple graphics, M2/16K validation and performance results remain open.

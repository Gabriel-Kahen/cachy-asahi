# Independent final virtual adapter publication review

2026-10-12. **BLOCKED: three reproduced P2 findings on the held 82-test adapter. Fresh-copy suite: 82 PASS, zero skips. Corrected native execution NOT RUN.** Implementation, shared pins/locks, Git and dispatch were not changed. This review owns only this document and `artifacts/reviews/virtual82-updater-peer/`.

The roadmap/package inventory constraints and [prior review](virtual-qemu-adapter-review.md) remain applicable. The original raw receipt/event capture and omitted guest-claim findings are closed on this hold. The subsequent text child-inventory and text/frame rename-registration corrections also pass the independent schedules described below. They do not close the new frame-validation, multi-frame retraction and handler-entry findings.

## P2: frame publication lacks the complete pre/post-rename invariant

Location: `scripts/ci/development/virtual_stage.py:840–849`. The receiver validates captured source frames, writes selected PPM/receipt files, and checks only selected PPM bytes before rename. It checks neither the complete receipt and exact two-child inventory before rename nor any of those invariants after rename. Registration protects cancellation ownership, but does not authenticate the renamed directory contents. `public_paths()` selects the complete frame directory.

Independent real temporary-file mutations inserted an extra file, directory or symlink, changed the PPM, or changed `receipt.json`, immediately before and immediately after the real minimal-frame rename. **All ten schedules completed adapter PASS and selected the unvalidated frame directory.** The independent signal worker separately changed the renamed PPM without cancellation: selected bytes were 29 bytes/SHA256 `0ad4757aae525cfc6de114e2fcb8e1b7bad5a17cf64bd4c24093fea46b2e2d16`, while the frame receipt still claimed 35 bytes/SHA256 `7617a3b22d50f7795ddbfc6f3f1ca24da4e79615b23437f4f3d66242004bb3bb`.

Required correction: bind both PPM and complete finite receipt to the captured objects; require exactly those two regular files before and after rename; retract the owned directory on any mismatch. Keep capability, event, source and frame acceptance gates intact. These are local publication schedules, not evidence of a native ARM incident.

## P2: deletion failure aborts remaining frame quarantine and loses cancellation

Location: `virtual_stage.py:851–858`; analogous cancellation loss occurs in text retraction at `534–543`. The frame loop interleaves each public-to-private quarantine rename with deletion. An error deleting the first private quarantine stops the loop before the second public frame is quarantined. The exception also bypasses the subsequent deferred-cancellation propagation check.

An independent bounded child delivered **actual SIGINT after the real overlay-frame rename**, with both frames registered. Minimal frame moved into private quarantine, then a controlled deletion OSError stopped retraction. The mutated overlay remained selected by `public_paths()` with the 29-byte/hash mismatch above. Final status was FAIL/`virtual-input-unavailable`; cancellation did not propagate. Separate text and single-frame deletion-error schedules kept their sole target outside the allowlist but likewise lost actual repeated INT/TERM cancellation.

Required correction: independently quarantine every registered public target before attempting private deletion; aggregate quarantine/deletion failures without leaving later targets selected. Preserve and propagate observed cancellation even when deletion fails. Private deletion failure must not restore quarantined bytes to the public allowlist.

## P2: interruption during handler installation bypasses restoration and final receipts

Location: `virtual_stage.py:675`; outer finalization call at `905`. `defer_finalization()` installs INT and TERM handlers in a comprehension before entering its `try/finally`. A signal after the first installation can execute the still-old second handler and interrupt construction before restoration is established.

Two independent bounded-child schedules delivered **actual SIGTERM immediately after SIGINT handler installation**. The direct helper schedule left SIGINT changed. The schedule targeted specifically the outer `run_virtual()` finalization entry after fixture receive/publication: KeyboardInterrupt escaped, SIGINT remained changed, and both `adapter-status/acquisition.json` and `adapter-status/result.json` were absent. The prior TERM handler raised KeyboardInterrupt, matching the development controller's interrupt-handler behavior; the probe did not signal another process.

Required correction: make partial handler installation and restoration cancellation-safe, preserve the caller's handlers/mask, and defer pending cancellation until required final receipts are sealed. Test interruption during setup and restoration as well as inside the protected body.

## Independent checks that passed

- A fresh isolated source copy ran `python -I -B -Werror::ResourceWarning` through unittest discovery: **82 discovered/run, zero skips/errors/failures/unexpected successes**, 4.237 seconds. Thirteen required dependency files were copied with exact hash/mode manifest; no symlink back to checkout or bytecode import occurred. Source/test/workstream hashes matched before and after execution.
- **Twelve** accepted/refused text schedules inserted extra files/directories/symlinks immediately before or after real rename. Every schedule refused with `virtual-public-copy-drift` and removed the target from the public allowlist.
- **Two** independent prior raw-mutation replays retained exactly the captured failure result bytes and captured empty event list, despite later raw result/success-event mutation.
- **Seven** failed-capability guest success/review claims refused with `qemu-capability-success-required` before public creation: guest PASS/CAPTURED, frame PASS/REVIEW, compositor PASS/REVIEW and session IPC PASS.
- **Four** actual INT/TERM schedules at text/frame rename-before-registration propagated cancelled FAIL, restored handlers and retracted the selected target. Repeated actual INT/TERM during successful quarantine deletion also restored handlers and propagated cancellation.
- Read-only rehash confirms the six adopted virtual owner files, tooling lock `a8060f5d…` and audit `cd11a837…` are unchanged. Captured-validator AST isolation, finite capability schema, exact21/45/366 closure and unchanged signature/source/image gates were covered by the copied suite and source audit; no new cryptographic or native acceptance is inferred.

The publication worker ran 31 independent schedules; the signal worker ran eleven bounded child schedules (ten with actual local signal delivery and one additional no-signal frame corruption). The passing suite does not contain or close the three counterexamples above.

## Held inputs and retained evidence

| Held input (0644) | SHA256 |
| --- | --- |
| `scripts/ci/development/virtual_stage.py` | `8ee546cf1268c6783f2a6e9f0b756d6bc145004780614c515940b7cc620b5845` |
| `scripts/ci/development/test_virtual_stage.py` | `5938494a2612cab4c846354f0d43a1f56ac5465887f04ce9573bfc2e38e06242` |
| `docs/workstreams/virtual-qemu-adapter.md` | `e882fcf718b6cc4b6d5553b40c09db1939525347eac06be43224aaa99c20b5e5` |

Evidence below is relative to repository root:

| Receipt | SHA256 |
| --- | --- |
| `artifacts/reviews/virtual82-updater-peer/publication/receipt.json` | `9ca77c0183a370ac3a87bc567d0dc0bd359ee5245efda45e6b3e244dabcd01dd` |
| `artifacts/reviews/virtual82-updater-peer/signals/receipt.json` | `0e7b6d544f889e70800777424cd92945c25bb47fa6a90c60e1ce094ae4129c8f` |
| `artifacts/reviews/virtual82-updater-peer/fresh-suite/run-e9952364d157/receipt.json` | `94ade5bebf9c07ea8aa87c394bdc9c8db86a480174796bbdeeaddf14ac4e5924` |
| `artifacts/reviews/virtual82-updater-peer/hold-check.json` | `e7d480468c899d67dd14bb074dc7663a0a34da82b1e09f62278e73865737ddfa` |

Reproducers are `publication/probes.py` and `signals/probe.py` beneath the same evidence prefix. Their fixture transport, owner process, signing authority and native identities are mocked; bounded parsing/export, local mutations/renames and explicitly identified child signals are actual. No Docker/QEMU, native guest, installation, M2/16K-page, graphics-acceleration or performance acceptance occurred. Implementation remains held for coordinator-owned correction; this review does not approve source-packet freeze or dispatch.

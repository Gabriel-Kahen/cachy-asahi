# Independent virtual QEMU adapter review

2026-10-12. **ORIGINAL TWO P2 FINDINGS CLOSED; FOLLOW-UP PUBLICATION/RETRACTION CORRECTION IMPLEMENTED AND HELD FOR INDEPENDENT RECHECK. Current working and copied suites each pass 87 tests, zero skips. Corrected native execution NOT RUN.** This receipt does not independently close the final correction or approve packet dispatch.

Roadmap, package inventory and AGENTS.md were read for the preceding owner review; the same constraints apply. Sole repository file written in this task: this receipt. The preceding owner review was originally held at `02e8c09ca8de4063d9d565144cc3af0138e8c52ed6dc012866d9b8e7f31955a8`; the coordinator subsequently committed its adoption footer separately. No source, production pins/locks, Git or dispatch was changed.

## Original P2 history, now closed: publication capture binding

**`scripts/ci/development/virtual_stage.py:692,700–707,711–719,726–732`; shared copy path `502–507`.** `receive()` captures and validates the receipt/list and initially inspects events, but publication subsequently rereads raw files. The later event read does not repeat the four-PASS gate; `text_projection()` hashes/copies whichever bytes are present then, rather than binding the original validated bytes.

Two independent synthetic probes reproduced the gap:

- A failed owner receipt had one valid `version FAIL / capability-missing` capability row and initially empty events. After the first `read_events()` returned the empty capture, the owned raw event file was replaced with the fixture's seven valid boot/GBM/frame/phase/guest-pass events. The second read saw seven events, and `virtual-public/events/guest-events.json` retained all seven successful event kinds. Adapter final status was FAIL with `virtual-owner-acceptance-failed`.
- After `capability_receipt()` validated the same finite failed prefix, the owned raw result file was replaced with status `CAPTURED_REQUIRES_VISUAL_REVIEW`, `qemu_capabilities="UNVALIDATED_RAW_TEXT"` and boolean capability hash. That unvalidated changed result was retained in `virtual-public/result/result.json`, while the adapter finalized FAIL from the original captured receipt.

The final FAIL is accurate but insufficient: `public_paths()` selects these already exported directories (`496–499,834`), so downstream public evidence contains claims/data that never passed the gate. Receipt identity/event SHA checks (`733–766`) occur after text selection; on owner failure, event SHA/protocol acceptance is never reached. Neither late refusal retracts the exported result/events. This is a public-selection binding defect, not an observed native race. Bind publication to the same captured validated bytes/objects, including the event capability gate, and add regressions that mutate raw files between validation and selection. Preserve failure diagnostics through validated snapshots.

## Original P2 history, now closed: omitted guest success claims

**`virtual_stage.py:664–686`, especially `669–671`.** The captured predicate detects owner/guest CAPTURED/PASS status, frames, session IPC PASS and frame proof REVIEW REQUIRED, but misses `guest.frame_proof="PASS"` and `guest.software_compositor="PASS"` (also compositor REVIEW REQUIRED). This contradicts the documented prerequisite for any guest/frame CAPTURED/PASS claim (`docs/workstreams/virtual-qemu-adapter.md`, capability-validation section).

An independent fixture used the valid one-row failed capability prefix, owner status FAIL, guest status FAILED, empty frames/events and guest frame/compositor fields both PASS. The receiver published those PASS fields in `virtual-public/result/result.json`; adapter later finalized FAIL with `virtual-owner-acceptance-failed`. Require four PASS rows for every allowed guest success/review claim, or refuse unsupported guest field/status shapes before copying. This malformed-receipt probe does not describe normal authenticated producer output, whose standard captured state is already gated.

## Original independently verified checks and limits

- `python -B -Werror::ResourceWarning -m unittest discover -s scripts/ci/development -p 'test_virtual_stage.py' -q`: **69 PASS, zero skips, 2.705 seconds** on the exact held bytes. The owner's copied-tree test claim was inspected but not independently repeated.
- Source audit confirms the validator hashes the same captured run.py bytes before AST parsing (`630–661`). It extracts three literal constants and one undecorated, unannotated, no-default one-argument function; imports/top-level statements are not compiled or executed. The suite independently exercised poisoned imports/top-level code, executing defaults/annotations/constants, duplicate definitions and source drift.
- The suite exercised strict 21 distinct packages/both modules, 341 base/362 expected/345 original installed baseline, 366 tooling capture and 45 distinct acquisition objects; matching audit, source-packet and literal owner pin bindings remain required. Historical 19-package closure refuses before acquisition. Candidate/transport/native execution and signing authority are explicit temporary fixture drafts/mocks, not production adoption.
- Canonical capability hash and field-pair symmetry, closed finite row schema, unknown/poisoned fields, missing/failed success prefixes and initially hidden successful events are correctly refused by existing tests. The findings above concern later mutable publication and omitted success flags, which those tests do not cover.
- Probe receipt: `/tmp/virtual-qemu-adapter-probes-v3zkj_5u/receipt.json`, SHA256 `6ead78e8ed623f9feefc07fd268eebc9ed3f709292fc9e3c36a41df24d41e2cf`. Transport, owner process, native identity and cryptographic fixtures were mocked; bounded JSON/AST/selectors and raw mutations operated on actual owned temporary files. No Docker/QEMU, ARM guest, target system mutation, hardware, 16K-page or performance acceptance occurred. Unchanged package authentication was not broadened/repeated.

## Original held inputs

| Input | SHA256 |
| --- | --- |
| scripts/ci/development/virtual_stage.py | `e792c6f25f9dc045fc216daa768fd83e38c6f14dc1be68262c7b22ca2cc678d1` |
| scripts/ci/development/test_virtual_stage.py | `716530553a5a3ae2d95a65a1c8b732f16cb27a1829ea5d4e0c4756ee7661da5a` |
| docs/workstreams/virtual-qemu-adapter.md | `ff26ac608441cf59f931eac0d15a1f1ca692dcbcfd4b0d870b85ddcd7dd932c3` |

The original two findings above are closed by the focused correction below. Existing owner P2 canonical-hash closure remains valid and separate. The remaining receiver retraction findings prevent final adapter signoff; packet freeze/dispatch and actual native retry remain pending.


## Focused correction recheck and original closure

Independently authenticated the corrected source/test/document hashes below. Current command `python -B -Werror::ResourceWarning -m unittest discover -s scripts/ci/development -p 'test_virtual_stage.py' -q`: **79 PASS, zero skips, 3.354 seconds**. Inspected the owner's held-source/copied receipts `/tmp/virtual-adapter-p2-held-source.json` and `/tmp/virtual-adapter-p2-held-copy-review.json`; copied-suite execution was not independently repeated.

**Both original P2 findings CLOSED on these bytes.** Result/event bytes are captured once and reused for parsing, validation, public text selection and event hash/protocol checks (`virtual_stage.py:745–792,799,824`). Independent replay of the prior raw-file mutation schedules retained exact original validated failure result bytes and empty events. A failed partial prefix with frame/compositor PASS now refuses with `qemu-capability-success-required` before public creation. The finite guest-claim schema covers all seven success/review combinations (`710–741`); those cases and malformed claim shapes passed the independently executed suite.

The correction stages text privately, checks selected bytes, manifest/accepted bytes and exact staged children, rechecks manifest/accepted bytes after rename, and quarantines detected corrupt copies before deletion (`505–540`). The suite passed actual temporary staged-copy corruption, normal postrename corruption/retraction, repeated cancellation during quarantine deletion, quarantine deletion failure and late second-frame failure/retraction. That supports those tested schedules, but the two additional focused probes below expose remaining gaps.

## Remaining P2: exact child inventory is not rechecked after rename

**`virtual_stage.py:527–531`.** Before rename, accepted exports require exactly the expected data file plus export manifest (`521–523`), and refusals require only the manifest (`525–526`). After rename only manifest equality and accepted-file bytes are checked; child inventory and the refused-export empty branch are not revalidated. This falls short of the documented pre/post-rename exact public copy contract.

An owned temporary mutation inserted `unvalidated-extra.txt` containing `UNVALIDATED_EXTRA_PUBLIC_BYTES` immediately after the real rename returned, before the adapter's postrename checks. The file remained under the selected `virtual-public/result` directory and the otherwise valid fixture completed **adapter PASS**. The unexpected file was absent from the checked manifest and never passed the exporter policy. Repeat the exact child/accepted-file invariant after rename and retract/quarantine on mismatch.

## Remaining P2: interruption between rename and registration skips retraction

**`virtual_stage.py:527,532–537`.** The flag `published` becomes true only after `staged.rename(target)` returns. Cancellation after the rename syscall succeeds but before that flag assignment enters the exception handler with `published=False`, so the owned public target is not quarantined.

A bounded probe performed the real temporary-directory rename, changed the renamed result to `qemu_capabilities="UNVALIDATED_RAW_TEXT"`, then delivered actual `SIGINT` to the Python review subprocess before the patched rename wrapper returned. `KeyboardInterrupt` propagated; the adapter saved **FAIL/cancelled**, but `virtual-public/result/result.json` remained selected with the unvalidated string. This is an actual local signal and filesystem schedule within a mocked owner/native fixture, not evidence of a native ARM incident. Defer cancellation across rename plus ownership registration, or establish/reconcile owned-target cleanup before attempting the rename; retain a regression for this precise window.

Both independent replays and follow-up probes are recorded in `/tmp/virtual-qemu-adapter-recheck-9yz1yqkn/receipt.json`, SHA256 `628d32ab52ed867e76f473e2d64ee29e65435ca50eb519804719454a53d45cde`. Fixture transport, owner process, signing authority and native identities were mocked; mutations/renames and SIGINT were actual operations on private temporary review data. No source, shared locks/pins, Git, dispatch, system installation, Docker/QEMU, ARM guest, hardware or performance execution occurred. No unchanged cryptographic/kernel checks were broadened.

| Corrected held input | SHA256 |
| --- | --- |
| scripts/ci/development/virtual_stage.py | `3e10102c593ac9fbf028dcf225492cd171f8e5e1c6cf3badf55aa778d981d42b` |
| scripts/ci/development/test_virtual_stage.py | `656dccf09709bfe6c3ebec0547fb82e8957ff232e885f4904dbcb1226abbee4b` |
| docs/workstreams/virtual-qemu-adapter.md | `6082c5ae1972e0915427acf732cf70c7076abf24cc6f1590060fb81196a45bc2` |

The historical original review receipt was `ce232b8edbffd0690844f67da996a66424e76f9d9252ffff9db43b3ca564607a`; its findings/repro remain above. Current two P2 gaps require coordinator-owned correction and independent recheck. Native acceptance remains NOT RUN.

## Coordinator correction held; independent final recheck pending

Ownership of the adapter/test/workstream was explicitly transferred to this worker after the two follow-up counterexamples above. The current implementation applies the same complete manifest/accepted bytes/exact child inventory check before and after public rename, for both accepted and refused exports. It defers INT/TERM across rename plus publication registration, then propagates cancellation through the existing deferred quarantine/removal. Frame rename/list registration receives the same protection. Historical probe results above remain evidence about the earlier `3e10102c` source, not current failures.

The delegated regression worker owned only test_virtual_stage.py. Three new methods exercise six unexpected file/directory/symlink schedules, four actual bounded-child SIGINT/SIGTERM text/frame registration schedules, and repeated actual cancellation during retraction with handler restoration. Against the captured old source these produce ten expected failures (`/tmp/virtual-adapter-registration-red-47izysyx/red-receipt.json`, SHA256 `80cca833dbb0c7f8f9ee95e4ab70dc660e11fd55dc4a8001dd2cd163988ae6bb`). On the current source the worker coordinator executed the complete focused suite: **82 PASS/zero skips, 4.277 seconds**, and **82 PASS/zero skips, 4.330 seconds** in a fresh owned copied scripts tree. These are implementation validation, not independent acceptance of this final hold.

| Final implementation hold (0644) | SHA256 |
| --- | --- |
| scripts/ci/development/virtual_stage.py | `8ee546cf1268c6783f2a6e9f0b756d6bc145004780614c515940b7cc620b5845` |
| scripts/ci/development/test_virtual_stage.py | `5938494a2612cab4c846354f0d43a1f56ac5465887f04ce9573bfc2e38e06242` |
| docs/workstreams/virtual-qemu-adapter.md | `e882fcf718b6cc4b6d5553b40c09db1939525347eac06be43224aaa99c20b5e5` |

Source AST delta from the preceding hold is confined to `text_projection` and the frame publication registration inside `receive`. No six-file virtual owner source, shared lock/pin/manifest, Git or dispatch was changed by this correction. The root coordinator owns independent final recheck and packet integration. Actual native execution remains NOT RUN.

## Subsequent independent findings and current 86-test implementation hold

The separate updater peer's `virtual-adapter-publication-final-review.md` (SHA256 `d67278390736789a1a02f82a0d3e0198b5ce6096ad386ad0ddb158f90a174b10`) independently reproduced three P2 gaps on the preceding 82-test source: complete frame publication drift, first-quarantine deletion aborting later quarantine/cancellation, and signal handler-entry interruption leaking a handler and omitting outer receipts. That review is preserved and was not edited by this worker.

The current implementation binds exact PPM/receipt bytes and closed frame children before/after rename; checks exact canonical text manifest bytes; records publication device/inode ownership; attempts all owned quarantines before independent deletion with cancellation precedence; and avoids overwriting foreign targets or quarantine paths. INT/TERM setup and restoration now occur with those signals blocked, preserving handlers/mask. Originally unblocked pending restoration signals become deferred cancellation, and outer restoration cancellation reseals FAIL/cancelled status before propagation.

Four causal regression methods produce sixteen expected failures on the captured 82-test source, zero harness errors: `/tmp/virtual-adapter-cleanup-red-v_9l8y78/red-receipt.json`, SHA256 `37c1af95b9104b89d5955a095d33da8515a5696f2fb67f90a77465d5a592875c`. Current full focused suite passes **86/zero skips, 6.017 seconds** in the working tree and **86/zero skips, 6.048 seconds** in a fresh owned copied scripts tree. This is implementation validation; independent final peer closure remains pending.

| Current implementation hold (0644) | SHA256 |
| --- | --- |
| scripts/ci/development/virtual_stage.py | `cdc616710b1f5e7b3d9652e887e24802aa1bbe1d4ee2e35a863a41551980a378` |
| scripts/ci/development/test_virtual_stage.py | `00a9edba0a21275179f7eeec7888b0d1f8f8b15fe2f329794c8a175f640d3f84` |
| docs/workstreams/virtual-qemu-adapter.md | `143dde58b087f9732554458e9c6b2cf89efc387e5dc48a84a34a1f445868b3e7` |

No six-file virtual owner source, shared metadata/locks/pins, Git or dispatch was changed. Corrected native execution, hardware and performance remain NOT RUN.

## Final-unmask correction held; independent replay pending

Root's actual bounded TERM probe on the 86-test source (`artifacts/reviews/virtual86-root-peer/final-unmask-probe.py/.json`) observed restored-handler KeyboardInterrupt after pending collection at final SIG_SETMASK, while the durable receipt remained PASS. The current finalization catches that context-exit KeyboardInterrupt and reseals FAIL/cancelled under a fresh deferred scope before propagation. Recovery result/public-path updates and save are protected together.

Four exact actual child INT/TERM schedules, including repeated recovery-unmask cancellation, fail on the captured old source and pass on this hold. RED proof `/tmp/virtual-adapter-final-unmask-red-qvb6bn_g/red-receipt.json`, SHA256 `dd17ffb44962e25352f487cffbecad04f0c8dc43221bb5cd5d2c19330cf3cf4b`. Current focused suite: **87 PASS/zero skips, 6.785 seconds** working and **87 PASS/zero skips, 6.799 seconds** copied. Only `run_virtual` production AST changed from the previous hold.

| Current finalization hold (0644) | SHA256 |
| --- | --- |
| scripts/ci/development/virtual_stage.py | `8f32213f275e70bd177ed432f381a2bf51193ee85d0aa3a0b912e883a3ae60c3` |
| scripts/ci/development/test_virtual_stage.py | `cec622cc81f6c99e01f71e2be1672be17ee6ca92027aac253c8e55a7f80c2958` |
| docs/workstreams/virtual-qemu-adapter.md | `488945ddda734e5142a57bf90a2cd9130e86ad3e61ae45642f8605868cf307d3` |

These results support the catchable caller KeyboardInterrupt path, not arbitrary termination after persistence. A default terminating signal, SIGKILL or other process failure after the cutoff can prevent resealing. Native acceptance must require uncancelled normal completion in addition to matching receipts; an earlier PASS file alone cannot establish acceptance. Actual default-handler/native termination was not tested here. All owner sources/shared metadata/Git/dispatch are unchanged; independent final closure and native execution remain pending.

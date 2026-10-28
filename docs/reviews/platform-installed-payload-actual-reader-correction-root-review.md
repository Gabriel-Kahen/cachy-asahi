# S01 actual-reader report-custody correction: independent Root review

**PASS for the held source correction and finite fixture scope.** Both P2 findings from the blocked `6849dda8…` review close against author receipt `3c423c4bdff2f4838f0fbc5bed8d9fd905f3a9b7a4135ddd674bc69a0a550448`; no new finding remains within this scope. Corrected30 and baseline14 methods, 23 custody controls and 50 disposal checks pass. The correction is eligible for coordinator source admission and a separately bound read-only trial. No actual reader execution or source admission occurs in this review.

Root owns only this document and `artifacts/reviews/platform-installed-payload-actual-reader-correction-root-peer-20261012/**`. Independent test, custody and disposal lanes own separate subdirectories. The roadmap and package inventory were read; full R1–R5 and M5–M9 remain mandatory and incomplete.

## Exact held inputs

The corrected 24,849-byte harness is `75ce16392e9d9595519de771d815bd24c093f7d8f7a2caab052522623ef4f19b`; the 27,310-byte test file is `b7a28808f91dffe2a3e6c97fc1f543d2fea8de71e87f80853e76143702e0a7a7`, both mode 0644. The old harness `7e1fb1b5…`, original proposal `7e75acc4…` and blocked Root peer `6849dda8…` are preserved historical inputs.

Initial authentication passes 633 byte/mode references, including all 39 correction artifacts, 70 original proposal artifacts, 472 adoption rows, four adopted source files, 14 original Root evidence rows and the prior installer/repository reviews. The adoption receipt remains `299faeb8fb55f276972ee5af780716f09ea434e36f8ea7cc798fbb32caa8deae`.

Post-run checks reauthenticate the same 633 references, nine Root fresh copies and every indexed file in the three frozen lanes. All 261 payload-reference metadata rows and seven source/JSON identities remain exact; the proposed actual output stays lexically absent, approval stays false and bytecode count is zero.

Candidate reader `485913978598a444f86de17c7583e14b96fb7fdb9b25334f4f59d054af09c16a` differs from the prior reader only by its one tool-contract hash literal. Reversing that literal restores exact bytes and AST. The adopted primary reader remains `968d31e2…`; candidate admission is separate.

V3 contract `4f53cd7be7a9f23c526007bd846b4c09b040be364504959dbf4273b5591d3ef6` retains schema 2 and `approved: false`. Recursive comparison against intact v2 finds exactly 32 UID/GID identity scalars changing 65534 → 0. Other values and recorded byte hashes, sizes, modes, link targets and identities remain exact. This authenticates a recorded contract; it does not read or renew executable hashes or establish the cause of the earlier identity drift.

Selection `6f2c42336a899e8daf02d720de69b596f4c77e0d3a7029177b6a487473c0fe6a` is byte-identical to the original. Its image, ownership and 259 archive references pass all nine current lstat fields and ancestor checks: 261 metadata-only references. Reader, core, tool JSON and four source references also match their selected metadata and source hashes. Image/archive/tool payload contents remain unread. The output remains lexically absent. The grant changes only the harness hash and remains `approved: false`.

## Original P2 findings

**Partial cleanup deleting a foreign replacement: corrected within finite controls.** The old Root cancellation fixture records the opened owned partial being renamed aside and a foreign regular file taking its name. Old cleanup deletes the foreign named file while preserving the original cancellation and leaving the displaced owned file. The corrected production `persist_report` registers the directory and partial descriptors and their first observed identities before writing. No-follow named cleanup requires a recorded regular single-link inode in the held directory. The same modeled cancellation now preserves the foreign replacement and records incomplete custody while retaining the original cause.

**Dangling final symlink accepted as absence: corrected within finite controls.** Old `exists()` follows the dangling target and returns absence without refusal. Corrected revocation uses no-follow metadata; a foreign dangling lexical entry refuses, remains untouched and sets sticky `revocation_failed`. Genuine absence and a provably owned regular final retain positive behavior. Later disappearance of the refused entry cannot erase the earlier unproved revocation.

The independent custody lane passes 23 controls, including both old-red/new-green pairs, 19 private filesystem fixtures and four first-cause/control models. Corrected owners are obtained through the actual production writer on tiny files, including its held directory and partial descriptor registration. A handmade weaker custody dictionary is not substituted for the corrected route. Cases cover foreign regular files, symlinks, dangling links, hardlinks and directories; displaced parent directories; owned partial/final positives; final publication refusal; sticky refusal and first-cause preservation.

## Descriptor disposal and CLI outcome

The independent disposal lane passes 50 checks. Initial parent or partial identity-query failure leaves identity unknown; later successful metadata does not adopt or authorize closing that slot. A different-inode descriptor reuse is preserved. Queried EBADF clears an absent slot without closing it. Owned close failures consume exactly three bounded attempts, and remaining known resources are attempted despite an earlier fault.

An active control remains primary. A later control can supersede an ordinary business failure with that failure retained as its cause; later ordinary failures preserve the active cause. Signal-mask restoration uses the same ordering. A parent-close fault triggers revocation of a provably owned final before a retry can close the held directory. Deadline failure after publication revokes before return when directory custody remains available.

Mocked CLI sequencing and AST order place parent disposal and the final deadline check inside the original envelope before success stdout. If a later cutoff occurs after parent closure, revocation may remain unproved and physical report data can remain. The modeled CLI withholds success and preserves the timeout; this does not prove absence of the residual report.

All deliberate unknown/foreign descriptor and displaced-file residuals are measured first, then explicitly disposed by fixture-only cleanup. That cleanup does not claim production authority over unknown objects. No fixture or bytecode is retained after the controls.

## Method replay and unchanged business route

Cold corrected30 and baseline14 methods pass: zero failures, errors or skips; both processes exit zero. All 44 per-method descriptor identity snapshots are unchanged, with no unknown residual descriptor. Six fresh harness/test/selection copies authenticate before and after the runs. The test lane records outcomes, actor audit, exact commands, environment and bounds.

All 14 inherited method names remain. Twelve bodies are AST-identical; two have exactly the declared fixture changes for directory-relative unlink and explicit successful parent disposal. Sixteen methods are added. Harness AST comparison finds fifteen unchanged old functions, four changed old functions and eight added report-custody functions. Imports, constants, policy, requests, all false acceptance flags, entrypoint and the original job envelope remain unchanged. True-looking grant dictionaries appear only in pure validation controls; they never authorize the actual execute route.

Thirteen Root static checks independently prove unchanged AST for execute, preflight, grant checking, reader loading, the outer job envelope, selection validation, metadata guarding, bounded source capture, POLICY, REQUESTS, ACCEPTANCE, FIELDS and MIB. The actual selected route remains exactly `stat <2>`, `ls -p <2>`, `stat <2>`; no CAT, recursion, extraction, write-mode debugfs or mount request is added. The same ledger accounts for report debt and image/decoded work, and no cutoff or cap is renewed.

The retained execution policy has one 1,200-second envelope, 8 GiB shared work, 20-second command and 2-second cleanup cutoffs, 2 GiB address space, CPU 1,195 seconds, report 256 MiB, metadata 8 MiB and stderr 65,536 bytes. These remain source limits; aggregate process resources and actual actor feasibility are unmeasured. Fixture supervising bounds are CPU 30 seconds, memory 512 MiB, wall 60 seconds and file 4 MiB. Harness resource and signal APIs are mocked, so fixture replay does not install real handlers, timers or limits.

## Scope and coordinator action

This review establishes finite inode custody and failure ordering. Same-inode/same-number reopening, descriptor generations and hostile metadata-query/operation races remain unproved. A displaced inode whose name is unknown can remain; unknown descriptors are deliberately retained. Failure after directory closure can prevent proven final revocation. Typed failure and withheld success remain required when disposal is unproved.

The coordinator owns candidate source admission and any exact read-only execution grant. The grant must bind this harness, candidate reader, adopted core, v3 contract, unchanged selection, original output path, request sequence and resource policy. This review issues no grant and executes no actual reader actor. Prior source/adoption evidence is not a hardware or full-correspondence acceptance.

There remain 259 archive candidates for 261 required tuples, two missing exact tuples and 26 unresolved signer joins. Installed payload, image issuer authentication, independent key-owner trust, installation, hardware and complete correspondence remain false. No image/tool/debugfs/archive/GPG/Docker/mount/native/network/package/service actor, primary/shared source edit, workflow/manifest/registry update or project Git mutation occurred. Full R1–R5/M5–M9, ARM/M2, 16K and performance acceptance remain unfinished.

Evidence is sealed in `artifacts/reviews/platform-installed-payload-actual-reader-correction-root-peer-20261012/final-receipt.json`: authentication, exact fresh source, independent frozen lanes, Root static checks and post-run conservation. The receipt indexes every retained regular file in that namespace except itself, plus this review document.

# Independent virtual QEMU correction review

2026-10-12. **SOURCE P2 FINDING CLOSED ON THE EXACT CORRECTED HOLD. Candidate archive authentication PASS. Shared adapter acceptance pending separate peer review; corrected native tooling/guest execution NOT RUN.** Original review and focused correction evidence are distinguished below; this receipt does not approve coordinator adoption or dispatch.

Read `AGENTS.md`, `docs/roadmap.md` and `manifests/packages.toml` before reviewing. Sole repository file written by this reviewer: this receipt. Source, active historical locks/audits, shared adapter, Git and dispatch were not changed. No relevant memory entry was found or used.

## Original P2 history: canonical hash contract

**Original held P2, now closed:** `scripts/virtual/controller.py:419–430`, especially line 430. `project()` parses and validates the finite list, then computes `qemu_capabilities_sha256 = digest(capability_file)`. It does not require canonical input bytes. This conflicts with the explicitly receiver-recomputable canonical-list hash documented in `docs/workstreams/virtual-qemu-correction.md:35,58`.

A synthetic one-row `version / FAIL / capability-missing` record with code 0 and empty-stream SHA256/lengths passes the finite validator. With only the held candidate run.py pin mocked in memory, projection accepts both `common.save()` canonical JSON and compact parse-equivalent JSON. The exact canonical-list SHA256 is `ba07c55aa318ba60003871e67553f958a8a942a7be611899a923db0154e7d40a`; compact JSON produces the public hash `929998c003cb41399bbd0700cc069fa5a9a9100a9e247426c964813c0e9ba42d`. A receiver hashing the projected rows by the documented formula cannot verify the compact receipt, although the producer accepted it. Hash the canonical projected rows, or refuse any noncanonical receipt bytes; retain a regression for parse-equivalent noncanonical input.

This is a bounded malformed-receipt ABI defect, not evidence that ordinary native output is broken. The normal authenticated `run.check_capabilities()` writes through canonical `common.save()` before and after every check (`run.py:74,81,92`; `common.py:50–51`), so that normal path currently yields the promised hash. Unmodified production projection of the synthetic held candidate refused with `capability projector source differs`; that refusal is intentional historical-pin behavior, not candidate success.

## Focused P2 closure on corrected owner bytes

Independently verified the exact new controller/test/document hashes in the table below and unchanged hashes for common/run/auditor/test_virtual. Reconstructing the original controller by replacing only the new two-line canonical hash with the old raw digest reproduced original SHA256 `207abdfe…`; removing only the added test reproduced original test SHA256 `aaddde81…`. Thus the bounded source change is exactly canonical hashing of the already captured/validated rows (`controller.py:427–431`), without rereading capability JSON, plus one focused regression (`test_controller.py:373–392`).

Independently reran the complete suite: **41 PASS, zero skips, ResourceWarning-as-error, 0.448 seconds**. Independently replayed canonical JSON, compact JSON without whitespace, and reversed key order with extra whitespace on the original failed-prefix fixture. All three project the same canonical SHA256 `ba07c55aa318ba60003871e67553f958a8a942a7be611899a923db0154e7d40a`; compact raw SHA remains `929998c0…`, demonstrating the correction. Both capability fields appear together, including without a final guest receipt; absent capability data leaves both fields absent. Missing/mismatching guest capability lists and historical/incorrect source pins refuse before publishing either field. Only the CORE run.py pin was mocked in memory for synthetic positive projection; unmodified production still intentionally refuses held edited source.

**P2 CLOSED; no additional finding in this focused recheck.** Temporary focused receipt `/tmp/virtual-qemu-p2-review-78nuices/receipt.json`, SHA256 `f17f44f7645f6a87fafea71518303dbdf54839427c70bb97223458f524c89776`, records exact layout/raw/projected hashes and refusals. No candidate data reauthentication was needed or repeated because both candidate hashes remain unchanged. The owner's new copied-candidate suite was reported, not independently repeated. Shared adapter source pinning, canonical field-pair/all-four-PASS acceptance and 21/45/366 integration remain outside this review; no native/system execution occurred.

| Corrected held input | SHA256 |
| --- | --- |
| scripts/virtual/controller.py | `a42b774a6aa4c571ad8e23861ad1eab2170df805f6a87b85a0a3cec9cdd28a1c` |
| scripts/virtual/test_controller.py | `67f7c6ec45f15a56a32a1c84feb3ac583d16d34d47446f8647fb49f3183714d7` |
| docs/workstreams/virtual-qemu-correction.md | `d9c5e66aa749a9576c44dda0adaae066f7e3bf8dd0ce9445041c66118590ccc4` |

## Explicit coordinator acceptance obligation

`run.py:68–93,210–226` executes version, TCG, virt-machine and virtio-gpu-pci checks before QEMU guest launch. Each failing check raises; the normal authenticated execution cannot reach guest capture without four PASS rows. The finite validator deliberately accepts ordered diagnostic prefixes and allows a last STARTING/FAIL row (`run.py:32–65`). It correctly refuses unknown keys/checks/reasons, reordered rows, booleans as integers, invalid hashes and out-of-bound encoded stream sizes.

**`controller.py:414–434,604–606` does not independently couple captured status to four PASS rows.** In an explicitly mocked candidate-pin projection, a synthetic `CAPTURED_REQUIRES_VISUAL_REVIEW` guest result plus a single `version FAIL` row was projected without refusal; the guest status remained CAPTURED and the capability row remained FAIL. This is recorded as the root-owned shared adapter integration obligation specified in the assignment/document (`virtual-qemu-correction.md:58–60`), not as a bypass of authenticated run.py execution. Before guest PASS or virtual success, the receiver must require both capability fields, exactly four ordered PASS rows, the canonical list hash, and all existing proof/frame/cleanup checks. Early failures may retain a valid partial prefix or absent preflight diagnostics. Projection alone grants no guest or hardware acceptance.

## Original independently executed verification

- `python -B -Werror::ResourceWarning -m unittest discover -s scripts/virtual -p 'test_*.py' -q`: **40 PASS, zero skips, 0.444 seconds** on the exact held source. This is independent execution, not replay of the owner's test report. The supplied copied-candidate test report was inspected but its copied-tree run was not independently repeated.
- Independently copied all **45** hash/size-pinned objects into an owned temporary cache, using the two candidate archives/signatures and existing original cache objects. Reran `scripts/virtual/audit_tooling.py` with the exact candidate lock digest, no download flag, and a fresh temporary output. **All 21 packages PASS; output byte-for-byte identical to tooling-audit.candidate.json.** This exercised actual archive SHA/size, detached signatures, private GPG `--no-autostart` verification, PKGINFO/BUILDINFO comparison and hook/path inspection. No package was installed or executed; temporary audit cache/keyring/output were removed.
- Independently verified the candidate contains the original **19 unchanged package rows** plus precisely `qemu-hw-display-virtio-gpu` and `qemu-hw-display-virtio-gpu-pci`; 341 base + 21 tooling = **362**, plus four overlays = **366**; three keyring objects plus two objects per package = **45**. The retained resolver output contains exactly 21 unique rows, and repo/name/version/archive/URL match every candidate package. This verifies retained resolver evidence; this reviewer did not independently rerun pacman resolution.
- Inspected the initial failed audit: SHA256 `6001e1531713463e70c074937ac3c1065c62b8d02e11366b9440d6395d45a18f`, status FAILED after 14 package records, error `authenticated archive differs from resolved metadata: depend`. It remains historical failure evidence, not candidate acceptance.
- Reproduced both projection boundaries and the intentional unmocked production source-pin refusal. Persistent temporary repro receipt: `/tmp/virtual-qemu-review-repro-u0d581kz/receipt.json`, SHA256 `9b88e4c1ff0f060c1494d1a41453fe9a50ce9948315cc13888d86c9d62306b42`. Synthetic guest data and only the CORE run.py pin were mocked in memory; source files and production literals were untouched. The repro directory contains only synthetic receipt/projection data, not keys or installed images.

## Bounded supervision, cleanup and native finish

Source review confirms each capability command has a 15-second deadline and 128-KiB combined captured-byte cap. Hashes and sizes describe replacement-decoded output re-encoded as UTF-8, so the validator's combined 393216-byte maximum is consistent with that expansion; no raw help output or exception text enters capability rows. `common.py:197–286` registers processes before deferred signal delivery, caps streams and kills/reaps process groups in finally. The independent suite exercised real Python child floods, group timeout, cancellation during process registration and stream closure (`test_virtual.py:101–111,230–310`); QEMU commands themselves were mocked.

The unchanged controller cleanup design verifies absence of owned containers and the private image, treats uncertain commit outcome as FAIL, preserves exact Config semantics, records workspace removal, and converts late cancellation/projection/cleanup failure to FAIL (`controller.py:302–339,391–411,457–466,613–658`). Runtime normal finish requires QMP quit, exit code 0 and log-drain finish, with final process/socket cleanup (`run.py:292–318`). Mocked controller tests exercise remaining-container/image rejection, uncertain commits and late receipt cancellation. No Docker, ARM QEMU, compositor, DRM, or actual corrected native cleanup/finish was executed by this reviewer.

## Original exact reviewed inputs

Original receipt SHA256 `daf7e3fdbd596a541beb39c43f09671df8d88779a5a8e55b3c898a022fe2f9a3`. These original seven hashes were checked twice; the three corrected hashes above supersede their original rows. Source modes are 0644. Other four source and both candidate data hashes remain unchanged.

| Input | SHA256 |
| --- | --- |
| scripts/virtual/common.py | `b5099507b27fd9f86259c0096d0128b3a2480c546469312763a84438202fa4c3` |
| scripts/virtual/run.py | `60a495285968d44f176a2cb299f3c251562ebdd2a8e7c7ecbdb3007bdec4575d` |
| scripts/virtual/test_virtual.py | `856668f473577834afa94afb3917ee3dd1e561d8d95292db3abafbc7395f55b3` |
| scripts/virtual/audit_tooling.py | `6677f391f2de23540bc147770148729fe4c993850b7bbed0b71fb7e48d296fdc` |
| scripts/virtual/controller.py | `207abdfe741e17560bf0cc572d3cd9325cc923d4d0bf19071a6121f71964c85d` |
| scripts/virtual/test_controller.py | `aaddde8120197631988d2810117ca26f948751f6532e5cfc34b61f4194b64975` |
| docs/workstreams/virtual-qemu-correction.md | `215021a6a3898d1a2277feb7716a77a4f8b245afa8092dcb5170fb2a306d1785` |
| artifacts/virtual-qemu-correction-20261012/tooling.lock.candidate.json | `a8060f5dab01277de200fb7c9a4418b565984eb6d1cfb4971f0a3bd013ee8073` |
| artifacts/virtual-qemu-correction-20261012/tooling-audit.candidate.json | `cd11a837b29e5c757b482a79b375f65170881d73f80db4ae645ed600a45378cd` |

Historical CORE, AUDITOR_PIN, LOCK_PIN and AUDIT_PIN literals/active 19-package files intentionally remain incompatible with the candidate until coordinated adoption. The canonical-hash source finding is closed by the exact owner correction above. Root-owned source-pin refresh, separately reviewed adapter success/count checks, packet freeze and subsequent actual corrected native execution remain unfinished. No exact-M2, 16K-page, accelerated-graphics, hardware lifecycle or performance acceptance is established by this receipt.

## Coordinator owner/input adoption

Root verifies the six exact final owner source hashes/modes, adopts candidate21 tooling lock `a8060f5d…` and audit `cd11a837…`, and changes only the controller's five reviewed literal bindings: LOCK_PIN/AUDIT_PIN/AUDITOR_PIN and CORE common/run. This produces controller `3f083173494cfb1f6ac40bbc0cd8bb90d62c56272f882232fb8aa16d8fa2e09d`; all other held owner source bytes are unchanged. The old19-package lock/audit are retained in the private correction artifact directory and Git history. All19 original package metadata rows remain byte-identical, with exactly both authenticated2D GPU modules added; base341 is preserved and corrected counts362/366/45 are explicit. Root's actual41-test owner suite passes/zero skips/0.450seconds. Root pin-only adoption receipt: `artifacts/reviews/virtual-qemu-owner-pin-adoption-20261012.json`.

The separate adapter's two publication findings remain unresolved; this owner/input adoption does not accept its public-selection protocol or dispatch a guest. Root will require corrected adapter peer review, exact211-source transitive freeze/copy/preflight and actual native/frame execution. M2/16K/installation/performance remain NOT RUN.

# Repository reset public evidence review

Status: **final CI-held source correction PASS** at `5ceaa566…`; REPO-PUBLIC-1/-2 resolved. Native run `38227121568` retains all eleven repository transaction cases PASS and its original public evidence export FAIL. This review does not change that historical outcome or claim a corrected native rerun.

## Reviewed bytes and independent checks

| File | SHA-256 |
| --- | --- |
| `scripts/ci/repository_projection.py` | `e249c0454ff4b207ce7c402f928815a62cf7ed3b43ad0b66eb5ae3467ef36d07` |
| `scripts/ci/test_repository_projection.py` | `cca61a7542b29888e9cfa41d30e9a32e25099008e173d7bec8d91cdda0c6591d` |
| `scripts/ci/integration.py` | `dbcfb2a36442f14d1898123ab3eafc07deb8589fc601d0a5609f5165099ac7ed` |
| `scripts/ci/test_integration.py` | `4764e98c3224a32036c56014c15f6db19677d02d2fafa364187e85bed43f872f` |

Independently ran **31 projection tests and 65 integration tests, all PASS with zero skips**. Eight additional temporary-fixture refusals exercised unknown credential fields, unknown sensitive paths, an extra reset receipt key after hash rebinding, a rebound dependency error, a rebound boolean snapshot UID, wrong source, wrong accepted baseline payload, and a public alias collision. All refused; any emitted export manifest retained FAIL. These used actual projection, selection and generic export code, without Docker, system installation or native transactions.

The projection binds known schema/purpose to the exact accepted source/input contract, unique ordered operation command labels and positional log names. It verifies revoked TEST-A identity/status/rejection, the exact reset receipt schema and database/signature pairs, accepted baseline archive identities and payloads, complete installed inventory, three equal snapshots, empty reset stderr, and exact dependency diagnostic/stderr bytes. Only nine exact validated operation names acquire neutral public aliases; unknown fields survive for generic credential refusal. Original evidence hashes/paths remain present alongside explicit public references and an alias index.

## Confirmed omission race

**REPO-PUBLIC-1:** `safe_public()` captures nine verified operation files, but writes those captures only when a subsequent `os.walk(raw)` encounters the original names. Removing `revoked-A-sync-cache-reset.json` immediately after `operation_files()` returns causes an actual generic exporter PASS and repository result PASS while `sync_cache_reset.public_receipt` and the operation index reference the missing `revoked-A-sync-reset.json`. The public directory contains only eight of the nine indexed operation files.

Reproducer: `/tmp/repository-operation-independent-review.py`; actual `safe_public()` and exporter with a mock scheduling boundary and temporary fixture files. Output fixture `/tmp/repository-op-race-pm6vdlpf`. No implementation edits. Reported to coordinator for a narrow correction: emit the verified captures independently of later traversal, or refuse omission before export, and verify complete public references. The first held checkpoint cannot receive source acceptance until this closes.

## Complete controlled replay and historical evidence

Independently replayed the owner reconstruction script in a fresh directory `/tmp/repository-public-independent-drfu_n0n`. The nine omitted files were reconstructed from retained equal-hash inventories/snapshots, empty stderr bytes, the fixed dependency diagnostic, and the exact held producer reset JSON schema with retained command/database hashes. **Every reconstructed file matches its SHA-256 in the retained native result**. Original selection without the new operation projection reproduces FAIL on exactly those nine names; corrected selection exports the complete controlled fixture PASS. All nine alias bytes/hashes/lengths agree with the original names, index and result evidence map; fixture input bytes remain unchanged.

This is hash-matched controlled reconstruction, not recovery of the original complete raw result/private tree or a new native run. The complete original raw result is not retained: its hash/count remain recorded by the original projection receipt. No original artifact was rewritten.

| Historical artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| Retained native public `result.json` | 160435 | `90886131ce205caeb3a288ba17ee4bbf7d7256fd327b7b575f2b12499256aad6` |
| Original FAIL `export-manifest.json` | 47085 | `687929680fe171c9e3532fa2cb0158b0da8282b1bc54eb8f5481c8e9228efee0` |
| Original inventory projection receipt | 414 | `04ce3ff785fa5d8dfc51f37ebbcddb466b3742cfa2649ec3ed4233635c830cd5` |

The historical receipt records original raw result 206601 bytes, SHA-256 `128219c6b9a38895a51b183b989fa0964416e73960bdc7c057eaecd8fd9d8d1e`; 341 base rows and status PASS survive projection. Native export acceptance remains pending a complete corrected run.

Unchanged generic guard: `scripts/ci/integration_export.py` SHA-256 `1ae8aded5ab461b280ca1ff82047f6766d58efacf7a09c83dc84515ac7d2216c`. Exact proven repository producer: `scripts/integration/repository.py` SHA-256 `49c87f41bbb2fe1288251f16019f12aaeabb98d81ff5339387873e88e903b940`; test SHA-256 `a7857437d1cf3e513720351299d241d7a6c97d3f58f0ef9b4bc92655dffd7274`. This publication correction does not change the positive transaction error gate or waive reset checks.

No new native execution, host installation, hardware/16K/M2 validation or performance claim. Shared locks, workflow and Git integration remain coordinator-owned.

## Follow-up review: remaining status-log reference omission

Review ownership transferred to the independent integration reviewer on 2026-10-12. Earlier findings and reconstruction/actual-history distinctions above are preserved. Read the updated roadmap and package inventory before this follow-up.

The current in-flight `integration.py` is SHA256 `94e4f57844019423d8a36bead96b18bd3eded32efb24ed87e6d9e0bf6f3b1c4e`, test `9b42d2ec117e487f546800b72a4787e05a08cf5da61f712695ec959b4995daac`. Projection/source tests remain at the first table's hashes; generic credential guard and repository producer remain unchanged. The nine captured operation files are now written before raw traversal, charged to the bounds independently, and checked in selected/public bytes plus the exported manifest. This addresses the original nine-file scheduling mechanism, pending final held validation.

**REPO-PUBLIC-2:** the six older deliberately allowed repository status logs still receive aliases from `repository_public_logs()` without captured-byte publication or complete-reference validation. After `operation_files()` returns, delete the already hash-validated `000-gpg-revoked-A-status.txt` in the current temporary operation fixture. `safe_public()` returns successfully; generic export and repository result are PASS, but `commands[].public_log` references missing `000-signature-revoked-A-status.txt`. This is the same omission class for another existing reference, not a request for broader aliases or a generic guard exception.

Independently reproduced against exact `94e4f578…` with actual selection/projection/export and a mocked scheduling boundary, without source edits or native/system operations. Reproducer `/tmp/repository-status-log-completeness-review.py`, small receipt `/tmp/repository-status-log-completeness-review.json` after execution. Reported to the coordinator for a narrow existing-six-log capture/reference-completeness correction or explicit refusal. Final source readiness remains withheld pending that correction and the owner's exact held four-file checkpoint.

## Final held correction: REPO-PUBLIC-1/-2 resolved

CI's explicit held receipt is `/tmp/cachy-repository-publication-proof-moqh_qwj/legacy-completeness/source-hold-receipt.json`. Independently rehashed all four final files, including their mode `0644`:

| File | Final SHA256 |
| --- | --- |
| `scripts/ci/integration.py` | `5ceaa566f1084b25e8ebbbe8585b577de64595f70035e89943e87fbb83c6becf` |
| `scripts/ci/test_integration.py` | `ec4f03f1195a5336d1bbb070f67c383910c401f50fb6de0203d04304dbe34a2f` |
| `scripts/ci/repository_projection.py` | `e249c0454ff4b207ce7c402f928815a62cf7ed3b43ad0b66eb5ae3467ef36d07` |
| `scripts/ci/test_repository_projection.py` | `cca61a7542b29888e9cfa41d30e9a32e25099008e173d7bec8d91cdda0c6591d` |

The existing six status logs are now read through the bounded hash-bound public reader into captures, alongside the exact nine operation files. All captures are written independently of raw traversal. Their count/bytes are charged before walking; disappearing originals cannot refund that charge or omit their public bytes. Unknown aliases cannot collide with captured names. The selected result, operation index and every captured public byte/reference are checked before export, and their exact accepted-manifest rows and actual public bytes are checked afterward. A generic exporter PASS alone cannot authorize missing references.

Independent tests: **72 integration + 31 projection = 103 PASS, zero skips**, logs `/tmp/review-repository-publication-integration-tests.log` and `/tmp/review-repository-publication-projection-tests.log`. These include the original nine files deleted individually/all together, all six legacy aliases in both legacy-only and reset-operation cases, selected/public omissions, missing result/index integrity, and source/credential/path/schema refusal. The owner's additional full 363-CI result is recorded by its held receipt; the reviewer did not repeat that whole unrelated suite.

Independently reran REPO-PUBLIC-1's scheduling mechanism in **ten** fresh temporary fixtures (each of nine originals deleted after capture, then all nine). All public bytes/hashes/lengths remain exact, all nine index rows and reset receipt references resolve, every command public log/stderr reference exists, and generic export is PASS. Independently reran the exact REPO-PUBLIC-2 revocation-status deletion: publication/result PASS with **no missing public references**; the already verified capture is retained. These are controlled data/scheduling fixtures, not native operations.

Repeated all eight prior poison cases independently: unknown credential field, unknown sensitive path, rebound extra reset key, rebound dependency error, rebound Boolean snapshot UID, wrong source, wrong accepted baseline and alias collision. All refuse. Existing unknown data is still subject to the unchanged generic credential guard; the correction adds no filename/content exception or unknown-path passthrough.

Fresh controlled reconstruction replay is retained at `/tmp/review-repository-reconstruction-final-clhdxojz/reconstruction-receipt.json`. All **nine reconstructed files** independently match the hashes in the retained native result; original selection still fails on the nine exact known names, corrected selection exports PASS, all neutral bytes/reference bindings agree, and the reconstructed fixture remains byte-unchanged by selection. This uses the reviewed reconstruction logic in a fresh reviewer directory. It does **not** recover the unretained original complete raw result or private tree, modify any original artifact, or create a new native run. The historical artifact/hash table above remains authoritative.

Final rehash confirms the generic guard remains `1ae8aded5ab461b280ca1ff82047f6766d58efacf7a09c83dc84515ac7d2216c`, repository producer `49c87f41bbb2fe1288251f16019f12aaeabb98d81ff5339387873e88e903b940` and producer tests `a7857437d1cf3e513720351299d241d7a6c97d3f58f0ef9b4bc92655dffd7274`. No positive transaction error, signature, reset, installed-state or capability gate was changed by this publication correction.

**Disposition: PASS for the exact held source correction; no remaining material defect reproduced.** Coordinator source-freeze/Git integration and a corrected complete native publication run remain required. Native export acceptance, target installation, M2/16K hardware and performance remain pending/NOT RUN.

## Coordinator integration

The coordinator independently passes all 103 focused publication/integration
tests without skips. It freezes the accepted four source changes into initial
lock SHA256 `9503d0583417956ef39da5e862eb9abd2f2d01cbdfffcfe26a25da25c53bbc35`,
with the same 159 sources and byte-identical 125 fixture entries. The generic
credential guard and proven repository transaction source remain unchanged.
Committed Git/fresh-copy preflight and corrected native publication are next
gates; historical run38227121568 remains aggregate FAIL.

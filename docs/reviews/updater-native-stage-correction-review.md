# Updater native stage observation/diagnostic correction review

2026-10-12. **HELD SOURCE ACCEPTED for coordinator commit/freeze and workflow-consumer adaptation. Corrected native execution NOT RUN.** Reviewer owns only this document. The prior 136-test source acceptance and UN1 correction remain historical accepted checkpoints; this review does not overwrite them or claim corrected native execution.

## Actual failed run, independently read

Read the current roadmap and package inventory. Inspected retained `artifacts/ci/38232511202/decoded/` receipts and independently verified every accepted file's byte count and SHA256 in all three public export manifests (original terminal, recovery terminal, guarded evidence).

The original terminal binds source commit `ea274b800be2d701511cf23692afb53482b2f709` and controller `5e1fd4899129b49c6753868b96c63e5bf2c4b21487c043d1f22875cb7524bd18`. It reports **FAIL / RuntimeFailure**, elapsed 49 seconds, native compilation NOT RUN, cleanup PASS, private data removed, within retention, and no cancellation. Its SHA256 is `17d5624a06279c9d7f53823366d82652ec6882e9b188abd7c34c5621718ae219`.

The guarded native result is STARTING at input-validation, not a compiled pair (`93667c85fdac454c6b4894ffaaf369ef526140f3ed65881e7a09b6f5fb1945dd`). Acquisition has 527 total, 125 PASS, 402 pending, zero fail, IN_PROGRESS, with **signature authentication NOT RUN** (`387d22e3ed3c1009a9b5dda1b942f68c6017a09734addebd4b83869a83f9a637`). Those input records do not establish complete acquisition or authentication.

Materializer PASS records 168 downloads, 167 registry sources, deterministic regeneration and its bounded resource policy (`8231a243b5fc6d102a30e43bd15e2b4af9c9f8273e5cc58702cb02c5d7dadec7`). Recovery is PASS for removal/cleanup, with native compilation NOT ATTESTED BY RECOVERY (`127b25b7204b0b82e966968bc5bfde72a7496afe46db916da37fb2101876dc45`). Recovery does not promote the failed stage to a successful native pair.

**Hosted causation is unproven.** The original bounded public terminal does not retain a phase-specific runtime/tick reason. The owner's separately reported local atomic-rename reproduction identifies an implementation defect to test; it cannot prove that defect caused this actual run's failure. No original private log/state recovery or new hosted run was performed by this reviewer.

## Correction scope and disposition

The owner is modifying only stage/public-worker code and their tests plus the stage workstream. Final review will bind the four held source/test hashes and check the actual rename fixture, root/current-directory identity, byte/member budgets, permission/type/ownership/mount failures and closed public diagnostic codes. Missing/replaced private roots must not become accepted observations, and raw paths/exception messages/log text must not enter diagnostics.

Unchanged source/helper/runtime/broker and the ready-map/package/root pins must retain their prior accepted values. The initial sampled draft is in flight and is not a source freeze. Workflow bootstrap/consumer adaptation, Git/source maps and dispatch are coordinator-owned and outside this correction signoff.

No implementation, source lock, shared map, workflow or Git edits, host installation/service/account/trust change, Docker/native build or dispatch were performed. Private native compilation, target installation/update behavior, publication/licensing, 16K/M2 hardware and performance gates remain unfinished.

## Bounded moving-source re-enumeration check

Captured stage SHA256 `64ce7f7c93dd0b37971d0810801241dbd10df6098c14b0106c63d284fbd0ca9a` before compiling its bytes into an isolated fixture module. This is an in-flight snapshot, not a final accepted source freeze. An earlier static observation about unrelated new entries during GPG dotlock re-enumeration was unproven; the current draft validates those entries.

The independent fixture `/tmp/updater-disk-reenumeration-review.py` injects a fresh entry at the second enumeration of a real owned GPG directory containing an actual two-name dotlock inode. All six cases triggered the intended schedule and were refused: real symlink/FIFO (`private-file-type`), simulated foreign UID metadata (`private-foreign-owner`, without chown), a real file crossing a two-byte budget (`private-disk-budget`), a new entry crossing the member cap (`private-member-budget`), and a real mode-0666 file (`private-file-permission`). Receipt: `/tmp/updater-disk-reenumeration-review.json`. The temporary directory was removed. No system, Docker, host trust, source, or Git mutation occurred.

Final real-rename, diagnostic/public-worker checks and exact held-source validation remain pending.

The independent real-thread fixture `/tmp/updater-rename-identity-review.py` obtains historical stage bytes by read-only `git show` of committed `c159cc3…`, SHA256 `96ddf13af155a0a01c499a53d92e8e8b5a50e28173368bbfdb8df3b0965b309c`, and compares the captured moving `64ce…` bytes. A bounded writer handshake atomically renames an enumerated regular descendant before metadata observation. Historical code raises FileNotFoundError; corrected code returns one charged member and zero observed bytes for the vanished name. This is a concurrent observation, not a claim to have counted a name that was never enumerated. Corrected code also refuses a missing root, replacement of the private root during the scan, and rename of an already-open live child directory. Historical code accepted a missing root as an empty tree. Receipt: `/tmp/updater-rename-identity-review.json`. All writer threads and private directories were cleaned. The harness initially failed to trigger the historical Path.lstat call; the retained final harness targets the actual historical lstat API and asserts its schedule and failure. This fixture reproduces the local defect, without attributing the hosted failure to it.

The same captured `64ce…` stage passed independent finite-diagnostic checks: 25 path/secret/container/bool substitutions across the five diagnostic fields were refused, and five exception classes containing secret strings mapped only to fixed codes (`validation-error`, `io-error`, `missing-path`, `permission-denied`, `unexpected-error`). `public_summary` omitted raw message/path fields. Receipt: `/tmp/updater-finite-diagnostics-review.json`. Final public-worker/schema and held-suite review remain pending.

## Final held-source disposition

No residual material implementation blocker was reproduced against the owner's final held checkpoint. The initial moving-source observations above were rechecked against the same now-held stage bytes. Only `stage.py`, `test_stage.py` and the workstream changed; the proposed public-worker edit proved unnecessary. All ten wrapper source/test files remain mode 0644. Exact hashes and test outcomes are retained in `/tmp/updater-correction-held-review.json`.

| Held input | SHA256 |
| --- | --- |
| stage.py | `64ce7f7c93dd0b37971d0810801241dbd10df6098c14b0106c63d284fbd0ca9a` |
| test_stage.py | `9dfc1a2435713815546c3632a3cb20fcf499fdd0df8d17ee29cf922513d64924` |
| workstream | `c63ac92cb8381085febc778dd65fe21628766873e8e20405664cede6cff55b4b` |

Independently attempted all **163 tests** with `python -B -Werror::ResourceWarning -m unittest discover -s scripts/port/updater-native-stage -p 'test_*.py' -q`. First attempt: 162 PASS, zero skips, one sandbox EPERM at the legitimate temporary GPG Unix-socket `bind`, before the scan function ran. After explicit coordinator authorization for this bounded temporary-socket/process scope, the automatic-approval rerun completed **163 PASS, zero skips, 6.280 seconds**. No test was weakened or skipped. These local fixtures exercise source/process/filesystem/public projection behavior; host/Git/native/Docker trust operations remain mocked. No native compilation, installation, host trust change or Docker operation occurred.

Independent ready-map validation confirmed `ff879da588419fc0f90ef6a27c8afc528c3f6a557ef2c060544d1b5e99ade4e2`, all 63 package and eight root file hashes, with zero drift (`/tmp/updater-correction-pins-review.json`). The source helper, runtime, UN1-corrected broker, public worker and their eight corresponding unchanged files match the historical accepted checkpoint.

Diagnostic role checks independently refused plain dicts, Receipt subclasses, success receipts, wrong process kind, boolean schema/return codes, unknown phase/reason, cross-operation tick codes and partial tick pairs. A legitimate exact-runtime Receipt admitted the finite five-field projection; subsequent guard failure could not overwrite that first failure. Together with the 25 poison/type substitutions and five secret-bearing exception mappings recorded above, this verifies that paths, exception messages and log text do not become public diagnostics. The full suite also executes the unchanged authenticated public-worker CLI through actual bounded processes and retains finite diagnostics through canonical terminal projection and cleanup. Role receipt: `/tmp/updater-diagnostic-role-review.json`.

The corrected scan opens ancestors/current directories without following links, binds the registered private root's device/inode, checks directory identity before and after observation, charges vanished enumerated members, and catches the tested newly observed security and budget violations during bounded GPG lock re-enumeration. It remains a periodic concurrent filesystem observation; a renamed destination that was never enumerated is not retrospectively counted. Original historical missing-root acceptance and atomic-rename abort are closed by the held bytes.

**Ready for source adoption only.** The coordinator must commit and prove the corrected complete 85-file source/Git/copy closure, adapt the workflow's exact bootstrap digest and finite terminal consumer, and separately validate any actual retry. Historical run `38232511202` remains FAIL before native compilation, with successful materialization and cleanup and an unproven precise cause. Historical 136-test acceptance is preserved. Publication licensing, dependency transaction/install/removal, M2/16K boot and performance gates remain open; these checks establish none of them.

## Coordinator source acceptance

The coordinator independently passes all 163 tests without skips in6.276
seconds. The exact held two source/test hashes and unchanged package/root
pins match. This closes the reproduced local rename/root-accounting defects
and adopts finite failure diagnostics; it does not prove hosted causation.
Actual source85 committed proof and workflow bootstrap/consumer adaptation
precede retry. Trial38232511202 remains FAIL, Rust compilation NOT RUN.

# Native updater workflow: independent source/interface review

2026-10-12. **Final held workflow `9638f48e…`: PASS for bounded source/interface readiness. UW1–UW4 resolved; hosted/native execution NOT RUN.** Earlier blocked snapshots and their reproductions remain below as history. Reviewer owns only this document, with bounded reproducer files under `/tmp`; no workflow, implementation, manifest, lock or Git mutation or dispatch was performed.

## Reviewed source and syntax boundaries

Read the updated roadmap, outline, package inventory, wrapper/workflow workstreams and complete workflow. The original supplied SHA256 was `98151e084e492a6f84485a8c8f259349db3c16e25e18f9c8c7a1c1c11e8588fb`. Its stage/source bootstrap literals match committed updater checkpoint `c159cc3b1c25ac3c70cf1cccaed1cbb8d17a310f`: stage `96ddf13af155a0a01c499a53d92e8e8b5a50e28173368bbfdb8df3b0965b309c`, source `259b13b210123d90f824f21bf7662785d50c7586519a78451ab62e97ec577d5f`.

Independently verified `artifacts/reviews/updater-stage-source-contract-20261012.json`: **85 selected source files, 3,875,628 bytes**. Every recorded Git blob/mode at exact `c159cc3` equals the current workspace bytes/file mode and SHA256; the aggregate byte count agrees. These were read-only Git queries, not a native host-bound controller freeze. The ready map remains `ff879da588419fc0f90ef6a27c8afc528c3f6a557ef2c060544d1b5e99ade4e2`.

Four shell blocks independently pass `bash -n`; all three Python heredocs independently pass AST parsing. The coordinator additionally reports actual yaml-cpp parsing and structural assertions against the original held hash: manual-only sole `source_commit`, read-only repository permission, one public ARM job, exact checkout SHA/ref/no credentials, existing concurrency group, five steps, always-step recovery and timeout fields. That parser result is coordinator-reported; actionlint and hosted executable validation remain NOT RUN.

The workflow binds supplied full source commit to `GITHUB_SHA` and checkout HEAD, independently hashes stage bytes before each CLI call, supplies the reviewed source bootstrap hash to freeze, and pins the external controller for both run/recovery. Cleanup separately hashes the bounded current ownership receipt after run exit; directory names alone do not grant authority. Actual wrapper source/Git/socket/tool checks and the previously reviewed broker ownership policy remain unchanged.

## UW1: legitimate runtime failure diagnostics discarded

The original consumer allows the package projector's error types plus RuntimeCancelled/SourceCancelled/BrokerError, but omits **RuntimeFailure**, emitted by the stage's normal nonzero/timeout/tick/registration runtime failure paths. A properly manifest-bound terminal FAIL with that type is refused before any public evidence markers, discarding legitimate stage failure and recovery diagnostics.

Reproduced the exact extracted original consumer with owned temporary fixtures, actual public-tree/credential-guard/bundler helpers, and mocked host/source authentication. Valid control: exit zero / three public bundles / aggregate PASS. Manifest/hash-correct RuntimeFailure terminal FAIL: exit one / **zero bundles**, `terminal-verification` refusal. There is no false native PASS; the defect is failure-evidence loss.

## UW2: recovery-only evidence discarded after a missing original terminal

The original consumer unconditionally opens `terminal-public` before considering `recovery-terminal-public`. A force-killed stage can legitimately lack the former while authenticated always-step recovery supplies the latter. Reproduced valid recovery-only output: exit one / **zero bundles**, again terminal-verification refusal. The workflow must retain verified recovery evidence while remaining aggregate FAIL and without claiming original native success.

The exact bounded reproducer is `/tmp/review-updater-workflow-UW1-UW2.py`, using the owner's fixture definitions but isolating all generated files under a new reviewer temporary directory. It extracts the actual current consumer and invokes it through bounded Python subprocesses; `/tmp/review-updater-workflow-UW1-UW2.json` records its source hash and outcomes. No host/native authentication, Docker, acquisition or compilation is executed.

## Observed UW1/UW2 corrections

The owner subsequently held `0d21c8e0b9a01756ff64a67d54b513fccfc08d37e1eaacc0367f748f739e6197`. Independent probes accept RuntimeFailure as a bounded type while retaining terminal FAIL (three bundles / exit one), and retain only one valid recovery bundle when the original terminal is missing (aggregate FAIL / exit one). The valid control still emits three bundles / PASS. No stderr diagnostics were emitted.

Additional malformed-fallback probes: missing both terminals, recovery source drift, unknown recovery field, credential-like failure type, and an existing malformed original terminal all fail with zero bundles. Missing original plus invalid/unbound guarded content emits **only** the valid recovery bundle, never that guarded content, and remains FAIL. During these tests the workflow changed again to `139f71a6cc5dcbd51b5235cd5ac38c68066a6ec5de0c8e6eff437f514c858647`, changing absent native status to NOT ATTESTED; this is a separately observed snapshot pending coordinator hold confirmation.

## UW3: named guarded JSON is not checked against its finite selector schema

At observed `139f71a6…`, the consumer checks guarded filename, dictionary type, byte/hash accounting and the generic credential guard, but does not require the dictionary to equal its authenticated projector selector's sanitized result. Therefore arbitrary unrecognized fields can survive in an otherwise allowed receipt name.

Concrete fixture: replace `native-result.json` with `{"native_pair":"PASS","opaque":"UNREVIEWED_PROPRIETARY_SOURCE_BYTES"}`, update its manifest byte/hash accounting and the terminal's bundle pin. The exact extracted consumer accepts **aggregate PASS / three public bundles**. The pinned projector's `native_result()` would drop the unrecognized `opaque` field. This demonstrates a publication schema gap, not an assertion that the actual trusted producer has emitted private data. The generic guard cannot recognize arbitrary noncredential source text. Reported for narrow reuse of the authenticated finite selector schemas and exact equality, preserving the existing credential policy and recovery-only behavior.

The retained reviewer harness additionally decoded the emitted marker bundles and confirmed that the unreviewed marker bytes actually reached public output at `139f71a6…`; this is not inferred merely from the accepted return code. Its JSON receipt records `unreviewed_marker_emitted: true` for that case.

## UW4: legitimate early recovery FAIL lacks an unobserved retention field

Independently exercised the actual committed `stage.recover()` with the existing private fixture and an authenticated ambiguous launch INTENT (`materialize`, `child_index: null`). Host/Git/Docker interfaces remain mocked; actual directory registration, recovery logic, canonical terminal and guard are used. The stage correctly returns FAIL/ValueError, preserves the raw cache and records `private_data_removed: false`. It omits `raw_retention_within_budget` because that elapsed observation is reached only after preceding cleanup checks succeed.

At observed workflow `97e69332120bfcdceda774b71c29059f72651a0869800fd2256f6ba4547564e8`, the consumer still requires all three Boolean lifecycle fields for every outcome. Feeding the actual recovery terminal into its exact consumer, with only source/controller identities rebased to the consumer fixture, yields FAIL / **zero public bundles** / terminal-verification refusal. Reported for non-PASS support of absent unobserved retention, while keeping Boolean typing when present and all PASS retention requirements strict. Do not fabricate a false retention measurement or promote cleanup/native success.

Reproducer: `/tmp/review-updater-workflow-UW4.py`; its current-source receipt is `/tmp/review-updater-workflow-UW4.json` after execution. Only bounded temporary fixtures and an extracted consumer subprocess are invoked. Final readiness remains withheld until this interface mismatch is corrected and the exact new workflow is held.

## Timing and remaining limits

One monotonic deadline starts before checkout, with 115 minutes to its deadline and a 116-minute job ceiling. Freeze/run/recovery/public expressions derive their remaining allowances from it. The run ceiling includes a 190-second force-stop allowance and leaves 300 seconds for recovery/public; recovery allows up to 167 plus 13 seconds and reserves 133; public allows up to 107 plus 13 seconds. The workflow deliberately can cancel before the wrapper's worst-case internal budget and cannot establish full worst-case completion by arithmetic alone. The outer VM/daemon disposal remains a platform dependency, not measured erasure evidence.

Independently executed all four exact clock expressions with ten controlled remaining-time values each: **40 boundary fixtures PASS**. Accepted intervals stay within the phase caps and force-stop allowance; native execution requires at least 60 seconds and preserves its 190+300-second reserves. These are arithmetic fixtures, not measured timed teardown or hosted VM disposal.

The public boundary transmits only rebuilt, re-guarded JSON bundles with hash/byte markers, not the original tar, raw logs, private source/vendor/artwork, package binaries, keys, controller or ownership files. Original and recovery outcomes plus actual run/cleanup exit codes and native step outcome are all required for workflow PASS. Recovery success alone cannot promote a missing/failed/cancelled native run. Publication remains NOT ACCEPTED and hardware NOT RUN.

Final signoff remains withheld for UW3 and a stable corrected workflow hash. Actual workflow registration/dispatch, native compilation, installed behavior, licensing/publication, target transactions, M2/16K checks and performance acceptance remain pending/NOT RUN.

## Corrected consumer validation at `d63593cd…`

Observed correction SHA256 `d63593cd4a90146a9f291d528b56581a4f39c92539cdcaf00a8748dcdb88d230` resolves all four reproduced interfaces. It permits the finite RuntimeFailure type, retains only authenticated recovery evidence when the original canonical pair is absent/partial, checks each named guarded record against the pinned selector's exact normalized schema plus bounded projection metadata, and permits an absent unobserved retention field only on non-PASS outcomes. PASS still requires true retention/removal/cleanup, false cancellation, proper native/recovery role and complete original outcome authority.

Independently repeated both retained reviewer harnesses: valid control emits three bundles/PASS; RuntimeFailure emits three/aggregate FAIL; recovery-only emits one/aggregate FAIL/native NOT ATTESTED; UW3 emits zero/refusal with **no unreviewed marker**. The actual UW4 ambiguous-INTENT recovery remains FAIL with its private cache retained and measurement absent, but its verified recovery receipt is now emitted while aggregate outcome remains FAIL.

Independently reran the owner's full **46 consumer fixtures PASS** in an isolated copied harness. The test uses actual pinned public helper bytes, with host/source authentication mocked; receipt `/tmp/review-updater-full-consumer-results.json`. This covers all selector inverse-normalization routes, complete metadata accounting, meaningful nested poison, duplicate/nonfinite values, typed booleans, identities, credentials and bundle headers/content. It performs no native/Docker/build operation.

Eight additional independent boundaries pass (`/tmp/review-updater-workflow-final-boundaries.json`): missing retention on original/recovery PASS is refused; absent retention on original/recovery FAIL is preserved without promotion; an unknown native field, unknown projection field and Boolean error count are refused even after **all** projection/manifest/bundle self-hashes are coherently updated; recovery-only ignores and never emits invalid guarded bytes. No unreviewed marker was emitted.

Three additional fallback checks distinguish a complete malformed original/recovery pair (refused, zero bundles) from a partial original pair (only the valid recovery bundle, aggregate FAIL). No partial original data is published. The coordinator-provided finite yaml-cpp parser was also independently executed against the correction and passed, and all four shell blocks/three Python heredocs parsed again. Actionlint/hosted execution remain NOT RUN.

During the last checks the source changed to `9638f48e601159f09207a5096381484e959372ea0e62259e235d43f3576ad9ed` and workstream document `4d942a4d733aab88f44ae9108f42d5ebfddf6793a372d17f4e298bdc37509765`. This snapshot drift was reported; final held-source disposition awaits confirmation/recheck of that exact checkpoint. No new material defect was reproduced.

## Final explicitly held checkpoint: source/interface PASS

The coordinator and owner now explicitly hold workflow SHA256 **`9638f48e601159f09207a5096381484e959372ea0e62259e235d43f3576ad9ed`**, workstream document `4d942a4d733aab88f44ae9108f42d5ebfddf6793a372d17f4e298bdc37509765`. The handoff `/tmp/cachy-updater-workflow-check-0mc69ljr/handoff.json` names the same hashes. Final rehash confirms the workflow and every one of the 85 committed source-file byte/mode bindings remain exact. The ten updater stage files retain their accepted `c159cc3` bytes.

Independently reran **all 48 consumer fixtures PASS** against this exact workflow, in the reviewer's isolated copied harness; receipt `/tmp/review-updater-final-held-consumer-results.json`. This includes the symmetric partial/missing recovery-pair cases added after the 46-fixture snapshot. No source/host/native authentication or Docker/build execution is claimed by that suite.

Both original reviewer harnesses were rerun at the final exact hash. UW1 preserves legitimate RuntimeFailure diagnostics without native promotion. UW2 preserves only verified recovery data when the native terminal is absent, reporting native NOT ATTESTED and aggregate FAIL. UW3 rejects the original unreviewed-field reproducer with zero bundles and no marker emission. UW4 preserves the actual early recovery FAIL without inventing a retention measurement; aggregate outcome remains FAIL.

Strict PASS retention remains mandatory for both original and recovery receipts. The eight independent coherent-self-hash/schema boundaries above pass, and the three malformed/partial canonical-pair checks distinguish complete invalid evidence (zero bundles/refusal) from partial absent authority (only verified recovery evidence/FAIL). Symmetric missing/partial recovery preserves verified original diagnostics while preventing workflow PASS. No partial invalid receipt or unbound guarded bundle is emitted.

The final workflow also passes independently executed finite yaml-cpp structural assertions, four shell-block syntax checks and three embedded Python parses. Forty exact clock-expression boundary fixtures pass; the clock formulas and all phase/job ceilings remain unchanged. These checks establish source/interface readiness, not GitHub actionlint, runtime timeout measurement or executable hosted acceptance. [GitHub's workflow syntax reference](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax) defines the job/step timeout and always-step controls used here; hosted cancellation/VM disposal still require actual execution evidence.

**No remaining material defect reproduced.** Ready for the coordinator's separate workflow registration and source/Git acceptance steps. The original historical native trial remains unrelated evidence; updater workflow dispatch and native compilation are NOT RUN. Private publication restrictions, licensing, target installation/runtime/removal, M2/16K hardware and performance gates remain open.

## Corrected scan and finite diagnostics handoff

The coordinator separately accepts workflow `78f9d914146fba9a6bc4df4052f352e356abf162dd4bfbb23765a88295034bba` and held workstream `19dc01aa12e1c5f6f05e97a4f42147e1decd4624bc51f4646201ffc8c04d3968`. Its bootstrap now names committed stage `64ce7f7c93dd0b37971d0810801241dbd10df6098c14b0106c63d284fbd0ca9a`; source verifier `259b13…` is unchanged. Actual Git/source collection and verification at `11cfd40f2521639f03d6f1b5d9f8296ba5161e73` binds all **85 files / 3,915,170 bytes**, including corrected stage/test, to committed bytes and modes; retained proof is `artifacts/reviews/updater-scan-correction-source-git-proof-20261012.json`.

Root replayed **147 consumer fixtures PASS**: the original 48 regressions plus 99 diagnostic and compatibility checks, including finite phases/reasons/tick relations, unknown/partial/type/poison refusal, recovery roles, terminal byte preservation and unchanged cleanup/PASS gates. The author's independent reviewer also reports all 147 PASS and four shell/three Python syntax checks PASS; held handoff is `/tmp/cachy-updater-workflow-check-0mc69ljr/corrected-handoff.json`. Root actual yaml-cpp contract parsing passes. The four deadline expressions, concurrency and phase/job ceilings are byte-identical to the previously accepted workflow.

The diagnostic consumer delegates to the authenticated stage's exact `diagnostic_projection()` and requires equality of captured fields; it does not adopt a permissive string validator or elevate diagnostics to acceptance. Historical receipts without fields remain valid. No new blocker reproduced. This is corrected source/interface acceptance. Actual run **38232511202 remains FAIL before compilation**; its old terminal omitted the underlying failure reason, so the scan fix is not yet proven causal for that hosted failure. Corrected hosted execution and Rust compilation remain NOT RUN pending a separate finite dispatch.

# Repository/client TEST restaging adapter review

**Corrected held source review PASS; actual accepted native repository-to-client execution NOT RUN.** The final closure below independently closes all four historical findings at review lock `f1fa8ba782fd245264057de2b546b458aef49a3858376a724e0f063db6be2147`. Earlier 64-test defects and hashes remain historical evidence. Only this document and owned temporary reproductions were written; implementation, shared locks, Git, Docker, host installation, default keyrings and native workloads were untouched.

## Historical 64-test checkpoint and independent verification

`review.lock.json` SHA-256 `a812e409897946e73b15537e7a4574757fd13b41a3f3da9b0dcd2d794387af63`. All nine listed source/test/interface/document entries independently match their actual SHA-256, byte count and mode 0644.

| Held file | SHA-256 |
| --- | --- |
| `adapter.py` | `ec83712366befd6075dc8619ac673e989494691ad71e1dbad48e376e778f54f0` |
| `gate.py` | `981cb993d2107e03ca4656a6f37dde6bb66f0b82ab25fecb2087d693f84e0479` |
| `interface.json` | `3e1582f77c1aef4d99a833bdc7e8a5fb83cd7c4500317dda14f004e91a5db5d6` |
| `test_adapter.py` | `1dfe8eb5556af4e9e4db10f61f6b5d7f291d4fcdbe160e50ea0666f2319df2d5` |
| `test_gate.py` | `62fdd3c2a36e5c4bdbbab89623981d8d7bf854c37738b3d0530c05f5ad06fb45` |
| `test_commands.py` | `aa96dc1378102d6fc63dfd82c9aa2af10d4c905ada050161bc3eac68e874cd4a` |
| `test_pipeline.py` | `0922eaad82b29f07a324814564f30d6dc8718db7b043a3ec232da5ae85c3c741` |
| Workstream document | `9b766b0ed8d89437766f90da2ffe4d3d8901f300081e897d9db423f8113d0f37` |

Independently ran **64 tests PASS, zero skips**, 13.800 seconds:35 gate, 21 adapter,5 real child-process bounds,3 modeled complete-pipeline tests. The initial sandbox run failed seven tests and one error when temporary GPG agent sockets were unavailable; approved local-fixture access allowed the unchanged suite to pass. The suite executes real temporary TEST signing, repo-add, frozen release verification and seven client CLI cases; its original native/base/crypto observations remain deliberately fabricated. No actual accepted native repository input was supplied.

## RCS-PROJ-1: current complete CI projection refuses

The gate reconstructs only the former six status-log aliases when checking raw/projected repository equality. Corrected CI publication also adds nine operation aliases, command public log/stderr references, `sync_cache_reset.public_receipt`, and `public_operation_index`. Those legitimate additions cause `unknown repository projection change` before an otherwise eligible complete current bundle can pass.

Independent controlled authority fixture passes its original gate. Adding the legitimate reset public receipt and operation-index fields to its projected record and coherently updating the projection hash/length and externally supplied authority hash reproduces the refusal. Reproducer `/tmp/repository-client-stage-independent.py`. This identifies a predicate incompatibility, not native execution; the finite current15-capture protocol must be validated with exact index/file/reference bindings rather than deleting unknown projected fields or weakening equality generally.

## RCS-SPAWN-1: cancellation loses a newly created child

`Commands.run()` calls `Popen` before entering its cleanup `try/finally`, with no cancellation protection around assignment. A real SIGTERM delivered after actual process construction but before that assignment runs the adapter's real cancellation handler and raises KeyboardInterrupt. The actual owned sleeper remains alive because no stored process object reaches cleanup. The reviewer killed its process group and reaped it afterward.

Reproducer `/tmp/repository-client-stage-independent.py`: actual command runner, real temporary30-second Python child, mocked scheduling wrapper around actual Popen and real TERM. This can also affect signing/tool descendants. Protect spawn/assignment against cancellation, and retain/reap the child before propagating the cancellation. Work-directory removal and signer-only cleanup cannot prove disposal of a lost arbitrary tool child.

## RCS-FINAL-1: cancellation during final descriptor disposal leaves PASS

After writing and verifying the durable PASS result, `execute()` returns through its outer `finally`. That block closes the publication descriptors under `defer_cancellation()`. TERM received during `Publication.close()` is remembered, then raised when deferral exits **outside** the preceding failure handler. The CLI can terminate with cancellation while its public `result.json` still records PASS.

Independent reproduction uses actual gate, metadata check, publication and handlers; only successful restaging is modeled. A real TERM at final close produces KeyboardInterrupt and leaves the actual durable PASS JSON present. Reproducer `/tmp/repository-client-finalization-independent.py`. Preserve receipt authority through final disposal/handler restoration: cancellation at this boundary must invalidate or replace PASS before retained ownership handles are lost. Earlier write/teardown cancellation regressions do not cover this final return boundary.

## RCS-DIAG-1: raw diagnostic admission is not independently enforced

The gate hashes and binds transaction logs, but accepts zero-exit positives based solely on the raw receipt's `positive_diagnostics='PASS'`. It never applies a diagnostic predicate to those actual log bytes; negatives likewise require only nonzero exit and equal snapshots, aside from separately checked revocation status.

The second reproducer changes the positive baseline-install raw log to `error: could not execute hook script (No such file or directory)`, updates all raw/projected/hash/authority bindings and retains the zero exit/PASS flag. Actual `gate.accept()` still returns `PASS-input-acceptance`. This is the same class of ancillary error that previously invalidated a native repository positive transaction. It is a controlled authority poison, not a claim that a real reviewed coordinator has accepted it. The workstream promises clean positive and signature-specific negative raw diagnostics; implement those predicates against the pinned producer policy, or explicitly narrow the gate's claimed independent validation. Do not add a generic diagnostic waiver.

## Positive boundaries and actual limits

The data-only gate requires an externally supplied authority digest; a self-declared manifest digest alone does not authorize input. It requires aggregate and named-stage PASS, exact eleven case identities/order/booleans, native architecture/capability/interface assertions, 341 exact package rows and existing input pins, raw/projected receipt hashes, snapshot continuity and full owned payload maps, reset/final database pairs, complete six repository artifact maps, canonical regular aliases, three distinct signer identities, a typed complete external crypto attestation and both owned-container name/ID absence assertions. It reads finite no-follow regular inputs and rechecks their identity/tree. It cannot turn these externally attested data statements into observed native execution or original cryptographic verification.

Metadata must independently bind the accepted authority, complete341 name/version set and explicit dependency/provides/conflicts/files metadata. Frozen release dependency/provenance checks run before key generation. Generic policy declares no M2 models; selected artifacts are exactly four project archives, excluding the probe. Baseline native and updated synthetic provenance labels remain distinct. Restaging creates a fresh temporary TEST primary, preserves archive bytes, produces new signatures/databases and development envelopes, calls the unchanged release verifier and frozen client, and explicitly records `original_B_continuity=False` and external-only original crypto acceptance. This is a separate signer experiment, not original A/B continuity or production promotion.

Current actual native inputs remain ineligible: run38227121568 has aggregate/exportFAIL; excluded original bytes are not recovered by references; complete base transaction/provenance/policy metadata and stronger container-ID absence evidence are pending. Existing reconstruction/control fixtures and modeled crypto/base attestations cannot satisfy those native gates. The adapter does not provision its own container/network isolation or establish source/toolchain acceptance; reviewed native worker wiring remains separate.

Normal command/output/resource budgets, independent teardown budget, signer PID/owner/start identity, no-follow owned publication descriptors and before-publication private-directory absence are useful controls. They do not close the reproduced spawn and final-return schedules above. Source correction/review/refreeze and actual accepted-input execution remain pending. Native compilation/installation, production trust/endpoint/promotion, supported Asahi/M2/physical16K behavior, recovery and measured performance are NOT RUN/unproven.


## Final held source: independent correction closure

`review.lock.json` SHA256 **`f1fa8ba782fd245264057de2b546b458aef49a3858376a724e0f063db6be2147`**,3425bytes,mode 0644. Independently rehashed all nine listed files; every actual byte count and mode 0644 matches the lock.

| Corrected held file | Bytes | SHA256 |
| --- | ---: | --- |
| `adapter.py` | 35204 | `69ad53b4bc041d37536ad15a4ced7efa4cb2d61bcd6cb4a62fdfce8a7dbd52ab` |
| `gate.py` | 47774 | `fa39cfd6b5c1a3718f888d3f9fdb51f5bb8e38a7e57a98d1c4c8c570ea70af1e` |
| `interface.json` | 12742 | `731aab034df785bd813cbc82087d239bf487dc7c1f29e7b3eda211306574ac94` |
| `test_adapter.py` (unchanged) | 24312 | `1dfe8eb5556af4e9e4db10f61f6b5d7f291d4fcdbe160e50ea0666f2319df2d5` |
| `test_gate.py` | 47068 | `1a853e04081694554b63475d85237754f2b6ea638f9b4266a47f9cc66db16c51` |
| `test_commands.py` | 6549 | `807ed617c6bdd840c1271e03803f41bfedf48d5dd375b8a068e0bed93ab6d008` |
| `test_pipeline.py` | 11119 | `cc0265ccc5d3197690fb51604914e2fa98748157f8fadfcceb1fbe5dde14ab50` |
| `README.md` | 4957 | `3092453ea5cae19c52006d2d26b31697ab23d94ccea8d8c9e6b8e7959f69005b` |
| Workstream document | 18391 | `46e6705999697379279444d708656a177817fc36afb2238f0ae46a6e143f5744` |

Independently ran the complete **79-test suite PASS, zero skips**, 17.844 seconds, with approved access only for owned temporary TEST GPG sockets/local signing and client processes. Counts: 45 gate, 21 adapter, 8 command-boundary and 5 modeled full-pipeline tests. New TEST signing/release/client work is real; original native/base/crypto assertions are modeled. No accepted actual native repository bundle was substituted or inferred.

`/tmp/repository-client-closure-independent.py` preserves the original scheduling/poison mechanisms from the two historical independent scripts and changes only expected corrected outcomes. Focused closure results:

- **RCS-PROJ-1 closed.** A complete current fixture now passes. Independently invoked the actual read-only CI `repository_projection.operation_files()` on the same raw bytes: its exact nine-row index equals the gate fixture index, every operation public copy equals its captured raw bytes, and all six legacy public logs resolve identically. The explicit reset public receipt, operation-index pointer and command public log/stderr references remain exact. The gate checks all 15 copies and coherent raw/public/authority hashes, source positions, reset inventories/snapshots and final dependency diagnostic. Unknown projection fields/references, malformed index scalar types, substituted copies and missing index remain refused by passing negative tests.
- **RCS-SPAWN-1 closed.** The same actual Popen wrapper injects real TERM or INT after real child construction and before outer assignment. Spawn now occurs inside the cleanup try under deferral. Both signals raise cancellation only after retaining and reaping the child; pipes close and no child survives. A second actual INT injected during process-group kill is also deferred until cleanup completes. All temporary children were independently checked stopped/reaped; the deferred-context stack is empty afterward.
- **RCS-FINAL-1 closed.** Repeated exact terminal-close schedule with actual gate/metadata/publication and modeled successful restaging. Real TERM immediately before descriptor close and real INT immediately after descriptors close now return FAIL, with no public PASS receipt. Closure occurs inside the caught transaction. If handles are already closed, removal recovers only the recorded output inode under the same no-follow ancestor chain, then invalidates and fsyncs the receipt. The full suite additionally performs these before/after schedules after all seven real TEST client cases and checks private cleanup PASS. Nested signer-stop spawn cancellation remains deferred until actual private signer teardown/directory removal complete.
- **RCS-DIAG-1 closed at the pinned producer policy.** Repeated the coherently rehashed positive stdout hook-error poison and a stderr root-directory error; both now refuse even with zero exit/PASS flags and matching projected records. A non-signature negative diagnostic and a negative transaction altered to exit 0 refuse. The gate checks both positive streams against the same anchored error/chdir predicate as the proven frozen repository source; other negative cases use its existing signature/trust-word predicate. Missing-DB failure uses the exact four-line selected local signature path and typed rejection kind, with no general download-error exemption. Passing tests reject positive/nonpositive exit and scalar-policy alterations. This mirrors the existing source predicates, rather than claiming a stronger arbitrary-language diagnostic classifier.

Nested cancellation guards relay pending signals outward until complete private teardown finishes. The finite source/tool/checksum, current-clock TEST key/envelope, strict client signer/namespace/state, protected/coordinated dependency/provenance and four-archive/probe-exclusion boundaries remain in place. Neither the new captures nor diagnostic correction weaken the generic credential guard or package/platform policy.

**Disposition:** all four reproduced findings are closed at these held bytes; no new material blocker was reproduced in the bounded re-review. Source is ready for coordinator integration/freeze and a controlled accepted-input trial. Current historical native input still lacks complete accepted aggregate/public/crypto/base-metadata/cleanup evidence, and fixture attestations cannot satisfy that requirement. Actual native repository-to-client execution, original A/B cryptographic acceptance, original B continuity, production trust/endpoint/promotion, target installation, Asahi/M2/physical16K recovery and measured performance remain separate pending/NOT RUN gates. Reviewer changed no source, lock, shared metadata or Git.

## Coordinator source acceptance

Root independently replayed all79 current source/TEST-signing/client tests PASS/zero skips/17.779seconds with approved owned temporary GPG sockets. The independent four-mechanism signal/projection/raw-diagnostic closure above is accepted. This commits the new adapter/gate/fixtures/review lock as source implementation. Actual accepted repository binary/crypto/immutable cleanup and full same-job base metadata remain necessary inputs; fixture observation records are not admitted as native evidence. Fresh TEST restaging remains a separate lineage, and no M2/Asahi/production acceptance is granted.

# FDK failed initial descriptor identity correction

Status: bounded source correction held for coordinator recheck and admission. Only `packages/libraries/cachy-asahi-fdk-aac/inner_observation.py` and its test changed. Parent reader `inner_evidence.py` (`bdbef4cb…`) and its test (`7cc9b798…`) remain unchanged. No native, compiler, makepkg, Docker, GPG, installation, namespace, network or service actor ran for this correction.

The exact root review receipt is `c52ad7daa213f7395768c6765e54c1676898b8988d7808ce6cdd433256576bb9`, preserved as [`root-checkpoint.json`](../../artifacts/reviews/fdk-initial-descriptor-identity-correction-20261012/root-checkpoint.json). It found that helper `dec7eeeb…` could close a different inode at the same descriptor number after an initial `fstat` EIO/control failure. Its later first successful query incorrectly became ownership evidence. The earlier 363-file packet, root review and all their historical proof remain unchanged.

## Correction

Fresh ownership can be established only by a successful first query in `close_owned`. If that query fails with anything other than Linux EBADF, the private entry remains `identity: None`. Later successful queries cannot adopt an identity and cannot authorize close, even if they observe the original inode. Remaining query slots can establish EBADF (errno 9), which proves release without reconstructing ownership. Non-EBADF query errors keep the same first error and first control. All paths remain within the existing three query/close slots.

Previously known identity still permits its bounded retry: a matching query can authorize close; a differing identity is retained and refused. Successful close or queried EBADF retires an entry. The correction adds no field, dependency, timer, recovery API or global framework. Only `close_owned` changes its AST; the eleven-module grant and every other helper function, schema, publication/refusal and business-failure behavior remain unchanged.

Retained unknown ownership keeps `write_failed`, cancellation and refusal sticky. A later healthy query or a fresh recorder cannot turn that uncertainty into healthy evidence. Existing first compiler failure/return facts remain unchanged. The positive controls also check that release established by EBADF does not undo an already durable refusal or prior nonzero fact. Descriptor recovery under persistent faults is not claimed.

This resolves the demonstrated initial-query-failure/different-inode reuse schedule without assuming that a failed query leaves the descriptor number exclusively owned. It does not authenticate an FD generation, make known-identity query and close atomic, distinguish same-inode reopening, or close the allocation-to-registration cancellation window. These limits remain unverified and are not silently promoted to broader safety claims.

## Validation

The final helper is `a5074240e9072c6fff15efd86d80d521d775ef0e1c2475ebe1710a3165df6c2a`; its test is `d62929e72e38b864fd430fdd71b7b8479f97f6180ef629627cc6b76210b103af`.

- [`held-test-receipt.json`](../../artifacts/reviews/fdk-initial-descriptor-identity-correction-20261012/held-test-receipt.json): 142 passing isolated-Python tests, zero skips/PYC: helper 25, inert compiler-call models 24, unchanged parent 26, worker 27, public projection 40. The 136-file held graph differs from the preceding final graph only in the two helper files. The existing suite includes bounded child-Python self-SIGINT and Unix IPC/fake-Docker fixtures; no actual daemon or native compiler is executed.
- [`independent-peer/receipt.json`](../../artifacts/reviews/fdk-initial-descriptor-identity-correction-20261012/independent-peer/receipt.json): four preserved RED controls reproduce foreign close against `dec7eeeb…` using pure descriptor models and actual private FD reuse, followed by twelve GREEN controls against `a5074240…`. GREEN covers the same EIO/control foreign-reuse cases, known-identity retry, unknown EBADF retirement, retained ownership and sticky first-7/write-failed/cancel/refusal across fresh recorders. These controls use mocks and owned temporary files, with no real signals or actors. Fixture teardown occurs only after measuring the exact live descriptor and checking its identity.
- [`prior-controls-peer/receipt.json`](../../artifacts/reviews/fdk-initial-descriptor-identity-correction-20261012/prior-controls-peer/receipt.json): all 44 descriptor schedules replay, with 41 expectations unchanged and three explicitly revised. Initial `query-before`, `control-query` and `control-over-business` now require unknown retention and zero close rather than recovery by a later initial identity query. The parent schedules use its final held source; assertions remain unchanged. Older scripts, results and intermediate pins remain historical evidence.

`integrated-red.log` preserves three expected failures against the older helper, and `integrated-green.log` records all 25 corrected helper tests. No failed run was removed or relabeled as a pass. [`source-delta.json`](../../artifacts/reviews/fdk-initial-descriptor-identity-correction-20261012/source-delta.json) and `helper-two.patch` make the two-file correction reviewable.

## Separate coordinator work

The shared modern public completion gate (`require_complete=True`), recipe's 23 source entries/checksums, reviewed maps, workflows, native dispatch and final admission remain outside this packet and coordinator-owned. This work updates none of them, does not certify their current status, and cannot substitute for their separate proof. The new helper bytes require exact reconciliation before any gated actor run; the older recipe proposals retain their older pins.

Historical actual FDK8 remains FAIL at exit/attach 4 with unknown inner function/compiler invocation cause. This source correction provides no new attribution or successful native build. Package byte-pair/reproducibility, installation/removal, ABI and AAC integration, Asahi/exact-M2 behavior, publication terms and performance remain separate unfinished acceptance work.

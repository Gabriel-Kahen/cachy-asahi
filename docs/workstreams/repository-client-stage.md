# Repository release-client follow-up interface review

Review date: 2026-10-12. Deliverable: source-audited adapter and declarative
[interface](../../scripts/port/repository-client-stage/interface.json).
Implementation and local synthetic integration tests: completed. Actual accepted
repository-input follow-up execution: **NOT RUN**.
This work owns only the new interface directory and this document. Repository,
release, client, CI, KSM and shared manifests remain held or with their owners.
The roadmap and package inventory were read before this review.

## Actual repository progress and remaining export gate

Native run `38227121568`, source
`5ce7802387bc257ce2da4d7a9902a09d1ebc4d2d`, has repository component **PASS** and
all eleven exact cases **PASS**, including revoked-A cache reset and clean final
B upgrade. Its decoded receipt reports native aarch64 execution with 4096-byte
pages and private-state removal. The aggregate is **FAIL** because public export
rejected nine reset/cache/dependency evidence paths. The decoded aggregate also
records confirmed owned-image absence. These observations do not establish a
complete accepted public repository bundle, production trust or M2/16K support.

| Retained decoded observation | SHA-256 |
| --- | --- |
| `repository/result.json` | `90886131ce205caeb3a288ba17ee4bbf7d7256fd327b7b575f2b12499256aad6` |
| `repository/export-manifest.json` (FAIL) | `687929680fe171c9e3532fa2cb0158b0da8282b1bc54eb8f5481c8e9228efee0` |
| `repository/repository-inventory-projection.json` | `04ce3ff785fa5d8dfc51f37ebbcddb466b3742cfa2649ec3ed4233635c830cd5` |
| `summary/result.json` (FAIL) | `72556086f3aeedcb7eff47214f24705056ea4514bdb1bc71f2f2cfc58cb8ba7c` |
| `native-evidence/bootstrap.json` | `d9bac4c5483fd8421257110cd23df1610f813d6b6361adeae3208809c0168f6c` |

Paths above are relative to `artifacts/ci/38227121568/decoded/`. The projection
binds original receipt hash
`128219c6b9a38895a51b183b989fa0964416e73960bdc7c057eaecd8fd9d8d1e`;
that raw receipt has not been independently consumed in this review. The reset
receipt hash recorded by the component is
`03f517a98b51915a348c570cbe5e99b23473989f80e71b837734823ecbd905ed`,
but its bytes were excluded from this public export. References to unavailable
bytes cannot satisfy the follow-up gate.

The CI owner is correcting publication. Preserve the proven transaction/reset
source hash `49c87f41bbb2fe1288251f16019f12aaeabb98d81ff5339387873e88e903b940`.
Any corrected producer needs its own reviewed source freeze and actual complete
export acceptance; never rewrite the failed run into a successful run.

## Gate before any client execution

The interface fixes the ordered eleven case names and their seven rejection/four
success flags. Require exact identities, not a case count or top-level PASS.
Bind them to the externally pinned source/run/attempt/job, nonce, native runner
and daemon, immutable image, actual bootstrap, complete 341-package lock and
initial source/fixture byte-and-mode maps. Current observed pins are image
`sha256:31761cc83f53ed4013ad76f89ec47d9088824a5f3edef3069c7d20a0c45a72bc`,
package lock `89bdb06fea1862b5a6e02b77a4b98f6e04755b02327d875a716bd792929f3a4f`,
inputs `3c16c37d1b12cc84a88572e82ab8ad59e7f3b5ed0d08f09ddf72a69f4711d650`
and initial lock `19d4662735c096a90417a92e501f45a8ffd7d4cc3b5bd97a7d088b95aaffe815`.
Future runs must supply their actual pins rather than inherit these observations.

Require negative raw diagnostics and identical complete installed inventory and
owned payload before/after maps; positive transactions need zero exit, clean
diagnostics and exact versions/payloads. Retain the narrowly typed missing-DB
rejection, reset receipt and current-path proof, final B cached DB/signature
hashes, strict configuration, exact guard and outer owned-container absence.
The copied repository inventory includes the 341-package generic base, four
project packages and synthetic probe. The probe is not a release candidate.

Then verify the complete public manifest against actual bounded regular-file
bytes, raw/projected receipts and logs. Independently verify healthy A/B packages,
both DB types, embedded signatures and DB contents in isolated public-only GPG
homes. Verify all certificate primary identities/self-signatures/expiry and A's
revocation. Keep original A baseline and revoked-A verification homes separate;
baseline signature validity does not establish current trust in revoked A.
Expected tamper/omissions must match exact recorded differences. Check the signed
alias map and each regular materialized alias against its canonical bytes.

Original verifier certifications used `--quick-lsign-key` and were not exported.
Source, native trust-transition logs and case results support that history; the
public certificate is not portable cryptographic proof of those certifications.
Neither importing certificates nor seeing `VALIDSIG` alone establishes trust.

### Receiver digest mismatch found during review

Frozen `scripts/ci/development/initial_artifacts.py:82` accepts only OpenPGP
hash algorithm 8 (SHA-256). Actual run logs, including
`repository/151-verify-database-tampered-package-B.txt` and
`repository/180-signature-revoked-A-status.txt`, record database signatures using
algorithm 10 (SHA-512). Package and alias signatures use SHA-256.
The complete public bundle is currently absent, so direct receipt-bound binary
receiver acceptance remains **NOT RUN**. The source/log mismatch is a concrete
compatibility issue for the CI owner to resolve with an explicit reviewed policy
and actual binary evidence. Preserve the generic credential filter; a broad
signature-policy bypass would not establish acceptance. The frozen client already
accepts digest algorithms 8, 9 and 10 with full-primary and validity checks.

## Original B continuity route (unavailable)

The repository export contains packages, databases, aliases and certificates.
It does not contain the release `spec.json`, `base.json`, per-package provenance,
signed `release.json` or signed client envelopes. The frozen client requires the
same externally pinned primary signer for envelope, release record, both DBs and
every package. A new metadata signer cannot wrap the existing B signatures.

The retained B database contains all five packages, including the probe. An exact
B-continuity sandbox must retain that set and explicitly mark the whole bundle
synthetic DEVELOPMENT. A four-project-package release candidate must exclude the
probe and generate a different database with new signatures and separately tested
artifact maps. Neither route turns fixtures into a stable release.

Original B's private key is deliberately destroyed before authoritative PASS.
The continuity route therefore requires the producer to prepare and sign the
complete development handoff while B is still alive, with release semantics and
package provenance already checked. Its provisional bytes can become eligible
only after all eleven cases, export integrity and required cleanup pass. Never
retain/export private keys or infer a signing capability from a public certificate.
Current held sources provide no such handoff, so the current run cannot supply it.

`release.stage` re-signs packages and rebuilds/signs databases. Calling it creates
new signature/database bytes; it cannot preserve the already tested exact B
mapping. A continuity adapter would need an independently reviewed implementation
in the new directory that constructs metadata around unchanged artifacts and
passes the frozen `release.verify_release` semantics. No B-continuity adapter was
implemented or run here. A separate new TEST signer/restaging experiment can
reuse archive bytes, but would need its own lineage, signature/DB maps and evidence
and could not claim original B continuity or production promotion.

The release verifier requires dependency/provides/conflicts/ownership metadata,
protected/coordinated platform policy, license records and provenance. A generic
341-row name/version lock does not provide that target metadata. Retain original
native packages, reviewed changed-package derivatives and synthetic probe as
distinct evidence roles. Do not describe generated upgrades as repeated native
builds or invent Asahi compatibility to satisfy the release policy.

## Implemented separate TEST signer route

The coordinator selected the separate new signer route after this initial
interface review. [adapter.py](../../scripts/port/repository-client-stage/adapter.py)
copies exactly four accepted project archives without changing their bytes,
excludes the probe, generates a temporary TEST primary and recreates package
signatures, databases and signed release/envelopes. It records the accepted native
authority hash, selected baseline/updated role, original signature lineage,
new signature/database hashes and a distinct `test-restage.*` namespace.
Original B continuity is explicitly false throughout the new receipt and lineage.

[gate.py](../../scripts/port/repository-client-stage/gate.py) consumes an authority
hash supplied outside the input tree. It checks actual aggregate PASS, exact eleven
case identities/flags, raw command/snapshot bindings, full inventory/payload checks,
raw/projected receipt consistency, strict configuration, all six public artifact
maps, reset/final cache binding, source/fixture/runner/bootstrap identity and owned
cleanup. Original repository cryptography is a typed, byte-bound **external
acceptance attestation**, not cryptography performed by this pure data validator.
The coordinator must supply that accepted cryptographic evidence before signing
work can begin. New TEST cryptography is actually exercised below.

The adapter separately binds reviewed generic metadata to that authority hash.
Its full base package names/versions must match the accepted 341-package inventory;
each record also needs real architecture/dependency/provides/conflicts/files.
Protected/coordinated policy is explicit and `supported_models` is empty. Four
artifact-bound provenance records retain source/recipe/license/build origin; an
updated derivative must remain labeled synthetic. No Asahi facts are fabricated.

Before creating a key, the frozen release dependency and provenance checks must
pass. The adapter constructs the local generic bundle directly because invoking
`release.stage` would require inappropriate M2 model declarations. It calls the
unchanged `release.verify_release` semantics on the new complete signed bundle,
then the unchanged client CLI for seven finite cases: read-only cold verification,
sequence 1 apply, unchanged read-only repeat, sequence 2 apply, genuinely signed
rollback rejection, genuinely signed same-sequence alteration rejection, and wrong
namespace rejection. Checkpoint hashes and durable apply results are retained.
Fresh TEST key validity and envelope expiry use the real current clock. Previously
accepted archive provenance is historical input; no live A/B trust is created.

Commands have a 45-second/1 MiB output bound, a 2 GiB child address-space cap and
the working phase has a 300-second
deadline. Private teardown has a separate 30-second budget and 10-second command
caps. It checks the private agent PID/owner/start time, stops it, removes all
private scratch and proves absence before publication. SIGINT/SIGTERM are deferred
through agent stop, directory removal and failed receipt invalidation. Public
output is bounded to 16 MiB per file, 64 MiB total and 512 files. Current directory
ownership is checked against retained ancestor descriptors; writes use no-follow
directory-relative opens. The final complete output bytes/inventory are rechecked.
No host package installation, default keyring changes or network requests occur.
The adapter does not provision or verify a new container/network namespace;
coordinator-owned native wiring must supply the reviewed worker isolation and
source/toolchain freeze. Local process bounds alone are not native worker evidence.

### Exact current input blockers

Current decoded run has no accepted complete public bundle or aggregate PASS, so
actual execution is refused before signing. The existing public cleanup record
also lacks the stronger container-ID absence observation required by the new
gate; name-only absence must not be rewritten into observed ID absence.
The retained builder lock supplies 341 names and versions, but not a full
receipt-bound set of package `depend`, `provides`, `conflict` and file ownership
records. Available per-package audits are not a complete base transaction.
Separately reviewed generic protected/coordinated policy and complete four-package
provenance/source/license records are also required. `execute` returns explicit
**NOT RUN** metadata blockers if authority passes but this metadata is absent.
These are producer/data requirements, not reasons to fabricate platform support.

## Original B client plan and production boundary

The following B client plan remains unimplemented; the selected route above uses
the new TEST signer instead. After all preceding gates pass, first run the separately pinned release semantic
verifier. Then exercise B cold read-only verification, bounded checkpoint apply,
same-envelope read-only repeat, higher sequence apply, genuine signed rollback
and altered same-sequence rejection, and wrong external signer/namespace rejection.
Produce the required signed envelopes before B cleanup. Use the real clock and
still-valid keys; these disposable keys expire after one day. Historical review
of an expired run cannot authorize a fresh successful live client verification.
No fake clock or bypass may turn an expired input into current acceptance.

Record command/log hashes, exact input signatures, state byte hashes/modes,
expected failure classes, cancellation, process/temporary-state cleanup and a
final development receipt. Rejected operations must preserve checkpoint bytes.
Do not run client fixtures in place of these artifact gates.

The frozen checkpoint binds namespace, scope **and signer**. A→B on an existing A
checkpoint is rejected even with a higher sequence. Separate B cold state proves
B verification only. An actual client A→B rejection case requires complete signed
A and B bundles plus authenticated evidence of an A checkpoint actually applied
before revocation. Do not manufacture that state or apply A using a stale
nonrevoked certificate as current trust. Absent prior-application evidence leaves
that case **NOT RUN**. Native pacman A→B trust-transition PASS remains separate
evidence.

Production key custody/bootstrap/rotation/revocation distribution, published
endpoint operation, stable promotion, target installation/removal, fresh Asahi
journey, M2/16K checks, recovery and measured performance retain separate gates.
This software adapter contributes to maintained repository work; all five roadmap
workstreams remain mandatory. Validation distinguishes local modeled acceptance
fixtures with real TEST signing/client execution from actual accepted native
repository-to-client execution, which remains **NOT RUN**. Frozen repository,
release and client source files were not changed.

Local validation: **79 tests PASS, zero skips**: 45 data-only gate checks, 21 adapter
regressions, eight real child-process bounds and five complete modeled-pipeline
checks. The complete pipeline admits a real byte-bound fixture through the actual
gate, then runs real TEST signing, repo-add, frozen release verification and all
seven frozen-client CLI cases. Its native/base/original-crypto assertions are
explicitly fabricated; no original repository cryptographic acceptance is inferred.
Independent review reproduced and confirmed fixes for expired cleanup budgets,
parent-directory replacement, cancellation during agent/directory teardown and
secondary cancellation during receipt invalidation. AST, JSON, file links and
whitespace checks passed. The adapter source/tests are held for coordinator wiring;
CI, Git and shared manifests were not edited here.

### Independent-review corrections

The earlier 64-test packet had four demonstrated gaps: it recognized only the six
legacy log projections, trusted positive diagnostic flags without checking raw
bytes, could lose a spawned child before assigning its handle during cancellation,
and could leave a PASS receipt if cancellation arrived during terminal descriptor
closure. These were implementation blockers despite those earlier tests passing.

The corrected gate reconstructs the current six-plus-nine projection protocol.
It binds the exact nine-row operation index, raw/public hashes and identical bytes,
ordered source command positions, reset inventories/empty stderr/snapshots, final
relation diagnostic and explicit public receipt/operation references. Its coherent
fixture is compared with the read-only current CI producer helper. Extra projection
changes, incomplete indexes, substituted copies and mismatched references remain
rejected. It verifies raw stdout and stderr independently for all positive
diagnostic flags and checks the current negative signature/trust pattern; only
the exact four-line selected-local-DB signature failure receives its typed exception.
Poisoned diagnostic fixtures remain in private temporary test directories.

The adapter now enters its cleanup try before `Popen` and defers cancellation until
the child handle is assigned, then protects group kill/reap/pipe closure against
secondary signals. Terminal publication close occurs inside the caught transaction
before success returns. If descriptors have closed when cancellation fires, receipt
invalidation reopens only the recorded output inode through unchanged ancestors.
Real SIGTERM/SIGINT regressions cover spawn assignment, secondary child cleanup,
and both sides of terminal publication closure. The latter runs real TEST signing
and seven client cases before proving overall FAIL, receipt absence, private cleanup
PASS and unchanged inputs. Independent bounded confirmation passed these paths;
actual accepted native input execution remains **NOT RUN**.

Nested command spawn/reap guards relay pending signals to the surrounding private
teardown guard. A real SIGTERM immediately after the `gpgconf --kill all` child is
spawned therefore completes signer stop and directory removal before reporting
FAIL. This regression retains private-cleanup PASS and publishes no output.

# Independent updater registration and consumer review

**PASS for the final source registration and workflow consumer hold.** The
registered helper is a real recipe input; corrected source closure accepts the
exact 86 files; modern workflow success requires both complete bound diagnostic
groups and both fixed selectors while retaining the original acceptance gates.
Fresh reviewer controls passed 33 tests, zero failures, errors or skips, including
57 workflow causal cases. This is source readiness, not committed Git or native
build/dispatch acceptance.

## Exact final hold

| Component | SHA256 |
| --- | --- |
| READY64 | `84eb3a020ed0cca3fe977feabc2b18bcaf6c6ae3811a5df5129c700ed9d8012f` |
| Stage | `3b38a7de9adea343dbc3cc08e3909e23b840ca12f0211e40e38afd7172b92012` |
| Corrected source collector | `4d3e3fd9848aaed94154f786b04a5ae07c7816dcef82857b671b51555895eacb` |
| Corrected source tests | `9e53e6ec2006732e771b0ef14a120c03a5cf4980040da7b1f8867ba26088785b` |
| Adopted workflow | `52320dfb23f192b3d22a1161e58cc0c8fcb65464f29688457461699af2516ba4` |

Registration records are
`artifacts/reviews/updater-worker-diagnostic-registration-20261012/registration.json`
and `registration-count-followup.json`. The workflow proposal receipt is
`artifacts/reviews/updater-worker-workflow-proposal-20261012/final-receipt.json`,
SHA256 `05a4f750b8ff2399344afd8b7a68adf194c7be534e70f71d6d105691d3e69725`.
The current primary workflow exactly equals the captured proposal. Previously
accepted inner-source/peer receipts `bb4e77ed…` and `f45ba9cc…` were authenticated
through the complete captured catalog, not relabeled as this review's execution.

## Recipe and map registration

PKGBUILD and `.SRCINFO` have the same 23 ordered source names and checksums.
All 21 local input hashes match the actual files. The two archive declarations
remain unchanged; no archive was read, extracted, generated or built. The new
`worker-diagnostic.py` checksum is
`2bde1dc53bc63fc8a536265100ed07ede16d3b96faa37af5054b977984c73048` in
both recipe vectors and READY. Entry/worker loaders use it from the authenticated
recipe location; it is not merely an inventory label.

The runner-inputs lock retains its exact old top-level and file keysets. Only
PKGBUILD and `.SRCINFO` hash rows changed; non-file fields are unchanged. READY
grows from 63 to 64 package rows with no removal, exactly the 12 stated existing
rows changed, and only the diagnostic helper added. All actual package hashes
match. The eight root rows remain unchanged and match their actual files.

Stage differs from its retained baseline only in READY_SHA. The independently
derived source set has **86 files, 4,180,952 bytes**, with exact hashes, byte counts
and modes. Those rows also match the coordinator's source86 proof. The unchanged
128-file and 32-MiB limits are sufficient without being expanded.

## Closed cardinality blocker

The initial unchanged collector
`259b13b210123d90f824f21bf7662785d50c7586519a78451ab62e97ec577d5f`
required exactly 63 package rows and could not accept READY64. The coordinator
then changed only that literal to 64 and adjusted the test fixture/expected
synthetic closure to 64/81. Reversing the collector's sole literal reproduces
the original source hash exactly. Those exact old bytes were captured and
executed against the new source tree: they refuse with `source-ready-file-count`
before any Git operation. Current exact bytes return the required 86-file set.
The refusal remains explicit; it is not overwritten by the corrected PASS.

An independent current-source model exercises collect, verify and stage snapshot
against all actual 86 captured files, with fabricated committed Git replies.
It validates the exact file/hash/mode set and 4,180,952-byte total. This is a
source/copy interface model, not actual committed Git proof. Synthetic source
tests expect 81 objects because their smaller controller set is deliberate;
that number is not the production closure count.

## Strict workflow consumer

The tested proposed consumer bytes exactly match the Python body extracted from
the adopted workflow. Reversing precisely its six declared additions/replacements
returns the original literal-rebound workflow bytes. Every other original
workflow byte, including the compile/package/comparison/cleanup gates, is retained.

Modern success requires both build status records. Each must contain all four
diagnostic group fields, BOUND/bound classification and a valid parent's
raw-capture digest. Both fixed `build-1-diagnostic.json` and
`build-2-diagnostic.json` selectors must exist, use the exact diagnostic handler
and source/destination tuple, and stay within 4,096 bytes before JSON parsing.
The diagnostic binds controller, image and entry-script hashes to the same
observed container State. Its parsed object must equal the parent's nested
diagnostic and satisfy the original accepted compiler-return/acceptance,
controller-validation, first-failure, cancellation and write-error predicates.

The parent digest identifies its once-captured raw diagnostic bytes. The public
selector may use a different JSON encoding, so the workflow correctly avoids
recomputing that parent digest from pretty selector bytes. The projection manifest
separately binds the actual selected bytes. These hashes do not attest compiler
execution or explain unexported output.

Diagnostic acceptance remains additional to original successful compile/package
proofs, input/image/hash equality, byte/payload/PKGINFO comparison, distinct worker
identities, clean observed exits and positive cleanup. Historical absent-group
projection remains readable for FAIL evidence, but cannot become modern success.
Late replacement cannot change captured validated bytes or repair an initially
invalid captured selector. No paths, argv, environment, keys or raw logs are
added to public diagnostics.

## Fresh verification and artifact provenance

The 33 selected tests comprise 13 source-contract models, four stage
authentication/snapshot controls, three independent collect/loader controls and
13 workflow tests with **57 causal cases**. They cover wrong pins/modes/closures,
late source/HEAD drift, missing/extra/cache/link inputs, real valid unchecked
poisoned PYC refusal, captured-byte execution despite late pathname replacement,
partial/absent diagnostic groups, binding/State/nested-object mismatch, raw size
bounds, cancellation/compiler facts, original acceptance gates and late selected
file changes. Python ran `-I -B -S -Werror::ResourceWarning`; both source captures
retained zero PYC files and unchanged hashes. The intentionally forged PYC lived
only in its owned temporary fixture. All Git/native facts were mocked.

The first reviewer test harness stopped before running tests because its initial
copy omitted the peer receipt referenced by the separately authenticated capture
catalog. That catalog was fully verified and copied, and the complete fresh run
passed. The initial log is retained. The coordinator's separate 23-source-test
run was not counted as reviewer execution or added to the 33 tests.

One known historical index mismatch is recorded rather than concealed: the
proposal's final receipt indexes original `tests.json` SHA
`500d6727a780f51ad2d6e7e84ac4a5bd7452f8cfe6dd23ebd98b32131c53271b`,
but the named file currently has the coordinator's rerun derivative SHA
`609f3cd98f82f203c07de3d5003240d3a87fadbc471a608ebd3771b8581c4bb2`.
All other indexed files match their declared bytes/modes/hashes. The derivative
is captured under an explicit derivative name; it is not claimed as the indexed
original. Source/code bindings and this review's fresh independently retained
results supply the validation used here. The historical index still needs its
owner's reconciliation or original-file restoration.

Both static peers found no remaining scoped registration/consumer defect after
the cardinality correction. No source, shared maps, workflows or Git were edited
by this reviewer. No archive, compiler, Docker, GPG, package/install or hardware
actor ran. Historical native failures remain unchanged and are not retrospectively
diagnosed. Fresh committed Git/copy/bootstrap proof remains coordinator-owned
before dispatch; actual native compilation, M2 behavior, release and performance
acceptance remain unestablished.

Evidence is held in
`artifacts/reviews/updater-worker-registration-root-peer-20261012/`: registration
results, exact old source/refusal, fresh 86-file source/snapshot, consumer capture
and catalog receipts, delta proof, focused log/results, scripts and review receipt.

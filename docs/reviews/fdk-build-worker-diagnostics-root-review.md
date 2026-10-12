# Independent FDK worker diagnostics review

The held seven-file candidate passes this bounded source and interface review.
No actionable finding was identified. This conclusion does not accept an FDK
native build or the forthcoming outer consumer integration.

## Reviewed hold

The author receipt is
`artifacts/reviews/fdk-build-worker-diagnostics-20261012/held-receipt.json`,
SHA256 `363a7e2db41ba1dd16fa0814e0c57ff58c039dfcc9d7143b6308e00d8c8feb7f`.
Its seven Python references, guide, complete 40-file stage closure and two
separate test inputs match the working and author-captured bytes, lengths and
modes. A new reviewer capture contains those same 40 stage files, 816,117 bytes,
two inputs and guide. It contains no bytecode caches. The guide remains SHA256
`d1175635c15f1de9e3db24c5cb0b11a8a42fe0dc90177a1aa6fb515b90daebf1`.

The held files are `stage.py`, `worker.py`, `worker_evidence.py`, `evidence.py`
and their three test modules in `scripts/port/fdk-native-stage/`. Their full
references are retained in the peer receipt. Original builder, broker and
runtime references also match the held closure. Neither static reviewer made
source edits or executed a native workload.

## Findings and acceptance boundaries

The stage hashes one capture of its actual saved worker config and supplies that
hash at launch. A returned worker code is recorded independently of the private
receipt's status. Exceptions without a returned code retain UNOBSERVED; missing
or invalid receipts remain UNAVAILABLE or UNVERIFIED. The private receiver
captures the owned receipt once and verifies its exact source, config, action,
run, nonce and input bindings. Declared provenance/log observations are captured
independently and must reproduce the worker's finite classification and
digest/length fields. Failed capture cannot be repaired by an unchecked reread.

Production build and compare verification consume the captured provenance and
log objects. Existing package, recipe, inventory, artifact, ABI, smoke and
paired comparison checks remain necessary. Later file mutation leaves an already
captured projection unchanged; a new receive of poisoned provenance is refused.

The broker observer is an instance wrapper around existing operations. It
preserves the actual create/start-attach arguments, returned results and daemon
operation sequence. Builder return, create return, attach return and container
State exit are distinct observations. State is reused only from the same
existing inspect bytes after the original ownership/configuration checks pass.
A known nonzero container exit prevents COMPLETE. Missing terminal State remains
UNOBSERVED; the observer introduces no new query and claims no compiler execution.
Later contradictory State cannot overwrite the first known exit.

First failure remains sticky across cleanup and late cancellation. Cleanup PASS
requires the existing positive scoped absence proof. Unknown exception text maps
to a finite UNKNOWN reason without exporting that text. Failed, cancelled,
unavailable or unverified work cannot authorize a public PASS.

The pure vector validator accepts exactly build-1, build-2 and compare with
closed row/observation shapes and distinct verified binding hashes. Its strict
completion gate requires all three VERIFIED, actual-zero, COMPLETE workers.
Build and compare completion have separate required operation shapes. The
current public projector emits schema 2 with exactly 13 keys, retains the
original acceptance and cleanup gates, and has no legacy PASS fallback. Private
paths, IDs, nonce values, keys, argv, logs and exception messages are absent;
only finite fields and binding/provenance/log hashes and lengths are projected.
These validators validate claims; captured execution evidence provides their
basis. They alone are not proof of execution.

The retained prior evidence module and the captured candidate differ in exactly
two function ASTs: `verify_attempt` and `finalstatus_public`. The other twelve,
including `accepted_base`, `inventory` and `read`, are unchanged. The diagnostic
helper import is local to the FDK projector. A fresh isolated subprocess tests
the standalone kernel accepted-base interface with no helper import.

## Focused verification

The reviewer ran **38 tests, zero failures, errors or skips**, from the fresh
captured tree using isolated Python with bytecode disabled and ResourceWarning
treated as an error. Every relevant imported module resolves to this capture;
captured hashes remained unchanged and zero PYC files existed afterward.

The selected controls cover returned and nonreturned worker/builder exits;
prebuilder, artifact and cleanup failures; real TERM handling in a mocked
builder; exact fake-daemon operation sequence and ownership before State;
wrong bindings, types, ownership, links and bounds; unknown-message privacy;
immutable captures; cancellation and stale PASS invalidation; standalone kernel
imports; and public acceptance/cleanup gates. Three additional reviewer tests
exercise vector poison cases, strict exit types, duplicate bindings, raw/extra
fields, immutable projection and absence of legacy PASS.

The first harness invocation passed all 38 tests, then its source-origin assertion
incorrectly expected the fixture-loaded stage in `sys.modules`. The assertion
was corrected to inspect the fixture module's actual file. The complete rerun
passed. Both logs are retained. This was a reviewer harness correction; the held
candidate was not changed. The author's two 104-test logs were hash-verified,
not rerun as a substitute for the focused checks.

All test execution used controlled host fixtures. No Docker daemon, compiler,
GPG, network download, package installation or hardware workload was run. Real
signals in these tests establish cancellation behavior in those fixtures only.

## Remaining integration and native result

The supplied canonical closure is stage 40 and the expected future job closure
is 129. Shared 39/128 locks are deliberately stale and cannot accept this new
helper. Coordinator adoption still needs authenticated imports of both evidence
and worker_evidence, strict schema-2 consumer/source-poison checks, run-attempt
forwarding, and consistent stage/job/workflow/packet pin rebinding. That consumer
delta is outside this seven-file hold and requires a separate combined review.

Actual run **38277573107 remains FAIL**, schema 1, phase build-1, native build
NOT ACCEPTED. Its retained public FDK status still hashes to
`df953517781c0811b604946099d9c57a4ad0af4366f34c14f7d37452e7e02404`.
Compiler invocation is not established by that receipt. This peer review
neither changes the historical result nor supplies a successful successor.
Installation, hardware, release selection and performance remain untested.

Peer evidence is held under
`artifacts/reviews/fdk-build-worker-diagnostics-root-peer-20261012/`, including
`capture-receipt.json`, `focused-results.json`, logs, reproducible reviewer
scripts, the captured tree and `review-receipt.json`.

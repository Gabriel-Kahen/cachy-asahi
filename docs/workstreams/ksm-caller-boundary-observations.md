# KSM caller-boundary observations

October 12, 2026. Implemented and held after bounded host validation and independent
review PASS. Actual KSM4 run 38294468323 remains FAIL, producer mutation
UNCERTAIN and cleanup FAIL. Its natural producer exit and primary caller exception
are unknown. KSM3 remains unchanged. No native fix or corrected run is claimed.

Before production edits, the exact closed schema was recorded in
`artifacts/reviews/ksm-caller-boundary-observations-20261012/schema-proposal.json`,
SHA `f9196ec88e0c18265bd4e7d4570aa02d26300cdbdccde1b06565b8d43b5df322`.
This extends only the existing bounded terminal diagnostics. Root owns packet,
required paths, workflow, Git, source adoption and dispatch.

The normal outer schema 2 still has exactly schema_version, rpc, producer and
cleanup. The existing request-count saturation, fixed command/error/transition
enums, first/last failure, returned-code/output-count/hash fields and cleanup
flags remain. A defensive oversize projection is exactly schema 2/state UNKNOWN;
the normal projection remains within 4096 UTF-8 bytes.

RPC current adds elapsed_ms and elapsed_state. Two guarded observational
monotonic reads measure the accepted service handle through its existing reply
completion/failure. OBSERVED has an exact nonboolean integer 0..8460000;
SATURATED fixes 8460000; UNKNOWN has null. Invalid/unavailable/decreasing clock
observations stay UNKNOWN. Finishing deactivates and freezes timing once; later
cleanup cannot overwrite it. These reads do not reset or change any operational
clock, caller timeout, phase budget or cleanup reserve.

CLI begin/return add context REQUEST/CLEANUP/UNKNOWN. Exact cleanup=True means
CLEANUP; exact False during an active request means REQUEST; unsupported or
outside-request values mean UNKNOWN. The ordinal remains a request counter,
not proof that a later cleanup query belongs to that request. Request-return
records remain separate from the mutable last CLI records.

Producer adds before_cleanup with exactly state and returncode. A new authorized
single process.poll call on the observed outer producer handle occurs before
existing process disposal. Alive/unavailable have null code; exited has an exact
nonboolean integer -128..255. Missing handles or observation errors remain
unavailable. This sample is separate from the original loop's natural_poll_code,
normal runner_return_code and later reaped_code. It does not reinterpret cleanup
as a previously observed natural exit. Existing cleanup, output drain, signal,
resource and acceptance operations remain mandatory.

All new observations guard against secondary errors, including cancellation,
without replacing an active original failure. Missing observations cannot grant
acceptance, clear sticky owner failure, change command order, retry a reply,
widen a timeout or add a daemon query. The existing executor projection naturally
carries the new closed observation; its production source needs no change.

## Caller classification deliberately deferred

The six-file grant provides no trusted structured exception channel from the
unchanged original native_arm.run. The shim emits untagged stderr; outer Runner
merges stdout/stderr, and request text or partial output can resemble a traceback.
A real original exception can also be absent or truncated when the callback
fails. A byte hash binds a captured prefix but cannot prove its claimed source,
current request or exception category. Therefore this implementation performs
no additional output read, arbitrary-text classifier or actual-cause inference.

The precise smaller proposal is timing/context/actual precleanup state only.
Reliable caller classification would require a separately reviewed authenticated
wrapper or original-source structured event contract, with finite source/request
binding and a private delivery channel. Root has not selected that extra grant.
The original 60-second caller limit and shim 2600-second socket limit remain intact.

## Validation boundaries

Baseline captures bind the exact actual KSM4 sources. Identical new tests must be
RED on that baseline and PASS on held candidates. Broker controls use a real
socketpair to show a caller timing out while a fake request returns known output
and the reply fails; they do not execute Docker or the original producer.
Runtime controls use harmless owned Python children to sample already exited and
still alive processes before disposal, preserve original errors across failed
observations, and keep natural/Runner/reap fields distinct. Executor controls
verify final source-bound projection without changing UNCERTAIN/PASS gates.

Fresh complete-source tests and a read-only independent peer bind exact source
hashes/modes and original/new guard inventories. Only two timing reads, closed
context wiring, one authorized poll and diagnostic projections are new. Existing
commands, deadline checks, timeout constants, resource policy, retries, signals,
cleanup selection and acceptance/export predicates must remain unchanged.

Fixture captures stay on the owned project filesystem. Small real temporary
socket/test directories may use short paths because AF_UNIX endpoints are
bounded and source readers reject symlink ancestry. Failed harness evidence is
retained. No shared packet, required path, workflow, Git or native actor changes
are made; caller-classification and actual KSM4 cause remain unresolved.

The fresh complete captured suite passes **292 tests, zero failures/errors/skips**
with isolated Python, bytecode disabled and ResourceWarning treated as errors.
Owner broker 64 and runtime 74 suites pass; final identical broker six methods
and executor two methods remain RED on the held previous source. Runtime
focused 11 controls also remain predecessor RED. Independent candidate 11 and
causal 4 controls pass with no findings; all 276 original guards, constants and
actor-policy calls are preserved. The exact original native.run still requests 60;
explicit .12/2-second test facades exercise the unchanged shim and candidate RPC
handler with harmless sockets only. No production timeout was changed.

The runtime's first long project-TMPDIR full run produced AF_UNIX path-length and
filesystem-enumeration fixture errors. Those failed logs remain; reruns use a
small owned real temporary directory, without weakening source ancestry guards.
The broker's first isolated capture omitted a required runtime dependency; that
failed log is retained and the complete capture passes. Pre-strict-context
evidence remains separate; the final exact-boolean context controls also pass.
All owned temporary fixtures were cleared and no PYC entered the captures.

Five of the six owned source/test files changed; executor.py remains byte-identical.
The external proposed packet is 152 rows (147 unchanged), 2,306,010 selected source
bytes, SHA `a4f0647a9c7c36a73ac0692b55a7c3553a9cda3847cce47c468c2441d3e9ee75`.
The actual shared packet remains 68c1bb, and required_paths/workflow/Git/dispatch
are unchanged. This new guide is outside the 152 packet; no new runtime path is
proposed. Root must authenticate and adopt a committed packet before execution.
Exact source holds, proposals, logs, classification limits and independent
evidence are bound by `artifacts/reviews/ksm-caller-boundary-observations-20261012/receipt.json`.

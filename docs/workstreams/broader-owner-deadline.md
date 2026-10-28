# Broader owner deadline seam

Status: bounded source implementation and independent modeled checks PASS; held
for coordinator recheck/admission. Exactly six owned
paths change: `scripts/ci/development/{common.py,test_common.py,base_stages.py,
test_base_stages.py,virtual_stage.py,test_virtual_stage.py}`. Shared controller,
packet, SourceSDK, maps, workflow, pins and underlying virtual guest/runtime/C
sources remain outside this lane. No actual actor or clock grant is established.

The exact six-file baseline is retained in
[`before-source-bindings.json`](../../artifacts/reviews/broader-owner-deadline-20261012/before-source-bindings.json).
The virtual baseline includes the reviewed SVG implementation and its 115 tests,
subsequently published by the coordinator at 76d94d4f… using the held index bytes
without overwriting this lane's working files. Its previous source review and
historical evidence remain unchanged.

## Interface and authority

The interfaces add an optional keyword `deadline=None` to `common.command`,
`common._stop`, `run_ksm`, `run_arm` and `run_virtual`. None preserves the legacy
working path. A composed parent must pass the same finite absolute monotonic J
explicitly throughout. Coordinator policy selects J once as
`min(trusted_workflow_deadline - 120, entry + 10080)`; this lane does not choose,
authenticate, renew or grant it. No global mutable deadline, controller deadline
attribute or local fallback provides authority. Validating a finite future number
is not proof that it came from the trusted parent.

Command work ends at `min(now + old_timeout, J - cleanup_grace - 10)`. Malformed,
expired or insufficient time refuses before opening a log or launching a child.
Arguments/environment are materialized before the final protected check immediately
preceding Popen. Drain/TERM/KILL/reap and restoration retain the existing grace and
10-second caps, clipped to the same J. Later owned disposal is attempted after
ordinary TERM, pipe, selector or restoration faults. Checks after restoration and
resource disposal prevent healthy late completion.

The first pending business/control exception survives later cleanup failures.
Cleanup uncertainty without a prior exception raises fixed typed `CleanupFailure`
with code `stage-cleanup-failed`. A validated `natural_returncode` preserves a
known normal wait result such as 7; a forced stop does not invent a natural result.
These are bounded modeled outcomes, not proof of all descendant/process-group or
container absence under persistent faults.

## Owner propagation

All three owners pass the identical J into child commands, recovery, prerequisite,
read/hash/copy and retention helpers. Meaningful file/hash/byte loops check it;
short reads and writes retain their bounds. The existing zlib 90 and tooling 600
phase clocks are subordinate to J and an earlier caller alarm. Socket timeouts and
explicit-J read1 chunks are clipped, while scoped alarms also cover DNS, headers
and framing. A blocked required alarm refuses before transport. Timer restoration
subtracts elapsed time, attempts later restoration despite ordinary faults, and
retains the first body cause. None does not add a zlib alarm or change its working
read mode.

KSM's existing 120-second cleanup phase is clipped to J. Its identity-bound queries
and disposal commands pass the original J; they do not get a fresh independent
job budget. Original command vectors, inner native timers and owner budgets remain.
Bounding a child with the parent's process envelope does not prove that the child
uses the same absolute clock.

Temporary fetch allocations retain their raw FD until transfer into a registered
stream. Explicit-J allocation/transfer masks the owned signals, so pending expiry
or control reaches cleanup after ownership is recorded. Refusal after allocation
closes the owned FD and attempts partial-file disposal. Source/target close and
later handler restoration attempt all owned resources while preserving the first
ordinary/control cause. Persistent close faults can remain uncertain; they do not
become PASS.

Virtual protocol, context 10, fixed event shape, nonce/order/privacy, original GBM,
both frames, both phase passes and cleanup acceptance retain their rules. The
unchanged image_decode_order, image_decode_binding and process_diagnostic_order
ASTs are authenticated. Deadline-aware finalization and recovery use the same J;
an expired or failed retention marks returned status FAIL with a finite
finalization_error_code, preserving any earlier error_code. It does not renew J
to write status after expiry. Failure metadata can therefore remain unavailable
on disk; actual admission must check the returned outcome and trusted clock.
If expiry occurs during restoration after earlier status writes, an earlier disk
status can remain while the final returned outcome is FAIL. The seam does not
claim an atomic on-disk clock/receipt transaction or permission to rewrite late.

## Verification and retained findings

Evidence is in
[`broader-owner-deadline-20261012`](../../artifacts/reviews/broader-owner-deadline-20261012/).
Original 9 common, 40 base and 115 virtual test-method ASTs are retained. New tests
exercise fake-clock pre-spawn refusal, argument/environment/mask latency,
unchanged forwarding, phase caps, partial IO, ordinary TERM/restore/pipe faults,
KILL/reap, first cause, typed uncertainty, raw FD custody and late finalization.
Existing bounded Python self-signal/log/pipe and Unix IPC fixtures are distinct
from actual Docker/network/native execution.

The fresh 47-file dependency capture passes 216 tests: 27 common, 59 base and 130
virtual, zero skips/failures/errors/PYC. Its six source pins reauthenticate
unchanged after the run. This includes 164 unchanged original methods plus 52 new
methods. The final common correction is 1718a824… and final base correction is
9a75059d…; virtual holds db35ff2f… with test 6acfd60e…. Independent virtual controls
pass 16 finite cases; the common/virtual peer's 33 selected methods overlap the
owned suites and are not added to 216. Peer receipts retain the old RED and final
GREEN findings with exact pins.

The final base follow-up passes 10 independent descriptor, first-cause and
restoration controls against ce4fb0fe… / 32d8ba27…. Its da223803… receipt records
no actionable finding within that finite scope. These controls are also separate
from the 216 owned tests and do not establish recovery under persistent faults.

Independent probes found and preserved late-Popen, base/virtual raw-FD,
late-transport, late-finalization, response-close and handler-restore failures.
Their old RED proofs and successive source snapshots/receipts remain historical.
Corrections are tested against fresh captures; no failed result is deleted or
relabeled. Common 5550… and base 97c…/a264… receipts remain immutable intermediate
history, with separate correction receipts carrying the final pins. Overlapping
peer test subsets are not added to the full owned test count.

## Remaining acceptance

Coordinator owns the composed caller, J's provenance, SourceSDK/clock/grant
implementation and admission, exact source/pin/map/workflow reconciliation and
separately gated actor work. This source seam supplies neither an actual clock
grant nor native PASS. No actual Docker, network, decoder, compiler, image/media,
native ARM, GPG, service, package installation or hardware actor ran. Blocking OS
operations and scheduling are not a hard real-time completion guarantee.
Historical native/guest failures and their unknown causes are unchanged; target
hardware and performance remain unverified.

# Whole-query Source review: adoption blocked

The frozen f2a083 proposal is blocked by two publication failure boundaries.
Eight fresh exact-byte fake schedules confirm loss of a falsey prior cause or
replacement of the original body exception by a publication clock error. Root
must select an independently reviewed immutable successor before adoption.
No Source integration, ownership grant, query or real process/signal/FD/FFI
actor runs in this review. Full R1–R5/M5–M9/A01–A15 remain required and incomplete.

The author receipt is
`artifacts/reviews/updater-maintained-query-whole-invocation-proposal-20261014/receipt.json`,
SHA-256 f2a0839aa17f63b1dc5265c552a2bc54961609ec42a85e73a420bfb1333b3faf
(17,288 bytes). All 37 indexed leaves and the exact guide authenticate; 45
Source/context/reference captures are held in
`artifacts/reviews/updater-maintained-query-whole-invocation-root-peer-20261014/held/`.
The author 73 inert assertions and 349 ancestor-authentication paths are retained
as author evidence rather than replayed or independently relabelled. Frozen
parent a50cd158, child d90a0994, custody 3152c876, bindings 5c39bdf2,
publisher 7d860b08 and terminal df09067e remain unchanged.

## Confirmed publication defects

1. `publisher.py:44` and `publisher.py:119` include a preexisting cause only if
   its truth value is true. An exception may define __bool__ returning false.
   With a write error whose prior cause is such an exception plus a close error,
   both finish and returned acknowledgement deliver the same write exception,
   but the new BaseExceptionGroup drops the prior cause. The nominal author
   prior RuntimeError is truthy and does not exercise this boundary. Use an
   identity/null test to preserve any non-null prior cause; do not overwrite it
   or silently discard close uncertainty.

2. `publisher.py:71`, `:93` and `:130` perform final publication, acknowledgement
   entry or final acknowledgement clock observations outside the failure
   boundary. With an existing body error, a clock exception or malformed None
   value escapes ClockFailure/TypeError rather than returning the original body
   exception and closed FAIL/uncertainty. For finish, the injected clock fault
   occurs only after the exact terminal context has set _COMPLETED_SCOPE. For
   acknowledgement entry it occurs on the first clock call; for final
   acknowledgement the fake close activates clock failure, a guarded line123
   catches its first occurrence, and unguarded line130 escapes the next. All
   six combinations reproduce. Clock validation and observation must be guarded,
   preserve the original body identity/cause, set sticky uncertainty/FAIL, retain
   available secondary channels and never create a fresh action budget.

`controls.py` compiles exact frozen publisher/terminal definitions with every
signal, mask, clock and file API substituted. Two write+close controls use
FalsePrior(Exception).__bool__False; the other six use exception/None clocks.
A nominal exact finish model passes and preserves the fake protective mask.
No actual signal getter/setter/mask, file descriptor, child, native library,
FFI, parser/query actor or author suite is invoked. Findings are Source failure
countermodels, not evidence that a historical host actually experienced them.
The author received exact sites and phase-triggered schedules; all f2a083 and
7d860b08 objects remain immutable.

## Contextual checks and limits

The proposal binds twenty Source rows and seven guardian roles to a trusted
Root expected selection, with twenty-five preflight/raw frame operands. It
raw-loads the held code rather than a preexisting .pyc, composes concrete
-I/-B/-c child argv, DEVNULL stdin and pinned control-file operands, and joins the selected
query/envelope/runtime/gate and metadata inputs. Independent inert checks
conserve original 304/300 outer endpoints, nested query end−16, exact two-variable
child environment, canonical argv hash, source layout/role joins and all seven
query operand hashes. The terminal classes/functions are exact AST copies of
the reviewed dbd016 runtime subset, without the FFI bootstrap. Query 892d,
runtime dbd016, envelope 79fb, gate db03 and guardian f2a remain frozen bodies.

Six focused contextual schedules cover mutated publisher selection, missing
whole-call review, wrong seed path, late preflight, consumed admission reuse
and exact parent adapter constructor refusal. In the constructor schedule all
context/read/write/loading APIs are fake; the same constructor exception
escapes before _drive, with the admission consumed and no PASS path. A model
iterator seam was corrected before the final schedule passed. Early preflight,
bootstrap or constructor errors require the pending trusted Root caller to
capture FAIL and any partial resource uncertainty; the Source API does not
provide a retained result for those earlier boundaries.

Opaque admission is an external trusted-Root argument identity boundary and
one-shot consumption, not a registry issuer here. Parent accepts the operative
object only when it is the separately supplied expected object; Root must bind
that expected object/selection from its existing authority and trusted entry.
Caller-controlled JSON, a syntactically valid review hash or equal untrusted
parameters cannot supply that Root authority. Root still needs independently
selected entry/registration/loaded callback and context custody; a source label
is not evidence that these conditions actually held.

The child inherits the outer-created sole group/session; envelope, worker and
read-only pacman calls use that group. Child-reported PID/group checks are
invariants, never parent ownership authority. The inherited guardian's direct
birth, WNOWAIT and structural membership proof remain the ownership mechanism,
under explicit current-host trusted runtime/noescape/nootherreaper/nootherwriter/
complete-visibility assumptions. No private cgroup or universal kernel Source
proof is imposed by this review. No hard syscall wall or actual disposition is
proved by fixed Source clocks. Parent/child receipt cause fields retain
producer-local versus guardian-local failures without claiming cross-process
causal order. Exact malformed child causes remain refusal/uncertainty inputs.

The intended publisher uses provisional, final and returned-decision leaves
and holds the protective parent mask through a dedicated parent exit. An old
successful leaf is not PASS authority. Root must join actual returned decision,
exit and original clocks with bounded publication before accepting an actual
query. This design intent does not waive the two confirmed Source defects.

## Successor and actual-entry prerequisites

The smallest successor corrects publication cause grouping and guarded final/
ack-entry clock observations, updates dependent Source data pins, and receives
independent focused review. Preserve f2a083 and this blocked receipt. Actual
Root entry, current host tool/stdlib/loader/snapshot modes and code custody,
existing opaque registration, fresh owned 700 cwd/nonexistent output, noescape/
nootherreaper/nootherwriter/visibility and dedicated exit reservation remain
separate. Root final metadata sealing is a distinct interval. No actual guardian,
Linux adapter, runtime Runner, libalpm/private query, archive or old generic 574
query is replayed or used to backfill the corrected 354 snapshot/CodeVim operands.

This work maps to R1/A05/A12 metadata-input and R5/A06 failure-refusal
preparation; it passes none of those acceptance entries. Actual ordered-provider
query results, source/license/signature/build records, supported Asahi/16K,
installation/update/recovery and measurements on both M2 Air sizes, maintained
releases and accountable human ownership remain open.

# Carrier disposal correction: independent P1/P2 recheck

**Disposition: the specific P1/P2 source findings are closed for the exact held
correction. Source-only review PASS; retrieval and actual admission remain open.**
Controller job.py is41,782 bytes/mode0644,
`2618d0f4acda078b80b53a5c666a72d25001c4e60e6b51e3167cfc4e919ef9b0`;
test_job.py is103,654 bytes/mode0644,
`db644d017ed5b9a56bbd6fc6ab7d2413e1c08e54d7659ab7905405ac4ec4a620`.
No actual archive/signature payload, retrieval, crypto249, acquisition501, native
retry, Docker, GPG, tool, image, network, Git, map/workflow or authority actor ran.

The [previous finding](frozen-vim-carrier-root-review.md) and its34d4bd08… sealed
receipt remain immutable. Author192c5a12…/1,024 indexed rows, peer34d4bd08…/304 rows,
and correction receipt
`47dd9609ad200b58a25fce2343d108975d9e9144eef527fde370a5579a387e07`
(51,933 bytes/mode0644) with163 indexed rows all authenticate. Independent evidence
is in
[`frozen-vim-carrier-disposal-correction-peer-20261013`](../../artifacts/reviews/frozen-vim-carrier-disposal-correction-peer-20261013/).
Only that new directory and this new guide were written by this reviewer.

## P1: first cause and close ownership

The local frozen_fds owner registers returned descriptors, attempts their closes
once in reverse order, records uncertain cleanup, and raises the exact first
ordinary/control/fatal body exception. Healthy-body cleanup failure refuses
success. frozen_names/directory/read, copy FDs and final cache FD use that owner.
No blind close retry is introduced: a close error may follow successful closure,
and a reused integer cannot prove ownership of the old descriptor.

Independent old/new replay of the three exact prior close controls confirms:

| Causal close control | Old held source | Correction |
| --- | --- | --- |
| Directory body cancellation + ordinary close fault | OSError replaces cancellation;1/12 close attempts | Exact original Cancelled;12/12 close attempts |
| Source-read cancellation + close fault | OSError replaces cancellation | Exact original Cancelled |
| Copy cancellation + final cache-close fault | OSError replaces cancellation | Exact original Cancelled; finite fixture cache removed |

The full corrected suite additionally covers ValueError, Cancelled,
KeyboardInterrupt and SystemExit first causes, enumeration/copy/cache closes,
cleanup-only refusal, close-before-effect uncertainty, handler restoration and
mask restoration. Frozen_defer preserves the body cause through the existing
jr.defer_signals restoration; frozen_critical preserves established cause through
mask restoration. Fixed notes/cancellation markers retain failure rather than
claiming unknown close outcomes as absence. Persistent faults and broader FD/
process absence are not proven.

## P2: legitimate pending signal before registration

New frozen_critical blocks existing jr.SIGNALS through real open, FD registration
and post-open fstat, then restores the prior mask inside owned cleanup scope.
Cache/copy descriptors likewise register before restoration, preserving the
existing defer API and same Runner.deadline. No new timer or producer allowance
is selected.

Independent causal replay sends genuine SIGTERM **only to the current private
Python fixture process**, under the existing job cancellation handlers, after
actual os.open. Old directory/read/enumeration helpers propagate cancellation
with1 allocated descriptor and0 close attempts. Corrected helpers register and
close that descriptor before propagating cancellation:1 allocation/1 close in
each case. All old fixture descriptors are manually retired after observation;
no other PID, external actor or child is signaled.

This closes the legitimate signal-handoff finding. The initial prior allocation
probe used an arbitrary replacement open that allocates then raises without
returning its FD. Signal masking cannot recover an arbitrary hidden/unreturned
resource, and the correction does not claim that capability. The retained
limitation test acknowledges it explicitly. Genuine pending-signal controls
supply the relevant causal proof without rewriting the old probe into a real OS
signal result.

Post-open fstat/restoration controls verify registered FD cleanup. If copy fstat
fails before the created file's inode is captured, the FD is closed but unknown
cache membership/custody can conservatively refuse deletion and retain private
unaccepted cache evidence. Close-before-effect faults can leave a known model FD
open until identity-checked fixture teardown. These are failed outcomes, not
successful cache admission or guaranteed cleanup.

## Exact source conservation and fresh checks

Cold held/corrected captures each contain145 rows:135 source/workflow/packet and
10 exact historical test dependencies. Only job/test_job differ. Independent AST
comparison verifies exactly four changed carrier functions, four added ownership/
signal helpers and the signal import. Every other top-level definition, constant,
class, main/execute/CLI/public flow and module AST is unchanged. All86 held test
methods/helpers remain exact;15 new methods are part of101. Previous baseline57
ASTs/results remain authenticated history and are not counted again.

| Fresh peer replay | Result |
| --- | --- |
| Held suite | 86 PASS; zero errors/failures/skips/actor attempts |
| Corrected suite | 101 PASS; zero errors/failures/skips/actor attempts |
| Independent causal old/new first-cause3 and genuine pending-signal3 | Old RED reproduced; corrected GREEN |

All rows reauthenticate after runs, there is no PYC, and project-owned TMPDIR is
used. Audit hooks deny actor/network dispatch and require every signal target to
be the fixture's own PID. Method rosters, causal controls and historical results
are separate; the added15 methods overlap101 and are not added again.

The exact frozen four-object manifest remains
`13bdcca86d6f6a5a02a6f43afff2b61c3ce832d9bc12ad2ada55b5dc404255d6`, canonical compact sorted
JSON without newline, total9,790,183 bytes. Frozen lock remains3c16c37d… and native
source remainsa8b6ed89…. Actual unchanged packet.closure selects133 sources,
adapter44, recipes4 and71 recipe files. Legacy execution, original fetch,
source/worker/public verification, Runner.deadline and original501/249 requirements
remain unchanged. The capture intentionally retains historical producer41c38989…
and excludes Root's current0f747 diagnostic composition. It is not a new primary
packet or joint committed source proof.

No additional actionable finding was established within this bounded recheck.
Root must rebase the source2 correction into its current joint133 producer/job
composition and public proposal, recompute/review actual source/packet/workflow
bindings, and retain exact committed custody. External carrier provenance,
retrieval implementation, bounded retrieval/retention evidence, accountable
retention policy, source/license/public distribution obligations and actual
acquisition/crypto/native retry remain unadmitted. R1–R5/M5–M9, Asahi lifecycle,
both M2 Air sizes and performance acceptance remain required and unfinished.

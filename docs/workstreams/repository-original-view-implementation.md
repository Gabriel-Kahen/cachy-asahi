# Repository original-only view implementation

This implements the selected original-view contract in the four adapter/callback
source and test files. Proposal artifacts and the historical v11/graph correction
holds remain unchanged. This is source/fixture evidence; original native execution,
external authority issuance, compiler, Docker, package, signing and hardware
validation are NOT RUN.

Current execution grants require schema2 and its closed `original_view` selection.
The deterministic view is `<adapter-output>/original-view`, separate from the full
source snapshot. Current producer/authority paths refuse a schema1 grant. Status22
and callback live12 remain; their execution-grant SHA binds the view selection.
The exact original argv/output hash is checked first. Each metadata path and SHA
must select the view, with single flags and explicit cache/native/integration
outputs. The adapter never rewrites argv. The unchanged native Git check inherits
the authenticated enclosing checkout cwd.

The Session creates one0700 view and copies exactly the159 original rows plus the
initial lock. Copying uses exclusive no-follow files and directory FDs, original
file modes, bounded writes and fsync, followed by captured-byte/node verification.
It registers the root before copying so an interrupted copy is eligible only for
owned cleanup. The private <=256KiB canonical receipt retains the original and
copied file nodes, copied directories, root/parent identities, exact source rows,
byte counts and grant/job/actor/invocation bindings. It is retained as immutable
bytes/SHA in Session; no reread can promote or replace those bytes. Added files,
empty directories, symlinks/FIFOs/hardlinks, mode or inode drift, directory
replacement and contradictory receipt fields refuse. No raw receipt/path/node
identity is added to public export.

The sole unchanged runtime entry loads the original nine namespaces and two
projection aliases once from this view. The graph distinguishes the full-source
and original-view domains. Only receipt-selected original paths can compile in
the latter; their bytes/modes equal the captured full-source originals. Namespace,
function/class/closure identities still compare against the loader-bound immutable
observation. The public receiver/authority callback authenticates Controller using
the actual view namespace and compilation filename, while preserving all old
nonce/image/source/returned-code/crypto/phase/cleanup conditions.

`session.original_context(*, deadline, controller=None)` returns exactly `root`,
`receipt`, `sha256`, `original`, `aliases`. It verifies source/copy/graph custody and
the actual suspended captured `entry.original_modules` generator frame, including
its code object/globals, original root/lock and yielded namespace identities. A
closed or foreign generator refuses. With no Controller this proves namespace
readiness only, not actor execution or compiler/PASS authority.

Controller access additionally requires the observation made by the actual
captured Session consumer wrapper. It verifies the wrapper's exact code/globals,
actual `Controller.run` frame and actual native `main` frame, their real Controller,
image, accepted commit and lock. The two frames must remain active during broad
consumers; after return both must be inactive and the separately recorded actual
native return must be typed. Direct wrapper/observer invocation with a fabricated
same-class Controller cannot mint this observation. Callback `_live` continues to
require actual returned0 and every original acceptance gate. These are cooperative
source/process ownership observations; they are not a hostile same-UID memory
barrier, compiler proof or independent actor grant. A legitimate actual main/run
positive is not exercised in this actor-free source fixture scope.

View preparation uses the existing original job deadline. No E is started or
renewed there. Broad consumers still execute first, then added work uses the one
fixed E and60-second reserve. The original runtime post-source check keeps its
existing outer deadline. Added view/receiver checks and final owned view deletion
use the existing selected E/cleanup endpoints. Existing timers, command/query
sequence, runtime sources, caps, package inputs and authority semantics are not
changed. Cleanup revokes the original context and independently removes the
registered view; it preserves the first failure and cannot assert unproved
absence. The full snapshot remains available to unchanged Development.consume.

Validation includes all prior61 adapter/17 callback test bodies, with fixture
context setup adapted to schema2/actual view custody, plus14 new adapter controls.
It exercises actual original scan159/freeze4/71 on the160 view, current full-root
add-on visibility, wrong metadata paths/hashes/duplicate flags/output, private
receipt contradictions, same-byte inode/mode drift, empty/foreign nodes, directory
replacement, copy failure/cancellation/expiry, owned cleanup and refusal of
fabricated Controller/foreign contexts. Tests use only source/filesystem and
harmless temporary Python/pipe/Unix-socket fixtures. Full-root scan175 at this
worktree is original159 +Zsh12 +installer4; the registered fresh source candidate
includes the selected Zsh12 while the view retains only original159. No source
scanner or recipe freezer is weakened.

Root must independently review/adopt the four changed source rows, bind the full
expanded packet, construct the schema2 grant/absolute view argv before hashing,
and register the authenticated Session interface. Shared packet/controller/workflow
and grant/map edits remain root-owned. The future Zsh helper must borrow this actual
context/receipt/nine+aliases; its separate copy/SourceAuthority/native loader is
not admitted for repository mode. No additional helper, second producer, actor
permission or scope reduction is supplied by this source hold.

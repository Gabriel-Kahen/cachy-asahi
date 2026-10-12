# Repository original-only view contract (proposal)

Status: proposed source/interface work, not an execution grant or native result.
The previously held adapter/callback composition is committed at
`7a49856080c3d7761ef4efd8695b2c621411fa1c`. Its full tree now contains the Zsh
add-on; the unchanged initial scanner sees five recipes there. The original
159-source, four-recipe, 71-input, 125-fixture gate must execute against one exact
160-file view. It must not be weakened or run against a five-recipe tree.

## Selection before allocation

The proposed current execution grant becomes schema 2 and adds exactly one
`original_view` object. This selects the full source root, deterministic absolute
view root `<adapter-output>/original-view`, the initial lock hash, canonical
159-row map hash, file count 160 and `absolute-view-metadata` invocation mode.
All existing source, actor, Git/job and live-binding fields remain mandatory.
Current execution refuses a schema-1 grant. Existing status22 and callback live12
may remain unchanged: their execution-grant hash already binds this new object.
Historical fixtures can replay schema1 only separately; it cannot select a current
producer or authority path.

Root constructs the real argv before `Session.execute`, with exactly one each of
`--inputs`, `--recipes`, `--integration` and their hash arguments. Their paths are
absolute children of the selected view, with hashes from the captured original
rows/initial lock. Cache, native output and integration output remain explicitly
selected by root. The existing initial-invocation hash binds the exact unmodified
argv plus adapter output. Duplicate metadata flags, full-tree metadata paths,
wrong hashes, missing view selection or substituted output refuse before
allocation/native invocation. The adapter never rewrites argv.

The unchanged native `git rev-parse HEAD` uses the enclosing checkout cwd; the
view contains no `.git`. Root must retain and authenticate the real committed cwd
and GITHUB identity. Loading native code from the view makes its ROOT the view;
absolute metadata arguments prevent ambient cwd from selecting the full tree.

## One registered copy and receipt

After the existing execution-grant/source/callback checks, the Session exclusively
creates its deterministic 0700 view under the registered fresh adapter output.
It copies only captured original159 bytes/modes and the separately captured
initial lock (`d4d603...`). No add-on, callback or development module enters this
view. Every copy uses no-follow, exclusive regular-file creation and verifies
source ancestry/owner/dev/inode/mode/link/size/times and the new copied node.
The complete tree must be exactly160; recipe contents must remain the four
originals/71 inputs and the generated fixture map remains125.

The private canonical receipt has a fixed closed schema and maximum256KiB. It
binds schema/purpose, full root/view root, source commit/run/attempt, execution
grant/actor/invocation hashes, original lock and map hashes, root/parent ancestry,
exact160 rows, byte lengths/modes and original/copied file-node identities.
Canonical bytes and their SHA are retained once in Session state. A persisted
receipt may be checked for exact equality, but never reread to promote or replace
that captured state. The receipt is source/copy custody evidence, not external
repository authority or native/compile/hardware evidence; raw paths/node IDs are
private and are not added to generic public export.

View preparation runs within the existing original-job deadline, before the
producer; it does not start or renew E. Source/copy checks after broad consumers,
terminal roles and cleanup are charged to the existing fixed E and its unchanged
60-second reserve. Before every reuse, verify the registered root/parent,
exact160 file set, hashes/modes/node identities and full-source ancestry against
the captured receipt. Missing, changed, additional, hard-linked, foreign-owned,
symlinked or replaced nodes refuse. Cleanup independently removes only the
registered view using the existing no-follow owned-tree rules; errors latch FAIL
without relabeling the first failure or asserting unproved absence. Receipt/context
access is revoked before deletion. No new actor, timeout, cap or cleanup renewal.

## Actual namespace and callback API

The sole captured runtime entry loads `original_modules` once, using the verified
view and its initial lock. The one actual `native.main` remains inside that
context and the existing Pending interposition. The Session graph explicitly
identifies the original namespace domain as this receipt-bound view; the full
source domain remains exclusive to the adapter/runtime/collector/phase code.
Only original159 paths may compile in the view domain. Their raw bytes/modes must
match the corresponding captured full-source rows. The nine actual namespaces
and two projection aliases are observed from this one loader; a recreated
namespace, filename match, same code or fresh lookalike view cannot substitute.

Proposed source-authenticated API:

`session.original_context(*, deadline, controller=None)`

It returns a closed object containing the captured view root, immutable receipt
bytes/SHA, actual original-nine mapping and exact two aliases. It is available
only while the registered original context is active and the matching guarded
source/view observation remains valid. When a controller is supplied it must be
the actual current Controller from that namespace and commit/image/job binding;
no name-based class admission. Root calls only the authenticated captured Session
method, not a supplied callback or fabricated dictionary. Before the native
callback and after producer return, its finite lifecycle flags distinguish
namespace readiness from actual Controller/returned-code observations. No phase
or mere namespace construction proves launch, compilation or PASS.

`RootCallbacks._live` validates the current schema2 selection and this exact
Session context/receipt. It authenticates Controller against the actual view
integration namespace and view compilation filename, while checking identical
captured source bytes. Existing job/nonce/image/native-return0/cancellation,
private-directory, source snapshot, full crypto/custody/phase gates remain.
Callback classes/methods/state and the caller's Sources/Session are still bound to
the full authenticated source graph. It cannot accept a caller-declared view label
or filename-equal Controller. All original authority17 and adapter61 controls
remain, with fixture setup adapted to the explicit current view contract.

## Coordinator and Zsh composition

Root owns packet/controller/workflow/live-grant integration. Full-root packet
registration currently calls `initial_paths(full_root, locked)`, which rightly
finds the add-on. Root must separately bind the full expanded source set and
validate the unchanged original scanner against this exact registered view,
without filtering the initial scanner or recipe freezer. The full snapshot stays
available to unchanged `Development.consume`, which receives the actual view
Controller and runs all existing broad consumers first.

The future Zsh helper must consume `session.original_context` and its actual
namespace/receipt. It must not call its current `prepare_initial_view` or install
its own initial SourceAuthority/native loader when repository handoff owns the
producer. Build owner will need an explicitly source-bound borrowed-context
interface, with same-view identity checks and add-on-only launch interception;
root selects that later integration. No helper or add-on actor is granted by this
proposal. The present scope is the four adapter/callback source/test files only;
shared packet, controller, workflow and source maps remain root-owned.

Required causal validation: unchanged original scan/freeze returns159/four/71 on
the exact copied view while full root reports the add-on; actual nine+aliases
reuse; wrong view selection/argv/hash/output refuses before actors; same bytes with
changed inode/mode or different view/namespace refuses; copy interruption,
expiry/cancellation/late mutation and cleanup failure retain finite FAIL; actual
callback `_live` rejects a full-root/lookalike Controller; immutable receipt does
not change through reread; old61+authority17 fixture controls remain. Tests use
only bounded source/filesystem and harmless process fixtures. Native, Docker,
GPG, package, mount, compiler and hardware actors remain NOT RUN.

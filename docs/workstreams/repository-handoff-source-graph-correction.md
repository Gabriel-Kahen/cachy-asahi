# Repository handoff captured source graph correction

This is a source-only correction to `repository_handoff.py` and its tests. The
historical v11 guide and its 42-test checkpoint remain unchanged. The corrected
runtime loader and the two external-callback sources remain separate owner holds;
this correction does not issue an execution grant or accepted authority.

The actual held `RootCallbacks` has twelve declared slots. The previous generic
`vars(instance)` walk rejected it before actors. The receiver now parses the
captured class declaration, requires the exact class and method globals/code,
checks declared member descriptors, and reads only those declared slots. Plain
source classes have only fields declared by their captured methods. Defaults are
checked against captured literals, including bounded integer arithmetic used by
the existing supervisor constants. Only the captured contextmanager wrapper and
its exact captured generator are allowed. Foreign classes, subclasses,
descriptors, defaults, methods and executable instance state refuse.

A Session explicitly carries the loader-created entry, six runtime namespaces,
five collector namespaces, four phase namespaces, and the original nine
namespaces. The original projections also create two private aliases:
`repository_projection.inventory` and `desktop_projection.policy`. These must
be the actual objects stored by their parent projections. Equal filenames or
function code do not admit a replacement namespace.

At the already authenticated dependency-loader boundary, the adapter validates
source/class/code/globals and captures an immutable tuple of namespace,
function, class, closure-cell and referenced executable identities plus closed
loader data. The second boundary adds original namespaces while requiring the
first observation to remain exact. Subsequent receiver checks compare the actual
graph to that observation. This includes private namespaces reached through the
phase loader's captured collector closure. Import compilation/context/stdlib
caches may grow under the existing loader; their object references remain fixed.
No new global registry, import hook or generic same-code allowance is introduced.
The observation begins unset and is established by the two existing authenticated
loader calls in `Session.execute`, before the original producer starts. It is
not an external authority or a substitute for the source/data/live grant.

An attached Controller must be the class from the captured original integration
namespace. A RoleSupervisor must be the class from the captured runtime namespace.
Its source guard must be the captured `services.<locals>.source_guard`, with the
actual cancellation observer, original outer deadline, runtime root, exact seven
source rows and observed file identities. Its seven role grants point to the
captured broker; cleanup and result/stream limits remain unchanged. The receiver
accepts the actual standard-library path classes supplied by these authenticated
namespaces and rejects path subclasses with executable overrides.

The correction retains the existing single original producer, two checkpoint ACKs,
source/mode/inode checks, broad consumers first, one fixed added deadline E,
60-second cleanup reserve, actor and initial-invocation hashes, twelve-field
callback binding, 22-key status, strict private-tree custody and separate external
phase verification. Construction/import/preflight remain actor-free. Missing
actual root callbacks or a complete live execution grant still refuse before
actors. No package, crypto, cleanup, compiler, native or hardware acceptance is
inferred from source fixtures.

## Bounded validation

The test suite contains the original 42 controls plus nineteen source-graph
controls. It exercises the actual captured 243-file graph and held callback2,
real inert Controller/supervisor construction, and causal slot, descriptor,
class, method, contextmanager, closure, root, namespace, nested-loader, expired
clock and recapture substitutions. The remaining fixtures use harmless temporary
Python processes, pipes and a Unix socket. No Docker, GPG, installation, compiler
or native actors run. The working and fresh-copy results and precise source
hashes are in the correction artifact namespace. These are two executions of the
same 61 tests, not 122 distinct tests.

## Coordinator integration and later original-only view

The current prospective source selection is the exact 243-file graph, with the
two adapter rows changed. The root must bind these rows into the complete packet
and grant, independently review the new graph contract, and commit/register it
before execution. Callback2 source identities and runtime/collector/phase maps
are unchanged. The historical v11 guide remains intact; this guide is a separate
correction record. Existing file and total-byte caps remain unchanged.

This correction admits no Zsh add-on or copied producer view. Root may select the
243-file repository graph without the unadmitted add-on's twelve files, so the
original scanner still sees the original four recipes. Once the add-on is
selected, the original producer requires a separately authenticated 160-file
view: the exact original 159 rows and initial integration lock, with bytes,
modes, copied-node custody and full-snapshot ancestry bound by a closed copy
receipt. The Session must then expose the actual view-loaded namespaces through
that explicit receipt; callback source must separately bind that Session view.
Filename equality or copied code cannot grant it. Root must construct the real
original argv using absolute view metadata paths or the authenticated view ROOT
defaults, then hash the actual invocation and output before producer execution.
The adapter must never rewrite the granted argv. That future composition and its
source/grant changes remain root-selected work; the current graph correction
makes no claim that a full snapshot containing five recipes passes the immutable
original four-recipe gate.

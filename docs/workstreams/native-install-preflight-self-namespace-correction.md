# Native installer self-namespace source correction

October 13, 2026. **SOURCE/CAPTURED-CALLABLE CONTROLS ONLY.** Actual owner wiring,
execution grant, native P0, ABI, fixture26, installation, both M2 Air sizes and M8
remain **NOT RUN**. The positive frame evidence below is an active captured
`namespace` frame, not an active native Session/controller frame.

The retained diagnostic bridge `1821ae1dad1dd1562ca7c648f12a77995006b52cb9c157acfa702d3a98760e8e`
fails its own `namespace(module, raw, pin)` call with `ISSUER_CODE`. Both a plain
source loader and actual captured `Sources.module` reproduce this. The retained
external validator accepts the same captured baseline. The failure is in the
`namespace` callable's serialized code comparison: builtin code equality, every
stored public code field, function globals, defaults, keyword defaults and
closure state match. Default marshal bytes differ at the nested active checker
code's `c | FLAG_REF` marker and subsequent reference indexes.
The earlier policy bridge `d214e21f…` reproduces the same two self-call refusals,
external positives and matching stored code fields; its source remains retained.

CPython's [marshal writer](https://github.com/python/cpython/blob/v3.14.7/Python/marshal.c)
uses object sharing information from format 3 onward; format 2 omits those
references. An active nested function holds additional references to its code.
The causal control balances only the corresponding expected nested code's
reference lifetime, and the unchanged baseline self-call passes. No source,
callable implementation, grant or policy is changed in that experiment.

A direct format-2 substitution was rejected and retained: Python 3.14 emits
slice constants that format 2 cannot serialize. Replaying the final 92-control
fixture against that retained candidate records 15 failures and 8 errors. The
published issuer and receiver positives are among the failures; this candidate
is not the correction.

The final comparison uses a local `code_bytes` function inside `namespace`.
It keeps marshal's complete code-object field serialization and replaces only
`co_consts` with a closed, recursively tagged representation: nested code gets
its complete serialized bytes; tuples and frozensets retain their separate
shapes; a slice retains separately tagged start, stop and step. None, Ellipsis,
bool, int, float, complex, str and bytes retain their literal value and marshal
type encoding. Unsupported constant types refuse `ISSUER_CODE` before foreign
getters, hashing or equality. Every constant shape is tagged, so a literal
tuple cannot impersonate the slice encoding or nested-code bytes. Format 2 then
removes reference bookkeeping without dropping code contents or provenance.
The normalizer is local, so it adds no mutable global callable that could
replace its own authentication comparator.

Removing only that local function and restoring the two old marshal calls
makes the whole production module AST identical to the baseline. All 48 prior
bridge test definitions are AST-identical. Thus pins, class/default/import and
builtin checks, source graph, active native owner guards, twelve Config fields,
two Config normalizations, six inspected policy fields, first-cause behavior,
immutable-CID cleanup and the hard 60-second budget remain unchanged.

Fresh captured-source execution passes **92 controls** (55 bridge, 37 receiver),
with zero failures, errors, skips, forbidden actor attempts or PYC. The seven
added tests cover actual `Sources.module` plus `graph_namespace` followed by
self/external namespace validation; a plain self-call; changed stored code
fields and provenance; nested constants and free-variable metadata; slice/tuple,
bool/int, signed-zero, bytes/str and tuple/frozenset distinctions; unsupported
foreign constants with no callbacks; and foreign globals/defaults/keyword
defaults/closures. The retained peer's byte-identical thirteen-group script
also passes, including constructor cleanup, first-control identity and refusal
before actors. Its inspected-policy acceptance gap list remains empty.

The [sealed evidence](../../artifacts/reviews/native-install-preflight-self-namespace-correction-20261013/receipt.json)
retains the old call routes, exact code-field and marshal differences, balanced
reference experiment, rejected candidate, exact captured loader/callable/frame
provenance, source snapshots, control logs and predecessor authentication.
The published `7202c974…` issuer bootstrap pin is unchanged here. Root still owns
independent review, final issuer rebind and source registration, sys.modules and
callback/frame composition, publication, enclosing cleanup and execution
admission. No Docker, image, GPG, package, compiler, library, service, network,
signal or host mutation actors ran.

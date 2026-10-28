# Independent empty-configerrors compatibility review

**PASS for the narrow source correction and focused host controls.** No
actionable finding. This review accepts only the claim **no reported
configuration-error text** for parsed `[]` or exactly `[""]`; the lossy upstream
API cannot establish an empty internal error vector. Actual run `38274341668`
remains FAIL with 13 events and no frames. No native successor, backend
experiment, native compilation, Docker, dispatch or hardware action was run.

Persistent output is limited to this new document and
`artifacts/reviews/virtual-empty-configerrors-root-peer-20261012/`. Installer
review histories and the four author code files/guide remain held. Controller,
packets, maps, workflow and Git adoption are coordinator-owned. The
[roadmap](../roadmap.md) and [development inventory](../../manifests/packages.toml)
still require integrated platform/desktop/installation/recovery acceptance;
these host fixtures satisfy none of the M2/16K or performance gates.

## Exact reviewed source

The author receipt is `040994c557ebfcbf12212520373cedfa975c843993653e5aecbf170e869a0f2a`.
All five current files match their held byte copies, at mode `0644`:

| Path | Bytes | SHA-256 |
| --- | ---: | --- |
| `scripts/virtual/guest.py` | 15,219 | `84b29d91c50ad7172009135283c05e405c9c1ecf08cfcad45ff3208d048834c3` |
| `scripts/virtual/test_virtual.py` | 54,015 | `a57f3491c73f5ec6d5ea87d85dea5d06f0e0b91ca40c209510f0c9cd951b9033` |
| `scripts/ci/development/virtual_stage.py` | 60,678 | `b116c5cc99245d3548481823554e4307dafcd21bd47d21fceece054296d6cc79` |
| `scripts/ci/development/test_virtual_stage.py` | 131,539 | `ed947a7aab205c7fb47ccc682ecdd11319ad316b6530beea09a268ea4cb7e10f` |
| `docs/workstreams/virtual-empty-configerrors-correction.md` | 6,310 | `4417bf045feb488e6fc1934df1becb91af3d3c3842ca375353801908251aad14` |

Each production module adds one pure helper and changes one readiness call.
Independent whole-module AST reversal removes that helper and replaces its
single call with the previous `== []` comparison; both complete prior module
ASTs are then identical. The two helper return-expression ASTs are identical.
Two separate read-only source reviews also checked the whole textual diffs.
Monitor, mapped-client, pixel/frame, publication, privacy and cleanup code is
unchanged by this functional delta.

## Focused independent controls

The review copied the author's hash-bound **16-file source/dependency capture**
into a fresh owned tree and used isolated Python with `-B` and
`-W error::ResourceWarning`. Explicit captured-source loaders and imports were
checked to resolve only within that tree or the owned before-source copies;
working-tree bytecode caches were never loaded. Before/after captures contain
zero PYC/cache directories. The author's admitted historical working-cache
refresh was preserved, not treated as source authority or repeated here.

[Guest controls](../../artifacts/reviews/virtual-empty-configerrors-root-peer-20261012/guest-controls.json)
passed **10 test methods, zero failures/errors/skips**. Direct causal replay of
the actual probe values at 9679/15807/21315 ms fails on old guest `3ca0e95e...`
with `runtime config errors`, while corrected source emits all three unchanged
probe records and the immediately correlated ordinary command. The last raw
stdout remains `[\n\t""\n]\n\n`. Controls reject the 19 required parsed shapes,
malformed JSON, wrong return-code types, transport errors, stderr, UTF-8 output
overflow, dead compositor, late replies and inexact exit-6 replies. The original
180-second cutoff, 24-attempt cap and bounded logs remain enforced.

[Receiver controls](../../artifacts/reviews/virtual-empty-configerrors-root-peer-20261012/receiver-controls.json)
passed **7 test methods, zero failures/errors/skips**. Direct old/new protocol
comparison covers all four minimal/overlay combinations of `[]` and the exact
actual empty-string reply: old source accepts only `[]`/`[]`, corrected source
accepts all four in otherwise complete **synthetic** protocols. Current full
adapter fixtures preserve actual probe values/times and raw command correlation.
The 19 malformed/nonempty parsed shapes, closed-field/type/UTF-8 bounds,
consecutive attempt/order/time violations, exact-retry violations, missing or
changed ordinary commands, missing phases/frames, unmapped/invalid clients and
invalid monitors remain refused. A synthetic positive PPM and three pixel
negatives cover wrong digest, wrong dimensions and rehashed blank data. No
accepted fixture frame is an actual compositor capture.

## Actual evidence and semantics remain bounded

The [held diagnosis](native-virtual-ipc-execution-38274341668.md) still hashes to
`a4c539fdad668b4bb27a5432312b70bd60bf315da256bf194d7b0c79aefe240b`.
The exact actual event bytes are
`ab406dd9607b7039420dc89d39c037039abd65e273b72336f64805331dcc1422`;
the owner result is
`085c7bfde34a99b9dc67509a173fc3e2f05dfaf91085a08055b80aa03de6fbde`.
Their 13-event FAIL/empty-frame state was independently verified. The corrected
receiver retains the same diagnostics but refuses that incomplete historical
stream as a successful protocol. No synthetic completion was written over it.

[Passive byte checks](../../artifacts/reviews/virtual-empty-configerrors-root-peer-20261012/passive-semantics.json)
confirm that retained formatter outputs for no accumulated messages, stored
empty messages, space-only messages and tab-only messages all equal the actual
reply bytes. These are readings of the earlier pinned host-extraction results,
not a new compiler run, full Lua-parser execution or proof of distribution-binary
patch equivalence. Received `[" "]` is refused, but whitespace already collapsed
upstream to `[""]` cannot be recovered. Internal error counts are not inferred.

The author logs report 65 guest/controller plus 98 receiver checks, 163 total,
with ResourceWarning treated as error and no skips. This reviewer reran only the
17 focused methods above, plus bounded direct causal/protocol/pixel controls.

## Coordinator pin and adoption boundary

The historical 16-file capture binds controller
`879b72ecbd3803e8745e99baa99c4e42c441af209234579620f50840b681614b`,
with guest pin `3ca0e95ed89cd21edc96b09e1bc98138e0addbd4b99fc9a3ba41f22ea562ddda`.
During this review the coordinator deliberately changed that one literal to
`84b29d91c50ad7172009135283c05e405c9c1ecf08cfcad45ff3208d048834c3`.
Independent byte replacement proves this is the only controller change and
yields current controller
`aeb4a9b9b050e084b0352f46a05807b8a3e42c76224d09c4f1a1e7383a1629de`.
The original capture guard correctly refused the moving working controller;
subsequent controls use the explicitly historical capture. No controller was
edited by this reviewer.

The coordinator's validated proposal binds the 211-file packet
`8fef8a03a58eafba992123690f758bc3e1405ae01a4ffeb26cce0b43ff4d170f`,
five changed code rows and 206 unchanged rows. Its receipt reports 210
development and 22 controller tests passing; these are coordinator results,
not independent reruns by this reviewer. Actual committed Git/blob/mode/source
proof and a later bounded native guest trial remain coordinator work. A real
usable compositor frame, full Lua behavior, ARM/M2/16K qualification, graphics
acceleration and performance remain unestablished by this correction review.

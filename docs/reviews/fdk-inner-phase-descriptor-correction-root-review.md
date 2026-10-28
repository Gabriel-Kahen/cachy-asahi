# FDK inner-phase descriptor correction: independent root review

**Source/admission readiness remains blocked.** The corrected helper can adopt
and close a different-inode descriptor after its initial identity query fails.
The parent reader's initial-ownership correction passes the bounded review, and
the prior known-identity retry/persistence findings are addressed. Passing tests
do not close the newly demonstrated initial-query reuse case.

This review edits only this document and
`artifacts/reviews/fdk-inner-phase-descriptor-correction-root-peer-20261012/`.
No held implementation, recipe, map, workflow, Git state or shared consumer was
changed. No real Docker, compiler, native build, makepkg, GPG, installation,
namespace, network or host service actor was run. Existing bounded local Python,
self-signal and Unix IPC test fixtures were replayed as source validation.

## Authenticated input and scope

The final author packet is
`artifacts/reviews/fdk-inner-phase-descriptor-correction-20261012/final-review.json`,
SHA-256 `62dd30555a3d56ad313709e2318d7733962987f32bc08e2cbc6eb16f826f9400`.
All **363 indexed records** matched their declared hashes, lengths and modes;
their combined length is 40,434,417 bytes. All four declared live source files
also matched their held pins. The review retains its own authenticated copies,
including the revised roadmap, package inventory and contributor instructions.

| Source | SHA-256 |
| --- | --- |
| `packages/libraries/cachy-asahi-fdk-aac/inner_observation.py` | `dec7eeeb939c730f7209207cc1a434350312be712845aad78c759b704c58855b` |
| `packages/libraries/cachy-asahi-fdk-aac/test_inner_observation.py` | `f74ddacb802e312b961d335c71bbfe1d95fbb1993d96010e89a925036e5c5f7c` |
| `scripts/port/fdk-native-stage/inner_evidence.py` | `bdbef4cbf9161ffe691375aa9f501dfcd09dd9983f5b119bd04ec3d7f1163a75` |
| `scripts/port/fdk-native-stage/test_inner_evidence.py` | `7cc9b798b7cd11a307559b4c99c61a494fb2a6c2266bc0071e2078e8d93b14a7` |

Comparison with the authenticated `0e31b0de…` kernel checkpoint covers all 136
held source paths: exactly these four changed, and 132 remain unchanged. Recipe
hooks, PKGBUILD/SRCINFO, build-codec, worker body, worker-evidence, shared evidence,
reviewed maps, stage lock and workflow remain byte-identical in this graph.
The final **held-source-v2** graph is the test input; the earlier held-source
snapshot contains an intermediate parent-reader revision and must not be treated
as the final four-source hold.

AST comparison finds changes to helper `close_owned` and `Recorder._publish`,
plus new `Recorder._ownership_refusal`; the other 25 helper methods/functions
match their baseline AST. The parent changes `release_owned`, `capture_file`
and `capture_inner`, adds two registry/refusal helpers, and preserves its other
11 methods/functions. The eleven-module observer grant, diagnostic schema and
private/public record shapes remain unchanged. This is descriptor diagnostics
work, not package or hardware acceptance.

## Remaining finding: initial unknown identity can become foreign ownership

**[P2] `inner_observation.py:119–142`, particularly the adoption at 136–137.**
`close_owned(fd)` creates a fresh registry entry whose identity is None. A
non-EBADF failure on the first `fstat` records an error and continues. If that FD
number is reused for a different inode before the next successful query, the
`fresh` branch adopts the new object's identity and closes it. There is no prior
identity against which that first successful query can be checked.

Five pure descriptor-table models independently reproduce the distinction:

| Schedule | Baseline helper | Corrected helper |
| --- | --- | --- |
| Initial query EIO, then different-inode reuse | Foreign descriptor remains open | Foreign descriptor is closed |
| Initial query KeyboardInterrupt, then different-inode reuse | Foreign descriptor remains open | Foreign descriptor is closed |
| Known original identity, close error, different-inode reuse | Separate positive control | Foreign descriptor remains open; original identity retained |

Both failing schedules still preserve the exact first exception object. That
property does not authorize closing the foreign descriptor. The reproducer uses
only mocked FD tables, `fstat` and `close`; it opens or closes no real descriptor.
The model script exits zero because it asserts this undesirable result, not
because the source is ready. See `initial-query-reuse-control.py` and
`initial-query-reuse-results.json`, with an independent replay/assessment under
`test-peer/`.

The final author's statement, “Different-inode reuse protected; same-inode
same-number reopen cannot be distinguished,” is therefore too broad. Protection
is demonstrated after identity is known. Initial-query retry additionally assumes
exclusive ownership of the FD table entry until the first successful query.
This limitation is distinct from same-inode reuse and was not covered by the
passing controls.

A safe correction needs a previously retained allocation/caller identity, or
must keep identity permanently unknown after failed initial acquisition and
refuse to authorize a later close from newly observed identity alone. Remaining
queries may establish EBADF without granting ownership. The implementation owner
must select and test that correction; this reviewer changes no held source.
If a narrower cooperative-ownership scope is selected instead, the unqualified
protection claim and its acceptance requirement must be explicitly narrowed.

## What the existing correction establishes

The parent reader does not share that initial-acquisition gap. `capture_file`
registers ownership as unknown before the first identity query. If that query
raises EIO or control, it retains the exact original exception/control and
rethrows it. `release_owned` refuses to query/close identity-None ownership.
Later captures refuse before allocating another descriptor; external fixture
closure does not erase retained uncertainty.

For already known identities, both paths use the existing **three query/close
slots**. Transient non-EBADF queries consume a slot and can retry without an
unjustified close. Success or a kernel EBADF retires ownership; persistent errors
and different known identities retain it. No timer or production recovery API
was added. Failed cleanup preserves the first ordinary cause and the first
control. Cancellation remains latched without replacing a prior business failure
in the diagnostic record; control propagation can supersede an ordinary active
exception while keeping its cause/record.

The helper's retained uncertainty sets `write_failed` and refuses healthy
publication, including later attempts. This closes the old `0e31b0de…` findings
about non-EBADF known-identity cleanup stopping with lost tracking and persistent
untracked residuals, within their exercised schedules. Persistent faults still
leave measured descriptors live: this review accepts their retained uncertainty
and refusal, not forced production recovery.

Other limits remain explicit: same-inode/same-number reopening cannot be
distinguished by the tuple; identity-check-to-close races require cooperative
ownership; controls are sequential; and the parent's unchanged `open()` return
to `retain()` registration interval is unmasked. The controls do not establish
lossless custody for arbitrary asynchronous cancellation in that interval.

## Fresh validation and separate admission dependency

Fresh captured-source tests passed with `-I -B -S` and ResourceWarning as an error:
23 observer, 24 build-model, 26 parent-reader, 27 worker and 40 evidence tests,
**140 total**, with zero PYC files. No FDK compiler or actual daemon ran. The
review also replayed 12 helper controls, 13 capture controls, three acquisition
controls and 16 old/new causal schedules: **44 descriptor replays passed**.
These schedules cover known-identity recovery, persistent retained faults,
foreign known-identity reuse, cleanup exceptions and first-cause/control handling.
The five new models demonstrate the additional blocker despite those passes.

The shared public completion gate remains a separate coordinator-owned dependency.
Held `evidence.py`, SHA `27d16ce1…`, calls `validate_workers(workers)` at line 243
without `require_complete=True`. Its default allows legacy COMPLETE observations
without mandatory inner evidence. `worker_evidence.validate_workers` lines
260–263 contain the strict path that requires inner records. The descriptor
correction does not wire that strict path into `finalstatus_public`; Root must
implement and verify that update before modern public PASS is admitted. No shared
consumer is edited here.

Actual **FDK8 remains FAIL, exit/attach 4**. Its historical inner function and
compiler invocation cause remain **UNKNOWN**. Synthetic nonzero/control models
provide no new attribution. The roadmap still has incomplete milestones, and
FDK remains unselected for release with native acceptance, target lifecycle,
Asahi/M2 behavior, ABI/use-case integration, reproducibility, publication terms
and performance work unfinished.

The independent review is complete as a blocked source handoff. Resolve the
initial unknown-identity finding and the separate modern completion gate, then
re-review exact source/recipe-map bindings before any actual actor admission.

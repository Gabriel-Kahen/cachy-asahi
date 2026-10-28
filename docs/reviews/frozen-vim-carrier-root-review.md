# Frozen Vim carrier: independent source review

**Disposition: two source custody corrections required before adoption.** The
normal source/copy/selection controls pass, but independent probes expose first-
cause replacement and unregistered source-FD cancellation windows. No actual
payload acquisition, signature/crypto verification, native retry, public carrier,
license clearance or execution authority is supplied by this review.

Author receipt
`192c5a12ab994d0d09fc888c71e7202dce85e1c604c488ceb7eda66fb833fdda`
authenticates at282,782 bytes/mode0644; all1,024 indexed rows authenticate. The
reviewed controller is `scripts/port/fdk-native-job/job.py`,38,692 bytes/mode0644,
SHA `65bd1cd9d272f8b8413263f1b01d2de5b49b840f43b062d0c41499fd9b066c69`;
test_job is86,249 bytes/mode0644,
SHA `a4cdb4d46f8527967a37ba6de9d8e791645904edd12120483ec986d6c0a69b65`.
The [implementation guide](../workstreams/frozen-vim-carrier-implementation.md)
correctly identifies the FDK job paths; no repository-native-handoff/job.py exists.

Evidence is in
[`frozen-vim-carrier-root-peer-20261013`](../../artifacts/reviews/frozen-vim-carrier-root-peer-20261013/).
Only that new directory and this new guide were written. Existing source, maps,
workflow, Git, author holds and historical failures remain unchanged.

## Finding 1: preserve first cancellation and attempt every owned close

**[P1] New helper finalizers, job.py:106,133,264 (also74–77,229).**
`frozen_directory` directly closes descriptors in a loop; the first close error
ends that loop and replaces an exception from the body. `frozen_read`,
`frozen_names`, copy FD and final cache FD use unconditional finally closes that
can likewise replace an earlier business/control exception. This contradicts the
held helper's first-cause/cancellation contract.

[`firstcause_probe.py`](../../artifacts/reviews/frozen-vim-carrier-root-peer-20261013/firstcause_probe.py)
uses actual private FD allocations and faults after a real close, without leaving
that tested close uncertain. Three finite controls reproduce the issue:

- Directory body raises the exact original `jr.Cancelled`; close raises OSError.
  The caller receives OSError, and only1 of12 owned FD closes is attempted.
- Source read raises the exact original cancellation; read FD close raises
  OSError. The cancellation becomes an ordinary OSError.
- Tiny source-derived copy raises cancellation; disposal removes the owned cache,
  but final cache close raises OSError and replaces that cancellation.

An ordinary exception that replaces cancellation can route through execute's
ordinary-failure handler without the original cancelled identity/marker. It still
fails; this is not a demonstrated actor/PASS bypass. Preserve the first body
business/control exception across all close and signal-restoration boundaries,
attempt later owned closes despite ordinary cleanup faults, and refuse healthy
completion when cleanup alone fails. Keep finite disposal notes and uncertainty
honest. The probe manually closes every skipped model FD after observation.

## Finding 2: register source FDs before pending cancellation can unwind

**[P2] New source FD allocation, job.py:68,93–96,116.** The helpers allocate an FD
before entering a protected cleanup/registration region. `frozen_directory`
registers the opened FD only after open returns; frozen_read/frozen_names begin
try/finally only after allocation. A pending control delivered at that boundary
can leave an FD invisible to owned cleanup.

[`allocation_probe.py`](../../artifacts/reviews/frozen-vim-carrier-root-peer-20261013/allocation_probe.py)
models pending `jr.Cancelled` immediately after real os.open, before helper-side
registration. Each directory/read/enumeration case retains one live descriptor
with zero close attempts. The first exception itself survives. The probe then
manually closes those model descriptors; no external process or payload runs.

Protect allocation through registration and cleanup ownership using the existing
owned signal contract; replay pending cancellation only after ownership is
recorded. Apply the same discipline to all new source/cache/copy allocation and
handoff edges, including faults during post-open fstat or deferral restoration.
Use the original Runner.deadline; add no fresh timer, producer allowance, shared
runtime relaxation or grant. Persistent OS faults may remain uncertain, but must
not be reported as proven disposal or successful issuance.

## What passed within the remaining scope

Fresh cold source-only processes pass published baseline57 and held candidate86,
zero failures/errors/skips and actor attempts. Independent AST comparison verifies
all57 original test-method bodies unchanged and exactly29 additions. The29 are
part of86 and are not added again. New fault probes expose gaps beyond that finite
suite; ordinary suite PASS does not close either finding.

The135-file source/workflow/packet capture and10 historical test-dependency rows
authenticate. The candidate changes only job/test_job relative to published9ed;
all unowned source rows remain identical. No PYC exists in the independent capture
or is loaded. All source/dependency rows reauthenticate after replay.

The immutable production tuple derives exactly the four original Vim archive and
signature names, full hashes and integer lengths from frozen input-lock
`3c16c37d1b12cc84a88572e82ab8ad59e7f3b5ed0d08f09ddf72a69f4711d650`. Total is9,790,183
bytes. Canonical compact sorted JSON has no trailing newline and SHA
`13bdcca86d6f6a5a02a6f43afff2b61c3ce832d9bc12ad2ada55b5dc404255d6`. Rehashed arbitrary
lock rows cannot redefine the production tuple. These checks read only lock/source
JSON; no real archive/signature payload was read or duplicated.

Actual unchanged packet.closure selects133 sources, adapter44, recipes4 and71
recipe files. The proposed packet is
`f714a121183b313e64254b23df0c2b1f2d7cf31ed5f326b40223a4bba1d67fed`; its actual selected
bytes/modes/hashes match the independent capture. It uses historical producer
`41c389897da7ee8b5d3fa7f927f9c95db537150d56dd67de927a3bce8ac1d500`, deliberately excluding
Root's concurrent primary diagnostic0f747 changes. It is not a joint registration.
Native source remains
`a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898`. Original fetch's
valid-existing branch is exercised by the held suite against tiny seeded fixtures
without transport; its full real size/hash and original501 acquisition/249 signed
payload gates remain required. None is claimed as actual crypto/native PASS.

CLI arguments remain optional; manifest pin without carrier refuses, while the
legacy route calls no helper. The hook is after complete source/Git/snapshot,
worker-validator capture and native-byte hash, before broker/producer construction.
Run/attempt shapes and lexical source/output/carrier separation are checked.
Carrier membership is exactly four; all bytes are captured before fresh private
cache creation. No-follow parent/source FD guards, ownership/modes/nlink, exact
size/hash, copy reread, created-inode correspondence, completed-file drift and
foreign replacement refusal are retained. Recovery deletes only known created
inodes and refuses foreign/unknown cache state. Copy guards use the same absolute
Runner.deadline; finite actor-free disposal does not renew copying/producer time.

## Limits and required next work

Tests use project-owned TMPDIR, tiny explicitly derived lock/payload fixtures and
actor/network tripwires. Published baseline57, original86 and the author's
19PASS/5FAIL/1ERROR/helper enumeration history remain immutable; no failed result
was relabeled. The two probes establish bounded source failures, not hostile
same-UID resistance, guaranteed cleanup under persistent faults or hard real-time
completion.

Root should obtain a separately sealed two-file correction with causal RED/GREEN
controls for both findings, then combine the independently reviewed producer
changes into the actual joint133 packet and update reviewed workflow/source pins.
Retrieval implementation, exact external carrier provenance, bounded retrieval/
retention evidence, accountable retention owner, license/source/public-carrier
obligations and actual authorized acquisition/crypto/native retry remain separate.
R1–R5/M5–M9, Asahi target transaction, both M2 Air sizes and performance acceptance
remain unfinished.

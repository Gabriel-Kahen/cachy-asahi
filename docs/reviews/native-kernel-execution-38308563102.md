# Kernel7 execution: independent evidence and worker-path audit

Disposition: **PASS for bounded source/archive/public authentication; actual
kernel7 remains FAIL.** The retained record establishes a baseline attached-start
CLI result1 and a failed kernel stage, followed by accepted cleanup. It does not
identify an inner-worker failure or establish whether full kernel compilation
started, failed, or completed before a later error. No new native run occurs in
this review. A minimal fixed diagnostic proposal remains artifact-only.

## Exact run and authenticated source

Run 38308563102 uses source commit
`25b0213e73c67efbed758af7c32f6c1057850052` and117-row packet
`4961fa1f324fea9cf173f69e8e90a491048359f8a4eb0d64ee90b50c177e0199`.
The 26-row stage lock is
`edf34671885cc3b76537a5d16f7768a97fa27d80ca66bd081397b144457d42b2`.
Both independent source lanes authenticate the exact committed blobs and modes;
packet source bytes total 2,052,823. Captures are read-only0400, with original Git
modes recorded separately. The packet lock is captured as an additional file.
Current mutable source and subsequent shared HEAD are not substitutes for this
run. Legitimate concurrent FDK helper corrections are outside this captured
kernel source and are neither edited nor rejected by this review.

Critical committed sources:

| Source | SHA256 |
| --- | --- |
| Kernel worker | `0586aa8803d34179713cf143f09e2d0395a8ee22d80fd55befbdee44352b19c0` |
| Broker | `370a6036d7c268267c31fa40dd08b159b70dba6e7ccd693b46b92df512725fe7` |
| Runtime | `6d733a1c70fb2dc37723527bd19a5947e77b354f2a5b0bdfec7c5c96f2de74e4` |
| Kernel source harness | `f2d6fc62d28b0c189469ca7cf8293f10c574ecd0459c33c013bf1a271b8a5ebf` |
| Job public projector | `418e65fde22aaa48721066e69f0b1e950da0199e68e752e24dbbc69b78fdb5f6` |

The selected workflow and its preflight/public bootstrap body match the retained
command echoes. Bootstrap SHA256 is
`3591729ac80dff8f89d64d05dededbffca4c164ed6a70aef3b81c8154a7d816b`.
The execution echo matches the committed command, including its fixed image/
endpoint/source bindings and redirected private output. No bootstrap/native
preflight is re-executed by the reviewer. Local Git/archive authentication does
not independently query external run metadata or reconstruct private bindings.

## Archive and closed public record

Retained ZIP SHA256 is
`0c3abaf3f42735818c3865575c24c6fc945f3cd9574e9676fc05563feb30a1c4`,
29,588 bytes. All nine unique file-name members total111,082 decoded bytes.
Independent raw parsing checks central/local headers, flags, sizes, compressed
extent, CRC and signed data descriptors, with no unparsed gap/trailing bytes,
encryption, traversal, duplicate name or special-file profile. This archive uses
DOSattr0 file-name entries; that profile does not establish an original Unix
filesystem inode. Every decoded member equals the retained extracted log bytes.
Fifteen hostile raw-archive controls refuse.

The actual public record is2,424 bytes, SHA256
`a8d92ded18793362be3c172e81d5a592b14cd8e9d232516765cd729a07d28f52`.
Root independently loads the committed projector from an authenticated copy,
reproduces the record byte-for-byte for the observed failure outcome, and matches
the one actual emitted JSON line in the publication log. The earlier root
verification artifact agrees but is not substituted for this fresh replay.

All five workflow outcomes (success/failure/cancelled/skipped/unavailable) retain
the actual first kernel failure, baselineFAIL, candidateNOT RUN, cleanupPASS and
native compilationNOT ACCEPTED. Cancellation adds its flag without replacing
the earlier cause. Twenty-seven hostile controls refuse changed schema/private
fields, boolean numeric impostors, source/packet mismatch, unsupported release/
hardware/runtime/performance/publication promotion, daemon-preservation/absence
contradictions, malformed child binding/exit/predicate/resource/cleanup fields,
duplicate keys, nonfinite JSON and stale PASS promotion.

## What the actual record establishes

| Boundary | Actual retained result |
| --- | --- |
| Original producer | PASS; returned exit0 |
| Acquisition | Returned exit0 |
| Provision command | Returned exit0 |
| Probe | PASS; command exit0, accepted userspace logic-fixture path |
| Baseline | FAIL; attached-start CLI returned1 |
| Candidate | NOT RUN |
| Kernel stage child | Returned exit1; verified closed diagnostics |
| First child failure | BASELINE_COMMAND / COMMAND_NONZERO |
| First broker failure | baseline / QUERY_RETURN / START / EXIT_NONZERO1 / CID_OBSERVED / EXIT_OBSERVED |
| Cleanup | PASS; no independent cleanup failure |
| Owned absence | PASS |
| Daemon preservation | PASS; pre/post identity hashes equal, initial six image identities and zero containers |
| Producer mutation | COMPLETE_ACCEPTED |
| Full native compilation | NOT ACCEPTED; actual compiler progress UNKNOWN |
| Kernel execution, hardware, installation, binary publication | NOT RUN |
| Performance, release selection | NOT MEASURED; selected_for_release=false |

The daemon identity hash is
`124fd070b1b7bc795026a7b7ed4773c03383c492587efeeaffc5faf65f7cb869`
before and after cleanup. This proves the retained source-defined preservation
comparison, not legacy build-cache absence or recovery/hardware acceptance.
The userspace extracted-function fixture is separate from kernel execution or
an accepted full build pair. Its underlying private outputs are not recovered.
The final current cleanup/checkpoint observation does not replace the sticky
baseline failure; a query return1 in a later current row is not an independent
cleanup failure when cleanup_failure is absent and cleanup is accepted.

Compared with kernel6, this run passes provision and reaches the baseline
command. It does not retroactively identify kernel6's unexported CapAdd values
or prove why that earlier run refused. Kernel6 remains historical FAIL. The
equivalence correction is present in this run's committed broker and registered
stage/packet; that is a source fact, not an inferred actual private spelling.

## Source-causal limit: CLI result is not an inner-worker diagnosis

`Broker._launch` observes the returned `docker start --attach` CLI status and
assigns EXIT_OBSERVED from that return. It does not capture the stopped
container's `State.ExitCode`. Therefore this record establishes the returned
attached-start result1, not an independently witnessed natural worker exit1.
An attachment/client failure and an inner worker failure are not distinguished
by this observation alone. No stopped-State or raw stderr is exported here.

The stage records the baseline command result, latches BASELINE_COMMAND failure
and refuses nonzero **before** loading `output-baseline/result.json`. A private
failed worker record may have been created on the owned output mount, but the
current stage's accepted/public diagnostic does not project it. Its actual
contents, existence and provenance are UNKNOWN in this retained packet.

Worker source has distinct failure classes before the private report exists:
argument/nonce/action and contract checks, code/dependency/input authentication,
temporary home/config setup and Runner construction. Later failures can occur
in profile, inventory, tool validation, full source materialization, input config
copy, olddefconfig return, config parsing/delta, generated-config copy, kernel
command spawn/return/timeout/output, output validation or final log/result
publication. Successful earlier command observations do not identify which
later path occurred. A generic top-level exit1 is compatible with several of
these classes; no missing compiler, Rust, configuration, disk or kernel cause
is selected from speculation.

The source-causal peer runs47 inert worker/command/compile/entry controls with
business calls fully mocked, plus eight AST-only stage/broker-boundary controls.
Multiple injected pre-report and post-report errors produce the same generic
worker failure outcome. Nonzero launch models demonstrate refusal before
private receipt load; valid zero and poisoned-receipt controls verify the
original successful path. An EXIT_OBSERVED model separately shows that this
field follows the CLI query return, not stopped State. These are fresh
source-model controls, not reenactments of the actual private failure or native
compilation. No production Runner or compiler executes.

## Minimal diagnostic proposal and adoption boundary

The artifact-only [proposal](../../artifacts/reviews/native-kernel-38308563102-root-peer/worker-cause/proposal.md) adds a finite, fixed
source-issued phase/command/error-kind projection for this worker path. It
must distinguish command attempt from observed Runner return, retain the first
business cause separately from diagnostic/finalization failure, and map errors
to closed kinds without messages, argv, paths or raw logs. Source/action/private
context pins and bounded once-captured bytes must bind any projection consumed
after a failed launch. Absent, malformed, unbound or unhealthy data stays UNKNOWN
and never supplies PASS or overrides original command/cleanup failure.

Actual worker exit remains UNKNOWN unless an original broker-validated stopped
State or equivalent owned witness binds it. Reuse an already required original
inspection where possible; no additional Docker query or raw/private log
publication is authorized by this review. A source-issued attempt alone cannot
prove subprocess startup. A returned CLI status cannot be copied into an inner
natural-result field.

This is a minimal observation proposal, not an implemented source correction,
registered packet or dispatch grant. Coordinator selection must precede exact
source ownership, independent old/new causal checks, source/dependency/recipe/
stage/job/workflow registration and any subsequent native trial. Existing
commands, flags, timeouts, resource/ownership checks, acceptance, cleanup and
platform stack must remain independently enforced. The proposal does not create
a general logging framework or accept arbitrary callbacks/raw exception text.

The roadmap/package inventory were read; R1–R5 and full M5–M9 remain required.
Camera peer3cbfd872, kernel capability peer9846fb83 and blocked FDK correction
peer0e31b0de remain preserved. No installer edit or revalidation occurs here.
All review-owned files are under this document and
`artifacts/reviews/native-kernel-38308563102-root-peer/`. Source receipts, strict
archive controls, public controls, inert worker/stage results and the proposal
are sealed in the final receipt. No Docker, native build/compiler/kernel,
installation, GPG, namespace, hardware actor or Git/shared/source mutation ran.
Only read-only Git queries and harmless source/data models executed.

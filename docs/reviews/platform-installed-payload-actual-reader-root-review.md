# S01 actual-reader proposal independent Root source review

Disposition: **BLOCKED for source/actor selection** at held review
`7e75acc46160f2201749224280512786375516cb260f27a3ca99362e02bbd2e7`.
The harness has two independently reproduced output-custody defects. No actual
debugfs trial is ready or accepted by this review.

## Findings

**P2: Dispose only the owned partial-report inode.** At
`reader_harness.py:268`, the `persist_report` finally block unconditionally
unlinks `preflight.json.partial`. An independent private-file fixture renames
the opened owned partial away, replaces its name with an unrelated regular inode,
and raises modeled cancellation at the next write-time ledger check. The source
preserves the original cancellation but deletes the foreign replacement; the
displaced owned partial remains. Record partial ownership before the first write
and verify it through no-follow custody before publication or disposal. Foreign
replacement must refuse and remain untouched. Preserve the active first cause
and record incomplete disposal rather than deleting an unowned node.

**P2: Detect dangling final symlinks during revocation.** At
`reader_harness.py:209`, `revoke_owned` tests `Path.exists()` before `lstat`.
A foreign dangling symlink replacement makes `exists()` false, so revocation
silently returns without the required custody refusal. The link is preserved,
but the outcome does not distinguish absence from an unowned named node. Use
no-follow lookup, treating genuine FileNotFound as absence and refusing a present
foreign/type-changed node. Retain causal tests for regular and dangling-symlink
replacement and a genuine missing/owned-file positive.

Both controls use only private tiny files and captured harness source. They show
software cleanup bugs, not hardware behavior or hostile same-UID protection.
They do not claim a real image/tool trial or full correspondence PASS. Exact
reproducers/results are retained as `custody.py` / `custody.json` below.

## Authentication and source controls

All70 indexed proposal rows authenticate by exact SHA/bytes/modes. Root's adopted
472 rows and four source files remain unchanged under adoption
`299faeb8fb55f276972ee5af780716f09ea434e36f8ea7cc798fbb32caa8deae`.
The adopted reader remains
`968d31e21e0f91ac21b4dd93835e52e68c6c93c4426e3efcb76c1b6a8a896fc1`.
Candidate reader
`485913978598a444f86de17c7583e14b96fb7fdb9b25334f4f59d054af09c16a`
differs only by its one TOOL_CONTRACT_SHA literal: reversing that literal restores
the exact old bytes and AST. Its23,916-byte/0644 source is proposed, not adopted.

V3 contract
`4f53cd7be7a9f23c526007bd846b4c09b040be364504959dbf4273b5591d3ef6`
retains schema2 and approvedfalse. Recursive comparison with intact v2
`6f0900f9a691944fe4a804407a3dd6e72ad8fb6380662162a74325b3d2384bf8`
finds exactly32 UID/GID scalar changes65534→0 across ten logical references and
six links. All other byte hashes/sizes/modes, targets and identity facts remain
exact. Nine physical tool files, the logical duplicate and historical namespace
observations remain distinct facts; the identity-drift cause remains UNKNOWN.
This review authenticates recorded tool metadata, not fresh executable bytes.

The proposal's retained image3680501760/SHA76f95..., ownership input and259 archive
references pass current nine-field lstat and ancestor checks without opening
payload bytes.261 required tuples, two missing exact archives and26 unresolved
signer joins remain incomplete. No archive/image digest is renewed by this review.
The ownership63721-path recount and tuple/signature facts remain retained metadata.

Cold isolated harness replay passes **14 methods,0 errors/skips** under
`-I -B -S -W error::ResourceWarning`; the independent captured14-group script
also passes. Resource/signal/Tool APIs are explicitly mocked. The default plan
stays unselected/actual_readerfalse; approvedfalse refuses before source/reader
execution. Expired preparation refuses before open. Grant/data/policy/resource
types, fixed three-request sequence, ledger report debt, ordinary/control late
revocation, regular foreign final refusal, first-cause precedence and partial
cleanup I/O limits are retained. Their mocked parser inputs are source grammar
controls, not observed actual debugfs output or an actual grammar success.

The additional custody control confirms a genuinely owned regular final can be
revoked. It distinguishes that positive from the two blocking replacements.
Fresh copies and evidence contain zero PYC. All previous installer87/native
correction and repository95 rechecks remain unchanged.

## Scope and next action

Correct/re-hold harness and causal tests, then independently recheck before Root
selects the actual read-only trial. The proposed actor requests remain exactly
`stat <2>`, `ls -p <2>`, `stat <2>` through pinned executable/image FDs, with only
LC_ALL/TZ environment and no `-w`, CAT, extraction, mount or recursion.
Before/after tool/image rehashes and final handle disposal remain source policies,
not actual outcomes in this review.

One20-minute envelope applies before CLI JSON/source preparation. One8GiB ledger
is retained for decoded/archive/image work plus serialized report debt; raw fixed
reference hashing is separately bounded under the same deadline. Per-call20s,
cleanup2s, AS2GiB, CPU1195s and report256MiB are finite source limits. AS/CPU remain
per-process, not measured aggregate process-tree acceptance. No cap or deadline
is renewed by these controls.

Root must bind exact harness/candidate/core/v3/selection/output/requests/resources
and issue separate actor authority. Metadata and source PASS do not self-approve
the grant. No primary source/shared pins/maps/workflow/Git edits occurred here.
No debugfs/loader/image/archive/GPG/native/Docker/mount/install/namespace actor ran.
Actual reader/output/resources, complete correspondence, issuer/key-owner trust,
installation/hardware/ABI16K/performance remain **NOT RUN** or unaccepted.
R1–R5/M5–M9 remain mandatory and incomplete.

Evidence is sealed under
`artifacts/reviews/platform-installed-payload-actual-reader-root-peer-20261012`:
`authentication.json`, `cold14.log`, `independent14.log`, captured source/models,
`custody.json` and `final-receipt.json`.

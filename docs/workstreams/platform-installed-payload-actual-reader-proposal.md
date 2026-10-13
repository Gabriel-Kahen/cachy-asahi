# S01 actual-reader preparation and narrow trial proposal

Status: **SOURCE-ONLY PROPOSAL; ACTUAL READER NOT RUN; NO ACTOR GRANT ISSUED.** This work creates only this guide and `artifacts/reviews/platform-installed-payload-actual-reader-proposal-20261012/`. It edits none of the adopted four sources, original v2 contract, older evidence, maps, workflows or shared registries. The default harness mode prints an unselected plan; its grant proposal is explicitly `approved: false`. Every result keeps installed-payload verification, image issuer/key-owner trust, installation, hardware and complete correspondence acceptance false.

## Authenticated sources and selected inputs

Root's source-only adoption is `299faeb8fb55f276972ee5af780716f09ea434e36f8ea7cc798fbb32caa8deae`, recording 472 checked rows and the author `cf6824a3…` / independent `cfaba6c4…` checkpoints. Its four active source pins remain unchanged:

| Source | SHA256 |
| --- | --- |
| correspondence | `3a71ba896700f72130e35a56845516bd9c42de0b1b0fd782b79829b37ac262a7` |
| image reader | `968d31e21e0f91ac21b4dd93835e52e68c6c93c4426e3efcb76c1b6a8a896fc1` |
| correspondence tests | `4b7652b408c28f1fd4d19591804b3c059e3929197c14d31f13f80e009cf480ae` |
| image-reader tests | `511718296b0344f76a0b47c2705df92438eeb5404ff1af5b0eb70ff0dd770219` |

The adoption's 105 methods plus independent 63 core/118 reader controls are prior source evidence, not actual image execution. They were not repeated as an actual trial here.

[`input-peer/selection-proposal.json`](../../artifacts/reviews/platform-installed-payload-actual-reader-proposal-20261012/input-peer/selection-proposal.json) locates the retained image at `/home/gabe/Documents/ChatGPT/cachy-asahi/artifacts/platform/m8-minimal-20261012-b/root.img`: 3,680,501,760 bytes, historical digest `76f95dae6180bc4a45ffdeaccec26681d75b2207b90062064fcd2a845adbf9db`. Its full nine-field lstat identity matches the retained ledger. All 259 exact selected package archives are present, with matching identities and no archive inode/ancestor aliases. No image/archive bytes were opened, parsed, extracted or freshly hashed during selection.

The ownership input is the retained `image-files.json`, 6,873,628 bytes / `f12aba8413c5d8a5de9419f4321381cde0b1ca50a4d9e1c4f40421768952e994`. Its 261 package tuples and 63,721 unique owned paths are metadata evidence. Exact NetworkManager `1.58.1-1/aarch64` and Perl `5.42.2-2/aarch64` archives remain missing, and 26 signer joins remain unresolved. The 259 references are not relabeled as a complete 261-package closure. No actual archive-header/installed-byte/signature fact is inferred from the metadata recount.

[`actual-input-selection-proposal.json`](../../artifacts/reviews/platform-installed-payload-actual-reader-proposal-20261012/actual-input-selection-proposal.json) normalizes each runtime reference to exactly `path`, `size`, `sha256`, `identity`. Historical digest declarations and current lstat observations remain separately identified in the input peer's evidence.

## Current tool contract and minimal proposed rebind

The old v2 contract remains exact `6f0900f9a691944fe4a804407a3dd6e72ad8fb6380662162a74325b3d2384bf8`. It records tool/reference/link ownership as `65534:65534`; the current execution sees `0:0`. These are strict identity mismatches, so the old contract cannot silently be used or relaxed.

Root then authorized metadata inspection plus fresh bounded tool-byte hashes, without tool execution. [`tool-v3-peer/receipt.json`](../../artifacts/reviews/platform-installed-payload-actual-reader-proposal-20261012/tool-v3-peer/receipt.json) binds all ten logical references/nine physical files and six library links. Every binary/library byte hash, size and full mode matches v2; every symlink target/full mode also matches. Exactly 32 scalar identity changes refresh UID/GID only, across ten logical references and six links. The logical loader duplicate is preserved.

The same Python inspection process captured `/proc/self/uid_map`, `/proc/self/gid_map`, UID/EUID/GID/EGID `1000`, and its user namespace `user:[4026531837]` with stable namespace device/inode before/after. Current UID/GID mappings are `0 0 4294967295`. This describes the current namespace; there is no matching historical namespace capture and **the cause of the old/new ownership difference remains UNKNOWN**. IDs alone do not establish a tool-byte change or a namespace-remapping cause. Namespace pseudo-file timestamps are recorded without treating their changes as namespace replacement.

The fresh, separately authenticated candidate [`tool-contract-v3.json`](../../artifacts/reviews/platform-installed-payload-actual-reader-proposal-20261012/tool-v3-peer/tool-contract-v3.json) is `4f53cd7be7a9f23c526007bd846b4c09b040be364504959dbf4273b5591d3ef6`. It changes only the exact identity fields; it remains unapproved, with the old behavior/policy fields unchanged. “v3” names this candidate revision; its schema_version stays 2, as the unchanged Tool parser requires. It does not weaken identity comparisons.

The proposed reader copy is 23,916 bytes / `485913978598a444f86de17c7583e14b96fb7fdb9b25334f4f59d054af09c16a`. [`candidate-literal-rebind.patch`](../../artifacts/reviews/platform-installed-payload-actual-reader-proposal-20261012/candidate-literal-rebind.patch) changes only `TOOL_CONTRACT_SHA` from v2 to this v3. Restoring that one literal reproduces the exact adopted reader bytes and AST. The original reader is untouched. The candidate is not automatically adopted or registered.

## Concrete first trial

[`reader_harness.py`](../../artifacts/reviews/platform-installed-payload-actual-reader-proposal-20261012/reader_harness.py) offers a finite preflight route, not an automatic full correspondence scan. The exact request sequence is:

1. `stat <2>`
2. `ls -p <2>`
3. `stat <2>`

Root inode 2 is selected from the adopted source's explicit `walk(2, '', 2, 0)` invariant. No retained inode index was found, and this is not described as an already observed image inode. No CAT, child recursion, dynamic path interpolation, filename command, arbitrary request or additional inode is selected. The trial requires a directory root, matching before/after stat, a bound `.` entry and `..` inode 2. Unknown grammar, diagnostics, identities or return codes refuse.

Every actual argv remains the adopted reader's closed `('/usr/bin/debugfs', '-R', REQUEST, '/proc/self/fd/IMAGE_FD')`, executing the pinned binary FD with only the pinned executable/image FDs inherited and environment `LC_ALL=C,TZ=UTC`. The separate Root grant must explicitly select this inode grammar: historical v2 descriptive grammar still mentions quoted paths, whereas the adopted reader implements only fixed inode requests and its already reviewed finite streamed CAT policy. This preflight selects no CAT and changes none of those reader behaviors.

One `WorkLedger` and one 1200-second absolute cutoff cover source preparation, metadata checks, image operations and report work. The CLI starts its envelope before selection/grant JSON and source reads. All calls share that original cutoff; each is at most 20 seconds with a two-second cleanup reserve. There is no new cap per retry/file and no PYC fallback. The selected tool context must complete its final raw-image/tool rehashes and descriptor cleanup before the harness reports grammar conformance.

The ledger counts archive decoded bytes plus installed-image stdout; the harness additionally charges its one serialized retained report on the same ledger using a distinct valid lease after Tool release. It uses no archive extraction, regular-CAT temporary content or recursive-image temporary tree. Report debt and resulting shared-work counters match the final serialized length. Raw compressed/image/source/tool hashing remains separately bounded by each fixed reference length and the same deadline; it is not falsely described as part of the decoded-work counter. A future full job must retain this same ledger across archives and image work, rather than call the old modeled-tree CLI or create per-archive budgets.

The parent envelope applies 2GiB `RLIMIT_AS`, 1195 CPU-second `RLIMIT_CPU`, 256MiB `RLIMIT_FSIZE`, disabled core dumps and the absolute wall timer; child limits are inherited and the adopted child setup retains its 2GiB cap. **These are per-process limits, not measured or independently enforced aggregate process-tree memory/CPU caps.** Whole-tree peak/cumulative resource feasibility and Root's full-job aggregate supervision remain unverified. This proposal therefore does not certify full correspondence or resource acceptance from static limits.

One fresh private report directory holds `preflight.json`; the partial and final are one logical retained report under the same work ledger and 256MiB cap. Late failure/control revokes the exact owned final inode; foreign replacement is refused and never deleted. Ordinary cleanup failure does not replace an active control; late control supersedes an ordinary failure while keeping its cause. If revocation or partial removal fails, absence is **unproved**, that failure is recorded as a secondary note, and Root must refuse a nonzero/interrupted CLI even if a stale file remains. File presence alone is not preflight acceptance. All full-installed/issuer/hardware acceptance flags remain false even on a successful grammar trial.

## Reviewable grant, tests and handoff

[`root-grant-proposal.json`](../../artifacts/reviews/platform-installed-payload-actual-reader-proposal-20261012/root-grant-proposal.json) is explicitly false and binds the exact selection, harness, candidate reader, core, v3 contract, output path, three requests and fixed resource policy. [`proposed-invocation.json`](../../artifacts/reviews/platform-installed-payload-actual-reader-proposal-20261012/proposed-invocation.json) gives the exact `-I -B -S` argv but is labeled unselected/do-not-execute. The grant cannot select full correspondence; that route is not exposed by this harness. Root must separately review/select the v3/candidate and issue a concrete actor grant before any actual trial.

Fourteen strict isolated-Python harness methods pass using process/resource/signal mocks and tiny owned JSON/report files. They cover policy/grant/pin/tuple closure, fixed three-call source models, single deadline, ledger report debt, exact-owned revocation, foreign replacement refusal and cancellation/cleanup precedence. Default plan mode also exits zero with `actual_reader:false`. Early stale-fixture/wrong-command-pin refusals and intermediate report/cancellation counterexamples are preserved; no failed run is silently removed. Independent review retains the v2 constraints, exact v3/candidate diff and corrected harness controls separately.

No debugfs/ELF/loader executable, actual image/archive reader, mount, package extraction, installation, GPG, trust mutation, native build, namespace or service actor ran. Tool bytes were freshly hashed only after Root explicitly extended the metadata-only preparation; this is distinguished from execution. The first actual grammar/output/resource trial, later archive/image correspondence, missing tuple/signature closure, issuer authentication, target installation/recovery, Asahi/exact-M2/16K, ABI/hooks and performance remain separate work. There is no automatic source promotion or shared registry write.

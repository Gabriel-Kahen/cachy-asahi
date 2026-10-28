# Platform evidence helper corrections

This successor to the [coordinated Python checkpoint](coordinated-python.md)
corrects three source defects found after its initial review. The original
transaction, authentication, recovery and payload reports remain historical
evidence. Independent checks found no changed findings in the retained links
or mismatches in the retained receipt bytes. The corrections do not adopt,
install or hardware-test the proposed platform set.

`ownership.reference` previously hashed a file, sought back, and let consumers
read the mutable source descriptor. A same-size overwrite between those steps
could supply unpinned bytes. It now captures bounded bytes once, verifies that
capture, closes the source descriptor and yields a seekable memory snapshot.
Later overwrite, truncation or pathname replacement cannot change the consumed
capture. The compressed payload cap remains 300,000,000 bytes per archive;
snapshot storage/copy overhead adds RAM use. Decoded work remains separately
bounded and streamed. JSON, repository catalogs and payload inspection share
the corrected reference helper.

`payload_audit.resolved_link` previously collapsed `..` before expanding prefix
symlinks. For `usr/link → other/deep`, `link/../target` must reach
`usr/other/target`. The component walker now expands observed symlinks first,
preserves unknown baseline ancestors, and reports `ENOTDIR` when an observed
regular file or hardlink is used as a directory, including before `..`, `.`
or a trailing slash. Expansion, cycle and pending-path work bounds remain
explicit. These are inert archive observations, not target filesystem checks.

`authenticate_missing.destination` previously used lexical containment, which
accepted `..` components and could create a directory outside its permitted
subtree. Its correction validates canonical containment, absence and parent
identity before creation. Regression fixtures use disposable temporary roots.
No archive downloads or signature checks are repeated for this source fix.

The original strict checkpoint contains the old ownership source hashes.
Future coordinated proposals can bind those exact historical bytes through
`strict_source_snapshots`, while recording the current helper hashes separately.
Unknown names, wrong original pins and oversized snapshots are refused.
Snapshots are validated as data and never executed. The original checkpoint,
its strict Python refusal and the original 77-test source pins are preserved;
the current ownership files have deliberately changed.

All seven follow-up helper modules passed **159 tests, no skips**, including
20 new regressions; syntax checks passed. Independent bounded source review
closed the three counterexamples and reviewed the historical-source binding.
The actual strict inputs validated with both retained snapshots: 261 image
packages, 201 protected versions, 45 roots and four provider constraints.
Transaction preparation, downloads and cryptographic verification were not
repeated in this corrective pass.

The refreshed ownership audit covers all 624 package file lists with zero
declared overlap candidates. The corrected payload audit consumed the same
406 archives through the verified snapshots. Its complete payload nodes,
controls, link results and unavailable-package set equal the historical report:
2,534 observed symlink targets, 26 same-archive regular hardlinks, zero observed
non-directory overlaps and 218 unavailable baseline archives. Its exit code is
still 1 because those baseline archives are unavailable. None of these findings
establishes installed payload identity or actual target filesystem resolution.

The successor [observation](../../scripts/platform/platform-source-corrections-observation.json)
records current hashes, actual regression results, independent review and
hash-bound refreshed offline reports. The [private checkpoint](../../artifacts/platform/platform-source-corrections-20261012/checkpoint.json)
binds the complete held source/test map for coordinator integration. Remaining
baseline payloads, runtime ABI, hook execution/order, trust custody, full
recovery retention, both M2 Air sizes and maintained-release gates remain open.

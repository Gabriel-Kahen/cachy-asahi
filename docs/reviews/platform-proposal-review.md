# Platform proposal independent review

Reviewed 2026-10-12. The original strict 55-target transaction remains **FAIL**. The separately prepared Python 3.14.7-1 → 3.14.8-1 alternative is **unadopted metadata preparation**, not an installed or accepted platform. No package, hook, scriptlet, target interpreter, firmware converter, network request or system workload was executed by this review. The roadmap, development package inventory and the three platform/Python workstream reports were read first.

## Reviewed historical checkpoint and data

Initial held checkpoint: `artifacts/platform/coordinated-python-20261012-inputs/held-source-checkpoint.json`, SHA256 `073c32fa3e3fda21cc5ce8353c8fb782826dc4ef48905e78a9198c5df550c7d5`. Its fourteen source/test hashes and Python compatibility document pin matched at the initial check. Original ten-file/77-test checkpoint and eight-file/70-test checkpoint hashes matched their retained sources/documents. Subsequent source corrections must be independently frozen and reviewed; they do not rewrite these historical receipts.

Independently rehashed **785 distinct absolute path/size/SHA256 reference bindings**, totaling 808,293,230 referenced bytes, across the held checkpoint and directly referenced JSON documents. All matched. This count concerns reference bindings, including repeated files under distinct references; it is not a disk-footprint measurement or a proof of authenticated image contents.

| Retained receipt | SHA256 |
| --- | --- |
| Original strict transaction | `b485e1bcbb2a1412159e9fdf774622e44db480a35c1919e36d7ee229ae8e8647` |
| Unadopted coordinated transaction | `bdf171c691f88340079d9632b801190d7866d06e3822c5cb83c7086245a8a030` |
| 151 candidate archive authentication | `4e92a950bccbf37002c964391c57da453bbc9c3bc1211b5134e5a69a79bbd6ee` |
| First recovery attempt, failed | `466b55f797bef649079172cf9b550b550f5dc104ba6c97dc856918b3391156c4` |
| Recovery resume, 16 complete | `186c12034720734d0bcc9274b95bcf44e91b08e045f50098fe8147c7ad26ae46` |
| Payload report c | `3228744a94b9409e8465acbf946f1bd0d286f11b90517cb9a769181569a51ac7` |
| Hook/scriptlet observation | `ebb0658e21d73a3599aa93879139ee27fe78ce7b70e0cd49ca4da4a785c8c6c6` |
| Python compatibility capture c | `70df91bc90d6591910311009038847290eb13413753ef31ac599391664b4b648` |

The strict result contains 55 requested targets, 54 satisfied and all 201 protected versions preserved. Python is the explicit rejected root. The separate alternative contains all 55 satisfied targets, 624 tentative final packages, 3,197 dependency witnesses and zero recorded package conflicts. Independent version-map comparison finds exactly one strict-to-alternative delta: Python. The other 200 protected versions remain unchanged. These are actual private libalpm metadata preparations; neither committed a transaction. The source allowlist excludes commit, download, repository-update and system-upgrade APIs, and sets private roots/databases/cache/GPG/hooks/logs with dependencies and conflicts enabled.

The 151 candidate authentication rows have zero failures: 148 recorded ALARM signatures and three community signatures. Independently checked retained bytes and strict recorded GPG status semantics: zero exit, ordinary exit reason, one valid signature, no error/expired/revoked status, strong digest and expected primary fingerprint. This review did **not** rerun cryptographic verification. Actual archive/signature retention is 364,535,409 bytes. The recovery resume retains all sixteen old exact versions and 31,800,492 bytes: fifteen fresh verification observations plus one explicitly reused/rehashed/reinspected row. The first attempt's fifteen HTTP 429 failures remain present, with their original failed receipt. Recovery hashes are post-download observations from exact operator listing links, not historical prepins or proof that image payloads equal those archives.

## Payload, ownership and compatibility bounds

The final payload receipt contains 406 successful archive inspections: 366 exact candidate metadata pins and 40 matching baseline identities whose image payload correspondence remains unverified. Its actual read counters are 84,371 nodes and 3,512,166,400 decoded bytes. All inspected file lists match declarations; observed non-directory overlaps are zero. **218 baseline archives/payloads remain unavailable.** Those gaps prevent complete installed-tree collision, link, source/license and recovery acceptance.

There are 2,534 symlinks classified as observed targets and 26 same-archive regular hardlinks. An independent component-by-component data resolver found no discrepancy in those 2,534 retained symlink observations and no observed regular-file ancestor fault. That recheck does not substitute for target filesystem resolution or validate unknown baseline payloads. ELF/header/program-alignment observations do not establish dynamic loading, general desktop ABI or 16K runtime compatibility. MTREE, xattrs and installation semantics remain outside this helper's acceptance scope.

All 41 retained hook text hashes and fifteen transaction scriptlet text hashes match. Nineteen archive-derived hooks additionally match inspected payload nodes; remaining hook text is retained image data. No trigger ordering, scriptlet effect or service transition was exercised. Static text shows PipeWire/WirePlumber global user-unit enable/disable operations, and Bluetooth enablement only in the desktop metapackage's `post_upgrade`. A fresh-install service policy still needs explicit testing. Unchanged firmware updater/extractor scriptlets are outside the prepared add/change set.

The Python audit supports a narrowly scoped compatibility trial: thirteen extractor source-module correspondences, unchanged cache magic, matched ABI/build declarations, seven source-directory sysconfig differences and 57 required Expat symbols supplied by the inspected old library. These do not prove runtime imports, XML behavior, compiler-binary identity, ctypes/native FFI, firmware output equality or privileged ESP updates. Nine newly selected direct Python consumers also require validation. Package LICENSE declarations and retained notices are evidence, not complete source/distribution grants. ALARM database authentication, independent certificate-owner custody and full image authentication remain unaccepted.

## Confirmed source findings at the initial hold

Focused existing tests ran **139 tests, zero failures/errors/skips**, with a tripwire preventing unmocked network access: transaction 26, ownership 27, archive coverage 17, authenticator 14, coordinated Python 17, payload 17 and recovery 21. Additional temporary-fixture schedules found three defects despite that suite passing:

1. **PLATFORM-PIN-1 — verified input stream can consume unpinned bytes.** Initial `ownership.py` SHA256 `2f902f3b72df0721ddf9135969c5902ece4e88b19746ecb1a39456fb8e436667`, `reference` lines 49–59, hashes an opened file, seeks back and yields the mutable stream without checking the consumed snapshot. A real same-size overwrite after verification changed the consumed JSON from pinned `{"v":1}` to `{"v":2}` without refusal. `json_reference`, metadata catalog reads and payload inspection inherit this boundary. Hash and parse an immutable bounded snapshot, or establish and verify that the returned results consumed exactly the hashed bytes. Retained files currently match their pins; no historical tampering was observed.
2. **PLATFORM-LINK-1 — lexical normalization precedes symlink expansion.** Initial `payload_audit.py` SHA256 `81429bded6010438e71ddf78c39b3803f5318c26101132eb1f4193505fe96d8d` returned `usr/target` for `usr/link → other/deep` and `usr/start → link/../target`; real temporary filesystem resolution returns `usr/other/target`. It also reported an observed target for `file/child` under an observed regular-file ancestor. Resolve components in filesystem order, reject known non-directory ancestors and retain unknown-ancestor limits. No such discrepancy was found in the historical 406-archive report.
3. **PLATFORM-OUT-1 — private authenticator output can escape its declared tree.** Initial `authenticate_missing.py` SHA256 `619f9e9dab73b8def6f90b22ec4842bc58231a198318b93c5a84c52fa5e5d1b9`, `destination` lines 141–149, checks lexical `relative_to` without rejecting `..`. A temporary root accepted `source/artifacts/platform/../../../outside` and created its directory outside the source/artifact boundary. Require canonical containment before creation, with traversal, symlink and existing-output regressions. The recovery helper already rejects `..`; this reproducer changed only disposable temporary files.

Historical checkpoints must remain labeled with their actual source. In particular, the initial coordinated Python implementation requires all prior70 source hashes to match current files: changing `ownership.py` requires explicit historical-source authority reconciliation rather than claiming the old checkpoint stayed unchanged.

## Correction recheck and final pinning boundary

All three exact independent counterexamples now close on the corrected code: the verified snapshot still returns pinned `v=1` after a real same-size overwrite; symlink/`..` resolution returns `usr/other/target`; a known regular ancestor returns `ENOTDIR`; and traversal output is refused before directory creation. The corrected `reference` consumes exactly the bytes it hashed from a bounded in-memory snapshot, with a caller limit of at most 300,000,000 compressed archive bytes. It does not reuse a mutable pathname stream during parsing.

The complete focused suite independently ran **159 tests, zero failures/errors/skips**, with unmocked network forbidden and all fourteen source/test hashes identical before and after execution. The owner's `platform-source-corrections-20261012/regression-tests.json`, SHA256 `d3b29d18ac4426cc6d459aa4530d23684acc2c4376cd46e7fa17c36efa75667d`, records the same current map. The four corrected helper hashes reviewed are:

| Helper | SHA256 |
| --- | --- |
| `ownership.py` | `aed58a9548ca5fbd440f6f28843e2b37b5481a4dba14c8241e953ea4ff1a725e` |
| `payload_audit.py` | `07dbd012913490e3a7e1360a50adb115ee6e01cb7d356501e5c9c67c82bb540c` |
| `authenticate_missing.py` | `28d7d4e007b9d856733eb64e250f8c24ecfedf409ce4c0b0221329e443e1f1fa` |
| `coordinated_python.py` | `48128d92373c84f6d72b3a323cbd39fe7e295c8ae5307816d5d9f7906055610d` |

The corrected ownership report SHA256 is `963c6b73e71d7ea41b4cf45bcef67e7df02ad0557f2142a84252133afad9590e`. The repeated corrected payload report SHA256 is `1b47237b65e73754b524be19aff929b65ab348217d6696cab247fa73cd68607f`; independent comparison finds its complete package/node/control records, links, unknown-package set, overlap list, read counters and counts identical to historical report c. This is a repeated inert data audit, not installation or ABI validation.

Corrected strict-history validation SHA256 is `5fa2f1207e9bec11a705038914cbdc168ca938c34c0658205acac16bd29cfa7b`. Independently reran only its read-only validation with prepare, ALPM audit and code compilation forbidden: original strict FAIL, 261 image packages, 201 protected entries and 45 roots remain. Explicit retained original `ownership.py` and its test snapshot supply old prior70 authority; eight historical source/document snapshots were separately rehashed. Snapshot source was not imported or executed, and the original strict receipts were not rewritten. Full transaction preparation under the corrected coordinated helper was not repeated by this review.

At the initial review, final packet source signoff was withheld until corrected pinning was held. The original held-source checkpoint `073c32…` and final platform packet `2b629913d2b956f167ce8383ca446f6cf2cb295a33708f01a9e1c7d9b6f46ebe` pin the preceding source bytes; their old unchanged-prior70 claims remain historical. This review accepts no moving source or stale final packet on the strength of passing tests.

## Final held checkpoint closure

The authoritative corrected hold is now `artifacts/platform/platform-source-corrections-20261012/checkpoint.json`, SHA256 **`5ee5932a1a994bb894962eea6911bcca184528d51eea126067e282a85e449e65`**. Independently rehashed its fourteen current source/test files and fourteen retained current-source snapshots. The map exactly matches the stable source bytes used by this review's completed 159-test run and the corresponding fourteen-pin subset of the owner's hash-bound regression receipt. That receipt's four additional historical capture/tuple source/test pins also match current files; their old tests were not repeated. No new source drift appeared, so broad tests and the 785-reference data pass were not repeated.

Eight small checkpoint references to current documents/observations, current snapshot metadata and retained historical checkpoint/document/observation were independently rehashed. Current public pointers identify this corrected source authority, explicitly mark prior70 current-source unchanged as false, and preserve the original history as separate, unrewritten evidence. The coordinated workstream labels its earlier unchanged-source statements as historical. The original77 source pins remain unchanged. The refreshed ownership/payload/history receipt fingerprints equal those already independently reviewed; strict55 FAIL, unadopted55 metadata PASS, 151 candidate/16 recovery authentication and 406 inspected/218 unavailable payload counts remain intact.

Reconciled current authority references are:

| File | SHA256 |
| --- | --- |
| `scripts/platform/coordinated-python-observation.json` | `2465f77fc845805c9e21a3d0cf11d6137fe7a593a4ba48eaeea984beb652766d` |
| `scripts/platform/platform-source-corrections-observation.json` | `2de23b52d907680f4d4a03f3670fdcf1fcfe897369130ffe52951b5fbdba6525` |
| `docs/workstreams/coordinated-python.md` | `ea466e0752c052e1f1ea6cca5765cb49f3f6a96ff1a4a6e9c01be0d03b9cb459` |
| `docs/workstreams/platform-source-corrections.md` | `08b1c48c538c6a1b8584cc5e0b7157e60ed00243755d35d41990fd0d621675e7` |

**PASS for this held source/data-review scope:** all three defects and the final source-authority publication gate are closed for the exact corrected checkpoint above. There is no remaining actionable finding within this review's bounded scope. This permits coordinator integration of the reviewed helpers, tests and observations; it does not adopt the platform proposal or establish runtime, installation or hardware acceptance.

The unadopted proposal, complete installation/recovery, firmware behavior, both M2 Air sizes, platform update/boot recovery and full-port/runtime/performance acceptance remain open. The strict failure is preserved.

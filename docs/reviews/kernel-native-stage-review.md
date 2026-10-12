# Independent kernel native-stage review

**Corrected source review PASS, pending coordinator rebind.** The focused closure below independently closes the uncertain/recovered-image cleanup defects and complete Image/vmlinux byte-correspondence gap. The earlier findings and checkpoint evidence are retained as historical records. Proposed 24-file map `53d5c0dba0102413256552da3534b553ce5591ceaa747980e579d4fa1359bc5d` matches current source; the old tracked lock remains deliberately stale. No native kernel compilation, kernel execution, Docker mutation, host installation, Asahi/M2/16K hardware or performance result is established here.

Read the current roadmap, outline, inventory, `docs/workstreams/kernel-candidates.md`, `kernel-native-stage.md` and prior `kernel-candidate-review.md`. All R1–R5 requirements remain mandatory; this experiment preserves the working platform stack and installs no kernel. Only this review document was edited.

## Exact reviewed source and tests

| Held input | SHA-256 |
| --- | --- |
| 24-file `kernel-native-stage/stage.lock.json` | `5c4ff86d87779dab5f47ece6cfab64780ba3210b2d552f34e1f49f137c2c4e32` |
| `kernel-candidates/verify_build.py` | `2a6feed4759348f1555069cdb5538014c87ef7ee82b4796d4245c75e234520e6` |
| `kernel-native-stage/stage.py` | `708116b803012f64651e6d1183e3055aa93df3134b4bb3a86bcb52e24e1ae13e` |
| `kernel-native-stage/image.py` | `df0f95c7e769e1b05e3af5b428dd8cf63d3f34a9f44fa030598afad0bcd060e2` |

Independently compared all 24 actual source hashes/modes with the lock and the closure derived by `source_files`; no drift. Candidate suite: **57 PASS, zero skips**, 0.237 seconds. Native-stage suite: **74 PASS, zero skips**, 1.479 seconds. The latter's ephemeral Unix-socket/fake-daemon fixtures ran with access to their owned temporary sockets. Those suites provide local source/synthetic/user-space fixture evidence, not native kernel or real Docker execution. Test counts refer to separate suites and are not hardware results.

Independent additional reproductions are in `/tmp/kernel-stage-independent-review.py`, using temporary files and mocked command/API observations only.

## KERNEL-PRE-1 and KERNEL-OUT-1 closure

Builder preflight now authenticates and parses one descriptor-captured byte snapshot. Replacing the on-disk receipt during JSON parsing leaves the parsed object equal to the previously authenticated UNREVIEWED/quota-false bytes; it cannot combine reviewed metadata with the other bytes' digest. Duplicate JSON and symlink inputs refuse. This closes the prior separate parse/hash schedule.

The output verifier now validates complete FDT headers/reservations/token structure, bounded tree/strings, unique nodes/properties and pinned J413/J415 root identities. It requires valid AArch64 ELF type/version, section/symbol/relocation geometry, nonoverlapping loads, executable file-backed entry, 16K segment alignment, config-selected EFI Image structure, exact embedded generated configs, consistent release headers, finite actual module inventory, required Apple audio modules, descriptor/export definitions, vermagic and dependencies. Source symlinks must resolve inside the verified source and directory traversal errors refuse. The old eight-byte DTB reproduction now refuses. Existing malformed ELF/FDT/Image/config/module regressions pass; no empty module inventory or arbitrary symbol-file text establishes acceptance.

**Remaining structural scope:** the verifier links Image to vmlinux by the first 64 header bytes, entry and `_text/_end` effective size, plus separately matching embedded config. It does not compare all Image body bytes with the corresponding vmlinux output. Flipping byte 64 of the valid synthetic Image while retaining unchanged vmlinux, headers and embedded config still yields `BUILD_OUTPUT_STRUCTURE_VERIFIED`. This is a concrete missing output-correspondence check; it is not a reproduced runtime/kernel bug. A bounded full Image/vmlinux byte relation would close this limit. Neither structure checking nor such byte correspondence can prove hardware execution or performance.

## KERNEL-CLEAN-1: uncertain commit and recovered image ID

The durable `COMMIT_ATTEMPTED` journal correctly precedes the potentially uncertain API POST, but `image.cleanup` can overstate absence:

1. With `image_id=None` after an uncertain commit, two successful immediate empty tag listings return `status=PASS`, `absence_verified=True`. A daemon commit can finish after those observations. The attempted mutation must remain uncertain FAIL unless a verified immutable image is recovered and disposal/absence is established; immediate empty tag observations do not resolve an unknown asynchronous attempt.
2. When the nonce tag does return a verified derived image, cleanup never persists that recovered ID. It removes only the private tag, checks tag absence, skips immutable-ID checks because the journal still has `image_id=None`, and returns PASS. A data-only fixture using the actual image verifier and Docker tag-removal semantics leaves the same image referenced by another tag while cleanup claims absence. Persist the recovered immutable ID before removal and confirm its absence, or retain explicit uncertainty/failure. Never remove the accepted base or unrelated images, and do not use global pruning/force-removal to hide uncertainty.

Both schedules were reproduced independently and sent promptly to the coordinator. The owner is correcting them; this document records the reviewed held baseline rather than claiming that later source is already closed.

## Positive boundaries and pending actual evidence

The source/patch/config pin closure remains explicit: Asahi `94fb23346d522edf53722357c426a3e58030beea`, source archive `874ef68d04ac8c831b90bb01a387cfabb58fceb60842c49a0d0e58bcd6c146ad`, selected BIO patch `d6564155f9cb9cabc2c281b39c92c8231086a6fce855aa685c9f3709e1f04674`, embedded config `ae1d4ce855bd435b62c8fb213cbcf2d4eefd47b62274792c4a6bf299848b3876`. The harness rechecks the complete source, permits only the selected `block/bio.c` change and applies with zero fuzz/offset. The 15-package authenticated extension preserves the original 341 versions and defines 356 exact rows; newer toolchain metadata and the one explicit Rust lint-probe change are constrained, and pair configs/tools must match. License declarations/notices remain source evidence, not completed distribution approval.

Acquisition has exact 35-item size/hash/HTTPS/redirect rules, fresh private public-only signature checks, a 1,200 MiB byte cap and 1,800-second aggregate deadline with an owned process boundary for blocking HTTP. This review did not repeat downloads or infer hosted acquisition success from retained local reused inputs. The native sequence remains one provisioner, one derived image and fresh nonroot probe/baseline/candidate containers, with the scoped capability profiles and observed cgroup/tmpfs limits. Full builds have fixed `-j2`, explicit tools/targets, finite output/runtime budgets and no install/boot/service target. The historical shell wrapper fails closed without the required source argument; it is not a substitute execution path.

Stage source snapshots bind lock/Git bytes and modes, reuse the unchanged accepted-base validator, and start with authoritative FAIL. Cancellation/failure publication tests show finite status-only projection and stale PASS retirement. Ordinary-user, local daemon/CLI/socket, immutable image, command/mount/nonce and private-journal checks constrain normal launch/removal. Kernel/fixture executables and arbitrary private logs never enter public status. These useful bounds do not close the two image-cleanup schedules above. Actual daemon/API compatibility, provisioning/commit/disposal, native tools, both full builds and all subsequent hardware/runtime/recovery measurements remain pending; a userspace extracted-C allocator fixture is not a kernel allocator/concurrency result.


## Corrected hold: independent focused closure (2026-10-12)

Reviewed latest workstream handoff and `artifacts/kernel-native-stage/independent-review/clean-1-20261012/source-delta-final-review.json`. Independently checked every current byte/mode and exact source closure against the proposed 24-file map in `artifacts/kernel-native-stage/handoff-20261012-rebind/stage.lock.json`, and regenerated its canonical JSON in memory **byte-identically**. Only the output verifier, image cleanup and image tests differ from the historical map. Applying this replacement to the tracked lock/Git/native packet remains coordinator-owned; running with the old tracked map must refuse current source drift.

| Corrected held input | SHA-256 | Mode |
| --- | --- | --- |
| Proposed 24-file map | `53d5c0dba0102413256552da3534b553ce5591ceaa747980e579d4fa1359bc5d` | — |
| `kernel-candidates/verify_build.py` | `2813838d6528a61f24c46e334790db4f3a378fe155b9aecc7068850ec3645b91` | 0755 |
| `kernel-candidates/test_verify_build.py` | `27a1988747fc068b8b27c3d92df5638960ca95ddfe1920915a993cc9aa96b4ae` | 0644 |
| `kernel-native-stage/image.py` | `df0f95c7e769e1b05e3af5b428dd8cf63d3f34a9f44fa030598afad0bcd060e2` | 0644 |
| `kernel-native-stage/test_image.py` | `5a8b04be1e785a96a72acd301acc57591d4aa89aa3ca56d95b8ab1b85cdef04a` | 0644 |
| Unchanged `kernel-native-stage/stage.py` | `708116b803012f64651e6d1183e3055aa93df3134b4bb3a86bcb52e24e1ae13e` | 0755 |

**Provenance erratum:** the first table above inadvertently reported corrected image hash `df0f95c7…` for the historical defective checkpoint. The original lock binds the defective image bytes as `34f34a5342527702dcdea9788938255e9ded4983290ecd8924c12e35276a6254`; corrected `df0f95c7…` is the closure reviewed here. The original lock `5c4ff86d…`, defect schedules and historical review text remain preserved. No same-byte defect/closure is claimed.

Independently reran **62 candidate/harness/verifier tests PASS** in 0.263 seconds and **78 native-stage tests PASS** in 1.448 seconds, both zero skips. The first sandbox-native-stage attempt had four transport-policy errors because temporary loopback/Unix socket creation was denied; the approved rerun used only owned local fixture servers. It did not contact Docker or external networks. The adapter suite's three userspace extracted-C tests use the host compiler; they do not compile or execute a kernel or establish native ARM/M2 behavior.

Focused independent reproducer: `/tmp/kernel-stage-closure-independent-review.py`, using actual corrected functions and temporary files/mock daemon observations. It verifies:

- The exact unknown-ID `COMMIT_ATTEMPTED`/empty-tag schedule returns FAIL, `absence_verified=False`, `uncertain_commit=True`, leaves the unknown-ID journal intact and issues no removal. Current tag absence cannot resolve a potentially late asynchronous commit.
- In the exact recovered-tag/alternate-tag schedule, verified immutable ownership is saved as `RECOVERED_FOR_REMOVAL` **before** private-tag deletion. After tag removal the immutable ID is queried, verified and scoped ID removal attempted. The simulated other-tag conflict raises a failure on both initial cleanup and retry; the recovered ID remains journaled, the base is untouched, and no force/global prune appears. Successful owner-suite cleanup requires both tag and ID absence.
- The valid synthetic Image/vmlinux control passes. Flipping Image byte64 with unchanged vmlinux now refuses with `Image body differs from vmlinux allocated section: .text`. The previous parsed/pinned receipt replacement and eight-byte FDT counterexamples remain closed.

`image_relation` implements the exact pinned `-O binary -R .note -R .note.gnu.build-id -R .comment -S` projection: every retained file-backed allocated section maps through one consistent PT_LOAD physical load address, copied ranges cannot overlap, all copied bytes are compared in bounded chunks, inter-section gaps must be zero, and file length/EOF must match. Removed notes/comments and NOBITS/unallocated debug data are excluded; effective kernel memory size may extend beyond file bytes. Retained allocated dynamic string/symbol/relocation data are compared. Independently replayed correspondence verification on the five retained data-only objcopy oracle pairs (normal, shifted LMA, dynstr, rela, dynsym); all passed. This replay inspected supplied synthetic bytes and did not invoke objcopy, a kernel compiler or an executable fixture.

**Disposition:** KERNEL-CLEAN-1 and the reproduced Image body-correspondence gap are closed at these exact bytes; prior PRE and minimal-output gates remain closed. Source is ready for coordinator rebind and a controlled native integration attempt. This establishes structural consistency and cleanup refusal behavior under local fixtures, not compiler/source-semantic attestation, actual daemon disposal, native kernel builds/runtime, physical16K boot, M2 compatibility, recovery, or performance. Same-job disposable execution remains required; standalone recovery acceptance is still absent. No new implementation, source lock, shared metadata, Git or native workload was changed by this reviewer.

## Coordinator source integration

The coordinator independently passes all 62 kernel candidate/harness tests
and 78 native-stage tests with zero skips. It regenerates the complete
24-file source map byte-identically at SHA256
`53d5c0dba0102413256552da3534b553ce5591ceaa747980e579d4fa1359bc5d`
and replaces the stale tracked input lock with those reviewed bytes.
The historical `5c4ff86d…` proposal and its reproduced defects remain
recorded above. Committed Git proof and a separate same-job native execution
are next gates; no kernel compilation, runtime, M2 or performance PASS follows.

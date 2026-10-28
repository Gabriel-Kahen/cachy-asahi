# Local native build-output admission

`scripts/maintenance/build_outputs.py` bridges completed `build_batch.py` results
into a finite local candidate manifest. It reopens the actual package archives,
checks retained inputs and environment records, compares two rebuilds byte for
byte, and writes an immutable digest-named JSON file for release review.
It does not build, install, sign, stage, publish or promote packages. Neither a
candidate nor a retained reviewer/source record grants licensing approval.

## Select completed results

Retain the planner input, both batch directories and their complete successful
build trees. Keep those inputs immutable. Supply a selection JSON with exactly
these fields; all paths below should be absolute:

```json
{
  "schema_version": 1,
  "purpose": "local-build-output-candidate",
  "synthetic": false,
  "input": {"path": "/retained/pre-change.json", "sha256": "INPUT_SHA256"},
  "batches": [
    {
      "id": "first",
      "path": "/retained/first-batch",
      "admission_sha256": "FIRST_ADMISSION_SHA256",
      "state_sha256": "FIRST_STATE_SHA256"
    },
    {
      "id": "second",
      "path": "/retained/second-batch",
      "admission_sha256": "SECOND_ADMISSION_SHA256",
      "state_sha256": "SECOND_STATE_SHA256"
    }
  ],
  "pairs": [{"package": "example", "first": "first", "second": "second"}]
}
```

Replace checksum placeholders with lowercase 64-character SHA-256 values. The
input is the exact finite pre-change document admitted by the existing batch
runner, including `packages`, `sources` and `build_dependencies`. No planner or
provider-selection code executes during output admission. Different batch
configurations may supply the two sides, but both must select the same input
checksum and each pair must use identical effective build inputs.

```sh
python -B scripts/maintenance/build_outputs.py candidate \
  --spec /retained/selection.json --spec-sha256 SELECTION_SHA256 \
  --output /retained/local-candidates
```

The output directory must already exist outside the retained batch trees. The
CLI writes `SHA256.json`, where SHA256 is the digest of the exact canonical JSON
bytes, and prints its path and checksum. Repeating unchanged inputs produces
identical bytes and reuses the checked existing file. Other existing files are
never overwritten. Refusal exits 2 and creates no candidate manifest. Success
exits 0. Temporary report files are local and removed after inspection.

## What admission checks

- The selected admission/state bytes, batch owner token and original input
  checksum agree. A shared advisory lock refuses an active batch runner or
  inherited builder lock. Only `PINNED_OCI_BUILD_PY` production-kind records are
  accepted; fake-builder batch kinds are refused.
- Each batch is `COMPLETE`; every planned package has a configured native task
  and a successful final attempt. Planner holds and cleanup uncertainty refuse
  admission. Every task appears exactly once on one side of a selected pair.
  The limit is 256 packages per batch/candidate and 512 selected batches.
- Successful output trees equal the runner's sealed file maps. Provenance,
  logs, validation, recipe snapshots, generated SRCINFO, toolchain/config files
  and expected/actual package locks are present and unchanged. The archive set
  has exactly the single package supported by the current builder.
- Archive `.PKGINFO` and `.BUILDINFO` match the reviewed recipe, package name,
  full version (including epoch/pkgrel), architecture, dependencies, provides,
  conflicts, replacements, backup declarations and recipe hash. The BUILDINFO
  installed-package inventory matches the exact retained package lock, accepting
  makepkg's version formats with or without the aarch64/any architecture suffix.
- Task image, native mode, source-date epoch, reviewed input map and package-lock
  digest equal build provenance. The entry-script hash equals the admitted
  implementation record. Source ID, recipe hash, source URL/checksum or Git
  commit and runtime/make/check dependency metadata match the planner input.
- The two sides use distinct batch paths and clean container IDs, identical
  recipe/environment/lock/entry-script inputs and identical complete archive
  byte hashes. Different archive bytes refuse admission even when installed
  contents match. Selected packages must also pass the existing file-conflict
  check against one another.

The existing `package_checks.py` inspector reads archives without extracting
members or executing recipes/hooks. Its unsafe-path, duplicate-member, link,
protected-platform, metadata and structural ELF checks remain in force. This
bridge runs it in a child with a 90-second wall timeout, 60-second CPU budget,
1 GiB address-space limit and 16 MiB report-file limit. Compressed input is
limited to 512 MiB; the inspector caps individual uncompressed members at
128 MiB and total member bytes at 512 MiB. Reports exceeding 32,768 members
are refused. General evidence maps have a 65,536-file bound and JSON inputs
have a 16 MiB bound. Filesystem hashing remains synchronous; there is no disk
quota or hard elapsed-time limit on an entire candidate.

## Failure and resumed work

`INCOMPLETE`, `INTERRUPTED`, `NO_WORK`, held, failed, blocked, active and pending
results cannot create candidates. A COMPLETE label cannot hide a non-successful
task. Admission never silently drops a failed package or chooses an older
successful archive. Use the existing batch runner's explicit resume/retry flow.

After a successful retry, the bridge accepts only the latest successful attempt
and keeps previous FAILED/INTERRUPTED attempt records in the manifest. Earlier
failed archives are neither admitted nor required to be valid packages. A
running or repeated-success attempt in the history refuses admission. This
retains the failure history while admitting only the completed rebuild pair.

If a batch includes held baseline/external packages, this bridge refuses the
whole batch. Reconcile its scope through the planner/runner's reviewed contract;
this CLI provides no flag to bypass that completeness requirement.

## Candidate handoff to release tooling

The manifest retains each archive path/name/size/digest, metadata, source row,
recipe-input map, image and image ID, epoch, lock digest, task digest, attempt
history and complete successful output file maps. Its input, selection,
admission, state and inspector implementation digests preserve the selected
context. The archive path and digest can be used as a later release spec's
artifact reference; the retained input/evidence bindings support preparation
of that spec's provenance and native-build evidence records.

This is a new local review format, **not** an automatically accepted `release.py`
spec. Existing release staging, dependency/conflict checks, signed trust,
source-delivery associations and promotion gates remain unchanged. Preparation
must supply the actual release-defined base transaction, source commit,
license/notices/source materials, retrievable inputs, policy and reviews; it
must not fabricate these fields from build success. `source_delivery.py`
validates declared source associations; it does not confer legal permission.

The manifest always records `authenticated=false`, `full_overlay_accepted=false`,
`dependency_solution=NOT_ESTABLISHED`, `source_delivery=NOT_CHECKED`,
`licensing_approval=NOT_ESTABLISHED`, and installation/hardware `NOT RUN`.
`batch_task_coverage=COMPLETE` describes only the explicitly selected rebuild
work. It does not establish the full overlay/dependency closure or M5 release
acceptance. Distinct recorded container IDs do not authenticate execution or
prove independent machines. The `synthetic` flag is an operator declaration,
not an authenticity detector; test fixtures must set it true.

## Host validation and retained-archive replay

```sh
python -B scripts/maintenance/test_build_outputs.py
python -B scripts/maintenance/test_build_outputs.py --exercise /new/synthetic-replay
python -B scripts/maintenance/build_outputs.py inspect-build --build /retained/build
```

The suite uses deterministic synthetic package archives and batch envelopes.
It covers positive CLI admission/content addressing, byte and input mismatch,
metadata/source/lock correspondence, corruption/missing/extra archives,
duplicate paths/members/tasks, partial batches, resumed failures, active locks
and symlink refusal. The optional exercise retains a clearly synthetic complete
pair and its candidate for inspection; it does not run makepkg, OCI or ARM code.

`inspect-build` replays one existing complete build tree without constructing a
batch envelope or candidate. During implementation it passed on both retained
`cachy-asahi-fish-config-0.1.0-1-any.pkg.tar.xz` builds from run 38526888627:
archive SHA-256
`38e766158d13a0e13b8f811766119d10c018ccc256f5d99c3561b74c99d12705`.
Those archives are genuine retained package outputs, distinct from the suite's
synthetic fixtures. Their recorded execution mode is native; this host replay
is not a new native execution or authentication of that recorded claim. No
production batch candidate was created from that historical pair because it
has no `build_batch.py` batch records.

**NOT RUN here:** fresh native rebuilds, actual completed-production-batch
candidate admission, signed staging/promotion, installation, physical M2 or
performance validation. No manifest or workflow changes are required.

# Setup and native CI independent source review

October 11, 2026. Read outline sections 8/11, the orchestration and acceptance
records, setup implementation/contract/tests, setup package, native workflow,
CI implementation/tests, frozen input/recipe data and native workstream reports.
Only this review file is owned by the reviewer. No implementation, manifests,
Git state, real user home, host packages/services, or external systems changed.

Reviewed initial canonical helper SHA-256:
`c7d4b9b93241c112af7b620a01eed55b1946232f4075f7cd52bd0ff532666f07`.
The package copy matched that byte hash. Initial native driver SHA-256:
`302db24e8d6c8fff3b6e99171b54204e087c6a4ca861483d7509a2ad82f74141`.
Sources were still being finished; missing in-progress files were not findings.

## Reproduced setup findings

### S1 — P2: Pending shell source is not bound to the recorded template root

`Setup.validate_journal()` checks that the journal's `template_root` matches the
invocation and that each block is canonical for its own recorded `source_root`.
It does not require a new shell block's `source_root` to match that trusted
transaction/invocation root. `replay()` applies shell append/splice text without
calling the selected template reader again.

Temporary reproduction:

1. Created a temporary home and distinct approved/unapproved fixture template
   directories, each with harmless files. Neither directory was a real system
   or user configuration location.
2. Activated Fish through `Setup.run()` but injected an exception immediately
   before its first configuration write. This left the actual helper-generated
   private pending journal.
3. Kept the journal's original `template_root`. Changed the entry's new record
   to the unapproved root and its canonical guarded block; changed `change.new`,
   the expected after hash, and corresponding new-state record consistently.
4. Called the same engine's recovery with the original approved root.

Actual result:

```text
journal template root: <temporary approved root>
new guarded source root: <different temporary unapproved root>
recovery mode: applied
recovered_transaction: true
installed Fish block references the unapproved root: true
```

This is inconsistent private-journal acceptance, not a claimed cross-user
privilege escalation: a user able to rewrite their own shell and state can
already execute their own code. The material issue is that the advertised
source-binding/tampered-journal validation does not reject this inconsistent
transaction. No fixture shell source was executed.

Fix: require every new append/update shell record to use the transaction's
template root, while permitting an old record to describe a previous explicit
root for legitimate migration/removal. Add a coherent canonical-root substitution
regression, not only a noncanonical arbitrary-block regression. Repackage and
refreeze the canonical byte hash after correction.

### S2 — P2: Setup creates configuration beyond its own manageable size limit

The helper accepts configuration up to `MAX_BYTES` on reads but does not check
the size of the proposed append/splice output before writing it. This can report
successful activation while creating a file that all subsequent helper reads
reject, blocking removal and repeated setup.

Temporary reproduction: created a singly linked private Fish config containing
exactly 2,097,152 UTF-8 bytes, then activated Fish through `Setup.run()`.

```text
input bytes: 2097152
output bytes: 2097409
activation status: add
subsequent remove: File permissions/size are unsafe
```

The journal had already been removed after the successful activation; there was
no pending transaction to resolve this newly unsupported configuration. Existing
bytes were not lost, but the shipped remove workflow could not manage its result.

Fix: reject oversized proposed results during planning/preparation before any
configuration change, and enforce the same bound defensively in the write
primitive. Cover both ordinary activation and coherent pending recovery at the
size boundary; preserve original files and an unresolved journal on refusal.

Both findings were sent immediately to the coordinator for the setup owner.
They remain open until independently rerun against the corrected canonical
source and synchronized package.

## Setup observations and actual local checks

- Independently ran all 31 temporary-user setup tests: passed. These include
  existing-file/edit preservation, interrupted replay, shell quoting, template
  changes, locking, no external process execution, unsafe paths/files and
  no user-content leakage. The reproduced cases above were additional checks.
- The CLI defaults to preview, rejects root, requires explicit activation
  components, and ignores real XDG/ZDOTDIR values with explicit fixture `--home`.
  Review/test invocations used only temporary homes; no runtime command targeted
  the reviewer's real home.
- Retained directory descriptors, `O_NOFOLLOW`, regular-file ownership/link
  checks, private state, checksums and atomic no-clobber creation constrain the
  observed write paths. No other concrete user-edit overwrite or real-home/
  external-system operation was reproduced.
- The implementation documents its cooperative-lock and editor-race limit,
  interrupted-user-edit refusal, private leftover temporary files, and absence
  of session/package operations. Those acknowledged limits do not certify
  power-loss or target-filesystem durability.

## Native CI source review

No concrete material native trust/bootstrap/evidence-gate bug was reproduced in
this review. This is independent source and bounded synthetic checking, not a
new authentication run or proof that the native workflow executes successfully.

Observed bindings:

- The manual-only workflow fixes `ubuntu-24.04-arm`, guards the named public
  repository, pins checkout by full commit, uses read-only contents permission,
  disables persisted checkout credentials, serializes jobs and sets a timeout.
  There is no release/signing/upload job or QEMU/binfmt setup.
- Audit/build require the caller-reviewed input-lock hash. Builds additionally
  require the complete four-recipe lock hash and exact current recipe-input maps.
  The loader hashes and parses one captured byte buffer, preventing a separate
  hash/read race.
- The input lock contains a dated official rootfs, three byte-pinned keyring
  files at a full upstream commit, 165 rootfs package records and 248 original
  xz package/signature pairs. Package architecture fields are `aarch64` or `any`.
  URLs, sizes, payload/signature hashes, exact versions and dependency/relation/
  license fields are recorded. Individual package signatures, rather than
  unsigned repository database metadata, anchor payload authentication.
- Cached/downloaded bytes are size/hash checked. Signature checks require one
  complete `VALIDSIG` with the pinned primary identity and reject explicit
  bad/expired/revoked/missing-signature statuses. Signed package metadata and
  rootfs inventory are matched to the lock. Docker-context copies are rehashed
  before execution.
- Scratch bootstrap is confined to the disposable image, uses offline required
  signature policy, disables scriptlets and masks recorded ALPM hooks with
  `/dev/null` overrides. Host package installation, service/kernel loading and
  real platform installation are outside the code path.
- Native build requires observed Linux ARM host and ARM Docker server, non-root
  coordination and the default local UNIX Docker endpoint. The resulting image
  is pinned by immutable ID and checked against the expected package inventory.
  All four recipes use the existing build validator twice, with byte comparison
  required; failures do not become a skipped-package success.
- Probe/audit records leave native builds and hardware validation `NOT RUN`.
  Only completed build/comparison execution can set native build `PASS`.
  Hardware validation remains separate. Evidence bundling excludes bootstrap
  contexts and GPG homes and has explicit size bounds.

Independently ran all 37 native CI tests: passed. Reviewed their fixture paths
and mocks before execution; they performed no real downloads, Docker execution,
package installation or workflow dispatch.

## Integration state and remaining gates

At inspection, all four recipes passed static checks; three frozen input maps
matched current files. The setup recipe map differed because finishing work had
added `evidence/packaged-cli-smoke.json`, `evidence/recipe-check.json` and
`runtime-dependency-observation.json`, and changed `host-validation.json`.
The native preflight rejects this drift as intended. This is an expected final
integration/refreeze task, not a trust bypass or missing-file finding. The
coordinator was informed; refreeze after source fixes and final package sync.

The CI owner reports a prior real x86 data-authentication audit. This review did
not rerun that audit or independently download/authenticate those 249 payloads.
No package/image/rootfs download, runner probe, workflow dispatch, host mutation,
physical ARM execution or M2 validation was performed by this reviewer.

Even a successful future native hosted-ARM build cannot satisfy M2/16K-page,
platform stack, target install/remove, independent onboarding, public trust,
boot/session recovery, performance/power or ongoing-maintenance requirements.
The acceptance matrix and outline retain those execution gates.

## Independent setup fix validation

Rechecked on October 11, 2026 against corrected canonical SHA-256
`a6251142b9c7e54796285c1a301fb590599d8aaa1625ea0bfebd7fc21622fdc2`.
The hash-matched source is `scripts/setup/setup.py`; the suggested renamed path
`scripts/setup/cachy-asahi-setup.py` was not present at inspection. Tests import
the existing path. The packaged `cachy-asahi-setup` copy matched the corrected
canonical hash byte-for-byte.

**S1 and S2 are resolved for the independently rerun original cases.** This
supersedes their earlier open status. No remaining material issue was reproduced
in these fix checks.

Repeated S1's exact coherent journal substitution with separate temporary
approved/unapproved template roots and the original approved invocation root:

```text
recovery rejected:
  Pending shell record differs from the approved template root
target created: false
pending journal retained byte-for-byte: true
```

Source inspection confirms newly introduced/changed shell records must use the
transaction's approved root, while unchanged previously approved records may
retain their old root. Each pending addition/update is also checked directly;
the old-root exception cannot authorize a changed entry. This preserves the
legitimate explicit root-switch/removal contract.

Repeated S2 with the original exactly 2,097,152-byte Fish configuration:

```text
activation rejected:
  Proposed configuration exceeds size limit; no write performed
original config unchanged: true
resulting size: 2097152
journal created: false
state created: false
```

The corrected code checks proposed sizes during planning, before replay writes,
and defensively before the atomic writer creates directories or temporary files.
It no longer creates the oversized, subsequently unmanageable file in the
original reproduction.

Independently ran the expanded temporary-user suite:

```text
PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -s scripts/setup -p 'test_*.py' -q
Ran 40 tests ... OK
```

The additional tests include coherent root substitution, an unapproved pending
record without an entry, legitimate partial root migration, exact post-delta size
removability, oversize planning/preparation/writer refusal, and copied-template
size boundaries. No real-home operation, external command, download, package
installation or workflow dispatch was performed. Final recipe refreeze and
native/target execution remain coordinator-owned gates.

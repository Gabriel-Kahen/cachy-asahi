# Independent native development evidence review — 38259350917

**The actual development run remains FAIL.** The retained initial integration,
ARM correctness, client and KSM records pass their bounded checks; virtual owner
acceptance fails before any captured frames. This review verifies retained bytes,
source predicates and recorded outcomes. It reruns no native build, compiler,
Docker, GPG, guest, installer, PTY or hardware operation. It does not establish
Asahi installation, M2 compatibility, 16K-page execution, production trust,
release readiness or performance gains.

## Execution source and export closure

The execution commit is `0e0ebb96b17041e1eed41f1769f3d19c99584e50`, development
packet `c031a6c8076f3756796c5f8e8712c7a49bd0f2750107c19398de72f9239af99f`,
and initial integration packet
`d4d603146f094c86242eaafbb887042959c510c9bb948579dd749d065dd8fc31`.
The reviewer reconstructs a fresh 211-file snapshot from that exact commit's
ordinary Git blobs, verifying every SHA256 and 0644/0755 mode. It contains
4,169,402 source bytes. Current checkout similarity is not substituted for the
execution commit. Review imports disable Python bytecode writes.

The retained workflow log independently decodes to exactly **33 bundles and
1,623 regular tar members**. All compressed size/hash headers and every decoded
member match the retained archives and decoded trees. The review verifies all
**27 finite export manifests**, **1,180 accepted-file bindings**, no rejected
files, and all **31 terminal summary bundle bindings**. The two summary bundles
contain equal FAIL summaries. The seven separately exported initial controller
status subtrees are verified through their own manifests; their files are not
misrepresented as members of the earlier component manifests.

The retained initial controller summary has all seven stages PASS, no
cancellation, initial exit code zero, and scoped owned-image cleanup PASS with
absence verified and uncertainty false. Both observed and terminal development
summaries retain aggregate FAIL because virtual owner acceptance fails. Publication
of valid evidence does not promote execution.
The lifecycle derivative's intermediate cleanup receipt remains `RETAINED` for
same-job consumers and requires final owned cleanup. The later initial summary's
verified absence records that final scoped cleanup; the earlier receipt is
preserved as written.

## Observed component results

| Component | Retained native/host observation and independent check | Acceptance boundary |
| --- | --- | --- |
| Hosted tests | 363 CI tests and 199 development tests, exact named counts and OK summaries. Exit zero is inferred from the `set -e` workflow continuing; no separate host process receipt exists. | Host source tests. |
| Original native builds | All eight original archives, seven artifact files per attempt, 71 recipe inputs and 222 build-record file bindings are retained. The exact source's full `compare.verify`/`compare` passes all four pairs, reproducing archive bytes, installed members, PKGINFO and BUILDINFO. All 501 acquisition, 249 zero-exit primary-fingerprint VALIDSIG, 248 upstream metadata audits and 341-package inventory records bind their frozen inputs. | Fresh peer byte/metadata verification of recorded native builds; no upstream cache reauthentication or native rerun. |
| Initial source suites | 13 native-container command receipts, all exit zero; 650 tests, zero skips, source-bound log parsers and cleanup PASS. | Coverage overlaps the host suites; do not sum them as independent tests. |
| Upgrade fixtures | Four changed `0.1.1-1 any` archives receive fresh payload, metadata and provenance checks; both retained fixture build-validation records and comparison booleans agree. Deterministic source reconstruction matches all generated input/diff bytes. | Disposable package fixtures, not a supported release. |
| Signer | Eight original archive receipts bind to retained archive bytes, eight 310-byte detached signatures, the original receipt output hash, public certificate and TEST fingerprint/expiry. All recorded full-fingerprint VALIDSIG checks pass. | Ephemeral TEST signing; signatures remain opaque and no new GPG verification is run. |
| Repository | All eleven cases match exact source policies and raw records: four positive install/upgrade/rollback transactions exit zero; seven expected trust/signature rejections exit one and preserve inventory and 19 owned paths. | Generic disposable builder transactions; production trust and stable promotion NOT RUN. |
| Lifecycle | 82 command records and 161 PASS checks; six expected exit-two cases and two intentional interruption exit-75 cases. Eight inventory projections rederive exactly; complete inventory and installed payload/image bindings agree. | Container package/user lifecycle and recorded baseline handoff. |
| Onboarding | SOFTWARE PASS; ten preflight, two software-suite and thirteen journey commands exit zero, including five scripted PTY steps; 59 suite tests. Installed-image, inventory and payload bindings agree with lifecycle. | Scripted contributor journey; raw PTY/compiler output is limited by the export policy. |
| Desktop container | 22 commands exit zero; twenty logs bind directly and two Hyprland SGR projections reproduce the exact source projector/index. Static configuration/syntax checks pass. | The compositor is BLOCKED and unattempted because DRM is excluded; Waybar/Mako runtime and portal/audio/session/acceleration are NOT RUN. |
| ARM-C01 | Source-bound verification covers the recorded 505-command graph, four baseline/LTO builds, 336 cross-decoder checks, 32 strict rejections at exit two, four strict-valid checks, four sample CRC exits one and four sample truncation exits zero marked OBSERVED/NOT CLAIMED. All 79 retained artifacts bind. | Correctness on a 4K native ARM builder; no performance or M2/16K execution acceptance. |
| Client | 37 unique named native test outcomes PASS, zero recorded exits, source pins and worker/container/controller cleanup agree. | Finite client software tests; private raw test logs are unavailable. |
| KSM | Two distinct native build attempts, each exit zero and 36 tests; both archives are byte-identical, with equal members/metadata and reviewed source bindings. Both owned-container absences pass. | Compiling and testing the package does not enable KSM or measure performance on an M2. |
| Virtual | Guest boot with 4K pages and the software GBM probe pass. Ten events record `hyprctl -j configerrors` returning **6 with IPC timeout**; no frames exist. Renderer is llvmpipe, LLVM 23.1.1. All five owned cleanup records and private workspace cleanup report PASS. | Virtual and aggregate FAIL. Exit six is not six configuration errors; no graphics/session/hardware acceptance or failure cause is inferred. |

The repository negatives cover untrusted A, untrusted rotation B, tampered package
signature, tampered database signature, missing package signature, missing
database signature and revoked A. Positives cover trusted baseline install,
trusted rotation upgrade, rollback to retained A and final unrevoked B upgrade.
The missing-database case matches the source's exact selected local
`/scratch/repos/active/integration.db.sig` retrieval classifier, with only the two
database signature aliases omitted from the signed reference. The missing-package
generic trust classifier also matches an earlier stale invalid-signature warning;
the reviewer separately checks the terminal missing selected signature and its
exported omission. The broad regex alone is not case-specific causal proof.

The actual initial runner records Azure `6.17.0-1022-azure`, aarch64, Neoverse-N2,
four CPUs and 4096-byte pages. Original builder packages total 341. Lifecycle
adds the four overlay packages; repository transaction tests also add their
explicit TEST package. These are separate declared inventories.
The four original baseline archive/payload authorities agree across native
builds, signer input rows, repository baseline exports and lifecycle handoff.

## Reconstruction and material limits

Original records remain unchanged. Reviewer-generated byte/path reconstructions
are kept within the review directories and explicitly labelled:

- The eight-row signer input manifest and omitted 128-byte query configuration
  reproduce their original contract/evidence hashes. Detached signatures and
  database bytes receive size/hash checks, not fresh authentication.
- Upgrade fixtures derive from the initial packet's held **recipe source commit**
  `ebd5812640b0b69f5c09a47752b739e37e338754` and recipe lock `20d846…`, while
  execution uses `0e0ebb…`. Substituting the execution pin changes generated setup
  provenance/checksums; the unmatched derivation is retained as a counterexample.
- Lifecycle inventory JSON and two desktop log projections are reconstructed
  from hash-bound logical source/receipt material. They are not additional native
  observations. Lifecycle logs combine decoded stdout, a newline and stderr;
  original raw streams cannot be recovered exactly.
- ARM verification restores four public log aliases to producer names without
  changing their bytes. Eight unretained sample stdout files are reconstructed
  from the independently pinned expected 312-byte gzip payload and match declared
  hashes/sizes. Those expected bytes do not prove original raw sample stdout was
  retained. The 79-member nested artifact bundle is separately verified at
  5,971,903 plain bytes and 2,969,906 compressed bytes, SHA256 `25f53be2…`.
- Onboarding excludes 52 raw stdout/stderr, source and binary files. Command JSON,
  hashes and outcomes remain; raw PTY output and compiler-test binary behavior
  cannot be independently replayed from this export.
- The client lacks raw private logs. KSM's full original comparison environment
  is represented by provenance hashes, so peer archive comparison is explicitly
  reconstructed from the two retained packages. Virtual private inputs, full
  serial output and current live daemon cleanup state are unavailable.
- Original upstream input archives/cache and key material are not reauthenticated
  or independently rehashed here. Their acquisition/audit/signature records are
  retained source-bound observations. All eight project-built original package
  archives and their full build environment files are retained and independently
  parsed; the integration subreview's four-archive limit applies to its separate
  upgrade fixture export, not the whole native bundle.

Unsigned producer records and recorded cleanup observations are not cryptographic
execution attestation or a fresh daemon inspection. Distinct recorded containers
do not prove independently operated machines. No failure cause is assigned to
the virtual IPC timeout. A passing byte/source review does not override required
desktop, supported-hardware, install/update/recovery or maintained-release gates.

## Retained review artifacts

The replay scripts and finite receipts are under
`artifacts/ci/38259350917/peer-review/`:

- `source_snapshot.py` / `source_verification.json`: exact execution Git snapshot.
- `verify_exports.py` / `exports_verification.json`: all log/tar/export/summary bindings.
- `integration/`: fixtures, host/source tests, lifecycle, onboarding and desktop.
- `repository-signer/`: eleven transactions and eight original signer records.
- `arm/`: source-bound 505-command graph and 79 retained artifacts.
- `virtual-client-ksm/`: virtual events/cleanup, native client and KSM packages.
- `initial-native/`: all eight original archives, full comparisons, signed-input
  observations and all seven initial controller/cleanup bindings.

`review_verification.json` binds the final document and these lane receipts.
No shared source, manifest, workflow or acceptance status is edited by these
review lanes. The concurrent FDK bootstrap correction is documented separately
in [its bounded correction record](../workstreams/fdk-bootstrap-schema-correction.md).

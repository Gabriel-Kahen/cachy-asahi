# Kernel daemon baseline preservation: independent final source review

Disposition: **SOURCE REVIEW ACCEPTED**, limited to the nine-file hold below. No material failure was reproduced. Registration and corrected native execution remain pending; this is not kernel build, installation, 16K-page or M2 acceptance.

## Exact reviewed hold

Verified `artifacts/kernel-native-job/baseline-implementation-20261012/checkpoint.json` SHA256 **788f52894e36ef07895b490ba452b5e8afb37609ff592704d49c069a4b1b4eda**, its eight referenced evidence hashes, and all nine source/document bytes, sizes and modes. The held source receipt is `705d1f70c41201bf72a23b412c338deb28edbfb8bb1af60f8fb6761d132748cb`.

| Held file | SHA256 | Mode |
| --- | --- | --- |
| `scripts/port/kernel-native-job/job.py` | `20a476c4f9d28d57578825c6e8125a124831abf347af3d73d7bf739373aa2d4b` | 0755 |
| `scripts/port/kernel-native-job/public.py` | `a1c7db9afdcbab797da8a2121efd18a599408076e7151b1d62b1a5bba48bd4ab` | 0644 |
| `scripts/port/kernel-native-job/test_job.py` | `33ac740ff6dfe51df9bae3edef0a648f30fb712069a9af434264421dec7b86a9` | 0644 |
| `scripts/port/kernel-native-job/test_public.py` | `ed92e3b63b636a980c6831cdb6805b70881361c5208641a52e12adeabb699b41` | 0644 |
| `scripts/port/kernel-native-stage/image.py` | `55f989c33e78b6664c47bbf937cf517bb7adaa78ccc75878379580ab2c2c96fc` | 0644 |
| `scripts/port/kernel-native-stage/test_image.py` | `cd55800cf8bd1b4cb24c647545c26da24f812924c5bbe7a36f789d1fe6a99614` | 0644 |
| `docs/workstreams/kernel-native-job.md` | `5ca29a6b13c1583edfa1f8cb44c76de701b13b7a103a8f2dbee55c5d86d6c64d` | 0644 |
| `docs/workstreams/kernel-native-stage.md` | `f1ee8071cf0cdaac6dd9339ada088c7a6af56a245205fb74fc8a2be10e90927c` | 0644 |
| `docs/workstreams/kernel-daemon-baseline-proposal.md` | `e2401f6893a9dc501f31e8f5a418ac007d7cbc8436795e607a0835175a131e49` | 0644 |

Historical packet `afdb5a4947acf71e511fe1266921d68149561aedb4ec5b030e841112e827d9e2`, kernel24 `e47d873cd1f8ff542ec1ffd3a5de4b51db4d890f28bc6f1dddbc27d989db0d5a`, packet helper `0afe993fa321e08cd1c3de1ebd13e4d708ff9586b31b199a478a5b6f2c31890f` and workflow `40a16f84d2a52f0574b71bb1baffdc6069429b2e27345870795f0351c34d0e4c` remain unchanged. The historical packet has 108 unchanged rows and seven authorized stale candidate rows. Its old hashes deliberately refuse this new source; they are not evidence of completed registration.

## Actual independent validation

Read the current roadmap and package inventory, selected daemon proposal, job/stage guides, all changed production code and relevant tests. Authenticated 14 hashes of the prior independent peer's actual evidence. That review records 186 job tests and 98 selected stage tests passing, seven actual TERM probes, and twelve cleanup-receiver cases. The owner's full stage result records 101 passing tests; the other reviewer explicitly excluded three unchanged host-C fixtures. These results are reported at their actual scopes.

Created a fresh 118-file selected-source copy from authenticated historical packet paths plus the nine candidate paths and packet file. Independently ran **52 focused job/public tests and 25 image tests, all PASS, zero skips**, with `ResourceWarning` treated as an error. Image tests used bounded owned temporary Unix sockets/processes under approved fixture execution; no Docker daemon was contacted. This avoids repeating unchanged full suites while independently replaying the modified paths.

A separate **35-case reviewer matrix passed**. It covers full unknown Config fields and null Config, omitted empty RootFS layers, non-ARM borrowed images, same-ID Config/architecture/OS/parent/digest/tag changes, missing dangling images, invalid metadata types, non-finite numbers, byte/reference limits, ambiguous references, exact own-ID deletion while preserving unrelated new images, public PASS poison fields and all failed/unavailable workflow outcomes. Metadata observations and daemon responses in these checks are controlled fixtures, not observations of a hosted Docker daemon.

Actual TERM regressions independently rerun in the focused suite cover producer receipt acceptance, before-kernel observation, baseline/state-transition boundaries and cleanup handler restoration. They retain bound FAIL diagnostics and prevent kernel execution where acceptance is incomplete. Prior peer evidence also tests final unmask and post-publication process death; a raw PASS is provisional until actual successful job outcome.

Rechecked all copied and live selected bytes/modes after tests: unchanged, no retained PYC. Independently compared eleven function ASTs against historical source `dcc170af543f3238f33efc0c623811d6620affaa`: original producer/acquisition/kernel commands and receivers, ordinary-host guard, execute/finalization/publication and terminal revocation remain unchanged.

## Reviewed safety and acceptance boundaries

Initial container and image inventories are separate positive observations. Query/parse failure remains null or UNVERIFIED; containers must be positively empty. Two bounded captures compare complete immutable-ID populations and full borrowed-image projections before the original producer. Config unknown fields/null, RootFS, size, parent and all references contribute to the protected digest. Limits cover raw rows, combined references, metadata JSON depth/nodes/strings and aggregate bytes.

The fsynced private baseline binds source, packet, run/attempt, nonce, daemon and Docker executable/socket identity. Later observations preserve borrowed B while recording actual total population. Unknown new IDs never become cleanup targets through inventory subtraction. A completed producer's borrowed IID collision refuses ownership; only its accepted new ARM64/Linux IID enters the exact ownership journal. Before-kernel and final preservation are separately observed. An interrupted producer remains UNCERTAIN/FAIL even if later inventories are empty and B is unchanged.

Kernel commit records all preexisting IDs before POST and reserves a fresh nonce tag. Returned or recovered protected IDs refuse removal, including a new private tag attached to a protected image. An uncertain POST with no recovered ID retains FAIL. All three base/derived-tag/derived-ID removal paths explicitly use `--no-prune`, with no force/global prune. Positive base absence, closed source/base/daemon-bound kernel cleanup receipts, empty containers and final B preservation precede aggregate cleanup acceptance. Missing, duplicated, malformed or incomplete cleanup records refuse acceptance.

The schema3 public boundary exposes only finite baseline counts/digests/statuses. Arbitrary private image metadata stays private. Exact integers, closed keys and mutation/cleanup consistency are enforced; failed/cancelled/skipped/unavailable actual outcomes revoke native acceptance. The first observed failure remains immutable. Original resource thresholds, producer/parallel/kernel reserves, absolute execution clock and cleanup envelope are unchanged.

This is cooperative disposable-VM **observed preservation**. It does not prove exclusion of outside writers or absence of Docker build cache/layers; `legacy_build_cache` stays `NOT_ESTABLISHED`. No mutation-prevention or shared-daemon-isolation claim is accepted.

## Coordinator adoption and remaining execution limits

The coordinator must adopt all nine reviewed files, regenerate the kernel24 map with the two changed image rows, refresh the dependent `packet.py` kernel-lock literal, regenerate the complete job packet, and prove committed Git blobs/modes plus authenticated bootstrap/copy closure. The packet's existing document closure and executable source count must remain exact; any added documentation rows require the coordinator's explicit closure change rather than an unreviewed manifest addition. The unchanged workflow's public path executes authenticated public-source bytes, so schema3 does not require weakening the generic bootstrap or outcome checks. Re-run source/packet/bootstrap checks after rebinding; these candidate hashes alone are insufficient to dispatch the corrected source.

Historical run **38253531983** remains a source-stage `DAEMON_OCCUPIED` failure before producer/acquisition/kernel execution. Its receipts do not establish image population, successful inventory queries or preloaded images as the cause. No corrected native Docker run, acquisition, eight original builds, kernel probe/build pair, cleanup/export, kernel runtime, installation, hardware/16K or performance result was produced by this review. No remaining source blocker was reproduced; actual finite native execution is the next evidence gate after registration.

Owned evidence: `artifacts/reviews/kernel-baseline-root-peer-20261012/{capture.json,job-focused-tests.log,image-focused-tests.log,independent-probes.json,final-source-stability.json,review-receipt.json}`. Reproduction scripts and the authenticated source copy are retained there. No source, shared lock/pin, Git, workflow or dispatch changes were made by this reviewer.

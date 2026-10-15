# Maintained574 cleanup component, native ARM — 2026-10-15

[Run 38815189239](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38815189239)
succeeded with all **five metadata-only cleanup cases passing**: normal,
missing CIDfile/name recovery, foreign reference, real token collision and
deliberate probe-handle loss. The retained results reconcile **five successful
metadata builds, six stopped created containers and seven cleanup CLI calls**.
Five cleanup results pass; the foreign-reference and lost-handle first calls
fail as expected before separately recorded successful recovery.

This validates real native Docker cleanup-component behavior for the selected
helper. It does not exercise its full574 build mode, package acquisition,
transaction or inventory process. All recorded probe-process, native574 and
hardware fields remain **NOT_RUN**. No image process was started.

## Frozen source and runner

| Binding | Identity |
| --- | --- |
| Component Source | `9ebf749c1d695cb93ed680e134437bfb946168c7` |
| Workflow Source | `02cfcc0cdd3d7c859770b4e3f8d9211efc70c227` |
| Workflow path | `.github/workflows/native-arm-build.yml` |
| Component SHA-256 | `74cc4f8fe62c27c284caf0a6581e595f8bc1dbcb22e89803e9be234cae17dc83` |
| Optional helper SHA-256 | `ebf62455e25b5471427224c4df9d75c0c1fd3a0f09a1864596171498740d4527` |
| Native guard SHA-256 | `a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898` |
| Existing process utility SHA-256 | `29c854180f55fe14475329601580e0345b50bc5ab365850c04003fa0b051c1a9` |

Retained checkout/verification logs bind the exact Source and show all five
runtime hash checks passing, including the existing evidence transport.
Independent local immutable Git reads reproduce those hashes and both test
hashes. Source changes only helper/test/component/test; workflow changes only
the workflow path. Both are isolated children of `2be7917bcff474d33b92b2838bfb0157c6bdfa67`.
This result does not adopt the optional helper into canonical package callers.

The native guard records Linux/aarch64 host and aarch64 Docker daemon,
Neoverse-N2, UID/GID1001, **4096-byte pages**, default local socket
`unix:///var/run/docker.sock`, and Docker Engine28.0.4 client/server.
The guard's `commit` is the workflow Source; component metadata separately
records the checked-out component Source. This is a hosted ARM runner, not M2
hardware or a 16KiB-page execution test.

## Observed cases and deletion bounds

Every case records actual build return0, a distinct arm64/Linux image ID,
matching unique tag/job label and a real inspected stopped probe CID/name.
The fixed Dockerfile contains only `FROM scratch` and a metadata CMD pointing
at `/component-not-executed`. Real create succeeds without adding a rootfs,
binary or alternate base. Containers remain in `created` state, running=false.

| Case | Retained outcome, reconciled with exact source gates |
| --- | --- |
| normal | Helper cleanup PASS; exact probe name/CID and image/tag absence required. |
| name-recover | Genuine CIDfile deliberately removed after create/inspect; exact name recovery removes the matching probe/image and passes. |
| foreignref | Second stopped fixture-owned container references the image. First helper call removes its probe, fails and preserves image/reference. Fixture verifies and removes only its separately captured reference CID, verifies absence, then helper cleanup passes. |
| collision | Real `owner_begin` against the occupied token in a fresh output refuses; original report bytes and image/probe are preserved, followed by normal cleanup PASS. |
| unknown-handle-loss | Fixture verifies/removes its real stopped probe CID and withholds the genuine CIDfile. First helper result is FAIL/probe UNKNOWN and image is preserved. Restoring the genuine CIDfile permits a separate PASS after CID/name absence checks. |

All five final cleanup records agree with their created probe IDs/names and
image IDs. The six container IDs, five tokens, tags and image IDs are distinct
and reconcile in the retained readout. Six pre-fixture image IDs are listed;
the final record and source gates require every one to remain after each case.
No synthetic baseline rewrite is involved. This does not exercise native
baseline-ID refusal or an independent label-only collision: the real occupied
tag short-circuits that collision check.

## Retention and limits

Root retained `logs.zip` once: **21,633 bytes**, SHA-256
`88361741a549bb295b9a969b12b711e6f872d4c729bda7f6feddfa3bd1fb031b`.
This review decoded only the single public metadata frame from the dedicated
retention-step log, not its aggregate duplicate: **3,587 compressed bytes**,
SHA-256 `f4248d5b507746a473d8583a60f27758f7dea3c09c498b84358ca75dd51b4325`.
Frame hash/size pass; its only regular files are component.json and the native
guard's runner.json, both mode0600. No other frame was decoded.

The [retained-only readout](../../artifacts/development/maintained574-cleanup-component-run38815189239/review/readout.json)
preserves full identities, source bindings, counts and evidence limits.
Preservation checks, create exit0, extra-reference absence and tag absence
are supported by the selected metadata together with the exact successful
source gates. Private raw Docker logs, per-case reports/CIDfiles and query
transcripts were not transported. This review did not reissue daemon queries,
fetch logs, run actors, alter Git or edit canonical code.

Missing-file and handle-loss faults are deliberate fixture operations, not
running-probe interruption or evidence of an unobserved daemon leak. No build
was interrupted; active-build completion/cancellation remains UNKNOWN/FAIL
without a daemon executor fence. Full574 owned-mode integration, installation,
hardware, performance and release acceptance remain open. Accepted historical
LSP/Rust/Zsh/composition caller selections are not replaced by this component.

Following review, the coordinator adopted the four exact helper/component/test
files and updated the same-checkout Zsh caller's helper binding. Its default
build call still omits the ownership token. Frozen LSP/Rust/composition callers
keep their historical selections; the new helper's full574 owned build mode
still needs its own native validation.

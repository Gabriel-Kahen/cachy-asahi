# Frozen Vim input recovery proposal

**The exact four missing inputs are recovered locally; the CI recovery route is proposed, unadopted and unpublished.** All four retained files match the frozen full SHA256 and length, with stable no-follow regular-file identity, one link and owner UID 1000. Read-only copies total **9,790,183 bytes** under `artifacts/reviews/frozen-vim-input-recovery-proposal-20261013/seed/`. Only these four literal names were opened from the private cache; no cache inventory, other user files or private key material was selected.

The retained FDK9 run `38326770829`, source `9ed0efa32d5177f1cc0cf6acf2a3ecea0263e2ec`, records acquisition **501 = 497 PASS + 4 FAIL**, with four HTTP 404s. Signature authentication and FDK are NOT RUN. This proposal does not change those historical results or establish a new crypto, native-build, ARM, M2, 16K or hardware PASS.

## Closed recovery set

| File | Bytes | SHA256 |
| --- | ---: | --- |
| `vim-9.2.1164-2-aarch64.pkg.tar.xz` | 2,086,796 | `d4f857559e5f0af1cd5a9603d31437ddc8fe35957c11bc6b8670b9a58a80ea73` |
| `vim-9.2.1164-2-aarch64.pkg.tar.xz.sig` | 565 | `38e920e436994e6516752f2057974ecd3d284b4be5887a183714175be9169524` |
| `vim-runtime-9.2.1164-2-aarch64.pkg.tar.xz` | 7,702,256 | `def07038ac8bde14c3c875ea2f37adc199e21bb237d357b1b2f00eb401d4add6` |
| `vim-runtime-9.2.1164-2-aarch64.pkg.tar.xz.sig` | 566 | `7481985526069c20b81762bbb308a0df61acf07d316f557d60e330a22627e5e3` |

These are unchanged original inputs. The proposal neither upgrades Vim nor removes it or its signatures. `seed-manifest.json` contains only the closed public file/size/digest/origin map, with endpoint and retention owner unselected and publication false. Its SHA256 is `a805a68d04d931253cca7bb68707711b36f8ec6258270e4c84a825b9f37cb864`. Local mode 0444 files in a mode 0500 directory plus recorded content pins are the hold mechanism; no immutable-inode or protection-from-root claim is made.

Frozen `scripts/ci/inputs.lock.json` remains `3c16c37d1b12cc84a88572e82ab8ad59e7f3b5ed0d08f09ddf72a69f4711d650`: 248 package payloads plus the rootfs make 249 signed payloads; their 249 signatures and three keyring files make 501 acquisition objects. All 133 current source-packet rows, four original recipes / 71 recipe files, original integration lock and protected workflow/source hashes match their held pins. Matching current file bytes is not a current HEAD or new committed-source proof; no Git query or mutation occurred here.

## Package data and provenance

Bounded streaming LZMA/tar inspection reads data without extracting members to the filesystem or running package code. Both `.PKGINFO` records match the frozen name, version, aarch64 architecture, dependency and relationship fields. Vim depends on exact `vim-runtime=9.2.1164-2`, gpm, acl, glibc, libgcrypt and zlib. Runtime has no required dependencies. Both `.BUILDINFO` records declare PKGBUILD SHA256 `febae3b77c5de8c3e4b0e96481cab14fd9f549619e0d2b3671ff1ce63ee2b06c`; this is a package declaration, not authenticated recipe correspondence.

The final archive pass examines 217 Vim and 2,559 runtime members, decodes 48,619,520 bytes and retains 62,790 bytes of selected metadata/notices. Safe member names, link-target checks and finite node/text/decode bounds pass. All observed members have archive UID/GID 0; no special node or setuid/setgid bit appears. The runtime license link's absolute package path resolves to its retained notice within the archive inventory. The Vim documentation hook is retained and unexecuted. These are data observations, not installation or binary correctness tests.

Full selected built notices are retained in `archives/evidence.json`: Vim/license and Uganda notice, runtime LICENSE, EditorConfig BSD-2, netrw 0BSD, and manual attribution. Every original archive and per-file header remains unchanged in the seed. The archive audit does not exhaustively classify all runtime headers or establish actual library linkage.

On 2026-10-13, bounded HEAD probes again find four HTTP 404s at the original CA mirror. GeoIP and NJ return transport errors; their HTTP status and availability remain UNKNOWN. No package/signature body is downloaded. The bounded official mirror references establish rolling/latest synchronization, with no historical-retention guarantee found; other possible mirrors are not ruled out. Current official [Vim](https://archlinuxarm.org/packages/aarch64/vim) and [runtime](https://archlinuxarm.org/packages/aarch64/vim-runtime) metadata advertise another version, which is not substituted.

The official upstream tag v9.2.1164 resolves to commit `6d862f58dd6d51b292dd26ae658b02fb1e691ca5`; its patch list starts at 1164. The immutable [Vim license](https://github.com/vim/vim/blob/6d862f58dd6d51b292dd26ae658b02fb1e691ca5/LICENSE) is held at SHA256 `0b3f1f330cb1b179bb17c7c687d4cec601e0aa3462bc7f890ad4c3888d37d720`. That identifies upstream source/license, not the ALARM `-2` recipe, downstream changes, compile flags or a reproduced binary. Official recipe-reference responses were unsuccessful; exact source correspondence remains UNKNOWN.

## Publication conditions still unresolved

A public byte-preserving mirror is **not cleared by this audit**. The upstream Vim license requires its full text and has additional routes/notice requirements for modified distribution. The built notice also makes GPL-linked distribution conditional on GPL terms and identifies distinct runtime-file licenses. A gpm dependency declaration is not actual linkage proof. Exact upstream/downstream modification correspondence, applicable source/change delivery and any linked-library obligations need closure before public distribution. The full existing notices and required attribution must accompany the distribution; do not publish a repacked binary stripped of its notices.

The manual references OPL 1.0-or-later with Bram Moolenaar, Steve Oualline and New Riders attribution. Its exact [publisher license reference](https://opencontent.org/openpub/) returns 404 in the live bounded lookup. Indexed primary publisher text is retained separately as a reference to general OPL conditions, including attribution, license/reference preservation, modification labeling and optional restrictions; it is not a live full-terms byte capture or proof of elected restrictions for this manual. Those documentation conditions and remaining per-file runtime terms remain unresolved. Detached-signature hashes identify bytes only; no GPG verification, signer authorization or independent key-owner trust is established here. The original producer's crypto gates remain mandatory.

## Smallest CI change

When `target.exists()` is true, `native_arm.fetch` checks its size and SHA256, rejects symlink/invalid targets and returns before network access. That verified-existing branch **does not overwrite or redownload**; it is not a general lexical-link or concurrent-cache race guarantee. Eleven tiny mocked transport/output models pass, including existing valid/invalid targets, missing-file outcomes, seeded/mixed acquisition bookkeeping, and the current fresh-output refusal. Acquisition PASS still leaves signature authentication NOT RUN. These checks do not execute the proposed helper or actual Vim, GPG, image, producer or native actors.

The current producer cache is `<output>/private/cache`. Pre-populating it from the workflow would create `<output>` before the fresh-root gates, and both workflow preflight and `job.output()` refuse. The minimum reviewable change uses a separate source-issued carrier of the four files and an inline controller hook **after complete source verification, before broker/producer launch**:

| Boundary | Exact original source point or proposed path |
| --- | --- |
| Workflow | `.github/workflows/native-arm-fdk.yml`, original SHA256 `056eab73b8b5fe711f15aec7cca495ed54465db16bcac82328b2ca498dd97e4c` |
| Native job controller | `scripts/port/fdk-native-job/job.py`, original SHA256 `39fba50688727b75f11492bf1fbb55a89f782f99a6d30d4f6f6307838dcae67d` |
| Fresh output | `$RUNNER_TEMP/fdk-native-job-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT`; workflow 145–147 / controller 90–96 |
| Separate carrier | Proposed `$RUNNER_TEMP/frozen-vim-seed-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT`, outside and non-overlapping with output |
| Source snapshot | `<output>/private/source`, controller 286–287 |
| Controller insertion | After controller 293 records authenticated native-source SHA; before broker creation 294 and producer launch 309 |
| Producer cache | `<output>/private/cache`; producer 381–383 |
| Existing producer | `scripts/port/fdk-native-job/producer.py`, SHA256 `41c389897da7ee8b5d3fa7f927f9c95db537150d56dd67de927a3bce8ac1d500` |
| Existing native acquisition | `scripts/ci/native_arm.py`, SHA256 `a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898` |
| Existing stage lock | `scripts/port/fdk-native-stage/stage.lock.json`, 44 rows / SHA256 `fbc0b0bbf0f3765729adb9193331b09903ad5b8c99d00871ece79218a8b36483` |
| Existing packet lock | `scripts/port/fdk-native-job/packet.lock.json`, 133 rows / SHA256 `42fd54ae73c57e47898ca9e7b293ca0dae1d4e57ac2836292f0cdf42b79dffcf` |

The source-only helper text and workflow transport sketch are in `pipeline/`. The hook derives its exact whitelist from the authenticated original input lock, checks membership/owner/no-follow identity/full pins, creates a fresh private cache and copies only those four objects under the existing job deadline. It leaves native acquisition, producer source/configuration, original versions, all 249 signature checks, recipe set, stage lock and public exports unchanged. The helper is syntax-inspected proposal text, not runtime-tested or production-admitted; cancellation, failure/disposal and integration controls are required before adoption.

A retrievable carrier needs a selected, reviewed HTTPS endpoint or exact artifact identity, recorded full transport implementation revision, retention owner/policy, and bounded full retrieval of all four objects against the manifest. The transport sketch has no selected URL/artifact/revision or upload command. It proposes a 120-second transport bound inside the existing 150-minute workflow envelope. Copy uses the unchanged controller 7,200-second deadline; producer 3,300 seconds and FDK 3,000 seconds remain unchanged. No cap is renewed. Root must review source-issued selection and disposal for carrier/cache, and resolve publication obligations before choosing a public mirror.

The minimum derived mutation is controller + workflow + packet lock, with meaningful tests in existing `test_job.py`. An inline helper and existing test path can retain 133 source members, but Root must recompute the actual union and every changed row/digest. The workflow is authenticated separately and is not a packet row. Rebind the external packet SHA and committed source/workflow identity before dispatch. Native/source hashes, input lock, recipes and stage lock can remain exact. All sketches live only in the owned artifact; no production source, workflow, manifest, Git or public asset was changed.

## Evidence and remaining work

Root owns this document and `artifacts/reviews/frozen-vim-input-recovery-proposal-20261013/**`. The three independent lanes are frozen. Archive inspection uses CPU 30 seconds, memory 512 MiB, wall 60 seconds, 128 MiB LZMA memory, 128 MiB decoded per archive / 256 MiB combined, at most 10,000 headers and capped texts. Three notice-selector passes total 145,858,560 decoded bytes; no archive member is extracted to disk. Pipeline fixtures use the same CPU/memory/wall caps and 4 MiB file/log cap, with no real transport. Public provenance captures 28 bounded observations / 149,272 bytes of text and 39 inert checks, including 12 HEAD-only probes; transport failures stay unknown.

The exact four held bytes, metadata/license/provenance evidence and source-only route are ready for review. Carrier publication/selection, license/source closure, helper implementation/tests, derived source/packet/workflow rebind and an actual authorized CI run remain unfinished. The 497 other acquisition successes are historical facts, not guaranteed future retention. M5 requires release-wide retrievable frozen inputs and accountable retention; this narrow four-file repair does not complete M5 or full R1–R5/M5–M9.

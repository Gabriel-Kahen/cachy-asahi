# FDK canonical selected tar source review — 2026-10-12

Disposition: **held correction source/data accepted for coordinator adoption; no confirmed blocker.** Shared pins and native retry remain pending. Compiler, makepkg, upstream codec execution, Docker, installation and publication were not run. The historical native FDK source failure remains FAIL, with its exact first hosted predicate UNPROVEN.

## Exact source hold

Checkpoint `artifacts/fdk-canonical-selected-tar-20261012/checkpoint.json` SHA-256 `eeacdd5275e216c525593c19ac4206b27a42777e2304982aa503a5e7a4b6e004` matches all 12 held primary files and all 44 recorded evidence files by actual bytes, size and mode. Workstream `docs/workstreams/fdk-canonical-selected-tar.md` matches `2f6b9f4eb4aa35b99febad6f99e4e4b7856f597ed57042fa15295d0284410044`. A fresh private external template copy contains no PYC/cache files. Primary held bytes remain unchanged after all checks.

| File | SHA-256 | Bytes | Mode |
| --- | --- | ---: | --- |
| `PKGBUILD` | `739b828cf7f27a65f2028e59214fc8543ff269760b9aa6517fb6fa2636b42e9f` | 4,536 | 0644 |
| `PUBLICATION.md` | `0db09f321999befabe795066a388c271db786377d312a3f60c84424cb7685efa` | 5,723 | 0644 |
| `README.md` | `724fffb8b56e40db668959fd5911d87c96529813499f6f63c5fdb37f69c76d09` | 5,521 | 0644 |
| `materialize.py` | `2c040e37b8f0b47213484c7834b70e030528dc5fe3277fecda989455862e0d75` | 2,889 | 0644 |
| `publication.py` | `257a1fe6e567209e318fd29691501076de4566c9a536157e7d91a1002eef48d4` | 7,800 | 0644 |
| `select-source.py` | `b7d9d047ffa87d6ec5e1fd26efb2d52dbf533d7f0359eee8874905e57c1511c7` | 7,494 | 0644 |
| `selected-source-manifest.json` | `3eb66e2e1632cf65044f9250c7460b1effe0de3217f83b573b4e23885772fc29` | 144,255 | 0644 |
| `source-provenance.json` | `2f5d3c3124bdc564e9183aac8a534e51ac03c078f8312395370b8454b435cae3` | 10,225 | 0644 |
| `source_check.py` | `3825fb36450ab96bc761bdb7c86075cfbe2d80cf28b95ebda18aafbbf6b6895b` | 9,753 | 0644 |
| `test_build.py` | `48d1d04433b27c7a235ae87f1d72993f09cc0d24675a22e1f70f0564a8b89500` | 8,862 | 0644 |
| `test_publication.py` | `64130b1723b73d0269112283c2441d3db0c661c603f239bdc9b86c20794cca04` | 13,797 | 0644 |
| `test_source.py` | `d1de6ee9687b7fa71e2023cb3bdb53b7a69094541a1ac986dcda9a15b8cedddc` | 35,725 | 0644 |

## Actual data replay and scope

The independent replay used actual Python **3.14.7 / zlib 1.3.1.zlib-ng** and bundled Python **3.12.14 / zlib 1.3.2**, isolated/no-bytecode/no-site, with finite subprocess deadlines and bounded captured output. Under both runtimes the selector, checker, materializer, corresponding-source pack and reconstruction CLIs exit zero. Raw selected outputs are byte-identical: **17,387,520 bytes**, SHA-256 `1065c4b30e0c2deee7965faa0257e10ac482a2516d51b5b8f17b1406b3ecb2f4`.

Independent raw USTAR inspection verifies all 900 rooted regular members, sorted order, exact file hashes/lengths, 16,686,087 content bytes, mode0644, epoch1791748800, uid/gid0, empty owner/group names and no PAX metadata. It does not extract source into a filesystem or execute it. All 900 manifest rows are identical to the historical contract; only `packet_bytes` and `packet_sha256` changed. Original grants, copyright bundle, build layout, build-codec/stage/inspection helpers and smoke source match historical captured bytes. PKGBUILD build/check/package function bodies are identical; prepare changes only the selected filename.

The actual historical selector under Python3.12 still refuses with `reconstructed packet differs from pinned selected digest`, exit1 and no output. That local red/green proof establishes the compressor portability defect and correction, not the first failure in hosted run38268251114.

Corresponding-source publication gzip bytes differ between these runtimes, as the documented recorded-digest contract permits. Each private bundle has its own actual hash and restores byte-identical complete recipe inputs. The raw selected packet, instead of the publication transport compression, is the invariant recipe source.

## Binding and limits

Without sourcing PKGBUILD or running makepkg, the peer regenerated `.SRCINFO` from fixed existing metadata and its 21 literal source/checksum pairs: `7d4d2f778d926c0171759ed6733eecfdbc60226c7c33bce4a3bed21de1ef1c19`. Every checksum matches actual selected/template data. The independently generated 22-template map is `bbe7ca8746ac142ef90d25dbec58a116e59d9dbea3a193fa9b2a725c37aaeb9c`; both real materializations independently reproduce the 23-file map `6d5927fbeddcfe21af0e212abbe029e48805bc0927968f6c913a8c94de1f8dea`. No checksum SKIP or alternate-version source is admitted.

Only the explicit selected reader receives 20MiB; exact length/SHA precede raw `r:` tar parsing. Upstream/private compressed source and all ordinary template files retain 8MiB. The selector retains 8MiB/member,32MiB expanded and4096 members. Publication grants 20MiB only to the exact rooted selected member; all other members and their combined content, including the bounded source map, remain8MiB. Total content is at most28MiB, with a separate strict decompressed serialization cap; outer gzip remains8MiB and member count128. This is a bounded reader policy, not a promise that every cross-product of maximum limits is admitted.

Nine independent synthetic cap controls admit exact selected20MiB and exact ordinary aggregate8MiB including map bytes; refuse selected/ordinary+1, a gzip-name lookalike, aggregate+1, outer overflow, expanded serialization overflow and129 members. Synthetic admitted dummy data proves reader bounds only; usable reconstruction separately verifies the actual selected hash. Sixteen focused source/publication tests from the fresh copy pass with **zero failures/errors/skips**, ResourceWarning as error, in1.583 seconds. They cover real900 scope, raw truncation/appended/changed/gzip refusal before parsing, complete map binding, rehashed bundle poison, rooted names/types and cancellation cleanup. The owner's whole81 tests per runtime remain reported evidence and were not duplicated.

## Coordinator integration and limits

Root must adopt generated primary `.SRCINFO`, the22/23 maps and their evidence constants; change only the known selected native-stage output filename to `.tar`; regenerate/review the39-stage closure and128-job/workflow bindings; and pass actual committed preflight before a corrected native trial. Their currently stale values are intentional coordinator work, not defects in this source hold. No shared source, lock, template, workflow or project Git was edited by the peer.

Actual corrected native compilation, both codec smoke/ABI pairs, provider transactions, installation, source/binary publication, M2/16K and performance remain unrun gates. Source audit and data reproduction do not advance them.

Private peer evidence: `artifacts/reviews/fdk-canonical-tar-root-peer-20261012/final-review-receipt.json`, with captured hold, focused logs, independently replayable runtime/cap scripts/results and historical preservation proof. Actual codec packets and materialized/reconstructed recipes remain in its recorded private external `/tmp` work root.

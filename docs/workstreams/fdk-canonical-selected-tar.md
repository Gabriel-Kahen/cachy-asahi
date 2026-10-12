# Canonical selected FDK source tar correction

Status: **HELD source/data proposal for independent review**. Local data-only checks pass in both actual Python runtimes. Corrected native FDK build, provider transaction, AAC integration, installation, binary/source publication, M2,16K and performance acceptance are **NOT RUN**. Actual trial38268251114 remains FAIL at its source phase; the reproduced gzip portability defect is not its established hosted first cause.

The [actual diagnosis](../reviews/native-fdk-execution-38268251114.md), SHA256 `1dec17f827bea1140e8a70e1108d69d53e90327fb7e7a783592ae7a9a5e0f365`, showed different compressed outputs from identical selected content under zlib-ng/standard zlib. Both already agreed on the uncompressed USTAR. The coordinator selected that exact raw contract:

| Selected packet field | Held value |
| --- | --- |
| Filename | `fdk-aac-3.0.0-selected-source.tar` |
| Format | Canonical uncompressed USTAR, sorted rooted regular members |
| Exact length | 17,387,520 bytes |
| SHA256 | `1065c4b30e0c2deee7965faa0257e10ac482a2516d51b5b8f17b1406b3ecb2f4` |
| Files/content | 900 files,16,686,087 content bytes;898 implementations plus two grants |
| Metadata | epoch1791748800, mode0644, uid/gid0, empty owner/group names |
| Selected read/storage ceiling | 20 MiB, exact length/hash required before tar parsing |

Only `packet_bytes` and `packet_sha256` change in the selected manifest. Every one of its900 included-file rows, revision, grant facts, source exclusions and codec-modification declarations remains identical. Classic/xHE notices and the full raw copyright bundle remain unchanged. No upstream implementation, build layout or build command is modified. Upstream remains commit `a68a51aa45d86a43c7b228e3d45624af09dcdd8d`, archive4707099 bytes/SHA256 `ac9682b35f6e5f75e1f008a5ba2636ba6c9c77c70b78377b53992559e8bda806`; historical private full archive digest `1244e519…` remains a private input, not redistributed output. The old compressed selected contract and source copies are retained as historical evidence.

## Source and bounds

`select-source.py` writes raw USTAR directly without a compressor. Selected raw input must have the fixed length/digest before parsing with `r:`; upstream/private gzip input retains its exact digest and8MiB boundary. Large file inputs enter only through the exact selected-packet verifier; other oversized originals refuse before a large read. The selector also enforces4096 members,8MiB per regular member and32MiB expanded data before selecting/copying. The fixed manifest and file hashes, individual implementation grant markers, duplicate/path/type/inventory rules remain mandatory. No gzip fallback or checksum exception is accepted for the selected packet.

`source_check.py` uses the20MiB helper only for the explicitly selected packet. `verify_packet` verifies raw bytes before the tar parser; `template_files` assigns that helper only to the exact selected filename, leaving every other template read capped at8MiB. `materialize.py` rechecks the selected bytes before copying and preserves its complete independently reviewed-map, fresh external output, mode and cancellation cleanup behavior. PKGBUILD has a literal fixed checksum for every one of21 source entries; no `SKIP`, shell-based compressor pin or host package dependency is introduced.

The corresponding-source publication bundle remains gzip with its own recorded actual digest. Its fixed selected-tar member alone has a20MiB ceiling. All other members retain8MiB each and **8MiB combined**, including the65,536-byte-capped source map. Content total is at most28MiB; decompressed tar serialization is bounded by that total plus128512-byte headers and one10KiB tar record. The outer compressed input and output remain capped at8MiB. Member count128, regular type/mode/ownership, rooted flat names, source/map hashes, fresh external output and reconstruction cancellation cleanup remain enforced. Actual complete maps/selected packet pin are still required before usable reconstruction. No source or binary upload/publication occurs here.

## Actual bounded checks

A fresh owned external template copy contains the generated `.SRCINFO`; primary `.SRCINFO` and all shared maps are untouched. Actual selector/checker/materializer CLIs run with a cleared private HOME/environment,120-second aggregate runner and30-second child ceilings; no compiler, makepkg, Docker, upstream build script or installer executes. The retained pre-existing private input was independently rehashed to `1244e51941011bb63433b022f8bc247a28cf374749a2c3fb30f73fae42c88c49`; its selected900 file bytes exactly match the immutable grant-scoped rows. No new upstream download is claimed in this correction.

| Actual runtime | Source tests | Build-data tests | Publication tests | Canonical tar/materialization |
| --- | ---: | ---: | ---: | --- |
| Local Python3.14.7, zlib1.3.1.zlib-ng | 58 PASS | 9 PASS | 14 PASS | Exact raw digest/length;23-file map PASS |
| Bundled Python3.12.14, zlib1.3.2 | 58 PASS | 9 PASS | 14 PASS | Same exact raw bytes and23-file map PASS |

Each runtime passes **81 tests, zero skips**, with ResourceWarning treated as error. Real900-file tests cover complete byte/grant scope, repeated raw generation, materialization, bundled source reconstruction and unchanged notices. Added causal controls reject gzip wrapping, truncation, appended bytes, changed content and selected overflow before parsing; large non-selected source input is refused before read. Publication tests admit exact selected20MiB and ordinary8MiB aggregate boundaries with synthetic data, refuse either+1 and any other member over8MiB, preserve the outer8MiB bound, and positively verify cancellation removes only the newly owned reconstruction output. Synthetic boundary members are not real codec packets; actual reconstruction still verifies the fixed selected digest.

The old captured selector under actual Python3.12 still exits1 with `reconstructed packet differs from pinned selected digest`, leaves no output, and reproduces the portability defect using the prior pinned compressed input. The corrected selector under each runtime exits0, followed by checker0/materializer0, yielding the identical raw packet and identical23-file map. This red/green data-only replay took2.202 seconds. It is separate from the hosted source failure and establishes no native compile. The existing trusted recipe checker inspected the real external recipe without sourcing PKGBUILD: zero errors, all23 exact input hashes match. No PYC was created in the owned external source/recipe tree.

## Held hashes and coordinator changes

All12 owned primary files remain mode0644:

| File | SHA256 |
| --- | --- |
| `select-source.py` | `b7d9d047ffa87d6ec5e1fd26efb2d52dbf533d7f0359eee8874905e57c1511c7` |
| `source_check.py` | `3825fb36450ab96bc761bdb7c86075cfbe2d80cf28b95ebda18aafbbf6b6895b` |
| `materialize.py` | `2c040e37b8f0b47213484c7834b70e030528dc5fe3277fecda989455862e0d75` |
| `PKGBUILD` | `739b828cf7f27a65f2028e59214fc8543ff269760b9aa6517fb6fa2636b42e9f` |
| `test_source.py` | `d1de6ee9687b7fa71e2023cb3bdb53b7a69094541a1ac986dcda9a15b8cedddc` |
| `test_build.py` | `48d1d04433b27c7a235ae87f1d72993f09cc0d24675a22e1f70f0564a8b89500` |
| `publication.py` | `257a1fe6e567209e318fd29691501076de4566c9a536157e7d91a1002eef48d4` |
| `test_publication.py` | `64130b1723b73d0269112283c2441d3db0c661c603f239bdc9b86c20794cca04` |
| `README.md` | `724fffb8b56e40db668959fd5911d87c96529813499f6f63c5fdb37f69c76d09` |
| `PUBLICATION.md` | `0db09f321999befabe795066a388c271db786377d312a3f60c84424cb7685efa` |
| `source-provenance.json` | `2f5d3c3124bdc564e9183aac8a534e51ac03c078f8312395370b8454b435cae3` |
| `selected-source-manifest.json` | `3eb66e2e1632cf65044f9250c7460b1effe0de3217f83b573b4e23885772fc29` |

Private proposed metadata under `artifacts/fdk-canonical-selected-tar-20261012/`:

| Proposal | SHA256 |
| --- | --- |
| `generated.SRCINFO` | `7d4d2f778d926c0171759ed6733eecfdbc60226c7c33bce4a3bed21de1ef1c19` |
| `template-inputs.proposed.json` (22 files) | `bbe7ca8746ac142ef90d25dbec58a116e59d9dbea3a193fa9b2a725c37aaeb9c` |
| `reviewed-inputs.proposed.json` (23 files) | `6d5927fbeddcfe21af0e212abbe029e48805bc0927968f6c913a8c94de1f8dea` |

Generated `.SRCINFO` comes from the existing fixed metadata plus the exact new filename/source checksums, without makepkg/shell evaluation; the read-only recipe check corroborates every binding. These are owner proposals, not independently accepted maps. After peer closure, the coordinator must adopt that generated primary `.SRCINFO`, explicitly rebind the22-template/23-materialized maps and their evidence constants, change `scripts/port/fdk-native-stage/stage.py`'s selected output filename to `.tar`, regenerate/review the39-stage source closure and128-job packet/workflow bindings, then dispatch a separately bounded native trial. Existing stage digest permits17MiB packet bytes under its64MiB hash bound; no shared reader-cap increase was found necessary. No stage/controller/workflow/shared lock or Git edits were made here. The raw selected tar and external recipes remain private outside Git; their exact paths/hashes and source captures are in the held checkpoint for peer replay.

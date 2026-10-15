# Asahi audio Rust notice packages, native ARM — 2026-10-15

[Run 38801968699](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38801968699)
passed six native builds and three byte-identical package comparisons for
**speakersafetyd 2.0.1-3, bankstown 1.1.0-4 and triforce-lv2 0.3.2-3**.
The actual metadata contains all ten added notice files with their pinned
hashes, regular-file types, root ownership and mode 0644. Complete strict
payload counts are **30 / 7 / 8**. Scoped cleanup reports the six named build
containers and single owned bootstrap image absent.

This is build-only evidence. The result records installation, services,
hardware and audio execution **NOT RUN**, target trust **NOT ESTABLISHED**,
and release selection **false**. The three compiled payload hashes equal the
previously inspected outputs; this review did not extract new binaries or
source bundles, run or load audio outputs, or perform a package transaction.
The [audio593 installation/removal record](full-composition-audio-native-20261015.md)
continues to apply only to its old 2.0.1-2 / 1.1.0-3 / 0.3.2-2 archives.

## Exact source and builder

| Binding | Identity |
| --- | --- |
| Product Source | `b83c0f539034f10112a2d1e9743810344f13bb9d` |
| Supplied workflow Source | `9424ae797401c4df4c2701c5cbe82e8ae97a8d8a` |
| Actual caller workflow path | `.github/workflows/native-arm-build.yml` |
| Fixed recipe policy SHA-256 | `1b1b966ab8e537f98f3e962555385f6764bb5a64511198757c762a5f9a7704c6` |
| Scoped wrapper SHA-256 | `6ea4f58b0e9b10027080f577ad231fe94e566cc31019d024347f8bc6e25c839a` |
| Caller SHA-256 | `877382ce1f4e9f8b7ceb693a0a0c97116e8e7655d6be998bd599cc865dcfea4f` |
| 350-package input lock SHA-256 | `7297c9fa299e65484cdb46fc4d149af5815627a385d3050c5c884cd0cc3889c2` |
| Actual 350-package inventory SHA-256 | `d6b50a41e5e1c1880faedfbd6a1eebad6d271901c0a42923af5c8e977f23e963` |
| Current bootstrap image | `sha256:c14e33ee164c814521c189bae42c2e23f1908981c2e2d7f63a03ec1a1e67d419` |
| Source epoch | `1791748800` |

The workflow log contains the exact Source equality guard, checkout and caller
selection. The supplied workflow commit uses the existing main native-build
workflow path for this isolated audio trial. The runner identifies native
AArch64 host and Docker daemon, Neoverse-N2, ordinary UID/GID 1001 and
**4096-byte pages**. The actual bootstrap image ID differs from
[run 38789573004](asahi-audio-rust-native-20261015.md); the exact input lock and
350-package name/version inventory are unchanged. No filesystem-byte or
independent-machine identity is inferred from the shared inventory.

Acquisition records 519 passed inputs, zero failures/pending. All 258 signature
records have exit zero and the fixed ALARM VALIDSIG fingerprint
`68B3537F39A313B3E574D06777193F152BDBE6A6`. These authenticate builder inputs,
not the produced audio packages or a release. Bootstrap records
`image-provisioned`, masked ALPM hooks, disabled package scriptlets and explicit
in-container `ldconfig`. This bootstrap behavior is separate from installing
the produced audio packages.

## Actual packages and metadata

Both sides of each pair have the following archive identity:

| Package, aarch64 | Archive bytes | Archive SHA-256 |
| --- | ---: | --- |
| speakersafetyd 2.0.1-3 | 371,904 | `259c27439420d6b18b04caf5ced5d0db5f27fb6a040a437e8fad48d8569c1232` |
| bankstown 1.1.0-4 | 144,404 | `5ce529103e77d6cc509e270d925f9ecaa126d6a9b14302cdb41c14b72ed0d3af` |
| triforce-lv2 0.3.2-3 | 334,900 | `d123dca2cd67099dfe3e45af9edc7f61ba11bf650a482695350184badd7dfa3c` |

Every attempt records native mode, network none, exit zero,
`built-package-static-pass`, the current image/inventory, a distinct container,
and no validation errors. Logs show 46/46 speakersafetyd, 18/18 Bankstown and
38/38 Triforce compilation lines, completed release profiles and `Starting
check()` in both attempts. The same non-fatal deprecated `usize::max_value`
warning appears in both Triforce builds. Recipe checks inspect output existence
and AArch64 headers; upstream unit tests and audio commands were not run.

The retained comparisons each report `contents-reproduced`, no errors, and
true archive-byte, installed-content, PKGINFO and BUILDINFO equality. This
review independently streamed SHA-256 over all six retained package archives
and matched their sizes/hashes to validation and provenance. It did not unpack
the nested package archives or rerun the comparator.

For all six attempts, the complete recipe input map and metadata equal the
fixed Source policy. Every policy-listed recipe input was independently
hashed from that exact Git Source. Retained generated `.SRCINFO`, `.PKGINFO`
and `.BUILDINFO` pass the existing pure metadata-binding functions, including
recipe hash, version, architecture, licenses, dependencies, build dependencies
and installation-hook absence. Each `.BUILDINFO` contains the exact 350-entry
builder inventory; both captured package locks match its pinned inventory.
Speakersafetyd declares alsa-lib and Rust/make/pkgconf; both plugins declare
lv2 and Rust/make. These metadata/build results do not establish installation
or complete runtime dependency/symbol resolution.

## Notice and complete payload checks

All ten notice paths below are relative to `/usr/share/licenses/`. They occur
in both attempts as regular mode 0644 files owned by root:root. Their recorded
bytes/hashes match the Source policy and the retained notice manifest:

| Added path | Bytes | SHA-256 |
| --- | ---: | --- |
| speakersafetyd/SOURCE.md | 1,807 | `9d92f616bd6f2bcf1692687c2e5cd446d87b763686f3772cbf0869d9e703bfe4` |
| speakersafetyd/THIRD-PARTY-LICENSES.txt | 904,599 | `ef39f00414e23f1251aa0a2e69f39d36b1de04345932abf7d8f417909782db27` |
| speakersafetyd/THIRD-PARTY.md | 9,557 | `52e560b71ff675a9dde84c56dfeca6d8d562c4736b62c62dc163980d638cace0` |
| bankstown/SOURCE.md | 1,176 | `9df69f83b82974c8f5263714f38620b089069579402d72d30ce23c29dc73a97a` |
| bankstown/THIRD-PARTY-LICENSES.txt | 218,674 | `22f1f0b9c70ec68ff842514f91a9baff5e49f33d2741dafd194759df4bbb46f1` |
| bankstown/THIRD-PARTY.md | 2,872 | `e5280f30076165b61d8032c475383b2c95036e1c9c4f438758e1773b1886321f` |
| triforce-lv2/GPL-3.0.txt | 34,674 | `fb981668c18a279e285fc4d83fba1e836cc84dd4daa73c9697d3cfd2d8aca6e0` |
| triforce-lv2/SOURCE.md | 1,182 | `36cb52a5c6379e49ac4685b87f5618f3c860ef43bf3acb119524f00f7b701feb` |
| triforce-lv2/THIRD-PARTY-LICENSES.txt | 470,258 | `8917b1fdfcc5d960c491f794d168c980da48b523b0d116b6ba20f902b3a9e53a` |
| triforce-lv2/THIRD-PARTY.md | 5,561 | `796dbc0acb109987a5f62b5131b9fbcbd524643774093e271eef9a35648d80c7` |

The recipes all use the same 48,916-byte notice input, SHA-256
`7cd393018f279ff2a1e71fe85fb5767e3f58398edcd395da4ab6f4eb357ce522`.
The upstream archives, Cargo locks, J504 patch and 117-crate vendor archive
remain unchanged; vendor SHA-256 is
`64cd55473b19f104f3a90570409d58c5ab69f63c61396541c4ad1e56e8d6293f`.
The recorded input maps and successful source-checksum lines bind this input
to each actual build. Compilation remains frozen/offline.

Full retained member maps match every fixed payload path, mode/type and
non-ELF hash. Only legitimate ancestor directories are present; there is no
unexpected payload, symlink, `.INSTALL` or package hook. Compared with old
retained validation metadata, all 27 / 4 / 4 prior payload files have unchanged
hashes, modes and types in both new attempts. The only additions are the
3 / 3 / 4 notice files. Service/udev/model files remain packaged data;
none was activated or tested. Speakersafetyd's existing service-installation
review findings remain visible despite its empty validation-error list.

Actual package metadata is MIT for speakersafetyd/Bankstown and
`GPL-3.0-only`, `Apache-2.0`, `MIT`, `Zlib`, `Unicode-3.0` for Triforce.
The Triforce metadata describes the proposed combined GPLv3 distribution and
component terms; it does not relicense upstream source or supply an exhaustive
legal verdict. Its original GPLv2 `LICENCE.txt` remains byte-identical and its
upstream GPL-2.0-or-later expressions remain unchanged. The aggregate component
notices, source information and supplemental GPLv3 text are now actually in
the new packages. The [notice handoff](../../artifacts/development/asahi-audio-rust-licenses-20261015/NOTICE-PACKAGING.md)
retains the later wmidi MIT-text association and nalgebra-macros workspace
manifest difference as open limits. Complete release-source delivery and
compiler recipe correspondence remain unresolved; successful packaging does
not settle them.

## ELF structure and old-payload comparison

| Compiled path | SHA-256, equal to prior actual output |
| --- | --- |
| `usr/bin/speakersafetyd` | `0f102e4d794d6ed0345d742bc05200de49691b6cf79e9562135645cc19c6e8ff` |
| `usr/lib/lv2/bankstown.lv2/bankstown.so` | `5ad5c45ead516c32b0639af52a9f9a2772994973d2c3f7870d1e0c8795cdc352` |
| `usr/lib/lv2/triforce.lv2/triforce.so` | `8c49f609fb86cc1d46d9971e4b9967f7dc5a60fa2185810eb85f368d5aad0e51` |

Each current validation record reports one AArch64 ELF, machine 183, four
PT_LOAD segments and no structural-check errors. Its recorded full-file hash
matches the previous directly inspected ELF. That retained prior inspection
records 65536-byte alignment and matching file-offset/virtual-address residues
modulo 16384 for every load segment. Thus the current metadata and identical
binary hashes support the same structural result without extracting the new
binaries. This review did not directly reparse their headers.

The host uses 4KiB pages. Static structure and matching hashes do not establish
execution on a 16KiB kernel, plugin loading, speaker safety, acoustic/DSP/limiter
behavior, either M2 Air size or performance. No such execution occurred.

## Scoped cleanup and retained evidence

Cleanup reports PASS for exactly the six provenance container names and the
one current image ID, each with recorded absence verification. The pinned
caller removes its own image with `image rm --no-prune` and verifies absence;
uncertainty would fail the summary. This does not claim global cache/parent
layer erasure, whole-daemon cleanup or removal of retained evidence/GPG data.

Root collected [logs.zip](../../artifacts/development/asahi-audio-rust-notices-run38801968699/logs.zip)
once: **84,943,253 bytes**, SHA-256
`e6c0ae93992d4732060f7791bda1aea7a7db69e8441af09f0b92d4cec71c60b2`.
After an initial decoder attempt stopped at a log BOM marker, the successful
metadata decode stripped 33 transport BOMs and timestamp prefixes, verified
all eight compressed frame sizes/hashes, and enumerated 118 regular members.
No logs were recollected. No new binary/source bundle was extracted or
exported; nested package archives were streamed only for their archive hashes.
Source snapshots remained in the original retained frames.

| Frame | Compressed bytes | Regular members | SHA-256 |
| --- | ---: | ---: | --- |
| summary | 1,996 | 13 | `1bc83754599f590734973e61da8a0bfbbbc22f26fbeb2d84e2e7abe2b1e4d196` |
| native | 798,478 | 13 | `a7d7c3b7dc682a75e026e554fb99ae9dbd7da82ba2a5ecea5a4e7a02cbff2374` |
| speakersafetyd-build-1 | 6,205,695 | 16 | `ee0f33561afdcf291c1c1882fe6ed6599b24e23ff3c3a986dc686aa57a420b72` |
| speakersafetyd-build-2 | 6,205,728 | 16 | `0683c918558af43834a84ab28da345f117ac734bf14586f6f08f31550679a476` |
| bankstown-build-1 | 5,953,806 | 15 | `1cafc946a2fb30aa2cd0bf8b9ca7a27c03cabb99b42cd8f2e6a8080c4712e6ca` |
| bankstown-build-2 | 5,953,786 | 15 | `0ceb2ea720c25c35fcedc86327caa680462e89e9eff091a1e22642593e5726af` |
| triforce-lv2-build-1 | 6,157,978 | 15 | `72414a23ae3e5d888a4148f60ffb52c55b85693387ef7879218b62535d76f5a3` |
| triforce-lv2-build-2 | 6,157,973 | 15 | `eafd73cf5f75a11fbd2021a688c34c6dd33697d4c1f28156c22c6b84db3de3e7` |

The [review readout](../../artifacts/development/asahi-audio-rust-notices-run38801968699/review-readout.json)
retains actual audio validation/provenance, frame identities, streamed package
hashes, exact notice checks, prior compiled-payload comparisons and summarized
upstream input/signature checks. No build, test suite, package transaction,
service, binary or audio actor was replayed. Only this unique validation doc
and owned artifact readouts were written by this review.

Produced-package installation/removal/recovery for these new versions, release
signing/target trust, complete audio runtime behavior, protected platform
integration, physical 16KiB/M2 validation and measured performance remain
**NOT RUN / NOT ESTABLISHED**. Old audio593 installation evidence remains
historical. Release selection remains **false** and full R1–R5/M5–M9 completion
remains open.

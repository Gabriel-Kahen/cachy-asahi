# LSP headless LV2 native build pair — 2026-10-15

[Run 38797402321](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38797402321) completed successfully. Two native ARM builds of **lsp-plugins-lv2-headless-development 1.2.35-1** produced the same recorded package hash, installed payload, PKGINFO and BUILDINFO. The unchanged comparator reports byte identity with no errors. The exact574 builder and both real compiler/header prerequisite probes passed; normal cleanup reports both named build containers and the newly owned builder image absent.

This is **build-only evidence**. No produced package was installed, no produced plugin was loaded or instantiated for audio processing, and no target audio, speaker, hardware, performance or release result is credited. The result explicitly records `installation`, `plugin_processing`, `audio` and `hardware` as `NOT RUN`, and `selected_for_release=false`.

## Exact selections and evidence boundary

| Item | Identity |
| --- | --- |
| Product Source | `71af5525cd7a62775e82b84aac702d384cf66c58` |
| Root-supplied workflow Source | `17efec579533e7367923fbfc2649b04f41511d68` |
| Registered workflow / isolated ref | `native-arm-build.yml` / `codex/asahi-lsp-native-v1` |
| Unchanged package API Source | `db1010de321cc056a01672f006e6cc25d3c8a8b7` |
| Unchanged574 preparation Source | `8d8e2f5d5a94ab3ebee2d8b1cc20aecf98e435e2` |
|574 input-lock SHA256 | `b2a234c76c3a820382238023203a8b699a503153f63b938376fd16433c4d90f9` |
| Actual574 installed-lock SHA256 | `cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac` |
| Same-job image | `sha256:25abf08888bb32ac29a34853c4dd068684792527f114db8e4b69c3d4dd9301c3` |
| LSP source archive SHA256 | `2c95ec7bb219d561ea3db36051b6c732133bcd76426fb836b1dd850dc4b5bb6c` |
| LSP recipe SHA256 | `8d78f75f57e3d54a00de8d074e5b31c050db11097890adea03a6d134ce4eac64` |
| Build helper SHA256 | `0bb4024d0eb02f4e8ced77a68fce80a730877a2b9cb190cae2aae650ecab1e0e` |
| LSP source epoch | `1787491172` |

Retained checkout logs show the exact product, API and desktop commits above; the job is registered against the supplied isolated ref on `ubuntu-24.04-arm`. The public result agrees with those selections. Native Linux ARM host/daemon and Linux/arm64 image checks are mandatory in the adopted caller and succeeded before the two builds. Public evidence does not retain a CPU model, host page size or raw compiler-version output; none is inferred from the runner label.

The host acquired the exact78,369,996-byte upstream1.2.35 archive into private scratch, checked size/hash, and supplied it as a local recipe input. Both public build-input maps retain that hash and the four exact recipe-file hashes, which match the adopted canonical files. The source archive and module snapshots were not exported. The upstream/module/license [source audit](../../artifacts/development/asahi-lsp-build-20261015/README.md) remains the source-selection record; this result does not establish correspondence to the different historical ALARM recipe or GUI-enabled LV2 binary.

The base reports `PASS_NATIVE_OFFLINE_574_TRANSACTION`,1153 acquired input objects, the exact input/helper/inventory pins and the unchanged required-signature, pinned-keyring offline package-transaction policy. This projection retains a base-report hash, **not1153 individual signature-verification receipts**. Input-object count includes archives, signatures, rootfs and keyring inputs and must not be described as a count of verified signatures. No new package signing or accepted target trust is established.

This review independently reconstructed a sorted name/version lock from all574 entries in each retained BUILDINFO; its SHA256 equals the selected installed lock. The two BUILDINFO inventories match. Installed inputs include GCC/libstdc++16.1.1+r12+g301eb08fa2c5-1, Make4.4.1-3, pkgconf3.0.7-1, Cairo1.18.6-1 and libsndfile1.2.2-4. Those package versions plus successful real probes/builds establish this trial's prerequisites, not compiler-source reconstruction or compiler reproducibility.

## Two builds, selected flags and package observations

| Result, both attempts | Recorded value |
| --- | --- |
| Package | `lsp-plugins-lv2-headless-development-1.2.35-1-aarch64.pkg.tar.xz` |
| Archive bytes |2,297,536 |
| Archive SHA256 | `8fbd603732c505a36cf57be2163cb96b5bd0a13171d64c6104ea6a6c8b1a8791` |
| Payload bytes |24,305,211 |
| DSP library bytes |11,050,096 |
| DSP library SHA256 | `b11bb9851ac3153ffe8b423d591133d4f48bd12cb9508c8c7080f93b6a906a84` |

Every retained build observation agrees across the pair except its raw build-log hash. Each private log was1,841,431 bytes; the public records retain only size/hash and bounded markers. Both attempts have all five prerequisite PASS markers—native compiler, pkgconf, Cairo, libsndfile and C/C++ headers—and PASS for configuration, compilation, TTL generation and packaging. No failure marker is present. Raw diagnostics were deliberately not published, so this review makes no warning-free-build claim.

Actual selected configuration is identical on both sides: **`BUILD_FEATURES=lv2`**, target/host C and C++ flags contain **`-march=armv8-a -mtune=generic -O2`**, and no selected LTO or `-mcpu` flag appears. C++ retains upstream no-exceptions/no-RTTI flags; shared-library flags include generic ARM tuning, RELRO/now, section collection and `-shared -fPIC`. The adopted helper parses/asserts these seven configuration fields before compilation; the public projection preserves their exact selected values. No Apple-specific optimization or performance advantage is claimed.

The unchanged standard builder used native mode, network none, two fresh containers, nonroot UID/GID, read-only root, dropped capabilities, no-new-privileges, fourCPU/4GiB/512-process limits and a4GiB executable tmpfs. The recipe bounded `make -j2` to1800 seconds inside a2400-second build deadline. The workflow's overall150-minute limit also covered only the established seed/574 preparation and LSP pair; no older package pair, full composition or desktop actor was repeated.

Generated `.SRCINFO` has SHA256 `5293a92f63bff2542ea985a4fe9984b446cc3ebb1ac47d03fa049a29525b3969`, equal to the reviewed source file. Both PKGINFO records declare aarch64, version1.2.35-1, runtime dependencies Cairo/glibc/libsndfile/libstdc++/lv2, build dependencies GCC/Make/pkgconf, and LGPL-3.0-or-later plus ISC. Both BUILDINFO records bind the exact PKGBUILD hash. Their `builddate` and payload mtimes are the selected source epoch, not the wall-clock execution date.

`compare.py --require-bytes` completed with `contents-reproduced`, zero errors, and true archive-byte, installed-content, PKGINFO and BUILDINFO equality. Its unchanged verifier rechecks private archives, input snapshots, held builder inputs and distinct container identities before comparing them. This review independently reconciled the **public hash/metadata/payload observations**; it did not independently rehash the original package/library bytes because they were intentionally not exported. The result is two clean runs on one hosted machine/daemon, not independent-machine reproduction.

## Payload and structural ELF limits

Both public member maps contain215 members: seven directories, three package metadata files, and **205 regular payload files** comprising one DSP library,199 TTL files including `manifest.ttl`, and five notice files. Payload files are root-owned, have source-epoch mtimes, mode0755 for the library and0644 otherwise. Their summed sizes match PKGINFO. The closed map contains no UI library/fonts, other plugin formats, hooks, install scripts, symlinks, service, protected platform path or unexpected file.

The five staged notice basenames are `COPYING`, `COPYING.LESSER`, `LV2-COPYING`, `Ardour-inline-display-NOTICE` and `SOURCE-NOTICE`. Only names, attributes and hashes are public; no notice/source excerpt was exported. TTL contents were also withheld, so this review does not validate their syntax, plugin URIs/control ports or Asahi filter-chain compatibility.

For `/usr/lib/lv2/lsp-plugins.lv2/lsp-plugins-lv2.so`, the unchanged checker records ELF machine183/AArch64, two PT_LOAD segments, no structural errors, and hardware `NOT RUN`. That checker enforces little-endian ELF64 and the recorded structural16KiB alignment conditions. **The public projection does not include binary bytes or program headers**: this review cannot independently derive segment alignments, DT_NEEDED, RPATH, symbol resolution or loader compatibility. Structural acceptance is not16KiB-kernel or M2 execution.

Upstream metadata generators/validator and the TTL generator executed as build tools. The inspected TTL generator enumerates linked metadata and uses the supplied library basename for emitted references; it does not dynamically load the produced plugin in that path. No DSP instance, audio graph, produced-plugin host test, external `lv2lint`, service or device operation was run. This headless payload deliberately differs from the full GUI-enabled upstream/ALARM package.

## Normal cleanup and retained review

The caller reports PASS and verified absence of `cachy-asahi-2e4f0824e68187ab` and `cachy-asahi-40ab1a065d4ec72b`, followed by removal of its private source/build/package/log scratch. Its borrowed-image marker means the caller preserved the base for the outer owner. The owner then reports seed/build/trial PASS, **`PASS-normal-completion`** bootstrap retirement, exact owned image absence and private job-root removal. The source removes that newly owned image with `image rm --no-prune`, preserves preexisting images and refuses unidentified resources.

This proves the recorded **normal-path cleanup scope**, not whole-daemon/cache/parent-layer deletion or all cancellation paths. The unchanged8d8 bootstrap and inventory probe lack unique daemon ownership handles. Interrupted/incomplete bootstrap or uncertain trial-controller retirement remains UNKNOWN/FAIL; this successful uninterrupted run does not resolve that known limitation. Hosted VM disposal is a separate lifecycle boundary.

Root collected [logs.zip](../../artifacts/development/asahi-lsp-build-run38797402321/logs.zip) once:115,104 bytes, SHA256 **`90150f247a479b74748fe51cca4461e19880711e7a2996c69c06f7d1b729e7dc`**. This review decoded the single public frame once, from the retention-step log; its identical occurrence in the combined log was not decoded again. The frame is37,919 bytes, SHA256 **`5e9538af8740e5f5bff50cec0d76b8f97f6154876f0ac8652a1a19a382374cb3`**. Its size/hash and exact four regular JSON members were checked before retaining [public-review](../../artifacts/development/asahi-lsp-build-run38797402321/public-review/result.json). No second compressed bundle was written. [review-readout.json](../../artifacts/development/asahi-lsp-build-run38797402321/review-readout.json) records member identities and the bounded reconciliation.

No logs were recollected; no build, comparator, test suite, package transaction, generated binary or plugin was replayed. No private output was requested or exported. Only this unique validation document and the retained public-observation review files were written; shared manifests and canonical implementation remain coordinator-owned.

Full-source fixture provenance, UI font mapping, corresponding-source/relinking delivery and final binary-license/distribution closure remain release blockers. Signed target integration, installation/removal/recovery, coordinated Asahi audio/speaker protection, plugin processing, real16KiB execution, both M2 Air sizes, acoustic safety and measured performance remain **NOT RUN / NOT ESTABLISHED**. Release selection remains false.

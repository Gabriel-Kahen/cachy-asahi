# Asahi audio Rust build pairs, native ARM — 2026-10-15

[Run 38789573004](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38789573004) passed six native builds and three byte-identical package comparisons for **speakersafetyd2.0.1-2, bankstown1.1.0-3 and triforce-lv2 0.3.2-2**. All six recorded native/static checks passed on the same exact350-package builder, and scoped cleanup verified the six build containers and owned image absent.

This is **build-only** evidence. None of these produced packages was installed, their audio outputs were not run or dynamically loaded, and no audio/service/hardware behavior was tested. The result records `selected_for_release=false`, `installation=NOT RUN`, `services=NOT RUN`, `hardware=NOT RUN` and `target_trust=NOT ESTABLISHED`. Canonical platform selection and exact-source adoption remain separate coordinator decisions.

## Exact source and native builder

| Item | Identity |
| --- | --- |
| Product/checkout Source | `6983455c92ac39064909923836d7c5122d423f0f` |
| Workflow Source supplied with the retained run | `ee1125b35af25536a681e7242c85bce9562b8841` |
| Fixed recipe policy SHA256 | `a93fe987785b4876adacc5d07812f5b19e57549abca70786f738df7ba7f46a11` |
| Scoped wrapper SHA256 | `cf4efa8b19b3743cf6b7e8aca9f7494119556e765781529d5b1cdd4266c19cff` |
| 350 input-lock SHA256 | `7297c9fa299e65484cdb46fc4d149af5815627a385d3050c5c884cd0cc3889c2` |
| Actual350 inventory SHA256 | `d6b50a41e5e1c1880faedfbd6a1eebad6d271901c0a42923af5c8e977f23e963` |
| Same-job builder image | `sha256:00d7c16e480c1e0c99bdf9beb9e645135e086a9fc944e06b52cee65f3184af3a` |
| Source epoch | `1791748800` |

The retained checkout and actual caller command select Source6983455 exactly. The product and supplied workflow revisions differ only in the unrelated `.github/workflows/native-arm-build.yml`; this isolated audio caller/recipes remain the product-source selection. The runner record identifies native aarch64 host and Docker daemon, Neoverse-N2, Linux6.17.0-1022-azure, ordinary UID/GID1001 and **4096-byte pages**. An architecture declaration alone is not the native-build evidence: the six completed compilation records and retained ELF outputs supply that evidence.

The original341 input versions remain unchanged. The nine additions are rust1:1.99.0-1 (including Cargo), compiler-rt23.1.1-1, lld23.1.1-1, libgit2 1:1.9.7-1, llhttp9.3.1-1, alsa-lib1.2.16.1-1, alsa-topology-conf1.2.5.1-4, alsa-ucm-conf1.2.16.1-1 and lv2 1.18.10-2. llvm-libs23.1.1-1 was already present. Read-only comparison of the two pinned input inventories confirms **341 + nine = 350**, with no replaced baseline version.

Acquisition reports519 passed inputs, zero failures/pending. All258 retained signature-verification records have exit zero and the fixed ALARM fingerprint `68B3537F39A313B3E574D06777193F152BDBE6A6`. These authenticate the selected upstream builder inputs, not the newly produced audio packages or release signing. The bootstrap uses the unchanged native builder's required-signature, network-disabled ordinary package transaction with `--noscriptlet`, observed hook masks and explicit in-container `ldconfig`; its result is `image-provisioned`. Actual350 inventories are retained for the bootstrap and both sides of every build. Each output `.BUILDINFO` also contains exactly those350 installed name/version entries.

## Six builds and three pairs

| Output package | Both archive bytes | Both archive SHA256 | Declared runtime dependency / license |
| --- | ---: | --- | --- |
| speakersafetyd2.0.1-2, aarch64 | 346,696 | `d5e838c90d72cab0ab8134e849eb963e243ae2c21d8a2ed7d851591e88589b34` | alsa-lib / MIT |
| bankstown1.1.0-3, aarch64 | 133,588 | `9cda94c16c02df110770489bd15ba21db3a86e4372f7e0e772105f096be9dd72` | lv2 / MIT |
| triforce-lv2 0.3.2-2, aarch64 | 311,300 | `c1869bad7a44c97d29432a840ee0c93a292fcd09b9a7b62a3f8b357e7f4973db` | lv2 / GPL-2.0-or-later |

Every attempt reports `mode=native`, aarch64 builder, `network=none`, exit0, `built-package-static-pass`, the exact builder image/inventory above and no package-validation errors. Each provenance record names a distinct container. The retained commands use non-root1001:1001, a read-only image, no capabilities, no-new-privileges, four CPUs,4GiB memory, a private4GiB build tmpfs and a900-second build timeout. These are two clean launches per recipe on one machine/daemon, rather than independent-machine reproduction.

Both records for each recipe match the complete input map from the fixed Source698 policy and the committed input bytes. The actual package hash matches its provenance, and `.BUILDINFO` binds the selected recipe hash. The PKGBUILD hashes are `d243ce80dc01c4107388cbe2b29d6f2c5e53dd76370874d8a6f2e9995b2144fd` (speakersafetyd), `3c20352f84534493f1d3eb1e080e5df88ba49698874f3d5e4152aaa08a0e0316` (bankstown) and `781039d63edbb0b9100b720fb01ba9111d828c5b70802374bec35c0ac285ca21` (Triforce).

Recipes use the previously retained upstream source archives and J504 label patch from the [audio input handoff](../../artifacts/development/asahi-audio-inputs-20261015/README.md), plus the same117-crate vendor bundle. That bundle is5,733,816 bytes, SHA256 `64cd55473b19f104f3a90570409d58c5ab69f63c61396541c4ad1e56e8d6293f`. Cargo builds with `--release --frozen --offline` and checks each original Cargo.lock hash before/after compilation. The retained logs show46/46 speakersafetyd compilation lines,18/18 Bankstown and38/38 Triforce, a completed release build and `Starting check()` for every attempt. Triforce emits the same non-fatal deprecated-`usize::max_value` warning in both builds.

All three comparisons report `contents-reproduced`, no errors and true byte, installed-content, PKGINFO and BUILDINFO equality. This review independently hashed both retained archives for each pair and read their metadata/payloads in memory; it did not rerun `compare.py` or a builder.

The recipes add explicit Rust build dependencies: Rust/make/pkgconf for speakersafetyd, Rust/make for both LV2 plugins. Actual metadata declares alsa-lib or lv2 as shown above; those inputs and the declared build tools are present in350, and compilation succeeds. This does not establish a produced-package installation/dependency transaction, dynamic symbol resolution, the complete audio-stack runtime closure or target integration.

## Structural ELF and protected payload boundary

Every package contains exactly one64-bit little-endian AArch64 ELF output, machine183, with four PT_LOAD segments. Direct read-only inspection of all six retained binaries found **65536-byte alignment** for every load segment and matching file-offset/virtual-address residues modulo16384, agreeing with the recorded structural16K checker. The outputs are `/usr/bin/speakersafetyd`, `/usr/lib/lv2/bankstown.lv2/bankstown.so` and `/usr/lib/lv2/triforce.lv2/triforce.so`.

This is static segment-structure evidence. The builder host used4KiB pages; no produced daemon/plugin was executed or loaded, including on a16KiB kernel. No M2, acoustic, DSP, limiter, safety-policy or performance conclusion follows.

The build-only wrapper retains the ordinary generic builder/checker/comparator and accepts only three complete pinned recipe/metadata/payload maps. It filters only the known protected speakersafetyd name/path findings after those exact checks succeed. The normal overlay protected gate remains unchanged; this exception supplies no installation or platform-mutation authorization.

Direct inspection agrees with the fixed policy: speakersafetyd has27 regular payload files—25 unchanged data files, the daemon and its source license—while each LV2 plugin has four, including its source license. Hashes/modes match for the fixed data, all payload files are root-owned, and no `.INSTALL`, `.hook`, symlink or unexpected payload is present. The service unit and udev rule are **packaged data**, not activated services. J413/J415 model configuration presence provides no test result for either machine. Recipe `check()` only checks output existence and the AArch64 header; no upstream unit test, daemon help command, plugin load or audio example was run.

## Licenses, compiler provenance and cleanup limits

The actual Triforce0.3.2-2 metadata corrects the selected upstream recipe/binary's erroneous MIT field to **GPL-2.0-or-later**, and includes `LICENCE.txt`; this does not retroactively correct the earlier signed0.3.2-1 archive. Speakersafetyd and Bankstown retain MIT and include their source licenses. Source/vendor snapshots are retained in the original evidence and committed candidate inputs. Full117-crate license compatibility, attribution/notice handling and corresponding-source/publication closure remain unfinished; package fields and bundled license files alone do not satisfy that release work.

The authenticated ALARM Rust binary is a fixed build input, not a locally rebuilt compiler. The retained [compiler recipe correspondence record](../../artifacts/development/asahi-audio-rust-builder-20261015/metadata/rust-recipe-correspondence.json) pins recipe commit `fc83842504046113895814fa55372e27775c6f5f`, recipe SHA256 `ce6002be1741dafc8d8387c32ad84daf67d923010b5e263e17787571d67273fd`. It differs from the signed compiler binary's declared recipe SHA256 `ef3fac9176e2a3698314d616e56d88b2df64d057ee7e9dfa13c98eb980a345fa`. Exact compiler-source/recipe reconstruction and compiler reproducibility are therefore **not established**. The audio pair result does not resolve this known provenance gap.

Cleanup reports PASS, six individually named build-container absences and absence of the single owned builder image. The source removes only that image with `image rm --no-prune` and verifies its ID absent; failure or uncertainty would fail the summary. It does not claim parent-layer/global-cache/whole-daemon deletion, nor removal of every retained output or public-key verification directory. The source snapshots, diagnostics and binaries were intentionally available for evidence retention. Bootstrap installed only authenticated compiler/dependency inputs; none of the three produced audio packages was installed or signed for release.

## Retained evidence and review scope

Root collected [logs.zip](../../artifacts/development/asahi-audio-rust-run38789573004/logs.zip) once: **83,988,563 bytes**, SHA256 **`5f41c3d2863a9ee1ce9564290621395c8b604f2e9a379c75d8188837a24ba4e9`**. This inspection decoded the eight original frames once, verified every compressed size/SHA256, and enumerated112 regular members, reading selected records and all six package archives in memory. The original ZIP was preserved; [review-readout.json](../../artifacts/development/asahi-audio-rust-run38789573004/review-readout.json) records the frame identities, selected result/provenance/inventory records, package hashes/metadata/payloads and structural ELF observations without exporting a second binary/source bundle.

| Original frame | Compressed bytes | Regular members | SHA256 |
| --- | ---: | ---: | --- |
| summary | 1,923 | 13 | `c6a24e8f0cbe8437e5f4b8bfceae424a00019a364eb7c0c1557850e8c772bb5c` |
| native | 798,486 | 13 | `96cc09f60c5c34b53c666b7896d3d183ca3ec3552a6dc451f73efe54b0555cdf` |
| speakersafetyd-build-1 | 6,130,018 | 15 | `7e81a366bbfffb0ec7d45567a1b6952f08d9fcb1784d3ba9b479d9c74858bec7` |
| speakersafetyd-build-2 | 6,130,026 | 15 | `d5674e0d84107237696f7ad44be66f227ec30d8c3f7b5d0fed82f006e26cd299` |
| bankstown-build-1 | 5,892,852 | 14 | `1d67c9352d6a93d9f8300f3a400a065413da5d49578d984332b55ae511265d2c` |
| bankstown-build-2 | 5,892,836 | 14 | `0ced0f8e0aa3975bee14fc74394e58bb887dd230356a6ada5c615576d858cfbe` |
| triforce-lv2-build-1 | 6,084,231 | 14 | `173b8495a2a06903d2cd3e428a01a55fc2488537fca748b077a43d1fa17e3a8d` |
| triforce-lv2-build-2 | 6,084,214 | 14 | `3021ee0996367489001914169e0d5a5e5f6e4495d765a26f74dcee2cb6ae609c` |

No logs were recollected; no build, test suite, package transaction, service, audio command or produced binary was replayed. This bounded evidence review found no mismatch in the three pair results, exact350 base or claimed scoped cleanup. Root retains its separate exact-source/integration decision; no new review chain or shared manifest/status edit was introduced. Only this unique validation document and its artifact readout were written.

Produced-package installation/removal/recovery, signed target trust/transaction closure, complete audio-stack behavior, service/udev operation, protected target policy, real16KiB execution, either M2 Air size, acoustic safety and measured performance remain **NOT RUN / NOT ESTABLISHED**. Release selection remains **false**, and [full R1–R5/M5–M9 completion](../roadmap.md) remains open.

# Independent Cachy-update build and license review

Initial review October 11, 2026; extension/metadata review updated October 12, 2026 (America/New_York). **Source review and offline resolution only.** The builder extension is now authenticated in retained coordinator evidence. Private isolated native Linux ARM compilation still needs an explicit scoped adapter and reconciliation of supplemental notice evidence in the closure validator. No source-level aarch64 blocker was found in the 17 build-script candidates shown by the normal/build tree. Native compilation, actual emitted unit/feature graph, binary linkage, 16K loading, package lifecycle, private-bus runtime and M2 update/recovery remain **NOT RUN**. The full all-target vendor distribution is **not accepted**.

This reviewer owns only this document. Roadmap and package inventory were read; R1/R4/R5 and M5–M9 require the broader maintained port, not this tool or four configuration packages alone. No updater, recipe function, build.rs, package-manager, service, key, compiler source build, Git mutation or original freeze change was executed. Only existing Cargo/rustc version queries, offline `cargo metadata`/`cargo tree`, safe file/JSON/TOML/archive reads and private temporary audit data were used. Three read-only subagent reviews checked source behavior, selected scripts/embedded inputs and the seven conservative metadata additions; they edited no files. The candidate owner is changing its own policy separately; this report binds the input snapshot below.

## Reviewed snapshot and actual resolution

| Input | SHA-256 / immutable identity |
| --- | --- |
| Upstream | `CachyOS/cachy-update@e2b1b7144be71cf392809f48d1440f8da1d9c81a`, 4.4.2 |
| Original source archive | `b5e4ca8f2f779d1a877ab7a815cbb40a9a9cecf16ac59852eb7a3072fb3a261d` |
| Tray Cargo.toml | `fcae83c668f4aa18800450ca165d87cd929cbf1141f33177628c32e451a2582a` |
| Cargo.lock | `0f12cdc2bd6e3838d67b08f0566f75f477bc83121196cf14d0ea5ce07faa3753` |
| Sanitized source | `029a92460a9baa29c052994a1cdf6f5821ae86b2d25ef7825dbdb61bd6ad9a0a` |
| Full vendor archive | `f02cd712c34a3467d63ff933396ea23e5ec5e0386e90701643006e0904c92f2c` |
| PKGBUILD | `8bc1eeaddd1746b6a79be14880b6c279e53f8cf33122442b5aafc92c95e26d06` |
| behavior.patch | `08a781eeae66881359207ed93cbe808f3fdff884de646ec09c9bc640ad527db6` |
| cargo-audit.json | `01d8fdc321d58f0153019b576db5abfd3e4a66320d5c26507cb40df7e9ff7ff8` |
| additional-cargo-licenses.json | `74a1dbfa75de13df5c82525af8d684e38b772c31bdf912d61f7fe74e7646c591` |
| build-policy.json / build-gate.py | `730bcd26dffb9187a9b8f5c70f41e852c467169333a355a81330004657040e0d` / `904e6181752bd7755bbdcd95bb9e7cfc0d86c5778a0d0754df5a8b1a259a4026` |

Actual data-only resolver experiment used `/tmp/cachy-update-independent-metadata-nbbxkfn2`: a copy of the exact tray manifest/lock/source, new private HOME and CARGO_HOME, explicit vendored source replacement, direct installed Cargo/rustc 1.96.1 binaries, fixed PATH, offline environment, no wrappers/default user cache and a dedicated unused target directory. No toolchain/registry download occurred. No Cargo target directory was created. Before/after lock bytes matched the original; shared vendor/source files were only read.

```sh
cargo metadata --format-version 1   --filter-platform aarch64-unknown-linux-gnu --offline --locked --frozen   --manifest-path /PRIVATE_AUDIT/tray/Cargo.toml
cargo tree --target aarch64-unknown-linux-gnu --edges normal,build   --prefix none --format '{p} [{f}]' --offline --locked --frozen   --manifest-path /PRIVATE_AUDIT/tray/Cargo.toml
```

Both exited 0 with empty stderr. Metadata contained **124 packages**, including the local tray. The normal/build tree contained **117 unique packages: tray + 116 registry crates**, and **17 build-script candidates**, compared with 168/167 packages and 38 scripts in the all-target lock inventory. Metadata's seven additional packages were bitflags 1.3.2, defmt 1.1.1, defmt-macros 1.1.1, defmt-parser 1.0.0, thiserror 2.0.20, thiserror-impl 2.0.20 and toml_writer 1.1.2+spec-1.1.0. Do not call the metadata package array the exact compile selection. Cargo documents that normal/build tree output approximates build feature unification, without guaranteeing the eventual compilation units. This experiment is x86-host resolution with an ARM target filter, not native ARM execution; the chosen native toolchain must repeat it and retain actual compiler unit/feature records. [Cargo metadata](https://doc.rust-lang.org/cargo/commands/cargo-metadata.html), [Cargo tree feature unification](https://doc.rust-lang.org/cargo/commands/cargo-tree.html#feature-unification).

Independent rehashing passed for **116 original registry archives, 5720 vendored file-checksum entries (88,130,577 source bytes), 216 retained license-notice files and all 17 selected script hashes**. This establishes byte binding, not a blanket license-compatibility approval. Highest declared MSRV in this tree is Rust **1.92** (GLib/GIO crates); edition is 2024. The separately authenticated native Rust package is newer (1:1.99.0-1); its retained archive/dependency evidence is described below. The installed worker image and native execution are still unverified.

Resolver receipt/metadata/tree and selected version/feature/archive/script map remain temporary read-only audit evidence at the private audit path. Important output hashes:

- `metadata.json`: `a6618d04f50188c0567a1ca170599334060761892205f1a1e1a0c6428bc918d2`.
- `tree.txt`: `6b0c8f0757adaf45d79a9e9febdc4d0dbad816a37a3c4f6993fe0bee56ee9ce2`.
- `tree-selected-closure.json`: `f8e9afc142c1f607739e4eded53a8cbc665ead231d9a1e494352a3c90597802c`.

Temporary paths are not permanent source/artifact retention. The coordinator must incorporate portable sanitized resolver receipts into retained build provenance before any accepted build/distribution claim.

## Compilation scope versus vendor distribution

The four unresolved historical notice packages (`block 0.1.6`, `malloc_buf 0.0.6`, `objc-foundation 0.1.1`, `objc_id 0.1.1`) are absent from both filtered outputs; source paths cross locale_config's macOS-only edges. They are not compilation dependencies in the observed Linux normal/build tree. They remain in the actual full vendor archive with unresolved complete notices and must remain visible in its all-target distribution audit. Four supplemental source matches close other historical notice gaps; none licenses the four unresolved packages retroactively. The observed 116-crate tree has no remaining notice blockers in the current audit's notice-detection evidence; that is not final licensing/attribution acceptance for a compiled package.

**A naive Linux vendor trim does not work with the frozen resolver.** A separate temporary directory-source experiment omitted only those four folders, preserved every other vendor source, and reran the same frozen offline Linux tree command. Cargo exited **101**: `no matching package named objc-foundation found`, required by locale_config → gettext-rs → tray. No target output was created. Diagnostic SHA-256: `d35d11075588ce53fbece7996d1c4bd58fb75c34803ce1628097421a93479ce1`. Cargo still needs unbuilt dependency metadata to resolve the existing lock. Do not delete the folders, claim full closure, silently stub them, alter the lock without review or disable frozen/offline checks. A genuinely excluded distributable source set needs a reviewed resolver/source redesign with new pins and actual resolver proof.

The unchanged recipe `_review_gate` deliberately requires complete all-target license/embedded/prebuilt/script review and rejects this snapshot. It cannot express a private target-limited compile result separately from full-vendor distribution. The package owner should retain that distribution refusal while, if proceeding, introducing an explicit **private native Linux compile** scope bound to source/lock/target/features and the selected script review. Do not turn full-vendor fields to PASS merely to get a binary. Private compilation can test the Linux tool without executing unused macOS/Windows code; it does not clear retained-source distribution obligations or authorize publication/package acceptance. Scope/legal/distribution decisions belong to the release custodian; this is a technical source/input audit.

## Authenticated extension and conservative 124-package scope

The follow-up independently rehashed and reconciled the retained extension records; it did **not** re-execute GPG or install packages. The coordinator’s `extension-receipt.json` reports authenticated package bytes/signatures, strict metadata and dependency checks: **13 additions, 341 → 354 packages**, no baseline version changes, conflicts, removals, missing dependencies or failures; private public-only verification home removed. The receipt’s 13 successful GPG records each identify full signer `68B3537F39A313B3E574D06777193F152BDBE6A6`. This reviewer checked receipt/lock hashes, every observation hash and package identity, every package/signature hash binding, complete inventory equality and unchanged baseline membership/versions. The mirror DB snapshots themselves are unsigned discovery data; the retained archive signatures establish the recorded archive authenticity.

| Retained extension input | SHA-256 |
| --- | --- |
| `scripts/port/updater-extension/builder-extension.lock.json` | `988a74e39f5d3b74cee18dcd53e78733c38872fe2143ccf4e2f4e95d5a5f8776` |
| `scripts/port/updater-extension/extension-receipt.json` | `f48c3fa41de8df649260e3c16fa3361f0c4b65e28c70e431baee8d887bcf4490` |
| Refreshed 341-package base inventory | `89bdb06fea1862b5a6e02b77a4b98f6e04755b02327d875a716bd792929f3a4f` |
| Extension 354-package `expected-packages.lock` | `d5e2b02a4af36b763c24c0eded8d4b7326874448996f94126fbfc3f787946271` |
| `linux-closure.py` reviewed version | `794e55e2f15cea879dc6346df9dd43a326fb63a85df55546b00acaea9df6455f` |
| `linux-closure-proposal.json` | `13ad09471d3e9002af0a4b727c9f9d15de26b86f42b8715c109e98075e384ded` |
| `build-script-review.json` | `11e687a1633cd09db2a24a9a6f7c32086a86e83dec615ec08a05143ed273ac49` |

Exact additions are bats 1.14.0-1, compiler-rt 23.1.1-1, git 2.56.0-1, libgit2 1:1.9.7-1, lld 23.1.1-1, llhttp 9.3.1-1, parallel 20260922-1, perl-error 0.17030-3, perl-mailtools 2.22-3, perl-timedate 2.35-1, rust 1:1.99.0-1, scdoc 1.11.5-1 and zlib-ng 2.3.3-1. Rust supplies Cargo/rustfmt and the native aarch64 standard library; compiler-rt/lld require 23.1.1, while llvm-libs 23.1.1-1 is retained in the baseline. The extension additionally pins existing glib2 2.90.1-1, gettext 1.0-2, pkgconf 3.0.7-1, python 3.14.8-1 and make 4.4.1-3. Declared toolchain licenses/source URLs and aarch64 ELF observations are retained, but complete corresponding-source/license closure for these external toolchain packages is explicitly **NOT ESTABLISHED**. Git contains one unexecuted `.INSTALL` scriptlet (SHA-256 `afe63da01ad0808371c99bb21865bd56a5cd2fee3efdd0372d98cde9310f3ca5`); the other 12 addition observations report no hooks/scriptlets. Worker creation must account for installation effects inside the disposable worker. No compiler/package/service action belongs on this host. Installation, compiler execution, updater build, 16K runtime and hardware are **NOT RUN** in the receipt.

For the conservative metadata scope, independent rehashing now covers **123 registry archives, 6019 source-file checksum entries (88,792,722 bytes), 228 retained notice entries and 20 build-script hashes**. With the local tray this is **124 packages**, not 124 registry crates and not a measured compilation-unit count. The seven extra packages listed above add three script candidates: defmt, defmt-macros and thiserror. The original manifest, lock, all-target source audit and vendor bytes remain unchanged. This is checksum/source binding; no blanket safety, license-compatibility, native-build or publication acceptance follows from it.

`linux-closure.py` is a data-only validator/retainer. It binds original manifest/lock/audit pins, validates native-worker/target metadata and cfg evidence, follows reachable typed dependency edges and declared feature forwarding, rehashes selected vendor files/scripts, rejects historical macOS blockers, requires `gettext-system`, forbids `system-deps/binary`, and labels metadata feature unions and worker-origin limits explicitly. Its JSON worker declaration cannot authenticate itself: the coordinator must match it against actual retained worker commands, logs and immutable image/inventory. Its retained selected vendor directory is an inert source record; it is **not** a proven standalone offline Cargo source. The unchanged lock can still require excluded manifests, as the omitted-four experiment demonstrated. Do not wire the selected record directly into Cargo’s directory source and claim subset resolution succeeded.

**Concrete pre-compilation defect in this reviewed validator:** line 389 refuses every selected `license_evidence_blockers` entry in the unchanged all-target audit, and accepts no supplementary notice input. That audit still marks defmt-parser 1.0.0 “No retained license/notice text in registry archive”; the 124-package metadata graph selects it. `additional-cargo-licenses.json` already supplies exact complete notice/source evidence, but the validator never consumes it. Therefore this reviewed version will refuse that graph even though the supplemental notice gap is closed. The owner should bind and verify the supplemental evidence for that exact archive/version/source match in a separate derived private-scope record, preserving the raw original audit and refusing unresolved four-package entries. Do not erase original findings, treat all supplemental entries as accepted, or label compatibility/distribution passed. Retain the exact MIT notice and source-match evidence in the private record; a compiled package’s notice collection remains a separate gate. This is a source-audited refusal condition, not an executed native-worker validation result.

## Selected build-script effects

All hashes below were independently matched to the retained sources and vendor checksum manifests; no script was executed.

| Build-script candidate | build.rs SHA-256 |
| --- | --- |
| `anyhow 1.0.104` | `89d1baedcff59822ed692d3a33f131c211a213bdec33c83f68b54110d9c64223` |
| `gettext-sys 0.27.0` | `8b7e5d9a63db1508d86e10bb9f3af7db1114dc4ca7eee1f1f7b3749d0f7fb7b0` |
| `gio-sys 0.22.9` | `23d6cc74e67684f75fd152ed1c5885c2eda1d80a4061b82c04f34130b140eede` |
| `gio-unix-sys 0.22.9` | `23d6cc74e67684f75fd152ed1c5885c2eda1d80a4061b82c04f34130b140eede` |
| `glib-sys 0.22.9` | `23d6cc74e67684f75fd152ed1c5885c2eda1d80a4061b82c04f34130b140eede` |
| `gobject-sys 0.22.9` | `23d6cc74e67684f75fd152ed1c5885c2eda1d80a4061b82c04f34130b140eede` |
| `inotify-sys 0.1.8` | `8070368f4661803c760dc05c9946f654af5ca54a0b224abc3c10f01e5e295a3a` |
| `libc 0.2.189` | `e47f4a6762799b6e69cefc7acdb3291df828010e4de20609f7378f9c94ea29e6` |
| `proc-macro2 1.0.107` | `baeb20b52f6b536be8657a566591a507bb2e34a45cf8baa42b135510a0c3c729` |
| `quote 1.0.47` | `cd6808c02e476b09a520105e2c6f6d325cccb1ecd542cbbcc836a0ae6f6fb0f1` |
| `rustix 1.1.4` | `74cb32e64aa6fe99c2496a425b016e22f4e43c438a8237966b8acae04a98eaf9` |
| `serde 1.0.229` | `e2ea6a7a82f5404c3e28cb055883c737ee7903367a10206fbb47b75c009f0eb3` |
| `serde_core 1.0.229` | `7bc6b1eec8913ff4cd8e4b9b92cd04a82a4f38beb30a0b73a64c1e6e49f07b5f` |
| `serde_json 1.0.151` | `a681e754be844c7dbef957f5d2d00b01f37c5dca160ef1055a8d8f975697a881` |
| `system-deps 9.0.0` | `9dfb922d1cc32726decedbbb5abcc463c1ce978e751a45fb9199a178ebef6c7d` |
| `target-lexicon 0.13.5` | `678ba872ef2254e8901d6a00536f64d74d375d919f845113bd3ded709b6edb4a` |
| `zmij 1.0.23` | `ad320bc635887879bdbbf1b9322da4a157ec2c5a4243bd7c2cf9b6884a3b2a41` |

For the conservative 124-package graph, the three additional script candidates were also read and rehashed independently:

| Additional candidate | build.rs SHA-256 | Inspected effects |
| --- | --- | --- |
| `defmt 1.1.1` | `9477326f9231bbbbb894499e9c3b28f70f06bc37ce08527def13d7fc634db1c7` | Reads `defmt.x.in`, writes `OUT_DIR/defmt.x`, emits link-search/cfg; optional panic-handler removal. No subprocess/network. Writing the template does not itself pass `-Tdefmt.x`. |
| `defmt-macros 1.1.1` | `e95adebcba8785d938de75f1555c0baf2ab7a7bf527c01fb9a5f36380fc4a2aa` | Only prints `rerun-if-env-changed=DEFMT_LOG`; no writes/subprocess/network. |
| `thiserror 2.0.20` | `ccc38283604f99237ad2333bbe395259e29fdf2ff4e04a60a95de9e4499c09a3` | Generates `OUT_DIR/private.rs`, queries rustc, compiles metadata probe under `OUT_DIR/probe`, then removes it; no probe output execution. |

The defmt linker template (1574 bytes; SHA-256 `59268a679b5d7c530b2583ebe11c6bf2503447c3b3d80acc02bff2aa4f0a94b7`) declares symbols/section placement. Its no-CAS target list excludes aarch64 Linux. The thiserror probe (844 bytes; SHA-256 `8df55471d6b75623d423b17ebbf493335ee66140d1ddd232c88db3e59f61298c`) has no process/filesystem/network operations. Thiserror inherits wrapper/encoded-flag settings and responds to RUSTC_STAGE/BOOTSTRAP, so the same pinned-tool/environment restrictions apply. None of the seven added packages contains detected ELF/Mach-O/Wasm/native archive magic or embedded archive suffixes in the independently scanned 299 checksum-listed files. This is bounded input inspection, not a whole-library security audit.

`defmt-macros` and `thiserror-impl` are compiler-executed procedural macros. Their inspected expansion/helper paths and operation scan found no direct filesystem/process/network APIs; defmt reads `DEFMT_LOG`, `CARGO_CRATE_NAME` and `CARGO_PKG_NAME`. Clear external `DEFMT_LOG`; preserve Cargo’s verified generated facts. Defmt symbol disambiguation hashes the debug representation of `Span::call_site()`, so source inspection cannot promise byte reproducibility. The retained thiserror `rust-toolchain.toml` requests rust-src without a channel; use absolute authenticated native tool binaries rather than rustup shims or execution from a vendor directory. All procedural macros remain confined executable inputs.

Six added packages retain complete MIT/Apache license texts. For defmt-parser, the independent read-only source comparison rechecked the pinned upstream archive (`0e5f4244d6418305ed6fc363c86c7e1e2effa72744cc14605384b69e69479bfc`, commit `4a8cdb44891ed57b8ff5a023b6bec7137c48708f`), all six compared crate files, and both exact parent licenses. MIT notice SHA-256 is `2710a622a896bba67356913d4d0492cab5465f61b2ecce6d880aeb483834fb50`; Apache notice SHA-256 is `8173d5c29b4f956d532781d2b86e4e30f83e6b7878dce18c919451d6ba707c90`. Retain those bytes and source-match evidence in a derived private-scope collection; license compatibility/publication acceptance remains separate.

The five probe/code-generation scripts (anyhow, proc-macro2, quote, target-lexicon, zmij) invoke the selected compiler for version/probe queries, emit cfgs and, where applicable, write generated source/metadata under `OUT_DIR`. Anyhow/proc-macro2 probes compile metadata libraries and remove their probe directories; they do not execute the generated target code. Target-lexicon writes `host.rs` from `TARGET`. No direct network, package/service action or privilege change was found.

libc runs rustc/version probes and attempts PATH-resolved `emcc -dumpversion` even on Linux; `LIBC_CI` also enables `freebsd-version`. rustix invokes compiler metadata probes with target and encoded Rust flags under `OUT_DIR/rustix_test_can_compile`; the ordinary aarch64/64-bit path selects retained raw syscall assembly (`src/backend/linux_raw/arch/aarch64.rs`, SHA-256 `12bb15064d25f0ed08e9eb8842c7dd570393222365b5a33206adc97406d2c061`). Overrides/Miri/libc/experimental flags change selection. Serde/core generate `private.rs` and query compiler version; serde_json emits aarch64 arithmetic cfgs. Inotify's external pkg-config/fallback branch applies to BSD, not Linux. These observations support controlled source execution, not actual ABI/16K/runtime acceptance or a performance claim.

The four identical GLib/GIO sys scripts call `system_deps::Config::new().probe()` and fail on unresolved native libraries; `DOCS_RS` bypasses linking and must be unset. Current features request the baseline pkg-config names `glib-2.0`, `gobject-2.0`, `gio-2.0`, `gio-unix-2.0` at ≥2.56. Native pkgconf/GLib headers, libraries and every linked library's source/license/provenance must come from the authenticated extension transaction. Freeze/unset unreviewed `PKG_CONFIG*`, `SYSTEM_DEPS_*`, static-link/build-internal overrides and wrappers; no substitute host sysroot can supply ARM proof.

`system-deps` enables only empty default features in the observed tree. Its `binary` branch downloads prebuilt inputs, but is not activated here. Its two flagged `.a` files are **zero bytes**; three tiny test archives contain only pkg-config/empty-archive fixtures, outside normal target execution. Their original hashes were checked. Nonempty Windows import archives belong to excluded Windows-specific crates; they still require attribution/provenance in the full retained bundle.

`gettext-system` is active in both filtered outputs and forwards through gettext-rs to gettext-sys. Linux GNU/musl returns before GETTEXT_DIR/BIN/LIB overrides and bundled extraction/configure/make/install. Therefore the embedded 10,405,692-byte gettext-1.0 archive (`20e3d2d679e74d64248b49b6ac00eeb516844413c75f69d3a4fb1a4790981670`) is dormant for this branch. It is not uniformly MIT: wrapper code is MIT; libintl source declares LGPL-2.1-or-later, while programs/documentation carry other GPL terms. Full vendor/source publication must retain/reconcile those notices even when the compiled GNU Linux tray uses system gettext symbols. [GNU gettext licensing](https://www.gnu.org/software/gettext/manual/html_node/Licenses.html).

`--offline` constrains Cargo's own retrieval, not arbitrary compiler/proc-macro/build-script subprocesses. The outer native container must independently disable networking, expose no host home/session bus/credentials/sockets/package database/devices, and run compilation non-root with dropped capabilities. Freeze PATH, actual compiler/linker/stdlib, Rust/makepkg config, target and `OUT_DIR`; clear unreviewed RUSTC_WRAPPER/WORKSPACE_WRAPPER/BOOTSTRAP/STAGE and encoded/RUSTFLAGS overrides. All procedural macros/compiler plugins execute inside that same boundary. [Cargo build scripts](https://doc.rust-lang.org/cargo/reference/build-scripts.html).

## Recipe, platform behavior and next native gates

The pinned Makefile builds the real tray, manuals and translations in its tree. `install` honors DESTDIR and enables no service or tray process. PKGBUILD invokes Cargo once with frozen/offline/locked flags, then `make WITH_TRAY=false` avoids a second implicit Cargo build; the binary is retained during staging. `check()` supplies private HOME/XDG paths because even help/version source common initialization creates state directories. Bats/source mock checks cannot replace installed native tray and private-bus menu/action checks.

The original four behavior patches retain dated GPL modification notices and fix GIO argument quoting, activation failure propagation, pre-operation Flatpak prompting and cooperative upgrade locking. In that original reviewed recipe snapshot, remaining runtime gates include the PC/generic `/usr/lib/modules/$(uname -r)/vmlinuz` reboot heuristic, service restart handling without Asahi speaker-protection/audio policy, optional ALHP/AUR paths, cache/orphan removal, disabled automatic pacnew handling, and `--check` error propagation before apparent no-update state. No explicit bootloader/chwd operation was found in inspected source; no Apple update/recovery safety is inferred. The owner subsequently added a separate caller-pinned Apple policy helper/patch (`asahi-policy.py` SHA-256 `80cda05980b064a9cb2ad47e5525ddba03dbaefaf350d44d18a27c63ac1ffbaf`; `apple-policy.patch` SHA-256 `8201ed41b9790cbb004f3ce62d80ce1e9f25d314e7ef685ffea44d2f1594b783`). It explicitly ships no accepted target policy; the inspected PKGBUILD still does not include these new files. Its separate source/mock checks do not establish package integration, actual policy/observation collection, native/private-bus behavior or protected-machine recovery. A revised recipe/adapter must pin exactly which patches it builds. Real native/private-bus testing must use command-recording stubs for system-changing endpoints, before exact-machine trials with a frozen protected-platform policy.

The next finite build trial should:

1. Resolve the closure validator’s defmt-parser supplemental-evidence refusal above, then bind a private compilation adapter to the actual native metadata/cfg/image and conservative 124-package source graph (20 script candidates). Preserve the 117-package normal/build observation, full-vendor unresolved notices and 38-script inventory separately. Do not weaken the existing distribution recipe gate.
2. Materialize the **separate authenticated extension** in a new isolated worker, verifying its full 354-package inventory and immutable image ID. Retain its exact archives/signatures and source/license observations; verify native Rust/Cargo version/host, compiler/linker/stdlib, pkgconf and GLib/gettext development inputs. The authenticated data-only receipt does not prove installation or execution. Do not mutate the original successful four-package builder.
3. Materialize both exact source archives in a new recipe snapshot; they are absent from the checked-in recipe folder. Keep source/vendor inputs read-only and private HOME/CARGO_HOME/work/target/output separate. No compiler/service/package install on this host.
4. Run a bounded native Linux aarch64 GNU compile with accepted default features and no network, capturing actual unit/features/build-script commands and linkage. Begin with finite CPU/memory/PID/disk/time limits; 88 MiB source bytes are not a peak RAM/object-space estimate. Record any limit failure and revise the budget, rather than hiding a failed crate.
5. Repeat in a second clean environment; inspect actual aarch64 ELF dependencies and 16K-congruent LOAD segments, then compare artifacts. Current static ELF gate/synthetic tests prove no loader result. Keep private compilation, licensed packaging, private-bus functionality, target installation/removal/recovery and production release gates distinct.

## Observed normal/build tree package set

Each registry name/version below binds to its unchanged Cargo.lock checksum and the separately rehashed original archive. Features are retained in the hashed `tree.txt`/selected-closure record. This is the observed filtered tree, not a claim that native Cargo has compiled every item or that a later toolchain/config preserves identical unit selection.

```text
aho-corasick@1.1.5, anstream@1.0.0, anstyle@1.0.14, anstyle-parse@1.0.0
anstyle-query@1.1.5, anyhow@1.0.104, arch-update-tray@4.4.2, async-broadcast@0.7.2
async-recursion@1.1.1, async-trait@0.1.92, bitflags@2.13.2, bytes@1.12.1
cc@1.4.6, cfg-expr@0.20.9, colorchoice@1.0.5, endi@1.1.1
enumflags2@0.7.12, enumflags2_derive@0.7.12, env_filter@2.0.0, env_logger@0.11.11
equivalent@1.0.2, errno@0.3.14, event-listener@5.4.2, event-listener-strategy@0.5.4
fastrand@2.5.0, find-msvc-tools@0.1.12, futures-channel@0.3.34, futures-core@0.3.34
futures-executor@0.3.34, futures-io@0.3.34, futures-lite@2.6.1, futures-macro@0.3.34
futures-task@0.3.34, futures-util@0.3.34, gettext-rs@0.8.0, gettext-sys@0.27.0
gio@0.22.9, gio-sys@0.22.9, gio-unix@0.22.8, gio-unix-sys@0.22.9
glib@0.22.9, glib-macros@0.22.9, glib-sys@0.22.9, gobject-sys@0.22.9
hashbrown@0.17.1, heck@0.5.0, hex@0.4.3, indexmap@2.14.2
inotify@0.11.5, inotify-sys@0.1.8, is_terminal_polyfill@1.70.2, itoa@1.0.18
jiff@0.2.37, jiff-core@0.1.1, ksni@0.3.6, lazy_static@1.5.0
libc@0.2.189, linux-raw-sys@0.12.1, locale_config@0.3.0, log@0.4.34
memchr@2.8.3, mio@1.2.3, notify@8.2.0, notify-types@2.1.0
once_cell@1.21.4, ordered-stream@0.2.0, parking@2.2.1, pastey@0.2.3
pin-project-lite@0.2.17, pkg-config@0.3.34, proc-macro-crate@3.5.0, proc-macro2@1.0.107
quote@1.0.47, regex@1.13.1, regex-automata@0.4.18, regex-syntax@0.8.11
rustix@1.1.4, same-file@1.0.6, serde@1.0.229, serde_core@1.0.229
serde_derive@1.0.229, serde_json@1.0.151, serde_repr@0.1.21, serde_spanned@1.1.1
shlex@2.0.1, signal-hook-registry@1.4.8, slab@0.4.12, smallvec@1.16.1
socket2@0.6.5, syn@2.0.119, syn@3.0.5, system-deps@9.0.0
target-lexicon@0.13.5, temp-dir@0.1.16, tokio@1.53.1, tokio-macros@2.7.2
toml@1.1.6+spec-1.1.0, toml_datetime@1.1.1+spec-1.1.0, toml_edit@0.25.15+spec-1.1.0, toml_parser@1.1.3+spec-1.1.0
tracing@0.1.44, tracing-attributes@0.1.31, tracing-core@0.1.36, unicode-ident@1.0.24
utf8parse@0.2.2, uuid@1.26.1, version-compare@0.2.1, walkdir@2.5.0
winnow@1.0.4, zbus@5.19.0, zbus_macros@5.19.0, zbus_names@4.3.4
zcheapstr@1.1.0, zmij@1.0.23, zvariant@5.15.0, zvariant_derive@5.15.0
zvariant_utils@4.2.0
```

Result: **independent source review advances the private Linux build plan; native build/distribution/platform gates remain open.** No shared manifest, recipe, updater, original integration/client freeze or Git state was edited. This report does not complete any full-port acceptance gate.

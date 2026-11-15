# Rust 1.99 source reference candidate

[`packages/port/rust199-source-reference`](../../packages/port/rust199-source-reference/README.md) is a separately named, opt-in **original** source candidate. It builds a private-prefix Rust 1.99 compiler/tool set rather than recovering the four unresolved official binary recipes. Nothing is selected in the shared package inventory, and no system provider or Asahi platform component changes.

## Fixed inputs and source choices

`inputs.json` pins Rust commit `b940084d7eb6a299eb4bfeb8e34901bc051e7ac4`, Rust source archive SHA-256 `cc41916a8c84f5d9ec4f55561b44e39f43b647b133f8a6f51be9ea13c83f7036`, LLVM commit `6dfe1677ab8dffbc6ec13d53a1e0215d75147689`, and LLVM 23.1.1 archive SHA-256 `ebe9be46fe8756d58c5b198ffad0fa2a766257add81a4dc52179bfacc7888ee6`. These reuse existing retained source inputs; the qualification must rejoin their owning authentication evidence before use. No new archive acquisition occurred.

Three additional local archive requirements come only from the exact retained Rust `src/stage0` metadata (SHA-256 `759b73eca37a7b589b1ecc0fea77d94a1f8ca36cddb94f1401c72343e0dc1d4e`): rustc, cargo and rust-std **1.98.0**, dated 2026-08-20, for `aarch64-unknown-linux-gnu`. Their exact `.tar.xz` URLs and SHA-256 declarations are in the manifest. They are declarations, not fetched, authenticated or qualified bootstrap artifacts. Initial rustdoc comes from the rustc component. No initial rustfmt is selected; the install path builds the requested new Rustfmt component.

The candidate uses the dist stage-2 plan and preserves its seven requested tools: Cargo, Clippy, rustdoc, Rustfmt, proc-macro server, analysis and src. The exact bootstrap revision has no standalone Analysis install step; preserving that requested string does not claim analysis output. Books, GCC codegen, Enzyme, CI downloads, sanitizers and the LLVM bitcode linker remain disabled. Native build/host/target are all explicitly AArch64. No PC target patch, M2 tuning, page-size override or performance claim is introduced.

This original reference applies **none** of the six downstream historical recipe patches. Its upstream stage0 lives in a dedicated prefix assembled from the pinned upstream components, rather than a system `/usr` sysroot. It retains upstream target, libexec and completion placement inside the private prefix. `rpath=true` is an intentional change from the system recipe for libraries under the private prefix; actual loader/runpath behavior still needs build and runtime verification.

External LLVM is constrained to the separately named private `cachy-asahi-llvm23-source-reference=23.1.1` package under `/opt/cachy-asahi/llvm23-source-reference`. The admitted image must contain its tools there; global LLVM packages do not satisfy that prerequisite. The fixed bootstrap config selects its `llvm-config`, the sanitized build PATH selects its linker, and the supported `rust.rustflags` setting adds its private library directory to link-time runtime search paths at every stage. Existing Rust-origin RPATH behavior remains enabled; actual ELF linkage/runtime behavior still needs a real build. `src/llvm-project` is joined to the supplied separate upstream LLVM source; `compiler-rt/lib/builtins`, `compiler-rt/lib/profile` and `libunwind/src`, plus their notices, are required. The unused Rust LLVM fork is not fetched. Profiler and AArch64's optimized compiler-builtins source use remain enabled; rust-src copies libunwind and vendors the library workspace.

## What must be supplied before a build

The recipe has **local source names only**, all checksummed, with all five archives marked `noextract`. Place the exact local archives in the package directory or makepkg's local source cache. Missing materials stop; the recipe/helper implements no downloader. Native dependencies must already be supplied separately; makepkg dependency installation is not authorized or invoked by this work.

Copy `admission.example.json` to an external qualification record and fill it only after establishing these inputs:

1. A clean native AArch64 dependency filesystem image with a complete canonical tree digest. It must contain the ordinary build environment, native Python >=3.12, GCC/G++, gcc-ar/gcc-ranlib, binutils, make, CMake, Ninja, Perl, bash, pkg-config, the private clang/LLVM/LLD/compiler-rt **23.1.1** candidate, and development/runtime dependencies including libffi, curl, libgit2, libssh2, OpenSSL, SQLite and zlib. It needs empty real mount directories `/work`, `/stage0`, `/proc`, `/dev`, `/tmp`. It may contain regular files/directories/symlinks, but no sockets, FIFOs or device nodes. The sandbox mounts its own proc/dev/tmp. No user homes or service endpoints are bound from the host.
2. The exact stage0 archives, their authenticated provenance and inspected component layout, and an independently qualified assembled prefix with a fixed canonical tree digest and compatible libraries. The proposed component directories are `rustc`, `cargo` and `rust-std-aarch64-unknown-linux-gnu` under each archive's named root. This layout has not been observed in this task. Qualify byte identity, native architecture, loader closure and compatibility with this source before setting the record's stage0 status. The recipe reconstructs that prefix and checks the expected digest before any stage0 execution; it never runs a stage0 installer.
3. A source audit tied to these exact archives: owning authentication records, generated library Cargo replacement configuration hash, active git dependency/source paths, compiler-rt/libunwind coverage and relevant notices. The known root/main/Cargo/bootstrap/library lock/config hashes are fixed in `inputs.json`. The helper checks replacement containment, complete vendor file sets/checksums and registry package-checksum joins for four locks. Those checks do not replace review of git dependency identity, applicable notices or build-script consumption.
4. A retained qualification evidence file with its SHA-256, and the qualification record's own explicit SHA-256. Its statuses attest input readiness for this private candidate only; all existing legal/source/binary/hardware holds must remain preserved. The bundled example is deliberately `UNQUALIFIED`, with no fabricated digests or success evidence.

The canonical image/prefix inventory can be calculated without executing its contents:

```sh
python -I packages/port/rust199-source-reference/reference.py inventory --work /absolute/qualified-tree
```

The digest binds relative paths, entry types, permissions, symlink text and file bytes. It omits owners/timestamps; it does not attest a machine or qualify the image's compatibility. Keep the image and work roots disjoint, owned and free of concurrent mutation. The image is mounted read-only throughout publisher execution. Stage0 is read-only at both `/stage0` and its `/work/stage0` alias. Prepare copies authenticated makepkg source symlinks to real material files and rechecks their bytes before extraction.

Once those inputs and a disk/RAM/time budget are established, the planned ordinary-user command is:

```sh
CACHY_ASAHI_RUST199_BUILD=1 \
CACHY_ASAHI_RUST199_ADMISSION=/absolute/qualified-inputs.json \
CACHY_ASAHI_RUST199_ADMISSION_SHA256=EXACT_64_HEX_DIGEST \
makepkg --cleanbuild
```

This command has **not** been run. Prepare/build refuse root or a non-native host. The data-only package phase permits makepkg's fakeroot while still refusing a kernel-root process. The host must already have Python >=3.12, libarchive's bsdtar and bubblewrap. Do not use an automatic dependency/download option. A complete archive copy plus extraction, stage0 staging and a stage-2 compiler build require a separately measured resource plan; the prior metadata-collection budget does not qualify this build.

## Planned build and package behavior

Before compiling, the sandbox probes the admitted stage0 versions/sysroot/host and external LLVM version/AArch64 backend, native GCC and LLD version. It then runs `python -I ./x.py --config bootstrap.toml install -j 2`, with `DESTDIR=/work/dest`, under bubblewrap's unshared namespaces and read-only dependency image. The environment is cleared, HOME/CARGO_HOME are new private directories, and Cargo offline mode also covers rust-src's separate `cargo vendor` invocation. The retained libgit2/SSH2/SQLite system-library switches are explicit. Failure of probes, vendoring, namespace setup or compilation stops without a fallback.

The recipe stages only `/opt/cachy-asahi/rust199-source-reference`. It checks required rustc/cargo/rustdoc/Rustfmt/Clippy/proc-macro/server and rust-src paths and executable modes, rejects global payload and escaping symlinks, removes the private upstream uninstaller/installation ledger, and retains Rust root notices, LLVM compiler-rt/libunwind notices, input provenance and original packaging MIT license. Existing upstream component notice output is otherwise preserved. Complete third-party source/license delivery remains held; collecting these files is not a license audit.

Runtime dependencies are declared explicitly, including the private LLVM23 source-reference package and the retained system-library set. There are no global provides/replaces/conflicts, installation hooks, services, alternative registrations or PATH edits. Users would invoke the private binaries by absolute path or choose their PATH themselves. ALPM removal would remove only package-owned files; this work has not installed or tested that lifecycle.

## Actual results and remaining work

Fourteen author-owned static/refusal controls and Bash syntax/PKGBUILD–SRCINFO checksum checks passed. They cover changed/missing inputs, unqualified refusal, makepkg source symlinks, fakeroot versus real-root guards, private native configuration, stage0 declarations, vendor integrity, source containment, sandbox arguments and private layout. Independent source review found the makepkg/fakeroot/stage0-alias issues and the implementation addresses them. No compiler, archive extraction, makepkg, native job, daemon, installation or network acquisition was run.

Remaining work is concrete: obtain/authenticate/qualify the declared stage0 inputs; qualify and pin the complete LLVM/native dependency image; verify archive library config/locks/vendor/source/notice closure and stage0 layout; measure the build resource budget; execute the sandbox and package pipeline; inspect generated linkage/private runtime behavior; then perform repeated native builds and disposable package lifecycle checks. ARM16K, both M2 Air sizes, measured performance and release acceptance remain separate and **NOT RUN/NOT ADMITTED**. All license108 holds and four original binary recipe SHA mismatches remain unresolved.

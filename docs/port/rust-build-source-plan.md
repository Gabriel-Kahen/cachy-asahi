# Rust source needs for the retained proposed recipe

The twelve submodule identities are not twelve demonstrated build blockers. The retained recipe selects a stage-2 `x.py install` with the dist profile, LLVM codegen, external LLVM, Cargo/Clippy/rustfmt, rustdoc/proc-macro server, and rust-src. Documentation books, Enzyme and GCC codegen are not selected. This is source review only: no patch application, compilation, installation, VM or hardware execution occurred.

The machine-readable plan, pinned evidence and offline checker live in [`build-source-plan`](../../scripts/port/arm-rust-toolchain-inputs/source-closure/build-source-plan/README.md). The owning source is Rust commit [`b940084d7eb6a299eb4bfeb8e34901bc051e7ac4`](https://github.com/rust-lang/rust/tree/b940084d7eb6a299eb4bfeb8e34901bc051e7ac4). The plan reads the existing recipe as data; it does not change it.

## What the install path consumes

The retained dist profile sets build-stage=2, extended=true and download-rustc=false. The recipe overrides channel=stable, docs=false, profiler=true, locked-deps=true, vendor=true and llvm-bitcode-linker=false. Config defaults codegen-backends to `[llvm]` and llvm.enzyme to false. External `/usr/bin/llvm-config` returns through the prebuilt-LLVM path; disabling GCC downloads alone would not disable GCC codegen.

| Declared submodule path | Role in this recipe | Remaining evidence |
| --- | --- | --- |
| `src/tools/cargo` | Active Cargo install; 2,949 regular archive members previously observed | Exact payload identity, recursion and notices held; no specific missing file established |
| `library/backtrace` | Bootstrap startup and std source inclusion; 101 archive members observed | Exact payload identity, recursion and notices held; no specific missing file established |
| `src/llvm-project` | Rust fork is intentionally replaced with separate upstream LLVM 23.1.1 source | External binary LLVM plus compiler-rt and libunwind source still required; consumed-member/license closure held |
| `src/doc/nomicon` | Docs disabled | Not a blocker for this selected build; redistribution obligations remain |
| `src/doc/reference` | Docs disabled | Same |
| `src/doc/book` | Docs disabled | Same |
| `src/doc/rust-by-example` | Docs disabled | Same |
| `src/doc/edition-guide` | Docs disabled | Same |
| `src/doc/embedded-book` | Docs disabled | Same |
| `src/tools/rustc-perf` | Perf/OptimizedDist not selected by install | Not an input merely because it appears in general Vendor's workspace list |
| `src/tools/enzyme` | llvm.enzyme defaults false | Becomes relevant if Enzyme is enabled |
| `src/gcc` | Default codegen backend is LLVM | Previously established lower bound of 45 missing direct root files remains real, but inactive for this recipe |

The Rust LLVM fork gitlink and the upstream LLVM release are different identities. `prepare()` removes the former source directory and substitutes the separate LLVM archive. Fetching that unused fork would not close the intended recipe's external LLVM inputs.

External LLVM does not eliminate source consumption. `compile.rs:502–523,582–638` supplies `src/llvm-project/compiler-rt` for the enabled profiler and, for AArch64's stable default, optimized compiler builtins. The AArch64 target lacks the x86 target's prebuilt builtins override. `dist.rs:1162–1224` copies `library` and `src/llvm-project/libunwind` into rust-src, then vendors its library workspace. Coverage of these exact substituted source paths remains to be verified.

`install.rs` and `builder/mod.rs:981–1002` select Rustc/Std, Cargo, Clippy, Rustfmt and Src. `dist.rs:532–553` bundles the requested rustdoc and proc-macro server with Rustc. `analysis` is a requested string with no standalone Install step; the Dist Analysis implementation is a removed-component placeholder. The tools list alone is not proof that an analysis artifact is installed. `docs=false` gates documentation output, not the requested rustdoc executable.

## Initial toolchain and network requirements

The recipe explicitly uses `/usr/bin/rustc`, `/usr/bin/cargo` and `/usr/bin/rustfmt`. `config.rs:838–858` derives `/usr/bin/rustdoc` from the initial compiler and asks that compiler for its sysroot. The declared unversioned `rust` make dependency does not pin compatible initial binaries, matching standard libraries, architecture or provenance.

`bootstrap.py:603–625` checks for missing/outdated rustc/cargo only when their paths begin with the bootstrap bin-root. The configured `/usr/bin` paths do not select that fallback download branch. Retained `src/stage0` declares fallback compiler 1.98.0 dated 2026-08-20, commit `88d9e12ae178fab0fb5cc050a94da85685d449ea`; this is not a requirement to download it when system providers are selected. No stage0 binary was fetched. The system-stage0 patch's old sysroot-copy preimage is present at `compile.rs:821`; applicability and resulting behavior have not been tested.

The recipe disables CI Rust/LLVM/GCC downloads. Bootstrap compilation and normal Cargo invocations append `--locked` and `--frozen` with the selected flags. However, rust-src invokes `cargo vendor --versioned-dirs --respect-source-config --config <source>/library/.cargo/config.toml`; that branch has no explicit `--offline` or `--frozen`. Its `only_library_workspace=true` bypasses the general Vendor list containing books/perf/GCC-related workspaces. Offline success still depends on exact library source replacement configuration and vendored payload, compatible initial Cargo, and controlled ambient configuration.

The newly collected pinned bootstrap/library locks contain 120/30 registry entries, all matching name/version/package-checksum declarations from the earlier archive inventory. This extends the earlier root/Cargo lock declaration comparison. It verifies neither archive membership of these new Git lockfiles nor per-file checksums, Cargo resolution, licensing or offline behavior. The earlier scan did not select library source configuration; a null Git lookup is not evidence that the generated release tarball lacks it.

Bootstrap's source mode also matters: `channel.rs`, `config.rs:2688–2692` and `lib.rs:662–708` distinguish a release tarball with `git-commit-info` from a managed Git checkout. A future candidate must preserve and verify the release stamp and lack of `.git`, or explicitly review different submodule behavior. This task did not re-scan those archive members.

## Concrete remaining inputs

1. Review an explicit AArch64 derivation. The raw recipe declares only `arch=(x86_64)`; its AArch64 target stanza and jemalloc page-size environment assignment do not establish build support. The retained SRCINFO additionally lists architectures, split packages, patches and config inputs absent from the raw recipe. They cannot be silently combined into an original recipe.
2. Pin compatible AArch64 initial rustc/cargo/rustdoc/rustfmt, sysroot/std and native dependencies. Pin LLVM/clang/lld/compiler-rt 23.1.1 binaries and verify the LLVM configuration and its compatibility with the supplied source.
3. Verify active archive manifests/locks, root/library Cargo source configuration, source stamp, vendor file checksums and applicable notices. Verify compiler-rt/libunwind member coverage and licenses in the substituted LLVM archive.
4. Check all six retained patches against exact source and inspect their output. Freeze ambient Cargo/bootstrap configuration, then design a bounded no-network build with an explicit resource plan.

All four original binary recipe SHA-256 mismatches remain **UNRESOLVED**, individually recorded in the plan for Rust, compiler-rt, LLVM/llvm-libs and LLD. This proposed source plan does not recover those recipes, establish full source/license closure, demonstrate an ARM build, qualify M2/16K behavior, measure performance or admit a release.

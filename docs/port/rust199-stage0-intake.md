# Rust 1.99 candidate: stage0 archive intake

The candidate's three missing stage0 archives are now **actually retained and checksum verified**. This closes archive availability and observes the expected component layouts as DATA. It does not qualify an initial toolchain, construct a native environment, or authorize publication. The candidate's existing input selector and unqualified admission example remain unchanged.

| Original archive | Actual bytes | Whole SHA-256 |
| --- | ---: | --- |
| cargo-1.98.0-aarch64-unknown-linux-gnu.tar.xz | 11,116,188 | `5784379d73ac881d15a9e67eed2882cd58c747c276221c23cdf9aff37e015ff6` |
| rust-std-1.98.0-aarch64-unknown-linux-gnu.tar.xz | 30,768,752 | `a36f7ac98af20ef0ba6368aace0345efabbebaef7962eba99f47190fd256162d` |
| rustc-1.98.0-aarch64-unknown-linux-gnu.tar.xz | 66,413,136 | `00590657f2356d7163ca5ef295283523974c340fa21bb94b420ce794f29b358c` |

The three original URLs are exactly the retained `https://static.rust-lang.org/dist/2026-08-20/` declarations in candidate `inputs.json`; no alternate version or source was selected. Each was fetched once over verified TLS, with no redirects or retries. Total response bodies: **108,298,076 bytes / three requests**, within the cumulative 300 MiB/eight-request budget. Acquisition took 1.746 s, with a 512 MiB address-space limit and 1200 s deadline. Streaming storage checks refused below 1 GiB available;1,933,299,712 bytes remained at completion. A named-file search first covered 43 retained project directories and found no copies; four permission-denied paths remain unexamined, recorded explicitly.

The compressed originals remain private, untracked files on `/home`:

```text
/home/gabe/Documents/ChatGPT/cachy-asahi-rust-submodule-closure-20261115/packages/port/rust199-source-reference/stage0_intake/work/artifacts/cargo-1.98.0-aarch64-unknown-linux-gnu.tar.xz
/home/gabe/Documents/ChatGPT/cachy-asahi-rust-submodule-closure-20261115/packages/port/rust199-source-reference/stage0_intake/work/artifacts/rust-std-1.98.0-aarch64-unknown-linux-gnu.tar.xz
/home/gabe/Documents/ChatGPT/cachy-asahi-rust-submodule-closure-20261115/packages/port/rust199-source-reference/stage0_intake/work/artifacts/rustc-1.98.0-aarch64-unknown-linux-gnu.tar.xz
```

## Observed archive and manifest data

[`stage0_intake`](../../packages/port/rust199-source-reference/stage0_intake/README.md) contains the request ledger, search limitations, complete inventories/file hashes, selected exact manifest/notice text, ELF records, source checks and a new DATA-only admission record.

| Component archive | Members | Declared regular payload bytes | Installer manifest entries | Top-level regular ELF files |
| --- | ---: | ---: | ---: | ---: |
| Cargo | 68 | 39,837,185 | 44 | 1 |
| rust-std | 80 | 162,174,103 | 61 | 1 |
| rustc | 69 | 309,737,853 | 40 | 12 |

Each namespace has one expected root, unique normalized paths and no symlinks, hardlinks or special entries. The declared `cargo`, `rust-std-aarch64-unknown-linux-gnu` and `rustc` component directories are present. All installer-manifest entries resolve to the expected kinds, and all component payload files are covered. Installer scripts were hashed as opaque files and never run. All three release `git-commit-hash` files contain `88d9e12ae178fab0fb5cc050a94da85685d449ea`. Rustc/std version metadata says `1.98.0 (88d9e12ae 2026-08-18)`; Cargo package metadata says `0.99.0 (797e8a9bc 2026-08-05)`. That Cargo package-version text is recorded separately from its archive filename and is not an observed CLI version. Twelve root/component notice copies were retained, including Cargo's third-party notices and Rust COPYRIGHT/MIT/Apache notices. Their presence is not complete corresponding-source or license qualification.

The candidate's proposed component merge models 166 entries/145 regular files with no nonidentical collisions. Its metadata-derived tree digest is `2590be106242f89885ec057b9ce907afae5a3264c393f38003c5b58cc10906e4`. This models recorded modes/path/type/bytes; **no prefix was assembled on disk**. Actual assembly permissions, runtime and compatibility must still be checked before populating the candidate's qualified assembled-tree field.

## Static ELF and dependency observations

All 14 top-level regular ELF headers identify ELF64 little-endian AArch64 (`e_machine=183`). Their PT_LOAD segments have alignment at least 16384 and congruent file offsets/virtual addresses modulo 16384. These are the checked static conditions, not proof that any binary loads or works on a 16 KiB kernel, Asahi or M2. Thirty-three ar/rlib payloads were identified but their nested objects were not parsed. No conclusion about all nested code follows from the 14 top-level headers.

Dynamic metadata preserves `DT_NEEDED`, `DT_SONAME`, `DT_RPATH` and `DT_RUNPATH` separately. The recorded interpreter is `/lib/ld-linux-aarch64.so.1`; observed RUNPATHs use `$ORIGIN`-relative paths. Bundled SONAMEs include `librustc_driver-e6f11afaeca7c6f5.so`, `libstd-d0d82f59f384a37e.so`, and **`libLLVM.so.22.1-rust-1.98.0-stable`**. Stage0's bundled LLVM 22.1 is a separate input from the candidate's external build LLVM 23.1.1.

After matching bundled SONAME names, external required names include `libc.so.6`, `libdl.so.2`, `libgcc_s.so.1`, `libm.so.6`, `libpthread.so.0`, `librt.so.1` and `libz.so.1`. These are filename-level observations only: no loader lookup, symbol/version resolution, ABI test, native execution or dependency environment qualification occurred. The matched names do not establish successful dynamic linkage.

## Results, limits and next work

The offline verifier passes for all whole archive checksums and pinned DATA records. Seven author-owned parser/refusal controls pass. Independent passive review led to two precision fixes: reject zero-sized ELF program-header entries when a nonzero count exists, and keep RPATH/RUNPATH distinct. Two local streaming audit runs are recorded; the final run took 4.115 s and peaked 206,472 KiB, below 512 MiB. No extra network requests accompanied the corrected audit.

No installer, acquired binary, compiler, makepkg, container, lease, signing or native/hardware job ran. Binary payloads were never extracted to files; only compressed originals and selected manifest/notice DATA were retained. Detached signature authentication was not performed; trust here is verified TLS plus agreement with the previously retained exact stage0 checksum declarations.

Next: rejoin appropriate source/authentication and dependency notice evidence, assemble and qualify stage0 in the separately authorized native environment, establish actual loader/library/bootstrap compatibility, and supply the candidate's pinned LLVM 23.1.1 dependency image and source/vendor closure. The new record keeps compatibility **UNQUALIFIED** and does not substitute for a qualified build admission. All license108/source holds, four original recipe mismatches, ARM16K/M2 qualification, performance and release acceptance remain open.

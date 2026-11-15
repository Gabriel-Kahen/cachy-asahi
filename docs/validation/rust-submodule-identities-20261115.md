# Rust declared submodule identities — 2026-11-15

The separate [verifier and retained report](../../scripts/port/arm-rust-toolchain-inputs/source-closure/submodule-closure/README.md) reconcile twelve declared paths at [Rust b940084d](https://github.com/rust-lang/rust/tree/b940084d7eb6a299eb4bfeb8e34901bc051e7ac4). The 1,508-byte authenticated archive `.gitmodules` member matches its official Git blob. Full entry lists reconstruct five connected Rust tree hashes and all twelve upstream root trees. Official repository names, owners, numeric IDs and exact commit objects join the gitlinks.

| Path | Declared repository | Gitlink commit | Archive regular members |
| --- | --- | --- | ---: |
| src/doc/nomicon | rust-lang/nomicon | `5012a37c682b26c4e19433888ed2ca9b129696ca` | 72 |
| src/tools/cargo | rust-lang/cargo | `5f94df4789f005f9a352888e8355ffc645b7ed0e` | 2949 |
| src/doc/reference | rust-lang/reference | `82da570bafd9efed421bdbae0f8603ede8dd308b` | 188 |
| src/doc/book | rust-lang/book | `917544888a55e4da7109bdba8c88c893c0da70f4` | 2650 |
| src/doc/rust-by-example | rust-lang/rust-by-example | `15308f3e951814ef3475d2b58f48276e6b17b9af` | 215 |
| src/doc/edition-guide | rust-lang/edition-guide | `5a14f7276ebc0bd100974f02b918f30472c782fc` | 62 |
| src/llvm-project | rust-lang/llvm-project | `1b9c0d5ff9bbe7634aead059efe6b11a7eeba145` | 104380 |
| src/doc/embedded-book | rust-embedded/book | `0789b0f29e73ecb91213cac10ad0eec1b9333770` | 61 |
| library/backtrace | rust-lang/backtrace-rs | `d902726a1dcdc1e1c66f73d1162181b5423c645b` | 101 |
| src/tools/rustc-perf | rust-lang/rustc-perf | `0a054b0ead56e41a4584bfab6fdc1a5fad2aedc3` | 14313 |
| src/tools/enzyme | rust-lang/enzyme | `fa6e20ebd80f0e28219abaf174d95baf1513ce92` | 1889 |
| src/gcc | rust-lang/gcc | `6f155cc3f5a2dff33afe6cc3ed6c2e0e605ae6a3` | 1 |

Four primary read-only metadata queries consumed 64,921 response bytes (limits 20 requests / 8 MiB). No new archive, upstream-source checkout, recursive fetch, retrieved-code execution, compiler, daemon, VM, CI/Source/Reader role or system mutation occurred. The verifier reuses the exact retained archive scan from worker commit `3c76059f0031b2433f25bd1e0fd1400a0a8bfcb5`; it does not rescan the large archives or rerun signature mathematics.

GCC is a concrete content gap: its pinned root contains 46 regular files totaling 5,061,455 bytes, but the source archive has only 1 regular member beneath `src/gcc`. At least 45 top-level regular files and 2,592,801 payload bytes are absent at the required paths, even allowing that one member to match the largest root file. This counts direct regular-member representations at pinned paths; symlink targets, duplicate bytes elsewhere and deeper content are not examined. Exact absent names and the recursive missing-byte total are not established.

For every other path, occupancy remains only an observation. Exact payload equality at the gitlink commit, recursive/nested completeness, copyright/notice coverage, bootstrap/provider closure, original recipe correspondence and actual build consumption remain open. GitHub repository owners are not legal license-ownership findings. Rust's LLVM, Enzyme and GCC forks are explicitly retained as forks; their parent repositories are not substituted for their declared identities.

Twelve focused controls cover tree omissions and altered modes/OIDs, disconnected path trees, wrong repository/owner/commit, archive declaration mismatches, unsafe paths, partial API results and acquisition budgets, plus descriptor read races, FIFO/symlink/hardlink/oversize/growth refusal. Source implementation and DATA joins are the scope; ARM, native16K, M2, performance and release acceptance remain unestablished.

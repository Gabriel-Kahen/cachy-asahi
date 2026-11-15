# Rust stage0 in an emulated ARM16K guest

Root accepted a finite emulated runtime component on 2026-11-15. Pinned upstream
Rust 1.98.0 and Cargo 1.98.0 compiled and ran the two correctness programs through
a normal UID1000 builder PAM login. The software-TCG guest reported aarch64,
16384-byte pages, systemd, logind and DBus. The toolchain uses the private
`/opt/cachy-asahi/rust-stage0` prefix.

| Check | Actual result |
| --- | --- |
| Direct rustc compile and execution | PASS |
| Offline Cargo compile and execution | PASS |
| Independent output ELF parsing | Both AArch64; all four PT_LOAD segments align and are congruent for 16K pages |
| Preservation | Controller checks passed for all 111 package versions, protected PAM/boot paths and private-prefix inputs |
| Retirement | Normal PAM logout, QMP quit, signal-free zero-exit QEMU, owned container absent |
| Independent retained-evidence reader | PASS, 208 pinned files; naturally retired under Root custody |

The exact [maintained controller](../../scripts/integration/arm16k_rust_stage0_vm/README.md)
matches public Source `af907a32bf6a438428357a15a8e8abda4461e2d2`, 73 files and
682106 bytes. Its source lock is 12800 bytes,
SHA256 `ece9d1557bf90d907454fe2c86d92864af6c6c41d964490ee79354c0c6511468`.
The original 39-input certificate retains its Source68/r8 observation provenance.

After the run, a separately bounded operation converted the retained overlay,
replayed the journal only on a derived copy, and extracted the two binaries.
Original raw/overlay hashes remained unchanged. Independent parsing checked the
actual extracted bytes:

| Output | Bytes | SHA256 |
| --- | ---: | --- |
| Direct | 4743488 | `a74d27cc25c2a9f11ca0cfd16e2c3e427142fa01948dd6a7da4231130b6a4d7e` |
| Cargo | 5094080 | `e741e913e56f4a8c88aa4c497029f10da17af250a9ea4a09bf51d41b14b57c3b` |

Root retains the boot report (9883 bytes,
SHA256 `ace0f28b8be54c4820f99c9868819e3b25920e236b3d0dde1175eb4c7b58dfc9`),
Reader result (5060 bytes,
SHA256 `8351869cffebe34678456958085bec1d7b4146a286762d07ec4897ae8a7bdfc5`),
and finite component decision (4083 bytes,
SHA256 `7d36c2ed5290528901b3142a5f25b12e9812e0b72656c523c60f340c8c4b9bbf`).
These hashes identify retained evidence; this document does not publish images,
credentials or an unredacted UART transcript.

The earlier failed preparations and extraction remain separate closed cases.
The successful run uses explicit dynamic libgcc linking and a bounded 160MiB XZ
decoder. All 94 controller controls pass on Python 3.12 and 3.14.

This qualifies the recorded stage0 fixture. Project-built Rust199, the complete
Rust ecosystem, full symbol/version ABI coverage, exact Cargo deps-path alias
identity, guest poweroff recovery, native ARM16K, physical M2, performance and
release acceptance remain open.

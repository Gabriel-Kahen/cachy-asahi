# Opt-in Bankstown 1.1.0-5 source candidate

This separate recipe preserves accepted `packages/audio/bankstown` 1.1.0-4 and
its evidence. It changes no selectors, manifests, runtime defaults or services.
It adds explicit locked/offline build controls, a pinned native compiler-input
association, native tool/support requirements, architecture/receipt guards and
installed build-input documentation. Package output contains only three LV2
files, five license/notice files and two provenance documents. There are no
hooks, configuration backups, daemon actions or user-data paths.

The unchanged inputs are Bankstown 1.1.0 commit
`e9829c9bccf5ed73768135c0ddd506f5a6690f9e`, shared 117-crate vendor archive
`64cd55473b19f104f3a90570409d58c5ab69f63c61396541c4ad1e56e8d6293f`,
and the retained notice archive. Nine local recipe sources, their licenses,
hashes and dependencies are pinned in PKGBUILD/.SRCINFO. The vendor file/lock
audit recomputes all 117 crates and the Bankstown 17-crate join before host builds.

The intended native provider is the genuine ALARM
`rust-1:1.99.0-1-aarch64.pkg.tar.xz` from the historical input lock:
59,807,260 bytes/SHA256
`337e715182a8f81bfd6df844793c5d1cb2697ff9e94ddb496dd850ba901c31d4`.
A bounded local retained-cache lookup found this exact archive and adjacent
566-byte signature/SHA256
`d7dcf2f24bca366570446a6c7228048524e1632122fa36200685a0fbe638735e`.
Both match the original BUILD.inputs.lock descriptors. The archive was read as
data: 137 ordinary payload files/262,066,494 bytes were hashed into
`native-rust-inputs.json`. The compiler's BUILDINFO declares recipe SHA256
`ef3fac9176e2a3698314d616e56d88b2df64d057ee7e9dfa13c98eb980a345fa`.
No archive code, old native role or Reader was executed. Signature authentication
and compiler-recipe/source correspondence were not established by this task.

Native `build()` requires `BANKSTOWN_NATIVE_TOOLS_PROFILE` and its trusted
`BANKSTOWN_NATIVE_TOOLS_SHA256`. The catalog must have schema 1,
purpose `bankstown-1.1.0-5-native-toolchain`, compiler_version `1.99.0`,
target `aarch64-unknown-linux-gnu`, tools matching the four fixed /usr/bin roles
in build_guard.py, and a `files` map of canonical paths to exact bytes/SHA256.
The guard verifies listed files, direct AArch64 tool ELFs, retained Rust
compiler/library payload associations and required native standard libraries.
A complete reviewed native runtime/linker catalog is not supplied here; the
requirements JSON is deliberately refused as an accepted tool catalog.

Use a separately provisioned disposable aarch64 builder. No dependency installer
or native provisioning command is provided. Ancestor Cargo configuration is
refused; the generated Cargo home and fresh build environment exclude inherited
wrappers, flags, aliases and credentials. The native command fixes
`--target aarch64-unknown-linux-gnu --release --locked --offline --jobs 1`,
generic CPU, one codegen unit and 16 KiB linker maximum-page-size. Upstream
opt-level 3/thin LTO remain. These are explicit build inputs, not performance or
hardware claims.

The existing direct 1.96.1 x86_64 toolchain is used only by the separate
[host diagnostic](../../../scripts/port/platform-audio-bankstown-build/README.md).
It is not a native provider or historical compiler replacement. The requirements
file retains exact alternative aarch64 dist URLs/hashes from its locally retained
channel manifest, with that alternative unselected, bytes not acquired by this
work and manifest authentication unperformed. `rust-src` there identifies
standard-library sources, not complete compiler/Cargo/LLVM/runtime sources.

## Actual checks, 2026-11-14

- Fifteen recipe/guard controls and ten host-builder/policy controls pass.
- Four explicit controls pass against the actual compiled host prefix, including
  exact ten-file layout, native relabel refusal and receipt/extra-link tampering.
- Actual makepkg source verification passes all nine local hashes; regenerated
  .SRCINFO matches. Ordinary dependency-checked `makepkg --nobuild --ignorearch`
  returns 8 because this host has no registered `rust` provider. No `--nodeps`,
  dependency installation or complete makepkg package-build success is claimed.
- The isolated direct source build and actual `package()` function staging pass
  with the explicitly unselected host compiler. The 435,208-byte x86_64 DSO SHA256
  is `d6371112ba528af943d5b934f7a6666ba017c434b322b486584fb1ca4dec1b5b`.
  Two completed host builds produced those same bytes. This is a local diagnostic
  observation, not a native reproducibility qualification. The plugin was never
  loaded; no audio device, routing or service operation occurred.

Native build/package installation/removal, aarch64 execution and M2 validation
remain NOT RUN for this successor. Raw.crate authenticity, compiler/std/linker/
runtime corresponding source, wmidi text association, relinking, legal and
release acceptance remain held. The original notice SOURCE.md is preserved
unchanged and the installed SOURCE-CANDIDATE.md explains the successor scope.

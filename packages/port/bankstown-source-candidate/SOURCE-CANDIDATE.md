# Bankstown 1.1.0-5 source candidate

This opt-in successor preserves Bankstown 1.1.0 source commit
`e9829c9bccf5ed73768135c0ddd506f5a6690f9e`, its entire shared 117-crate vendor
archive and the retained notice archive. Its intended native compiler is the
genuine ALARM Rust 1:1.99.0-1 package from the historical input contract, with
locked/offline commands, one codegen unit and generic target CPU. It does not
replace or select the accepted 1.1.0-4 recipe or its native evidence.

The historical ARM4K package was built with ALARM Rust 1:1.99.0-1 and
GCC 16.1.1+r12+g301eb08fa2c5-1. The exact Rust archive and detached signature bytes
were found and hashed locally; native-rust-inputs.json binds its actual payload.
Signature authentication and compiler/source correspondence remain unresolved.
The original SOURCE.md notice is delivered unchanged for context.

Native build requires a separately supplied, trusted, SHA256-pinned aarch64 tool
and support-file catalog matching the retained Cargo/Rustc 1.99.0 payload, the
linker and native standard libraries. No complete native runtime/source catalog
is supplied here. The requirements JSON
records missing inputs; it is not an executable or accepted native catalog.
The recipe refuses missing native prerequisites, wrappers and other compiler
versions. The held 1.96.1 host compiler is an explicitly unselected native
alternative. It may separately stage x86_64 diagnostic output through an explicit
receipt and flag, with no historical/native/ARM/M2 credit.

The upstream release profile's opt-level 3 and thin LTO remain. The explicit
single codegen unit and 16 KiB linker maximum-page-size option are recorded build
policy, not measured performance or hardware compatibility. No audio service,
routing, device, firmware or system state is modified by building or package().

The package retains upstream MIT and third-party notices as data. Raw.crate
authenticity, complete selected compiler/std/linker/runtime sources, wmidi 3.1.0
license-text association, relinking/legal acceptance, native qualification and M2
validation remain held. Source/license presence and a host build do not establish
complete corresponding source or release eligibility.

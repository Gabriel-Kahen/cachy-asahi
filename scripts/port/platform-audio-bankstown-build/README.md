# Bounded Bankstown host source/package diagnostic

This specific adapter builds the
[new opt-in source recipe](../../../packages/port/bankstown-source-candidate/README.md)
with held Cargo/Rustc 1.96.1 for x86_64, then invokes the actual recipe's
`package()` function in its explicit host diagnostic mode. The intended native
compiler remains the retained ALARM 1:1.99.0-1 contract. No native provider,
selector, older recipe, source-delivery module or metadata source is changed.

```sh
task_private=$(mktemp -d)
python3 -I -B scripts/port/platform-audio-bankstown-build/build.py \
  --toolchain /private/held/1.96.1-x86_64-unknown-linux-gnu \
  --tools-sha256 66a3d8c97e084162a50fb8b0375e61532f18b57297779e5e7c4be25fcd81b60b \
  --output "$task_private/host-report"
```

The reviewed 197,366-byte runtime catalog is `host-tools.json`: 803 files/632,639,346
bytes, with profile SHA256
`66a3d8c97e084162a50fb8b0375e61532f18b57297779e5e7c4be25fcd81b60b`.
It pins direct Rust tools, standard libraries, bundled Rust LLD, the GNU driver/
linker objects/scripts and recursively required shared libraries, Python and
the small packaging tool set. GNU linker-script inputs are followed as literal
data. Missing or changed files are requirements; nothing is downloaded or
installed. The collector is a read-only source helper for catalog review, not a
production auto-update CLI.

The unchanged FDK finite Runner bounds the complete job to 600 seconds,
build to 300 seconds, other phases to 60 seconds, output to 4 MiB per command, and
retains its CPU/address-space/file-size/cancellation/group-cleanup controls.
Cargo jobs and codegen units are 1. The explicitly pinned host linker wrapper
adds LLD `--threads=1` for host build scripts as well as target linking. This
avoids an unbounded linker pool under the finite address-space limit; it is
not tuning/performance evidence or a silent native flag change.

All sources and vendor files are checked against the recipe, exact declared file
checksums and original Cargo.lock. Full vendor bytes, including its inactive
configuration data, remain unchanged. A fresh neutral working directory and
generated Cargo home control configuration discovery; direct toolchain ELFs
avoid rustup/toolchain-file discovery. No inherited Cargo/Rust flags, wrappers,
aliases, credentials, loader injection or host HOME are forwarded.

The operation reuses the held metadata namespace primitives as pinned code in a
new build-specific bootstrap. Fresh user/mount/PID/network namespaces, read-only
root/source/vendor mounts, zero capabilities, no-new-privileges and seccomp
confine the build. Network socket creation/connections and namespace/mount
changes remain denied. Unnamed AF_UNIX pairs and their messaging are permitted
for Rust's compiler-launch/CLOEXEC channel; no socket descriptors are inherited
and no named/host socket service is exposed. Only /work is writable/executable;
HOME/temp are NOEXEC. There are no host audio devices, runtime sockets, services,
host home or package database inside this namespace.

This source-build authorization permits upstream Rust build scripts and
procedural macros to execute inside the confined build workspace. It does not
load or execute the resulting Bankstown audio plugin. This differs from the
earlier metadata-only operation, whose source-execution denial and files remain
unchanged. Every phase requires the exact nine build-isolation observations.
Metadata preflight, locked/offline release build and trusted recipe package()
must all succeed; partial failures never become a prefix PASS.

`host-build.json` binds the current recipe, adapter sources, environment,
runtime profile, actual host artifact, unchanged source lock and exact ten-file
prefix hashes/modes. The fresh private output also retains bounded phase logs
and the actual prefix. It is not an Arch package archive, signed release record
or installed package. Files created while staging remain under a private parent;
the prefix preserves real package() file/directory modes for inspection.

## Actual local result, 2026-11-14

Python 3.14.7 completed metadata preflight (18 packages/37 edges), frozen/offline
release source build and actual package() staging. The final report is 30,552
bytes/SHA256
`d0a2424dcb9d4c0175a8a3ccc8cba9880a3e53b799c33854d5c0564dcbc0d2df`.
The DSO is 435,208 bytes/SHA256
`d6371112ba528af943d5b934f7a6666ba017c434b322b486584fb1ca4dec1b5b`,
ELF machine 62, with exported function `lv2_descriptor` and structural 16 KiB load
alignment. The prefix contains 10 files/668,404 bytes. Structural inspection and
same-byte host repeats do not prove aarch64/M2 or original-build equivalence.

Real earlier attempts remain as private diagnostics: the metadata-only IPC
policy blocked Rust launch, then the incomplete host support catalog exposed
missing bundled LLD, the unmapped GNU driver and a GNU linker-script input;
an unconstrained LLD pool hit the finite resource bound. The final source build
uses the explicit build-only IPC allowance, complete observed linker support
and one-thread LLD wrapper. No failure was replaced with a stub or fetched
dependency. The final ordinary makepkg check still refuses missing `rust`
(exit 8), while source verification passes; no `--nodeps` is used.

Run the 25 focused controls and four explicit actual-prefix controls:

```sh
python3 -I -B -Werror::ResourceWarning packages/port/bankstown-source-candidate/test_candidate.py
python3 -I -B -Werror::ResourceWarning scripts/port/platform-audio-bankstown-build/test_build.py
python3 -I -B -Werror::ResourceWarning scripts/port/platform-audio-bankstown-build/check_actual_prefix.py \
  --report /private/actual-host-report
```

Native tool/support/source closure, detached-signature authentication, raw.crate
authenticity, compiler-source correspondence and legal/relinking acceptance
remain held. No host/native package installation, native ARM actor, old Reader
replay, audio execution, routing/service action, physical M2 test, performance
claim, publication or release admission occurred.

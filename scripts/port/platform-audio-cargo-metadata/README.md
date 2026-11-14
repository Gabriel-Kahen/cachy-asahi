# Isolated host Cargo metadata for delivered audio sources

`replay.py` resolves the actual retained Bankstown, Speakersafetyd and Triforce
inputs with an explicitly pinned host Cargo/Rustc toolchain. It adds a real
target/default-feature graph to the earlier
[vendor declaration audit](../platform-audio-vendor-audit/README.md). The 307
unmatched declarations and 42 multiple-candidate observations remain historical
audit results; this operation identifies the graph selected by one new, explicit
host-tool invocation. It does not prove the original native build's flags,
toolchain, feature activation or generated build-script configuration.

Cargo documents metadata as workspace/resolved-dependency information.
`--filter-platform` filters the resolve graph, while dependency declarations
inside package records remain unfiltered. Default features apply when feature
switches are absent; `--locked` refuses lock changes and `--offline` prohibits
network access. The checker traverses only root-reachable resolve edges and
does not mistake package declaration lists for resolved dependencies.
See [the Cargo metadata command](https://doc.rust-lang.org/cargo/commands/cargo-metadata.html).
Cargo describes build scripts as operations performed before building; this
adapter never invokes a build command, compiler source compilation, or a source
artifact. See [build-script lifecycle](https://doc.rust-lang.org/cargo/reference/build-scripts.html).

## Run

Supply the unchanged [five-package handoff](../platform-audio-sources/README.md),
trusted hashes, and the existing direct 1.96.1 host toolchain directory. This
interface supports the reviewed x86_64 Linux host runtime and queries the
aarch64 GNU/Linux target. It does not require installing a target standard
library, installing packages, or running aarch64 code.

```sh
task_private=$(mktemp -d)
python3 -I -B scripts/port/platform-audio-cargo-metadata/replay.py \
  --handoff /private/relocated/handoff \
  --index-sha256 70a94f1df45b982abd78644e2bc9182bf0b761f8a11549a993bc2f73e22e777c \
  --profile-sha256 e2ab9b6cc2810bf5d5b6454abdb9bcdeea6567797247c745b0d04541cb99c6c8 \
  --toolchain /private/existing/1.96.1-x86_64-unknown-linux-gnu \
  --tools-profile-sha256 e3b9393532e4b92f4f29a7c073c51bbbcfa02419e2f703b969af487446d24a67 \
  --output "$task_private/metadata-report"
```

The fresh private directory contains `metadata-replay.json` and bounded command
logs, all mode0600 inside mode0700. Existing destinations are preserved. The
successful structured report uses fixed virtual namespace paths, without
operator paths. Private failure logs may contain local startup paths; they are
diagnostic data and are not published by this tool. Obtain hashes through a
trusted channel rather than from the same untrusted download.

`trusted-tools.json` is 163,485 bytes/SHA256
`e3b9393532e4b92f4f29a7c073c51bbbcfa02419e2f703b969af487446d24a67`.
It pins 684 direct tool/runtime/support files totaling 417,979,903 bytes, including
Cargo, Rustc, RustcDriver/LLVM, the recursively inspected ELF shared-library and
interpreter closure, and the trusted Python bootstrap support. Python
site-packages, bytecode caches and unrelated extension modules are excluded.
The ELF reader accepts the reviewed x86_64/ELF64 format and fixed loader aliases;
unknown formats or absent support are requirements, never mocked availability.
The read-only `collect_tools` source helper constructed this catalog for review;
the production CLI cannot regenerate it or silently accept another toolchain.

The direct tool pins are:

| Tool | Bytes | SHA256 |
| --- | ---: | --- |
| cargo 1.96.1 | 42878680 | `a73b2c25573d251489101c0d8f19ad3702eb9761166de5ed8437b472b6c038ce` |
| rustc 1.96.1 | 646024 | `4a84e05991ad6f2a84c1361c29b52b38c390365bd1fc269b1936c88d482a8928` |

Rustc reports commit `31fca3adb283cc9dfd56b49cdee9a96eb9c96ffd`, host
`x86_64-unknown-linux-gnu`, and LLVM 22.1.2. These are new host runtime observations;
they do not establish historical compiler correspondence or toolchain source
delivery. Rustup proxies are never run, so no toolchain discovery/auto-install
occurs. [Rustup's override behavior](https://rust-lang.github.io/rustup/overrides.html)
explains why direct tools and exclusion of toolchain files are required here.

## Isolation and scope

The unchanged finite FDK `Runner` supplies aggregate 180-second and per-command
30-second bounds, output/CPU/address-space/file-size limits, cancellation,
process-group ownership and cleanup. Bubblewrap supplies fresh user, mount,
network, PID and other namespaces. A small pinned operation-specific bootstrap
sets NOEXEC on source, vendor and every writable workspace/home/temp mount,
makes the root read-only, removes its Python executable mount, drops every
capability, sets no-new-privileges and installs a fixed x86_64 seccomp policy.
Network/socket calls, namespace/mount modification, io_uring, memfd and related
escape mechanisms are denied; ordinary process/thread and read operations needed
by the pinned tools remain allowed. This does not introduce a new supervisor or
general command runner.

Before **every** trusted tool operation, the bootstrap proves that an exact
copied trusted Cargo ELF cannot execute or acquire an executable file mapping
from the workspace. It also checks socket and new-user-namespace denial, distinct
network namespace, zero capabilities and required mount flags. The probe is
trusted Cargo data, not upstream/artifact code. No metadata is admitted without
all nine explicit isolation observations. Compiled executable/build outputs are
also refused after replay, and all projected input and original lock bytes are
checked unchanged.

The original handoff and vendor audit are verified as data first and remain
read-only. The private replay projection excludes source `.cargo` controls and
`rust-toolchain` files, records omitted paths/hashes, and never follows source
symlinks. It keeps every Cargo manifest/lock and all remaining ordinary vendor
bytes unchanged. The only Cargo configuration is a generated offline replacement
pointing crates.io at the delivered vendor directory. Fresh environment and
HOME/CARGO_HOME exclude inherited aliases, wrappers, flags, credentials, helpers,
loader injection and rustup settings. Cargo's
[hierarchical configuration rules](https://doc.rust-lang.org/cargo/reference/config.html)
make both source and ancestor configuration exclusion necessary.

Only fixed version probes and
`cargo metadata --format-version 1 --locked --offline --filter-platform aarch64-unknown-linux-gnu`
run. Source/configuration/tool/runtime/isolation failures become explicit
requirements; missing vendor or target source is never fetched or replaced by a
stub. A successful query must bind every package record to the original lock and
delivered manifest/vendor/checksum identity. The recorded graph includes only
root-reachable nodes/edges, their selected features, aliases and dependency kinds.
Exit 0 means the three new host-tool graphs were recorded; exit 1/2 leaves explicit
requirements. No exit code grants corresponding-source or legal acceptance.

## Actual local result, 2026-11-14

Python 3.14.7 and the pinned host Cargo/Rustc 1.96.1 completed all five operations
(two version probes and three metadata queries), with all denial proofs present.
The actual root-reachable graphs are:

| Project | Packages including root | Edges |
| --- | ---: | ---: |
| Bankstown 1.1.0 | 18 | 37 |
| Speakersafetyd 2.0.1 | 47 | 63 |
| Triforce 0.3.2 | 39 | 80 |

Their union contains 88 registry package identities, all supplied. The projection
has 4,448 files/57,731,668 bytes, manifest SHA256
`c042ef08c7fb4b96cdfe42152b9966fa881ae7c8879f8bdd4b2d0798c833d4dd`.
Nine source Cargo/toolchain controls and 11 inert Speakersafetyd symlinks were
excluded and recorded. Original locks remain unchanged; no compiled artifact
output was found. The actual 134,856-byte report SHA256 is
`bbdb8c033a859050d188ae1e573b91fd14d77092cd24ee6e8c5159bd5c02c210`.
Private reports, runtime copies and source projections are not committed or
published.

Twenty-three focused data/policy controls and seven actual host replay controls
passed. The latter poison inherited configuration, require all five actual
isolation proofs, remove a real vendor crate and real target source, reject a
tampered resolved version, exercise a private requirements report, and reproduce
the successful CLI report byte-for-byte. No test executes upstream build scripts,
procedural macros or other source artifacts.

```sh
python3 -I -B -Werror::ResourceWarning scripts/port/platform-audio-cargo-metadata/test_replay.py
python3 -I -B -Werror::ResourceWarning scripts/port/platform-audio-cargo-metadata/check_actual_replay.py \
  --handoff /private/relocated/handoff \
  --index-sha256 70a94f1df45b982abd78644e2bc9182bf0b761f8a11549a993bc2f73e22e777c \
  --toolchain /private/existing/1.96.1-x86_64-unknown-linux-gnu \
  --tools-profile-sha256 e3b9393532e4b92f4f29a7c073c51bbbcfa02419e2f703b969af487446d24a67
```

Raw `.crate` authenticity, original compiler/standard-library/linker/runtime
corresponding sources, original native build flags/features, wmidi/nalgebra term
associations, relinking and legal completeness remain held. No build,
installation, native ARM execution, audio/speaker-safety check, M2 validation,
performance measurement or release admission occurred.

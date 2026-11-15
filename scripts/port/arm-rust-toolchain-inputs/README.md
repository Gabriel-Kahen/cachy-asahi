# Offline ALARM Rust 1.99.0 input preparation

This finite, data-only command verifies and optionally copies the retained
`rust 1:1.99.0-1` aarch64 toolchain inputs for the opt-in Bankstown successor.
It needs Python's standard library and the existing `/usr/bin/gpgv`. It performs
no downloads, package installation, payload execution or native dispatch.

`inputs.lock.json` fixes 271 archive/signature pairs and 1,154 package dependency
joins: Rust, compiler-rt/lld/llvm-libs 23.1.1-1, the declared runtime dependencies,
`filesystem` for the real `/lib` namespace aliases and recursively inspected
auxiliary providers. The original 84 package descriptors are preserved byte for
byte and enforced as a subset. See [the supplemental result](SUPPLEMENT.md) for
the 187 additions and remaining whole-payload gates. The selected GCC is
16.1.1+r12+g301eb08fa2c5-1 and glibc is 2.43+r22+g8362e8ce10b2-2. These are
explicit retained runtime inputs, not a reconstruction of Rust's complete build
environment. All pins and source metadata provenance are reviewable in the lock.
Archive `.PKGINFO` dependencies take precedence over abbreviated repository
summaries; every observed summary difference is retained explicitly in the lock.

The public ALARM keyring is binary data converted from the retained armored
public key. Its exact pin and the original armored pin are recorded. The expected
primary/signer is `68B3537F39A313B3E574D06777193F152BDBE6A6`.
Successful detached-signature mathematics does not establish key freshness,
revocation status, current repository policy or source/license acceptance.

## Commands

Supply one or more existing directories containing the exact locked filenames.
Discovery is nonrecursive; no host package database or moving mirror is used.
The following reproduces the bounded local check from the retained caches:

```sh
project_artifacts=/home/gabe/Documents/ChatGPT/cachy-asahi/artifacts
python3 -I -B scripts/port/arm-rust-toolchain-inputs/catalog.py \
  --cache "$project_artifacts/kernel-native-stage/dependencies/freeze-20261012/cache" \
  --cache "$project_artifacts/platform/baseline-acquisition-20261012/cache" \
  --cache "$project_artifacts/platform/coordinated-python-20261012-auth/cache" \
  --cache "$project_artifacts/platform/maintained-baseline-audit-actual01-20261013/private/cache" \
  --cache work/auxiliary-cache \
  --output /private/new-rust-input-report
```

Add `--prepare` to copy the 542 verified archive/signature files into the new
output's `cache/`. The output parent is mode 0700, copied files are mode 0600,
and payload directory trees are never materialized. The output also contains
`inputs.lock.json` and a deterministic `catalog.json`. A prepared cache can be
moved and checked with the same committed command:

```sh
python3 -I -B scripts/port/arm-rust-toolchain-inputs/catalog.py \
  --cache /private/moved-rust-inputs/cache --output /private/new-recheck
python3 -I -B -Werror::ResourceWarning \
  scripts/port/arm-rust-toolchain-inputs/test_catalog.py
```

Output must be new and must not overlap an input cache. Missing inputs give an
incomplete report and exit 2; missing inputs refuse `--prepare` before output
creation. Changed/corrupt inputs, including a corrupt duplicate in another
specified cache, refuse rather than fall back. Invalid metadata, signatures,
namespace joins or associations refuse. If an error occurs while copying a
prepared output, that partial directory is retained without a completed catalog.

Exit 0 requires both exact input checks and whole-payload structural ELF joins.
**The actual retained set exits 2**: all 271 exact input checks pass, while
eleven Qt dependency edges and one empty-RUNPATH policy gate remain unresolved.
The unacquired exact Qt candidates and their unknown transitive dependencies
are explicitly recorded in `remaining-inputs.json` and in the report.
`--prepare` deliberately allows this fully byte-verified set and preserves the incomplete closure in its report.
It does not create an accepted native builder profile.

## What is checked

- Archive/signature sizes and SHA256, package name/version/architecture,
  declared dependencies/provides, raw metadata and every regular payload hash.
- Private verified archive/signature snapshots bind signature mathematics and
  inspection to identical bytes even if a source cache changes concurrently.
- Canonical member paths, duplicate/ancestor collisions, links confined to the
  catalog namespace, regular-file-only hardlinks, special-node refusals and
  cross-package non-directory collisions. Nothing is extracted into a root.
- ELF64 little-endian AArch64 headers, dynamic string tables, interpreter,
  SONAME, RPATH/RUNPATH and direct NEEDED joins through actual retained links.
  Required Cargo/Rustc/CC/GNU-LD/LLD file identities are recorded. Nine exact
  byte-pinned V4L BPF relocatable objects are separately retained as data; they
  cannot provide native tools or shared-library dependencies.
- The exact 137-file Rust association copied from Bankstown worker commit
  `1a639abda4ddf3580aa2fed9466fa835adf96830`. The companion's original content
  and exact hash remain pinned; an override must have those same bytes.
- Recorded recipe-hash comparisons and three LLVM-family license-notice joins
  against the independently recovered official source facts.

The package dependency comparison is deliberately finite: exact/provided
versions plus the four retained numeric lower bounds. Ambiguous comparisons are
refused; it is not a general package solver. ELF joins are structural direct
joins, not a loader simulation: GNU symbol versions, inherited RPATH semantics,
runtime dlopen, compiler child-tool discovery, linker scripts/objects and actual
loading remain separate. Each package is bounded to 50,000 members, 512 MiB per
file and 2 GiB expanded data. A 300-second cooperative deadline is checked
between operations/chunks/members; each GPG process has a 20-second timeout.
This is not a hard wall-clock sandbox for individual decompression operations.

## Preserved 84-pair result, 2026-11-14

At original commit `e61a895dcc0ce5376225d126b7451a9ececde4f8`, twenty-six focused
controls passed, including corruption, snapshot replacement,
wrong signer, unsafe archives/links, malformed ELF, dependency/provider refusal,
missing-input preparation refusal and source-acceptance separation.

That original check and archive-only preparation verified all 84 pairs: 219,962,392
archive bytes plus 47,544 signature bytes. All signatures verify mathematically
under the pinned ALARM signer. There are 28,742 archive members, 1,055,299,447
expanded file bytes and 907 AArch64 ELF records. All 307 package dependency joins
and the unchanged 137-file Rust association match. The catalog joins 3,002 ELF
dependencies and explicitly retains these two unresolved auxiliary requirements:

| Consumer | Missing ELF input |
| --- | --- |
| `/usr/bin/memusagestat` from glibc | `libgd.so.3` |
| libmount's Python 3.14 extension | `libpython3.14.so.1.0` |

Both original requirements are now resolved by exact supplemental providers;
the original lock/result remain under `history/`, and the private original
catalog/cache are retained. The current result still has the separately listed
Qt/RUNPATH gates. Neither auxiliary was silently removed or treated as a
complete toolchain closure. No replacement compiler is selected. Preparation and rechecking from
only the moved-style prepared cache produce identical catalog bytes. A separate
read-only host `readelf` comparison confirms the NEEDED/SONAME parsing of seven
actual compiler/library ELFs; payload data is supplied through non-executable
memory files and is never executed.

## Corresponding source remains open

The ten-minute official recipe search recovered the exact version declarations,
upstream Rust/Cargo/LLVM commits, source archive URLs/checksums and license facts
in [source-facts.json](source-facts.json). ALARM Rust revision
`fc83842504046113895814fa55372e27775c6f5f`, compiler-rt
`c0b8ebf9d8727e0c163485488e237cc9614fafb4`, LLVM
`81126c646304d65bc7bbff809815f298406be0a5` and the official Arch LLD revision
are recoverable, but **none of the four raw recipe hashes matches the archived
`.BUILDINFO` recipe hash**. No matching packaging transformation is established.
LLVM, LLD and compiler-rt license notice bytes do match their pinned upstream
texts. Matching notices and tags do not establish binary/source correspondence.

Complete compiler, Cargo, LLVM and runtime corresponding source was not acquired
or authenticated. The retained `rust-src` package is not a complete compiler
source closure, and the host 1.96.1 compiler is not a substitute. Complete
runtime/linker catalog review, source delivery, relinking/legal acceptance and
key freshness remain open. Native build/execution, installation, generic 16K
execution, physical M2, performance and release acceptance are NOT RUN here.
The existing Asahi stack, historical evidence, shared manifests and workflows
are unchanged.

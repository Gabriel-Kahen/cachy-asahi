# Rust/LLVM source availability, 2026-11-14

This separate data-only collector retains exact recoverable source inputs for
Rust 1.99.0 and LLVM/compiler-rt/LLD 23.1.1. It does not open archives, extract
files, evaluate/source recipes, compile, install or enter native/Source/Reader
roles. Parent catalogs, the Qt3 successor and shared manifests remain read-only.

## Actual retained inputs

| Input | Bytes | SHA256 |
| --- | ---: | --- |
| `rustc-1.99.0-src.tar.xz` | 265,258,564 | `cc41916a8c84f5d9ec4f55561b44e39f43b647b133f8a6f51be9ea13c83f7036` |
| `llvm-project-23.1.1.src.tar.xz` | 179,168,672 | `ebe9be46fe8756d58c5b198ffad0fa2a766257add81a4dc52179bfacc7888ee6` |

Both opaque archives match the exact checksums declared by the retained pinned
official recipes. Rust matches BLAKE2b; LLVM matches both SHA256 and Rust's
independent BLAKE2b declaration for that LLVM archive. Exact byte counts and both
computed digests are frozen in `source-inputs.json`. This establishes retained
source-archive identity against those recipes, not binary/source correspondence.

The cache also retains the 801-byte upstream Rust detached signature. Its exact
SHA256 is pinned, but release-key bytes are not retained and signature mathematics
is NOT PERFORMED. The declared Rust release fingerprint is recorded separately.
LLVM's source signature and release keys were not acquired. No ALARM package key
or version string is treated as authentication of upstream source signatures.

The two archives total **444,427,236 bytes**; with the detached signature the
cache contains **444,428,037 bytes**, below the 1 GiB new-archive cap. Exactly four
HTTP requests were made: LLVM's published URL, its explicit GitHub asset redirect,
Rust's source archive and Rust's signature. Redirects consume the same persistent
four-request budget. Cached replay and offline verification make no new requests.
Temporary free space remained above 3 GiB (6,577,975,296 bytes at the recorded
post-retention check).

Seventeen small local materials are retained byte-for-byte: the four pinned raw
recipes, six Rust patches and one compiler-rt patch matching literal recipe
checksums, the separate retained Rust SRCINFO and five pinned Rust/LLVM-family
license documents. Their original hashes, revisions, URLs and data-only status
are recorded in the manifest. No recipe shell is evaluated to derive these facts.
Upstream patch/license whitespace is preserved because it is part of those
checksum-pinned bytes; the local attributes exception applies only to that data.

## Runnable collector

```sh
mkdir -m 700 /tmp/owned-rust-sources
python3 -I -B scripts/port/arm-rust-toolchain-inputs/source-closure/collect.py collect \
  --cache /tmp/owned-rust-sources/cache --output /tmp/owned-rust-sources/collection
python3 -I -B scripts/port/arm-rust-toolchain-inputs/source-closure/collect.py verify \
  --cache /tmp/owned-rust-sources/cache --output /tmp/owned-rust-sources/verification
python3 -I -B -Werror::ResourceWarning \
  scripts/port/arm-rust-toolchain-inputs/source-closure/test_collect.py
```

The cache is dedicated and must be below `/tmp`; output must be new and separate.
The HTTP ledger is persisted beside the cache **before** each request, including
redirects and failed requests. It is not reset on rerun. There are no unbounded
retries, implicit redirects, keyserver requests or version substitutions.
GitHub asset query credentials are redacted in evidence; the complete URL hash
is retained. Only fixed HTTPS publisher/asset hosts are allowed.

Each transfer has a 20-second socket timeout, 180-second cooperative deadline,
explicit byte ceiling, atomic checked retention and streaming hashes. The
collector checks free space before mutation and each write, preserving the
3 GiB floor with an additional metadata margin. Archive opening/extraction is
absent from the implementation. Signature packets are retained as unverified data.

Exit 0 means the declared opaque source archives are retained and match their
checksums. It does not mark complete corresponding source or legal acceptance.
All four recipe comparisons and the source/signature/completeness holds are
included in every report. Failed or budget-refused inputs remain explicit.

Eight focused controls pass, including corrupt input refusal, persistent request
accounting, counted redirects, query redaction, the free-space floor and cache
namespace restrictions. Cached collection and offline verification produce the
same 10,469-byte report, SHA256
`4a540773430605dc14e5bee6302bd6112be6703e2ab04d0d1b8efa8c6d012a2d`.

## Correspondence remains held

The bounded, local primary-source search completed within the 20-minute cap,
without using any of the four acquisition requests. `correspondence.json` records
the actual recipe bytes and the four still-unmatched `.BUILDINFO` hashes:

| Recipe | Expected `.BUILDINFO` recipe SHA256 |
| --- | --- |
| Rust | `ef3fac9176e2a3698314d616e56d88b2df64d057ee7e9dfa13c98eb980a345fa` |
| compiler-rt | `a08be2c30265ea1dcf95931d8e03f08dd5ff90e1cc1f092bd659f2687aa5d06c` |
| LLVM/llvm-libs | `7c6a21c0d9b125e981011016635541c970552776caa52b58c88b61d32feee5c9` |
| LLD | `96344e325a4cb35f32f316a36e3e23507abb8b0c3ffe1c4b615f7f804fc9fb06` |

Pinned primary pacman source at `54d94116164b0b2202c6061c4a59c6f3e70820d8`
hashes `BUILDFILE` bytes directly. The retained historical ARM makepkg agrees.
`--ignorearch` permits an architecture check bypass; it does not establish a
recipe-byte rewrite. No exact official ALARM preprocessing transformation or
matching recipe revision was recovered. No guessed canonicalization, newline
or architecture replacement is applied to manufacture a match.

Rust/Cargo/LLVM upstream Git identities are pinned facts, with Cargo submodule
`5f94df4789f005f9a352888e8355ffc645b7ed0e`. Archive contents were not inspected:
crate/submodule completeness and their individual source/license authentication
are not inferred. Retained SRCINFO also declares two additional Rust patches
not present in these local materials; it is not substituted for the unmatched
actual build recipe. The stdlib-only `rust-src` package and host Rust 1.96.1 are
not used as replacements.

Exact binary recipe/source correspondence, complete compiler/Cargo/LLVM/runtime
corresponding source, upstream signature mathematics, legal/relinking and
release acceptance therefore remain held. Actual build-recipe bytes or a proven
official transformation are still required. Root owns integration/publication
and all native, source-acceptance and release decisions.

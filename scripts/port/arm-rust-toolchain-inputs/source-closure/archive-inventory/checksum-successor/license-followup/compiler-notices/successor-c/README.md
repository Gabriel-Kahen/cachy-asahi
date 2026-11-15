# Successor C: exact compiler-lock source-file attribution

This batch closes **one source-file notice evidence item**, with **zero new
package-root notice closures**. All **100 unresolved package cases remain**.
The exact `wasmparser 0.243.0` workspace version is additionally resolved. This
is source correspondence and retained attribution, not all-file/legal/native/
M2/release acceptance or demonstrated Linux Cargo feature resolution.

## Exact file and grant

The primary upstream file is
[`crates/wasmparser/src/lib.rs`](https://raw.githubusercontent.com/bytecodealliance/wasm-tools/d05406062d031ae96146486f58a965d87eefea5e/crates/wasmparser/src/lib.rs)
at `d05406062d031ae96146486f58a965d87eefea5e`:

- Complete bytes: **75,545**.
- SHA-256: `1a3d8c79f116527f3c4dcb4e256758acfe3096e87d96f4ec27bbcbd10b587ddf`.
- Named notice: `Copyright 2017 Mozilla Foundation`.
- The same source header expressly applies Apache-2.0 to this file.

The complete ancestor
[`LICENSE-APACHE`](https://raw.githubusercontent.com/bytecodealliance/wasm-tools/d05406062d031ae96146486f58a965d87eefea5e/LICENSE-APACHE)
is retained at the same revision: **10,847 bytes**, SHA-256
`a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`.
Both source and grant match their Git blobs through small exact ancestor tree
shards. The original package manifest/VCS metadata and pinned root workspace
manifest establish the exact `0.243.0` version and source path.

The source file independently matches the **full member SHA-256 and length**
from the existing authenticated private vendor capture. That capture retained
only 8,192 text bytes; its recorded full-member hash was not truncated. The
fresh complete primary file matches both that full hash and the retained
prefix. This proves this file's exact upstream/vendor byte correspondence;
it does not prove correspondence for the rest of the package. No private
candidate packet or unknown captured context is copied into this commit.

The Mozilla notice applies to this source file only. It is not relabeled as
a package-root notice or assigned to every file. `wasmparser 0.243.0` stays in
the 100 unresolved package cases.

## Compiler selection and the remaining object hold

The authenticated Rust root lock has the static path
`rustc-main → rustc_codegen_ssa → object 0.38.1 → wasmparser 0.243.0`.
The retained compiler manifest declares normal `object = 0.38.1`, disables
its defaults and explicitly enables `wasm`.

For the next edge, official docs.rs source pages retain the published object
0.38.1 original manifest and VCS metadata. The original manifest matches the
Git blob in `gimli-rs/object` at
`faf1fa5457f74492ae0cb2030b044032c2c6b7a3`. It declares optional wasmparser
0.243.0 with defaults disabled, and `wasm = ["dep:wasmparser"]`. This is a
concrete pinned **published-source feature declaration chain**.

It does **not** establish the exact vendor feature graph:

| Object normalized manifest | Bytes | SHA-256 |
| --- | ---: | --- |
| Existing authenticated Rust vendor member | 3,600 | `cd79471da0ae6344168c6b7c068657827cc1c3b8066ae9d991fa2e1d79f57639` |
| Extracted docs.rs published source | 2,823 | `d4d83c3c65a6a51bb750c9bb0fe3b3fb4b908fc3e5c8ea5b43844917d976493a` |

The bytes differ. The vendor original manifest/VCS identity and normalized
manifest correspondence are explicitly **unproved**. No assumption about
normalization, equal package versions, source equivalence or harmless changes
resolves this difference. The published feature declarations strengthen
selection priority but receive no active Linux/AArch64 resolution credit.
The wasmparser file correspondence above is independent of this object hold.

All historical package/root-notice counts, source/version/dirty constraints,
original recipe/BUILDINFO discrepancies, submodule reconciliation, platform,
all-file, legal, native/M2 and release holds remain unchanged. There is no
package activation or global manifest edit.

## Acquisition and offline controls

Acquisition is closed at **11 actual HTTP requests / 392,546 response-body
bytes / 119.821 seconds**, within 20 / 16 MiB / 20 minutes. All eleven returned
HTTP 200; no redirects, errors or retries occurred. The ledger counts every
response and the controls cover hypothetical errors/redirects too.

Only official source metadata, pinned raw files and three exact-version
object source pages were fetched with TLS verification. HTML is inert DATA;
`source_text.py` extracts exactly one source element and executes no scripts.
Its derived original manifest is independently corroborated by the upstream
Git blob. The differing normalized manifest remains held as described above.

```sh
python -I -B scripts/port/arm-rust-toolchain-inputs/source-closure/archive-inventory/checksum-successor/license-followup/compiler-notices/successor-c/reevaluate.py \
  --candidate-packet /tmp/cachy-checksum-successor-20261115-03/private-license-candidates.json \
  --output /tmp/new-notice-successor-c.json
python -I -B scripts/port/arm-rust-toolchain-inputs/source-closure/archive-inventory/checksum-successor/license-followup/compiler-notices/successor-c/test_reevaluate.py -v
```

All **nine** controls passed, including actual offline replay, full-member and
prefix correspondence, HTML extraction fences, published original/VCS joins,
feature declaration changes, wrong repository/origin, sibling notice scope,
request/body/time budgets and closed acquisition. The replay control skips if
its deliberately private source packet is unavailable. Replay uses zero
requests and a 256 MiB/30-second process bound; output must be new below `/tmp`.
There were no archive reads/downloads, checkouts, builds, package activation,
actor/lease, system trust or daemon changes.

# Compiler notice followup

This finite batch closes **two additional scoped root-grant/notice evidence
gaps**, reducing the preceding **108 unresolved cases to 106**. The original
111-case review now has five such scoped closures across both batches. This is
source evidence, not all-file license closure, legal acceptance or permission
to publish a release.

| Exact component | Exact recorded upstream revision | Result |
| --- | --- | --- |
| valuable 0.1.1 | `9efc29b6e58cef28f6566a47aa7e142a55fead77` | Complete root MIT grant; `Copyright (c) 2021 Valuable Contributors` |
| levenshtein 1.0.5 | `1b1132a97498e9f1bb34a7f461e042fc5cd50603` | Complete root MIT grant; `Copyright (c) 2016 Titus Wormer <tituswormer@gmail.com>` |
| intl_pluralrules 7.0.2 | `d0715d5b7cca72e228d6e6c4de154bd30dfdd06a` | Prior grant rechecked; attribution still unresolved |
| polonius-engine 0.13.0 | `741e6095fe50f468982d4d253e842eb7d12ed9d3` | Prior grant rechecked; attribution still unresolved |
| perf-event-open-sys 3.0.0 | `6218ac1912aa2210b46713d5c5c51ddb4be805f5` | Prior grant rechecked; attribution still unresolved |
| self_cell 1.2.1 | `7b98b472a3948bc5f678b9fdea4a80935368611b` | Actual complete Apache-2.0 grant; no named attribution established |
| jaq-core 3.1.0 / jaq-json 2.0.1 / jaq-std 3.0.1 | `ebd9d94b182fb8a38b8d8eb1e57d1319889201b9` | Three exact manifest/ancestor MIT grant joins; attribution unresolved |
| comma 1.0.0 | `01828e71a20d81acdbecbbf5df36ba8e3d302eba` | Exact manifest binding; no actual grant established |
| wasm-encoder / wasmparser 0.219.2 | `3a7d60de4be52c24e4392548af16c4bd5075bff3` | Exact workspace versions and root MIT grants bound; package attribution unresolved |

There are **12 reviewed exact manifest/version/revision bindings**: three
rechecked prior partial cases and nine new bindings. The two inherited wasm
versions are resolved from `[workspace.package].version = "0.219.2"`, not the
root package's different `1.219.2` version. Small primary tree shards are joined
through exact directory Git IDs to the recorded commit. This avoids a full
repository traversal while preserving the manifest, ancestor license, workspace
and retained source-file joins.

The parser's exact `crates/wasmparser/src/lib.rs` contains `Copyright 2017 Mozilla
Foundation` and an Apache-2.0 application header. Its complete ancestor Apache
grant is retained too. That is **one file's notice**, not the package's named
root notice. The parser remains in the 106 unresolved cases. Names in author
fields, matching license bytes and Apache appendix placeholders do not establish
ownership. Independently matching Git blobs can establish that the same grant
text exists in another exact tree; they do not transfer attribution.

The nine additionally inspected README/source files for the three original
partial cases establish only what those particular files contain. None supplied
a named copyright notice. There is no claim that every file in those packages
was searched, or that absent notice evidence establishes absence of ownership.

## Compiler and target selection limits

The authenticated Rust root Cargo.lock is unchanged. Valuable and self_cell
have static paths from rustc-main/rustc_driver; their incoming feature/cfg
activation remains unproved. The retained compiler manifest directly declares
normal `wasm-encoder = "0.219"`. Encoder's parser dependency is optional; parser
activation does not follow from this path. Levenshtein and comma are reached
through Clippy → ui_test; jaq crates through the jsondocck tool root. These are
explicit tool/test paths, not compiler paths or demonstrated Linux/AArch64
activity. No Cargo resolver or target build was executed. Unrelated tool graph
edges are not silently declared resolvable.

All 106 remaining component names are retained in `report.json`. In particular,
explicitly dirty spanned, missing VCS/version cases, other workspace-version
holds, Apple/WASI selection hazards, original recipe/BUILDINFO mismatches and
submodule reconciliation remain held. Resolving the two wasm workspace
versions does not resolve their notice or activation holds.

## Acquisition and replay

New acquisition used **35 actual HTTP requests / 2,585,627 response-body bytes**
in a closed **428.344-second** window, within 40 / 16 MiB / 1200 seconds.
Requests and body bytes include:

- Request 17: HTTP 422 for hifijson's recorded 39-character revision. No spelling
  correction or version/repository equivalence was inferred.
- Request 24: a recursive wasm-tools response stopped at the 2 MiB body cap;
  those consumed bytes count, and no incomplete tree was retained or used.
  The predecessor fetcher did not record its response status before the cap
  exception, so the receipt explicitly leaves that status unknown.
- Small non-recursive tree endpoints subsequently established the required wasm
  paths. They are distinct requests, not an automatic retry of the capped URL.

The preceding 20-request packet is reused offline, outside this new acquisition
count. TLS verification was enabled. There were no retries, archive downloads,
archive reads, checkouts, upstream payload execution, builds, package changes,
lease/trust/daemon changes or system mutation. The acquisition ledger is closed;
`fetch.py` refuses further acquisition against it. The fetcher reuses the prior
finite mechanics rather than adding a general acquisition framework.

```sh
python -I -B scripts/port/arm-rust-toolchain-inputs/source-closure/archive-inventory/checksum-successor/license-followup/compiler-notices/reevaluate.py \
  --candidate-packet /tmp/cachy-checksum-successor-20261115-03/private-license-candidates.json \
  --output /tmp/new-compiler-notices-report.json
python -I -B scripts/port/arm-rust-toolchain-inputs/source-closure/archive-inventory/checksum-successor/license-followup/compiler-notices/test_reevaluate.py -v
```

Replay uses zero requests, a 256 MiB address-space cap and a 30-second deadline.
Output must be new and below `/tmp`. The giant private candidate packet is
required for its frozen original manifest/VCS/checksum joins and is **not
included in this commit**. Primary files are retained as DATA and never run. Two upstream trailing-space
lines in self_cell source/README are deliberately preserved for exact blob
identity; authored files pass whitespace checks.
The eight controls cover real offline replay; inherited version and blob
changes; dirty/commit/path holds; wrong repository; wrong tree ancestor;
sibling file/grant scopes; templates/incomplete grants; and request, body and
time budgets. The real replay test skips if its intentionally private packet
is unavailable. All eight passed with the retained local packet.

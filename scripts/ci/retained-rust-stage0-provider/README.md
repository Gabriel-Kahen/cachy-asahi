# Retained Rust stage0 provider

This trusted-Main workflow retains three opaque Rust1.98.0 AArch64 stage0 archives for the existing Rust314 material consumer. It fetches DATA only. It never extracts an archive, executes Rust/Cargo, creates a container, verifies a detached signature, signs a package, or grants native compatibility or Root admission.

The input tuples come from `packages/port/rust199-source-reference/stage0_intake/acquisition.json` and exactly match `scripts/ci/rust199-source-reference-native/successor_v5/payload/hosted/materials.py::STAGE0`, inherited by successor_v6. The acquisition record reports earlier TLS/checksum intake; no download has been performed while implementing this provider.

| Flat ZIP member | Bytes | SHA256 |
| --- | ---: | --- |
| `cargo-1.98.0-aarch64-unknown-linux-gnu.tar.xz` | 11,116,188 | `5784379d73ac881d15a9e67eed2882cd58c747c276221c23cdf9aff37e015ff6` |
| `rust-std-1.98.0-aarch64-unknown-linux-gnu.tar.xz` | 30,768,752 | `a36f7ac98af20ef0ba6368aace0345efabbebaef7962eba99f47190fd256162d` |
| `rustc-1.98.0-aarch64-unknown-linux-gnu.tar.xz` | 66,413,136 | `00590657f2356d7163ca5ef295283523974c340fa21bb94b420ce794f29b358c` |

Only `https://static.rust-lang.org:443/dist/2026-08-20/<member>` is permitted. Three direct requests transfer exactly108,298,076 body bytes. Redirects, retries, query strings, alternate versions/hosts, proxies, credentials, chunked/content-encoded bodies and nonexact Content-Length are unsupported. The client uses verified TLS, including hostname verification, and validates each whole-file pin. No auxiliary signature/metadata download is required by the maintained delivery contract. TLS plus retained whole-file pins does not establish fresh upstream signature authentication.

The external whole-profile SHA256 is:

```text
3b247bbaa5cdb547a6d6a0e6291e10ed17898785e83b6274b3f6044f72ffc6ee
```

Review/recompute it without network:

```sh
python3 -I -B scripts/ci/retained-rust-stage0-provider/collect.py --describe
```

The hash binds fixed archive URLs/pins and transfer policy. The eventual provider source pin is the actual trusted-Main workflow commit (`github.workflow_sha`), checked equal to `GITHUB_SHA`; it is not the Rust314 Source commit. The workflow accepts only the same repository's Main/manual dispatch, attempt1 and the exact workflow ref. Root must review, merge, select this profile hash and dispatch separately. Checkout/upload actions use the repository's existing immutable pins, and checkout does not persist credentials. The collector does not read tokens or Git configuration and uses direct `http.client` HTTPS rather than environment proxies.

The collector has a300s overall deadline,120s per-file wall deadline,15s socket bound,256MiB address-space limit,60s CPU limit,512MiB free-disk floor and exact body caps. `read1` returns control between receives; a per-file/overall wall timer also interrupts trickled headers or bodies. Every response and connection is closed, including `Connection: close` responses. A failed attempt has no retry path or successful output; GitHub's upload step runs only after collector success.

The upload directory contains exactly the three files above, each ordinary single-link0644, with no receipt, manifest, nested directory or partial file. Whole hashes and namespace are checked again before exposing its path. Receipts remain in a sibling RunnerTemp file and are not uploaded. `upload-artifact` uses compression-level0 and no overwrite; the conservative ZIP bound is checked against the existing128MiB consumer cap. Uploaded archive bytes remain opaque.

Root later fills the actual stage0 carrier row using genuine terminal metadata. Its members have `member=name`, `name=name`, `role="stage0:"+name`, `container="ZIP"`, `outer_member=null`, and the whole pins above. `members()` emits these exact declarations. The remaining fields are an unissued draft until actual evidence and Root selection exist:

```json
{"repository":"Gabriel-Kahen/cachy-asahi","id":null,"run":null,"job":null,"source":null,"bytes":null,"sha256":null,"metadata_sha256":null,"job_metadata_sha256":null,"redirect_hosts":null,"members":null,"accepted_by_root":null}
```

Here `source` must be the provider's actual trusted-Main job/artifact head SHA. `job_metadata_sha256` is the genuine raw single-job endpoint response hash; do not substitute a selected jobs-envelope serialization. Root supplies the real uploaded ZIP digest/size, artifact metadata and exact allowed redirect hosts. Provider success establishes pinned DATA custody only. Native stage0 execution/compatibility, Rust Source publication, resource/dispatch admission and all existing hardware, performance, signature and release holds remain separate.

Run the inert-response controls from the repository root (no live downloads or archive code):

```sh
python3 -I -B -Werror::ResourceWarning scripts/ci/retained-rust-stage0-provider/test_collect.py
```

Root can add that exact command to source CI when integrating; this change owns only the new provider directory and its new manual workflow. The tests check fixed consumer/intake pin parity, bounded transfers/failures, closed ZIP layout and unissued provider bindings. The workflow has not been dispatched and no real provider artifact is claimed.

# Successor F: exact PQ wrapper and declared PostgreSQL grants

This batch closes **one composite upstream grant/notice evidence case**,
`pq-src 0.3.6+libpq-17.4`, reducing **91 unresolved cases to 90**. It does not
reach the 8–12 aim: the other candidates lack the required package/source
proof and receive zero credit. All prior reports and broader holds stay intact.

The package's declared license remains **PostgreSQL**. This work retains two
distinct actual grant/notice layers; it does not relabel the package MIT,
transfer ownership between those layers, or establish all-file/legal/native/
M2/release acceptance.

## Exact package and restored manifest

The complete published original manifest is **8,758 bytes**, SHA-256
`b515af637371396c35e5203e2da3fa28c70a96dc3c14baf8909e1789f4b195ad`.
It exactly matches the existing authenticated full-member hash and retained
8,192-byte prefix. The full body was recovered as inert DATA from the exact
version's official docs.rs source page, using the existing source-element
extractor. It additionally matches the upstream manifest Git blob at:

- Repository: `sgrif/pq-sys`.
- Recorded VCS commit: `2d59148f5613cc0d7de42ab21ba71bb32f8fd9d3`.
- Manifest: `pq-src/Cargo.toml`.
- Literal version: `0.3.6+libpq-17.4`; declared license: `PostgreSQL`.

The historical private capture remains truncated and unchanged. Replay
supplements it in memory only after both full-hash and prefix verification.
No private candidate packet or unknown source context is published.

## Separate actual grants and notices

| Scope | Exact source | Complete retained notice/grant |
| --- | --- | --- |
| Parent wrapper/source declaration | `LICENSE-MIT` at `2d59148f5613cc0d7de42ab21ba71bb32f8fd9d3` | MIT; Copyright (c) 2015-2017 Sean Griffin |
| Declared PostgreSQL submodule | `COPYRIGHT` at `f8554dee417ffc4540c94cf357f7bf7d4b6e5d80` | PostgreSQL grant; Portions Copyright (c) 1996-2025, PostgreSQL Global Development Group; Portions Copyright (c) 1994, The Regents of the University of California |

The package README expressly offers the wrapper's MIT/Apache alternatives
and matches the complete authenticated vendor README. The actual ancestor
MIT grant retains copyright/permission inclusion, warranty disclaimer and
liability exclusion. Its Sean Griffin notice is **not** assigned to PostgreSQL
C code. The differing package-manifest and README declarations remain visible;
this evidence does not determine a blanket exclusive license formula.

The exact `.gitmodules` blob declares `pq-src/source` from
`https://github.com/postgres/postgres`. The package tree's entry is mode
`160000`, type `commit`, at the exact child revision above. This establishes
upstream declared-submodule lineage without cloning or executing it. The
PostgreSQL root `COPYRIGHT` matches the primary child tree blob and retains
both notices, permission and reproduction conditions, and both disclaimer/
liability paragraphs. Its owners are not assigned to Rust wrapper code.

The same child tree and raw `configure.ac` independently establish
`AC_INIT([PostgreSQL], [17.4], ...)`. This is pinned **child source version
metadata**, not evidence that every bundled vendor file equals that child.
No configure script was executed.

`report.json` retains all URLs, byte counts, SHA-256/Git blobs, package version,
Gitlink and notice joins. Full vendor-C projection, third-party file notices,
installed notices, wrapper-versus-bundled license interpretation, activation,
all-file/legal/native/M2/release acceptance remain **HELD**. This is one scoped
composite notice evidence closure, not complete bundled-library qualification.

## Other candidates and resource bounds

The eleven `ra-ap-rustc_* 0.166.0` descriptions explicitly declare Rust source
commit `ce89c898570852a1bb441d77570596e50bf362c2` and identify the publisher.
That is retained revision evidence, but the publisher revision and generated
manifest transformation remain unproved and VCS captures remain missing.
They receive **zero package-closure credit**. No current publisher head/tag was
substituted for missing proof.

Fresh small metadata for `objc2 0.6.3` and `block2 0.6.2` established no complete
package grant. They receive zero credit; prior framework/SDK uncertainty is
unchanged. The remaining list preserves all 90 cases, including original
partial attribution, dirty/version, object-mismatch and platform holds.

Acquisition is closed at **13 actual HTTP requests / 223,877 body bytes /
237.949 seconds**, below **50 requests / 2 MiB / 15 minutes**. All thirteen
returned HTTP 200; no redirects, errors or retries occurred. The per-body cap
is 256 KiB; network timeout is 20 seconds with a 60-second transfer check.
TLS verification stayed enabled. Only exact-version source HTML, pinned raw
files and small primary trees were read.

```sh
python -I -B scripts/port/arm-rust-toolchain-inputs/source-closure/archive-inventory/checksum-successor/license-followup/compiler-notices/successor-f/reevaluate.py \
  --candidate-packet /tmp/cachy-checksum-successor-20261115-03/private-license-candidates.json \
  --output /tmp/new-notice-successor-f.json
python -I -B scripts/port/arm-rust-toolchain-inputs/source-closure/archive-inventory/checksum-successor/license-followup/compiler-notices/successor-f/test_reevaluate.py -v
```

Offline replay and all **nine controls passed**: full-hash/prefix restoration,
source extraction, Gitlink path/repository/mode/revision, both PostgreSQL
notices and conditions, ownership-scope separation, child-tree identity,
resource caps, closed acquisition, and actual replay preserving all holds.
Real replay skips if its intentionally private packet is absent. Replay uses
zero requests and a 256 MiB/30-second process bound; output is new below `/tmp`.
Primary files remain DATA. No archives, checkout, builds, package activation,
source/native actors, leases, trust, daemons, shared manifests or workflows
were changed. Only this new subtree is changed; Root owns integration and
publication.

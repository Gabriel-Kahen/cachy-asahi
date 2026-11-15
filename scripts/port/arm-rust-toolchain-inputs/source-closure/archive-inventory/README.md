# Authenticated source metadata inventory

This successor actually streamed both existing authenticated source archives.
It writes hashes and parsed declarations as JSON, never source member files.
No payload is evaluated, imported, executed or installed; links are not followed.
There is no network code or new source archive acquisition in the scanner.

| Archive | Physical headers, including extensions | Logical stream bytes | Wall seconds | Worker peak RSS |
| --- | ---: | ---: | ---: | ---: |
| Rust 1.99.0 | 413,568 | 4,077,516,800 | 14.596 | 169,861,120 bytes |
| LLVM 23.1.1 | 197,181 | 2,393,804,800 | 8.195 | 33,398,784 bytes |

Both final scans reached the tar/XZ end and revalidated the complete compressed
byte count and SHA256 against the previously authenticated inputs. The five
previously retained Rust/LLVM notices match their corresponding archive members
exactly. The new inventory pins additional source-root/Cargo notices and
declarations without copying their text. Earlier opaque and signature reports
remain unchanged as snapshots of those stages.

Concrete declaration findings in `reports/offline-gaps.json`:

- Rust contains 1,900 vendor component directories, each with a parsed Cargo
  manifest and checksum declaration. The main lock has 540 registry entries;
  Cargo's lock has 523. Every entry matches a vendor name/version/package-checksum
  declaration; neither lock declares a Git source. Individual vendored source
  file checksums were **not** verified, and crate archive availability is unknown.
- 119 vendor components lack regular files matching the scanner's explicit
  license-name predicate. Their manifest license expressions and checksums are
  retained for review. This is a bounded filename observation, not a finding
  that their licenses are absent or violated; custom files and README grants
  need further audit. Presence of other license-named files also proves no grant.
- Twelve Rust submodule paths are declared. Counts include 2,949 regular members
  under Cargo, 104,380 under Rust's LLVM fork, and only one under `src/gcc`.
  Occupied paths do not establish exact Git revisions or recursive completeness.
  Rust's LLVM fork and the separate upstream LLVM archive are distinct inputs.
- Stage0 declarations and source replacement configuration are pinned. No
  bootstrap components or actual offline build were run. The retained recipe
  explicitly chooses system rustc/cargo and disables CI LLVM/GCC downloads;
  neither those settings nor the metadata establish an accepted toolchain.

The five original notice matches cover only those exact files. Cargo's own
notices and LLVM's other component notices have separate byte pins. Recursive
third-party notice/grant coverage, original recipe correspondence, actual offline
build consumption, binary compatibility and release acceptance remain held.

`inventory.py` uses a strict streaming tar parser with bounded XZ output, rather
than allowing a general tar library to allocate extended headers implicitly.
Limits are enforced by counters and process limits:

- 500,000 physical headers and 8 GiB decompressed logical bytes per archive,
  including extension records, payloads and padding.
- 32 MiB per selected/extended metadata payload; no raw member payload is
  persisted. JSON output across both archives is limited to 16 MiB, with a
  supervisor reserve. Record, path and PAX limits can stop a scan earlier.
- A worker has a 448 MiB `RLIMIT_AS`; its sequential supervisor has a 64 MiB
  effective soft limit. The supervisor's inherited hard ceiling is 448 MiB so
  children can establish their worker bound. Effective simultaneous virtual
  ceilings sum to 512 MiB, which also bounds resident process memory.
- Worker alarms fire at 298 seconds; the supervisor kills a worker at 300
  seconds including report production. No jobs run concurrently.

The first attempt stopped on stricter internal decoder/prefix-table limits;
both partial reports are retained in `reports/attempt01/`. The successful
attempt uses a 320 MiB decoder memory allowance within the worker ceiling and
tracks directory prefixes, not every file path. `controls.json` pins both
attempts and records measured time/memory/output. Twelve parser controls and
two declaration comparison controls passed.

```sh
python -I -B scripts/port/arm-rust-toolchain-inputs/source-closure/archive-inventory/inventory.py \
  --cache /tmp/cachy-rust-source-closure-a3megt_w/cache \
  --output /tmp/new-source-inventory
python -I -B scripts/port/arm-rust-toolchain-inputs/source-closure/archive-inventory/analyze.py \
  --reports /tmp/new-source-inventory \
  --output /tmp/new-source-inventory/offline-gaps.json
python -I -B scripts/port/arm-rust-toolchain-inputs/source-closure/archive-inventory/test_inventory.py -v
python -I -B scripts/port/arm-rust-toolchain-inputs/source-closure/archive-inventory/test_analyze.py -v
```

Outputs must be new private paths below `/tmp`. `inputs.json` binds both exact
archives to the preserved original manifest and byte-identical pre-redaction
signature-stage snapshots in `authentication/stages/`. The public signature
successor subsequently gained an explicit redaction manifest and working replay.
Incomplete or unsupported scans report `PARTIAL`; they do not turn missing data
into an acceptance decision. Metadata comparisons have their own 128 MiB/30s
limits and retain the source report pins.

The separate [redistribution notice audit](../history-search/licenses/NOTICE.md)
retains the exact devtools GPL grant/license. Four PlugBuild UI source/base64
copies without a found grant were removed from the proposed current tree, with
hashes and primary URLs preserved. Root must also exclude those blobs from
public ancestor history; a deletion commit is insufficient. The complete older
private packet and its factual report remain retained privately. The current
public authentication replay passes with four explicit redactions, rather than
silently dropping their failed input pins. This inventory verifies the preserved
source-authentication evidence and exact archive identities directly.

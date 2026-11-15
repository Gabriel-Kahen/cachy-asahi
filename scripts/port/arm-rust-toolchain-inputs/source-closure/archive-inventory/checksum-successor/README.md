# Actual vendor checksum and license-content successor

The complete authenticated Rust source stream passes **117,695 file SHA256
comparisons across all 1,900 vendor components**. The separate 1,900 checksum
markers account for the remaining regular members: 119,595 = 117,695 + 1,900.
Every marker also matches its previously pinned inventory bytes/SHA256. Missing,
changed, extra, alias and refused-entry counts are all zero.

The final scan read 413,568 physical headers and 4,077,516,800 logical bytes in
15.393 seconds, with 233,562,112 bytes peak worker RSS. It reached XZ EOF and
revalidated the exact 265,258,564 compressed bytes and authenticated SHA256.
Minimum sampled MemAvailable was 14,761,611,264 bytes, above the 8 GiB reserve.
This is an actual data-integrity result, not original crate-archive authenticity,
binary/source correspondence, offline-build, legal or release acceptance.

Actual content review of the original 119 filename gaps found complete grant
text and scoped notices for **eight** cases. Fifteen exact license/notice spans
(53,780 bytes) are retained with their original member identities and byte
offsets. The remaining **111 stay UNRESOLVED**. The original name predicate
missed British LICENCE spellings and MIT grants in AUTHORS. See
[the content report](license-review/review.json) and
[retained notice provenance](license-review/retained-notices.json).

The review uses 428 bounded captures: 375 complete members and 53 prefixes.
Unknown full README/source content stays private. Absence outside those
captures is not asserted. Actual source-root grants are separately pinned in
`license-review/criteria.json`; Cargo/SPDX declarations are recorded as
declarations and never blanket source-root rights. All-file grant/notice
coverage remains held, including for the eight cases with retained grants.

`verify.py` reuses the byte-pinned earlier streaming parser without changing
earlier reports. Each regular vendor member is hashed once in its bounded
stream. In-memory actual/expected maps make comparison independent of file
order. Root checksum markers are regular and unique; nested marker basenames
are ordinary files. Marker self-checks, invalid digests, duplicate JSON keys,
unsafe paths, normalized duplicate paths, ancestor collisions and links are
refused. The inherited parser accepts a lone leading `./`; duplicate normalized
aliases are still refused. Nothing follows archive links or executes payloads.

The maps' bounded `$comment` strings are annotations only. They cannot supply
paths/digests or override the `files` map. Package checksums are distinct from
file hashes; rust_team_data has no package checksum, while its six actual file
hashes still pass. Original registry archive identity is not inferred.

Limits per scan are unchanged: 500,000 headers, 8 GiB decompressed logical
stream, 32 MiB individual checksum metadata, worker 448 MiB AS plus supervisor
64 MiB effective AS, and a 300-second supervisor watchdog (worker alarm 298s).
Preflight reserves 8 GiB available RAM plus process/output headroom; the reader
checks the available-memory reserve every half second and stops partially if
it falls below 8 GiB. Output has an additional 6 MiB per-invocation cap; all new
private/public successor metadata is measured against the delegated 16 MiB cap.
No network or new archives are used. Only metadata/captured prefixes are written
privately; the public packet contains reports and the explicitly reviewed
license/notice text, with no source member tree materialized.

`reports/attempts.json` preserves the earlier outcomes and private report pins.
Attempt 1 stopped partially at an overstrict schema check. Attempt 2 completed
the authenticated stream but left maps unresolved because of `$comment`.
Attempt 3 actually verifies every listed file. Earlier outcomes are not
rewritten. Sixteen meaningful controls pass, including changed/missing/extra
files, archive/JSON aliases, links, unsafe/self paths, optional package fields,
comment boundaries, low host-memory refusal and a bad compressed-source pin after matching file data.

```sh
python -I -B scripts/port/arm-rust-toolchain-inputs/source-closure/archive-inventory/checksum-successor/verify.py \
  --cache /tmp/cachy-rust-source-closure-a3megt_w/cache \
  --output /tmp/new-vendor-checksum-successor
python -I -B scripts/port/arm-rust-toolchain-inputs/source-closure/archive-inventory/checksum-successor/test_verify.py -v
```

Worker exit zero alone is not acceptance: inspect `checksums.json` for complete
authenticated-stream status and per-component results. A timeout, unsupported
map or resource limit remains partial/unresolved. The private candidate packet
is content-review evidence, not authorized source-publication material.

Scope is Rust's root vendor tree and its 119 target cases. LLVM's prior complete
inventory has zero root-vendor component records; LLVM is not rescanned here,
and no LLVM-wide checksum-discovery claim is made. Twelve submodule declarations
and their earlier member-count facts remain in the original `reports/rust.json`
for Root's separate reconciliation. All four original PKGBUILD/BUILDINFO
mismatches remain unresolved. No native/Source/Reader actor was invoked.

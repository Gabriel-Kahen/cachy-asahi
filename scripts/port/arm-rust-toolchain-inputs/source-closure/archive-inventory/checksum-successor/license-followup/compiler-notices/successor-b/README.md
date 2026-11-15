# Successor B: pinned Libffi and PHF notices

This batch closes **six additional scoped root-grant/notice evidence gaps**,
reducing the preceding **106 unresolved cases to 100**. These are exact
package/version/commit plus ancestor MIT grant and named notice joins. They
are not all-file licensing, active Linux/AArch64 dependency selection, legal
acceptance or release qualification.

| Exact component | Recorded upstream revision | Actual named root-license notice |
| --- | --- | --- |
| libffi 5.1.0 | `7b1471ad430dd899046280f79066fc2d9b0fac90` | Copyright (c) 2016 Jesse A. Tov |
| phf_codegen 0.10.0 | `3ea14b2166553ad6e7b9afe7244144f5d661b6c6` | Copyright (c) 2014-2016 Steven Fackler |
| phf_generator 0.10.0 | same exact revision | Copyright (c) 2014-2016 Steven Fackler |
| phf_shared 0.10.0 | same exact revision | Copyright (c) 2014-2016 Steven Fackler |
| phf 0.10.1 | `bed01538ae576876f11189d541875d228acef9e8` | Copyright (c) 2014-2016 Steven Fackler |
| phf_macros 0.11.2 | `c9c35fd8ba3f1bc228388b0cef6e3814a02a72c0` | Copyright (c) 2014-2022 Steven Fackler, Yuki Okushi |

Each original manifest has a literal matching version and an exact Git blob
match in its recorded VCS tree. Older VCS records omit a package path; their
actual subdirectory manifests are established by exact manifest blob joins,
not guessed from omitted fields. Complete MIT grants are retained separately
for the three PHF revisions, including their different notices. The newer
notice is not assigned to older versions. No attribution comes from author
fields, matching license text, or template placeholders.

Libffi inherits its license and repository. Its exact root workspace manifest,
Git blob and explicit `libffi-rs` member establish `MIT/Apache-2.0` and the
canonical repository. Official GitHub redirects from `tov/libffi-rs` and
`sfackler/rust-phf` to numeric repository IDs are retained. Separate official
repository metadata binds those IDs to `libffi-rs/libffi-rs` and
`rust-phf/rust-phf`. That metadata establishes repository identity only; it
does not substitute current licenses for pinned source files. Each grant has
an exact revision/path HTTP receipt, SHA-256 and Git blob check.

## Selection and unresolved work

Libffi is a static Miri dependency in the authenticated Rust root lock.
Optional/target activation and the selected Linux/AArch64 Miri configuration
remain unproved. The five PHF versions are authenticated checksum-PASS vendor
components outside both recorded Rust root and Cargo-tools locks. Their runtime
maps/shared support and build-time generators/macros are source-notice targets;
**no active compiler/runtime use is established**. This batch cannot be read as
six active Linux compiler dependencies becoming qualified.

Four unsuccessful selections remain unresolved:

- `ui_test 0.30.7`: the exact complete tree has no license file; no actual grant
  was established. Source/header ownership was not inferred.
- `anes 0.1.6`: the exact manifest blob is under `anes/`; ancestor license IDs
  match previously retained bodies without named notices. No named attribution
  was established and no new notice closure is claimed.
- `rsqlite-vfs 0.1.1`: the recorded revision returned HTTP 422 in the repository
  linked by its README. That link did not establish the source relationship.
- `line-index 0.1.2`: a primary root tree and complete ancestor Apache grant were
  retained, but no package-manifest join or named notice was established. The
  remaining request budget went to concrete PHF grant/notice joins.

The original partial intl_pluralrules/polonius/perf-event attribution cases,
all explicit dirty or unresolved-version cases, platform/feature constraints,
original recipe/BUILDINFO mismatches and submodule reconciliation remain held.
`report.json` includes the complete list of 100 remaining components. It does
not overwrite any preceding evidence or claim a full vendor-to-upstream file
projection.

## Actual acquisition and controls

Acquisition is closed at **20 genuine HTTP requests, 336,941 response-body
bytes, 160.998 seconds**, within 20 / 16 MiB / 900 seconds. This includes four
redirect responses (1, 4, 10, 12) and the HTTP 422 response (8). No request was
retried. TLS verification remained enabled. Only official metadata and pinned
primary files were fetched. There were no archive downloads/reads, checkouts,
builds, package activation, actor/lease changes, trust or daemon changes.

```sh
python -I -B scripts/port/arm-rust-toolchain-inputs/source-closure/archive-inventory/checksum-successor/license-followup/compiler-notices/successor-b/reevaluate.py \
  --candidate-packet /tmp/cachy-checksum-successor-20261115-03/private-license-candidates.json \
  --output /tmp/new-notice-successor-b.json
python -I -B scripts/port/arm-rust-toolchain-inputs/source-closure/archive-inventory/checksum-successor/license-followup/compiler-notices/successor-b/test_reevaluate.py -v
```

Offline replay uses zero requests and a 256 MiB/30-second process bound. The
preceding report is re-evaluated before these six joins. Output is new and
exclusive below `/tmp`. The private candidate packet stays private and is not
part of this commit. Upstream files remain DATA and are not executed.

All eight controls passed: exact alias/ID/revision identity, unrelated tree
rejection, inherited workspace provenance, revision-specific notices, sibling/
template/incomplete-grant rejection, error/redirect/body/time accounting,
closed acquisition, and complete real replay retaining the 100 holds. The
real replay control skips if the deliberately private packet is unavailable.

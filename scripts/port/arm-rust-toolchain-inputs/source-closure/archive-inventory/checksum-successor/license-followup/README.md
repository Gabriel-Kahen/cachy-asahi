# First upstream license followup

This finite batch closes **three scoped grant/notice evidence gaps** among the
previous 111 unresolved cases, leaving **108 unresolved**. The closed evidence
is an exact package-version/commit binding plus actual upstream root grant and
named notice. It does not close all-file licensing, legal acceptance, source
equivalence, original crate authenticity, native builds or binary admission.

| Exact package | Pinned upstream commit | Result |
| --- | --- | --- |
| fluent-langneg 0.13.1 | `7fdc590466ea63ca2367ac10fb1b881fe561f1a8` | MIT grant and Mozilla Foundation notice retained |
| ruzstd 0.8.2 | `fcc40ba1bc766ba38eca852cb64550c827d7068d` | MIT grant and Moritz Borcherding notice retained |
| thorin-dwp 0.10.0 | `89f541df648437083c40241e1c0e6bd93e308ce0` | MIT grant and Rust Project Developers notice retained |
| intl_pluralrules 7.0.2 | `d0715d5b7cca72e228d6e6c4de154bd30dfdd06a` | Actual grants retained; attribution unresolved |
| polonius-engine 0.13.0 | `741e6095fe50f468982d4d253e842eb7d12ed9d3` | Actual grants retained; attribution unresolved |
| perf-event-open-sys 3.0.0 | `6218ac1912aa2210b46713d5c5c51ddb4be805f5` | Actual grant retained; attribution unresolved |

Three cases have complete MIT grant text without named copyright in the fetched
grant. Authors, equal license bodies and Apache appendix placeholders were not
substituted for an actual copyright notice. Separate component-scoped files
preserve identical license-only bytes; no common ownership is inferred.

The targets were selected from the Linux compiler build inputs, using the exact
Rust lock graph instead of vendor-name parity. The primary Rust Cargo.lock at
commit `b940084d7eb6a299eb4bfeb8e34901bc051e7ac4` matches the previously
authenticated archive member byte-for-byte (160,984 bytes). All six have
dependency paths from rustc-main/rustc_driver, retained in `report.json`:
diagnostic macros through fluent-bundle, compiler borrow-checking structures,
object decompression, DWARF packaging and Linux profiling bindings. This is
static lock-graph reachability. Features, target cfgs and the selected
Linux/aarch64 Cargo graph were **not** executed or resolved. Three additional
pinned compiler Cargo manifests corroborate normal, non-optional dependencies
on thorin-dwp/object, fluent-bundle and measureme. The compiler object declaration
disables defaults and does not explicitly enable compression; active ruzstd
feature selection remains unproved. Its notice evidence is independent of that
priority limit.

Each exact Cargo.toml.orig capture has a Git blob ID matching the primary tree
at its recorded VCS commit. Literal package name/version and VCS path agree.
The records are not marked dirty; an omitted dirty flag is not called proof
that the entire tree was clean. Each retained grant's bytes independently match
its Git blob in that same complete tree, at package or ancestor root scope.
No full vendor-to-upstream file projection is asserted.

The old perf-event-open-sys repository returned HTTP 422 for the recorded commit.
The maintainer's perf-event monorepo contains that exact commit, path and
byte-identical manifest; its actual root MIT grant is pinned separately. The
old request remains in the receipt rather than being silently rewritten.
Polonius's official repository-ID redirect is also retained and counted.

Acquisition stopped at **20 HTTP requests and 592,376 response-body bytes**,
including the redirect and failed request, below 20 requests and 8 MiB. Only
primary pinned metadata/raw files were read. There were no archive downloads,
checkouts, archive reads or upstream payload execution. Existing private captures
and old reports are reused without modification. `primary-a/` contains the
three compiler/diagnostic proofs; `primary-b/` contains the remaining proofs and
the lock graph. `priority-notes.json` records the original static selection data.

`cases.json` is the small reviewed evidence table. The offline re-evaluator
checks frozen inputs, exact manifest/version/VCS identity, complete primary
tree receipts, license blobs, ancestor scope, named-notice bytes and source-
qualified lock edges. Eight controls cover changed evidence, wrong versions/
commits, dirty data, templates, inferred attribution, sibling scope, ambiguous
graph edges and aggregate HTTP limits. It does not turn keywords into a legal
decision; the retained complete grants were read and reviewed as source DATA.

```sh
python -I -B scripts/port/arm-rust-toolchain-inputs/source-closure/archive-inventory/checksum-successor/license-followup/reevaluate.py \
  --candidate-packet /tmp/cachy-checksum-successor-20261115-03/private-license-candidates.json \
  --output /tmp/new-license-followup-report.json
python -I -B scripts/port/arm-rust-toolchain-inputs/source-closure/archive-inventory/checksum-successor/license-followup/test_reevaluate.py -v
```

Replay makes zero requests and uses a 128 MiB/30s process bound. New output is
exclusive below `/tmp`. The required existing candidate packet contains unknown
source/README context and stays private; it is not publication material.
The other 105 cases were not upstream-reviewed in this batch; the three partial
attribution cases remain among the 108 unresolved. Explicitly dirty or missing
version-link cases are not promoted by this work. All four original
PKGBUILD/BUILDINFO mismatches and the separate submodule reconciliation remain
outside this directory and unchanged.

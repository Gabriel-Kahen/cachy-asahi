# Rust submodule identity joins

This finite offline verifier closes the twelve **metadata identity** questions at
Rust `b940084d7eb6a299eb4bfeb8e34901bc051e7ac4`. It does not close source,
recursive payload, notice/license, binary correspondence or build acceptance.
The sibling archive inventory, source manifest and workflows remain unchanged.

The retained authenticated archive scan pins the 1,508-byte `.gitmodules` member.
Its bytes match the exact official Rust Git blob. Five connected Rust Git trees
are reconstructed from their complete entry lists, including mode160000 gitlinks.
Each declared URL joins the official repository name, owner, numeric GitHub ID,
exact commit and reconstructed root tree. Repository ownership is an observation
at acquisition time and does not identify every copyright holder or grant.

Four read-only primary GraphQL metadata queries retained 64,921 response bytes
against a cap of 20 requests / 8 MiB. Queries and public metadata responses are in
`records/`; no credentials, source code payloads, private role outputs, archives,
checkouts or recursively fetched trees are included. The `.gitmodules` text is
Rust's source metadata, not a submodule payload. Parent Rust MIT/Apache notices
remain retained separately; no submodule license coverage is inferred.

## Replay

Supply the exact existing full archive report pinned by `inputs.json`:

```sh
python3 -I -B verify.py \
  --inventory-report /absolute/archive-inventory/reports/rust.json \
  --output /absolute/new-submodule-report.json
python3 -I -B -Werror::ResourceWarning test_verify.py
```

Paths to these scripts are relative to this directory. The report comes from
archive-inventory worker commit `3c76059f0031b2433f25bd1e0fd1400a0a8bfcb5`;
its 2,704,405 bytes/SHA256 are pinned. It is an explicit external operand and is
neither copied nor modified here. Parent signature evidence is rejoined, not
rerun; no large archive is opened. New output creation is exclusive.
The CLI and controls run with 128 MiB address-space limits; bounded ordinary
metadata reads use no-follow/nonblocking descriptors and a 4 MiB read cap.

## Remaining content gap

All twelve official repository commits resolve. All twelve archive payloads
remain unverified at those commits. Counts of occupied paths cannot substitute
for per-member identity, nested submodule closure or full license review.
Rust's `rust-lang/llvm-project` fork is distinct from the separately retained
upstream LLVM release archive.

GCC's exact root tree has 46 regular files totaling 5,061,455 bytes, while the
archive scan found only 1 regular member anywhere under `src/gcc`. Even granting
that one member matches the largest root file, at least 45 root files and
2,592,801 payload bytes are absent at their correct paths. This lower bound
excludes deeper GCC content and counts regular-member representations at pinned
paths; symlink targets or duplicate bytes elsewhere were not examined. The archive
scan did not retain the lone member's
name, so exact missing filenames and total recursive missing bytes remain
unknown. No bootstrap/provider changes or build necessity are inferred.

`report.json` gives all twelve pins, archive counts, fork provenance and holds.
`controls.json` records real replay and refusal-control results. Nothing here
admits a Native/Source/Reader/CI role, a package, ARM/M2 behavior or a release.

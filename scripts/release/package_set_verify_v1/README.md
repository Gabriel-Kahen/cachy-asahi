# Verify a selected local package set

This read-only operator command checks downloaded or retained candidate archives
before handing them to a separate installation/release workflow. It fills the
offline selection check between the raw `package_checks.py artifacts` command
and the larger signing/provenance/repository staging workflow. This supports the
finite package identity and file ownership work in
[release coverage](../../../docs/workstreams/full-port-release-coverage.md),
without changing the development inventory into a release selection.

```sh
python -B scripts/release/package_set_verify_v1/verify.py \
  --selection /data/release/release.json \
  --selection-sha256 "$authenticated_release_sha256" \
  --archive-root /data/release/repo > package-verification.json
```

Use the existing `release.json` format: integer `schema_version: 1`, a nonempty
`release_id`, and nonempty `packages` records with `name`, `version`, `arch`,
`filename`, and `sha256`. Other existing release/package fields are retained in
the input but do not grant additional checks. Package filenames must be direct
basenames. `any` and `aarch64` are supported. The selection must have at most 256
unique package names/filenames and occupy at most 4 MiB. Archives are capped at
512 MiB each and 2 GiB total compressed input, in addition to the current
validator's uncompressed/member bounds. The full selected set must fit these
limits; larger sets refuse rather than being partially verified.

Obtain the selection hash through the existing authenticated repository/release
workflow. Computing a hash from an untrusted downloaded selection does not
authenticate it. This command does not verify signatures. Only explicitly
selected archive basenames are inspected; extra directory files are ignored.
Use a stable local input directory; this is not a filesystem lease against
concurrent directory replacement. Symlink paths and nonregular files refuse.

Each archive is copied from one regular file descriptor to a private temporary
snapshot, with its exact bytes hashed before inspection. The command imports
the **current** `scripts/checks/package_checks.py`, records that implementation's
SHA-256, compares `.PKGINFO` name/version/arch with the selection, and invokes
its set-wide `conflicts()` API, including ancestor-file conflicts. It never
executes PKGBUILDs/package hooks or extracts archive payloads into the system.
Temporary snapshots are removed on completion. Python and zstd (for `.zst`)
are the existing validator requirements; no dependency is installed.

The deterministic JSON summary includes all selected identities, archive sizes,
per-package errors/review findings and cross-package conflicts. Exit codes:

| Code | Result |
| --- | --- |
| 0 | `STATIC_PASS`: exact selected bytes/identities and current structural checks passed, with no review holds |
| 1 | `FAIL` or `REVIEW_REQUIRED`: inspect the JSON findings on stdout |
| 2 | `REFUSED`: invalid/missing/changed/oversized input or inspection error; JSON diagnostic on stderr, no partial stdout |

The result establishes static selected-archive evidence only. Dependencies,
source/license closure, signatures, installation/removal, native ARM/16K runtime,
physical M2 behavior and release acceptance remain **NOT_ESTABLISHED**. In
particular, preserving Asahi's platform protections can refuse platform archives;
this is an overlay preflight, not an alternative platform admission policy.

Run the focused synthetic integration controls with:

```sh
python -B -m unittest discover -s scripts/release/package_set_verify_v1 -p 'test_*.py' -v
```

No shared manifest, static workflow, historical source profile or native actor
is changed. These controls do not constitute a package build or target trial.

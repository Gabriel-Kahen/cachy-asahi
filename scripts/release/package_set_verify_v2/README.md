# Verify a full selected package set

V2 extends the read-only local archive workflow to **1,024 selected packages**.
V1 and the current package validator remain unchanged. This addresses the
256-package selection limit in v1 without retaining every archive and complete
inspection report in memory or temporary storage.

```sh
python -B scripts/release/package_set_verify_v2/verify.py \
  --selection /data/release/release.json \
  --selection-sha256 "$authenticated_release_sha256" \
  --archive-root /data/release/repo > package-verification.json
```

The input is the existing release.json format: integer `schema_version: 1`, a
nonempty `release_id`, and unique `packages` records with `name`, `version`,
`arch`, `filename`, and `sha256`. Archive filenames are direct basenames;
architectures remain `any` or `aarch64`. Only selected files are inspected.
Authenticate the selection hash using the existing repository/release workflow;
hashing an untrusted selection does not authenticate it. Signatures are not
verified by this command.

Each archive is hashed into one private snapshot. A resource-limited worker
checks the exact current validator SHA-256 before calling its `package()` API.
The parent retains a bounded summary, writes only member paths/types and archive
labels to a private JSON-lines spool, and deletes that snapshot before inspecting
the next archive. A final bounded worker calls the current `conflicts()` API on
all spooled projections together. Sharing directories, duplicate file ownership,
ancestor-file conflicts and metadata exclusions retain the API's semantics and
finding order across the entire selection. No chunk boundary can hide conflicts.

| Resource | Maximum |
| --- | --- |
| Selection | 1,024 packages; 16 MiB JSON |
| Archive inputs | 512 MiB each; 64 GiB aggregate compressed bytes |
| Archive namespace | 131,072 members per archive; 1,000,000 aggregate members |
| Namespace spool | 128 MiB |
| Worker address space / CPU / wall time | 1 GiB / 60 CPU seconds / 90 seconds per worker |
| Worker output / retained summaries | 32 MiB each |
| Final stdout report | 64 MiB |

Workers use Linux resource limits, so this version requires Linux, Python and
the current validator's zstd dependency for `.zst`. The validator's existing
128 MiB member and 512 MiB payload bounds also apply. Resource exhaustion or an
unsupported large archive remains a refusal; increasing the selection count
does not bypass those checks. Temporary archive storage holds at most one
512 MiB snapshot, alongside the spool and bounded worker output files. Caller
inputs are not modified. This is bounded processing, not a reservation of free
disk space or protection against concurrent replacement of input directories.

Operators can lower aggregate budgets with `--max-total-bytes`, `--max-members`
and `--max-spool-bytes`. Zero, negative and above-policy budgets refuse. The JSON
report includes configured budgets and actual copied archive bytes, member
count, spool bytes and largest snapshot. Every budget or worker failure removes
private temporary files and exits 2 with a JSON diagnostic on stderr and no
partial stdout. Exit 0 means `STATIC_PASS`; exit 1 means `FAIL` or
`REVIEW_REQUIRED`, with findings on stdout, exactly as in v1.

Protected Asahi package names/relations/paths, structural errors and review
holds remain unchanged. There is no platform exception. Dependencies,
source/license closure, signatures, installation/removal, native ARM/16K runtime,
physical M2 behavior and release acceptance remain **NOT_ESTABLISHED**.

The full-count control retains all **607** names and versions from the current
generic software/test-install lock, whose provenance is in `testdata/provenance.json`.
It generates explicitly synthetic inert archives; the lock has no architecture
or archive hash fields. All 607 records are inspected, and the existing protected
name errors remain for Mesa, Asahi Audio, speakersafetyd and ALSA UCM Asahi.
This is capacity and refusal evidence, not a successful real 607-archive release
verification. The documented 624-package alternative remains unadopted.

```sh
python -B -Werror::ResourceWarning -m unittest discover \
  -s scripts/release/package_set_verify_v2 -p 'test_*.py' -v
```

The dedicated `package-set-verification-v2-source.yml` workflow runs these
controls alongside the unchanged v1 and existing validator controls. No shared
manifest, static workflow, historical source, build actor or target system is
changed.

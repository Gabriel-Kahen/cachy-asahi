# Offline release source mirrors

`scripts/release/release_source_mirror.py` exports an existing caller-pinned
`release.json` and its exact package set. It reuses `release_sbom`,
`source_delivery`, `recipe_source_delivery`, and the offline
`source_materials.prepare` path. It never evaluates PKGBUILDs, runs retained
Python, extracts to the filesystem, fetches sources, or installs packages.

The output contains `mirror.tar`, a standalone `verify.py`, and
`mirror-receipt.json`. The deterministic USTAR contains a `mirror.json` index,
the verifier, and SHA-256-addressed objects. Identical objects are stored once
across packages and roles. Original package/source archive bytes are retained
alongside source files, so archive-internal duplication is preserved. Indexes
contain relative paths and content hashes; wall-clock time and input/output
locations do not affect bundle bytes.

## Export

Authenticate the release digest through your established release trust process.
This tool verifies that digest; it does not verify release signatures.

```sh
python -I -B scripts/release/release_source_mirror.py export \
  --release-dir /absolute/path/to/retained-release \
  --release-sha256 "$release_sha256" \
  --output /absolute/path/to/fresh-mirror
```

Every package must have a complete registered source-delivery association,
matching package/provenance/recipe identities, format-2 `.BUILDINFO` with an
installed dependency lock, source map, notices, existing review artifact, and
matching source/package license text. Missing, conflicting, unsafe or changed
required inputs refuse the whole export before its output directory is created.
An existing output directory is never overwritten. An I/O failure while writing
may leave a partial fresh directory; only a successful result confirms export.

Two source paths are supported:

1. Existing exact current/legacy `recipe_source_delivery` profiles. Its pinned
   recipe/SRCINFO pairs, complete source sets and payload correspondence remain
   unchanged. Extra remote provenance references require retained input and
   therefore refuse this path.
2. A source-delivery bundle containing literal `PKGBUILD`, `.SRCINFO`, all local
   sources/notices/hooks and their exact source map, plus an explicitly pinned
   supplemental descriptor for every HTTPS recipe source. The exporter calls
   the existing offline source-materials validator and checks the retained
   cache objects, receipts, catalog notices and release provenance together.

Source bundles must be bounded, uncompressed USTAR regular files/directories.
Links and special members refuse. VCS/`SKIP` source recipes, epoch/split-package
metadata and other bundle profiles currently refuse; add reviewed support in a
separate change. Remote source bytes remain opaque data and are never unpacked.

## Retained HTTPS inputs

Add these options for the second path:

```sh
  --retained-inputs /absolute/path/to/inputs.json \
  --inputs-sha256 "$inputs_sha256" \
  --retained-root /absolute/path/to/private-retained-root
```

The supplemental descriptor has this shape (use actual hashes and byte counts):

```json
{
  "schema_version": 1,
  "purpose": "release-source-mirror-inputs",
  "packages": [{
    "package": {"name": "demo", "version": "1.0-1", "arch": "aarch64", "sha256": "PACKAGE_SHA256"},
    "plan": {"id": "plan", "path": "plan.json", "sha256": "PLAN_SHA256", "bytes": 123},
    "catalog": {"id": "catalog", "path": "catalog.json", "sha256": "CATALOG_SHA256", "bytes": 456},
    "cache": "cache"
  }]
}
```

All descriptor paths are relative to `--retained-root`. The existing source plan
uses purpose `offline-build-sources`, the exact source-bundle file hash map as
`recipe_inputs`, a pinned source-cache catalog digest, and complete ordered
remote bindings. The catalog/receipts use the existing `source_cache` format.
The source cache must already be populated and private. Missing objects or
receipts refuse; export never acquires them. Source-plan/catalog revisions,
URLs and fixed recipe SHA-256 sums must agree. Provenance must cover exactly
those retained remote URLs, and catalog license evidence is retained without
interpreting it as permission.

## Relocate and verify offline

Retain the authenticated mirror digest and release digest separately from the
bundle. Prefer your trusted installed exporter for verification:

```sh
python -I -B scripts/release/release_source_mirror.py verify \
  --bundle /new/location/mirror.tar \
  --sha256 "$mirror_sha256" --release-sha256 "$release_sha256"
```

For a standalone recipient, first authenticate `verify.py` against the
`verifier_sha256` in the trusted export receipt using a trusted SHA-256 tool.
Then run the same command using `/new/location/verify.py`. The receipt itself
must come through the trusted export channel; a receipt shipped beside an
untrusted script does not authenticate that script. The verifier uses only the
Python standard library, reads no sibling helper/source modules, and works
without the original repository, release directory, cache or network.

Verification checks the entire pinned TAR, canonical member set/metadata,
object inventory/digests/lengths, original pinned release and file bindings,
exact package/provenance identities, source index/map/bundle/recipe joins,
report input coverage, and supplemental plan/catalog/receipt/license joins.
It reads source members as bytes. It does not repeat the exporter's package
archive decoding or execute the archived verifier/source files. The
authenticated mirror digest binds the exporter's full validation result.

The retained build context and dependency lock identify supplied build evidence;
they do not supply dependency source archives or establish a rebuild. Hash and
metadata joins do not establish complete corresponding source, redistribution
permission, native ARM execution, installed behavior, M2 compatibility,
performance, or release acceptance. These remain explicit non-acceptance fields.
Unknown/multiple license declarations remain `NOASSERTION` where the existing
coverage model permits them; text is retained without a legal conclusion.

Current bounds are 64 MiB per object, 512 MiB unique object data, 256 packages,
and 16,384 objects. The shared SBOM/source readers impose their own smaller
metadata/member/source limits. Large source sets refuse rather than weakening
the bounds silently.

## Proposed release hook

After the coordinator authenticates a completed release directory, invoke the
export command above as an opt-in sibling export. Record the mirror and verifier
hashes in the release publication plan. No hook or package selection change is
included here; `release.py`, `release_sbom.py`, source profiles and shared
manifests remain byte-held. Publication and native/hardware trials remain with
the integration coordinator.

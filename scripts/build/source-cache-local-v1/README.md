# Import retained archives into an offline build cache

The existing cache CLI can acquire a reviewed HTTPS object or verify an existing cache. It cannot seed a fresh cache from an already retained, exact archive. `build_v2.py --network none --source-plan ...` therefore cannot use such an archive without network acquisition or manual cache construction.

This versioned command imports one explicitly selected local material into an existing private source cache. It validates the independently reviewed catalog SHA256, material length/hash, revision/catalog association and notice bytes through the existing source-cache validator. It opens an owned, single-link ordinary0600/0644 source without symlinks, checks its held descriptor/path identity, and hashes it before any cache write. A cache hit still validates the caller's source. An isolated module instance substitutes only the local stream transport; other HTTPS callers and all existing private-cache/no-clobber/object/receipt validation code remain unchanged.

Initialize a fresh private cache using the existing command, then import:

```sh
python3 -I -B scripts/maintenance/source_cache.py init --cache /absolute/private/source-cache
python3 -I -B scripts/build/source-cache-local-v1/import_source.py \
  --cache /absolute/private/source-cache \
  --inputs /absolute/reviewed/source-inputs.json \
  --inputs-sha256 INDEPENDENTLY_REVIEWED_CATALOG_SHA256 \
  --id EXACT_CATALOG_MATERIAL_ID \
  --local-archive /absolute/retained/upstream.tar.gz
python3 -I -B scripts/maintenance/source_cache.py verify \
  --cache /absolute/private/source-cache \
  --inputs /absolute/reviewed/source-inputs.json \
  --inputs-sha256 INDEPENDENTLY_REVIEWED_CATALOG_SHA256 --id EXACT_CATALOG_MATERIAL_ID
```

The same cache works with the existing `scripts/build/build_v2.py` offline source-plan interface. Catalog URLs remain reviewed source identifiers; importing never contacts them or claims an HTTP transaction. The existing generic cache receipt binds the reviewed catalog/material/notice record without HTTP metadata. A separate deterministic `receipts/local-import-<catalog-sha256>-<id>.json` records local acquisition, exact bytes/hash, zero network fetches and no archive execution. Keep it with the cache as acquisition provenance. Existing build evidence retains its existing generic receipt; it does not automatically copy this additional local-origin receipt.

The default source limit is64MiB; `--max-bytes` may explicitly raise it to the existing512MiB per-file maximum. One ID is accepted. The timeout defaults to120seconds and may not exceed600; the CLI enforces a real-time alarm in addition to per-read and original-deadline checks, and refuses to replace an existing alarm. Source changes, missing files, bad pins/notices, unsafe files and existing conflicting cache entries refuse without network fallback or replacement of the conflicting object. A failure after cache publication may leave already validated cache objects or generic receipts; preserve and verify them rather than treating a failed invocation as successful acquisition.

This stages data only. It performs no download, extraction, Docker/GPG invocation, build, installation or source execution. Notice validation does not establish license clearance or sufficient notices. No publisher-signature, complete-source, ARM/16K/M2, reproducibility, performance or release acceptance is granted.

Run the new source-only controls:

```sh
python3 -I -B -Werror::ResourceWarning scripts/build/source-cache-local-v1/test_import_source.py
```

The real retained zlib archive exercises import, ordinary offline verification, and the unchanged offline source-material staging consumer. The other controls cover missing/tampered/unsafe input, catalog/notices, budgets/deadlines, in-stream changes, cache-hit validation, preserved bad cache/provenance, repeated imports and transport isolation. No recipe/archive code or container runs in these controls.

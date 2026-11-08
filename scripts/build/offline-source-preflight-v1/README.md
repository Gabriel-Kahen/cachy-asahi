# Check an offline source plan before starting a builder

`source_cache.py verify` checks reviewed cached materials. It does not bind those materials to a recipe. `build_v2.py` performs that binding, but its interface also requires a pinned container image, architecture mode, build output, epoch and package lock. This command exposes the existing source-material validator directly so developers can check an offline recipe/source binding before preparing a builder.

```sh
python3 -I -B scripts/build/offline-source-preflight-v1/preflight.py \
  --recipe /absolute/reviewed/recipe \
  --source-plan /absolute/reviewed/source-plan.json \
  --source-plan-sha256 INDEPENDENTLY_REVIEWED_PLAN_SHA256 \
  --source-catalog /absolute/reviewed/source-inputs.json \
  --source-cache /absolute/private/source-cache
```

The plan hash is a caller-supplied review anchor; computing it from an unreviewed input does not establish trust. The existing recipe parser reads literal metadata without executing the PKGBUILD. The unchanged `source_materials.prepare()` checks the complete recipe input map, ordered remote source coverage, URL/revision/hash binding, catalog pin, notice bytes, private cache objects and generic provenance receipts. A missing or changed object/receipt refuses; there is no download or repair fallback. Populate a cache with the existing HTTPS acquisition command or `source-cache-local-v1/import_source.py` first.

The command writes its JSON report to stdout and returns zero only for `VERIFIED_OFFLINE_SOURCE_BINDING_ONLY`. It does not write cache objects, receipts, partials or locks: the validator invokes `source_cache.run(..., offline=True)`, whose missing-object and missing-receipt branches refuse before creation. Normal filesystem access-time updates may still occur. The CLI enforces a 120-second wall-clock limit and refuses to replace an existing real-time alarm. Existing validator limits remain: at most 128 source bindings, 4MiB JSON, 512MiB per material and 2GiB selected material total. Recipe traversal retains the existing static validator's behavior.

This is source DATA verification at the time of the check. A later build must still run its own complete verification. There is no staging, extraction, source execution, Docker, network, GPG, build, installation or native dispatch. Notice checks grant no legal or complete-source acceptance. No signature verification, native ARM/16K/M2, reproducibility, performance or release acceptance is established.

Run the eight source-only controls:

```sh
python3 -I -B -Werror::ResourceWarning scripts/build/offline-source-preflight-v1/test_preflight.py
```

They use the retained real 1,502,830-byte zlib archive with the repository's baseline/LTO recipes and pinned fixture manifest. Tests cover read-only successful CLI use without builder arguments, both recipe plans, missing/tampered object or receipt, recipe drift despite a valid cache, plan integrity/coverage/duplicate keys, notice/private-cache refusal and outer-alarm behavior. No recipe or archive executes.

# Finite offline-source build batches, interface v2

`build_batch_v2.py` explicitly selects `build_v2.py` and reuses the existing rebuild planner, provider witnesses, image dependency checks and finite scheduler. Legacy builder, batch and output entrypoints are unchanged. The initial delivery had host/source controls only. The later [Source129 native batch component](../validation/offline-source-batch129-native-component-20261027.md) qualifies the recorded offline build/retry workflow; installed Asahi, native16K, M2, performance and release acceptance remain separate.

Use `--builder-interface offline-build-v2`. Supply the existing reviewed batch input/config/planner and their SHA256 values. Dependencies must already be at reviewed versions in each immutable image lock; completed prerequisite artifact hashes must match the reviewed pins before a dependent task starts. The adapter installs nothing and creates no dependency image.

Add a separately reviewed `--sources` JSON and `--sources-sha256`:

```json
{
  "schema_version": 1,
  "builder_interface": "offline-build-v2",
  "tasks": {
    "PACKAGE": {
      "source_plan": "/absolute/reviewed-plan.json",
      "source_plan_sha256": "EXACT_REVIEWED_SHA256",
      "source_catalog": "/absolute/catalog.json",
      "source_cache": "/absolute/existing-private-cache"
    }
  }
}
```

Bindings must cover every task exactly. Each plan binds its own complete recipe-input map and ordered remote source/catalog selections. The current interface supports reviewed HTTPS archive plans; it refuses missing plans, sources, receipts, ambiguity and incompatible recipes. No fetching, cache repair or implicit legacy fallback occurs. `source_materials.prepare` uses `source_cache.run(..., offline=True)` to verify existing private cache data; original code, plan, catalog, notice, cache-object and receipt bytes are pinned before/after admission and execution.

Use the same reviewed arguments for `plan` and `execute`. `plan` emits deterministic admission JSON; `execute` additionally requires `--admission-sha256` and a fresh `--output`. A second independent batch needs another fresh output root. Resume uses the same admission and `--resume --retry PACKAGE`; unchanged successful tasks are reverified rather than rebuilt. Changed reviewed inputs, source data or successful output trees cause refusal.

Each clean v2 builder receives only its selected staged source files at `/offline-sources`, read-only, with network disabled. The cache root is never mounted. Outputs retain the complete plan/catalog, source-cache receipts, notices, source bytes and selection, all joined to provenance and the batch checkpoint. The v2 cleanup checks the exact five mounts, pinned image identity and owned container name.

For output admission, create the existing `local-build-output-candidate` spec with two fresh batches, admission/state hashes and a pair for every completed package. Then run:

```sh
python -B scripts/maintenance/build_outputs_v2.py candidate \
  --builder-interface offline-build-v2 --spec /absolute/spec.json \
  --spec-sha256 EXACT_SPEC_SHA256 --output /absolute/existing-manifest-directory
```

The consumer verifies both complete native batch states, distinct clean environment IDs, original graph metadata, complete source material and byte-identical package pairs. It can replay retained evidence after the original cache is removed. `inspect-build` is a narrower integrity view and reports `source_task_admission: NOT_CHECKED`; it creates no candidate. All candidates remain local, unsigned and unauthenticated, with licensing/source-completeness approval, installation, capacity, M2, performance and release acceptance unestablished.

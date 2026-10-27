# Import a retained release for maintenance planning

`scripts/maintenance/import_release_graph.py` adapts retained release/package
metadata and explicitly selected local recipes to the inputs used by
`rebuild_plan.py` and `update_plan.py`. It reads DATA only, with bounded file,
archive, recipe namespace and output sizes. It never runs PKGBUILDs, fetches,
builds, installs, signs, publishes or discovers the host package inventory.

Supply a SHA-256-selected JSON selection containing these exact fields:

| Field | Retained input |
| --- | --- |
| `schema_version` | Integer `1` |
| `release_id`, `snapshot_id` | Explicit pre-change DATA identifiers |
| `inventory` | `{path, sha256}` for the retained `name version` lock |
| `manifest` | `{path, sha256}` for existing release `packages` and `projects` records |
| `extension_profile` | `{path, sha256}` for an existing `incoming` map, or `null` |
| `metadata` | `[{file: {path, sha256}, select: [...], format: "lock" or "pkginfo"}]` |
| `archives` | Explicit `{path, sha256}` package files for metadata-only inspection |
| `recipes` | `[{package, path: ".../PKGBUILD", files: {relative_file: sha256, ...}}]` |
| `changed` | Existing rebuild planner `{sources, toolchains, advisories}` declaration |

All input paths are canonical relative paths beneath `--root`. `select` follows
at most eight JSON object keys to an existing list or map of records. `lock`
records retain the existing package-lock shape: binary name, version, archive
hash, architecture, depends/provides/conflicts/replaces and license/URL
declarations. `pkginfo` accepts existing metadata reports with `.PKGINFO` and
optional `.BUILDINFO`, or their direct metadata objects. Package archive bytes
are read without payload extraction; only metadata is interpreted. Each selected
file must be at most 8 MiB, with at most 512 files/96 MiB total. Recipe selections
bind the exact bounded directory namespace before the existing static audit.

```sh
python -B scripts/maintenance/import_release_graph.py \
  --selection selected-inputs.json --selection-sha256 "$selection_sha256" \
  --output bundle > imported-review.json
```

`--output graph` and `--output inventory` emit deterministic consumer-compatible
JSON. Retain the full bundle alongside both outputs: it carries exact selected
input pins, per-package provenance distinctions, correspondence errors and
unresolved holds. Invalid/tampered/inconsistent inputs exit 2 without partial
stdout. Exit 0 means DATA import succeeded, never maintenance acceptance.

Names, versions and archive hashes must agree with the selected pre-change
inventory. Explicit extensions select newer versions; ambiguous same-version
archive identities refuse. Project membership also requires the exact
name/version/archive hash. A matching local recipe cannot turn an external ARM
package into a project-built package. Binary names, pkgbase, source build IDs and
virtual provides stay distinct. Unknown external build dependencies remain
omitted rather than being declared empty; the existing planner conservatively
holds incomplete build coverage. Owners and native builder capacity stay null.

For project recipes, the existing auditor/normalizer retains architecture-aware
dependencies and immutable declared source pins. Available archive metadata is
compared with the existing `.BUILDINFO` recipe-hash binder. This establishes
metadata correspondence only. Missing source archives, unbound source-only
metadata, implicit toolchains, owners, ARM affectedness/fixes and operational
capacity remain explicit holds. A source-only bridge requires matching retained
project runtime relations and recipe identity; it never establishes archive
architecture or build acceptance. License/URL declarations are kept separate
from corresponding source/license closure and signature authentication.

The retained 607 example is in
`artifacts/development/maintained-release-graph-import-development-20261027/`.
Its selection imports 607 exact versions, preserves 583 external packages and
24 project-release memberships, and joins 21 recipe records. Thirteen have
matching archive metadata/recipe hashes; seven require held source-only bridges.
Two recipes lack declared local source archives. The current Welcome8 recipe
hash differs from the retained archive's `.BUILDINFO`; that correspondence stays
unverified. No fetched/rebuilt replacement was substituted.

The example also feeds the generated inventory to the canonical advisory
producer and then joins its report and generated graph with `update_plan.py`.
Its advisory DATA is **deliberately synthetic**; it is not an official advisory
or a security finding. Every resulting group remains held. The 607 input join is
host/source tooling evidence, separate from historical generic VM acceptance,
authenticated ARM mitigation, a maintained release or physical M2 acceptance.

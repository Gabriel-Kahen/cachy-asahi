# Offline maintenance update planning

`scripts/maintenance/update_plan.py` joins an existing advisory review report to
the frozen M5 rebuild planner. It prints exact advisory roots, source-build
groups, transitive consumers, prerequisite order, baseline inputs and actionable
holds. It performs no network access, builds, installation, signing, publication
or source changes.

Retain the original `inventory.json`, tracker `advisories.json`, `provenance.json`
and `report.json` from `security_advisories.py`. Supply a pre-change release/build
graph in the format documented in [rebuild-planning.md](rebuild-planning.md), with
the exact same binary package set, versions, architectures and, where supplied,
provides metadata. Include source IDs, recipe/source pins, dependency records,
owners and capacity. Run with independently selected SHA-256 digests:

```sh
python -B scripts/maintenance/update_plan.py \
  --inventory inventory.json --inventory-sha256 "$inventory_sha256" \
  --advisories advisories.json --advisories-sha256 "$advisories_sha256" \
  --provenance provenance.json --provenance-sha256 "$provenance_sha256" \
  --advisory-report report.json --advisory-report-sha256 "$report_sha256" \
  --graph graph.json --graph-sha256 "$graph_sha256" \
  --as-of 2026-10-26T20:00:00Z --max-age-hours 24 --format json
```

Use `--format text` for an action list. The command replays the original report
against its original inventory/cache/provenance using the existing Arch version
comparator. Tampering, inconsistent identities, invalid pins, unsupported graphs,
future dates or wrong digests refuse with exit 2 and no plan on stdout. Stale
cache/report inputs produce an exit-0 **held** plan with refresh actions. Exit 0
means a plan was produced; inspect `maintenance_review_held`, `global_holds`,
`package_reviews`, `maintenance_groups` and `rebuild`.

Every exact binary advisory match seeds review, including versions at or above
Arch's fixed reference. `pkgbase`, virtual provides and recipe `source_id` remain
distinct; they are never advisory aliases. Same-source outputs and provider edges
are used only for rebuild planning. Missing matches create coverage holds,
without inventing change roots or asserting safety. Graph
`unaffected_by_declared_graph` means only no declared change path was found.

ARM affectedness and fixes remain **UNKNOWN**. Retain separate reviewed source,
patch, authenticated ARM build and target evidence for the responsible
maintainer; this command does not accept JSON claims as mitigation evidence or
release acceptance. Owners/capacity/pins are supplied records rather than
authenticated staffing or build results. Missing owners/pins remain visible even
outside affected groups. Held prerequisites block downstream groups. Existing
graph holds, cycles, ambiguous providers and external-update reviews survive.

Inputs are bounded to the frozen planner's 4096-package/root batch and a bounded
replay expansion. Larger advisory sets refuse before report generation; retain
the complete original report and select a smaller explicit planning batch with
its corresponding producer report and dependency graph. Inventory and graph must
describe exactly that selected package set. Batching never proves complete
system/advisory coverage; missing dependency providers remain held.

The exact reviewed provider-aware rebuild implementation is required. Dependency drift
requires review and repinning; no solver is silently substituted. Digests bind
bytes rather than authenticate origin. Native ARM, ARM16K, physical M2,
build/update lifecycle, maintained operations and release acceptance remain
separate checks.

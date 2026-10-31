# Finite repository rebuild planning

`python -B scripts/maintenance/rebuild_plan.py --input INPUT.json
--input-sha256 SELECTED_SHA256 --format json` emits an offline review plan to
stdout. `--format text` produces a readable prerequisite list, reasons, holds,
and input reviews. A valid plan exits 0 even when held; invalid input, mismatched
digest, exceeded bounds, or unavailable `vercmp` exits 2 without a plan. A plan
never establishes successful builds, solved dependencies, advisory mitigation,
installed behavior, target compatibility, or release acceptance.

The input is a single JSON object with these fields:

| Field | Explicit input |
| --- | --- |
| `schema_version` | Integer `1` |
| `metadata_role` | Exactly `pre-change-release` |
| `release_id`, `snapshot_id` | Selected finite release and base identifiers |
| `packages` | Unique release/base binary package rows with `name`, complete `version`, `arch` (`aarch64`/`any`), `depend`, `provides` |
| `sources` | Unique `{id, recipe_sha256, sources}` rows; source descriptors use the existing provenance `{url, sha256 and/or commit}` shape |
| `build_dependencies` | Unique `{package, source_id, makedepend, checkdepend, toolchain, disposition, owner, hold_reason}` rows |
| `changed` | `{sources: [source_id], toolchains: [binary_package_name], advisories: [{package, reference}]}` |
| `capacity` | `{native_aarch64_slots: integer or null, owner: string or null, reference: string or null}` supplied by the operator |

Use the **pre-change** release's metadata and source pins. This preserves provider
offers and relations that the proposed change may remove. A single post-change
snapshot cannot recover a removed virtual offer when another provider satisfies
the same dependency. Post-change and newly introduced dependencies are outside
this plan; final candidate consistency still requires the existing dependency
and release checks. `metadata_role` records the caller's claim, not verification
that the supplied metadata actually predates a change.

Each `build_dependencies` row maps one binary output to its source-build ID;
all outputs sharing an ID are one build unit. `source_id` may be null to retain
unknown source coverage. The relation lists must be explicit arrays, including
empty arrays. `toolchain` records implicit build inputs such as compiler, linker
and build-image tooling absent from recipe `makedepend`. The caller must include
them; they are not discovered from the host. Architecture-specific/inherited
recipe dependencies must already be expanded for the selected aarch64 build.
`checkdepend` is conservatively included even when a future build might skip tests.

`disposition` is `build`, `external`, or `hold`; `hold` requires a non-null reason.
Owners may be null, which holds affected work. Capacity zero/null, missing
capacity owner, or missing capacity reference holds the plan. Positive slots are
recorded, not measured or reserved; the planner does not generate a generalized
resource schedule or duration estimate. Assign real owners and independently
establish capacity before execution.

`packages` accepts the package metadata shape from release/base inventories.
Additional artifact fields are not verified. Join their names to the chosen
release's retained provenance for `sources`, reusing `recipe_sha256` and `sources`
without reinterpreting URLs. Supply reviewed build metadata from recipes/build
records separately: runtime metadata does not describe a complete build
environment. Combine the explicit effective release and base package set first;
duplicate binary names are refused rather than silently choosing an overlay.
This command performs no signature checks. An input checksum binds selected bytes
and is not origin authentication.

The planner imports `check_source_pins.py` to reuse its pin validation and
`release.py` relation matching, with real Arch `vercmp` ordering. It does not copy
or extend a package solver. `compare_releases.py` already reports possible runtime
consumers across two signed releases; it explicitly does not check build
dependencies. This planner fills the separate build-input ordering gap. A caller
can select roots from changed binary packages, source-pin preview changes mapped
through explicit source IDs, or advisory-review reports. Advisory roots use exact
binary names only. Virtual provides and source names never become advisory
aliases. These are review triggers, not asserted fixes.

Impact follows runtime, make, check and toolchain inputs in reverse, expanding
same-source outputs together. It retains every matching virtual provider and
holds ambiguous consumers instead of selecting one. Named providers that fail
a version constraint also retain **review** edges with `relation_satisfied:
false`. Such edges cannot prove availability and hold affected consumers.
Completely unavailable-input consumers are selected for review whenever any
change roots are supplied. This favors extra review over omitted impact; it is
not a minimum rebuild-set calculation.

Missing runtime/build metadata selects the package for review when there are
change roots. Missing `provides` makes provider coverage unknown, so the whole
finite set is selected and held. Missing source pins hold affected work. Unmapped
source rows are retained and globally held. Unavailable change roots trigger
whole-set review with the unresolved root preserved. Malformed/duplicate records
are refused. Lists, provider probes, graph edges, traversal work, input bytes and
JSON output are bounded and never silently truncated. No roots means no invented
rebuild work; coverage and dependency issues remain visible in JSON.

Output supplies package reasons, matched/rejected input edges, transitive baseline
prerequisite reviews, SCC groups, and prerequisite-first `groups` and
`prerequisite_levels`. Levels express dependency structure and ignore slot
counts. Cyclic groups, including a dependency within one source-build unit,
require an independently reviewed bootstrap strategy. The planner does not pick
an old compiler or break cycles. Held prerequisites hold downstream groups.
Unchanged baseline inputs remain visible with their owners, hold reasons and
prerequisites; explicit holds or incomplete metadata propagate through them.
An unchanged `external` input is an operator-supplied baseline prerequisite. An
affected external package requires upstream update/availability review and is
not counted as a project rebuild. Baseline bytes, availability, conflicts, ABI
transitions, and bootstrap suitability still need separate checks. The planner
makes no Asahi platform changes and does not authorize platform replacement.

JSON pins input bytes and the three imported implementation files. Its
`authenticated: false`, `build_status: NOT_RUN`, `dependency_solution:
NOT_ESTABLISHED`, and `advisory_fix_status: UNKNOWN` are intentional. Output is
deterministic for identical inputs and implementation dependencies. No clock,
network, package database discovery, installation or output-file mutation is
involved. Store stdout in an evidence directory and authenticate release inputs
through existing release tooling before considering execution.

## Illustrative compiler/library/consumer fixture

The proposal's `fixtures/compiler-library-consumer.json` models a compiler
transition coordinated with a zlib source change and a libpng advisory review:

`gcc/cmake (unchanged baseline) → clang → zlib → libpng → waybar`

Expected rebuild groups are clang, zlib, libpng and waybar, in that order. Some
consumers also depend directly on the compiler and cmake. The companion
`compiler-bootstrap-cycle.json` makes clang use its own changed compiler offer;
the compiler group is cyclic and held, and consumers inherit the hold. Fixtures
have synthetic pins, simplified dependency lists and example versions. They
demonstrate realistic coordination topology, not audited upstream metadata,
authenticated artifacts, available capacity, actual CVEs or a real release plan.

Run the focused host suite with
`python -B scripts/maintenance/test_rebuild_plan.py`. It uses real local `vercmp`
for epoch/pkgrel and virtual-provider checks and temporary files for CLI safety.
Native ARM builds, installation, physical M2 validation and maintained release
acceptance require separate evidence.

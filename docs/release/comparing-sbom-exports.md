# Compare offline release SBOM exports

`scripts/release/compare_sboms.py` compares two explicitly selected export
directories containing `sbom.spdx.json` and `coverage.json` from
`scripts/release/release_sbom.py`. It adds an SBOM evidence comparison alongside
the existing signed release/policy comparison; the exporter and its historical
output format stay unchanged. Runtime dependencies are Python 3.12+ standard
library and the existing adjacent `source_delivery.py` helper.

Authenticate and record all three hashes for **each** export through the caller's
existing release/evidence process. Computing a hash from an unknown file alone
does not authenticate its publisher. The comparison does not verify signatures
or reopen `release.json`, package archives, source bundles or evidence payloads.
The caller's release digest and release ID must match the pinned coverage file;
its SPDX digest must match both the actual document bytes and coverage binding.

After coordinator integration, run from the checkout:

```sh
python3 -I -B scripts/release/compare_sboms.py \
  --before /absolute/path/exports/previous \
  --before-release-id previous-release \
  --before-release-sha256 "$PREVIOUS_RELEASE_SHA256" \
  --before-spdx-sha256 "$PREVIOUS_SPDX_SHA256" \
  --before-coverage-sha256 "$PREVIOUS_COVERAGE_SHA256" \
  --after /absolute/path/exports/candidate \
  --after-release-id candidate-release \
  --after-release-sha256 "$CANDIDATE_RELEASE_SHA256" \
  --after-spdx-sha256 "$CANDIDATE_SPDX_SHA256" \
  --after-coverage-sha256 "$CANDIDATE_COVERAGE_SHA256" \
  --format json
```

Use the same arguments with `--format human` for a concise summary. Successful
JSON or human output goes to stdout; refusal goes to stderr and exits 1, with
no successful report on stdout. Argument errors exit 2. Changes and held
unknowns are observations, so a valid comparison exits 0 regardless of counts.
The module itself creates no output files; callers can retain stdout normally.

The deterministic JSON contains:

- `before` and `after`: exact document, coverage and release identities, including
  the retained synthetic flag. Local absolute paths and clock time are excluded.
- `packages`: added/removed rows with their evidence; common-package changes to
  identity (including version and architecture), archive digest/path, recipe and
  source references/retained digests, declared/raw/bundled license evidence,
  provenance, build evidence, and unresolved coverage. Versions are compared
  as exact strings; no upgrade/downgrade or compatibility decision is inferred.
- `held_unknowns`: unresolved coverage and `NOASSERTION` declarations from either
  side, including unchanged packages. Null evidence and raw declarations remain
  intact. Disappearing evidence is not an acceptance or remediation decision.
- `relationships`: added/removed recorded SPDX relationships, using package names
  for stable endpoints so a changed version or artifact digest alone does not
  invent a changed dependency edge. Duplicate or foreign endpoints are refused.

The current exporter records `DESCRIBES` relationships only. An empty dependency
edge inventory therefore reports `dependency_completeness=NOT_ESTABLISHED`.
Recorded local package-to-package dependency relationships can be compared when
present in an explicitly pinned compatible document. `.BUILDINFO` installed
entries remain build evidence; they do not establish runtime dependencies,
dependency closure, a rebuild requirement or a vulnerability result. No solver
or `vercmp` is invoked. Existing `compare_releases.py` remains responsible for
signed release policy, base inventory, coordinated sets and dependency impact.
The finite map-difference structure is reused from that comparator without
importing its release/GPG runtime into this inert reader.

Evidence arrays are normalized as unordered multisets for semantic comparison;
reordering preserves their multiplicity. Input hashes still identify exact
original bytes, so they can change even when the semantic change lists are empty.
Changing source/exporter interpretation of one release is also reportable;
matching release IDs are permitted and do not imply a release upgrade.

The reader reuses `source_delivery.local_read`, `decode`, `identity`, reference
and SHA checks. It refuses symlinked ancestors/leaves, hardlinked inputs, FIFOs,
duplicate JSON keys, floats/nonfinite numbers, malformed package identities,
duplicate package/archive/provenance identities, repeated source/license/notice
paths, mismatched SPDX/coverage/source/recipe joins, and unbound evidence paths.
Each selected JSON file is limited to 4 MiB, 48 nesting levels, 200,000 nodes,
256 packages, 4,096 source/input-reference rows and 32,768 relationship/list
entries. Embedded `sourceInfo` JSON has the same 4 MiB bound. Reads are immutable
hashed byte snapshots; no archive is executed or extracted and no network,
subprocess or package mutation is performed by the module.

Run the focused suite:

```sh
python3 -I -B -Werror::ResourceWarning scripts/release/test_compare_sboms.py
```

The suite uses original fixtures, one current exporter fixture round trip and
owned bounded CLI children. Its distinct-release examples are synthetic. The
development packet separately records actual historical export comparisons of
the same release, unchanged input hashes, CLI/library equality and tamper
refusal. Full SPDX conformance validation, a distinct actual release pair,
native ARM/16K execution, installed target and physical M2 testing remain unrun.
This is source/host maintenance tooling, with no legal, security, source
completeness, performance, production trust, M5/M9 or release acceptance claim.

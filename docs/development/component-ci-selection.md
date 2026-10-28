# Conservative component CI selection

The selector schedules reviewed dependencies without changing product tests,
central static/cache checks, native workflows or acceptance rules. This candidate
uses prospective PR299 head `670067d84da4615b7779887ebbd8432d5771bf27`, tree
`ab3207ea88c4d711ed962950acf0ce8c56e26331`.

| Group | Pinned matrix inventory |
| --- | --- |
| Full-port | 25 components × Python 3.12/3.14: 50 rows |
| Parallel development | Five lanes × both versions: 10 rows |
| Static components | Comparison 25 × both; developer package 13 × both; release-v1 13 × 3.14; release-v2 7 × 3.14: six rows |

These **66 component rows are an inventory**, not a per-PR check count. Expected
checks derive from the event's workflow/branch/path triggers, selected matrix
rows and job conditions. Untouched workflows retain their existing triggers;
there is no universally always-run remainder or fixed total per PR.

`scripts/ci/component_selection/dependencies.json` maintains exact consumer
routes and Python dependency footprints. All 19 release-v2 recipe/export/runtime
files are mapped. Source-set metadata (`PKGBUILD`, `.SRCINFO`, payload/provenance
and export lists) requires full coverage. The seven canonical runtime origins
also conservatively select the v2 consumer, preserving existing consumers by
union; frozen private copies do not dynamically read the checkout.

A complete ordinary A/M diff can narrow only when every path is reviewed and
changed Python imports, call targets and string/path footprints still match.
The unchanged selector normalizes AST optional fields across Python 3.12/3.14.
New cross-imports, unknown paths, deletions/renames/type changes, malformed,
unavailable or truncated diffs, manual dispatch and protected/common primitives
select the full baseline. Ambiguous source/export changes stay full.

Examples include the desktop input/runtime/window chain, borrowed mirror test
fixtures and the campaign's fingerprint of all Python/shell files in build,
checks, maintenance and release. A canonical comparator edit selects both
comparison versions, the release-v2 row and both campaign versions. It cannot
silently drop the new v2 consumer or the existing release-v1 row from full mode.

Only static, full-port and parallel component scheduling is wired. The two
component workflows' `**` entries ensure unknown changes reach FULL fallback;
their branch/manual semantics remain intact. All other workflow triggers stay
unchanged. Existing metrics assertions and common-core FULL rules remain intact.

Each selector job checks out only depth two, without tags or history expansion.
For PRs, HEAD must equal `github.sha` and have exactly the ordered event base/head
parents, with both commit objects available. Collection compares that first
parent directly to the verified checked-out merge tree. Any mismatch or missing
object selects full coverage; there is no merge-base lookup or extra fetch.
Pushes compare the exact event before/head only when both commit objects are
already available and HEAD matches the event checkout; otherwise coverage is full.

The shared Bash collector runs with explicit `set -euo pipefail`; each caller
also explicitly selects Bash and pipefail. A failing Git process that emits
apparently valid partial records cannot mark its diff complete. The final NUL
diff pipeline has no external diff/rename actor, a 30-second timeout and a 1 MiB
input limit. Metadata reads have five-second limits. The Python selector itself
runs no Git, API, subprocess, product or package actor. Collector failure selects
full coverage. Selector failure uses literal full
matrices even after partial narrow outputs; failure remains visible. Unselected
groups skip using a valid unused full matrix operand rather than an empty matrix.

```sh
python3 -I -B scripts/ci/component_selection/select.py \
  --event pull_request --group static --diff /absolute/path/name-status.z \
  --complete --source-root /absolute/path/checkout
python3 -I -B -Werror::ResourceWarning scripts/ci/component_selection/test_select.py
```

Without `--complete`, selection is full. Keep policy rows, dispatch cases,
reviewed package/export closure and literal workflow fallbacks synchronized.
Policy or workflow changes themselves select full coverage. The new PR299
integration controls cover six-row preservation, the 19-file v2 mapping,
unknown/truncated/deleted/renamed inputs, cross-workflow consumers, protected
paths and failed-selector fallbacks. Hosted event behavior remains a separate
validation step; row selection is not a measured CI-time improvement or admission.

The separate collector integration controls use only isolated local Git fixtures,
disabled hooks/signing and file-only shallow clones. They cover verified depth-two
merges, mismatched/missing metadata, exact multi-commit push endpoints, valid
partial output plus nonzero diff status, real oversized output and manual fallback.

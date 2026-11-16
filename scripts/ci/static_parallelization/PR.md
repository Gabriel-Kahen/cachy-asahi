# Publication handoff

Target base: public main `fd374f605cc51381a8c787549b9e15c424c9f48e`.
Branch: `codex/static-parallel-20261116`.
Root owns publication, exact-head hosted validation and merge. No push, PR,
Actions dispatch or native actor has been performed by this worker.

## Proposed PR title

Parallelize independent static suites behind the required checks aggregate

## Proposed PR body

Static validation currently serializes independent source and fixture suites
on one runner. Run ordinary validation as four independent matrix jobs, then
require every shard to succeed before the existing `checks` status passes.
Keep matched cache measurements as one `Static all` job so the full suite and
its setup report still share one runner.

All 181 original step definitions remain unchanged apart from explicit shard
routing: the 149 non-report suite shell blocks run exactly once normally.
Pinned checkouts, source provenance, prerequisite/cache behavior, environment,
working directories, timeouts and no-native-actor fences are preserved. Only
the two shared historical checkouts repeat where their consumers require
them. Native scheduling, grants, manifests and signing are unchanged.

Validation: fresh committed-export YAML/preservation/routing proof; 155 shell
blocks pass `bash -n`; 81 extracted path dependency edges and passive replay
ordering pass; all 64 aggregate outcomes pass. Eight negative mutations were
refused. Existing selector, collector and prerequisite tests pass (30/8/12).
Independent read-only review found no dependency gap. Hosted exact-head shard
execution and a matched cache run remain required; throughput is unmeasured.

## Exact-head merge-verifier proposal

For an ordinary PR run of workflow `static-validation` containing this change,
require each exact job/check display name below once, on the current PR head's
latest applicable run. The static workflow change conservatively selects all
six existing developer/release rows. Treat queued, in-progress, failed,
cancelled, timed-out, action-required, neutral, stale or unexpected skipped
results as unfinished or failing; do not substitute counts or an older run.

Expected `SUCCESS` names:

```text
Static foundation
Static source-data
Static desktop
Static composition
checks
Conservative component selection
Developer/release sbom-comparison (Python 3.12)
Developer/release sbom-comparison (Python 3.14)
Developer/release developer-package (Python 3.12)
Developer/release developer-package (Python 3.14)
Developer/release release-package (Python 3.14)
Developer/release release-package-v2 (Python 3.14)
```

Expected `SKIPPED` name:

```text
cache-seed
```

`Static all` is **absent** in ordinary runs, rather than a skipped job. The
nonmatching suite steps inside each created shard are routing skips, not
additional check-run names. The four `Static ...` names above are new check
identities; `checks` keeps its old display name but now belongs to job ID
`static-result`. The matrix job ID remains `checks` for source-contract
compatibility. The six developer/release names, selector and cache seed retain
their existing identities. Other workflows' required identities and permitted
skips are unchanged by this owned increment; Root must combine this list with
their own owning workflow inventories, including any separately integrated
native-source-controls change.

For direct dispatch with `measure-cache: true`, replace the four ordinary
`Static ...` success names with exactly `Static all` (`SUCCESS`), and change
`cache-seed` to `SUCCESS`. Keep aggregate `checks`, selector and the six
developer/release names `SUCCESS`. None of the four ordinary shard names is
created. The original matched full-suite report is required in `Static all`;
the aggregate alone does not attest that report.

For the unchanged `static-cache-one-pair` wrapper, require caller job `cold`
`SUCCESS`. Its reusable caller job `warm` invokes the same single `Static all`
path with `setup-phase: warm`: the called workflow's `cache-seed` is `SKIPPED`,
while `Static all`, `checks`, selector and the six developer/release jobs must
succeed. Raw GitHub job names for reusable runs may carry the caller prefix
`warm / `; compare against the called workflow's job identities under that
prefix rather than accepting an unrelated normal run. This wrapper is a
separate measurement run, not the ordinary PR required-check inventory.

No result above is claimed to have occurred on hosted CI. Root must inspect
the actual published exact-head check identities and job conclusions before
merging, and separately measure timing before claiming a throughput gain.

# Offline security rebuild operations

`scripts/maintenance/security_campaign.py` fills the concrete CLI composition gap
between retained advisory DATA and an actionable rebuild campaign. Existing
`security_advisories.py` produces a report; `update_plan.py` replays it and computes
pre-change impact; `campaign.py` requires that report and a caller-declared
candidate graph; `build_batch_v2.py` separately admits reviewed build tasks.
Previously the operator had to transfer advisory roots and old impact into the
candidate graph and assemble those commands manually.

This adapter produces the exact existing advisory report, calls the existing
update and rebuild planners, carries every pre-change impacted binary into the
candidate review roots, and prepares an ordinary durable `campaign.py` store.
Candidate dependency changes therefore cannot erase work required by old edges.
It does not implement a dependency solver, scheduler, builder, or release actor.

## Select retained inputs

Use Python 3, `vercmp`, and `bsdtar` already installed. Select ordinary local
files by actual SHA-256. This command performs no inventory discovery or network
request. An installed inventory must already have been explicitly retained;
the command does not establish that it still describes a running machine.

The prepare selection has exactly these fields:

```json
{
  "schema_version": 1,
  "operation_id": "reviewed-security-operation",
  "as_of": "2026-10-27T12:00:00Z",
  "max_age_hours": 24,
  "inputs": {
    "inventory": {"path": "/retained/inventory.json", "sha256": "ACTUAL_SHA256"},
    "advisories": {"path": "/retained/advisories.json", "sha256": "ACTUAL_SHA256"},
    "provenance": {"path": "/retained/provenance.json", "sha256": "ACTUAL_SHA256"},
    "graph": {"path": "/retained/pre-change-graph.json", "sha256": "ACTUAL_SHA256"},
    "candidate_graph": {"path": "/retained/candidate-graph.json", "sha256": "ACTUAL_SHA256"}
  },
  "import_bundle": null
}
```

Inventory and graph use the current advisory/rebuild schemas. Exact binary sets,
versions and architectures must match; explicit provides are required for known
coverage. Every pre-change graph package also needs its selected release archive
`sha256`. These identities are caller-supplied DATA, not authenticated archive
or installed-byte evidence. Source IDs, recipe hashes, immutable source pins,
owners, capacity, dispositions and optional installed provider selections remain
under the existing planners' validation. The candidate target `snapshot_id` must
equal the pre-change target; additions/removals need a successor workflow.

Retained graphs may come from `import_release_graph.py`. To preserve that review,
select its complete `--output bundle` as `import_bundle: {path, sha256}`. Its
inventory and graph must exactly equal the selected pre-change inputs; all
imported package/global holds are retained. Selecting a bundle does not replay
the importer, authenticate its claims, or clear its held unknown build metadata.
A subsequently enriched graph needs its own reviewed provenance; do not silently
rewrite an import bundle to make the equality check pass.

Advisory provenance uses the existing official URL/bytes/hash/retrieved-at schema.
Retrieval provenance is an operator record, not a signed advisory attestation.
The adapter does not infer ARM affectedness from Arch versions, source names, or
virtual provides. All exact advisory matches remain review roots, including
versions at or above an Arch fixed reference. No match remains coverage UNKNOWN.

```sh
python -B scripts/maintenance/security_campaign.py prepare \
  --operation /private/security-operation \
  --selection /retained/security-selection.json --selection-sha256 ACTUAL_SHA256
python -B scripts/maintenance/security_campaign.py status \
  --operation /private/security-operation
```

The operation directory must be fresh. Both original and effective candidate
graphs remain content-addressed. Generated reports replay through
`update_plan.plan()` before campaign preparation. Original impact roots use the
explicit `security-campaign:pre-change-impact:GRAPH_SHA256` reference. Those
references mean rebuild review, never mitigation. Existing declared changes and
provider metadata stay present. `NO_REBUILD_FROM_SUPPLIED_ROOTS` emits no commands;
its graph-unaffected list only describes paths in the supplied graph. Advisory
coverage, platform, recovery and ARM security remain unknown/unestablished.

## Obtain concrete existing batch commands

Supply exactly two independent output directories and select each reviewed
existing batch config and offline source-binding file:

```json
{
  "schema_version": 1,
  "batches": [
    {
      "config": {"path": "/retained/first-config.json", "sha256": "ACTUAL_SHA256"},
      "sources": {"path": "/retained/first-source-bindings.json", "sha256": "ACTUAL_SHA256"},
      "output": "/private/first-build-batch"
    },
    {
      "config": {"path": "/retained/second-config.json", "sha256": "ACTUAL_SHA256"},
      "sources": {"path": "/retained/second-source-bindings.json", "sha256": "ACTUAL_SHA256"},
      "output": "/private/second-build-batch"
    }
  ]
}
```

```sh
python -B scripts/maintenance/security_campaign.py plan-builds \
  --operation /private/security-operation \
  --selection /retained/batch-selection.json --selection-sha256 ACTUAL_SHA256
```

The adapter invokes only `build_batch_v2.admission()` with the current canonical
rebuild planner and explicit `offline-build-v2` interface. That admission invokes
the offline planner and real `vercmp`, checks recipes statically, verifies source
cache objects/receipts offline, and binds task images, locks and reachable
installed-provider witnesses. It launches no builder and never repairs a missing
cache entry. Each batch must cover exactly the complete campaign output set;
capacity/provider/group/source holds prohibit commands. Split-source groups and
cycles remain subject to the existing single-package builder restriction.

Successful output records two `plan_command` and `execute_command` argv arrays
with actual retained graph/config/source paths, exact planner and admission
hashes, and distinct output directories. These are real existing CLI commands,
without shell interpolation. Only `plan` is exercised by the adapter's tests and
demonstration. `execute` remains a separate operator action using already
reviewed preexisting images and source cache. Configs/source plans still refer
to external recipes, package locks, notices, cache objects and source plans;
these must remain available with their selected bytes. Admission digests bind
those dependencies. Changed bytes require replanning and reviewed new hashes.

The security review can remain BLOCKED while a fully bound build pair is planned
to support investigation. Build admission does not discharge security, protected
platform compatibility, recovery, release, install, native 16K or physical M2
gates. The adapter has no API that turns those gates into PASS. It records no
remediation and changes no installed packages, Asahi components or boot setup.

## State and controlled recovery

The adapter uses `campaign.Store` locking, immutable objects and chained journal
events. The existing implementation/runtime closure plus exact adapter bytes are
pinned. `status` checks those and all current operation objects, while retaining
the campaign's `RECORDED_ONLY_REVERIFY_BEFORE_USE` scope for external inputs.
It does not re-admit external caches or verify external batches on every status.

Preparation has the existing campaign commit, extended with an exact original
security-selection object and adapter hash, followed by a security metadata
commit. A crash between them cannot be reported as a complete security
operation. `prepare --retry` only completes that one-event intermediate state
when the original selection/adapter, regenerated report/input/candidate hashes
and operation ID are identical. Original candidate and optional import bundle
identities are already selected by the exact original security-selection bytes.
An interruption before the campaign's initial event needs a fresh directory.
Temporary composition paths retained in the original campaign selection are
historical provenance; resume reads the campaign's retained objects.

Batch planning records RUNNING before admission, then COMPLETE or FAILED. Missing
source files, changed cache data, invalid tasks or an incomplete independent pair
leave no current command receipt. Restore/review explicit inputs and rerun
`plan-builds --retry`. The failed event remains; no retry happens automatically.
An interrupted RUNNING attempt also requires `--retry`. There are at most three
batch-planning attempts per operation. A changed implementation requires a
successor operation. Existing `build_batch_v2 execute --resume --retry PACKAGE`
handles actual build failures separately; this adapter never invokes it.

After independently executing and verifying builds, use the existing
`campaign.py bind`, `verify` and `handoff` commands against this same operation
directory. They retain their original receipt, independent-pair, release and
staging gates. A campaign handoff still cannot establish ARM mitigation or clear
the adapter's platform/recovery unknowns. Recheck external admission before
using a recorded command. Storage is a cooperating-writer contract, not a
cryptographic trust boundary against someone able to rewrite the whole store.

## Bounded host demonstration

The development packet's test file provides `--demo-directory FRESH_DIRECTORY`.
It creates a tiny original MIT fixture archive, original recipe/metadata DATA,
synthetic advisory records and explicitly illustrative image/archive/capacity
claims. It runs current `import_release_graph.py`, the adapter, and both emitted
`build_batch_v2.py plan` commands. It retains a three-package transitive impact,
an unrelated graph no-op, a held importer join, and missing-source failure plus
explicit recovery. No upstream security finding, real image availability,
native build, installation, hardware result or remediation is represented.

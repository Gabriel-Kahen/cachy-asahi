# Offline maintenance campaigns

`scripts/maintenance/campaign.py` connects the existing advisory/update planner,
rebuild graph, retained `offline-build-v2` batch receipts, output admission and
release input checks. It runs no build actors, scheduler, acquisition, signing,
installation, service, publication or hardware operations. Those existing
interfaces stay unchanged. It needs Python 3, `vercmp` and `bsdtar` already present.

A campaign is an explicit finite rebuild of a fixed package-name set. Changed
versions, sources and dependency metadata belong in a caller-reviewed candidate
build graph. The original graph remains the pre-change graph for impact analysis.
Package additions/removals require a reviewed successor input. The required
output set is the union of packages affected by the original update plan and by
the candidate rebuild plan. A candidate package/source/build-metadata revision
outside the declared candidate rebuild coverage is refused. Missing build
dispositions, held candidate groups, missing capacity and omitted original impact
packages remain blocking conditions. Dependency ordering stays exclusively in
`rebuild_plan.py` and `build_batch_v2.py`.

## Prepare and resume

Prepare a selection JSON with exactly these fields (all references contain an
explicit local path and its actual SHA256):

```json
{
  "schema_version": 1,
  "campaign_id": "reviewed-local-campaign",
  "as_of": "2026-10-27T12:00:00Z",
  "max_age_hours": 24,
  "inputs": {
    "inventory": {"path": "/retained/inventory.json", "sha256": "ACTUAL_SHA256"},
    "advisories": {"path": "/retained/advisories.json", "sha256": "ACTUAL_SHA256"},
    "provenance": {"path": "/retained/provenance.json", "sha256": "ACTUAL_SHA256"},
    "advisory_report": {"path": "/retained/advisory-report.json", "sha256": "ACTUAL_SHA256"},
    "graph": {"path": "/retained/pre-change-graph.json", "sha256": "ACTUAL_SHA256"}
  },
  "build_graph": {"path": "/retained/candidate-graph.json", "sha256": "ACTUAL_SHA256"}
}
```

The five originals must replay through `update_plan.plan()` exactly. Graphs can be
prepared with `import_release_graph.py`; campaign preparation does not bypass its
review or manufacture metadata. `health.py` remains the separate authenticated
release/observation review interface; campaign state is unauthenticated and does
not substitute for health observations.

```bash
python -B scripts/maintenance/campaign.py prepare \
  --campaign /private/campaign-01 \
  --selection /retained/campaign-selection.json --selection-sha256 ACTUAL_SHA256
python -B scripts/maintenance/campaign.py status --campaign /private/campaign-01
```

The campaign directory must be fresh. Planning inputs, reports and the candidate
graph are retained as content-addressed objects. Removing original planning
files does not break resume. Exact source bytes for the build/checks/maintenance/
release Python and shell implementation closure, and the actual Python, `vercmp`
and `bsdtar` executables, are pinned. Shared libraries, the whole OS, origin
authentication and execution attestation are not established. Code or tool
changes require a reviewed successor campaign rather than silent repinning.

Each mutation holds a nonblocking exclusive lock. Events are numbered immutable
JSON objects with a previous-event hash. Objects and events use fsync plus atomic
create-if-absent publication; prior attempts remain in the journal. Interrupted
object writes may leave unreferenced `.pending-` files, which confer no progress.
A crash before the first event commits leaves an unprepared directory; use a new
directory. A corrupt/gapped journal or drifted current object is refused. There
is a finite 256-event bound. This is a local cooperating-writer contract, not
tamper-proof storage against an actor able to replace the entire directory.

## Bind caller-provided batch receipts

Run the existing explicit `build_batch_v2.py plan/execute` workflow separately.
The campaign never launches, retries or cleans its actors. Prepare a selection
in the existing `build_outputs_v2.py candidate` schema, explicitly retaining
`synthetic`. Its `input` must select bytes identical to this campaign's candidate
graph, and its pairs must cover exactly the complete campaign required set.

```bash
python -B scripts/maintenance/campaign.py bind \
  --campaign /private/campaign-01 \
  --selection /retained/output-selection.json --selection-sha256 ACTUAL_SHA256
python -B scripts/maintenance/campaign.py verify --campaign /private/campaign-01
```

Binding retains the original selection and a derived selection pointing at the
campaign graph copy with absolute batch directories. Batch directories and output
archives remain external read-only inputs and must remain available. Their
selected admission and state digests, runner lock, ownership marker, every complete
output tree, retained source material and independent rebuild pair are verified
by existing `build_outputs_v2.candidate()`. No legacy fallback or fixture exemption
is added. Binding alone is `BOUND_NOT_VERIFIED`.

Verification records `RUNNING` before admission, then `COMPLETE`, `FAILED` or
`BLOCKED`. A surviving `RUNNING` record after acquiring the lock means the last
attempt did not commit a result. Explicitly resume with `verify --retry`; failed
or interrupted attempts are never reported complete. There are at most three
verification attempts per binding. After rebuilding/retrying through the existing
batch CLI, bind a newly selected state/receipt digest to begin a fresh attempt
budget. Rebinding invalidates candidate and handoff readiness. An identical bind
is idempotent and cannot reset the budget. Re-verifying a complete candidate is
idempotent but still rereads existing admission gates; drift invalidates it.

## Produce the local staging handoff

Supply a normal `release.py stage` spec whose package set is exactly the complete
admitted campaign output set. Keep its relative artifact, release-provenance,
base, evidence, license and optional source-delivery references below the spec
directory. Raw build provenance is not release provenance. Supply the existing
release schema, including project commit, source/license projection, complete
target transaction, protected platform list and coordinated compatibility policy.

```bash
python -B scripts/maintenance/campaign.py handoff \
  --campaign /private/campaign-01 \
  --selection /retained/release/spec.json --selection-sha256 ACTUAL_SHA256
```

Handoff replays output admission before using cached success. Shared batch locks
remain held through release preflight and the committed handoff. It then calls
the existing read-only `release.pkginfo()`, `provenance_check()` and
`dependency_check()` interfaces. It binds the release projection to admitted
archive/identity/recipe/source bytes, checks referenced evidence and project
license, and invokes optional source-delivery assembly and association checks.
The effective final package set, versions, architectures and runtime/provides
metadata must match the candidate graph exactly; its snapshot must be the declared
target base snapshot. A build environment snapshot may differ from that target.

Release fields used only during signing/staging remain subject to
`release.stage()`; preflight is not a stage execution guarantee. Only a complete
consistent nonsynthetic set receives `STAGING_INPUTS_READY`, with the exact spec
and transitive data-reference hash map and an argv template for the existing
staging command. Synthetic inputs receive `SYNTHETIC_HANDOFF_NOT_STAGEABLE` and
no command. No keys are created; no staging, signing or publication is executed.

The planner's ARM security/coverage holds remain `security_review=BLOCKED` in the
campaign and handoff. Staging-input readiness does not discharge those holds or
establish a secure update, supported release, installed behavior, native 16K
result, physical M2 behavior or maintenance acceptance. Staging, publication,
installed and hardware phases stay `NOT_RUN`. Existing stable-promotion gates
remain responsible for their own requirements.

`status` explicitly reports `RECORDED_ONLY_REVERIFY_BEFORE_USE`; it is not a live
external-byte audit. Re-run `handoff` immediately before using its command
template. A failed handoff clears current readiness and retains its failure.
Old objects are historical receipts only. Readiness is a bounded snapshot for
cooperating writers; the external release input directory must remain immutable
after its final hash check. Package origins, maintainer judgment, actual clean
execution and ongoing staffing/capacity are not authenticated by SHA256 selections
or native-labeled retained receipts.

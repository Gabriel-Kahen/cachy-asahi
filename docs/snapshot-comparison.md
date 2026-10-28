# Retained Asahi snapshot comparison

`scripts/platform/snapshot_compare.py` compares two exact retained outputs of
`target_snapshot.py` against a checksum-bound, explicit proposed change set. It
prints JSON to stdout and creates no files. Run with Python bytecode disabled:

```sh
python -B scripts/platform/snapshot_compare.py \
  --contract /absolute/private/comparison.json \
  --contract-sha256 REVIEWED_CONTRACT_SHA256
```

Exit 0 admits the **data comparison only**; exit 2 reports blocked data, and exit
1 refuses the outer contract/proposal. Findings distinguish `UNCHANGED`,
`INTENDED_CHANGE`, `UNEXPECTED_DRIFT`, `MISSING_EVIDENCE`, and
`INCOMPATIBLE_BASELINE`. A blocked bundle does not prevent inspecting the other
bundle. A malformed, missing, changed, linked or unbound bundle object blocks it.

Every reference below is an exact `{path, size, sha256}` object: canonical
absolute path, positive byte count, lowercase SHA-256. All files and path
ancestors must be regular/no-follow inputs; files must have one hard link.
Directory ancestors are opened as directories. No paths are discovered.

The comparison contract contains exactly:

```json
{
  "schema_version": 1,
  "kind": "retained-Asahi-snapshot-comparison",
  "before": {"snapshot": "REF", "collection": "REF", "inputs": "REF", "context": "REF"},
  "after": {"snapshot": "REF", "collection": "REF", "inputs": "REF", "context": "REF"},
  "proposed_changes": "REF"
}
```

`REF` placeholders must be replaced with reference objects, not strings. The
collector outputs remain unchanged. `snapshot` references its `snapshot.json`;
`collection` references its `collection.json`. The `inputs` reference names a
supplement with exactly `schema_version: 1`,
`kind: "collector-retained-input-map"`, `collection: REF`, and a `files` list of
`{source_path: ORIGINAL_ABSOLUTE_PATH, retained: REF}` rows. Retain an independent
copy of **every** entry in `collection.sources`, including the original capture
contract, fixture runtime if applicable, descriptors, selected files and any
preflight inputs. The source pathname is a label; it is never opened. Copies
must match the recorded size/hash. A later capture can therefore follow a
baseline capture without requiring the baseline machine paths to stay unchanged.

The `context` supplement contains exactly:

```json
{
  "schema_version": 1,
  "kind": "snapshot-comparison-context",
  "snapshot": "REF",
  "machine_id": "operator-supplied-stable-pseudonym",
  "model": {"compatible": "apple,j413", "air_size_inches": 13},
  "configuration_ownership": [
    {"path": "/etc/asahi.conf", "role": "system-configuration",
     "owner": {"kind": "package", "id": "asahi-scripts"}, "artifact": "REF"},
    {"path": "/home/operator/.config/session.conf", "role": "user-configuration",
     "owner": {"kind": "user", "id": "uid:1000"}, "artifact": "REF"}
  ],
  "recovery": {"receipts": ["REF"], "assets": [{"role": "kernel", "artifact": "REF"}]}
}
```

Model, snapshot and selected configuration references must match the snapshot
exactly. Ownership is an operator assertion about the selected individual file;
it is not an observed ALPM ownership check or a complete configuration inventory.
Supply each of the four boot and two configuration roles in `recovery.assets`,
using the exact snapshot artifact references. Missing roles remain blocked.
`recovery.receipts` references existing `exact-superseded-recovery-archive-data`
receipts from `recovery_inputs.py`. Their whole image inventory must equal this
snapshot's inventory. Required protected packages need matching package metadata,
version and architecture plus retained archive, signature, index and inspection
references. Those bytes and inspection identity fields are checked; cryptographic
statuses are not replayed, archive contents are not reinspected, and current
repository availability does not supply missing old recovery bytes.

The proposal contains exactly `schema_version: 1`,
`kind: "explicit-snapshot-change-set"`, `baseline_snapshot: REF`,
`candidate_snapshot: REF`, and four lists: `packages`, `assets`, `runtime`, and
`configuration_ownership`. Each list contains `{key, from, to}` rows. Empty
lists explicitly request preservation. Duplicate or no-op declarations are
refused. Keys and exact values are:

| List | Key | `from` / `to` value |
| --- | --- | --- |
| `packages` | Package name | Full snapshot `metadata` object, or null for absent |
| `assets` | One selected role | `{size, sha256}`, ignoring retained copy pathname |
| `runtime` | Runtime field name | Exact scalar observation |
| `configuration_ownership` | Logical absolute configuration path | `{role, owner, artifact: {size, sha256}}`, or null |

Review every proposed row. A version-only allowance cannot exempt dependency,
provider, conflict, license or other metadata drift. Kernel changes require all
associated changed runtime/artifact rows to be declared too. All package changes
are compared, including additions and removals; the maintained protected set
covers boot, kernel, firmware, Mesa, audio and speaker protection. Missing core
tuple members block admission even if a removal was declared.

The exact model/size, raw compatible property, machine pseudonym, capture scope
and collector source-hash map must agree. One Air size cannot stand in for the
other. Inputs are rechecked before reporting, with a 60-second deadline,
512 MiB aggregate input bound, 65,536-object bound and bounded per-file reads.
Larger packets require a separately reviewed bounded extension.

`comparison_data_admitted` never accepts installation, hardware usability,
backup completeness, protected-stack compatibility, or boot/session recovery.
This tool does not solve a dependency transaction or replace the narrower
`recovery_preflight.py` checks against `transaction.py`'s prepared update.
Physical M2 testing and exercised recovery remain separate requirements.

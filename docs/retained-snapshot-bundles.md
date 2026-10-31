# Capture a retained comparison bundle

`scripts/platform/retained_bundle.py` retains the original bytes needed by the
[offline comparator](snapshot-comparison.md) during a normal explicit collector
capture. It writes only a requested new private evidence directory. No package,
boot, service or configuration changes occur. It does not discover a machine or
infer ownership, recovery readiness or hardware support.

Create the usual checksum-bound `target_snapshot.py` capture contract, preserving
its explicit `fixture` or `live` mode and selected individual files. Then supply
this request, replacing `REF` with `{path, size, sha256}`:

```json
{
  "schema_version": 1,
  "kind": "retained-Asahi-snapshot-bundle-capture",
  "capture_contract": "REF",
  "machine_id": "operator-stable-machine-pseudonym",
  "configuration_ownership": [],
  "recovery_receipts": [],
  "recovery_assets": []
}
```

```sh
python -B scripts/platform/retained_bundle.py \
  --request /absolute/private/request.json \
  --request-sha256 REVIEWED_REQUEST_SHA256 \
  --output /absolute/private/new-bundle
```

The parent must already exist, belong to the caller and have mode 0700. Output
must be new, use canonical absolute paths without symlink ancestors, and stay
outside the source package inventory. Files are mode 0600, directories 0700.
Exit 0 means bundle production completed, not that comparison or recovery passed.
Exit 1 refuses the request/capture. Failed publication leaves `INCOMPLETE`;
preserve that packet for diagnosis and use a new output name for another attempt.

`bundle.json` contains exactly the comparator's four references (`snapshot`,
`collection`, `inputs`, `context`). Put the parsed object directly into a
comparison contract's `before` or `after` field. Its `capture/retained-inputs.json`
covers every entry in `capture/collection.json`'s source map. Raw copies come from
the collector's original stable reads, not later rereads. Originals are rechecked
after retention; captured inventory and runtime guards remain in place. Offline
comparison opens retained copies; original machine paths remain labels.

Unknown supplements stay empty. Comparison reports missing ownership and
recovery evidence. For known **operator assertions**, add ownership rows exactly
`{path, role, owner: {kind, id}}`, with a logical absolute configuration path,
one selected `user-configuration` or `system-configuration` role, and explicit
`user` or installed `package` owner. The producer binds each assertion to that
role's selected artifact. It never claims ownership was observed or verified.

`recovery_receipts` may reference existing
`exact-superseded-recovery-archive-data` receipts. The producer retains those
original bytes and their directly consumed inventory/certificate/archive/
signature/index/inspection dependencies. It emits separate copies with relocated
references and records each derivation. Prior signature observations and scope
claims stay unchanged. Historical referenced JSON stays verbatim; its internal
paths remain historical labels. No archive or signature verification is rerun.
The comparator checks package and inventory correspondence and blocks stale or
missing evidence. Supplying a receipt does not establish its completeness.

`recovery_assets` is an explicit list of selected roles to reference, for example
`["kernel", "kernel-release"]`. It asserts only which retained individual files
the operator supplied as recovery references. It does not make them bootable,
complete or usable. Unknown roles stay absent rather than being inferred.

`producer-receipt.json` records the request's retained copy, producer input map,
recovery derivatives and omissions. `missing_evidence` lists omitted supplements;
it is not a complete preflight assessment. The collector's source-hash map adds
the exact `retained_bundle.py` hash for this opt-in mode. The comparator accepts
only the four known legacy source keys or those four plus this known producer,
and requires the producer manifest/receipt and absence of `INCOMPLETE`. Different
producer source identities remain incompatible baselines.

Legacy `target_snapshot.run(contract_ref, output)` and its CLI remain unchanged.
The new keyword `retain_inputs=True` is the bounded adapter used by the producer;
the complete bundle command is the supported path into offline comparison.
The collector and producer each limit original inputs to 64 MiB. Output rechecks
are bounded to 256 MiB, JSON to 8 MiB, recovery receipts to 32 and aggregate
recovery package rows to 4096. Stable readers enforce the existing 60-second
deadlines. Larger packets need a reviewed extension.

Retain the bundle at its captured absolute paths; arbitrary relocation requires
new explicitly bound references. Synthetic inputs remain `SYNTHETIC_FIXTURE`.
Live metadata remains metadata only. Physical M2, full backup, installation,
trust, usability and actual boot/session recovery acceptance are all separate.

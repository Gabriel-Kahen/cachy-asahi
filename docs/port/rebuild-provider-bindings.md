# Explicit installed-baseline provider bindings

The planner preserves all matching and version-rejected named candidate edges.
Default input/output behavior stays unchanged. Optional `provider_selections`
can discharge one exact ambiguous **unchanged external runtime baseline**
relation using a reviewed installed-ALPM query. It never chooses automatically.

Each row has exactly `package`, `field`, `dependency`, `provider`, and `evidence`.
`field` is `depend`; consumer and every candidate must be unchanged external
baseline packages. The original relation, including its version constraint,
must have multiple satisfying providers. Existing Arch relation/vercmp semantics
must confirm the selected provider satisfies it.

Evidence has exactly:

- `kind`: `INSTALLED_ALPM_CACHE_QUERY_V1`.
- `image`: exact installed image `sha256:<64hex>`.
- `inventory_sha256`: sorted external-baseline name/version lock digest.
- `capture_sha256`: selected raw installed-query capture digest.
- `metadata_sha256`: `provider_context(...)` encoded using `pins.encoded`, binding
  complete consumer/all-candidate name/version/architecture/dependency/provides
  metadata and the exact relation.

All selections must reference one image/lock/capture. Duplicate, unused/stale,
unknown, changed-metadata/inventory, non-runtime, non-external, nonambiguous and
unsatisfied selections refuse. Affected consumers/candidates cannot reuse a
pre-change installed query to discharge their review.

Reports retain all candidates and matching providers, record the full binding
as `AMBIGUOUS_PROVIDER_BOUND_TO_INSTALLED_QUERY`, and preserve all edges for
conservative reverse impact and closure. Only that exact ambiguity hold is
resolved. Source/owner, unavailable, version-rejected, SCC, external-update,
capacity and unrelated ambiguity holds remain. With no selections the canonical
unbound report is byte-identical. No virtual offer or dependency is deleted.

Digests bind bytes, not origin/native execution. Operators independently
authenticate source, image, DB and actual capture before execution admission.
The native trial's bounded read-only libalpm16 collector records actual cache
order, full574 metadata/raw descriptions, all matching candidates/chosen result,
library/helper hashes, DB before/after snapshots and parent command/stdout
receipt. It exposes no transaction API and mounts no Docker socket in the guest.

This is `alpm_find_satisfier` on the captured local cache list, not a retained
historical transaction edge. Literal-name preference is not inferred from docs
for the distinct `alpm_find_dbs_satisfier` API. The fresh qualified image provides
the observation before admission; Setup7's old lock retained no selected edge.

Run existing planner tests plus `test_rebuild_provider_selections.py` for host
controls. Native capture and batch execution need separate actual evidence.

For each task whose dependency closure reaches a bound baseline consumer, batch
admission requires the exact witnessed image ID and exact captured inventory
lock digest. Equal package versions in a different image do not qualify. A
repository/manifest digest is a different namespace: resolve/review its immutable
image ID outside admission and supply that exact ID, or admission refuses.
The admission record retains the used provider selections, including capture
digest, on that task. Unrelated tasks and no-selection behavior stay unchanged.

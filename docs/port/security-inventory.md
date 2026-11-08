# Retained Apps inventory for offline Security review

The repository converter bridges an existing Apps16 `complete-installed-inventory`
JSON snapshot to the bare package list accepted by the advisory monitor and
campaign. It reads only explicitly selected retained JSON. It never queries an
installed database, invokes pacman, contacts a service, or builds, signs or
installs anything. This is a repository CLI addition; packaged Apps/Security
copies and native admission closures are unchanged.

Choose the original inventory and its SHA256 independently, then use a fresh
output directory with an existing ordinary parent:

```sh
python3 scripts/maintenance/security_inventory.py \
  --input /path/to/retained-installed.json \
  --input-sha256 <independently-selected-original-sha256> \
  --output /path/to/new-inventory-projection
```

The command requires schema 1, kind `complete-installed-inventory`, target
`aarch64`, a nonempty snapshot identifier and 1–4096 packages. Input must be an
ordinary, single-link file without symlinks, at most 16 MiB. Duplicate JSON keys,
nonfinite/fractional numbers, duplicate binary names, incomplete versions,
missing provides and non-ARM package identities are refused. Package architecture
may be `aarch64` or `any`. No architecture or version is guessed.

On success, the private directory (0700) contains private files (0600):

- `source.json`: the exact original bytes, including every retained metadata and
  observation field.
- `inventory.json`: a name-sorted bare list, at most 8 MiB, preserving exact binary
  names, complete versions including epoch/pkgrel, architectures and provides.
  Optional `pkgbase` and `origin` labels are also preserved. No virtual provides,
  source names or spelling variants become advisory aliases.
- `receipt.json`: hashes and lengths of both files, snapshot identifier, package
  count, retained qualification and observation, and explicit scope limits.

For example, select the resulting list for the unchanged offline monitor:

```sh
python3 scripts/maintenance/security_advisories.py \
  --inventory /path/to/new-inventory-projection/inventory.json \
  --advisories /path/to/advisories.json --provenance /path/to/provenance.json \
  --output /path/to/new-advisory-report
```

For `security_campaign.py prepare`, select this list and its SHA256 as
`inputs.inventory` in the retained selection JSON.
See [the advisory monitor](../security-advisory-monitor.md) and
[the campaign workflow](security-campaign.md) for their remaining inputs and
review requirements. Keep the projection receipt and source with the report;
the monitor consumes only the list and does not propagate its freshness labels.

A caller-declared snapshot retains qualification
`CALLER_DECLARED_METADATA_NOT_HOST_ATTESTED`. An observed snapshot must pass the
existing Apps helper's observation qualifier and internal hash checks: the input
record hash map, snapshot identifier, package metadata hash and required record
references must agree. The converter does not reopen the database or original
record bodies. These checks do not authenticate the observation, validate a full
Apps plan or payload, or make an old snapshot current. The separately selected
input hash identifies bytes; it is not a signature or a freshness guarantee.

Every result says `NOT_REOBSERVED_SOURCE_MAY_BE_STALE`, leaves ARM security status
`UNKNOWN`, and grants no payload, hardware or security acceptance. Preserve the
source's provenance when deciding whether its retained inventory is suitable for
your review. A declared label never upgrades into an observed claim.

Existing outputs and symlink paths are refused. Failed writes may leave a partial
private directory for inspection, without a completion receipt; the CLI exits
nonzero. Do not consume partial files as a successful conversion or reuse that
directory for a retry. Select a new output path after resolving the failure.

# Local repository endpoint export

`scripts/release/export_repository.py` prepares a versioned local tree for a
repository maintainer. It uses the existing signed release, promotion and
withdrawal contracts. It does not upload files, configure hosting, install
packages, create/import keys, modify package-manager trust or authorize a
development bundle as stable.

The input is an existing operator-owned release store produced by the
[release CLI](release/interface.md), including its `.release.lock`. The selected
`stable/current` release must pass complete release verification, its signed
promotion binding and the existing promotion gates. The external GPG home and
full fingerprint must already be provisioned through the release trust process.
Synthetic or incomplete gates are refused by the real CLI. No gate override is
provided.

Create a dedicated, empty endpoint directory owned by the invoking maintainer.
Use absolute canonical paths with exactly one leading slash and no symlink components. Both managed roots and
their consumed files/directories must prohibit group/world writes; files have
one hard link. The GPG home stays outside both roots and the checkout. Source
and endpoint roots may not overlap. The endpoint reserves only `generations/`
and `current`; unrelated files or an unmanaged selection are refused.

Preview the exact selected release, signer, file hashes, repository aliases and
previous selection:

```sh
python3 -B scripts/release/export_repository.py \
  --root /srv/release-store --endpoint /srv/repository-endpoint \
  --gpg-home /secure/release-verification --key FULL_AUTHENTICATED_FINGERPRINT
```

Add `--apply` to materialize and select that local generation. Preview creates no
repository or endpoint files. Signature checks use the supplied existing GPG
home; source and endpoint cooperative locks refuse concurrent writers.

The resulting layout is:

```text
repository-endpoint/
  current -> generations/EXPORT_SHA256
  generations/EXPORT_SHA256/
    export.json                 # unsigned local inventory, not trust metadata
    release/                    # complete original stable bundle, unchanged
      release.json{,.sig}
      spec.json, base.json, repo/, provenance/, evidence/, ...
    promotion.json{,.sig}        # unchanged existing signed promotion
    withdrawals/ID.json{,.sig}   # complete signed withdrawal records
```

Package/database signatures, normal repo-add aliases and opted-in source-delivery
sidecars/materials retain their exact bytes. The complete signed bundle includes
its evidence; the deployment owner selects a release whose payload is intended
for the endpoint. The normal live repository path is
`current/release/repo/REPOSITORY.db`. A server and its document root, transport,
public trust bootstrap, freshness/key lifecycle and recipient update policy
remain separate integration work. The unsigned export inventory supplies local
integrity and generation identity, not network authentication or newest-release
discovery.

Every available withdrawal must have a valid signed pair bound to its filename
and signer. Selecting a withdrawn release refuses export. After the release CLI
withdraws the current selection, export can create a withdrawal-only generation
with no `release/` route. This removes the live package route on local activation
and retains the incident records and older generations; it does not contact
clients or erase previously downloaded packages.

Every consumed source directory is checked for caller ownership, nonwritable
group/world permissions and absence of symlinks before its contents are read,
including the stable root, selected release, promotions and withdrawals.

Apply copies into a private staging directory, checks each copied hash and
repeats stable release verification. For both a new generation and reuse of a
retained generation, it confirms the source selection/withdrawals have not
changed immediately before selection. It retains a generation by rename and switches only the managed
`current` symlink atomically. A copy/verification failure leaves the old live
selection unchanged. A failure before pointer replacement may leave a complete
inactive generation. Existing generations are verified before reuse and never
overwritten or pruned. They are immutable by this tool's behavior, not a promise
of filesystem immutability against the owner. File contents are mode0444;
directory traversal and server access also depend on the operator's root
permissions and umask.

Exit 0 emits JSON with `planned-local-endpoint` or
`materialized-local-endpoint`, always `network_published: false` and
`trust_changed: false`. A directory-sync or selection-temp cleanup failure after
pointer replacement reports materialized state with
`durability_uncertain: true`; it does not claim an undone commit. Exit 1 reports
a refusal/error. For interruption at the pointer switch, inspect `current` and
its hash-bound generation before deciding what is live. The tool uses Linux
directory flock/fsync and atomic symlink replacement; cooperating writers and
operator-controlled storage are assumed. Bounds are 16,384 members and 8 GiB per
examined tree, with complete exported file/byte checks; rejected input is never
silently truncated.

Run `python3 -B scripts/release/test_export_repository.py`. Its temporary
filesystem and ephemeral TEST-key signatures are real. Positive stable export
tests explicitly model only the promotion/hardware gate verifier; real bundle,
signature, dependency and source-delivery checks remain active. A separate case
uses the unchanged real gate verifier and refuses the synthetic stable fixture.
These tests prove no native ARM execution, supported public release, M2
installation, recovery, performance or A01–A15 acceptance.

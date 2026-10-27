# Operator-policy signed archive intake

`scripts/platform/signed_archive_intake.py` authenticates a finite local package
selection with fresh offline detached-signature verification, then produces a
pristine staging tar and manifest. It accepts `aarch64` and `any` package tuples
through an explicitly SHA256-pinned operator policy. It performs no downloads,
signing, system-keyring access, package transaction, script/hook execution, mount,
boot setup or host installation. Original code is MIT licensed.

This profile is distinct from the frozen NetworkManager/Perl historical-proof
profile. It does not write or accept that profile's proof format. The operator's
policy selects trust inputs; the code cannot establish independent key ownership,
complete source/license closure, release coverage or installed-system acceptance.

## Inputs

Both input files use canonical JSON: sorted keys, compact separators, no NaN or
Infinity, and a trailing newline. Equivalently:

```python
(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()
```

The CLI pins their complete raw bytes separately. The policy also binds the exact
canonical selection digest. Duplicate fields, additional schema fields, aliases,
symlink/hardlinked files and changed file identities refuse.

A selection has exactly:

```json
{
  "schema_version": 1,
  "scope": "EXACT_LOCAL_SIGNED_ARCHIVE_SELECTION_V1",
  "release_set": null,
  "packages": [
    {
      "identity": {"name": "example", "version": "1-1", "arch": "aarch64"},
      "primary_fingerprint": "<full uppercase fingerprint>",
      "archive": {"path": "/absolute/example.pkg.tar.xz", "size": 123,
                  "sha256": "<64 lowercase hex>", "identity": [0,0,0,0,0,0,0,0,0]},
      "signature": {"path": "/absolute/example.pkg.tar.xz.sig", "size": 123,
                    "sha256": "<64 lowercase hex>", "identity": [0,0,0,0,0,0,0,0,0]},
      "metadata": {"name": "example", "version": "1-1", "arch": "aarch64",
                   "depends": [], "provides": [], "conflicts": [], "replaces": [], "license": []}
    }
  ]
}
```

The reference placeholders above are not runnable. Each nine-integer identity is
the exact `lstat()` sequence `st_dev, st_ino, st_mode, st_nlink, st_uid, st_gid,
st_size, st_mtime_ns, st_ctime_ns`. The inherited no-follow reader holds every
ancestor and ordinary single-link operand while checking its full reference.
Archive/signature paths and package names must be unique. The expected metadata
lists preserve multiplicity. The strict parser checks these fields against the
PKGINFO bytes inside the actual signed archive; unsigned source labels or hashes
cannot replace signature verification.

The policy has exactly:

```json
{
  "schema_version": 1,
  "profile": "operator-policy-offline-signed-pristine-v1",
  "selection_sha256": "<exact canonical selection SHA256>",
  "release_set": null,
  "issued": 0,
  "expires": 0,
  "signers": [{"primary": "<full uppercase fingerprint>",
               "signature_not_before": 0, "not_after": 0}],
  "gpg": {"path": "/absolute/gpg", "bytes": 123, "sha256": "<64 lowercase hex>"},
  "public_keyring": {"path": "/absolute/public.gpg", "bytes": 123, "sha256": "<64 lowercase hex>"},
  "trusted": {"path": "/absolute/trusted", "bytes": 123, "sha256": "<64 lowercase hex>"},
  "revoked": {"path": "/absolute/revoked", "bytes": 0, "sha256": "<empty-file SHA256>"}
}
```

Replace timestamps with actual integer Unix seconds and all byte/hash fields
with exact local pins. Policy validity must include the current clock and last
at most seven days. Every selected signer must be approved, within its policy
window, present in the pinned trusted file and absent from the pinned revoked
file. Signature timestamps must be at or after `signature_not_before` and within
the existing verifier's current-time/expiration rules. At most64 signers are
allowed. Full uppercase 40- or 64-character fingerprints are required.

Trusted-file rows are `FINGERPRINT:VALUE:` with VALUE 1–6. They provide explicit
membership only; their numeric ownertrust values are **never imported**. Revoked
rows begin with a full fingerprint, optionally followed by colon-separated data;
all listed fingerprints are denied, including a signing subkey. Empty lines and
lines beginning `#` are ignored; malformed or duplicate fingerprint rows refuse.
An empty revoked file is an explicit pinned snapshot, not proof that no later
revocation exists. Current revocation acquisition and production owner approval
remain operator responsibilities.

Public key data may be a finite binary public export or strict PUBLIC KEY BLOCK
armor with valid CRC24. The existing release offline-kit's public-packet allowlist
rejects secret packets, armor of another kind, partial/unknown packet forms and
truncation before import. Import statuses must identify exactly the approved
primary fingerprints and contain no secret-import flag or failure. No private
key material, key generation, signing or ownertrust import is provided.

`release_set` may instead be exactly `{"record_sha256":"<64 lowercase hex>",
"release_id":"<identifier>"}`, identical in selection and policy. This carries
a future release-record association. It does not verify the record's semantics,
dependency closure, package completeness, repository metadata or licensing.

## Execution and retained results

```sh
/usr/bin/python3 -I -B -S -Werror::ResourceWarning scripts/platform/signed_archive_intake.py \
  --selection /absolute/selection.json --selection-sha256 SELECTION_SHA256 \
  --policy /absolute/policy.json --policy-sha256 POLICY_SHA256 \
  --output /absolute/nonexistent-output --epoch 1700000000 --seconds 180
```

The output must be fresh; populated/incomplete outputs are never repaired,
overwritten or resumed. The module snapshots all selected archive/signature bytes
into private ordinary files, checking original identities/hashes. GPG and the
parser consume those same snapshots. The public key inputs are also retained.
All signatures must pass before any payload parser runs.

Each run uses one fresh private GPG home and explicit keyring, no options file,
automatic key import/retrieval/location, dirmngr, autostart or automatic trustdb
check. The executable is rechecked before dispatch. Native commands transfer
exclusive wait ownership to pinned `owned_process.py`; no independent PID
retirement is invented. Separate stdout/stderr files inherit a 256KiB per-file
limit. Every command has at most 30 seconds including retirement; the shared
operation budget is at most 180 seconds. The complete source graph is pinned.

The reused release-client `signature_status` requires exactly one NEWSIG,
GOODSIG and VALIDSIG; SHA256/384/512 binary signatures; the pinned primary
fingerprint; acceptable signature version/time; and no bad, expired, revoked,
missing-key or other failure status. GPG performs the cryptographic operation
and evaluates key validity. Eligible signing subkeys remain bound to the
approved primary and are checked against the explicit revoked set.

The unchanged bounded XZ/USTAR parser checks members, PKGINFO metadata, controls,
regular payload hashes, metadata/ownership, same-package hardlinks, virtual
symlinks, explicit parents and cross-package conflicts. Extensions, special
nodes, escaping/cyclic/invalid links and conflicting shared paths refuse.
INSTALL files, ALPM hooks, tmpfiles/sysusers inputs, backup paths and configuration
payloads remain inert and separately inventoried. MTREE token parsing is not
complete inode metadata or license/source admission.

Reuse is explicit: the existing pinned authority adapter replaces only the
parser's modeled-authority call with freshly verified expected metadata. No
modeled/historical proof document is manufactured. A separately checked AST
capacity adapter changes only the old bridge's 261-package ceiling to 4,096 in a
private function. It does not edit dependencies or their live globals. Existing
500,000-node, 8GiB aggregate payload, per-file/decoder/spool and compressed-work
limits stay fixed. Supporting 4,096 entries in source does not qualify a 574-set
execution or establish resource sufficiency.

`staging.tar`, `assembly.json`, new-profile authentication envelopes, policy and
selection copies, raw command streams/receipts, and independent serialized-node
verification are retained. The verifier distinguishes the new receipt status
and checks the pending marker before publication. Spool, private runtime and GPG
home cleanup must finish before the final `receipt.json` is published. Failures
retain `INCOMPLETE.json` and `failure.json`; a valid signature alone cannot
publish a successful staging receipt. Inherited parser compatibility labels
remain conservative; effective cryptographic authority is the separate new
profile envelope. No source/license approval is inferred from their reference
fields.

## Optional DATA image composition

`compose_image(selection, policy, tool_pins, metadata_pins, root_policy, output,
epoch)` is an explicit API for the subsequent image stage. It uses the pinned
portable bridge's real metadata capture/join, generated-root proof, body reader,
ext4 encoder and raw readback. It never dispatches the bridge's old exact-two
authentication pipeline or supplies generic empty metadata. Schema2 host profiles
and the existing explicit root policy remain mandatory. It runs additional
native metadata/filesystem tools and was **NOT RUN** by this packet's GPG-only
authorization.

The encoder's existing512MiB regular-body and20,000-node ceilings still apply;
the intake capacity successor does not expand them. A full-system selection may
need a separately reviewed encoder-capacity successor before image composition.

A separately proposed `release_image.py` hook accepts recipe kind
`cachy-asahi-policy-signed-payload-ext4-v1`. The recipe's existing
`authentication` JSON slot carries the new operator policy, while its `selection`
slot carries this selection. The other three inputs remain tool/metadata
profiles and root policy. The old recipe kind keeps its exact-two guard. Parent
recipe/source/artifact binding, image hashing/readback and pinned completed-output
resume remain in the release CLI. This hook is separately staged for Root's
integration; the preceding PR290 packet remains frozen.

## Evidence from this packet, 2026-10-27

The 35 focused pure controls pass with genuine pinned parser/spool/ownership/
assembler/verifier code and modeled GPG only. The optional hook has 4 pure controls,
and all 29 legacy release CLI controls pass against it. Mutation coverage includes
policy expiry/binding, keys/revocation, bad/weak/multiple signatures, tuple/list
metadata, traversal/extensions/special nodes, shared-owner conflicts, hardlinks,
symlinks, source/operand drift, cleanup and pending publication. These tests are
separate from the actual proof below.

The first authorized real invocation used the selected 13 operands, totaling 803,788 bytes,
pinned `/usr/bin/gpg` SHA256
`0317f5ec41b20edcaafc0e99455deba85ca7b3381b1f681dff3c2394de1667f0`
and signer `68B3537F39A313B3E574D06777193F152BDBE6A6`. One public import and five
detached verifications completed with exit 0 and successful exclusive reaping.
The five packages were archlinux-contrib, htmlq, pacman-contrib, pyalpm and
xdg-utils. Their genuine raw streams and receipts are retained in this packet's
`actual/commands/`; they are this source's own execution, not Root's earlier probe.

After those six successful GPG calls, the proof harness rejected the parser's
first directory-relative spool open because its write audit required absolute
paths. The CLI correctly retained incomplete state, removed the private GPG home,
and published no parent receipt. **That first CLI proof remained incomplete.**
GPG was not repeated. A separate subprocess-forbidden data driver rechecked this
packet's own six pinned command outputs/envelopes and consumed the identical
verified snapshots through the unchanged production parser/assembler/verifier.
That separate DATA execution passed 158 nodes (30 directories, 128 regular files)
and produced a 3,532,800-byte staging tar. It explicitly grants no new GPG or
production CLI acceptance and introduces no production replay-authentication API.

Generic ext4 composition, full 574
acquisition/transaction, source/license/independent owner approval, production
trust/bootstrap, scriptlet-installed state, native ARM/16K, Asahi boot/firmware,
physical installation/recovery, M2, performance and release acceptance remain
NOT RUN or NOT ACCEPTED. That initial authorization was exhausted; those six successful calls remain
split evidence and were not relabeled. A separately authorized causal retry is
recorded below.


## Uninterrupted full CLI qualification, 2026-10-27

A new bounded authorization permitted one fresh full CLI after correcting only
its proof harness. Python's `open` audit event exposes path/mode/flags but omits
`dir_fd`; the original absolute-only write audit could not recognize the existing
safe relative spool create. The corrected harness carries a single-use grant
only for exact `body-NNNNNNNN` creates, mode0600, O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW,
through the verified owned0700 output-spool directory descriptor. It forwards the
original syscall unchanged. Exact GPG argv/environment/six-command roles and
network/native-probe prohibitions remain enforced. Seven focused mutation
controls and one actual pinned-spool control passed before GPG dispatch.

The unchanged34996-byte product source SHA256
`fb06597a7ee68e9b3c66209e43a8b058d9d7a472a83434504936c99df2eed0f0`
then passed one uninterrupted CLI invocation from a fresh source projection and
output. The same13 owned operands and original policy/selection were retained;
no new download, key generation, signing, system keyring, private key, host
package operation or production source change occurred. One public import and
five detached verifications each returned0 with exclusive successful reaping,
complete output, EMPTY_TWICE, no signals/timeouts/errors. The outer CLI returned0
in1.4133s under a180s outer cap; CLI budget was170s and each GPG cap at most30s.

That command completed signature authentication, exact PKGINFO/list metadata,
strict payload/ownership checks, staging serialization and independent tar/body
verification for158 nodes (30 directories,128 files). All143 owned-relative spool
creates passed the narrow audit grant. Spool, staged runtime and GPG home cleanup
passed; no INCOMPLETE/failure marker remained. Only then was the final new-profile
receipt published. Its10408-byte SHA256 is
`98b4a12d38bd71bb2967a1a1f8508176501d9847b589a5f42fb5627865d31ab4`.
The3532800-byte tar SHA256 is
`829eda48803ddf8ce09133dff93fe15907171c64b1dfbe3104e6e5c32d624945`;
manifest SHA256 is
`5cd90c303f89eb0baf6bda23e21b873f885eef8fd2eb1024b0f8b76a33c7dfa6`.

The separate `generic-signed-archive-intake-full-cli-proof-20261027` evidence
packet retains the complete command, raw stdout/stderr, all six inner owned
supervision receipts, outer receipt, corrected audit grants, source/dependency/
operand pins and final artifact hashes. The entire original split-pass/refusal
packet rejoined its frozen144-leaf inventory unchanged. The new result closes the
finite five-package uninterrupted CLI proof; it does not substitute split passes
for full command behavior. Generic ext4, full574, installed/bootstrap/source/
license/independent owner trust, ARM/16K, boot/M2/performance and M8/release gates
remain unaccepted.

# Offline recovery data workspace

`scripts/release/recovery_bundle.py` materializes an explicitly selected
predecessor development kit and the exact already-authenticated recovery archive
inventory into an absent private directory. It supplies a relocation-safe
read-only verifier and a reviewable command template for the existing repository
recovery planner. It does not execute the template or install anything.

This fills the consumer step between `offline_kit.py inspect` and reviewing
`recover_repository.py plan`. The existing offline lifecycle rehearsal supplies
the distinction between a synthetic predecessor and accepted stable recovery;
this consumer does not run the rehearsal or create signatures. It directly
reuses `offline_kit.inspect/inventory/publish` and
`recovery_inputs.plan/previous/reuse` plus the bounded metadata reader.

## Trust and selection contract

Obtain the selection JSON and its SHA-256 from the operator's already
authenticated selection channel. An observed checksum of arbitrary files does
not establish that selection's authority. Independently supply the existing
kit signer fingerprint, namespace, minimum sequence and private receiver state.
The transport receipt and a copied public key cannot establish those values.

The kit is freshly inspected with the current trusted local `offline_kit.py`
and client. Envelope expiry, signer/namespace, package/database signatures,
sequence floors and existing checkpoints remain enforced. An old envelope that
has expired cannot be used; an authorized producer must supply a fresh valid
envelope through the existing process. No clock or checkpoint override exists.

The exact selection schema is:

```json
{
  "schema_version": 1,
  "purpose": "offline-recovery-selection",
  "kit_sha256": "<kit.json SHA-256>",
  "release_sha256": "<release/release.json SHA-256>",
  "release_id": "<selected predecessor ID>",
  "base_sha256": "<release/base.json SHA-256>",
  "policy_sha256": "<SHA-256 of client.encoded(spec.policy)>",
  "packages": [
    {"name": "<name>", "version": "<exact version>", "arch": "aarch64",
     "filename": "<exact archive basename>", "sha256": "<archive SHA-256>"}
  ],
  "protected_versions": {
    "linux-asahi": {"version": "<exact base version>", "arch": "aarch64"}
  },
  "recovery_receipt": {
    "path": "<absolute retained recovery-receipt.json path>",
    "size": 12345,
    "sha256": "<already-authenticated receipt SHA-256>"
  }
}
```

`packages` must equal the complete release package list projected onto these
five fields, sorted by name. `protected_versions` must equal every protected
policy package's version and architecture in the signed complete base. The full
policy digest binds supported models, selected and protected packages, and
coordinated sets. No protected package, kernel, firmware, boot, graphics or audio
choice is changed.

The recovery receipt must have the existing
`exact-superseded-recovery-archive-data` schema and
`PASS-all-exact-old-recovery-archive-data` status with all 16 packages verified
and no failures. This deliberately retains the existing finite profile and its
pinned ALARM public certificate; it does not generalize it into an arbitrary
archive installer. Every recovery package must match the exact predecessor
base name/version/architecture. The entire receipt pin binds its package,
archive, signature, original index and inspection inventory.

All original data is copied and rehashed. The existing recovery reader checks
retained signature status and signer, exact operator links and archive metadata.
The result explicitly reports `fresh_recovery_signature_verification: false`:
these are retained authenticated observations, not fresh cryptographic or
independent key-owner verification. The operator must already trust the pinned
recovery receipt. Expired or revoked trust learned after that observation needs
separate current authentication before operational recovery.

## Materialize and verify

Use a trusted local checkout/runtime. The consumer never executes Python copied
from the kit. Python, GPG and Linux `renameat2(RENAME_NOREPLACE)` must already be
available; no software is installed.

```sh
python3 -B scripts/release/recovery_bundle.py materialize \
  --selection /absolute/selected-recovery.json \
  --selection-sha256 "$SELECTION_SHA256" \
  --kit /absolute/previous-kit \
  --signer "$KIT_SIGNER_FINGERPRINT" --namespace "$KIT_NAMESPACE" \
  --minimum-sequence "$KIT_MINIMUM_SEQUENCE" \
  --state-dir /absolute/existing-private-receiver-state \
  --output /absolute/private-parent/recovery-workspace
```

The output must be absent and outside the kit and external receiver state.
Its parent must be caller-owned without group/world writes. Staging and the
published workspace are private `0700`; copied files are read-only `0400`.
Publication refuses existing destinations and destination symlink substitution.
Before publication, the complete workspace is verified again. A post-rename
I/O/custody failure may retain a complete output requiring inspection.

Record the returned `receipt_sha256` independently. After moving the entire
workspace, verify it with both the original selection and receipt pins:

```sh
python3 -B scripts/release/recovery_bundle.py verify \
  --workspace /absolute/relocated/recovery-workspace \
  --receipt-sha256 "$WORKSPACE_RECEIPT_SHA256" \
  --selection-sha256 "$SELECTION_SHA256" \
  --signer "$KIT_SIGNER_FINGERPRINT" --namespace "$KIT_NAMESPACE" \
  --minimum-sequence "$KIT_MINIMUM_SEQUENCE" \
  --state-dir /absolute/existing-private-receiver-state
```

The workspace contains the exact predecessor kit, original selection and recovery
receipt, input documents and public certificate, all exact archives/signatures,
indexes and prior inspections, extracted `.PKGINFO` data, `commands.json`, and
the complete `recovery-bundle.json` file/alias inventory. Reverification ignores
historical absolute paths: it checks original evidence bindings before making
an ephemeral local reference view for the existing planner. It succeeds after
source deletion and relocation. Missing bytes, extra members, changed metadata,
hardlinks, special files and escaping aliases refuse verification.

`commands.json` contains an argument array for `recover_repository.py plan`.
Replace its placeholders with the actual authenticated retained **stable**
source, local endpoint, observed current generation and public verification
home. The copied development kit is not that stable root. The existing planner
must still authenticate promotions and compatibility, and any later repository
recovery requires its separately reviewed/signed plan. No `--apply` command is
generated. No package/host ALPM, mounts, disks, boot, network, signing, private
keys or user-session access occurs here.

## Evidence limits and tests

Run `python3 -B scripts/release/test_recovery_bundle.py` after installing the
proposed files in the canonical layout. Tests create tiny original xz fixtures
and explicitly mock kit authentication and the fixture public-certificate pin.
They execute the real CLI parser/main, copying, archive reinspection, metadata
extraction, relocation, hash/tamper controls and no-replace publication. They do
not generate or use private signing keys and do not establish positive
cryptographic integration. The retained example kit's expiry is also exercised
through the unmodified production CLI as an actual refusal.

All results remain recovery **data** custody evidence. Package installation,
usable-system restoration, stable admission, ARM/native execution, M2 hardware,
snapshot restoration, boot/session recovery and performance are not accepted.

## Real host cryptographic component validation (2026-10-28)

The mocked fixture coverage above is the initial consumer-test history. The
corrected product retains those explicit unit-test seams and now has 23 focused
host tests. A separate real host integration used an isolated disposable TEST
authority without mocking signature/authentication, certificate pins, clocks or
checkpoints. It materialized an authenticated kit, reinspected the copied kit,
verified the workspace before and after relocation and producer-input removal,
then verified again using public material after private signing-home retirement.

That finite observation includes 14 causal CLI refusals and 55 owned commands
reaching their expected exits. Expected refusal exit1 is preserved, not relabeled
as exit-zero success. TEST fingerprint was
`7DC954EC29B50C54BA40DE712BC81A8722A5ACB0`; this is historical test provenance,
not production trust or a current-validity claim. The short/long envelopes expire
naturally; no expiry/checkpoint override or operational signing authority follows.

The product correction admits finite fractional recovery timing observations
emitted by the actual producer. Duplicate keys, nonfinite/overflow numbers,
boolean/string/negative timing values and malformed timing rows refuse. Authority
selection/client parsing stays integer-only, and retained signature exit requires
an exact integer before existing exit-zero/status/fingerprint checks. The exact
pinned ALARM recovery certificate is armored, so the unrelated binary kit-key
packet parser is removed only from that certificate path; its SHA/size/bytes,
planner checks and separate kit-keyring guards remain. No signature bypass exists.

The integration used inert synthetic overlay/base inputs and 16 exact retained
ALARM recovery archives as rehashed/reinspected data. Their signature observations
remain retained evidence: `fresh_recovery_signature_verification` stays false.
No archive payload or hook was executed. Owned-agent reaping, per-home gpgconf
shutdown/socket removal and private-home removal were recorded; no secret export
is retained. Global escaped-descendant absence and physical erasure were not
observed. The earlier failed/retired authority is preserved as failed evidence.

These results establish host crypto/component behavior only. They do not establish
native ARM execution, installed transactions, stable endpoint recovery, usable
system/boot/session restoration, M2, performance or release acceptance. Retained
integration provenance: `artifacts/development/recovery-bundle-crypto-root-integration-20261028/`
and its pinned replacement-authority evidence inventory. No crypto or test rerun
occurred during this source integration.

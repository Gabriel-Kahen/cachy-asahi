# Three-package coordinated-maintenance DATA proposal

November 14, 2026. The actual retained 626-package composition **prepares as
metadata under an explicit three-package proposal**. The original protected
policy still fails and remains visible. Overall result is **HOLD / UNAPPROVED**;
no package, protected-list file, repository selection or system was changed.

This is a separate optional phase of the
[supported composition adapter](../../scripts/port/supported-composition/README.md).
It reuses the same bounded private libalpm worker and does not create a solver,
installer, acceptance authority or changed default profile.

## Exact proposal

The schema is `unapproved-Asahi-three-package-maintenance-v1`, with explicit
`approval_status: UNAPPROVED`. It binds the exact original composition contract,
image inventory, protected tuple and ordered Asahi/core/extra catalog references
by their full paths/sizes/SHA-256 values. Its only change records are:

| Package | Exact retained before | Exact proposed after | Repository |
| --- | --- | --- | --- |
| Python | `3.14.7-1` | `3.14.8-1` | core |
| NetworkManager | `1.58.1-1` | `1.58.1-2` | extra |
| Perl | `5.42.2-2` | `5.42.3-1` | core |

Each record requires its own nonempty bounded reason. Extra changes/fields,
missing before identities, different versions/repositories or changed bindings
refuse. All three after identities must already be explicit roots/providers in
the original composition; the proposal cannot add or retarget them. Additional
kernel/Mesa/boot/audio protected target changes refuse, and any extra implicit
baseline change fails proposed preparation.

The original 201-protected policy is evaluated first without relaxation. The
second private run uses an in-memory proposed Python version and exact three
base-change expectations. Root/provider policy and all other original protected
versions remain fixed. Neither that temporary model nor successful dependency
preparation adopts the proposal.

## Actual retained-data run

The original full-held-desktop contract remains SHA-256
`af4622c393f1fb0ec8d3ba81b1ff3f9179e6033049c375e8d209f28a83b0fd45`.
Its before image/protected/catalog references and two actual unqualified host
candidate archives are unchanged from the
[previous demonstration](supported-composition.md).

The new local ignored proposal is
`work/supported-composition-20261114/three-package-maintenance-proposal.json`,
2468 bytes, SHA-256
`a8f8cb9faf69f0fbb297ef9cc1f18cd15d3682efa494e1894b509536ddf419f3`.
The exact command executed was:

```sh
python3 -B scripts/port/supported-composition/compose.py \
  --contract /home/gabe/Documents/ChatGPT/cachy-asahi-install-completion-20261114/work/supported-composition-20261114/full-held-desktop.json \
  --contract-sha256 af4622c393f1fb0ec8d3ba81b1ff3f9179e6033049c375e8d209f28a83b0fd45 \
  --maintenance-proposal /home/gabe/Documents/ChatGPT/cachy-asahi-install-completion-20261114/work/supported-composition-20261114/three-package-maintenance-proposal.json \
  --maintenance-proposal-sha256 a8f8cb9faf69f0fbb297ef9cc1f18cd15d3682efa494e1894b509536ddf419f3 \
  --output /home/gabe/Documents/ChatGPT/cachy-asahi-install-completion-20261114/work/supported-composition-20261114/three-package-maintenance-result
```

The output path is exclusive; repeat with a new one.

| Observation | Original policy | Explicit proposed policy |
| --- | --- | --- |
| Metadata status | FAIL | PASS |
| Policy blockers | Original five retained | Zero |
| Tentative packages / dependency relations | 626 /3202 | 626 /3202 |
| Python | Protected `3.14.7-1`; `3.14.8-1` target refused | Proposed `3.14.8-1` selected |
| Base changes permitted | None | Exactly the three named records |
| Original protected versions unchanged | 201/201 in the original diagnostic run | 200/201; only explicitly proposed Python differs |
| Proposed expected protected versions matched | Not applicable | 201/201 |

The proposed worker returns0/errno0 under libalpm16.0.1. Every original root and
provider remains satisfied in that proposed model; no fourth baseline change or
platform removal appears. CLI exit2 and overall HOLD/UNAPPROVED do not mean the
original policy passed or that this is an accepted maintenance transaction.

The report retains all original five blockers and original holds/26 catalog
exclusions. The proposed inventory separately retains 626 per-package acceptance
holds, including archive custody, signature authentication, corresponding source/
license/grant/maintainer review, installed payload/hooks/ABI/recovery and native/
hardware work. Python's catalog declaration is not substituted for an inspected,
authenticated native archive or its source/build provenance.

Retained local identities:

```text
three-package-maintenance-result/composition.json: 2672044 bytes
SHA-256 64f6c7419f602712ef783a30d5a190d9575b5bddf6bde20b9b4a97d1dee00bd4
proposed-maintenance/inventory.json: 1333961 bytes
SHA-256 3575118db3240a4a343490771eff536f0ded2231870f51c20c2d5a2bd0ba01d4
```

Both private DBs were removed; original/proposed worker DATA and diagnostics
remain. No network acquisition, package/recipe execution, installation, image
assembly, native dispatch or shared-policy mutation occurred.

## Verification and next gate

The original 12 composition controls still pass. Eight new real-libALPM synthetic
proposal controls pass: exact positive model with original failure retained,
unchanged default failure, wrong versions/reasons/extra changes, reference
binding mismatch, absent before identity, kernel/Mesa/audio target changes,
extra implicit baseline change, root-retarget and approval-flip refusal.
Synthetic fixtures are explicitly labeled and do not supply real package facts.

The resulting unapproved inventory is concrete input for reviewing this exact
coordinated maintenance set and preparing the existing transition/recovery
contract once real authenticated archive/signature/provenance and recovery assets
are supplied. ABI consumers, protected-platform update/recovery and actual
supported-machine behavior still need their own evidence. Source DATA success
cannot authorize a changed protected tuple, install/update, native acceptance,
production signing or either M2 model.

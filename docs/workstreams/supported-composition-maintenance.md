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

## November 25 offline selection and custody

The R132 transport recheck hashed all 753 files (653,469,760 bytes) against
manifest `08a1f949794b085158608c9577476574514fa963a8168554ca523c2242f35178`.
All 368 forward archive names, versions and runtime package metadata match
the pinned 626-package selection. Of those, 366 match vendor catalog archive
pins and 359 also match the catalog's embedded signature bytes. The seven
community archives use separately pinned detached signatures. The three
rollback pairs match their original archive join, including the signed
`.PKGINFO` hashes. All 371 pairs produce the expected cryptographic
`VALIDSIG`. The two project TEST certificates have expired. The current strict
signature check refuses them and a new rehearsal requires fresh scoped trust.
The four key fingerprints and raw verifier status are in the
[local readback receipt](#local-evidence-pins).

All five [Overlay Preview 1](../release/overlay-preview-1.md) archives match
the retained release checksums. Each archive's `.BUILDINFO` recipe hash
matches the bundled PKGBUILD and release provenance. The source bundle
contains all five license and notice pairs. The adapter joined each archive's
package identity and runtime relations to its retained SRCINFO.

| Profile | Libalpm metadata result | Final packages | Qt6 Base |
| --- | --- | ---: | --- |
| Preview 1 under original protection policy | FAIL with the same five blockers | 629 diagnostic | 6.12.0-3 in the private alternate catalog |
| Preview 1 with three proposed updates on the frozen catalogs | PASS, unapproved | 629 | 6.12.0-2, historical archive unavailable |
| Preview 1 with three proposed updates and the exact R132 Qt catalog alternative | PASS, unapproved | 629 | 6.12.0-3, archive SHA-256 `2777135b375ba82250896fa9a993926bf3c05b59dd22217f63d6a1391c1b4c31` |

The last row has 371 proposed archive additions, zero removals and 3,213
dependency edges. It preserves all 201 versions expected by the proposal.
Compared with the installed R132 forward lock, First Login moves from
`0.1.0-2` to `0.1.0-3` and the Fish, Zsh and Hyprland settings packages join.
The other 625 shared package metadata rows match R132, including Setup8,
the Asahi graphics and audio stack and the three maintenance versions.

An explicit development variant swaps vendor `libfdk-aac 3.0.0-1` for
`cachy-asahi-fdk-aac 3.0.0-1`, archive SHA-256
`237b7812435bd78456d72c157f5703f258f5b6b7455cb99e5b075f642071c247`.
The project archive's BUILDINFO matches the current recipe, and its regular
license files include the complete classic and xHE notices. The variant
preserves the other 628 package metadata rows and all three proposed
maintenance changes. All three explicit provider pins resolve. PipeWire
uses the project package for `libfdk-aac` and `libfdk-aac.so=2-64`.
The variant remains unapproved. The exact project binary previously passed
the generic native ARM replacement and AAC-LC callback trial. Its TEST
certificate has since expired. A local pack and recipient reconstruction
verified all 25 recipe inputs, including the 900-file codec source packet.
The source bundle SHA-256 is
`577305d7575e23dfcf3d55fb6da7fdc53f4257b5f44390acaa35a5d2850ec631`.
[FDK provider trial](../validation/fdk-provider-native-20261015.md)

Release decisions still needed for this composition:

- Approve the exact three-version proposal and the reviewed Qt archive selection.
  Bind the new project set to a signed installation, recovery and installed
  Asahi kernel boot exercise.
- Hold vendor FDK for redistribution. Its archive includes both codec
  libraries with only the classic notice. If using the project FDK variant,
  finish recipient source delivery and applicable rights review, bind a fresh
  TEST signature, and exercise the provider on the selected Asahi system.
- Finish source and license review across the selected inventory, including
  the 258 unchanged inherited base packages and the two missing forward
  build-time recipes. `asahi-desktop-meta 4-10` requires
  `widevine 4.10.2891.0-1`, whose archive declares `custom` and includes a
  Widevine EULA. Review delivery from the vendor or an explicit profile
  change before including it in a project repository.
  [R132 recipe custody](supported-composition-update-sources.md)
- Preserve the Asahi audio and graphics owners and versions in the proposal.
  Audio source review, Mesa source correspondence, installed loader closure,
  production trust and physical boot, accelerated rendering, protected audio
  and failed-update recovery on both Air sizes remain open.

### Local evidence pins

Selection reports are under
`~/.cache/asahi-preview1-composition-20261125.cobdq0my/`. The archive readback
is under `~/.cache/asahi-r132-selection-recheck-20261125.6pmy5WWJ/`.
The FDK variant is under
`~/.cache/cachy-asahi-preview1-qt-fdk-provider-alpm-ffr8ubsm/`.

| Receipt | SHA-256 |
| --- | --- |
| `r132-transport.ACTUAL.json` | `020410486a6fddedec735c96229fc7b1fe530d684683a0c4ef0c8cde53653cae` |
| `preview1-archive-source-joins.ACTUAL.json` | `4517e48eb55f2077cba2be53536d42550965626f2fb59d494123d56a67e42b40` |
| `qt-alternative-preview1-selection.ACTUAL.json` | `aeb0536068e09140bbf577ee36beec960520ca4415f095c30d77379bc2302cfc` |
| FDK variant `comparison.DATA.json` | `62bb1911fbcd1f1aef194d2b54c4b82d1ebeb863d672b000aa635e11bc1730ab` |

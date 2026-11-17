# Source79 final 779 preparation DATA

`prepare.py` deterministically reuses the whole-pinned adoption from commit
`46c25cb31c8e2a518a865127c3c8745d11ea4ac8`. It copies **zero archives** and issues
no Root authority. Its only writes are fresh small preparation outputs and the
unchanged Source79 Reader's bounded temporary inverse DATA. No network, GPG,
mount, lease, signing, secret access or native dispatch is implemented.

The fixed publication is Source79 commit
`429f82ea1e63cdf69b4be4be518257142f925e91`, ref
`refs/heads/codex/bankstown-qt3-hosted-source79-20261117-r1`, tree
`3a5082263b9e0bf1bd0ffc87b2dd9570d5effb8a`. Its whole-pinned Root publication
receipt and unchanged Reader join every file/mode/map and the complete Source78
inverse before operands are used. The pinned original provider tuple must match
the pinned owner request. A new `material_root` may rebase the existing exact
layout; all actual bytes at the selected paths are reverified by the maintained
complete 773 planner. Rebinding preserves historical provider source-map and
baseline provenance; those historical refs are not owner-input transport roles.

The actual count is:

| File roles | Count |
| --- | ---: |
| Base archives/signatures | 498 |
| Supplemental archives/signatures | 16 |
| Public keyring DATA, including zero-byte revoked file | 3 |
| Candidate archives/signatures | 256 |
| Base lock, bootstrap profile, explicit baseline inventory, catalog | 4 |
| Official public certificate and Root admission | 2 |
| Final transport references | 779 |

Every role path must be distinct. A missing trust selection produces an actual
**777-reference HOLD**, two named missing file roles, unknown missing bytes
(`null`), and no fabricated final envelope. A fingerprint is an additional
non-file selection. Existing 773 materials total exactly 1,737,014,022 bytes.

The explicit selection JSON has schema 1, kind
`SOURCE79_FINAL779_PREPARATION_DATA_V1`, and exactly these remaining fields:

- `seed_owner_inputs`, `seed_provider`, `publication_receipt`: full
  `{path,bytes,sha256}` references matching `inputs.lock.json`.
- `source_root`, `material_root`: canonical existing absolute directories.
- `official_trust`: null, or exactly `{Root_admission,public_key,fingerprint}`;
  the two file refs are whole-pinned, nonempty, capped at 2 MiB/64 KiB. Fingerprint
  must equal the frozen base's uppercase 40-hex primary fingerprint.
- `custody_selection`: null, or a whole reference to external Root custody DATA.
- `observed_epoch`: explicit positive integer time selected by the caller.
- `Root_authority`: null.

Fresh official admission DATA must already exist outside this helper. The
operative audio predicates require Root issuer/approval, the exact full public
reference/fingerprint, scope `BANKSTOWN_QT3_IMAGE_INPUT_TRUST_ONLY`, exact integer
issued/expires times and `issued <= observed_epoch < expires`. The helper does
not authenticate the issuer, validate the public certificate cryptographically,
or run GPG. Generic onboarding scope cannot substitute. When both actual trust
files exist, the unchanged hosted assembler streams and joins all 779 refs and
emits its exact canonical envelope; authority remains unissued.

`Root-custody.UNISSUED.DATA.json` is the exact fillable custody selection shape.
Root may supply a separately whole-pinned, fresh completed record after selecting
actual custody. Binding checks source/map/final owner pin/staged root, a positive
non-root launcher UID, and the exact 15-field maintained mount-observation shape
and finite capacity/inode bounds. This is an external DATA join, never an actual
mount observation or retirement proof. An incomplete 777 template leaves its
final `owner_inputs_pin` null to prevent selecting the incomplete request.

**Root custody and mount ownership are separate.** The unchanged launcher starts
as `getuid()==geteuid()>0`, and the private0700 input mount must be owned by that
caller UID. A UID0-owned input root cannot satisfy that operative gate. Root may
retain custody and own the retirement obligation, while the mounted input-root
UID remains the selected non-root launcher UID. This helper changes no gate.

All non-Source references and the small envelope must be inside the selected
staged root; metadata outside it is reported as an unfinished placement binding.
To prepare for later sealing, select a fresh output directory **inside** a writable
prestage root already containing the verified materials and trust files. Only
small metadata is added. If the final mount is already read-only, prepare small
outputs elsewhere and have Root place/rebind them before sealing; the helper
cannot write a sealed mount or claim outside metadata is confined. All reference
paths must be final before Root selects the resulting owner/request pins.

Run with explicit paths, an independently selected selection hash, a private
`TMPDIR` with space for the 36 MB inverse, and the existing 512 MiB process bound:

```sh
python3.14 -I -B -Werror scripts/ci/bankstown-qt3-source79-final779-preparation/prepare.py \
  --repo /path/to/reviewed/repository \
  --selection /path/to/selection.UNISSUED.DATA.json \
  --selection-sha256 SELECTED_WHOLE_SHA256 \
  --output /path/to/fresh/preparation-directory
python3.14 -I -B -Werror scripts/ci/bankstown-qt3-source79-final779-preparation/test_prepare.py -v
```

Outputs include the owner inputs, provider tuple, custody template, delegation,
request and report. Official trust/admission templates also record the exact
required fingerprint and scope with issuer, approval and validity null. These
proposals never count as the two missing actual trust files. A final envelope
exists only when all 779 actual refs join.
Root request/delegation issuer, approved, nonce, validity and runtime fields
remain null, `dispatch_ready` is always false, and the CLI installs an actor
refusal fence. Failed preparation leaves partial DATA without a completion
receipt; use a fresh output. Original Qt-minus2 and missing original PKGBUILD
correspondence, source/legal/key freshness, native, physical M2 and release gates
remain held. Synthetic tests establish no actual trust, mount or admission.

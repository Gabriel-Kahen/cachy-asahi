# Local recipient adoption DATA for published Source79

This separate family adopts only the existing public material references selected
by the two whole-pinned manifests in `inputs.lock.json`. It performs no discovery,
network request, Original artifact GET, secret lookup, key-home read, subprocess,
native build, mount, lease change or Root authorization. It does read the three
explicit public keyring DATA files; these are not private key homes.

Published Source79 is commit `429f82ea1e63cdf69b4be4be518257142f925e91`, ref
`refs/heads/codex/bankstown-qt3-hosted-source79-20261117-r1`, tree
`3a5082263b9e0bf1bd0ffc87b2dd9570d5effb8a`: 79 files / 35,747,849 bytes.
The exact Root publication DATA receipt is required, whole-pinned separately from
Source. The unchanged Source79 Reader validates every Source member, map alias,
mode, tree and complete Source78 inverse. This helper does not fetch or republish
that commit. A source-equivalent local tree plus Root's publication receipt does
not itself prove another recipient has cloned that commit.

The original complete517 provider requires its original onboarding Source map;
passing the Bankstown map to that API is invalid. Both roots must be explicit.
The helper uses the unchanged provider's metadata/selected-reference APIs and
Bankstown's maintained actual `plan_inputs(..., verify_archives=True)` API.

Before copying any archive, both manifests must match their required whole pins,
all selected role sets and archive/signature pins must join the frozen metadata,
and every supplied path must be distinct, ordinary, single-link and nonwritable
by group/other. Unknown, substituted, oversized, aliased, special or changed
operands refuse. A missing ordinary file produces a precise role/count/byte HOLD
receipt; no material bodies are streamed in that case. Present files in a HOLD
receipt remain unverified. Each file is capped at 1 GiB; all 773 selected materials
must total exactly 1,737,014,022 bytes. No directory carrier is recursively read.

A successful run copies all 773 materials to a fresh owner0700 DATA directory,
with owner0600 single-link leaves. Creations use retained directory descriptors;
namespace/owner/mode/inode changes refuse. The copied output is reverified by the
unchanged complete517 provider and full773 assembler, preserving protected349,
205 shared selections, 128 additions, and prospective477. Two metadata operands
are copied separately. This is local user-owned custody; Root's required UID0
retained exact read-only mount and external retirement proof remain UNISSUED.
No completion receipt is emitted after a copy/hash/join failure. Partial output
is retained for diagnosis and must never be adopted; select a new output path.

Example (all paths must be absolute and explicit):

```sh
python3.14 -I -B scripts/ci/bankstown-qt3-source79-adoption-data/adopt.py \
  --repo /path/to/reviewed/repository \
  --source-root /path/to/exact/source79 \
  --provider-source-root /path/to/original/onboarding/source \
  --base-manifest /path/to/base517-existing-fields.DATA.json \
  --candidate-manifest /path/to/candidate_materials.json \
  --publication-receipt /path/to/Root-publication.ACTUAL.json \
  --output /path/to/fresh/private-DATA
```

Use a private `TMPDIR` with sufficient space for Source79 Reader inverse DATA
(about 36 MB per inverse). The helper installs an audit hook refusing actors.
The successful local check was run with a 512 MiB address-space limit.

Outputs include the whole-pinned owner-input request, complete517 result,
adoption receipt and Source79-specific Root request/delegation proposals. The
proposals preserve 4320-second delegation / 4170-second launcher / 3960-second
controller limits and all 77 mapped member pins. `issuer`, `approved`, nonce,
validity, actual run/job, image, current official trust and final owner-input pin
remain NULL. `staged_inputs` remains NULL: no hosted envelope is fabricated.
The owner request has `official_trust: null` and cannot pass hosted admission.
The final trust operands bring the transport join to779 references; Root must
reassemble and bind that complete request before issuing authority.

Checks:

```sh
python3.14 -I -B scripts/ci/bankstown-qt3-source79-adoption-data/test_adopt.py -v
```

Synthetic controls only exercise refusal boundaries; they never count as a real
773 join or native qualification. Actual local adoption evidence is separate.
Original Qt `6.12.0-2`, the missing original PKGBUILD SHA256
`0bd04f4db92ed8b0992e851a4ddd68f39ac7b6b079af4e354dba466946ca2272`, source/legal,
key freshness, physical M2, installation and release holds remain unchanged.

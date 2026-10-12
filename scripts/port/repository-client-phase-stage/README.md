# Phase-aware repository-client successor

This separate successor preserves the held v1 native admission checks and adds
independent public-key phase verification before fresh TEST restaging. It owns
only this directory and `docs/workstreams/repository-client-phase-stage.md`.
The earlier stage and collector remain independently reviewed dependencies.
Actual accepted native handoff, installation and M2 validation are **NOT RUN**.

`entry.py` authenticates all five production source files against a coordinator
supplied source-map hash before compiling captured bytes. Launch requires
`python3 -I -B`; Python import loaders and PYC are excluded. `dependencies.py`
authenticates the collector's complete seven-file proposed/adopted source map
`50638283c25bc76ec66bd47988227e31022cbad3bac16354d9db8ca7081dccc3`, both
held predecessor sources and the frozen release/client dependencies. A cached
collector module set still requires current source authentication on every use.
The coordinator must authenticate the launcher's bytes before launching Python.

```bash
python3 -I -B scripts/port/repository-client-phase-stage/entry.py \
  --source-map scripts/port/repository-client-phase-stage/source-map.json \
  --source-map-sha256 "$REVIEWED_PHASE_SOURCE_MAP_SHA256" \
  accept --inputs "$PINNED_PRIVATE_INPUT_ROOT" \
  --authority "$PINNED_AUTHORITY" --authority-sha256 "$REVIEWED_AUTHORITY_SHA256"
```

Use `restage` with the same admission arguments plus `--metadata`,
`--metadata-sha256` and a new `--output` directory to run the adapter. Hashes
must come from the coordinator's independently reviewed packet. Computing a
hash from an untrusted input does not establish acceptance.

## Exact admission boundary

The outer authority retains the predecessor's exact `FIELDS` and sixteen
`REFS`, with integer `schema_version: 2`. Its `crypto` object has exactly:

```json
{
  "schema_version": 2,
  "purpose": "external-repository-cryptographic-phase-acceptance",
  "status": "PASS",
  "request": {"path": "control/phase-request.json", "sha256": "<external SHA256>", "bytes": 0},
  "receipt": {"path": "control/phase-receipt.json", "sha256": "<external SHA256>", "bytes": 0}
}
```

The example's hash and size placeholders are not acceptable inputs. Both
references must identify nonempty mapped bytes in the outer authority. Schema1
and its flat fifteen `VALID` assertions are refused; no compatibility conversion
can manufacture current A authorization.

The request is the collector's exact schema2 `repository-cryptographic-phases`
request. Its mapped files form a strict subset of the complete authority map,
including the complete six public repository inventories and exact native status
logs. Request, receipt and authority share source commit, run, nonce and image.
Both the complete request artifact map and public artifact map are bound by
hash. Three distinct full fingerprints and the original/revoked certificates
must match accepted role identities and public bytes.

There are fifteen ordered healthy signed objects: seven retained A packages/DBs
and eight B packages/DBs/signed aliases. For every object the retained receipt
binds exact data/signature hashes, GPG argv, actual exit, stdout machine status,
stderr hash and current certificate validity. Snapshot checks have integrity
`VALID` and authorization `SNAPSHOT_ONLY`. Terminal A authorization is `REVOKED`;
terminal B authorization is `VALID_AT_OBSERVATION`. These are observation bounds,
not production trust grants. All positive invalid/expired/revoked status refusals
remain intact; no fake clock, expiry bypass or weakened digest policy is used.

Native observations must bind exact command indices, labels, argv, stdout files
and raw receipt evidence hashes. A's healthy observations precede its actual
signing-home revocation import. Both native imports precede the verifier's
revoked-A DB status. The B-signed public alias may follow A revocation. Exact
`SIG_ID` and `VALIDSIG` facts must match independently verified signature packets.
Local certifications stay `native-receipts-only`; this code does not invent or
export verifier certifications.

The gate creates a private copy of exactly the request map and reruns the
source-authenticated collector's real current-clock, public-only attester. It
compares stable certificate, artifact and phase proofs, independently checks all
six repository contents/negative differences, then removes the private copy and
rechecks the admitted input bytes. Local recheck environment observations grant
no native or M2 evidence. The larger authority retains all eleven native cases,
341-package inventory, source/bootstrap/image, projection/reset/final-cache,
raw positive diagnostics and container name/full-CID/image cleanup predicates.

## Fresh TEST restaging

`adapter.execute` accepts only the independent phase result. It retains four
selected archive bytes, excludes the probe and creates a separate temporary
TEST primary. Frozen release semantics and all seven frozen client cases must
pass. Signed lineage retains the original role fingerprints, phase request and
receipt hashes, all fifteen phase entries and A's `REVOKED` authorization. It
never claims continuity with destroyed original B key material.

Signal transitions use authenticated corrected collector runtime `common.py`
`92ca41005397c6cccfd70497646c0de1f2ac88a697e0fcbec4165bf5326cfc08`.
Both handler installations/restorations are protected as a pair. Bounded owned
processes, private signer teardown, separate cleanup budget and descriptor-bound
publication remain mandatory. A cancellation or uncertain cleanup invalidates
the original authoritative output receipt.

## Required producer work

This directory supplies no accepted native authority. The actual repository
producer already records healthy signature statuses and command argv. Run
38259350917 retains all fifteen healthy stdout logs and hash-checkable source-derived
argv, but its public result stores argv hashes and renamed revocation paths. This
projection is insufficient for the preserved original raw receipt admission gates.
The coordinator must add a same-job bounded private handoff containing complete
raw repository receipts, the fifteen indexed healthy status observations,
revocation/import history, snapshots/reset/projection data and terminal aggregate
and public acceptance. It must record original full CID before launch and prove
both name and CID absent, as well as owned image cleanup. Current name-only
producer cleanup cannot be upgraded by this consumer.

Real immutable-base metadata and complete archive/build provenance must be
collected while their evidence is available; reviewed generic policy/license
approval is separate. After the actual terminal aggregate/export/cleanup gates
pass, generate the typed phase request and actual collector receipt and bind them
in a new externally pinned schema2 authority. Only then is this successor eligible
for a separately reviewed worker registration/dispatch. No CI, dispatch, workflow,
shared manifest or native producer source is modified here.

Local fixture tests deliberately model native/install/base/provenance observations.
Real ephemeral TEST signing, public phase verification, fresh restaging and client
commands are distinguished in the review record. Local tests cannot establish
accepted native handoff, M2/16K hardware support, installation, stable promotion,
production trust, endpoint publication or performance.

## Retained run observation

The local [observation](evidence/retained-public-38259350917.json) checks actual
run38259350917 public bytes with current-clock GPG: fifteen snapshot signatures,
A7 terminal revoked signatures and B8 terminal valid-at-observation signatures.
This is **PASS-public-signature-observation**, explicitly ineligible for native
admission. Source-derived native argv hashes and all fifteen original signature
packet facts match retained logs. No certification or raw native authority is
constructed from these observations.

The pinned collector's complete repository auditor fails on actual input:
fish/zsh `.PKGINFO` has `url = ` (`['']`), while repo-add omits `%URL%` (`[]`).
The [blocker record](evidence/retained-public-38259350917-blockers.json) binds the
twelve differences across six DBs. A separately reviewed optional-empty-URL
normalization or future package metadata correction is required. The held
collector and its source pins remain unchanged; mathematical signature success
does not bypass that repository attestation failure.

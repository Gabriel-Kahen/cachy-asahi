# Project TEST native-provider admission v1

This separately named successor interface starts at immutable Rust18 author
revision `8128cd73c85d533092d081f0b9131b2ca9893ecd`. Its official-only policy,
ALARM signer/keyring, Source367 inverse chain, actors and nine-probe qualifier
remain byte-for-byte unchanged. Project TEST packages cannot satisfy that path.
This family does not issue Root decisions, sign, fetch, install or dispatch.

`recipes.DATA.json` pins the original project recipes at combined revision
`fed5d7c97c3745f9b7dd6c3f0b64ad441c333e98`, separately from their upstream source
revisions. The finite candidates are `cachy-asahi-llhttp-reference 9.3.1-1` and
`cachy-asahi-libgit2-reference 1:1.9.7-1`. Their virtual provides satisfy ordinary
`llhttp`/`libgit2` dependencies; they are not ALARM packages. The allowed conflicts
are only those original names, which must be absent from the exact350 baseline.
The normal dependency solver and complete352 inventory remain mandatory.

## Explicit external selection

`admission.admit(source_root, policy_raw, policy_sha256, decision_raw,
decision_sha256, now=...)` consumes two independently selected canonical DATA
bodies. The caller must obtain both expected hashes through genuine trusted
Root custody. Hashing a received file or finding `issuer:Root` is not approval.

The policy is schema1/kind `PROJECT_TEST_NATIVE_BUILD_DEPENDENCIES_V1`, with exact
keys `predecessor`, `parent350`, `trust`, `packages`, `qualification`, `actual`.
`trust` has scope `PROJECT_TEST_ONLY`, a relative whole public-key reference,
full uppercase primary/signing fingerprints and `ALARM_authentication:false`.
Only a finite binary v4 public export is accepted; secret/encrypted/armor or
foreign fingerprints refuse. A project key never enters the ALARM allowlist.

Each of the two package rows contains its exact name/version/XZ filename,
original archive/signature whole pins, URL, observed eight-field package metadata,
complete library providers, `license_provenance` and `native` evidence. Actual
SONAME provides must come from the package; recipe or native-plan declarations
are not observed metadata. `license_provenance` retains:

- Immutable project recipe URL/revision, original PKGBUILD, complete recursive
  recipe-file inventory (including patches/support files where present), and
  unedited signed BUILDINFO with that PKGBUILD SHA.
- The exact pinned upstream archive/revision/checksum, required source license
  files, and identical regular0644 installed license payloads. Source archives
  authenticate via the recorded checksum, without an upstream-signature claim.
- Full package-scoped relative references under `dependency-provenance/NAME/`;
  no private keyhome, path alias, mutable revision or copied foreign recipe.

`native` contains exactly two `{provenance,validation}` whole-reference records
and a `comparison` reference. `native.py` reopens the complete original build
directories, requires native mode and ARM host/image identity, distinct clean
environments, full identical inventories/environment evidence, known normal
builder entry, complete recipe snapshots, archive/provider/BUILDINFO reports
and strict contents/PKGINFO/BUILDINFO/archive-byte pair equality. Host results,
plans, architecture declarations and an ELF header alone cannot satisfy it.

The external decision is schema1/kind
`ROOT_ACCEPTED_NATIVE_PROJECT_TEST_PROVIDER_TUPLES_V1`. Its exact keys are
`issuer`, `approved`, `scope`, `policy_pin`, `accepted_tuples`, `reviews`,
`issued_at`, `expires_at`, `Root_acceptance`, `release_acceptance` plus schema/kind.
It must explicitly accept each whole canonical package tuple and policy, with
native execution, clean pair, ordinary dependencies, complete inventories and
exact source-license-byte reviews true. Approval must be fresh and finite.
Global Root acceptance stays NULL and release acceptance false. Source/license
semantic review remains Root's responsibility; byte joins do not interpret law.

Selection admission returns `signature_mathematics_verified:false`. This is
deliberate: Root selection and native receipts cannot replace signature math.

## Verification, context and image component

`prepare_context(state, context, output, call, now=...)` rechecks the fresh
external decision and source bytes, uses a fresh public-only verification home,
then calls the caller's existing supervised `gpgv` interface for each detached
signature. There is no default subprocess, key import, key download or fallback.
The actual signer/primary, validity, expiry/revocation/error status and successful
exit are mandatory before archive parsing. The caller retains real command and
retirement evidence; a supplied callback is a trusted supervision boundary.

`archive.py` composes the unchanged BUILDINFO/metadata predicates and independently
enumerates every ELF/shared-library/alias provider. Undeclared ELF/static/libtool
providers, external/cyclic/dangling aliases, hardlinks, special nodes, hooks,
scriptlets or substituted license bytes refuse. Every alias ends at a declared
same-package regular ELF64 AArch64 shared library. Verified original inputs are
copied into a fresh context with exact complete352 inventory.

`image_dockerfile(state, original, verified_context, now=...)` requires that
verified context and the same fresh selection before returning DATA text. The
image component uses a distinct temporary TEST gpgdir/config, imports only the
selected public key, checks its full fingerprints and imports explicit scoped
ownertrust. It never signs or alters the baseline ALARM keyring. Normal Required
signature `pacman -U --noscriptlet`, `pacman -T`, fixed inventory comparison and
owned temporary-keydir cleanup remain. No `--nodeps`, sync, upgrade or trust-all
exception is added.

`image.observe`/`validate_observation` reuse the unchanged full ALPM/provider
ownership/mode/hash/alias and native `RTLD_NOW|RTLD_LOCAL` predicates, with new
TEST-specific schema/status and selected image/policy bindings. Both cap0 phases
and the nine original bounded natural-retirement CLI probes are checked by
`validate_qualification`. This is a dependency component only: it cannot replace
the complete Rust Root/pregrant/kernel/raw mount/volume/source qualification.

## Current state and use

All real operands in `UNBOUND.DATA.json` are unavailable. Native llhttp preparation
exists; no actual signed native llhttp tuple is supplied here. Libgit2's host
result/native plan is insufficient; its actual clean native pair is also UNBOUND.
There is no ready policy, Root decision, source identity, image or runtime result.

The family emits no Source and does not bypass Rust18's unavailable ALARM closure
or its unchanged full Source367 inverse. Future finite runtime/Source integration
must bind every new helper/input byte, preserve that complete inverse, wire this
distinct policy through both actual cap0 observations, and keep every existing
resource/authority/recipe/notices/108 hold. That integration remains unissued.

To inspect a genuinely supplied selection, use `admission.py --source-root DIR
--policy FILE --policy-sha256 EXTERNAL_SHA --decision FILE
--decision-sha256 EXTERNAL_ROOT_SHA`. Missing or unaccepted operands fail closed.
Do not pass `UNBOUND.DATA.json` as an admission policy.

Run each `test_*.py` separately with `-I -B -Werror::ResourceWarning` and adequate
explicit `TMPDIR`. Fixtures are synthetic DATA. Combined controls explicitly
model the native-receipt and cryptographic-call boundaries; their dedicated
controls exercise retained receipt/archive/observation predicates. No tests
authenticate a real signature, issue Root authority or establish native build,
load, package lifecycle, Asahi/M2, performance, legal freshness or release credit.

# Current onboarding staged inputs v3

Source implementation only. No Docker, native build, package execution, GPG,
network, signing, lease, publication, or Root grant was entered. Exact byte and
metadata joins do not authenticate Root or establish runtime/hardware acceptance.

API `CURRENT_ONBOARDING_INPUTS_V3` belongs to the new Source program descriptor
`programs.inputs_assembler`. The constructor/coordinator must include its exact
committed body and both validator entrypoints below. This increment
changes no constructor, owner, image, policy, Source packet, or shared manifest.
The fixture accepts only the committed `bc5df257` image body
(55783 bytes, SHA256 `f4e590532d7f6115f830215810f9dee5f2a1eb714351a9a7e572d22c5a255f90`),
whose context basis is `992cf5b2`. This increment changes no image/executor body.

```python
assemble_inputs(*, delegation_raw, delegation_sha256, source_root, request,
                output, context=None, context_program=None, now=None)
validate_hosted_inputs_v3(*, inputs, delegation, source_root)
validate_owner_inputs_v3(*, inputs, delegation, source_root)
stage_inputs(owner_inputs)
```

`assemble_inputs` verifies the external delegation hash before loading its pinned
context program, replays a supplied poststart context when present, and verifies
the entire closed Source through the maintained context program. It writes only
a fresh disjoint output directory: canonical `inputs.json`, `owner-inputs.json`,
operational `official-materials.json`, and a separate `assembly.DATA.json` report.
Source/proof bodies are not edited.
`context_program` and `now` permit bounded component controls; ordinary Root
integration leaves them unset. `template()` returns an unissued request with all
actual operands NULL. A missing actual operand raises `MissingInput`; there is no
download, implicit cache search, substitute package, or invented proof fallback.

The exact request keys are:

```text
schema: 3
kind: CURRENT_ONBOARDING_INPUT_REQUEST_V3
stage: backend | ui | lifecycle
source_date_epoch: actual nonnegative integer
base_lock: {path, bytes, sha256}
bootstrap_profile: {path, bytes, sha256}
base_materials: {exact filename: {path, bytes, sha256}, ...}
supplemental_materials: {exact fixed8 filename: whole_ref, ...}
keyring_materials: {exact original keyring filename: whole_ref, ...}
official_trust: {public_key: whole_ref, fingerprint, Root_admission: whole_ref}
test_trust: {public_key: whole_ref, fingerprint, Root_admission: whole_ref}
products: {required kind: product_refs, ...}
retention: NULL | {} | {prior_backend: whole_ref, prior_ui: whole_ref}
```

All path refs are canonical absolute ordinary single-link files. The held base
lock is fixed by its existing whole pin, with all165 rootfs records and248 package
records. Their actual union is341. The additional `bootstrap_profile` is pinned
to168201 bytes and SHA256 `2c42c705654d31e639f389f9a868dada0d9df76813d865e766be7b7c08f8404c`.
Both metadata operands and the exact349 baseline join the frozen Source factory
profile's original `parent_files` descriptors; the factory itself joins its
fixed whole pin and the verified Source map. No original lock is rewritten.
The eight supplemental names/versions/architectures must add to the original341
without replacing a package and reproduce the exact349 baseline inventory.

The five shared request/image fields are `base_lock`, `bootstrap_profile`,
`base_materials` (498 archive/signature refs), `supplemental_materials` (16 refs),
and `keyring_materials` (3 original public keyring refs). These517 operands have
distinct paths and exact frozen whole pins. Unknown and missing roles refuse;
all refs join the staged closure. `archlinuxarm-revoked` is deliberately zero
bytes with the empty-file SHA256 and must remain an explicit streamed operand.
The assembler streams their entire bodies;
it does not parse or execute their contents. The image actor retains its own
normal signed archive/PKGINFO/rootfs checks before ALPM, including actual native
identity and archive metadata. The assembler grants none of those runtime checks.

The entire original59 Source role set is resolved through the constructor's
fixed lowercase aliases; altered, missing, extra, or colliding aliases refuse.
Every alias joins its Source descriptor and immutable body. Official package
name/version/epoch/architecture/filename and archive/signature pins join the
Source catalogue, original materials table, and exact 23-package closure. The
operational table contains absolute references to those same Source bodies;
historical path strings inside original tables/proofs are never opened.
The expected inventory is independently reconstructed for backend350,
lifecycle372, or UI374, with no baseline replacement. Setup8 stays exactly
0.3.0-1 and the pinned payload/archive; current first-login stays 0.1.0-3.

The default selects exactly59 materials and preserves the original
`inputs/delegated-materials-v4.json` four-key schema and bytes. The opt-in
constructor extension instead selects exactly64: the original59 plus
`retained_carrier_profile`, `retained_prefill_profile`, `public14_profile`,
`staging_base_lock`, and `staging_bootstrap_profile`. The extra five live only
in `inputs/material-staging-materials-v4.json`, whose exact shape is
`{schema:4,kind:DELEGATED_MATERIAL_STAGING_SOURCE_MATERIALS_V4,materials:{...}}`.
Its descriptors must equal the whole-Source registry's `staging_materials` at
`scripts/ci/first-login-enrollment-native-source/successor_v4_source/program.json`
and the same five entries in Root's selected delegation. Every descriptor then
joins its verified Source member, actual whole body, fixed role/member/SHA256,
and mode0644. The lock and bootstrap sizes also remain exactly328101 and168201.
Missing tables, registry disagreement, omissions, unknown roles and cross-role
or original-carrier aliases refuse. Registry/table signals cannot silently fall
back to59. No staging capability, Root trust or acquisition is granted by this
material selection; the result's original-role projection still has59 entries.

Both public trust rows require separately issued, current Root trust documents
with the image API's existing `CURRENT_ONBOARDING_IMAGE_INPUT_TRUST_ONLY` scope.
The test key must be the exact retained Setup8 public certificate/fingerprint.
Its historical Root decision/proof bodies and archive/signature/key joins stay
unchanged. The module reads no host keyring or private TEST home. Explicit
public keyring operands are hashed as whole files without GPG authentication.
Root authentication
and selection of the whole request/staged document are external prerequisites;
an `issuer: Root` string is not independently authenticated by this DATA code.

Backend requires `products={}`. UI requires exactly `first-login`. Lifecycle
requires exactly `enrollment`, `first-login`, and `ui`; Setup8 remains a Source
material, not a generated product. Each product has exactly:

```text
archives: [whole_ref_A, whole_ref_B]
signature: whole_ref
Root_decision: whole_ref
Root_verification: whole_ref
producer_delegation: whole_ref
producer_context: whole_ref
pair: whole_ref
test: whole_ref
```

Products must have complete identical archive pins and current profile versions,
actual producer delegation/context selected by `private_stage_producers`, the
same Source/ref/attempt/map, actual numeric producer run/job, exact pair and
TEST-proof program/policy/nonce bindings, two natural retained TEST signature
receipts, and the separately Root-issued current signature decision/verification.
Current detached signature pins join both retained TEST receipts. With an actual
consumer context, producer run must also equal its run. Before that context
exists, no consumer run/job is fabricated; the real owner still joins actual
same-run product provenance after poststart. The source epoch is explicit and
never guessed from host time or a fixture.

The assembler returns the launcher's canonical wrapper:

```text
{schema: 3, kind: ROOT_STAGED_CURRENT_INPUTS_V3,
 owner_inputs: {image_inputs: {...}, stage_inputs: {...}},
 staged_refs: [{path, bytes, sha256}, ...]}
```

`owner_inputs` has exactly two keys, `image_inputs` and `stage_inputs`. It contains
no envelope fields, duplicate request, provenance, or invented authority fields.
Both trust rows live in `image_inputs`, including lifecycle's required TEST trust
for its signed stage. Original-role provenance, unchanged future provider IDs,
and unset final acceptance fields remain in the separate `assembly.DATA.json`
report, outside both callable schemas. All external/generated refs are
de-duplicated and sorted into `staged_refs`; conflicting pins, omitted refs,
extras, and unknown owner/image fields refuse. Source materials remain
authenticated Source members and are not included in the external staged list.

Only lifecycle requires `stage_inputs.retention`, with exactly the explicit
`prior_backend` and `prior_ui` public capsule references. Each is an external
ordinary `{path,bytes,sha256}` operand, capped at 64 MiB. It must be selected by
Root through the whole staged request/launcher-input boundary; this module
does not discover private paths or treat producer verdicts as selections.
Lifecycle NULL, missing, extra, or Source-relative capsule roles refuse. For
backend/UI, retention may be absent or an explicit empty object only. The
assembler hashes supplied capsule bodies; the pure validators declare both
refs in `required_refs`, and the outer validator requires both in `staged_refs`.
The launcher streams them before sudo. Hydration preserves those references
unchanged. Capsule authentication, semantic validation and public retention
remain the retainer's independent responsibility; no capsule PASS is invented.

The owner calls the separate pure
`validate_owner_inputs_v3(*, inputs, delegation, source_root)` with only the exact
inner object. This is the sole semantic implementation: it reconstructs the
request from canonical image/stage fields and the delegation's stage, then uses
the same planner. It reads the closed Source and bounded metadata/proof documents,
verifies the operational official table, and returns exactly
`{valid: True, required_refs: [...]}`. It starts no actors and writes nothing.
The launcher calls `validate_hosted_inputs_v3` with the exact outer envelope.
That function validates only envelope shape, delegates once to the inner
validator, and compares `staged_refs` with its returned complete closure. Inner
and outer arguments are not interchangeable; old overloaded shapes refuse.
It deliberately does not stream external rootfs/package/signature bodies: the
launcher must check every returned ref's complete size/hash, ordinary modes,
ancestry, and containment under its explicitly selected `staged_root` **before
sudo**. Hashing only `inputs.json` or trusting the declared list is insufficient.
The whole canonical staged wrapper itself must be pinned by the Root-selected
launcher request. A later byte change is rechecked by image/owner consumers.

Root's `run_owned_current_v3` adapter receives `owner_inputs` unchanged. The
necessary consumer calls are:

```python
inputs_assembler.validate_owner_inputs_v3(
    inputs=inputs, delegation=delegation, source_root=source_root)
image_report = image.build_stage(..., inputs=inputs['image_inputs'], ...)
private_inputs = inputs_assembler.stage_inputs(inputs)
# existing route/owner: inputs=private_inputs, image_report=image_report, ...
```

`stage_inputs` rehashes all actual generated refs and loads only bounded product
bodies, producing the existing delegated owner's byte ABI (`archives`, signature,
producer delegation/context, pair, TEST proof, Root decision and verification).
It keeps the JSON controller ABI free of embedded bytes. Image UI adoption uses
the same exact product refs with the unchanged context adoption callback. No
field or authority is renamed into Root issuance, final image qualification,
independent component acceptance, M2 support, performance or release acceptance.

Twenty-six small fenced controls pass on Python 3.12.14 and 3.14.7 with one isolated,
bytecode-disabled process per interpreter. They use explicitly fictional DATA
and call the actual committed image's `selected_inputs`, without executing its
actors. They cover all three compositions, current product hydration, pure
preflight with no writes, every-ref closure, missing trust/pair/body, stale
package/proof pins and versions, bad aliases/hardlinks/symlinks, expired trust,
strict JSON, and the launcher's required external streaming boundary.

The fixture uses an actual341-plus-fixed8 split, complete517 refs, and both
bootstrap provenance descriptors. Additional controls check every supplemental
and keyring ref in the outer closure, stale/missing/unknown operands, and the
pure validator's required deferred body checks. A separate permanently fenced
test feeds unmodified real lock/bootstrap/factory/inventory bytes to the actual
`base349_inputs` assembler seam, without inventing available archive bodies or
Root authority. All three compositions now pass the actual final image selector,
including its committed context schema/issuer/program-pin check for same-run UI
adoption. The context body is copied as inert Source DATA and never executed by
this fixture. `CACHY_CURRENT_INPUTS_IMAGE` can point to a disjoint copy of the
same final committed body; old/intermediate bodies refuse the exact pin.

The maintained assembler base seam also streamed a complete real517 handoff:
1,558,660,382 bytes, no missing files, and all identities stable through the end.
The evidence is `work/base349-provider/complete517-assembler-seam.DATA.json`.
This closes the earlier missing-file HOLD only. Current Root public trust,
GPG authentication, operational assembly, native image and hardware qualification
remain separate. No body was acquired or copied by this check.

The prior freeze pins were assembler41570 bytes,
`a1838fe056f95ae5baae5a70b9ba20a623271475160c9010ae59e3c751e90f9c`,
and its fixture39434 bytes,
`ee72d05d380caa6c49e7b0601a3ac641d55c352478f35d7d251f14c6a0dd6b8e`.
The local seam report is1573 bytes,
`ecfead82ee7c20a747b599f4d17425942ece0b33cd90f46f18008240a65b8fd0`.
The optional64-material join changes the assembler/fixture bodies; these prior
pins and the original676 evidence are retained as historical seam evidence.

The full517 handoff also exposes a launcher integration prerequisite: the
empty original revoked-key file must pass staged-leaf whole checking. The
currently reviewed launcher requires positive size for all refs and therefore
still refuses that genuine zero-byte leaf. Source/control documents remain
subject to their own positive-size requirements. This increment does not edit
the separately owned launcher.

```sh
python3 -I -B -Werror::ResourceWarning \
  scripts/ci/first-login-enrollment-native-source/payload/native/test_inputs_current_v3.py
```

## Explicit context-v4 selected products

The context loader still selects only the exact Source-relative descriptor and
whole body, and now checks its declared operation/delegation API version. It
accepts explicitly V3 or V4 identities; it never changes schema, issuer, tuples,
timestamps, or old workspace strings to make a v3 observation look current.
V3 products retain the original fresh-producer and same-run behavior.

The separate v4 route requires schema4, the exact pinned context program's
`ROOT_DELEGATED_CURRENT_ONBOARDING_PRIVATE_EXECUTION_V4` API,
`allow_pair_adoption:false`, and `allow_selected_pair_adoption:true`. A product
then has exactly this distinct reference shape:

```text
kind: ROOT_SELECTED_PRODUCT_INPUT_REFS_V4
selection_role: an exact key of Root's pair_selections, or NULL for pair_selection
archives: [whole_ref_A, whole_ref_B]
signatures: [whole_ref_A, whole_ref_B]
producer_delegation: whole_ref
producer_context: whole_ref
completion: whole_ref
pair: whole_ref
root_component: whole_ref
root_test: whole_ref
```

Every pin joins the consumer grant's explicit selected component. Name/version/
architecture come from the held recipe profile, including current first-login03.
Both detached signatures are preserved separately. Completion, producer tuple,
same Source/ref/map, original pair/program/policy/nonce, independent Root
component and TEST decision fields and current decision lifetime are checked.
The original producer delegation is not required to be a fresh execution grant:
its original complete bytes and expired timestamps remain historical. This path
does not run the v3 current-context validator on the old producer or renew it.

Before a genuine consumer context exists, hosted validation performs only this
read-only semantic/pin preflight. It does **not** claim the historical provider
replay or completed-component adoption succeeded. No consumer IDs are supplied
or guessed. The separate pure inner/outer validators and canonical wrapper still
apply; the launcher must stream every external required reference before sudo.

After actual capture, Root's adapter must call:

```python
receipts = inputs_assembler.adopt_selected_inputs(
    document=inputs, delegation_raw=delegation_raw,
    delegation_sha256=delegation_sha256, context=context,
    source_root=source_root)
```

This reselects the exact Source context program and calls its public
`adopt_selected_pair` with the original producer/completion/pair/decision bodies,
two real archive bodies, two signature bodies, and exact public TEST key.
Retain the returned receipts. They keep actual consumer and producer tuples
separate and explicitly require current-stage GPG; all final acceptance fields
remain unset. `stage_inputs(inputs)` preserves a distinct v4 byte ABI with
`root_component_raw`, `root_test_raw`, `completion_raw`, `signatures`, and the
explicit kind/selection role. It does not rewrite these decisions into the older
schema1 `Root_decision_raw`/`Root_verification_raw` shape.

The image's UI `pair_adoption` carries that same distinct reference object.
The final image has its own explicit v4 branch. Runtime consumers must use the
exact Source-selected context and its accepted producer-stage rules. This
assembler neither bypasses those rules nor converts a selected v4 proof into
the older same-run/schema1 path.

The focused controls now also cover v4 reference/decision omissions and stale
pins, unknown selected roles, forbidden v3 relabelling, preservation of expired
historical bytes and NULL consumer IDs, distinct signature bodies, and the
runtime callback argument/receipt shape. They do not fabricate a qualified Root
fixture. An earlier MODEL smoke used the actual context-v4 public API
with its original fixture, expired v3 producer and removed historical workspace;
the selected-product preflight and real context replay both passed. Evidence is
`work/current-inputs-context4/actual-context4-component.DATA.json` in this
worktree. It is component DATA, not actual Root authentication or native work.

The tests now pin only the `bc5df257` image listed above.
`CACHY_CURRENT_INPUTS_IMAGE` selects that exact file for local verification;
any other body refuses before import. Both Python versions were checked against
that image selector. This supplies no native image or Root authentication credit.

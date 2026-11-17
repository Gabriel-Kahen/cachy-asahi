# Unissued Source205 ONCE request planning

This local DATA generator produces one fresh `ONCE.UNISSUED.json` plan. It does
not issue Root authority, select an existing Source CID automatically, publish,
dispatch, query a service, acquire a lease, read credentials, install tools or
enter a native role. `once=true` and `retry=false` express intent; they do not
consume an operational ONCE token or enforce a live reservation.

All three selectors are mandatory CLI operands with no defaults or HEAD/ref
lookup: the published Source CID, its exact branch ref, and the independently
selected Main commit. The Source CID must differ from Source196's actual
`0a49872473251ad289fc8a49f51f3a27334c0b35`, the constructor commit and Main.
The generator requires externally whole-pinned public DATA for the unissued
Source205 profile, a normalized publication-readback projection and explicit
Main selectors. It validates their declared joins. It cannot authenticate a
receipt's issuer, prove publication remotely or verify Main Git contents.
Both publication and Main authentication remain `UNVERIFIED_DATA_ONLY`.

Only corrected constructor `9e26ce819a258225cac866341e15d7099038ab9e` and its
205-file,45962607-byte candidate are accepted: tree
`d7e48cbd6a3a638c5ecdabf8ca98a6a642dfde36`, map40793bytes/SHA256
`a6d22a528075c11f6fa2e87d894c41e0ed31befcd17f99a8b92d6c26fccdb815`.
Schema7, program pin, historical basis metadata,25 delegated roles and59+5
materials must match the contract. Historical Source196 metadata is retained
only as inverse DATA; it cannot become the selected Source or authority.

## Deliberate route HOLD

`dispatch_ready` is always false. The finite route HOLD is
`CANONICAL_MAIN_V7_LAUNCHER_AND_WORKFLOW_ADOPTION_REQUIRED`.
The existing native workflow invokes Main's canonical
`payload/native/hosted_current_v3.py`, which still contains the frozen v6 body.
The Source205 launcher also requires its executing Main body to equal
`Main/r['launcher']['member']`, where the Source registry requires that same
canonical operational member. Choosing only the new `v7/payload/hosted.py`
pathname does not satisfy those gates.

Therefore the Main selector DATA must describe a **future explicitly adopted
canonical member** with the exact v7 launcher body,68455bytes/SHA256
`d491626c309a4b0f1fc198fa1cc8515d2412326d0e4fb9947332590d9de0132e`.
The separate `provenance_operand` describes the new v7 pathname with that same
body. Frozen v6 pins and a new-path-only launcher refuse. The generator neither
claims that any supplied Main commit has adopted that body nor changes the
canonical member/workflow. Separate Root review, Main route adoption and actual
selector verification remain required. Legacy v6 remains available only through
its immutable old Source/Main selectors; none of its authority is inherited.

## Explicit operand formats

`--root-profile` is the complete canonical schema7 unissued constructor profile,
not a resource grant. The deterministic body is pinned to21451bytes/SHA256
`99198c00308780aaf95e803c43d01ab185b55a049731287b7644c2425dd90a12`;
the caller must also supply its whole SHA256 independently. This prevents
retargeting another descriptor roster while claiming the same Source205 map.
The required
normalized publication projection has exactly:

```json
{
  "schema": 1,
  "kind": "SOURCE205_PUBLICATION_READBACK_DATA_ONLY",
  "status": "PASS_COMPLETE_PUBLIC_GIT_READBACK_DATA_ONLY",
  "source": null,
  "ref": null,
  "tree": null,
  "files": null,
  "bytes": null,
  "source_map": {"bytes": null, "sha256": null},
  "profile": {"bytes": null, "sha256": null}
}
```

Nulls above are schema placeholders, not accepted values. Root must supply
independently selected readback DATA for the explicit published CID/ref, exact
Source205 tuple and whole selected profile. This worker generates no publication
receipt and makes no network verification claim.

The Main selector projection has exactly `schema=1`,
`kind=EXPLICIT_MAIN_REQUEST_SELECTORS_DATA_ONLY`, `commit`, and four closed
`{member,bytes,sha256}` descriptors: `launcher`, `provenance_operand`, `reader`
and `workflow`. Main's Reader member is the canonical
`payload/native/reader_current_v3.py`; the workflow must be an explicitly
selected `.github/workflows/*.yml` member. All descriptor paths include the full
`scripts/ci/first-login-enrollment-native-source/` prefix where applicable.
The launcher and operand members/pins are fixed as described above. Reader and
workflow bytes/hashes are required explicit inputs; they have no guessed default.

Example generation command, with every uppercase operand independently supplied:

```text
python3 -I -B request_generation/prepare.py \
  --published-source-cid PUBLISHED_SOURCE_CID --source-ref EXACT_SOURCE_REF \
  --main-commit EXPLICIT_MAIN_CID \
  --root-profile ABS_PROFILE --root-profile-sha256 PROFILE_SHA256 \
  --publication-readback ABS_READBACK --publication-readback-sha256 READBACK_SHA256 \
  --main-selectors ABS_MAIN_SELECTORS --main-selectors-sha256 MAIN_SELECTORS_SHA256 \
  --output ABS_FRESH_PRIVATE_OUTPUT
```

The inner launch uses schema3, the active delegated-context contract uses
schema4/`ROOT_DELEGATED_CURRENT_ONBOARDING_PRIVATE_EXECUTION_V4`, and the material
grant uses schema3. The generator follows the active context wrapper and its
patched `_CORE` validator, rather than the retained v3 text embedded in that file.
The outer plan and all three inner runtime-shaped templates retain null issuer,
approval, issuance/expiry, nonce and authorization. Image IDs, run/job and
acceptance remain absent. The launcher's canonical delegation JSON/hash, staging
selection and control name are unresolved. The generator never converts these
into approved live requests. Existing launch, delegation and staging validators
must reject them before actor entry. Root issuance is a separate operation.

Inputs are canonical duplicate-free JSON, regular single-link files, stable
across descriptor/path checks, capped at128KiB each and externally SHA256-pinned.
Output is capped at128KiB and written mode0600 in a fresh owned mode0700 directory;
an existing output is never adopted. Unknown keys, unsafe members, changed whole
pins, old schema/map/CID, wrong role counts and authority-bearing output refuse.

Twelve actor-fenced MODEL controls cover unissued output, required selectors,
Source196 refusal, profile/readback/Main joins, route gaps, malformed/capped DATA,
live-validator refusal and fresh publication of inert templates. Their synthetic
publication/Main claims are not genuine publication, adoption or Root authority.
MODEL profile bodies explicitly patch only the profile pin inside the test
scope. The literal production profile pin and self-rehashed descriptor refusal
are checked independently. Optional `test_prepare.py --genuine-profile ABS_PATH`
adds one check consuming the exact genuine unissued profile while keeping
publication/Main selectors explicitly MODEL and all authority absent.

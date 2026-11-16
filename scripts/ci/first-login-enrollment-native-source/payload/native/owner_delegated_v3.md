# Delegated private-stage owner v3 / route v4

Source implementation and fenced models only. No native actor, Docker, GPG,
network, lease, key, dispatch or publication operation ran. Old v1, bc47942,
current v2 and the Source139 packet are unchanged.

## Entries

The owner exposes `CURRENT_ONBOARDING_DELEGATED_OWNER_V3` and:

```python
run_owned_current_v3(*, delegation_raw, delegation_sha256, context,
    source_root, inputs, executor, output, public_output) -> dict
open_delegated_session(*, delegation_raw, delegation_sha256, context,
    image_report, executor, source_root, output, inputs)
launch_delegated_lifecycle(*, delegation_raw, delegation_sha256, context,
    image_report, executor, source_root, output, inputs) -> dict
```

The controller passes an existing empty owned0700 `output` root. The first entry
validates the shared inputs, calls the selected `image.build_stage`, executes
the backend/UI route or lifecycle outer launcher, then calls selected public
retention. It returns `completed=True` only after all three succeed. This is
private stage completion, never independent component or Root acceptance.
Retention failure remains HOLD. Completion contains public pins, not raw input,
launch, home, keyring, executor configuration or capsule bytes.

## Selected programs and policy

A genuine Root-selected schema3/V3 or schema4/V4 conditional delegation must name these Source-relative
whole descriptors in `programs`: `context`, `owner`, `image`, `image_executor`,
`owned_process`, `route`, `build_validator`, `local_callbacks`,
`inputs_assembler`, `retention`. Context/source/expiry/nonce/program/policy
checks are delegated to the pinned context program. `image.admit` independently
rechecks actual native owner/daemon identity, kernel limits, private endpoint,
PIDFD/deadline/storage facts and the actual executor code. Unknown predispatch
run/job/image IDs remain NULL; observed IDs are program facts, never Root-issued
image qualifications. Host preservation uses the selected image helper’s metadata-only trust
observation; host private key contents are not opened. Actual image inventory
and protected-state observations
must match; actor creation rechecks the real engine/image.

`local_callbacks` selects unchanged bc47942 owner body SHA256
`f1a91dee080f76eff88409dd1fe893dc45a2084338017f367ec9874a462a612d`.
Only its reviewed local `SignedSession`/supervisor/private trust body is used.
Its old Root admission, old build gate and signing-verification admission are
never called. Local configuration contains no issuer, approval, Root admission,
Root image qualification or synthetic future IDs. Whole helper pins and the
single invertible held ALPM import seam remain required.

The pinned policy additionally contains:

```text
private_stage.test = {fingerprint: UPPERCASE_PRIMARY, public_key_role: ROLE_ALIAS}
```

V3 same-run UI/lifecycle delegations explicitly authorize pair adoption. Their
`private_stage_producers` maps `backend` (and lifecycle's `ui`) to whole producer
delegation pins. The backend entry equals `pair_policy.producer_delegation_pin`.
These belong in later external delegations, not inside their own Source policy;
backend → UI → lifecycle selection avoids self-referential hashes. V3 producer
contexts remain strict and current; another run is never relabelled current.

V4 selects the whole committed context successor through the same Source API.
Set `allow_pair_adoption=false`, `allow_selected_pair_adoption=true` and supply
its exact `pair_selection` or `pair_selections` with the authentic Root
component/TEST decisions. `products[kind].selection_role` selects a multi-role
entry. The owner calls `adopt_selected_pair`, preserving original producer
identity, workspace and time; it then performs actual current-stage owned GPG
verification on both selected signatures. The module's independent Root
selection/completion/expiry/source-map checks are not duplicated or waived.
Context successor561c20da maps each exact selected component/version/architecture
to its backend or UI producer, including completed UI02 for lifecycle. This
supersedes the backend-only historical gate in282b7d4a; actual selected context
and producer checks still run at the external admission boundary.

All contexts and Source code are selected by exact descriptors. The owner emits
pair-observation schema/kind/issuer V3 or V4 according to the actual selected
producer context, with actual component/program/policy/archive/comparison pins.
It never claims Root issuance or final acceptance.

## Public input contract

The pinned `inputs_assembler.validate_owner_inputs_v3(inputs=inputs,
delegation=d, source_root=source)` accepts the actual unchanged inner
`owner_inputs = {image_inputs, stage_inputs}` object received from the executor.
It returns `{valid: True, required_refs: [{path,bytes,sha256}, ...]}` after the
shared semantic/Source checks. The launcher's separate
`validate_hosted_inputs_v3` accepts exactly the outer envelope
`{schema, kind, owner_inputs, staged_refs}` and delegates its inner validation
to the same semantic implementation. The owner calls only the inner validator;
there is no alternate program key, schema overload, duplicate semantic
validator or credential/path fallback. The stage fields are:

```text
stage_inputs = {schema: 3, kind: DELEGATED_CURRENT_PRIVATE_INPUTS_V3,
  source_date_epoch: INTEGER, setup8: {
  archive_role: ROLE, signature_role: ROLE, decision_role: ROLE,
  verification_role: ROLE}, products: GENERATED_PRODUCTS}
```

Static stage operands use aliases from the delegation's closed `materials`
table. Each resolves `{member,bytes,sha256}` through the actual Source root;
absolute filenames inside genuine Root proof bodies remain provenance and are
never opened. The owner passes the validated `image_inputs` object unchanged to
the selected image API. The assembler's `stage_inputs(owner_inputs)` hydrates
canonical serialized product references for the stage callbacks. There is no
parallel owner input schema or role-tree conversion. The owner does not rewrite
signed or original Source bodies.

Backend requires an empty `products` object and no future product archive,
signature or Reader selector. UI requires only `first-login` after
its actual pair and Root signature. Lifecycle requires `enrollment`,
`first-login`, `ui`, all under the Setup8-selected TEST primary.

For V3 same-run products, body fields are `producer_delegation_raw`,
`producer_context`, `pair_raw`, `archives` (two actual equal compressed bodies),
`signature`, `Root_decision_raw`, `Root_verification_raw`. The last two use the
authentic current TEST-only batch-sign decision/proof, not an owner-issued Root
statement. For V4 selected products, use the context API's exact
`producer_delegation_raw`, `producer_context`, `completion_raw`, `pair_raw`,
`root_component_raw`, `root_test_raw`, `archives`, `signatures` (both actual
bodies), and optional `selection_role`. No V1/V3→V4 Root-format conversion occurs.

The canonical owner object carries whole public references selected by the
shared validator for JSON transport. Its hydration function reads those exact
references and returns bytes and the producer context object to the internal
stage callbacks. No caller-selected arbitrary host path is opened. Actual
products are copied to bounded generated
observation files for the local actor. The authentic selected Root decision,
completion and pair bodies remain retained DATA. No key or signing authority is
delegated. Actual pair records are program observations with all final fields
unset/false.

## Actual execution and retirement

Backend350 builds Enrollment04 and CLI03 twice; UI374 waits for the genuine
Root-signed CLI03 input, then builds UI02 twice. Each actor runs the unchanged
normal makepkg entry script with checks, exact source snapshots, inventory,
epoch and fixed4CPU/4GiB/no-swap/512PID limits. Actual Docker create/inspect/
attach/terminal/remove/two absence receipts are retained. Each host command's
original receipt and separate stdout/stderr are saved, and the aggregate
`commands/commands.json` index is atomically updated. The final route report
captures the command list after session exit, including trust cleanup. The static validator
reuses the held package predicates through a pinned reversible import seam;
its decoder descendants belong to the real executor. Both Docker attach streams are retained; build.log is explicitly stdout
followed by stderr, with per-stream pins and no cross-channel ordering claim.
Actual held comparator
argv and complete compressed/metadata/content equality are required. No generic
build CLI argv is fabricated as an executed receipt.

Host trust retirement uses `no-agent-private-N` with actual expected exit2,
empty stdout and the exact separate stderr diagnostic
`gpg-connect-agent: no gpg-agent running in this session`. The original exit and
both channel pins remain in the command index. A zero exit, substituted stdout,
missing/changed stderr or uncertain retirement refuses and preserves the
private directory for scoped cleanup.

The lifecycle callback instance also adapts only its registered
`no-agent-private-N` command to expected exit2 through the unchanged held
supervisor. Its original combined-channel log, expected exit, natural retirement
and pin remain intact. No global/frozen callback or ordinary command expectation
is changed, and held private-retirement failure predicates still apply.

`observed_local_workflow(held)` supplies a per-owner `Commands` subclass around
the whole-pinned, unchanged held `Commands.run`. Before that actual invocation
it writes `<step>.invocation-request.json` containing the actual instance
timeout, monotonic deadline, output cap and argv pin. Its per-call supervisor
proxy writes `<step>.supervision-request.json` before forwarding the actual
`cap`, `retirement`, `grace` and `max_output` arguments. These are observed call
operands; no delegation limit is substituted for a missing observation.

After the held call, whole request-file/index readbacks and exact
argv/cwd/expected/output/supervision joins precede any enriched success receipt.
The original held receipt remains unchanged under `held_receipt`; its
`supervision.passed` value is preserved even when a legitimate expected exit2
has `passed=false` and the held command's `success=true`. Natural retirement and
the expected exit are checked separately. A missing hook, changed request/index,
unexpected result, forced retirement or unmatched exit refuses. Failed held
calls retain their original failure and request files, without invented bounds.

The enriched row exposes the actual scalar fields `timeout_seconds`,
`supervision_cap_seconds`, `retirement_seconds`, `grace_seconds`,
`max_output_bytes`, plus `local_invocation_v1` with schema1/kind
`DELEGATED_LOCAL_COMMAND_INVOCATION_V1`. That public-safe object contains
`request`, `request_pin`, `supervision_request`, `supervision_request_pin`,
`held_receipt_pin` and `supervision_result_pin`. It contains no raw argv or cwd.
The selected retainer/Reader must explicitly preserve and verify these fields;
the full private held receipt is not a public projection.

Lifecycle starts project-free372, uses one TEST primary for all four packages,
and materializes every detached signature at `<archive>.sig` for required normal
`pacman -U` signature discovery. The held local lifecycle performs two cycles,
actual payload ownership/stat/hash observations, installation-reason and all six
protected-state checks, and private trust retirement. It retains the held
lifecycle's private configuration policy; it does not claim an unrestricted
system-hook or target-machine lifecycle qualification.

Bash remains PID1 and owns its direct native root Python child. The local actor
checks actual kernel CPU/memory/swap/PID limits and the selected hostname. Source
and control material are RO; only a fresh empty output parent is RW. Local output
remains PENDING until actual outer CID retirement/absence, evidence retention
and private control removal finish. Failed entry/probe/launch paths retire only
submitted, inspected identities and retain HOLD; forced removal cannot pass.

## Public retention integration

The selected retention module must explicitly expose:

```python
retain_delegated_stage(*, stage, output, destination, source_root,
    delegation, context, image_report, stage_report, profile, inputs,
    executor) -> dict
```

Return `evidence_state='COMPLETE'`, `Root_final_acceptance=None`, a JSON manifest
and whole `capsule_pin`, with no independent/hardware/release acceptance. This
module owns its privacy projections, source selections and trusted encoder.
The owner does not copy a raw private tree or re-label v4 data as an older Root
route. The old retention v3 implementation has only the older `retain_stage`
interface/schema. The additive delegated selector was supplied separately in
`retention_delegated_v4.py` at c67f7f123a1100b810a0043ee137e8dda30881d8,
whole41534B/SHA256ac6536c1375de1ff63e0757201caf3202039bd25ed0b4c45208e4abedfdef438.
That body pins owner81d66ae5 as its selector basis; any new owner body requires
an explicit reviewed retainer-basis update by its author. Missing or old-only
retention refuses before image work. The currently selected image API must also receive a semantically validated
portable public input view, never unchecked legacy host paths or fabricated
producer signature observations.

Root final/component/hardware/release acceptance remains NULL/false in every
stage, context and completion. An independent matching delegated public Reader
and coordinator acceptance are still required; Reader1da96c5e continues to
match its original Root-grant route only.

## V4 selected-product body fields

For `allow_selected_pair_adoption=true`, each hydrated internal product supplies
`producer_delegation_raw`, original `producer_context`, `completion_raw`,
`pair_raw`, `root_component_raw`, `root_test_raw`, `archives` (two bodies),
`signatures` (two bodies), and optional explicit `selection_role`. These are the
actual committed context-v4 API fields. Canonical serialized products use the
assembler's whole-reference fields; its hydration function supplies these body
operands. Root decisions are retained unchanged under
`adopted/`; no schema1 Root TEST decision is manufactured from a schema4 one.
The selected Context performs its own historical replay and independent Root
decision joins. No caller-side timestamp, run or workspace relabelling occurs.

## Actual callback / actual retainer MODEL seam

`test_owner_delegated_retention_v4.py` loads the reviewed owner and route and
exact committed retainer4da93bf359d871bc0c4a8440edbb132f5572aab5, its fixture,
immutable pure reader and encoder. The retainer blob is43990B with SHA256
`677bd9c6c34e63352da017f4191e64d60a3e53f7cec25de3d6d861388265ba3a`,
verified from that commit. Each external helper has an explicit whole pin.
Supply an exported tree containing the four helper paths named in the test:

```text
python3 -I -B -Werror test_owner_delegated_retention_v4.py \
  --retention-source-root /absolute/closed-helper-source \
  --owner-sha256 4196aa414d7711a5e56c0a73f63282db712fffdfccdd9206e5b4e69f9605c7ad
```

The real owner callback, route, session entry/trust/GPG-receipt/probe, four
builds, two comparisons, exit, aggregate command indexes, real retainer
collection/manifest/public-tree writer and real encoder run. Source/context and
Setup8 authenticity, image construction and all executable results are declared
MODEL boundaries. No successful selector, retention predicate or encoder is
replaced. The minimal positive model omits optional makepkg log files; it proves
serialization joins, not a native build or an acceptable public artifact.

Four controls cover the generated callback evidence, genuine-index and separate
stdout/stderr pin refusals, actor-failure retirement with no completion, and the
realistic makepkg-log HOLD. The positive control also explicitly reproduces the
retainer's private image-inventory path leak; this is a known defect
characterization, never a privacy PASS. The retainer author must support normal
`artifacts/*.log` provenance roles and project `route.image.inventory_pin.path`
to a public member/whole pin or omit that nested private path. Owner provenance
and original report bytes remain truthful. Its fixed owner81 selector basis
also needs an explicit reviewed re-pin before this successor can be admitted.

`test_local_command_invocation_v1.py` separately exercises the actual held
`Commands.run` with modeled process/supervisor/signal boundaries, including
persist-before-supervise ordering, actual shrinking deadline cap, unchanged
expected2 `passed=false`, request/index/result drift and natural-retirement
refusals. These controls do not qualify real GPG, ALPM, native ARM or hardware.

Verification:53 controls (26 owner,14 route/static-validator,9 held-command
invocation,4 callback/retainer models) pass on Python3.12.13 andPython3.14.6
with `-I -B -Werror`, each under128MiB.
The validator controls are in `successor_v4/test_route.py`; there is no separate
`test_validate_build.py`. The local-retirement control loads exact held callback
and tool bodies for their pure command adapter and temporary-directory cleanup;
it does not invoke their actor or admission entries. Models perform no operational
or kernel qualification.

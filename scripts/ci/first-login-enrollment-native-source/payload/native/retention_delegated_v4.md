# Delegated private-stage retention v4

`retention_delegated_v4.py` selects public DATA from the committed delegated owner
`9fa3201a28d3981fd05013d4244fbb406739cbc5` and its separate v4 route. It preserves
the original delegation/context identities and whole report pins. It never
constructs old Root image/admission/runtime observations or runs a native actor,
GPG, network request, archive extraction, or private launch replay.

The owner calls the exact keyword-only API:

```python
retain_delegated_stage(stage=stage, output=stage_output, destination=public_output,
    source_root=source, delegation=delegation, context=context,
    image_report=image, stage_report=report, profile=profile,
    inputs=owner_inputs, executor=executor)
```

The entry point rejoins the closed Source and selected context, exact owner/route
basis, its own body, encoder, and the shared `inputs_assembler` program. It
requires the distinct `validate_owner_inputs_v3` inner-object API; an outer
hosted-envelope validator is not a substitute. A caller must already have
authenticated the external Root delegation pin. Hash joins are not Root trust.

The immutable pure reader/selector helpers are reused from
`payload/native/retention_current_v3.py` only after whole-body SHA256
`738360745901f1938be1e6a893ce45131c3f1f825421991522cfee3c66ed8c6a` matches.
That file must be an explicit closed Source dependency. The encoder is the
unchanged `scripts/ci/log_evidence.py`, SHA256
`a25f0089759c12afae3eea23bab8b22fa05cf5bbaa9eddc1611ce78b0405f8f5`.
The existing8MiB file,16MiB total,512-member,8MiB compressed caps remain strict,
including the new manifest. Cap overflow refuses rather than truncating evidence.

The distinct manifest has `schema:4`, kind
`DELEGATED_CURRENT_STAGE_RETENTION_V4`, issuer
`DELEGATED_RETENTION_PROGRAM_V4`, actual binding/nonce, delegation/context/image/
stage-report whole pins, selector basis, `files`, and `origins`. Member paths are
Source-relative or generated public names; original private absolute paths are
not copied into provenance. `Root_final_acceptance` stays NULL and independent
component/hardware/release acceptance stays false. `COMPLETE` describes selected
evidence only. Missing bodies, uncertain cleanup, non-natural supervision,
credentials, aliases, body drift, or incomplete pairs/lifecycle refuse.

Members contain:

- Original canonical delegation and context, plus public image/domain/route
  projections. Owner and aggregate daemon PID/start/cgroup/kernel limits remain
  observed facts with the unchanged2GiB/1CPU/256PID and6GiB/4CPU/768PID caps,
  swap0 and actual bounded storage. No independent image qualification is made.
  Where the selected image emits `base_input_provenance`, the additional
  `image/base-inputs.public.json` preserves its actual original341/fixed8/final349
  counts, factory/input-body pins, all257 consumed material records and their514
  archive/signature pins, filenames/source groups and metadata pins. References
  must match the canonical assembler image inputs exactly. Original host/staging
  paths are excluded; the whole original provenance-record pin is retained.
  This is a projection of emitted consumption facts, not a claim that original
  base archive bodies were included or independently qualified by retention.
- Selected UI image adoption receipts retain the actual context-v4 receipt and
  both current `verify-NNN` / `verify-selected-NNN-1` GPG streams. Each selected
  prerequisite also retains the original owner-written
  `adopted/KIND-selected-adoption.json`, rejoined to the canonical archive,
  signature, pair, completion, Root public decision and TEST key pins. Missing
  second status bodies or receipts refuse. These program observations never
  become independent component/image qualification.
- Public command indexes retain whole original receipt pins and natural
  supervision. Raw argv, mounts, launch manifests, tool paths, key listings,
  daemon/inspection/configuration bodies are excluded before opening their logs.
  Safe ordinary stage command bodies retain exact channels. Image command bodies
  are packed without loss into `streams/image/bodies-NNN.json`, kind
  `EXACT_PUBLIC_COMMAND_STREAMS_V4`: each row is `{step,stdout:{pin,base64},
  stderr:{pin,base64}}`. `body_frame` in the public command index selects the
  frame. Base64 is strict transport for original bytes, not a redaction or a
  rendered-log claim. This keeps hundreds of actual image GPG bodies inside the
  existing member cap.
  The same command-stream frame kind carries original local bytes as
  `{step,combined:{pin,base64}}`, preserving the actual combined-pipe contract.
  Actual local invocation request files are packed without change in
  `streams/LABEL/invocations-NNN.json`, kind `EXACT_LOCAL_INVOCATION_BODIES_V1`,
  schema1, with `rows:[{step,request:{pin,base64},
  supervision_request:{pin,base64}}]`. Each public command's `invocation_frame`
  selects those two original bodies. The public `local_invocation_v1` record
  joins request/argument pins, actual cap/retirement/grace/output-limit arguments,
  original held-receipt pin and actual supervision-result pin. Raw held argv/cwd
  is never copied. These frames keep the real frozen profile's hundreds of
  lifecycle commands inside the unchanged512-member cap; no requests/logs are
  silently omitted to fit it.
  The index envelope is `{schema:4,kind:"DELEGATED_PUBLIC_COMMAND_INDEX_V4",
  source,count,rows}`. `source` binds the original complete command-index body
  pin (owner/local), or the original image-report pin and literal `commands`
  field; both include the canonical original row-list pin. Each public row has
  its original ordinal/receipt pin, exact expected status, original
  `timeout_seconds` and `supervision_cap_seconds`, and observed supervisor
  `seconds`/`passed` alongside exit/reap/ownership/census/output/timeout/signals/
  error. Optional emitted forced-retirement flags are retained and must be false.
  Owner rows additionally join their original executor receipt pin and identical
  timing/channel observations. `body_frame` selects exact image stream frames;
  it also selects local combined streams. `body_members` selects retained owner
  stdout/stderr members.
  `exit`, `success`, `expected_policy` and `channels` are retained only when
  emitted: absent image `success` is never synthesized as true. The supervisor's
  `passed` means zero-exit success: an explicitly expected no-agent exit2 keeps
  its actual false flag while natural retirement, exact exit, elapsed bound and
  stream bodies are checked separately. The emitted supervision cap is the
  executor's command envelope bound; no unobserved inner timing or retirement
  argument is manufactured. Elapsed time must be finite and less than that
  bound, which must fit the emitted timeout and external delegation limit.
  Missing original pass/elapsed/bound observations refuse with specific
  `HOLD_MISSING_ORIGINAL_*` reasons. The immutable held
  `developer_workflow.Commands` body still emits no command-bound fields. The
  selected committed owner9fa adapter now observes the arguments at its real
  supervisor invocation, durably writes request bodies before delegating the
  original wait owner, and rejoins its original receipt/result. This retainer
  requires those actual observations and exact original request files for local
  commands. Old unwrapped rows remain HOLD; policy-derived limits and lifecycle
  exemptions are unavailable. Fenced tests model those emitted observations and
  independently refuse their absence or mutation; no native run is asserted.
- Backend/UI both complete compressed archives, original check logs with separate
  stdout/stderr composition, static validation, finite provenance outputs,
  recipe snapshots, comparison output, projected pair receipt, current-stage GPG
  status and natural actual CID retirement. Original pair receipt pins are kept;
  its private comparison argv is excluded.
- Lifecycle all four actual archives/signatures, original current GPG and package
  metadata, exact inventories and payload ownership/stat/hash/absence bodies,
  local trust retirement/restoration, natural outer command index/terminal/removal
  facts, plus both explicitly approved prior public capsules. No private keyring,
  signature configuration, launch tree, cache, storage tree or broad original
  stage walk is read.
- Original Source-role Setup8 dependency, signature, public key, public decision
  and verification, plus every explicit approved prerequisite product body.

Lifecycle transport additionally needs
`owner_inputs.stage_inputs.retention={prior_backend:<whole public reference>,
prior_ui:<whole public reference>}`. Both references must appear in the shared
validator's `required_refs`. No path is guessed. Product keys follow the committed
owner's explicit same-run or selected-pair mode. Selected serialized products
have kind `ROOT_SELECTED_PRODUCT_INPUT_REFS_V4` and keys `selection_role`,
`producer_delegation`, `producer_context`, `completion`, `pair`, `root_component`,
`root_test`, `archives` and `signatures`; both archive and signature lists have
two exact public references. The original serialized reference names from the
canonical inner-input validator are preserved. The owner's decoded transient
`*_raw` bytes do not replace their provenance. Complete original owner
`commands.json` indexes must match every selected command row.

The callback writes a fresh `delegated-STAGE-public-v4/` tree and its whole
`delegated-STAGE-public-v4.tar.gz` sibling under `destination`. It returns
`evidence_state`, `manifest`, `capsule`, `capsule_pin`, `capsule_path` and acceptance
fields. Only that newly generated public namespace is traversed by the existing
encoder. The whole capsule file survives the controller's public-output copy.

Fenced portable checks:

```sh
python3 -I -B -Werror::ResourceWarning scripts/ci/first-login-enrollment-native-source/payload/native/test_retention_delegated_v4.py
```

Tests exercise real selectors, generated manifests, filesystem bodies and the
actual immutable encoder with wholly synthetic package bytes. The external
Source-authentication seam is replaced only in explicitly marked MODEL end-to-end
controls; no actual Source, Root grant, GPG verification, native stage or Reader
acceptance is asserted. Unpatched bootstrap drift/alias refusals are tested.
Old v3 retention, Source139 and all old owners remain unchanged. A matching new
public Reader, inner-input transport/API and constructor registry selection must
be committed before this can form an actual complete delegated Source.

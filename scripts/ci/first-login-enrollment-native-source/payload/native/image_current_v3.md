# Current onboarding prerequisite image construction v3

Executable callback code, **not an operational result**. No Docker, GPG, sudo,
image, package, namespace, network, lease, private-key read or Root issuance ran.
Existing admitted Source packets and every old owner/route/Reader/constructor
remain unchanged. Root must admit and bind this new program in a fresh Source.

`build_stage(delegation_raw=..., delegation_sha256=..., context=...,
source_root=..., inputs=..., executor=..., output=...)` constructs exactly:

| Context stage | Complete expected image | Project prerequisites |
| --- | --- | --- |
| backend |349 + genuine Setup8 =350|Existing qualified Setup8 only|
| lifecycle |349 +23 official =372|None; project-free image|
| ui |349 +23 official +Setup8 +genuine current CLI03 =374|CLI03 pair, TEST signature and adoption after its actual build|

There is no candidate-signature bootstrap circle. Enrollment04/CLI03 are built
using350; UI waits for genuinely built/signed CLI03; lifecycle later receives all
four signed project inputs through the separate current owner. The image module
never signs a package, acquires inputs or issues independent image qualification.

## Root context, executor and resource contract

The module selects exact committed context-v3 or context-v4 bytes, binding the
program descriptor, Source body, module API, delegation/context schema, kind,
issuer and operation together. Both expose `validate_delegation`,
`validate_context` and strict same-run `adopt_pair`. The explicit v4 selected
route uses the separate `adopt_selected_pair` API described below. All consume
actual producer delegation/context and proof bodies, never future predispatch IDs. Context binds actual Source/ref/run/job/attempt1/map, stage and
nonce and remains explicitly provisional. Root delegation pins Source-relative
`programs.context`, `programs.image`, `programs.image_executor` and policy.
All actual Root approvals/selectors remain external; no grant is produced here.

The supplied executor is a **separately Root-reviewed implementation**, not an
unbounded default subprocess runner. It must be instantiated from the exact
pinned executor code. There is no fallback executor or resource-owner issuance.

- `executor.run(step, argv, timeout_seconds, expected=0)` returns
  `{stdout: bytes, stderr: bytes, receipt: {step, argv, expected, exit,
  output_pin, stderr_pin, supervision}}`. The two streams stay separate, each
  capped at1MiB and bound to its own complete pin. Parsers receive stdout only;
  ALPM failure detection checks each stream independently. Supervision must prove
  reaping, REAPED ownership, EMPTY_TWICE, complete output, exact expected exit,
  no timeout/signals/error. Every row is retained, including first failures.
- `executor.facts` contains API`CURRENT_ONBOARDING_IMAGE_EXECUTOR_V3`, exact
  binding/stage/nonce, whole code/domain-policy pins, actual native architecture,
  UID/GID/engine ID, exclusive nonce-specific Unix Docker endpoint, actual owner
  and daemon domain records, held daemon PIDFD, hard whole-owner/daemon deadline
  enforcement and actual kernel-enforced storage scope. The module independently
  reads native host/process/cgroup limits and the dockerd executable, and checks
  actual Docker architecture/cgroup/capability/engine identity before image work.
- Owner/daemon records contain actual PID/starttime/cgroup and finite
  `memory.max`, `memory.swap.max`, `pids.max`, `cpu.max`. Swap must be0. Exact limits
  equal the separately pinned policy; the domains must differ. No declaration of
  aarch64, default socket, CLI timeout or client AS substitutes for those facts.
- Storage facts must cover **all owner/context/daemon writes**, with actual
  kernel quota evidence retained by the executor for independent review. A free
  disk observation or cooperative Python counter is not sufficient.

Policy retains `context` and `stage_capabilities` as required by the context
program and adds `image_domains` (owner/daemon exact limit-file maps),
`image_endpoint_template` (nonce-specific Unix endpoint), `image_storage_bytes`,
`image_alpm_capabilities` and `image_steps`:

```json
{
  "verification_seconds": 60,
  "bootstrap_seconds": 1800,
  "stage_seconds": 180,
  "inspect_seconds": 15,
  "cleanup_seconds": 90
}
```

These are the held audit/bootstrap/current-stage caps, not a new180-second
bootstrap ceiling. Delegated max-command time must cover1800; its exact total
comes from reviewed Source policy. One monotonic whole-role deadline reserves90
seconds **inside** that total for cleanup; neither cleanup nor delegation expiry
renews new-work authority. At most512 rows are allowed. The normal actor remains
4CPU/4GiB/no-extra-swap/512PIDs. Root ALPM actors use only
CHOWN,DAC_OVERRIDE,FOWNER,FSETID,SETUID,SETGID,SETFCAP,KILL with cap-drop ALL;
no host PID/IPC/UTS/user namespace, devices, privileged mode, host mounts or
unconfined security option is permitted. Probe actors drop all capabilities.
The normal current build owner's separate admission limits remain unchanged.

## Exact input data and normal ALPM

`inputs.base_lock` whole-pins the held328101-byte `scripts/ci/inputs.lock.json`
(SHA beca39e0…); `baseline_inventory` is the held6800-byte349 lock
(SHA57998119…). `base_materials` maps the rootfs and each248 baseline archive
and their detached signatures by exact filename to `{path,bytes,sha256}`.
The rootfs is streamed/hash-checked and its complete165 package records must
match the held lock; the248 packages produce the exact original341 union, and
the separately pinned eight supplements complete the exact349 union. These
large public cache operands are explicit outside-Source inputs; this module
performs no download or secret-cache acquisition and cannot silently skip one.

`official_catalog` and `official_materials` select exactly the known23-package
transitive closure, including GTK's epoch and archive/signature pins. No349
replacement, package sync or implicit optional dependency is allowed.
`setup8` and `cli03` rows include name/version/arch, archive/signature whole refs,
source-bound payload maps, `Root_decision` and `Root_verification` refs. The
unchanged current profile whole pin binds Setup8's33900-byte archive/10 payloads
and CLI03's exact0.1.0-3/6 payloads. CLI02 is refused. UI additionally passes
`cli03.pair_adoption` references for `producer_delegation`, `producer_context`,
`pair` and `test` to the context program for the legacy same-run route. Both adopted archive pins must equal
this actual CLI03 body; adoption is not independent component acceptance.

`official_trust`, and `test_trust` only when project inputs are used, contain an
explicit public key whole ref, exact40-hex primary and current Root trust
admission. That Root document must approve the same certificate/primary for
`CURRENT_ONBOARDING_IMAGE_INPUT_TRUST_ONLY` with actual issue/expiry epochs.
Project Root package-specific TEST decisions/proofs must join archive, signature,
public key and TEST-only scope. Import/actual supervised GPG verification still
runs for every rootfs/archive; bad, unknown, expired or revoked status refuses.
Only public certificates enter two private homes, retired through the held
normal ALPM helper. No signing credential or private-key home is consumed.

A scratch seed Dockerfile contains only `FROM scratch` and `ADD` of the exact
signed rootfs. Its explicitly selected legacy build backend has no RUN and no
fallback to inferred BuildKit resource behavior. Actual normal ALPM runs in a
separate created/inspected/started native container. Configuration requires
package/local-file signatures and has no repositories. It performs only local
`pacman -U` with normal dependency checks, scriptlets and hooks. There is no
nodeps/nocheck, hook mask, `--noscriptlet`, privileged retry or inside-actor
network. Zero-exit hook/scriptlet failure diagnostics also hold.

The actor records full `pacman -Q`, actual `pacman -Qkk`, project owned-file
lists, root ownership/mode/size/hash observations and ordinary alarm UID/GID.
It retires public trust/input trees, then commits only that stopped owned CID.
The module inspects the immutable image and uses a fresh read-only ordinary
probe to re-read the actual complete inventory. Docker output/IID/inspect facts
supply every image ID; no expected image ID is fabricated.

Cleanup validates full CID/name/image/labels before removal, includes uncertain
creation discovery, removes only owned temporary images and checks absence
twice. A failed live actor can be stopped to recover ownership, but forced or
uncertain retirement remains HOLD. Primary failure and cleanup are separate.
Protected host observations use held snapshot helpers; protected GPG trust is
metadata-only, so no ambient private-key contents are read. Private namespace
collision never authorizes cleanup of someone else's directory or image.

Successful return is only `PROVISIONAL_CURRENT_IMAGE_CONSTRUCTED_DATA_ONLY` with
actual image ID/inventory/payload/command facts, no Root final acceptance or
independent image qualification. Only the target image is deliberately retained
for the separately qualified same-daemon handoff; job-local IDs are not assumed
pullable or durable. Root's independent Reader/coordinator must qualify it before
it becomes the350/374/372 input of an actual build/lifecycle admission.

## Verification

```sh
python3 -I -B -Werror::ResourceWarning scripts/ci/first-login-enrollment-native-source/payload/native/test_image_current_v3.py
python3 -I -B -Werror::ResourceWarning scripts/ci/first-login-enrollment-native-source/test_image_selected_context_v4.py
python3 -I -B -Werror::ResourceWarning scripts/ci/first-login-enrollment-native-source/test_image_base349_current_v3.py
```

Thirty-eight image MODEL controls, five genuine base metadata controls and
eleven real context API integration
controls pass on Python3.14.7, Python3.12.13 and Python3.12.14. The image executor
and tiny class-local archives, keys/statuses, IDs and receipts remain MODEL DATA.
The integration controls replay the actual committed context program on ordinary
fixture files; they exercise no native role. They cover all three exact inventory
shapes, normal actor/probe vectors, current payloads, delegated CLI adoption,
wrong/expired signatures, substituted Setup8/CLI02, hook failure with exit0,
resource/endpoint/storage/privilege mutations, uncertain creation, forced failure
retirement, collision nondeletion, first-failure preservation, protected-state
change, archive alias/hash refusal and finite JSON. They perform no Docker/GPG,
package execution, network, lease, Source freeze or Root issuance. Actual native
image construction, resource enforcement and qualifications remain NOT RUN.


## Versioned no-agent stream adapter

`retire_private_separated_v3` calls the byte-identical held tools helper. Its
callback handles only that helper's exact gpg-connect-agent no-autostart command.
It requests exit2, requires matching actual receipt/supervision exit2, empty
stdout, and the exact known diagnostic in separately pinned stderr. A versioned
receipt records source_stream=stderr and the callback-token pin; stdout's pin
remains the empty-body pin. This is an explicit projection of one validated
stderr diagnostic into the held helper's byte-token interface, not merged or
relabelled stdout. stderr is retained in `<step>.stderr.log` beside stdout logs.
Wrong exits, missing stream/pin, substituted bytes, unknown diagnostics and an
agent-present success response refuse. No actual GPG command was used to verify
an exit in these controls. The held tools hash remains
`eb1ff0ee8aefc2c0e32b38520e1bf0dabcbb9308081a24e2f9c378366a3cab13`.

The source prerequisite is c33861f1fea8c87755015ae1a2a751728de3a738, cherry-picked
separately into this worker branch. Integrate only the focused compatibility fix
atop the already integrated image prerequisite. No ALPM driver, inventory,
trust, payload, image-inspection, resource or Root grant checks were relaxed.


## Explicit context-v4 selected-product compatibility

The exact registered context bodies are v3 at author commit88ca3568
(21460 bytes, SHA256 efa5a2687ac1504ef565763ac0828dd6c98c593563df97b2f540ccf4e0de9d2b)
and v4 at author commit992cf5b2
(43482 bytes, SHA256 2d08f9572b3f5f89d3ebac2b32e6d41a00ff4929739c35780c7c96a1d3d3b21d).
External delegation authentication precedes program import. A matching label
alone cannot select a program. The Source map remains
`CURRENT_ONBOARDING_CLOSED_SOURCE_V3` and the executor ABI remains V3.

For a selected historical backend, `cli03.pair_adoption` consumes the exact
`ROOT_SELECTED_PRODUCT_INPUT_REFS_V4` object agreed in input-assembler author
commitae50567d. Its exact fields are `kind`, `selection_role`, `archives` (two
whole refs), `signatures` (two whole refs), `producer_delegation`,
`producer_context`, `completion`, `pair`, `root_component` and `root_test`.
All refs retain `{path, bytes, sha256}`. The first archive/signature and the
schema4 Root component/TEST refs must equal the effective cli03 row refs.
`selection_role` passes unchanged, including NULL for a single selection.
There is no conversion of authentic schema4 decisions into legacy schema1 proof.

Only a genuine schema4 consumer with `allow_selected_pair_adoption: true` and
`allow_pair_adoption: false` may take this route. The helper sends both actual
archive/signature bodies, all original historical/proof/Root decision bodies,
the current public TEST key and the explicit role to `adopt_selected_pair`.
The real context program replays the selected completed successful producer,
Source/ref/map, pair, component and decision pins. A historical v3 producer stays
v3; its expired grant is never renewed. A selected capability cannot fall back
to legacy adoption. The strict old same-run route and Setup8 qualification
remain separate and retain their original proof checks.

Both selected signatures require current-stage offline GPG verification against
the admitted current TEST primary. The existing expiry/revocation/status checks
apply to each, before any seed image or ALPM actor. The helper then replays all
selected operands and fresh Root component/TEST decisions again, and rechecks
current TEST trust expiry. Its immutable adoption receipt and both actual GPG
command-step references are retained in `selected_pair_adoptions_v4`. The
receipt's `current_stage_gpg_required` flag is preserved. No final, independent
component, hardware, release or image qualification is introduced.

The eleven integration controls use the byte-identical context-v4 fixture from
the separately committed prerequisite. They cover original v3/v4 completed
producers, a disappeared historical workspace, explicit role maps, every second
archive/signature and historical operand, component/key substitution, strict
Root decision expiry and unchanged V3 Source-map identity. Image models also
cover both current GPG calls, second-signature expiry, post-GPG Root decision
expiry, capability/fallback refusal and mismatched v3/v4 identity. No actual
GPG, Docker, ALPM, native execution, Root issuance, lease or network was run.
The input assembler must re-pin this new image body; its code is not edited here.


The explicit V4 basis was updated to author commit992cf5b2, replacing the older
42498-byte commit282b7d4a body rather than allowing arbitrary V4 implementations.
Both image and executor require the same exact 43482-byte program listed above;
the superseded body and any V4 body labelled V3 refuse before import. Exact V3
program bytes and schema/issuer selection remain unchanged.

The real API controls now exercise every reviewed component/stage mapping:
Enrollment04 and CLI03 originate in backend; UI02 originates in ui and may be
selected only by lifecycle. Both original V3 and V4 completed producers are
covered. The new real executor admission parser control constructs a closed
ordinary MODEL Source with actual context, image, executor and held supervisor
program bytes, then captures and validates the context without mocking the
registry, program loader, context validation or policy validation. Image admission
consumes that same real context; only its native/kernel observations are MODEL
values. These controls establish parser composition, not native resource
qualification or Root authority. Strict V3 admission is covered through the same
unmodified parser calls. No actor was launched.


## Original341 plus exact supplemental8 base consumption

The original 328101-byte lock is unchanged: 165 rootfs records and 248 selected
package archives yield 341 final names. Eight additional official packages
(cmake, cppdap, jsoncpp, libuv, meson, ninja, python-tqdm and rhash) bring that
base to 349 before Setup8 or the separate23-package desktop stage. They are
required in backend, lifecycle and ui. No package, version or dependency is
removed to make the inventory match.

Two mandatory image inputs extend the existing498-entry `base_materials` map:

```text
bootstrap_profile: {path, bytes:168201,
  sha256:2c42c705654d31e639f389f9a868dada0d9df76813d865e766be7b7c08f8404c}
supplemental_materials: {
  <each fixed supplemental filename>: {path, bytes, sha256},
  <each fixed supplemental filename>.sig: {path, bytes, sha256}
} # exactly16 entries
```

These use the names emitted by `BASE349_CACHE_REFERENCES_V3` at provider author
commit80fccbd3. The image accepts explicit whole refs only, with all514 base and
supplemental archive/signature paths distinct. Missing, extra, aliased or
substituted operands refuse. It neither searches caches nor acquires inputs.
Public current official trust remains a separately Root-admitted input; the
provider's three keyring operands do not replace that trust decision.

`base_inputs` verifies the exact Source factory profile62259 bytes / SHA256
ad874751a48cfd7e7d94f5d38d79caa138679be067cb113ead35150f0d3c78fa, then joins
its original lock, supplemental profile and expected349 parent descriptors.
It checks original341 names/versions, all fixed8 names, architectures and whole
archive/signature pins, no baseline replacement, and the exact final349 vector.
The new metadata refs are external operands; this does not rewrite Source139,
the original248 lock, the expected inventory or the project profile.

All256 selected package archives (original248 plus fixed8) use the existing
normal base ALPM transaction. Before a seed image, every body is whole-hashed,
every signature passes the same current official primary/status/expiry checks,
and actual signed PKGINFO must match name/version/architecture. The unchanged
driver uses normal dependency resolution, hooks and scriptlets, then checks
pacman-Qkk and the complete349 inventory. There is no dependency bypass or
masked scriptlet. The separate23 additions still produce372; UI still produces
374. `base_input_provenance` retains the original metadata refs, factory pin,
341/8/349 counts and all257 rootfs/package archive/signature refs with source
groups and per-row metadata pins.

Five unmocked metadata controls read the genuine lock/profile/inventory and
factory body, with deliberately unavailable MODEL archive refs. They establish
metadata composition only. The image MODEL controls cover all supplemental
GPG calls, 256-body staging, missing/extra/substituted refs, wrong provenance,
expired supplemental signature and refusal of an inventory omitting the8.
Existing actual context admission and v3/v4 compatibility controls remain.

An offline read of the provider's explicit retained operands independently
streamed all16 supplemental bodies (27037704 bytes) and verified their actual
PKGINFO identity, architecture and dependency metadata against the fixed
profile. The actual selector accepted the genuine Source139 metadata and
matched its exact372 lifecycle vector. Missing rootfs/signature refs in this
metadata-only exercise were explicitly MODEL/unavailable; no provider was
invented or marked complete. Its uncommitted checkpoint is
`work/image-base349-supplement/audit.DATA.json`. The rootfs, its signature and
three public keyring operands remain genuinely missing, so provider availability
remains HOLD. GPG, ALPM, image/native execution, resource qualification, Root
issuance, hardware and release acceptance remain NOT RUN/ungranted.

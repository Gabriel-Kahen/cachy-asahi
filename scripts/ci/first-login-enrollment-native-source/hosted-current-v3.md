# Delegated current onboarding hosted launcher v3

This launcher connects an externally Root-selected conditional delegation to the
owned executor's actual controller entry. It adds one manual workflow,
`.github/workflows/native-arm-current-onboarding-delegated-v3.yml`. It does not
issue Root grants, register/dispatch the workflow, acquire package inputs, install
host tools on the legacy path, or qualify an image. The opt-in prerequisite path below can install the one reviewed host prerequisite. No operational role has been run for this change.

The workflow accepts exactly two inputs: `root_request_json` and its independently
Root-selected `root_request_sha256`. The canonical request is capped at49152
bytes, leaving room within GitHub's aggregate dispatch input limit. Equality with
an input hash is not Root authentication: the existing Root once operator must
select and supply that hash. A self-asserted issuer field grants no trust.

The workflow body is published/registered separately by Root. It checks out the
request's exact Source commit at GITHUB_WORKSPACE and the separately selected
trusted Main commit. The latter checkout is moved outside the Source tree before
closed-source validation. Source/ref/GITHUB_SHA/GITHUB_WORKFLOW_SHA and all actual
hosted selectors must match the delegation; checkout does not fabricate them.
Root must select the exact registered workflow selectors in the delegation.

The concrete CLI is:

```text
python3 -I -B <trusted-Main>/scripts/ci/first-login-enrollment-native-source/payload/native/hosted_current_v3.py launch \
  --request /absolute/Root-request.json --request-sha256 ROOT_SELECTED_WHOLE_SHA \
  --source-root "$GITHUB_WORKSPACE" --main-root /absolute/separate/trusted-Main \
  --control-root "$RUNNER_TEMP/cachy-current-hosted-<64hex-nonce>"
```

The request has exactly these fields. All actual selectors below remain NULL;
this is a schema sketch, not an issued request:

```json
{
  "schema": 3,
  "kind": "ROOT_AUTHORIZED_CURRENT_HOSTED_LAUNCH_V3",
  "issuer": "Root",
  "approved": null,
  "trusted_main_commit": null,
  "launcher": {"member": "scripts/ci/first-login-enrollment-native-source/payload/native/hosted_current_v3.py", "bytes": null, "sha256": null},
  "delegation_json": null,
  "delegation_pin": {"bytes": null, "sha256": null},
  "staged_inputs": {"path": null, "bytes": null, "sha256": null},
  "staged_root": null,
  "control_name": null,
  "authorization": null
}
```

`delegation_json` is the complete canonical Root conditional delegation, not a
legacy runtime/image admission. Its programs require whole closed-Source
`context`, `owner`, `image`, `image_executor`, `owned_process`, `hosted_launcher`
and `inputs_assembler` descriptors. The context and all other programs/policy/
materials are validated by the actual selected context's closed-source API.
The executing Main launcher's whole body must equal the Source descriptor.
Held owned_process SHA256 remains
`83444522f4dfede67f6965ea75de8411b9e34510c04d40571fe439c223294e8f`.

The actual committed owner must declare
`API='CURRENT_ONBOARDING_DELEGATED_OWNER_V3'` and the exact keyword-only
`run_owned_current_v3(delegation_raw, delegation_sha256, context, source_root,
inputs, executor, output, public_output)` callback. Old qualified owners cannot
be substituted. The separately whole-pinned input assembler must expose:

```python
validate_hosted_inputs_v3(*, inputs, delegation, source_root)
# returns exactly {"valid": True, "required_refs": [{"path": ..., "bytes": ..., "sha256": ...}, ...]}
```

That validator receives the WHOLE four-field outer envelope and owns
package/proof-role semantics through its separate inner validator. It runs under a pure-DATA
write/process/network fence before any privileged entry. Its exact returned
references must exactly equal envelope.staged_refs, then are streamed whole, stable-FD checked and limited to closed Source
materials or the existing caller-staged private directory. Missing assembler,
callback, semantic input, authorization, body or descriptor is a preprivilege
HOLD. No old acceptance, future image ID or host-tool availability is inferred.

The externally pinned staged JSON has exactly:

```json
{"schema":3,"kind":"ROOT_STAGED_CURRENT_INPUTS_V3","owner_inputs":{"image_inputs":{},"stage_inputs":{}},"staged_refs":[]}
```

The two-key inner `owner_inputs` is passed unchanged to the executor/owner
callback. The committed owner81d66ae calls validate_owner_inputs_v3 on that
inner object; the launcher calls validate_hosted_inputs_v3 on the distinct outer
object. Unknown outer/inner fields, duplicate/omitted refs and mismatched pins
refuse. Root must supply
genuine signed349 cache/rootfs/bootstrap/public trust and package/proof inputs
through this caller-bound DATA file and ordinary bodies. The staging directory
must already exist, be owned by the ordinary runner and have mode0700. Up to1024
selected references,8GiB each and32GiB aggregate, are streamed within the180s
preflight bound. Private-home/keyring paths, aliases and private-key armor refuse.
This change deliberately adds no archive provider. A fresh hosted runner without
those staged bodies holds; an undeclared download or future image qualification
is not used to make it proceed.

On the legacy path, `authorization` must equal `jobs_metadata=true`, `privileged_controller=true`, and
`launcher_limits=hosted_current_v3.LIMITS`. This explicit Root selection covers:

| Launcher domain | Bound |
|---|---|
| Request / whole preflight | 49152 bytes /180s wall and180s CPU soft limit |
| Whole launcher / CPU hard ceiling | 7740s /7740 CPU seconds |
| Address space / core dumps | 512MiB /0 |
| Private control storage | 32MiB /128 nodes, plus64MiB and128 inode fresh reserve |
| Metadata query | exact context policy, at most30s and1MiB, one GET/no retry |
| Captured child stdout/stderr | 2MiB /sealed-size1MiB, separate pins |

The whole policy must join the selected context fields/stage_capabilities and the
executor777 image/domain policy. The launcher admits only controller512MiB,
CPU1,64PIDs,swap0 and RuntimeMaxSec7560. It invokes the actual executor controller
inside the exact fresh `cachy-current-controller-<nonce>.scope` with finite10s stop
and KillMode=control-group/OOMPolicy=kill. Root must explicitly select this same
policy on the legacy path; no old actor cap is widened. The explicit prerequisite timing successor below uses a smaller actual controller runtime within the same 7560-second budget. The executor itself observes the actual
controller cgroup/kernel limits, scope runtime and activation clock before setup.
Its separate2GiB owner and6GiB daemon aggregate domains, private endpoint,
allocated storage, original PIDFDs and owned cleanup remain unchanged.

All Git/sudo/systemd/Python actor arguments are direct argv. The metadata child
uses one fixed public GitHub jobs URL, HTTPS/no redirects, minimal environment,
no token/authorization header, and no header retention. Actual allowlisted
GitHub fields plus the complete bounded public jobs body feed capture_context.
Future run/job IDs and image IDs remain NULL before that genuine observation.
The root controller wrapper converts cancellation into Python's existing finally
cleanup path rather than bypassing executor cleanup with default SIGTERM.
Success requires natural held-child/group retirement, actual controller success,
owned storage absence and two final empty/absent scope observations. A forced or
uncertain result remains HOLD. No arbitrary unit is stopped or adopted.

On the legacy path, only `public/context.json`, `public/controller-observation.json` and
`public/launcher-report.json` are uploaded for3days. The opt-in path additionally selects only public timing, prerequisite and refreshed-context receipts described below. The selected controller
observation keeps actual PID/start/cgroup/kernel limits, finite scope runtime and
activation clock; it carries no acceptance.
Request/delegation/input launch DATA, raw stdout/stderr, environment, credentials,
keyrings and arbitrary owner outputs are excluded. Root final, independent,
hardware and release acceptance remain NULL/false in selected receipts.

This is one selected stage per Root request. V3 pair adoption retains its exact
same-run producer constraint; external staged UI inputs cannot relabel a previous
run. A genuinely versioned cross-run context successor must be selected explicitly
and supported by its matching executor/owner. The launcher selects context by
whole descriptor/API and does not impersonate v3. Source/executor/owner/assembler
closures, actual staging, prerequisites on an actual runner, workflow registration, Root runtime/
resource grants, actual dispatch and acceptance all remain independently open.

Validation uses30 fenced tests with the explicit three-blob public donor fixture
(26 without that optional fixture) on Python3.12.13 and3.14.7, temporary MODEL programs
and DATA bodies, mocked metadata/process/scope operations and syntax checks. The
3.12 build lacks memfd constants, so stderr primitives are explicitly modeled in
those controls; no qualified runtime fixture is claimed. No HTTP, sudo, systemd,
Docker, GPG, lease, native build, publication or dispatch occurred.

The integration regression pins canonical assembler commit
`2a5e0ebeaa48c19237ecf716a87d4261e82de9c3` (program SHA256
`a1838fe056f95ae5baae5a70b9ba20a623271475160c9010ae59e3c751e90f9c`)
and its committed tiny MODEL fixture (SHA256
`8762a4160da6dbbbba4c3e5845d773c233fd334512fcc069e04ecedc6468ba45`).
The actual assembler generates the canonical wrapper and both real validators
run before the launcher streams every selected body. Only the original fixture's
MODEL catalogues/context are parameterized; no replacement validator is used.
The fixture contains tiny inert341-base plus fixed8 bodies and supplies no native/Root credit.
The actual fixture's zero-byte `archlinuxarm-revoked` public file is included in
the exact semantic reference join and streamed as an ordinary stable-FD leaf.
Only explicitly declared DATA under the caller-staged domain outside Source may
have length zero, and its SHA256 must be the standard empty-file hash
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
Source descriptors, Source-relative materials, programs, control/request files
and staged wrapper JSON retain their existing positive-length requirement.
Absent, changed, extra and incorrectly pinned empty leaves still refuse. These
controls use the exact committed assembler and MODEL fixture, not a matching
replacement validator or private provisional image implementation.
After 2a5e0ebe is integrated, the normal repository-local test command needs no
private cache or historical Git object. In an older isolated base, set
`CACHY_CURRENT_INPUTS_FIXTURE` to a whole-pin-checked export of that committed
`payload/native/test_inputs_current_v3.py` with its same-commit assembler/image
and `successor_v2/profile.json` siblings. This permits dependency testing without
copying or changing another worker's maintained files. Reader code is unchanged
and never executes these Source programs.


## Opt-in host prerequisite with a shared 7560-second deadline

This increment wires the committed `ac4dc53d` helper before the complete tool
preflight. It adds no workflow, executor or constructor edits. An absent or false
`capability.allow_host_prerequisites` preserves the strict legacy path: missing
bsdtar refuses before privilege, there is no implicit APT, and the old lifetime
requirements remain unchanged. A present non-boolean selector refuses.

The opt-in Source requires four additional explicit whole-program descriptors:

| Role | Required committed body |
|---|---|
| `host_prerequisites` | `payload/native/host_prerequisites_current_v3.py`: 13750 bytes, SHA256 `521163f6f9504edaa573fa079751d7714065bea2ceef69428e8bc7585e361daa` |
| `host_prerequisite_plan` | Fish013c plan: 13845 bytes, SHA256 `4bef653f0e999876e8dd1e74e7d61b808182f7528f4f50ce6444e14f6ff33d64` |
| `host_prerequisite_tools` | Fish013c tools: 5273 bytes, SHA256 `5f980d2df87cebdf264167e7be7220485a6fcc555667782d31316da0d08aef72` |
| `host_prerequisite_runner_basis` | Fish013c runner basis: 31464 bytes, SHA256 `7f4d2a68f13a2439a4363cfb154553dc9e721a88dc985080dd290d44583ad634` |

The existing context/owner/image/image_executor/owned_process/hosted_launcher/
inputs_assembler/policy/material closure remains required. Source-relative member
names are constructor-selected and their complete bodies must match these pins.
No uncommitted donor or arbitrary frozen Source is imported. The executing Main
launcher must still equal its exact updated Source descriptor.

Root must separately select all three opt-ins: capability
`allow_host_prerequisites=true`, `policy.host_prerequisites_current_v3` equal to
the helper's `PROPOSAL`, and `policy.host_prerequisite_timing_v3` equal to the
launcher's `TIMING`. The latter is the explicit new timing proposal:

```json
{
  "kind": "CURRENT_HOSTED_SHARED_7560_PREREQUISITE_TIMING_V3",
  "whole_budget_seconds": 7560,
  "charge_preflight_and_prerequisites": true,
  "allow_clipped_stage_window": true,
  "metadata_queries": 2,
  "controller_retirement_reserve_seconds": 15,
  "Root_acceptance": null
}
```

The request's existing exact authorization object additionally requires
`host_prerequisites=true` and `whole_timing=TIMING`. No top-level request field or
workflow input is added. These are proposed contract values; actual approval,
Source/Main pins, resources, runtime, nonce and dispatch selectors remain unissued.
Root's external whole request hash remains mandatory. The helper policy's
495-second physical scope is charged within this timing proposal, not added to
the old whole budget. Both timing and helper selection are required; neither
implicitly grants the other.

Before any privileged entry, the actual assembler/staged-body validation and all
Source/owner/delegation checks still run. Only bsdtar may be missing. The launcher
captures actual poststart context through the first fixed public bounded jobs
GET, then creates hash-pinned `timing.json` with the actual request/delegation/
context/policy pins, same-boot pin, launcher-start monotonic time and absolute
monotonic deadline. The deadline is the earlier of launcher-start+7560 and actual
Root expiry. A process alarm also bounds the remaining launcher work, including
fresh tool hashing and metadata after prerequisite retirement, to that deadline.
The initial preflight remains bounded to180 seconds.

The exact fresh prerequisite scope is
`cachy-current-prerequisites-<nonce>.scope`, with RuntimeMaxSec495, MemoryMax512MiB,
swap0, CPU1,64PIDs, finite10-second stop and control-group/OOM killing. The launcher
rejoins fresh root-owned `/usr/bin/systemd-run` and `/usr/bin/python3` observations
and the fixed sudo body before entry. All arguments are direct argv. Its root
`prerequisite` mode revalidates Root request/Source/context/timing and the selected
helper, sets AS512MiB/CPU500/core0, then calls the **actual** pinned helper with the
allowlisted actual public environment and owned `/var/lib/cachy-current-prerequisites-<nonce>`
output. The helper observes its real kernel domain/runtime and executes its nine
normal signed APT commands. No fake preexisting-tool observation is inserted.

Only natural held retirement is accepted. The prerequisite cgroup must then be
actually absent twice within ten seconds and the shared deadline. Only after
that does the launcher observe and require all sixteen tools, rejoin scope tool
identities, and perform a second fixed bounded public jobs GET to refresh the
actual context without changing Source/ref/run/job. There are exactly two metadata
queries on this selected path, with no redirects, retries, token or header
retention. Private environment/launch DATA is not uploaded.

The main scope's RuntimeMaxSec is floor(actual remaining shared time)-15, never
7560 after consuming prerequisite time. The root wrapper independently observes
its physical scope's activation/runtime and refuses if its physical end exceeds
the hash-pinned shared deadline. Executor777 already accepts a smaller actual
runtime and clamps its work and cleanup deadlines accordingly. Policy
`stage_seconds=7200` remains the maximum; the available stage window is smaller.
`launcher-report.json` records actual elapsed time and prelaunch controller/stage
ceilings, not a claim that the full7200 seconds remained. Insufficient remaining
setup/work/cleanup, expired Root authorization, stale context, extended/tampered
scope or timing, missing inputs/tool/helper/descriptor, forced retirement and
uncertain cleanup all HOLD. No7560-to8055 relabeling occurs; old actor/domain/
recipe/semantic limits are not changed.

Selected additional public files are `timing.json`, `host-prerequisite.json` and
`context-after-prerequisites.json`, plus bounded observations in the existing
launcher report. They carry no Root/independent/hardware/release acceptance. Raw
APT command streams, cache, private environment, keyrings, credentials, launch
request/delegation and owner outputs remain excluded. The helper's installed host
package remains on the disposable runner; its own cache/log cleanup is checked.

Fenced tests add actual committed-helper loading and pinned Fish donor controls,
legacy missing-cap refusal, strict dependency pins, actual-helper resource refusal
before actors, exact scope argv, scope absence, second-context refresh, actual
elapsed495-second charging, clipped physical runtime checks, Root-expiry and
same-boot/timing tamper refusals. Set `CACHY_HOST_PREREQUISITE_FIXTURE` to the same
three public code-only blobs described in `host-prerequisites-current-v3.md` to
exercise the four actual-helper integration controls. The other new controls need
only the checkout. Existing real-assembler fixture controls remain unchanged.
Actual Source construction/integration, Root review/resource/authorization,
genuine caller-staged input delivery, workflow registration/dispatch, real host
prerequisite installation, native execution and acceptance remain NOT RUN here.

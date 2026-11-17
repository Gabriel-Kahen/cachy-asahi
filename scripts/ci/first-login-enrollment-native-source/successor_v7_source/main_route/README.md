# Source205 Main route and external Root ONCE DATA contract

This family checks a complete future Root-supplied case. It creates no issued
case, admission, runtime observation, registration/readback proof, request,
credential, lease or workflow run. The three JSON files are unissued templates:
issuer, approval, issuance/expiry, Source CID/ref, Main CID/tree, workflow ID,
stage, nonce and runtime observations remain null wherever unresolved. Source205
has no CID default. Source196 and constructor CIDs cannot substitute for a
published Source205 selector.

Unlike the older unissued request planner, `qualify` has a fully bound positive
path. Consistent independently selected Root operands produce
`DATA_CONTRACT_QUALIFIED_FOR_EXTERNAL_ROOT_OPERATOR` and
`ready_for_external_root_operator=true`. This is DATA consistency only:
`Root_authentication=false`, `lease_observed_here=false`, `POSTs=0`, no native
entry or acceptance. An issuer string and matching input hash do not authenticate
Root. The actual Root operator must independently choose the expected pins and
enforce its custody/authority boundary; deriving those pins from untrusted input
does not establish that boundary.

## Exact route and Source

The Source205 constructor and closed Source remain unchanged: constructor
`9e26ce819a258225cac866341e15d7099038ab9e`,205 files/45962607bytes, tree
`d7e48cbd6a3a638c5ecdabf8ca98a6a642dfde36`, map40793bytes/SHA256
`a6d22a528075c11f6fa2e87d894c41e0ed31befcd17f99a8b92d6c26fccdb815`, program
15135bytes/SHA256
`623f667137fd38d9c319de729df910780fbf0fae7c0bc7e2aade27889c102dae`.
The complete unissued profile is21451bytes/SHA256
`99198c00308780aaf95e803c43d01ab185b55a049731287b7644c2425dd90a12`.
It binds all25 program and64 material descriptors; requests cannot retarget a
stager/helper while retaining only the claimed Source map.

The canonical Main launcher member must contain the exact frozen v7 body:
`scripts/ci/first-login-enrollment-native-source/payload/native/hosted_current_v3.py`,
68455bytes/SHA256
`d491626c309a4b0f1fc198fa1cc8515d2412326d0e4fb9947332590d9de0132e`.
That member agrees with both the existing closed native workflow and the
launcher's executing-Main/body predicate. Merely selecting the new provenance
operand pathname does not satisfy the route. Main adoption is a separately
reviewed narrow copy; this DATA module does not perform it or alter Source205.
Old published v6 Sources remain bound to their immutable old Main selectors.

The unchanged workflow is
`.github/workflows/native-arm-current-onboarding-delegated-v3.yml`,8949bytes/SHA256
`4aaa31fae8b6665d502372467d3da5ceef0bb30553d2dfb1ac9f38a41fc90165`.
Its registration ID is an explicit Root operand, never guessed. The chosen Main
Reader requires a finite positive whole-body pin and the declared
`SOURCE205_FINITE_TRANSPORT_V2` contract. No Reader/source code is imported from
an unqualified input.

## API and independent inputs

```python
result = contract.qualify(
    operands, expected_pins, now=explicit_epoch,
    core_raw=exact_frozen_v7_launcher_bytes,
    profile_raw=exact_unissued_Source205_profile_bytes,
)
```

Both dictionaries must contain exactly `case`, `admission`, `runtime`,
`registration`, `readback`, `once` and `request`. Operand values are canonical,
duplicate-free JSON bytes. Every expected pin is independently supplied as
`{bytes,sha256}`. The case anchors all six other pins without a self-hash cycle;
the case's own pin comes only from the external caller. Each ordinary operand
is capped at128KiB; the live request at49152bytes. The explicit integer `now`
is the only clock. The function performs no filesystem, lock, process, Git,
network, credential or wall-clock operations.

All six Root proof kinds use integer schema1, `issuer=Root`, `approved=true`
only when supplied in externally selected bytes. The templates never fill
those values. The schemas are closed and do not accept arbitrary proof fields:

- **Case — `ROOT_SOURCE205_ONCE_CASE_V1`:** Source205 CID/ref and exact
  tree/map/program/profile; distinct Main CID/tree and canonical launcher,
  Reader and workflow descriptors; workflow ID; case ID, operation, group,
  stage, nonce, issuance/expiry, canonical lease identity, resources and six pins.
- **Admission — `ROOT_SOURCE205_ONCE_ADMISSION_V1`:** exact case identity
  binding, issuance/expiry, identical fixed resources and a Root-held reservation
  with zero active/pending, matching group/operation and no exemptions.
- **Runtime — `ROOT_SOURCE205_ONCE_RUNTIME_V1`:** the same case binding,
  issuance/expiry, complete lease identity, custody and two metadata sweeps.
- **Registration — `ROOT_SOURCE205_WORKFLOW_REGISTRATION_V1`:** case binding,
  observation epoch, repository, positive workflow ID, exact path/body pin and
  active registration state.
- **Readback — `ROOT_SOURCE205_READBACK_V1`:** case binding, observation epoch,
  exact Source and Main projections, fixed profile pin, complete publication and
  Main-adoption claims. These remain external claims, not observations here.
- **ONCE — `ROOT_SOURCE205_ONCE_GUARD_V1`:** case binding, observation epoch,
  once/retry flags, empty prior run IDs/intents, no uncertainty or prior POST,
  `BEFORE_POST`, fresh/exclusively reserved output, exact runtime and request pins.

`binding(case)` supplies the exact shared case ID/Source/ref/map/Main/operation/
group/stage/nonce projection. The functions and templates declare every field
name. Case/admission/runtime windows must be fresh and at most7560seconds;
admission/runtime cannot outlive or precede the case window. Registration,
readback, ONCE and both sweeps must be no more than120seconds old.
The final `BEFORE_POST` observation cannot predate admission/runtime issuance,
either sweep or registration/readback observation. A collection of individually
fresh inputs does not satisfy the final guard if their causal order is reversed.

## Runtime and request constraints

The canonical lease pathname is fixed. Mode0644, single link and size0 are
invariants. Root must independently select the current full device/inode,
owner/group and nanosecond timestamp tuple in the case. Templates leave those
values null. No historical runtime54 inode/device/timestamp is adopted as new
authority. Runtime's lease, held-FD and pathname identities must exactly equal
that case identity. Held FD and owner PIDFD must be distinct valid descriptor
numbers; owner PID/starttime, alive/starttime/PIDFD checks, independent
nonblocking contention and lock-held proof must be explicit. Release is
`CLOSE_ONLY`. No descriptor is opened or inspected here.

Exactly two independently identified censuses must enumerate all five live
statuses with complete pagination and all-job metadata. Their run/job/source/
attempt/status/workflow/body identities must converge, ignoring ordering.
Appearance, disappearance, movement, unknown classifications and conflicts hold.
Only explicitly classified automatic X64 `LIGHT_OTHER` rows may coexist.
ARM64, heavy, native/kernel, same group/operation, selected workflow/Source,
unclassified jobs and empty job censuses hold; no lane or actor exemption exists.

Resources bind the Source205 policy pin, exact launcher limits/shared timing,
stage/context limits and physical scope limits. They do not change the Source
policies. The request must already be independently Root-issued schema3 launch
DATA containing schema4 active-context delegation, schema3 material grant and
whole-pinned canonical assembler selection. Source/Main/stage/nonce/policy/
clocks,25+64 descriptors, finite capability/resource fields and hosted selectors
must all join the case. Unknown images/run/job, extra fields, old Source196
authority, retargeted descriptors and expanded capabilities refuse.

The exact frozen `Core.request` predicate is compiled unchanged with its nine
pure helper predicates and two literal resource declarations. Its single read
uses a bounded in-memory adapter. Imports/loaders/operational entries are not
compiled, and production globals are not patched. This validates request DATA;
it is not a runtime file/Source/privilege attestation. The unchanged native
launcher still performs its actual Source, Main, host, input and custody gates.

## External operator handoff

A qualified result preserves the supplied request bytes unchanged and returns
the registered-workflow direct argv, canonical dispatch body and exactly two
workflow inputs: `root_request_json` and `root_request_sha256`. These are code
and DATA for Root's existing ONCE operator; this family contains no POST/send
implementation. Root must rejoin actual current lease, admission, live census,
Source/Main readback and whole request immediately at the POST boundary.
Qualification is neither a consumed ONCE token nor an excuse to reuse stale DATA.

An uncertain outcome, prior intent/run/POST, reused output or nonexclusive intent
is reconciliation-only and never authorizes redispatch. After any possible POST,
Root must discover/reconcile the original outcome rather than repeat submission.
No successful native result, image, hardware, release or Root acceptance follows
from a DATA-contract pass.

`test_contract.py` uses actor-fenced, explicitly synthetic Root assertions. It
tests a fully bound positive DATA path and refusal mutations over all major
authority/resource/runtime/request seams. MODEL profiles explicitly patch only
the profile pin in their fixture scope. `--genuine-profile ABS_PATH` additionally
checks the exact real unissued profile while Root case/admission/runtime/run
selectors remain MODEL. No test observes a lease, submits a request or issues a
real Root proof.

## Complete operand scaffolds

`Root-case.TEMPLATE.json`, `admission.TEMPLATE.json` and
`runtime.TEMPLATE.json` are the constructor's unissued scaffolds.
`registration.TEMPLATE.json`, `readback.TEMPLATE.json` and
`once.TEMPLATE.json` complete the remaining external observation shapes. Their
binding, observation time, approval and actual selector fields remain null;
empty prior discovery is not invented. `request-code.contract.json` records the
fixed source/profile/canonical launcher, schema3 launch/schema4 delegation/
schema3 material grant, required seven independent pins and two workflow inputs.
It supplies no Source CID, Main CID, registration ID, authority or POST.

Root supplies an already-issued canonical request as the seventh operand. The
qualifier preserves those exact bytes; it never issues a request or fills an
approval. After actual publication/readback and live Root qualification, the
returned dispatch body and single exact operator argv are available to the
existing canonical ONCE operator. Do not bypass its actual held lease, live
observations, external authentication or uncertainty reconciliation.

# Delegated context v4: explicit completed component adoption

Source implementation only. All test identities, responses, keys, signatures,
archives and decisions are MODEL fixtures; no operational Root grant is made.
No native, GPG, API, hardware, performance or release result follows.

The single Source `programs.context` descriptor selects the whole
`payload/native/delegated_context_v4.py`. Its immutable embedded predecessor is
exactly `delegated_context_v3.py` at commit
`88ca3568df958ee7707bee9869f632b1f5796498`, SHA256
`efa5a2687ac1504ef565763ac0828dd6c98c593563df97b2f540ccf4e0de9d2b`.
A finite reversible adaptation changes only explicit version/issuer/schema
seams and checks the complete byte inverse. V3 is not edited. The closed Source
map format remains `CURRENT_ONBOARDING_CLOSED_SOURCE_V3`. Context/grant kinds
and issuers are explicitly V4 and schema4; the original v3 identity is never
claimed by v4. A v3 producer's exact program must also be in the same map.

The external Root admission boundary must authenticate the whole consumer
**grant**, not merely its self-declared issuer. Hashes alone do not authenticate
Root or provider data. Reviewed metadata acquisition remains the caller's job.

## API for owner/launcher integration

`validate_delegation`, `source`, `resolve_material`, `material_reference`,
`capture_context`, `validate_context` retain the v3 argument shapes. `adopt_pair`
is the strict same-run counterpart for v4 producer observations. The original
v3 program and its same-run behavior remain unchanged.

The distinct cross-run entry is:

```python
adopt_selected_pair(delegation, context, *, producer_delegation_raw,
    producer_context, completion_raw, pair_raw, root_component_raw,
    root_test_raw, archive_bodies, signature_bodies, public_test_key_raw,
    selection_role=None, now=None)
```

For stages consuming multiple packages, use the bounded `pair_selections` role
map described below and pass the explicit `selection_role`.

Whole bodies are bytes; producer_context is the original JSON object whose
canonical bytes are selected. `archive_bodies` and `signature_bodies` each hold
exactly two byte strings. No pathless PASS or hash-only archive is sufficient.
`source` rejoins the whole finite map before use. All material resolution stays
Source-relative. The consumer's Source/ref/map equal the selected producer's;
its actual run differs and comes from a fresh genuine poststart observation.
The producer's original workspace and timestamps stay historical. Its expired
delegation can establish history at its original observation time, never new
execution authority. Current consumer and Root decision expiry remain required.

## Explicit component and producer-stage mapping

Selected adoption is restricted to the actual current identities in the held
`successor_v2/profile.json` read at owner commit
`e8034dab` (profile SHA256
`8ad3641649e395b1202363e3368f713f65252a743b12e3a8d69430e4f82bc171`):

| Component name | Version | Architecture | Required original producer stage |
| --- | --- | --- | --- |
| cachy-asahi-repository-enrollment | 0.4.0-1 | any | backend |
| cachy-asahi-first-login | 0.1.0-3 | any | backend |
| cachy-asahi-first-login-ui | 0.2.0-2 | any | ui |

A completed UI producer is accepted only by a lifecycle consumer. Other
components, versions, architectures or producer stages refuse, even when their
whole bytes are selected in a fresh MODEL grant. Setup8 remains on its existing
separately qualified input route. Its name/version does not enter this map.

No new selection field or signature schema is introduced: the explicit Root
selection fixes the component and whole producer delegation/context pins, and
that original producer delegation must have the mapped stage. Provider metadata
still has to match that producer's original job name/runner/run/attempt/Source.
The original v3 or v4 producer context, issuer, workspace, timestamps and expiry
remain historical; nothing is converted or relabelled. Current consumer expiry,
fresh separate Root decisions and actual owner GPG requirements stay unchanged.

The original native owner pair proof must use `package` and `version` equal to
the selected component's `name` and `version`, alongside the existing exact
`component`, schema/kind/issuer, program/policy/binding/nonce and archive joins.
These are the literal fields emitted by
`owner_delegated_v3.Session.compare()` in `e8034dab`, not a new owner format.
Root's independent component and TEST decisions still join the whole original
pair bytes. Context never invents either decision.

## Required Root selection in the consumer grant

Use schema4, kind `ROOT_DELEGATED_CURRENT_ONBOARDING_PRIVATE_EXECUTION_V4`,
otherwise the original bounded grant fields. Future consumer `binding.run` and
`binding.job` remain NULL. Set `capability.allow_pair_adoption=false` and
`capability.allow_selected_pair_adoption=true`; stage is UI or lifecycle.
The exact additional `pair_selection` object has:

```text
schema: 1
kind: ROOT_EXPLICIT_COMPLETED_COMPONENT_SELECTION_V4
producer_binding: {source, ref, run, job, attempt:1, source_lock:{bytes,sha256}}
component: {name, version, architecture: any} # exact current identities below
producer_delegation_pin: {bytes,sha256}
producer_context_pin: {bytes,sha256}
completion_pin: {bytes,sha256}
pair_pin: {bytes,sha256}
archives: [{bytes,sha256}, {bytes,sha256}]
signatures: [{bytes,sha256}, {bytes,sha256}]
public_test_key_pin: {bytes,sha256}
test_fingerprint: exact uppercase primary fingerprint
root_component_decision_pin: {bytes,sha256}
root_test_decision_pin: {bytes,sha256}
max_producer_age_seconds: positive integer <= 2592000
```

For multiple components, use `pair_selections:{role:selection,...}` instead of
`pair_selection`; each entry has exactly the schema above. There are at most
eight safe role names. Both representations together refuse. An explicit
`selection_role` is required when there is more than one entry; unknown roles
refuse. This lets one UI/lifecycle grant name enrollment and first-login
separately, with distinct native pair and Root decision pins.

All producer IDs and **all whole pins** must be observed and externally
Root-authorized before grant issuance. Root issues this after independently
reading the completed native pair and making its separate TEST decision.
No guessed future producer IDs and no arbitrary earlier run is authorized.

`completion_raw` is pinned JSON:

```text
schema:1, kind:CURRENT_ONBOARDING_COMPLETED_PRODUCER_V4
producer_binding, producer_delegation_pin, producer_context_pin: selection values
observed_epoch: original completed-job observation time
jobs_response: {url,status:200,body: original UTF-8 JSON text,
                received_epoch,elapsed_ms}
```

The fixed complete single-page jobs endpoint must contain the exact selected
job/run/attempt/Source/name/runner/provider URLs, status completed, conclusion
success, and ordered original UTC `started_at`/`completed_at` times. Completion
must precede consumer issuance within the selected maximum age.

`pair_raw` is the native owner's original V3 or V4 pair proof. It must join
schema/kind/issuer, producer binding/nonce/owner/policy, selected component,
matching two exact archive pins, and all original unset final acceptance fields.
A producer PASS alone does not establish a native pair: Root's independent
component decision and both actual archive bodies remain mandatory.

Root decision bodies remain separate authentic bytes. They are **inputs**, never
emitted, reissued, or upgraded by context. This new adapter expects each to have:

```text
schema:4, issuer:Root, approved:true, operation:first-login-enrollment-ui-current-v2
kind:ROOT_SELECTED_CURRENT_ONBOARDING_COMPONENT_V4
  or ROOT_SELECTED_CURRENT_ONBOARDING_TEST_V4
scope:CURRENT_PRIVATE_COMPONENT_ONLY
producer_binding, producer_delegation_pin, producer_context_pin, completion_pin,
component, pair_pin, archives: exact selected values
issued_epoch, expires_epoch: fresh finite decision spanning current use
Root_final_acceptance:NULL, hardware_acceptance:false, release_acceptance:false
```

TEST additionally joins `signatures`, `public_test_key_pin`, `test_fingerprint`
and `trust_scope:TEST_ONLY`. Both decisions are issued after the observed
completion and no later than the consumer grant; maximum lifetime is bounded by
the reviewed delegation policy. Existing Root decision formats need explicit
owner/constructor coordination; context does not rewrite them into this format.

The result is `DELEGATED_CURRENT_ONBOARDING_SELECTED_PAIR_ADOPTION_V4`, issuer
`DELEGATED_CONTEXT_PROGRAM_V4`, schema4. It retains consumer and producer tuples,
selected decision/body pins and `current_stage_gpg_required:true`. It always has
`Root_final_acceptance:NULL`, and independent component/hardware/release
acceptance false. The owner must retain the authentic Root decision bodies and
perform actual current-stage supervised offline GPG verification with primary
key, trust, expiration/revocation and natural retirement checks. This DATA API
cannot satisfy those checks. Setup8's separately qualified input route remains
separate; no general cross-Source trust is added.

## Portable validation

41 fenced MODEL tests pass with CPython3.12.13 and CPython3.14.6 using isolated,
bytecode-disabled interpreters and a128MiB address-space limit. The test driver
blocks subprocess/exec/spawn/fork/system/socket/ctypes/lease-lock events. It runs
the exact pinned v3 regression suite, a fully invertible v4 adaptation of that
baseline, and explicit cross-run cases including v3/v4 producers, an expired
historical delegation, a disappeared historical workspace, multiple selected
component roles, completion/body/tuple/decision/program/key/signature refusals,
and unchanged unset final authority. All37 earlier controls remain present.
Four added controls exercise original v3/v4 completed UI producers to lifecycle,
the exact profile mapping, contradictory actual owner pair fields, separate
Root decisions, provider completion and Source/ref refusals. These are portable
source/DATA results.

```sh
python3.12 -I -B scripts/ci/first-login-enrollment-native-source/test_delegated_context_v4.py
python3.14 -I -B scripts/ci/first-login-enrollment-native-source/test_delegated_context_v4.py
```

Owner/launcher, Source constructor, authentic Root decision issuance and actual
current-stage GPG integration are coordinator-owned work. This commit changes
none of those existing programs or shared manifests.

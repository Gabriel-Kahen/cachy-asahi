# Material scope and retained input domain v3

Source implementation with fenced controls. No sudo, systemd scope, loop device,
format, mount, privilege change, acquisition, live secret, GPG, ALPM, native role,
Root grant, Source freeze or publication was executed. Native resource enforcement
and transport memory remain NOT RUN. The existing executor and image are unchanged.

## Caller API

```python
M.API == 'CURRENT_ONBOARDING_MATERIAL_DOMAIN_V3'
M.CLOSE_SECONDS == 90
session = M.open_material_session(
    source_root=source_root,
    delegation_raw=delegation_raw,
    delegation_sha256=Root_external_delegation_sha,
    context=actual_context,
    grant_raw=staging_grant_raw,
    grant_sha256=Root_external_staging_grant_sha,
    shared_timing=actual_shared_timing,
    control_root=existing_runner_owned_0700_control_root,
    runner_uid=actual_runner_uid,
    runner_gid=actual_runner_gid,
)
try:
    staged = session.stage(secrets=explicit_owned_exact22_dict)
    # staged == {receipt, references, assembler_fields, staging_scope_retirement}
    # Assembler -> checked inputs -> prerequisites -> clipped main execution.
    # Keep session and its mounted input filesystem until ALL consumers retire.
finally:
    session.close()
```

`stage` is one-shot. There is no destructor or stage-finally unmount. Successful
staging returns references only after the actual held scope command retires
naturally and its whole cgroup is absent twice. Its filesystem remains mounted,
with ownership retained for the caller's later consumers. The caller must retire
those consumers before `close`; unmount is ordinary, never forced/lazy. A busy or
uncertain domain remains HOLD/CLOSEONLY. `session.receipts` records the physical
caller command supervision and actual absence observations separately from the
unchanged stager receipt. `session.storage_observation` records the retained
filesystem observation. All are private DATA requiring a public allowlist
projection before retention/publication; argv and whole refs contain private
absolute paths. No fixed success receipt substitutes for these observations.

The launcher must reserve `CLOSE_SECONDS` plus its existing15-second main
retirement allowance before choosing main RuntimeMaxSec. Every stage/close scope,
held supervisor and command is clipped to the same boot-bound absolute monotonic
Root deadline and the earliest verified delegation/staging-grant expiry. The shared
timing expires_epoch must equal that minimum; an earlier Root staging grant
shortens the window, while equal expiries retain their existing behavior. The close role is capped at90 seconds, including
its physical work, with a5-second systemd stop bound and15-second submission/
retirement margin. A late close gets a smaller scope or refuses before privilege;
it adds no tail beyond the shared7560. The stager's separate30-second internal
retirement budget and3600-second phase ceiling remain unchanged.

## Explicit Source roles and unissued policy

Root must select `programs.material_domain_executor` as this exact new body,
`programs.materials_stager`, `programs.inputs_assembler`, plus the existing context,
image executor and held supervisor. The exact reused executor is53735 bytes /
SHA256 aee41c0956f3249eef2e9c8974238b214622cb385e2d8f736109d9650ce7120a.
The actual stager is the separately committed Python-path successor at
author commitdb619da7: `stage_materials_current_v3_python_v1.py`,32266 bytes /
SHA256 d0c0764b1b7a92bb55dce63ba55314bb84ace4533434afcc47b1e23205e1cac9.
The selected hosted launcher supplies its unchanged `fixed_tool` sudo guard;
sudo is outside the old executor's finite16-tool resolver. Canonical Python paths
and absent-only `/usr/bin` to `/usr/sbin` fallback use the held resolver without
changing it. Held supervision remains83444522f4dfede67f6965ea75de8411b9e34510c04d40571fe439c223294e8f.
These are exact dependency pins, not an arbitrary Source implementation allowlist.
The stager's original helper/program/profile closure is also mandatory; see its
separately owned specification. Missing helpers still HOLD before acquisition.

Two original metadata references derive only from these exact closed descriptors:

| d.materials role | Source member | Bytes | SHA256 |
| --- | --- | ---: | --- |
| staging_base_lock | bootstrap/scripts/ci/inputs.lock.json |328101|beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f|
| staging_bootstrap_profile | native/input-profile.json |168201|2c42c705654d31e639f389f9a868dada0d9df76813d865e766be7b7c08f8404c|

No path scan, guessed provider, extra API operand or substitute metadata is used.
Whole Root delegation and grant hashes are checked before selected imports.
The actual selected context validates the delegation, complete closed Source and
context. The existing executor's strict v3/current-v4 contract and policy validator
remain in use. Native/physical entry requires real Linux/aarch64/root identity;
open requires the actual ordinary caller UID/GID and its existing owned control
root, disjoint from Source. Source and foreign files are never chowned.

The exact unissued `M.PROPOSAL` must be included as
`policy.material_domain_executor_current_v3`. It does not issue a grant. Existing
`allow_material_staging`, actual unchanged c640 staging grant and policy,7560 context
age/lifetime and actual shared timing remain required. The actual launcher owns
validation of the timing receipt's original request pin against its request;
this module checks its typed pin, boot, delegation, context, policy, lifetime and
absolute deadline. Authority fields in proposals remain NULL, and all acceptance
fields remain unset/false. Inert approved MODEL fixture dictionaries are not Root
issuance evidence.

## Physical ownership and limits

The caller invokes sudo noninteractively for a nonce-specific transient scope:
`cachy-current-materials-<nonce>.scope`. Actual kernel PID/start/cgroup and all four
limits must match: CPU1, MemoryMax512MiB, Swap0, Tasks64. Runtime is at most3600
seconds, with actual systemd activation/runtime checked before storage allocation.
Only this new role raises virtual AS to2GiB; core is0 and CPU is at most3600.
Existing512MiB launcher/controller and image resource policies are unchanged.

Root creates `/var/lib/cachy-current-material-owner-<nonce>` exclusively, retains
root-only custody and bounded administration receipts there, physically allocates
an8GiB backing file and obtains exactly its own loop association. Ext4 uses
`-N18432`, avoiding the inode rounding risk of requesting20000. Actual statvfs must
show at most8GiB and20000 nodes, at least6GiB and18000 nodes free. The mount is
`nodev,nosuid`, mode0700, and only the newly verified mounted root is chowned to
the runner. The selected grant parent must be
`/var/lib/cachy-current-material-domain-<nonce>`. Staging then drops supplementary
groups, GID and UID before invoking the actual Python-path successor public wrapper. It cannot
regain root through this module.

The retained8GiB is additional to later image storage. Preflight requires the
existing image policy's full disk minimum plus8GiB and128MiB bounded administration
reserve; no old storage admission is waived. Administration has32 bounded held commands split into separate16-command
staging and close receipt directories, with256 declared nodes, separately from the8GiB DATA filesystem. Each reused
command engine stream is sealed/bounded at1MiB; commands are fixed root-owned
storage/systemd tools. The private root custody/administration directory remains
for diagnostics after the backing file and mount are removed. This is source-bound
finite execution, not a measured hardware qualification.

On close, the root-only saved request/custody and backing inode/mode/UID/GID/link
identity must match. The old staging scope must actually be absent. Recovery may
identify an uncertain loop only through the exact newly created backing file;
it never lists/deletes arbitrary Docker resources or foreign volumes. Mount
identity and its loop association are rechecked before ordinary unmount; the
original empty underlying mountpoint is checked before rmdir. Detachment must
produce an observed empty owned association before removing the backing file.
Partial own setup is close-only; foreign/colliding/changed/busy storage refuses.
Expired authority does not create an extra privileged cleanup window: preserve
custody/HOLD for the coordinator if no authorized time remains.

## Private values

Only an explicit dict of the original22 exact names is accepted. Those exact
ambient names are removed before public carrier execution and on failure. No
ambient value or credential store is read. Values enter only a sealed anonymous
memfd inherited as stdin through the exact scope entry; they never enter argv,
Root request DATA, receipts or disk. Root storage commands receive DEVNULL stdin.
After the one-way runner UID/GID drop, the actual stager receives its own
`OneShotSecrets` object. Private mapping references are cleared on all exits;
this does not claim cryptographic memory erasure. All nonprivate children keep
the original stager's minimal environments and exact original seed boundaries.

## Controls and remaining gates

```sh
python3 -I -B -Werror::ResourceWarning scripts/ci/first-login-enrollment-native-source/test_material_domain_current_v3.py
```

Twenty-six fenced controls cover actual committed context v3/v4, executor and
unchanged staging grant/Source authorization on inert closed sources; exact closed metadata
roles; stale dependency/Root pin refusal; finite kernel/scope properties;
Root-to-runner handoff into the real stager wrapper; cleared MODEL values;
forced/nonzero/timeout/incomplete retirement refusal; clipped/expired close;
retention across assembler/image consumption; foreign/backing/cgroup cleanup
refusals; actual absence receipt flow; and atime exclusion while body/mutation
checks remain strict. Process, mount, privilege and scope observations are MODEL
values. No physical resource, normal native retirement, hosted acquisition or
transport memory result is invented.

Root still owns final Source construction, actual grant/cap/policy issuance,
caller/workflow/22-secret binding, timing request authentication and consumer
retirement. Actual privileged tools, memfd/seal APIs, physical storage availability,
UID/GID transitions, hard scope enforcement and native transport remain operational
acceptance gates. This change contains new module/test/doc files only; it changes
no existing image/executor, Source constructor, owner, shared manifest or CI file.


The earlier c640 canonical-Python guard HOLD is corrected by the exact db619da7
successor selected above. It qualifies canonical Python/systemctl rows through
the unchanged actual executor, uses the verified canonical paths for outer
commands and rechecks each immediately before Popen. API, proposal, caps and
original helper pins remain unchanged; c640 and91fee archived bytes are intact.
The successor's19 fenced controls also pass on the three local interpreters.
Physical/native resource and acquisition gates remain NOT RUN.


## Observed caller return normalization

The session adds `staging_scope_retirement` as the fourth stage result key. This
public projection has `natural`, `scope_absent` and the exact
`cachy-current-materials-<nonce>.scope` name, plus whole pins for the underlying
held supervision and actual twice-absent scope observation. It is derived from
`session.receipts[-1]`: the record must be STAGE, naturally retired, have actual
complete exit0 held supervision, and name the correct twice-absent scope. Missing,
false, forced, incomplete or foreign-scope records refuse before provider refs
are read/returned. The original stager receipt is not rewritten and private argv
is not projected.

After actual delayed storage retirement, `close` adds `closed`, `scope_absent`
and `input_storage_absent`. These join the root storage owner's verified
`owned_storage_absent` and original staging-scope absence with the held close
command's natural retirement and twice-absent close scope. The root body must
match binding, nonce and request pin. An unsubmitted session checks both scope
absences and both known storage paths without privilege; it cannot attest absence
of a preexisting/foreign domain. No fixed True replaces an observation. Failed or
missing proof remains HOLD/CLOSEONLY, and the caller retains the same90-second
reservation inside the original whole deadline.

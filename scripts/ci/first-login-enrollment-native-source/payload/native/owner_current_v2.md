# Current onboarding owner successor

Source implementation, not an operational result. No native image, package,
signature, runtime qualification, Reader acceptance, M2, performance or release
result was produced by its fenced tests. Frozen `owner.py` is unchanged.

`owner_current_v2.py` exposes `CURRENT_ONBOARDING_OWNED_CALLBACKS_V2` and
`open_current_session(grant, source, output)`. Backend350 builds enrollment04
and CLI03 twice; UI374 builds UI02 twice through the maintained generic CLI.
The Docker proxy preserves the CLI's declared provenance vector and retains
its distinct effective create vector: fixed endpoint, no network, labelled
containers, inspected 4CPU/4GiB/no-swap/512PID limits, exact mounts and full CID
retirement. It also intercepts the generic CLI's inherited timeout removal.
Unknown or nonnatural nested completion remains HOLD.

The owner consumes separately Root-qualified stage image IDs. It does not
construct the prerequisite 350/374/372 images, issue their qualifications,
acquire official packages, sign packages, obtain leases or grant acceptance.
Those inputs remain independent gates, never inferred from architecture or
the success of a package build.

The runtime closure is the owner's `DEPS` map plus the owner itself. Keep these
files at their repository-relative paths in a new source carrier; changing
their layout breaks literal held dependency resolution. The constructor must
read committed blobs and include the whole dependency closure. Import is DATA
only; it performs no process, Docker, GPG, network or system mutation.

## Root inputs and entries

All route admission fields remain required, including the Source/run/job tuple,
source lock, current profile/input pins, qualified immutable stage image and
inventory, whole runtime input, matching Reader selector and finite resources.
Each stage needs its own current Root admission. The owner adds:

```text
source_date_epoch: same integer as inputs.source_date_epoch
owner.api: CURRENT_ONBOARDING_OWNED_CALLBACKS_V2
owner.code: {path, bytes, sha256} for this maintained owner
owner.inputs: {path, bytes, sha256} for the admitted input file
owner.test_public_key: {path, bytes, sha256} for Root-selected public TEST key
owner.test_fingerprint: exact primary fingerprint selected by Root's decision
```

These fields, the actual Root signature decisions and all image/runtime gates
are checked before daemon or GPG roles. A partial, NULL, stale or old admission
refuses. Every proxy entry repeats that gate; an expired admission can stop a
later build rather than silently extending authority. Existing `Commands` owns
all command waits. The owner uses at most 600 seconds from the admitted total;
backend/UI reserve up to 60 seconds of that budget for retirement. Exhausted
or uncertain cleanup never becomes PASS.

Backend/UI use the maintained route entry with explicit admission SHA and
`--execute`; it imports this whole-pinned owner and opens the callback session.
Lifecycle uses this owner's `--launch-lifecycle` entry with the same explicit
`--admission`, `--admission-sha256`, `--inputs`, `--source`, `--output`,
`--execute` operands. Direct lifecycle callbacks on the host refuse.

Lifecycle additionally requires:

```text
owner.admission_path: exact absolute admission filename
owner.launch_manifest: /tmp/current-onboarding-owner-<8..64 safe chars>/inside.json
owner.lifecycle_capabilities: [CHOWN, DAC_OVERRIDE, FOWNER, SETUID, SETGID]
owner.input_references: list(references(inputs)), in recursive JSON insertion order
signed: the route's exact four current package/archive/signature/pin records
```

The selected launch-state directory must not exist. The output's parent must
already be an empty, nonaliased directory owned by the invoking non-root user,
mode0700; output itself must not exist. Nothing else is exposed through its RW
mount. Code is copied into a finite private carrier and mounted RO at its
original absolute filenames. Public proof/material operands use exact same-path
RO mounts. There is no daemon socket inside the actor. Source and input mounts
cannot overlap the writable output carrier.

## Authentic TEST decisions and lifecycle retirement

`current_TEST_signature_verification` now contains exactly
`{Root_decision: whole_reference, Root_verification: whole_reference}`. The route
joins the actual retained `ACCEPTED_PRIVATE_SETUP8_PACKAGE_TEST_ONLY` decision,
or explicit current onboarding package decision, to the actual
`ROOT_VERIFIED_PUBLIC_TEST_SIGNATURE` proof, archive/signature/public-key pins,
fingerprint and TEST-only scope. Historical Root observation timestamps remain
historical. They are not rewritten as a fresh Root verification.

Before native work, the owner imports only that public key into private trust,
sets its explicit TEST ownertrust and performs actual supervised offline GPG
verification. Raw status and its original command/log/supervision receipt are
retained under `DELEGATED_CURRENT_OWNER_GPG_NOT_ROOT_OBSERVATION`. Bad, expired,
revoked, unknown or wrong-primary signatures refuse. Administrative commands
remain outside the route's exact build/lifecycle command index.

Lifecycle runs as a root native Python child of non-exec Bash PID1 in a writable
ephemeral project-free372 container. It uses the held ALPM/payload helpers,
private required-signature configuration, actual baseline/install-reason reads,
protected-state snapshots and failure restoration. Both genuine private GPG
homes are retired, including on failed restoration. The local report remains
`PENDING_OUTER_CURRENT_STAGE_RETIREMENT`; it never claims its own absence.

The outer owner reconstructs the exact launch policy, joins created/terminal
inspections and natural command receipts, removes only the validated full CID,
and verifies exact-name absence. It retains receipts and removes private outer
state before publishing final route PASS. Failure leaves HOLD or PENDING DATA.
No new platform/hardware acceptance follows from this result.

The matching passive Reader needs an explicit successor adaptation for this
Root-decision/delegated-verification shape and outer receipt. The previously
accepted Reader expects the earlier fresh-Root proof schema and is
not a matching acceptance Reader for this change. Root owns that integration.

## Verification performed

23 fenced owner controls and 13 route controls pass on Python3.12.13 and
Python3.14.6 under 128MiB address-space limits with isolated, bytecode-disabled
interpreters. Controls refuse subprocess/socket/ctypes/exec/fork/lock activity;
they use fictional command receipts, never actual actors. They cover NULL
preflight, exact generic provenance and inspection mutations, timeout custody,
private trust/configuration, normal and failing restoration/retirement, exact
absence/removal, namespace collisions, carrier escapes, coherent launch-policy
changes and nonnatural outer evidence. This verifies source behavior only.

# Current onboarding owned executor v3

This new runner implements the actual controller/owner/daemon machinery behind
`CURRENT_ONBOARDING_IMAGE_EXECUTOR_V3`. It is source-audited and covered by fenced
controls. Docker, systemd, sudo, mounts, network, GPG, native execution, leases,
Root issuance and dispatch were NOT RUN. No old owner, route, Reader, constructor,
image/context program, manifest or CI registration was edited.

## Interface

Inside the ordinary owner service, `Executor` exposes a defensive-copy `facts`
dictionary with:

- api, actual binding `{source, ref, run, job, attempt: 1, source_lock}`, stage,
  nonce, whole executor code_pin and domain_policy_pin;
- actual owner_domain and daemon_domain (PID/start/cgroup/finite kernel limits,
  resolved executable), native_architecture, UID/GID and held-daemon-PIDFD fact;
- exclusive docker_endpoint, observed engine_id, tool observations, storage quota
  and domain/deadline facts; held supervision-program pin;
- Root_final_acceptance NULL and independent/hardware/release acceptance false.

`run(step, argv, timeout_seconds, expected=0)` returns:

```
{
  "stdout": bytes,
  "stderr": bytes,
  "receipt": {
    "step": str, "argv": original_argv, "executed_argv": resolved_argv,
    "expected": int, "exit": int,
    "output_pin": {"bytes": int, "sha256": str},
    "stderr_pin": {"bytes": int, "sha256": str},
    "supervision": actual_held_supervision_receipt,
    "timeout_seconds": requested_seconds,
    "supervision_cap_seconds": remaining_finite_seconds,
    "tools": actual_preuse_tool_observations
  }
}
```

Original argv remains exact even where the reviewed resolver chooses a canonical
executable alias. Both executed tool paths are retained for the sole permitted
env wrapper, `env DOCKER_BUILDKIT=0 docker ...`. There is no shell or PATH fallback.
Docker requires `--host=<exact private endpoint>`; the global socket is refused.
Image commands are restricted to Docker/env, GPG/gpgconf/gpg-connect-agent,
bsdtar and zstd. Privileged controller commands are a separate internal path.

The held supervisor is `scripts/virtual/owned_process.py`, whole SHA256
`83444522f4dfede67f6965ea75de8411b9e34510c04d40571fe439c223294e8f`.
prepare precedes launch; custody transfers immediately, including late spawn.
No Popen poll/wait follows transfer. A success requires exact integer exit,
reaped/REAPED, EMPTY_TWICE, complete output, no signals, timeout or error.
`passed` is not used because it hardcodes exit zero. Stdout is supervised as its
own pipe; stderr has a separately sealed-size memfd. Overflow is a HOLD. This
avoids contaminating Docker JSON and avoids imposing file-size limits on image
layers or legitimate archive/copy output. Both streams and failure intent are
retained beneath the bounded owner work directory.

## Runtime topology and proposed budgets

The root controller requires an existing finite systemd scope named
`cachy-current-controller-<nonce>.scope`. It verifies actual cgroup limits and
systemd runtime/activation clock before setup. There is no shared daemon.
The controller allocates a full 32 GiB backing file, verifies allocated blocks,
associates one loop device, formats/mounts ext4, and verifies backing/device
identity. Work, both temporary aliases, context and Docker data/exec storage use
that finite filesystem. Container tmpfs/memory remains charged to finite domains.
Controller diagnostics and selected public exports have separate finite reserves.

`owned-executor-current-v3.policy.PROPOSAL.json` is an unissued fragment for the
coordinator's full context/image policy. It proposes:

| Domain | Memory | CPU | PIDs | Swap |
| --- | --- | --- | --- | --- |
| Controller | 512 MiB | 1 | 64 | 0 |
| Owner | 2 GiB | 1 | 256 | 0 |
| Daemon and container aggregate | 6 GiB | 4 | 768 | 0 |

The daemon's actual PID subgroup is also finite, with the same daemon limits.
The aggregate service ancestor bounds it and all sibling container cgroups.
Ordinary build actors retain the held 4 CPU / 4 GiB / 512-PID limits.
The owner has a 2 GiB address-space ceiling; the controller has 512 MiB.
Minimum fresh availability is 12 GiB memory and 40 GiB disk, including the
32 GiB allocation, 3 GiB controller receipt reserve, 512 MiB public evidence
reserve and 2 GiB host reserve. These are proposals, not observed capacity.

The new stage budget is 7200 seconds, with 180 seconds setup and 180 seconds
cleanup: 7560 seconds maximum controller scope. Service maximum is 7380 seconds,
clipped further to the observed common controller deadline with stop time
reserved. Image bootstrap retains its existing 1800-second command bound;
verification/stage/inspection/image-cleanup remain 60/180/15/90 seconds. Existing
build command limits are not changed. Image command rows remain at most512;
controller rows are at most1024, with ten-second owner polling explicitly fitting
that budget. No old Fish1200/1290 or frozen onboarding caps were widened.

The reviewed Fish resolver was adapted from commit
`a645b938136fbc5106afc41e7e47882c2e260233`,
`scripts/ci/fish-config02-native-source/successor_v2/host_tools.py`. It probes fixed
/usr/bin and /usr/sbin candidates, records whole streamed hashes/metadata and
alias chains, allows only the finite mkfs/Python aliases, rejects any invalid
present candidate, and repeats the complete observation before every use.
Additional fixed roles env, gpgconf and gpg-connect-agent serve the image API.
That resolver fix was newer than the assigned Main base and is preserved here.

Each fresh service submission is recorded before systemd-run. Both services have
Restart=no, OOMPolicy=kill, KillMode=control-group, finite RuntimeMaxSec, finite
CPU/memory/PID/swap limits and a protected filesystem view. Owner writes are
restricted to allocated work and its /tmp,/var/tmp aliases. Host /dev/shm and
/proc/sys are read-only. The daemon has delegated cgroupfs/container roots,
private socket/data/exec roots, no bridge, iptables, forwarding or masquerading.

Before the owner may seed, the controller records actual live PIDFDs,
PID/start/cgroup/executable identity, exact kernel limits, finite systemd runtime,
private socket ownership and actual Docker engine/storage/capability identity.
The ordinary owner opens and retains its own PIDFD observations and rechecks
both processes, aggregate daemon limits and storage aliases. Lost custody stops
new commands before further PID probing.

Cleanup stops owner before daemon, verifies original PIDFD exits and cgroup
emptiness twice, retains bounded selected evidence, then rechecks loop backing
identity, unmounts, detaches and confirms association absence. Uncertain service
ownership retains storage. A known nonnatural outcome stays a HOLD even if
owned storage is safely released. Foreign/preexisting output is never adopted.
Surviving owner descendants or containers cannot become a successful stage.
A Docker CLI timeout is never evidence that its daemon work ended.

## Coordinator wiring

The coordinator must integrate the new code into its new Source closure and
supply a genuinely Root-selected delegation/context. The expected delegation
whole hash is checked before any delegation-selected program import. The runner
replays delegated_context_v3 rather than inventing hosted IDs. Predispatch run/job
stay NULL; the executor requires actual poststart IDs from the reviewed context.
Hash equality alone does not authenticate Root: the caller supplies that hash
through the existing reviewed Root trust boundary.

Required Source program descriptors are context, owner, image_executor, image,
and owned_process. owned_process must carry the exact held hash above. Context
is the separately owned `delegated_context_v3.py` (author commit88ca3568), and
image is the separately owned `image_current_v3.py`. Include this policy fragment
in the coordinator's full pinned policy, keeping its context/image fields and
ALPM capability list. Root must explicitly choose/issue compatible stage
capabilities/lifetimes; the stage_capability_proposals here issue nothing.

The controller CLI is:

```
python3 -I -B native/owned_executor_current_v3.py controller \
  --source-root /absolute/closed/Source \
  --delegation /absolute/delegation.json --delegation-sha256 ROOT_SELECTED_SHA \
  --context /absolute/actual-poststart-context.json \
  --inputs /absolute/image-and-stage-inputs.json \
  --output /var/lib/cachy-current-NONCE --uid RUNNER_UID --gid RUNNER_GID
```

The caller must place that root command inside the correctly named finite
controller scope with the exact proposed kernel limits, RuntimeMaxSec at most
7560, and an actual activation timestamp. This worker created no workflow or
privileged caller. The policy fixes the private endpoint to
`unix:///var/lib/cachy-current-<nonce>/volume/docker.sock`.

The controller launches this same whole-pinned executor module's owner entry.
The reviewed Source owner program must expose this adapter (owned by the
coordinator; no existing owner was edited):

```
run_owned_current_v3(*, delegation_raw, delegation_sha256, context, source_root,
                    inputs, executor, output, public_output) -> dict
```

output is the private, freshly created stage directory on allocated storage.
public_output is the separate selected evidence directory: put only bounded
public receipts there, not rootfs/cache/keyrings or daemon data. The adapter can
call image_current_v3.build_stage with this executor, then consume the resulting
image and complete its stage before returning; the dedicated daemon is retired
after the callback. Keep frozen build command/resource caps intact. Return
`completed: true`, the exact actual binding, and `Root_final_acceptance: null`
only after the requested private stage completes; a HOLD must remain a HOLD.
The controller does not turn this return into Root/native/M2/release acceptance.

The image helper now supplies `retire_private_separated_v3`, an explicit
versioned adapter for the held no-agent callback. It requires actual exit2,
empty stdout and exact separately pinned stderr; it returns that validated
stderr only as the held callback's diagnostic token. Original stdout remains
unmodified in receipts. Unknown stderr, substituted/missing pins, wrong exits
and agent-present responses remain a HOLD. The held tools stay byte-identical.

The controller's executor-report.json and evidence directory contain only DATA;
all Root final acceptance fields remain NULL. Its source was based on public
Main15fffb50adf4d123dcb163c75c9ae1df90b0f91e in an isolated worktree.

## Validation

```
python3 -I -B -Werror::ResourceWarning \
  scripts/ci/first-login-enrollment-native-source/test_owned_executor_current_v3.py
```

30 controls pass separately on Python3.12.13, Python3.12.14 and Python3.14.7.
All24 predecessor substantive controls remain. Three runtime controls cover real
runtime exports/memfd behavior, early missing-API refusal across operational
entries, and explicit PIDFD/seal-export refusal. There are no skipped tests.

The production guard `require_runtime_capabilities()` refuses missing
os.memfd_create/os.pidfd_open, both MFD flags, and fcntl's three required seal
constants before command resolution, buffers, child launch, domain submission,
controller/owner entry or host setup. There is no numeric-constant, syscall,
regular-file or other production fallback. stderr_buffer also closes the newly
created descriptor if real truncation/sealing fails.

Command/domain MODELs install labelled inert API attributes with create=True
inside the actor-denial audit fence. Their byte buffer is explicitly MODEL data,
not a kernel seal. PIDFDs/processes/supervision are modeled. These attributes are
restored before the independent real-runtime control. The real memfd test uses
unmodified APIs: it exercises actual local grow/shrink refusal if all exports
exist, or the actual explicit unsupported-runtime refusal when exports are
absent. No version is made to appear kernel-qualified.

| Interpreter | Controls | Unmodified runtime observation |
| --- | --- | --- |
| uv-managed CPython3.12.13 | 30 PASS | Production HOLD: memfd_create, pidfd_open, both MFD flags, F_ADD_SEALS/F_SEAL_GROW/F_SEAL_SHRINK absent |
| bundled primary-runtime CPython3.12.14 | 30 PASS | Production HOLD: F_ADD_SEALS/F_SEAL_GROW/F_SEAL_SHRINK absent |
| host CPython3.14.7 | 30 PASS | Exports present; actual local memfd growth and shrinkage rejected |

The interpreter paths for the3.12 runs were
`/home/gabe/.local/share/uv/python/cpython-3.12.13-linux-x86_64-gnu/bin/python3.12`
and
`/home/gabe/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3.12`.
The earlier7778865 controls exposed17/14 errors on those two builds; those
historical failures are not relabelled as operational success. The updated
controls now explicitly verify refusal instead of failing with AttributeError.
Both3.12 builds remain unsupported for production execution. Passing MODEL
controls on them establishes portable controls and refusal behavior only.

The image compatibility controls remain25/25 on both3.12 builds and3.14.7.
No process, Docker, systemd, sudo, mount, network, GPG, privilege change, lease,
Root issuance or native role ran. Real allocated-storage/owner/daemon behavior,
PIDFD custody and end-to-end onboarding remain NOT RUN. Context selection now supports the exact independently committed V3 and V4
programs below. Three additional MODEL controls bind descriptor, Source body,
module API, delegation and context identity; substitution refuses before import.


## Explicit context v4 compatibility

The Source-selected programs.context descriptor must match one exact program:

| Version | Bytes | SHA256 |
| --- | --- | --- |
| V3, commit88ca3568 | 21460 | efa5a2687ac1504ef565763ac0828dd6c98c593563df97b2f540ccf4e0de9d2b |
| V4, commit992cf5b2 | 43482 | 2d08f9572b3f5f89d3ebac2b32e6d41a00ff4929739c35780c7c96a1d3d3b21d |

The corresponding delegation/context schema, kind, issuer, operation, module API
and actual Source-relative module body are checked as one versioned contract.
V4 remains schema4 / DELEGATED_CONTEXT_PROGRAM_V4; it is never relabelled V3.
An unknown program body, mixed schema/issuer, substituted descriptor, module API
or file refuses. External whole-delegation authentication still precedes Source
program import, and the chosen program still performs its full validation and
replays the actual context. No arbitrary issuer allowlist or Root grant is added.
The closed Source map format remains CURRENT_ONBOARDING_CLOSED_SOURCE_V3.
This executor increment does not choose or adopt a historical package pair;
image/input adapters own that separate explicit V4 route.


### Committed context basis correction

The V4 registry row above selects the current committed program at992cf5b2
(43482 bytes), replacing the superseded282b7d4a body. V3 remains pinned to the
same exact21460-byte predecessor. A superseded V4 pin, an unknown implementation
or a V4 program relabelled V3 refuses before Source import in both executor and
image. The declaration remains schema4 and Source-map format remains V3.

Eleven cross-module controls in `test_image_selected_context_v4.py` exercise
actual committed context programs. They include unmocked `admitted_inputs`
positive paths for both V3 and current V4, with real program loading, closed
Source replay, exact executor bytes, held supervisor loading and policy
validation. Image admission also consumes the same real context, with only
native/kernel observations modeled. Additional controls exercise all three
reviewed selected-component producer mappings and superseded-basis refusal.
They grant no Root authority and execute no actor or native qualification.

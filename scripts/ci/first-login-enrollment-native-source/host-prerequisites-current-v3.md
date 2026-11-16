# Current onboarding host prerequisite (unissued proposal)

`payload/native/host_prerequisites_current_v3.py` exposes:

```python
prepare_host_prerequisites(
    *, source_root, delegation_raw, delegation_sha256,
    context, environment, output
) -> dict
```

This is execution capability, not an issued grant or native qualification. No APT,
network, systemd, Docker, GPG, lease or target actor was executed for this change.
`Root_acceptance` and `Root_final_acceptance` remain null and the independent,
hardware and release acceptance flags remain false. No project archive is installed.

The caller first authenticates Root's external complete delegation hash. This API
rechecks that hash, calls the descriptor-selected context program's
`validate_delegation`, `source`, and `validate_context`, requires actual current
Source/ref/run/job context, and checks every selected program's whole Source pin.
It requires `capability.allow_host_prerequisites: true` and policy member
`host_prerequisites_current_v3` **exactly** equal to the helper's `PROPOSAL`.
The delegation must remain valid for at least 495 seconds. These fields have not
been issued. No existing controller, stage, actor or job policy is overridden.

## Source dependency contract

In addition to `context`, `image_executor` and `owned_process`, the closed Source
program map must explicitly include these descriptor roles (`member`, `bytes`,
`sha256`). The new helper itself must be selected as `host_prerequisites`.
Members are constructor-selected ordinary Source files, never import paths from
the host or an uncommitted worktree. Missing descriptors refuse.

| Role | Exact public code from Fish commit `013c6214` | Bytes | SHA256 |
|---|---|---:|---|
| `host_prerequisite_plan` | `successor_v2/host_prerequisites.py` | 13845 | `4bef653f0e999876e8dd1e74e7d61b808182f7528f4f50ce6444e14f6ff33d64` |
| `host_prerequisite_tools` | `successor_v2/host_tools.py` | 5273 | `5f980d2df87cebdf264167e7be7220485a6fcc555667782d31316da0d08aef72` |
| `host_prerequisite_runner_basis` | `successor_v2/hosted_owner.py` | 31464 | `7f4d2a68f13a2439a4363cfb154553dc9e721a88dc985080dd290d44583ad634` |

All three original paths start with
`scripts/ci/fish-config02-native-source/`. No frozen Source is copied into this
implementation. Only the AST of the whole-pinned runner's literal
`Controller.run_prerequisite` method is compiled; its unrelated Fish controller
is never imported or executed. Held `owned_process` remains SHA256
`83444522f4dfede67f6965ea75de8411b9e34510c04d40571fe439c223294e8f`.

The exact pinned APT plan is reused with one explicit context predicate adapter;
it never impersonates the Fish job/ref. Its tool adapter uses the selected current
executor's complete sixteen-tool observer and uses Fish's fixed `/usr/bin` APT/dpkg
inspector for the four additional tools. Fresh observations rejoin every existing
executable body after installation. Missing tools other than `bsdtar` refuse.

`environment` contains actual allowlisted public provider fields:
`GITHUB_ACTIONS`, `RUNNER_OS`, `RUNNER_ARCH`, `GITHUB_REPOSITORY`,
`GITHUB_EVENT_NAME`, `GITHUB_RUN_ATTEMPT`, `GITHUB_RUN_ID`, `GITHUB_SHA`,
`GITHUB_REF`, `GITHUB_JOB`. The caller must preserve these before clearing its
process environment. Values must match validated current context, Linux/ARM64,
workflow_dispatch, first attempt, actual root UID, native aarch64/arm64 and actual
Ubuntu `ID=ubuntu`, `VERSION_ID=24.04`. Unrelated environment is neither read nor
retained. This API supports descriptor-selected context v3 or a compatible actual
successor API; it does not relabel a context schema or bypass producer adoption.

## Caller scope and policy seam

Before this API the launcher must enter a fresh exact
`cachy-current-prerequisites-<64-lowercase-hex nonce>.scope`. It must select the
new policy explicitly and set controller AS 536870912, CPU 500, core 0. The helper
checks actual kernel cgroup membership and all four kernel limits before its first
command. It then runs one supervised read-only `systemctl show` to bind actual
scope activation and exact runtime 495 seconds, reserving 450 seconds for the
literal APT plan and 30 seconds for cleanup. Late activation/observation refuses.

Required direct argv properties for a future caller's scope entry are:

```text
/usr/bin/sudo -n /usr/bin/systemd-run --scope --quiet
--unit=cachy-current-prerequisites-<nonce>.scope
--property=MemoryMax=536870912 --property=MemorySwapMax=0
--property=CPUQuota=100% --property=TasksMax=64 --property=RuntimeMaxSec=495
<whole-pinned finite controller wrapper and direct argv>
```

The wrapper must apply the rlimits before calling this API, own natural scope
retirement/empty-and-absence observations, and impose a finite outer wait. This
helper cannot elevate itself or create its own scope. Do not use the existing
7560-second build controller scope. The helper alone requires a separately selected physical scope. The launcher
successor now charges that scope within one shared7560-second deadline through
its separately selected `host_prerequisite_timing_v3` proposal; it does not add495
to the old budget. Its explicit opt-in hook runs before the complete tool gate.
Without that opt-in, missing bsdtar still produces HOLD. See `hosted-current-v3.md`
for the exact new authorization and reduced available-stage semantics. No executor
has been edited.

The output directory must be new, canonical, root-owned beneath a non-writable
root-owned parent, named `cachy-current-prerequisites-<nonce>`. Actual statvfs must
report at least 784 MiB and 4288 free nodes (512 MiB cache + 16 MiB reports +
256 MiB reserve; 4096 + 64 + 128 nodes). Unknown inode capacity is refused.
The caller selects/owns the domain; no HOME/tempfs capacity waiver is implied.

The reused plan preserves its nine exact normal signed APT commands: architecture
and initial package query; update; policy/candidate; exact-version simulation,
download-only and no-download install; exact installed version/arm64 query; actual
`bsdtar --version`. Candidate is durably recorded before simulation/download/
install. Retries are zero; no unauthenticated/insecure/downgrade flag, dependency
bypass, hook suppression, repository/config/key mutation, alternate provider or
fallback package is allowed. Existing public keyrings under `/usr/share/keyrings`
and `/etc/apt` are hashed; auth.conf and auth.conf.d are never visited.

Finite bounds are the audited plan's 450 seconds, 9 commands, 512 MiB cache,
4096 cache nodes, 128 MiB per file, 1 MiB per command output and 512 MiB child AS;
CPU limits and core0 are set before each child. One separate 15-second scope
observation makes ten commands total. Each child gets fresh held custody, WNOWAIT
before transfer and actual natural reaping/empty-twice checks. Forced retirement,
timeout, cancellation, incomplete streams and mutated trust refuse. The finally
path removes only the finite owned cache and exact command logs, retaining one
bounded public `prerequisite.json` (at most 1 MiB); it never retains raw APT output,
keyrings, credentials or arbitrary environment. The installed host prerequisite
remains on the disposable runner; this is not an unchanged-host claim.

## Fenced verification

Portable isolated tests require only the checkout (no historical Git objects):

```text
python3 -I -B scripts/ci/first-login-enrollment-native-source/test_host_prerequisites_current_v3.py
```

For the additional audited-plan controls, supply `CACHY_HOST_PREREQUISITE_FIXTURE`
pointing to a directory containing the **three exact pinned public code blobs**
named `host_prerequisites.py`, `host_tools.py`, `hosted_owner.py`. The tests verify
all three whole pins before use. This optional code-only fixture is 50582 bytes,
not an official archive, private cache or operational role. It is used to execute
the actual reused plan and runner with modeled children, real temporary config/
keyring/cache files, durable candidate checks, exact signed argv, trust mutation
refusal, auth-file exclusion, sixteen-tool refresh and forced-retirement refusal.
No test executes an actual child process or APT command. Both modes were checked
with Python 3.12 and 3.14; neither establishes host ARM or native acceptance.

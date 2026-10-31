# Finite maintained ARM rebuild batches

`build_batch.py` consumes the finite pre-change input accepted by
`rebuild_plan.py` and an explicit execution configuration. `plan` produces a
deterministic admission document. `execute` requires the SHA-256 of that exact
document and uses the existing `scripts/build/build.py`. Neither command
installs host packages, provisions an image, installs a scheduler, signs,
publishes, or changes Asahi's stack.

This interface supports **exact-source, exact-version rebuilds against already
reviewed pinned images**. It does not assemble first-time dependency images.
The frozen pre-change planner has no post-change candidate mapping; new
sources/versions need a separately reviewed planning/image step.

## Inputs and review

Supply these selected inputs to either command:

```
python -B scripts/maintenance/build_batch.py plan \
  --input /absolute/pre-change.json --input-sha256 INPUT_SHA256 \
  --config /absolute/batch.json --config-sha256 CONFIG_SHA256 \
  --planner /absolute/scripts/maintenance/rebuild_plan.py --planner-sha256 PLANNER_SHA256
```

Store stdout as admission JSON, select its SHA-256, then repeat the same
arguments with `execute`, adding:

```
--admission-sha256 ADMISSION_SHA256 --output /absolute/new-batch-directory
```

Output's parent must exist; output itself must be new. Valid plans exit 0 even
when held: inspect `groups`, `global_holds`, and `max_parallel`. Hashes bind
bytes, not signer identity, code review, source availability or origin.
The selected planner is Python code; review it before selecting its hash.
Config accepts no shell command or alternative builder path.

Configuration has exactly these fields:

| Field | Meaning |
| --- | --- |
| `schema_version` | Integer `1` |
| `owner`, `review` | Nonempty accountable operator and review reference |
| `max_parallel` | Integer 1–32 |
| `cpu_budget`, `memory_gib_budget` | Integers 4–128, aggregate container budget for this batch |
| `max_wall_seconds` | Integer 1–86400, invocation execution-loop deadline |
| `max_attempts` | Integer 1–10, total attempts per package across resumes |
| `tasks` | Up to 4096 package task objects below |

Each task has exactly these fields:

| Field | Meaning |
| --- | --- |
| `package`, `owner` | Planned binary name and exact planner owner |
| `recipe` | Absolute nonsymlink recipe directory |
| `reviewed_inputs`, `reviewed_inputs_sha256` | Absolute independently reviewed recipe input-map JSON and selected digest, as consumed by `build.py` |
| `expected_packages`, `expected_packages_sha256` | Absolute reviewed sorted, unique-name, newline-terminated `pacman -Q` lock and digest |
| `image` | `repository@sha256:64hex` or `sha256:64hex`; no tags |
| `mode` | `native` or `emulated`; `build.py` checks Docker server architecture |
| `source_date_epoch` | Nonnegative integer |
| `timeout` | Integer 1–86400, passed to `build.py` |
| `prerequisite_artifacts` | Exact predecessor-group package-to-artifact-SHA256 map |
| `image_dependency_review` | Review reference associating those artifact bytes with this image |

Every runnable planned build requires a task. Tasks for planner-held groups may
be omitted. Every planned package remains in the checkpoint, including affected
external packages, missing-owner/source packages, cycles and downstream holds.
A supplied task always requires valid pins and an owner, even when held.

Admission joins each PKGBUILD hash and source URL/checksum or Git commit to the
planner source record. Descriptor `url` must equal the recipe source after
stripping an optional `filename::` prefix, including `git+` and `#commit=`.
Local sources use their recipe-relative name and hash. Extra descriptor fields
are ignored in this pin comparison. Full version including epoch/pkgrel,
architecture, effective runtime dependencies, provides, make dependencies and
check dependencies must agree with planner metadata. Implicit toolchain inputs
remain explicit operator-supplied planner inputs.

## Prerequisites and limits

The existing builder cannot install a batch's new artifacts into another
build's immutable image. Each consumer lock must already contain the planned
predecessor versions. Before launch, completed predecessor artifacts must match
`prerequisite_artifacts`. Mismatched bytes block the consumer and descendants;
independent work continues. New bytes need a new reviewed image/plan. Every dependency-closure member, including transitive rebuilt predecessors and
unchanged baseline inputs, must also have its selected version in the image lock.
`build.py` checks the actual image's package inventory against that lock.

The artifact-to-image association in `image_dependency_review` is an **operator
review claim**, not automated proof of installed bytes. Image assembly,
retrievable inputs, signature verification, complete dependency solving,
conflicts, ABI transitions and bootstrap correctness remain separate checks.

SCC cycles, grouped/split outputs unsupported by the single-package builder,
held prerequisites, external update reviews and global holds stay held. No
bootstrap compiler is invented and no planner hold is overridden.

Each existing builder container has 4 CPUs, 4 GiB memory, a 512-process limit,
nonroot execution, read-only root, no network, and no image pulling. Concurrency
is the minimum of `max_parallel`, planner native slots, CPU budget divided by 4,
and memory budget divided by 4. These controls also conservatively bound emulated
jobs; emulated results stay emulated. The outer watchdog permits 30 seconds
beyond task timeout for preflight/cleanup, then stops the owned process session.
Shutdown may add process-termination and bounded Docker inspection/removal calls.
Input hashing and filesystem I/O are synchronous; this is not a hard real-time
deadline. Limits are **per batch**, not a global reservation or measured
sustainable capacity. Budget Python overhead, tmpfs, image storage, I/O, other
batches and host load separately. No disk quota or global scheduler is installed.

## Ownership, interruption and resume

Each batch owns a fresh marked directory, `admission.json`, advisory lock and
atomic/fsynced `state.json`. Each attempt owns a new `PACKAGE/attempt-NNN/`
with recipe/review/lock snapshots, runner log and a new `build/` evidence
directory. Existing paths, symlinks, nested batch roots and overlapping
input/output ownership are refused.

The runner rechecks implementation hashes, recipes, reviewed-input maps and
locks immediately before each launch, snapshots the build inputs, then checks
again. Keep selected trees immutable during execution; these checks are not
protection against a hostile same-user race.

A failure blocks descendants while independent tasks continue. SIGINT/SIGTERM
and deadline stop active work and preserve attempts. Surviving Python builders
inherit the batch lock after runner SIGKILL, so immediate resume refuses. Once
the lock becomes available, resume cleans interrupted owned containers and
marks running attempts interrupted, even if successful-looking files remain.
It never infers success from leftovers. Cleanup checks recorded command/image/
attempt mounts, inspects live container mounts/image, then requires successful
removal or independently confirmed absence. Daemon errors retain cleanup-pending
work and refuse recovery rather than consuming another resource slot.

Repeat `execute` with the exact original selected input/config/admission hashes,
the same output and `--resume`. Failed/interrupted packages restart only when
named with repeatable `--retry PACKAGE`. New attempts get new paths; blocked
descendants become eligible after prerequisites recover. Total attempt bounds
persist. Retained successes require whole-tree hash equality and replay of the
existing build evidence verifier. Changed evidence refuses resume.

Per-package states are PENDING, ACTIVE, SUCCESS, FAILED, INTERRUPTED, BLOCKED
and HELD. Per-attempt records retain output, exit, validation and hashes.
COMPLETE means every planned package has a successful bounded build record;
INCOMPLETE retains failures/holds; INTERRUPTED records stopped work; NO_WORK
means nothing selected. Execution exits 0 for COMPLETE/NO_WORK, 1 for valid
incomplete/interrupted runs, and 2 for refusal or unexpected runtime/input error.
Every state retains hardware status `NOT RUN`.

## Host checks

```
python -B scripts/maintenance/test_build_batch.py
python -B scripts/maintenance/test_build_batch_e2e.py
```

The first suite tests pure admission, production command construction and mocked
Docker cleanup. The second launches disposable fake-builder subprocesses with
explicit `HOST_FAKE_PROCESSES_NOT_OCI_NOT_ARM` evidence: actual concurrent
processes, ordering, failures, retries, output locks, runner SIGKILL, inherited
lock retention, stale evidence refusal, and independent progress beside holds.
There is no production fake-builder CLI switch; fake evidence cannot resume as
production evidence. `test_build_batch_e2e.py --exercise NEW_DIRECTORY` retains
an illustrative fake failure/recovery record.

**NOT RUN by these checks:** OCI builds, native aarch64 builds, measured capacity
or sustainable staffing, reproducibility pairs, package installation, ARM16K,
physical M2 behavior/performance, maintained releases or M5 acceptance.

For each task whose dependency closure reaches a bound baseline consumer, batch
admission requires the exact witnessed image ID and exact captured inventory
lock digest. Equal package versions in a different image do not qualify. A
repository/manifest digest is a different namespace: resolve/review its immutable
image ID outside admission and supply that exact ID, or admission refuses.
The admission record retains the used provider selections, including capture
digest, on that task. Unrelated tasks and no-selection behavior stay unchanged.

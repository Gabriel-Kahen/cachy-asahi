# Perl 5.42.3 XS four-command runner

Source proposal only. This executor has not run Perl, MakeMaker, a compiler,
make, or an XS extension. Native package acceptance remains Root's separate
Original Reader decision. The reported native job success and outer artifact
digest are not a native package archive pin or XS acceptance.

`scripts/port/perl5423-xs-consumer/runner/run.py` consumes the frozen preflight's
complete canonical JSON plan and a separately whole-pinned Root sandbox
admission. It stages exactly the five pinned fixture sources, calls the
whole-pinned frozen preflight again, and compares the entire canonical plan
before launching anything. Only its four planned argv arrays run: configure,
`make -j2`, `make test`, and standalone provenance. Each receives exactly the
plan's replacement environment. The unchanged owned-child helper is pinned at
`eaf9a46630e4fe4ca0a8f94a6dc2de4a881a6ad7e8b4dd0810b3347c0d7038d5`.

Root must prepare and admit the archive, complete runtime/header inventory,
metadata, compiler/linker-driver/make binaries, prefix and isolated sandbox.
The runner installs/extracts nothing and creates no container, daemon, VM,
namespace, cgroup or mount. The caller must already be a nonroot Linux actor,
without effective capabilities and with no-new-privileges, on the same actual
architecture as the admitted package. The sandbox must prevent prefix/tool/
source/operand mutation and escaping its exclusive process/resource scope.
Hash arguments bind Root's supplied bytes; they do not authenticate Root or
replace Root's review and coordination.

The existing unified cgroup must have `cpu.max=200000 100000`,
`memory.max=4294967296`, `memory.swap.max=0`, and `pids.max=256`, on a read-only
cgroup mount. Root's workspace must already be a private caller-owned mode0700
tmpfs mount with at most256 MiB capacity and at least192 MiB free. All source,
prefix, tools, metadata and input operands must be outside that workspace.
Both `workspace/xs-stage` and `workspace/xs-evidence` must initially be absent.
Root supplies an exclusive stable caller scope: cgroup process/thread IDs must
return to their initial sets after each command, and memory/PID event counters
must remain unchanged. Namespace, cgroup, actor and workspace identities and
resource limits are checked again during commands. A changed scope fails.

The sandbox JSON has exactly these required meanings (fill actual values;
this is a field guide, not an executable admission):

| Field | Root-supplied value |
| --- | --- |
| `schema` | `1` |
| `authorization` | `ROOT_ADMITTED_FOUR_COMMAND_XS_SMOKE` |
| `exclusive_scope` | `true` |
| `plan_sha256` | SHA256 of the entire canonical frozen preflight plan |
| `runner_sha256` | SHA256 of the reviewed `runner/run.py` |
| `target_arch` | Actual `x86_64` for host or `aarch64` for native |
| `uid`, `gid` | Actual nonroot caller IDs |
| `workspace` | Absolute private tmpfs mount path |
| `workspace_identity` | Actual `device`, `inode`, `owner_uid` integers |
| `namespaces` | Actual `/proc/self/ns/{user,mnt,net,pid,cgroup}` link strings keyed by name |
| `cgroup_membership` | Exact `/proc/self/cgroup` text, including newline |
| `cgroup_directory` | Actual unified membership directory under `/sys/fs/cgroup` |
| `cgroup_identity` | Actual `[device,inode]` of that directory |
| `accepted_reader_receipt` | Host: `null`. Native: Root-accepted actual Reader receipt `{path,bytes,sha256}` |

For native scope, Root must first accept the Original Reader evidence and
derive the actual package archive pin; it must supply the accepted Reader
receipt and the actual native Source/run/job selectors in the frozen admission.
The executor checks the supplied Reader file's whole pin; interpretation and
acceptance of that receipt remain Root's responsibility. Host admissions retain
null native selectors and cannot supply a native Reader claim.

Root can use the existing frozen preflight to plan against the exact prospective
`workspace/xs-stage`: briefly stage the five fixture files there for preflight,
save its canonical JSON outside the workspace, then remove that DATA-only
planning stage before execution. The runner recreates and independently checks
those same five bytes at that same path. No fixture or preflight edit is needed.
After all external admissions and Root's one-heavy-actor scheduling decision,
the future explicit entry point, inside the already prepared sandbox, is:

```sh
python3 -I -B scripts/port/perl5423-xs-consumer/runner/run.py --execute \
  --plan /admitted/plan.json --plan-sha256 ACTUAL_PLAN_SHA256 \
  --sandbox /admitted/sandbox.json --sandbox-sha256 ACTUAL_SANDBOX_SHA256
```

Per-command wall caps are30/90/30/30 seconds, with a210-second aggregate command
deadline and30 additional seconds reserved for export/cleanup. The existing
helper can spend up to2 seconds retiring a failed child. Each child inherits a
soft16 MiB file-size limit, or a tighter existing limit; the caller's original
limit is restored. Each stdout/stderr has a polled4 MiB policy cap. The stage
has polled64 MiB/512-entry bounds; polling can overshoot. The existing tmpfs
capacity and file-size/cgroup limits provide hard backing bounds. Deadline
checks cover bounded scans/exports; blocking kernel filesystem calls are not
an independently interruptible wall-clock guarantee. Cancellation requests
retire the owned child through the helper and always fail the smoke.

`xs-evidence/receipt.json` contains only observed command lifecycle facts,
actual resource snapshots and actual artifact pins. Raw stdout/stderr and
actual generated Makefile, dependency file, C/object/extension and configure/
runtime provenance are retained; the standalone runtime JSON stays in command4
stdout. Provenance preserves Config, actual module/extension/libperl paths and
candidate header/dependency pins. Existing generated artifacts are also exported
on failure where safe. Nothing fabricates a missing configure/runtime receipt.

Success requires four natural zero exits, each directly reaped with absent
owned process group, no forced cleanup, all expected generated files, and safe
stage removal. Forced cleanup can establish retirement but cannot establish
success. The runner removes only its new stage, after checking identity and
ordinary owned finite contents, using descriptor-anchored `rmtree`. Any uncertain
retirement, scope, alias or cleanup leaves failure evidence and retains the
stage when removal cannot be justified. Evidence remains for Root to inspect
and export before Root tears down its sandbox.

Even `FOUR_SMOKE_COMMANDS_COMPLETED` keeps `native_acceptance=false`,
`XS_acceptance=false`, and `qualification=NOT_GRANTED`. This is a tiny consumer
smoke receipt for later Root review, not general XS ABI, installed lifecycle,
16K/M2 hardware, performance or release qualification.

Four controls exercise whole-plan substitution, sticky cancellation, rejection
of a zero/forced-cleanup success claim, and real retirement of one fixed sleeping
Python child under an argv actor fence. They never invoke the production
executor or manufacture successful command/provenance receipts.

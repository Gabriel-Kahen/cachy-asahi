# Owned original-group RSS observations

This optional extension keeps `owned_process.py` standalone and adds one keyword:

```python
owned_process.prepare()
child = subprocess.Popen(argv, start_new_session=True, pass_fds=(lease_fd,),
                         stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, cwd=cwd, env=env)
result = owned_process.supervise(child, cap=30, retirement=5, grace=1,
                                rss_interval=0.1)
```

The caller still owns launch policy and the lease. Keep exclusive wait ownership
and SIGCHLD at SIG_DFL; never poll/wait/communicate through the transferred Popen.
The existing module's custody/pipe contracts remain required. There is no public
callback, external sampler dependency, observer thread, or logger cleanup hook.
`rss_interval=None` is the default: no observations, no new result keys, and the
existing default post-reap census is unchanged. Group mode is required when RSS
is enabled; the finite interval must lie in `[0.01, 60]` seconds.

The implementation adapts the existing `process_group_memory.py` algorithm:
the original session/group leader must be present, `/proc` membership is checked
before and after RSS reads, Tgid must equal PID, and identity/starttime and
zombie classification must stay stable. R/S scheduler-state changes are allowed.
Each live member needs an actual `VmRSS` value. Zombies contribute zero only
within a verified group snapshot; an exited-only snapshot has **no** RSS sum.
Missing data, member churn, permission/read errors and deadline exhaustion produce
an incomplete observation. They never turn into zero, leader-only group RSS, or
wait4 usage. The captured process-group sum preserves the exact existing scope:

> original process group only; per-process RSS sum double-counts shared pages; sampled, not true peak

This scope excludes detached sessions and members that leave the original group.
Forks/exits between snapshots are invisible. Before/after scans detect observed
churn but are not atomic kernel snapshots. Shared pages may appear once per
member. Neither the group sum nor the leader projection is unique physical memory
or a true peak, and neither provides global daemon/zombie absence evidence.

Every numeric `/proc` read in the new RSS, opt-in live-group, and final-census
paths is preceded by the supervisor's own fresh non-reaping WNOWAIT check. Its
private helper receives only that built-in check, not caller code. As with the
base core, exclusive wait ownership is essential: userspace cannot atomically
protect a later numeric read from an unauthorized concurrent stealing reaper.
Detected ECHILD sets ownership UNKNOWN and stops subsequent numeric probes and
signals. Errors in observation are data; only the coordinator's existing owned
retirement path may decide to signal. Logger threads never signal.

Sampling occurs only before retirement begins. Each attempt gets at most 0.1s
and cannot run past the existing run deadline. An incomplete observation stops
sampling and fails the run, initiating the existing bounded retirement. No
observation extends the total or retirement deadline. Scans cap numeric tasks at
4,096, group members at 512, and status input at 16KiB; the existing 4KiB stat
and 131,072 total-entry bounds also apply. Retention is capped at 4,096 records
(including a reserved error marker) and 8,192 member rows across records.
Exhaustion invalidates coverage explicitly. Intervals use actual sample-start
clocks; a slow attempt can delay the next start, and samples do not claim uniform
coverage. Scheduling/kernel latency are not hard real-time guarantees. Observation
overhead and performance effects are **NOT MEASURED**.

The opt-in route also removes all numeric PID/PGID operations after raw reap.
Before crossing the existing final signaling barrier, a bounded fresh-owned
census must contain **only the exact terminal reserved leader**. Raw reap then
removes that final observed member. The distinct result label is
`group_census="RESERVED_LEADER_ONLY"`; it is not relabeled `EMPTY_TWICE`.
This proof requires `reaped=True` and the other existing success conditions.
Remaining members or an incomplete census cannot pass. The disabled route keeps
its original, limited read-only post-reap census and original result semantics.

An enabled result contains `result["rss"]`:

| Field | Meaning |
| --- | --- |
| `samples` | Bounded original-schema records with group ID, member identities/RSS, scope, monotonic start/end ns, and complete/exited/incomplete status |
| `status` | `complete`, `partial`, `error`, or `unavailable` |
| `error` | Bounded reason, if observation/custody/retention failed |
| `process_group_sampled_rss_kib` | Maximum complete group sum, usable only with complete coverage and a stable leader identity |
| `process_group_observed_rss_kib` | Diagnostic maximum of completed snapshots, retained even if later coverage fails |
| `leader_sampled_rss_kib` | Separate usable maximum of the actual live leader's member VmRSS reads |
| `leader_observed_rss_kib` | Diagnostic live-leader maximum; never promoted from partial coverage |
| `process_group_rss_coverage` | Complete, exited, missing/incomplete record counts |
| `process_group_leader_identity_stable` | Whether complete observations bind one leader PID/starttime |

The other existing group-summary fields and exact scope string remain present.
Successful raw reap does not repair incomplete samples. A lost/unconfirmed wait
also creates an explicit incomplete error record (no proc access, no RSS value),
so the existing `process_group_memory.summarize(samples)` cannot mistake earlier
complete snapshots for usable coverage. `rss.status != "complete"`, a missing
live-leader peak, or unavailable group RSS prevents `result.passed`.

For the metric adapter owner: preserve all raw records and clocks and require the
normal successful workload/custody predicates **plus** usable RSS status. The
benchmark's current `root_rss_kib_pct` guardrail is a leader/root-RSS guardrail;
its truthful projection is `leader_sampled_rss_kib`, which comes from actual live
leader VmRSS observations. Keep `process_group_sampled_rss_kib` additive and
separate. Do not place the group sum in `root_rss_kib`, substitute the diagnostic
observed peak when coverage fails, or accept an unavailable guardrail. An adapter
must still validate source/config/clock/workload evidence and retain failures.
This packet does not implement or claim that downstream adoption/acceptance.

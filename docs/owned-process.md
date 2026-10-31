# Owned Linux child supervision

Reusable stdlib module: `scripts/virtual/owned_process.py`. Standalone Linux
real-child controls cover CPython 3.12 and 3.14. Caller adoption and lane
qualification remain separate.

Call `prepare()` on the main thread **before** creating a child. It rejects
ignored/custom SIGCHLD and reinstalls SIG_DFL to clear inherited SA_NOCLDWAIT.
Thereafter one coordinator exclusively owns that child's waits. No other thread,
signal handler, library, Popen context manager, `poll()`, `wait()`, `communicate()`,
or global `waitpid(-1, ...)` reaper may consume its status or alter SIGCHLD.
WNOWAIT cannot provide atomic protection against a concurrently stealing reaper;
exclusive wait ownership is a required caller contract.

```python
owned_process.prepare()
child = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         start_new_session=True, pass_fds=(lease_fd,),
                         cwd=cwd, env=env)
result = owned_process.supervise(child, cap=30, retirement=5, grace=1)
# Use result['passed']; exit == 0 alone does not establish success.
# Keep lease_fd open until retirement is established; only its caller closes it.
```

The module neither launches children nor chooses resource limits, argv, paths,
environments, transports, locks or leases. Popen creation time is outside the
supervision cap; the caller separately bounds setup/exec if required. Parameter
validation errors occur before custody is accepted; the caller still owns that
child. Keep `pass_fds` minimal. Do not add a threaded `preexec_fn` for policy.

For `os.fork()`, pass the positive PID to `supervise(pid, ...)`. Group mode needs
a child-created fresh session/group and a ready-pipe handshake **before**
transfer; inspect neither a not-yet-ready group nor a later reaped PID. Set
`group=False` to signal only the owned direct child; this mode permits its
session/group to change and makes no descendant or census claim. It needs no
memfd, exec wrapper, compiler or third-party Python library. The caller's
`/proc` must describe its own PID namespace and permit complete bounded scans.

Wait ownership is checked by non-reaping `waitid(WEXITED|WNOWAIT|WNOHANG)` before
numeric child access or signals. PID/starttime and, in group mode, session/group
identity are verified. The leader remains unreaped through the **last** TERM or
KILL decision, even if already a zombie. A final barrier forbids later signals;
only raw `waitpid(WNOHANG)` supplies exit status. Popen wait fallbacks never
supply evidence. A reaped Popen receives that real returncode. An unreaped Popen
has CPython destructor waiting disabled with `_child_created=False`, preventing
its ECHILD-to-zero fallback; this private detail was exercised on the exact
3.12/3.14 interpreters in the evidence and needs review on another implementation.
Do not reuse the transferred Popen's wait/poll methods.

`ownership=UNKNOWN` means no further numeric signals, child probes or census
occur in the core; `exit=None` remains unknown. It is a failed run, never zero.
If `reaped=False, ownership=OWNED`, a cap exhausted with an unresolved wait
obligation. Retain custody/lease and reconcile the owned raw wait separately;
do not infer completed retirement, release the lease, or send more group signals.
No user-space supervisor can force an uninterruptible task to become waitable.

`cap` includes retirement from transfer onward; the run budget is
`cap-retirement`. Retirement starts on terminal observation, failure or run-budget
expiry, and its deadline never moves later. If terminal observation first occurs
at/after the run deadline, timeout is conservatively true. A small tail is held
for final KILL/reap. All waits, reads and log writes are nonblocking and `/proc`
enumeration is bounded. Scheduling and kernel syscall latency are not hard
real-time guarantees; a result reaching the total cap cannot pass.

Default output pipes are Popen stdout/stderr. Alternatively transfer at most two
distinct fresh binary pipe objects via `streams=(...)`, with no prior buffered
reads or concurrent readers. The core takes and closes these handles. It captures
at most `max_output` **combined** bytes; order is the order observed while draining.
Overflow fails the run and retires the owned group. A borrowed nonblocking
pipe/socket `log_fd` can receive bytes; it must have a nonblocking consumer and SIGPIPE must
remain ignored. Short/blocked/failed writes fail the run. The core never closes
that log descriptor. Logging threads consume bytes only: they must never receive
child cleanup responsibility or signal a PID/group, including during late flush
failure. The returned bounded bytes also allow caller logging after supervision;
a failure then cannot trigger numeric child cleanup.

After raw reap, group mode performs at most two read-only `/proc` scans, within
the same retirement deadline. `EMPTY_TWICE` is two complete empty observations of
that numeric group/session. `PRESENT_OR_REUSED` means a member or reused identity
was observed; `UNKNOWN` means the scan failed, and `NOT_OBSERVED` means no scan
completed/was allowed. No census drives a signal after reap. These observations
do not prove global zombie/daemon absence, catch escaped sessions, or establish
native ARM, M2, package, lane or release acceptance.

Adapter changes are small but semantic: Done must transfer custody before its
wait; Orphans must send logger failures as data and use UNKNOWN on ECHILD;
Offline-kit must finish cleanup decisions before raw reap. Remove their old
post-wait numeric kill/probe paths rather than wrapping those paths in this API.
The existing lane fixes remain owned by their authors.

## Provenance and license

The module is MIT-licensed under the project `LICENSE`, with its original
2026 cachy-asahi contributors attribution preserved. It is derived from the
9,401-byte `reservation.py` snapshot, SHA256
`bd165fcc806c2951698cc16e1610ffb12a0da95404b5c99aaf3cdc067c1ea0e4`.
The new custody API and raw-wait behavior are semantic changes; the module
records the predecessor identity but has no runtime dependency on that file,
development packets or repository history.

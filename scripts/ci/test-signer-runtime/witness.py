# SPDX-License-Identifier: MIT
"""Original pure witness controller proposal; no syscall, process or clock actor.

Inputs below are runtime-adapter proof obligations, not self-authenticating JSON.
The controller consumes the owner-held kernel listener and pidfd observations.
Never serialize these object tokens or pass synthetic claims to a native signer.
"""
from dataclasses import dataclass
import math

ARCH = 0xc00000b7
EXECVEAT, BRK, EXEC_FD, EMPTY_PATH = 281, 214, 197, 4096


class Refused(ValueError):
    pass


def need(value, code):
    if not value:
        raise Refused(code)


@dataclass(frozen=True)
class Scope:
    source: str
    nonce: str
    policy: str
    generation: str
    pid: int
    start: int
    uid: int
    gid: int
    job_inode: tuple
    home_inode: tuple
    socket_inode: tuple
    executable: tuple  # dev, ino, bytes, sha256, root uid/gid, mode, nlink
    argv: tuple
    shim_argv: tuple
    kernel_commit: str
    filter_sha256: str


@dataclass(frozen=True)
class NativePremises:
    """Must come from pinned native adapter + compiled-shim admission, never files."""
    kernel_semantics_checked: bool
    builtin_elf_handler_proved: bool
    loader_closure_checked: bool
    static_shim_failure_path_proved: bool
    exact_filter_installed: bool
    single_thread_nofork_proved: bool
    inherited_exec_fd_custody_proved: bool
    no_external_ptrace_mutator: bool
    same_pid_namespace: bool
    source_policy_custody_checked: bool


@dataclass(frozen=True)
class Notification:
    identifier: int
    pid: int
    arch: int
    syscall: int
    args: tuple
    flags: int = 0


@dataclass(frozen=True)
class Observed:
    """Real stat/status/cmdline observation supplied at each existing guard."""
    pid: int
    start: int
    ppid: int
    group: int
    session: int
    uid: tuple
    gid: tuple
    argv: tuple
    state: str
    tracer_pid: int
    seccomp_mode: int
    seccomp_filters: int


class Witness:
    def __init__(self, scope, premises, parent_pid, work_end, cleanup_end):
        need(type(scope) is Scope and type(premises) is NativePremises, 'witness-types')
        need(all(type(v) is bool and v for v in premises.__dict__.values()), 'native-premise-missing')
        need(type(scope.pid) is int and scope.pid > 0 and type(parent_pid) is int and parent_pid > 0,
             'witness-owner')
        need(type(scope.uid) is int and scope.uid > 0 and type(scope.gid) is int and scope.gid > 0,
             'witness-credentials')
        need(scope.kernel_commit == 'adc218676eef25575469234709c2d87185ca223a', 'kernel-scope')
        need(len(scope.executable) == 8 and scope.executable[4:] == (0,0,0o755,1), 'held-executable-custody')
        need(scope.argv != scope.shim_argv and scope.argv[0] == '/usr/bin/gpg-agent', 'distinct-current-argv')
        need(all(type(x) in (int,float) and math.isfinite(x) for x in (work_end,cleanup_end))
             and work_end < cleanup_end, 'original-endpoints')
        self.scope, self.parent = scope, parent_pid
        self.work_end, self.cleanup_end = work_end, cleanup_end
        self.phase, self.first_cause, self.uncertain = 'RESERVED', None, False
        self.integrity = True
        self.last_now = -1
        self.listener, self.pidfd = None, None
        self.initial_id, self.birth_checked, self.brk_id = None, False, None
        self.consumed_ids, self.closed = set(), False

    def fail(self, code, compromise=True):
        if self.first_cause is None:
            self.first_cause = code
        self.uncertain = True
        if compromise:
            self.integrity = False
        raise Refused(code)

    def live(self, now, cleanup=False):
        if type(now) not in (int,float) or not math.isfinite(now) or now < 0 or now < self.last_now:
            self.fail('witness-clock-refused')
        self.last_now = now
        if now >= (self.cleanup_end if cleanup else self.work_end):
            self.fail('witness-deadline',compromise=False)

    def work(self, now):
        self.live(now)
        if not self.integrity or self.uncertain or self.closed:
            self.fail('witness-work-refused')

    def handoff(self, listener, *, nonce, generation, credentials, rights_count, flags, now):
        self.work(now)
        if not (self.phase == 'RESERVED' and type(listener) is object and rights_count == 1
                and type(rights_count) is int and type(flags) is int and flags == 0 and nonce == self.scope.nonce and generation == self.scope.generation
                and credentials == (self.scope.pid,self.scope.uid,self.scope.gid)):
            self.fail('listener-custody')
        self.listener, self.phase = listener, 'LISTENER'

    def notification(self, token, n, now):
        self.work(now)
        if not (token is self.listener and not self.closed and type(n) is Notification
                and type(n.identifier) is int and n.identifier > 0 and n.identifier not in self.consumed_ids
                and type(n.flags) is int and n.flags == 0 and type(n.pid) is int and n.pid == self.scope.pid and n.arch == ARCH
                and len(n.args) == 6 and all(type(a) is int and 0 <= a < 2**64 for a in n.args)):
            self.fail('notification-custody')

    def observe(self, row, argv, initial=False):
        if not (type(row) is Observed and all(type(x) is int for x in (row.pid,row.start,row.ppid,row.group,row.session,row.tracer_pid,row.seccomp_mode,row.seccomp_filters))
                and type(row.uid) is tuple and type(row.gid) is tuple and type(row.argv) is tuple
                and all(type(x) is int for x in row.uid+row.gid) and all(type(x) is str for x in row.argv)
                and row.pid == self.scope.pid and row.start == self.scope.start
                and row.group == row.session == row.pid and row.uid == (self.scope.uid,)*4
                and row.gid == (self.scope.gid,)*4 and row.argv == argv and row.state not in ('Z','X')
                and row.tracer_pid == 0 and row.seccomp_mode == 2 and row.seccomp_filters >= 1
                and (not initial or row.ppid == self.parent)):
            self.fail('current-observation-refused')

    def initial(self, token, n, row, now):
        self.notification(token,n,now)
        if not (self.phase == 'LISTENER' and n.syscall == EXECVEAT and n.args[0] == EXEC_FD
                and n.args[4] == EMPTY_PATH):
            self.fail('initial-exec-refused')
        self.observe(row,self.scope.shim_argv,initial=True)
        self.initial_id, self.phase = n.identifier, 'INITIAL_SUSPENDED'

    def acquire_birth(self, token, identifier, pidfd, *, valid_before, valid_after, no_reply_between, now):
        self.work(now)
        # Native bridge order: ioctl(ID_VALID), pidfd_open(Popen.pid), SAME ioctl(ID_VALID).
        # A failed second check closes possibly foreign pidfd WITHOUT signalling it.
        if not (token is self.listener and self.phase == 'INITIAL_SUSPENDED' and identifier == self.initial_id
                and type(pidfd) is object and self.pidfd is None and not self.birth_checked and valid_before is True and valid_after is True
                and no_reply_between is True):
            self.fail('birth-proof-refused')
        self.pidfd, self.birth_checked = pidfd, True

    def continue_initial(self, token, identifier, *, send_succeeded, now):
        self.work(now)
        if not (token is self.listener and self.phase == 'INITIAL_SUSPENDED' and self.birth_checked
                and identifier == self.initial_id and send_succeeded is True):
            self.fail('continue-refused')
        self.consumed_ids.add(identifier)
        self.phase = 'CONTINUED'  # Definitely NOT image proof or successful exec.

    def post_exec(self, token, n, row, *, valid_before, valid_after, pidfd_unreadable_before, pidfd_unreadable_after, now):
        self.notification(token,n,now)
        if not (self.phase == 'CONTINUED' and n.syscall == BRK and valid_before is True
                and valid_after is True and pidfd_unreadable_before is True and pidfd_unreadable_after is True):
            self.fail('successful-exec-witness-missing')
        self.observe(row,self.scope.argv)
        # Raw static shim's post-filter failed-exec path cannot issue brk.
        # Suspended brk proves return to user mode in selected new ELF image.
        self.brk_id, self.phase = n.identifier, 'IMAGE_PROVED'

    def release_brk(self, token, identifier, *, send_succeeded, now):
        self.work(now)
        if not (token is self.listener and self.phase == 'IMAGE_PROVED' and identifier == self.brk_id
                and send_succeeded is True):
            self.fail('brk-release-refused')
        self.consumed_ids.add(identifier)
        self.phase = 'BOUND'

    def guard(self, token, pidfd, row, *, nodes_unchanged, policy_unchanged, pidfd_unreadable_before, pidfd_unreadable_after, now, cleanup=False):
        self.live(now,cleanup)
        if not (token is self.listener and pidfd is self.pidfd and self.phase == 'BOUND'
                and not self.closed and self.integrity and (cleanup or not self.uncertain) and nodes_unchanged is True and policy_unchanged is True
                and pidfd_unreadable_before is True and pidfd_unreadable_after is True):
            self.fail('active-image-proof-refused')
        self.observe(row,self.scope.argv)
        # A distinct typed proof, NOT a fabricated /proc/exe row.
        return ('MONOTONIC_EXEC_WITNESS_V1',self.scope.executable,self.scope.source,
                self.scope.policy,self.scope.nonce,self.scope.generation)

    def later(self, token, n, now):
        self.notification(token,n,now)
        if self.phase != 'BOUND':
            self.fail('out-of-order-notification')
        self.consumed_ids.add(n.identifier)
        if n.syscall == EXECVEAT:
            return ('ERROR',-1)  # Never CONTINUE after the single initial attempt.
        if n.syscall == BRK:
            return ('CONTINUE',0)
        self.fail('unexpected-filter-notification')

    def eof(self, now):
        self.work(now)
        self.fail('EOF-is-not-exec-success')

    def cancel(self, now):
        self.live(now,cleanup=True)
        self.fail('cancelled',compromise=False)

    def closure(self, *, close_succeeded, task_terminated, pidfd_matches, now):
        self.live(now,cleanup=True)
        if not (close_succeeded is True and task_terminated is True and pidfd_matches is self.pidfd
                and self.pidfd is not None):
            self.fail('closure-uncertain')
        self.closed, self.phase = True, 'TERMINATED'
        # Cancellation/first cause/sticky uncertainty is never cleared.
        return dict(task_absent=True,signer_recovery_pass=False,keyhome_absent=False)

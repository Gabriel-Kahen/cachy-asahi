# SPDX-License-Identifier: MIT
"""Pure proposal only: runtime adapter must supply actual suspended-thread facts.

No proc reads, syscalls, actors, or serialized-proof admission. This supplements
Root's leader/image/custody controller; it never grants exec continuation.
"""
from dataclasses import dataclass

ARCH, BRK, EXECVEAT = 0xc00000b7, 214, 281


class Refused(ValueError):
    pass


@dataclass(frozen=True)
class ThreadRow:
    tid: int            # /proc/TID/stat pid
    tgid: int           # /proc/TID/status Tgid, never inferred from tid
    group: int
    session: int
    uid: tuple
    gid: tuple
    state: str
    tracer_pid: int
    seccomp_mode: int
    seccomp_filters: int


def admit_thread_notification(n, row, *, leader, uid, gid, listener, expected_listener,
                              pidfd, expected_pidfd, phase, valid_before, valid_after,
                              group_pidfd_live_before, group_pidfd_live_after, shim_no_clone_or_brk_proved,
                              initial_continuations):
    """Only a currently pending same-TGID syscall can advance post-exec state.

Native adapter order under exclusive controller lock: validate ID, poll owner-held group pidfd, read actual
thread stat/status, poll the same group pidfd again, validate same ID again; no
response/reply or token replacement between these operations. Root must retain
original endpoints, nonce/generation and first-cause state around this helper.
"""
    good = (type(n) is dict and set(n) == {'id','tid','arch','nr','args','flags'}
            and type(row) is ThreadRow and type(leader) is int and leader > 0
            and type(uid) is int and uid > 0 and type(gid) is int and gid > 0
            and type(listener) is object and listener is expected_listener
            and type(pidfd) is object and pidfd is expected_pidfd
            and valid_before is True and valid_after is True
            and group_pidfd_live_before is True and group_pidfd_live_after is True
            and type(initial_continuations) is int and initial_continuations == 1
            and phase in ('CONTINUED','IMAGE_PROVED','BOUND'))
    if not good:
        raise Refused('thread-custody')
    if not (all(type(n[k]) is int for k in ('id','tid','arch','nr','flags'))
            and n['id'] > 0 and n['tid'] > 0 and n['arch'] == ARCH and n['flags'] == 0
            and type(n['args']) is tuple and len(n['args']) == 6
            and all(type(a) is int and 0 <= a < 2**64 for a in n['args'])
            and all(type(v) is int for v in (row.tid,row.tgid,row.group,row.session,
                                            row.tracer_pid,row.seccomp_mode,row.seccomp_filters))
            and type(row.uid) is tuple and type(row.gid) is tuple
            and all(type(v) is int for v in row.uid + row.gid)
            and row.tid == n['tid'] and row.tgid == leader
            and row.group == row.session == leader
            and row.uid == (uid,)*4 and row.gid == (gid,)*4
            and row.state in ('R','S','D','T','t','I') and row.tracer_pid == 0
            and row.seccomp_mode == 2 and row.seccomp_filters >= 1):
        raise Refused('thread-observation')
    if n['nr'] == EXECVEAT:
        return 'DENY_EXEC'  # even leader/fd197/expected argv can never exec again
    if n['nr'] != BRK:
        raise Refused('unexpected-thread-notification')
    if phase == 'CONTINUED':
        if shim_no_clone_or_brk_proved is not True:
            raise Refused('shim-first-witness-premise')
        return 'SUSPENDED_POST_EXEC_WITNESS'  # no syscall response or image fabrication
    return 'CONTINUE_BRK_ELIGIBLE'  # Root state/deadline/cancel gate still required


def require_initial_leader(n, leader):
    """Supplement to existing initial exec checks; no thread can get CONTINUE."""
    if not (type(leader) is int and leader > 0 and type(n) is dict
            and type(n.get('tid')) is int and n['tid'] == leader
            and type(n.get('nr')) is int and n['nr'] == EXECVEAT):
        raise Refused('initial-exec-not-leader')

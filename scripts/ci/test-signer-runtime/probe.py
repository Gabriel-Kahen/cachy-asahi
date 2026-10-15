# SPDX-License-Identifier: MIT
"""Minimal signer-only event/cleanup Source. Root-dispatched methods only.

No key generation/signing commands, production adoption, or standalone CLI. Root
supplies Source-admitted model/thread classes and actual custody/disposal guards.
"""


def need(value,reason):
    if not value:raise ValueError(reason)


def convert(row,observed_type):
    keys=('pid','start','ppid','group','session','uid','gid','argv','state','tracer_pid','seccomp_mode','seccomp_filters')
    return observed_type(**{k:row[k] for k in keys})


def wire(n,notification_type):
    return notification_type(n['id'],n['tid'],n['arch'],n['nr'],n['args'],n['flags'])


def own_guard(io,witness,listener,pidfd,observed_type,custody_guard,end,*,cleanup=False):
    """Both original-task checks bracket all proc reads and custody inspection."""
    with io.lock:
        before=io.live_pidfd(pidfd);need(before,'original-dead-before-guard')
        row=io.read_proc(witness.scope.pid,end,command_line=True,cleanup=cleanup)
        need(row['tgid']==witness.scope.pid,'leader-TGID')
        nodes,policy=custody_guard(end)
        after=io.live_pidfd(pidfd);need(after,'original-dead-after-guard')
        return witness.guard(listener.token,pidfd.token,convert(row,observed_type),
            nodes_unchanged=nodes,policy_unchanged=policy,
            pidfd_unreadable_before=before,pidfd_unreadable_after=after,
            now=io.live(end,cleanup=cleanup),cleanup=cleanup)


def run(io,running,listener,*,make_witness,notification_type,observed_type,
        thread_row_type,thread_admission,custody_guard,dispose_verified,work_end,cleanup_end,
        deadline_exception_type,idle_exception_type,cancel_exception_type,proof_exception_types=()):
    """Caller has authentic SCM handoff and opaque compiled/kernel custody grant.

    make_witness consumes the ACTUAL initial suspended leader row, not expected
    executable observations. It binds Source/policy/nonces/inodes/held-file data.
    """
    result=dict(status='FAIL',availability='CHECKED_SEPARATELY',first_cause=None,cancelled=False,
        initial_exec_attempted=False,image_witness=False,current_guard=False,idle_expired=False,task_absent=False,
        keyhome_absent=False,socket_absent=False,full_signer_api_acceptance=False,
        thread_compatibility='NOT ESTABLISHED',native_addon_acceptance=False)
    witness=None;pidfd=None;proof_intact=False
    def fail(error):
        if result['first_cause'] is None:
            if type(error) is cancel_exception_type or isinstance(error,KeyboardInterrupt):kind='CANCELLED'
            elif type(error) in (OSError,PermissionError,FileNotFoundError,ProcessLookupError,InterruptedError,TimeoutError):kind='IO_FAILED'
            elif type(error) in (ValueError,*proof_exception_types,deadline_exception_type):kind='PROOF_REFUSED'
            else:kind='OTHER'
            result['first_cause']=kind
        result['cancelled']=result['cancelled'] or type(error) is cancel_exception_type or isinstance(error,KeyboardInterrupt)
    try:
        need(idle_exception_type is not deadline_exception_type
             and idle_exception_type is not cancel_exception_type,'distinct-idle-exception-required')
        n=io.receive(listener,work_end)
        need(n['tid']==running.pid and n['nr']==281,'initial-exec-leader-only')
        with io.lock:
            need(io.valid(listener,n['id']),'initial-observation-pre-ID')
            row=io.read_proc(running.pid,work_end,command_line=True)
            need(io.valid(listener,n['id']),'initial-observation-post-ID')
            witness=make_witness(row)
            witness.handoff(listener.token,nonce=witness.scope.nonce,generation=witness.scope.generation,
                credentials=(running.pid,witness.scope.uid,witness.scope.gid),rights_count=1,flags=0,
                now=io.live(work_end))
            witness.initial(listener.token,wire(n,notification_type),convert(row,observed_type),io.live(work_end))
            pidfd=io.birth(listener,n,running,work_end)
            witness.acquire_birth(listener.token,n['id'],pidfd.token,valid_before=True,valid_after=True,
                                  no_reply_between=True,now=io.live(work_end))
            io.send(listener,n['id'],proceed=True,end=work_end)
            witness.continue_initial(listener.token,n['id'],send_succeeded=True,now=io.live(work_end))
            result['initial_exec_attempted']=True
        n=io.receive(listener,work_end)
        # This first probe is deliberately narrower than the optional thread helper.
        # A leader brk witness is required; a thread-first event remains REFUSED.
        need(n['tid']==running.pid and n['nr']==214,'first-witness-must-be-leader-brk')
        row,bracket=io.bracket(pidfd,running.pid,work_end,listener=listener,identifier=n['id'])
        need(row['tgid']==running.pid,'post-exec-leader-TGID')
        witness.post_exec(listener.token,wire(n,notification_type),convert(row,observed_type),
                          **bracket,now=io.live(work_end))
        io.send(listener,n['id'],proceed=True,end=work_end)
        witness.release_brk(listener.token,n['id'],send_succeeded=True,now=io.live(work_end))
        result['image_witness']=True;proof_intact=True
        own_guard(io,witness,listener,pidfd,observed_type,custody_guard,work_end)
        result['current_guard']=True
        # One short, caller-reserved observation interval, never a new endpoint.
        # Notification service is meaningful but does NOT test GPG signing API.
        while True:
            # Only this adapter-proved no-event completion is expected. General
            # deadlines after readiness/RECV or in a guard/send remain failures.
            try:n=io.receive(listener,work_end,idle=True)
            except idle_exception_type as error:
                need(type(error) is idle_exception_type and result['current_guard']
                     and error.args==('native-original-idle-deadline',),'idle-completion-proof-refused')
                result['idle_expired']=True
                break
            own_guard(io,witness,listener,pidfd,observed_type,custody_guard,work_end)
            if n['tid']==running.pid:
                action=witness.later(listener.token,wire(n,notification_type),io.live(work_end))
                io.send(listener,n['id'],proceed=action[0]=='CONTINUE',error=action[1],end=work_end)
            else:
                row,bracket=io.bracket(pidfd,n['tid'],work_end,listener=listener,identifier=n['id'])
                thread=thread_row_type(tid=row['pid'],tgid=row['tgid'],group=row['group'],session=row['session'],
                    uid=row['uid'],gid=row['gid'],state=row['state'],tracer_pid=row['tracer_pid'],
                    seccomp_mode=row['seccomp_mode'],seccomp_filters=row['seccomp_filters'])
                action=thread_admission(n,thread,leader=running.pid,uid=witness.scope.uid,gid=witness.scope.gid,
                    listener=listener.token,expected_listener=witness.listener,pidfd=pidfd.token,
                    expected_pidfd=witness.pidfd,phase=witness.phase,
                    valid_before=bracket['valid_before'],valid_after=bracket['valid_after'],
                    group_pidfd_live_before=bracket['pidfd_unreadable_before'],
                    group_pidfd_live_after=bracket['pidfd_unreadable_after'],
                    shim_no_clone_or_brk_proved=True,initial_continuations=1)
                witness.work(io.live(work_end))
                need(n['id'] not in witness.consumed_ids,'thread-ID-replay')
                witness.consumed_ids.add(n['id'])
                io.send(listener,n['id'],proceed=action=='CONTINUE_BRK_ELIGIBLE',
                        error=-1 if action=='DENY_EXEC' else 0,end=work_end)
    except BaseException as error:
        fail(error)
        if witness is not None and result['cancelled']:
            try:witness.cancel(io.time.monotonic())
            except BaseException:pass
    finally:
        try:
            if pidfd is not None and not io.live_pidfd(pidfd):
                result['task_absent']=True  # exact original group, no current PID lookup
            elif pidfd is not None and proof_intact:
                own_guard(io,witness,listener,pidfd,observed_type,custody_guard,cleanup_end,cleanup=True)
                result['task_absent']=io.terminate(pidfd,cleanup_end)
            # Never signal a guessed PID or an fd from failed birth validation.
            if result['task_absent']:
                io.close(listener)
                # Existing exact node/socket/journal disposal remains mandatory.
                removed=dispose_verified(cleanup_end)
                need(type(removed) is dict and set(removed)=={'keyhome_absent','socket_absent'}
                     and all(type(v) is bool for v in removed.values()),'disposal-observation')
                result.update(removed)
            elif listener is not None:
                io.close(listener)  # no exec permission; no absence inference
        except BaseException as error:fail(error)
        finally:
            if pidfd is not None:
                try:io.close(pidfd)
                except BaseException as error:fail(error)
            if io.close_uncertain:result['first_cause']=result['first_cause'] or 'OwnedCloseUncertain'
    try:
        if io.cancelled():
            result['cancelled']=True
            result['first_cause']=result['first_cause'] or 'CANCELLED'
    except BaseException as error:fail(error)
    if (result['image_witness'] and result['current_guard'] and result['idle_expired'] and result['task_absent']
        and result['keyhome_absent'] and result['socket_absent'] and not result['cancelled']
        and result['first_cause'] is None):result['status']='PASS_FIRST_EXEC_AND_OWNED_CLEANUP_ONLY'
    return result

# SPDX-License-Identifier: MIT
"""Native probe bootstrap Source; Root API only, never self-issues admission."""
from pathlib import Path

FLAGS=('-O2','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-pie','-no-pie',
       '-fno-tree-loop-distribute-patterns','-nostdlib','-static','-Wl,-e,_start,--build-id=none,-z,max-page-size=65536')
_QUARANTINED_TRANSFERS=[]


def need(value,code):
    if not value:raise ValueError(code)


def build_source(builder,*,admission,expected_admission,compiler,source_directory,output,
                 endpoint,supported_thread_requirements=None,expected_thread_requirements=None,
                 thread_bindings=None,expected_thread_bindings=None):
    """Compiler Runner and output custody are separately Root-admitted actors.

    Returns only the actual builder result. The caller must hash/hold/audit the
    resulting ELF and mint its own native capability before any launch.
    """
    need(type(admission) is object and admission is expected_admission,'build-admission')
    source_directory,output=Path(source_directory),Path(output)
    need(output.parent==source_directory and not output.exists(),'fresh-private-build-output')
    flags=FLAGS
    if supported_thread_requirements is not None:
        need(type(supported_thread_requirements) is object
             and supported_thread_requirements is expected_thread_requirements
             and type(thread_bindings) is dict and thread_bindings==expected_thread_bindings
             and set(thread_bindings)=={'gpg_sha256','npth_sha256','glibc_sha256','gpg_source_revision',
                 'npth_source_revision','glibc_source_revision','source_build_binding_sha256','review_receipt_sha256','legacy_flags'}
             and thread_bindings['legacy_flags']==0x003d0f00
             and all(type(v) is str and len(v)==(40 if k.endswith('_source_revision') else 64) and all(c in '0123456789abcdef' for c in v)
                     for k,v in thread_bindings.items() if k!='legacy_flags'),
             'held-GPG-npth-libc-requirements-review')
        flags+=('-DWITNESS_SUPPORTED_THREADS',)
    return builder.run([compiler,*flags,str(source_directory/'witness_shim.c'),'-o',str(output)],
                       deadline=endpoint,environment='ROOT_PINNED_COMPILER_ENVIRONMENT')


def spawn(io,*,compiled_shim,held_agent,agent_listener,home,nonce,environment,setup,endpoint,
          admission,expected_admission):
    """Fixed fd duplication never overwrites a pre-existing (possibly foreign) fd."""
    need(type(admission) is object and admission is expected_admission,'launch-admission')
    import subprocess
    io.live(endpoint)
    need(not _QUARANTINED_TRANSFERS,'earlier-transfer-close-uncertain')
    need(io.agent_attempted is False,'agent-already-attempted')
    control,child=io.socket.socketpair(io.socket.AF_UNIX,io.socket.SOCK_SEQPACKET)
    copies=[];primary=None
    io.running=None;io.control=control
    try:
        physical=io.os.fstat(control.fileno())
        io.control_identity=(physical.st_dev,physical.st_ino,physical.st_mode,
                             physical.st_uid,physical.st_gid,physical.st_nlink)
        control.setsockopt(io.socket.SOL_SOCKET,io.socket.SO_PASSCRED,1)
        for original,wanted in ((agent_listener.fileno(),194),(child.fileno(),196),
                                (io.held(held_agent,'agent-executable'),197)):
            fd=io.fcntl.fcntl(original,io.fcntl.F_DUPFD_CLOEXEC,wanted)
            copies.append(fd);need(fd==wanted,'reserved-fd-occupied')
        shim_fd=io.held(compiled_shim,'compiled-shim')
        # Both executable launches use held descriptors; no mutable-shim pathname.
        argv=['TEST_EXEC_WITNESS_SHIM',str(home),nonce]
        io.agent_attempted=True
        running=subprocess.Popen(argv,executable='/proc/self/fd/'+str(shim_fd),
            pass_fds=(*copies,shim_fd),close_fds=True,start_new_session=True,
            preexec_fn=setup,env=environment,stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        io.running=running
        return running,control,tuple(argv)
    except BaseException as error:
        primary=error
        if io.running is None:
            io.control_retired=True
            try:
                physical=io.os.fstat(control.fileno())
                need((physical.st_dev,physical.st_ino,physical.st_mode,physical.st_uid,
                      physical.st_gid,physical.st_nlink)==io.control_identity,'transfer-FD-custody')
                control.close()
            except BaseException:
                io.close_uncertain=True
                try:control.detach()
                except BaseException:_QUARANTINED_TRANSFERS.append(control)
        raise
    finally:
        try:child.close()
        except BaseException:io.close_uncertain=True
        for fd in copies:
            try:io.os.close(fd)
            except BaseException:io.close_uncertain=True


def availability(io,*,compiled_shim,environment,setup,endpoint,cleanup_end,
                 held_fd_type,admission,expected_admission):
    """One helper, no competing reaper/child creation; ECHILD never means absence.

    Birth is checked by positive/raw child wait semantics on both sides of
    pidfd_open. Cleanup signals additionally require actual helper exe inode,
    actual argv/credentials/session and fresh original-pidfd brackets.
    """
    need(type(admission) is object and admission is expected_admission,'availability-admission')
    import subprocess
    fd=io.held(compiled_shim,'compiled-shim');io.live(endpoint)
    expected=io.os.fstat(fd);owner=(io.os.getuid(),io.os.getgid())
    need(io.helper_attempted is False,'availability-already-attempted')
    io.helper_attempted=True
    running=subprocess.Popen(['TEST_EXEC_WITNESS_ABI'],executable='/proc/self/fd/'+str(fd),
        pass_fds=(fd,),close_fds=True,start_new_session=True,preexec_fn=setup,env=environment,
        stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    io.running=running
    result=dict(status='REFUSED',exit_code=None,direct_child_wait_observed=False,
                task_absent=False,full_signer_acceptance=False)
    pidfd=None;first=None
    def waited():
        pid,status=io.os.waitpid(running.pid,io.os.WNOHANG)
        if not pid:
            io.live(endpoint);return False
        need(pid==running.pid,'availability-child-identity')
        running.returncode=io.os.waitstatus_to_exitcode(status)
        result.update(exit_code=running.returncode,direct_child_wait_observed=True,task_absent=True)
        io.helper_task_absent=True
        io.live(endpoint) # preserve the physical wait result, refuse late availability
        return True
    try:
        with io.lock:
            if not waited():
                handle=io.os.pidfd_open(running.pid,0)
                try:
                    # No other child creation/reply/reaping may occur in this interval.
                    # Second 0 => same unreaped live child; positive wait => exact exited child.
                    exited=waited()
                    pidfd=held_fd_type(handle,io.owner,io.generation,'pidfd')
                except BaseException:
                    try:io.os.close(handle)
                    except BaseException:io.close_uncertain=True
                    raise
            while not result['task_absent']:
                io.live(endpoint)
                if waited():break
                io.select.select([],[],[],min(.02,endpoint-io.time.monotonic()))
        if result['exit_code']==0:result['status']='AVAILABLE'
    except BaseException as error:first=error
    finally:
        try:
            if pidfd is not None and not result['task_absent']:
                if not io.live_pidfd(pidfd):
                    result['task_absent']=True;io.helper_task_absent=True
                else:
                    with io.lock:
                        need(io.live_pidfd(pidfd),'availability-original-dead')
                        row=io.read_proc(running.pid,cleanup_end,command_line=True,cleanup=True)
                        # This unhardended ABI helper can be observed directly. Refuse denial.
                        io.os.readlink('/proc/'+str(running.pid)+'/exe')
                        executable=io.os.stat('/proc/'+str(running.pid)+'/exe')
                        need((executable.st_dev,executable.st_ino)==(expected.st_dev,expected.st_ino)
                             and row['pid']==row['tgid']==row['group']==row['session']==running.pid
                             and row['ppid']==io.os.getpid() and row['uid']==(owner[0],)*4
                             and row['gid']==(owner[1],)*4 and row['argv']==('TEST_EXEC_WITNESS_ABI',)
                             and row['tracer_pid']==0 and io.live_pidfd(pidfd),'availability-execution-identity')
                        result['task_absent']=io.terminate(pidfd,cleanup_end)
                        if result['task_absent']:io.helper_task_absent=True
        except BaseException as error:
            if first is None:first=error
        finally:
            if pidfd is not None:
                try:io.close(pidfd)
                except BaseException as error:
                    if first is None:first=error
    if first is not None or io.close_uncertain:result['status']='REFUSED'
    # Runtime caller records the original closed cause separately; never stringifies it.
    return result,first

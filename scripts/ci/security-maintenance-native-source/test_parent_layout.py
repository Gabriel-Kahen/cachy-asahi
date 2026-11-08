"""New HOST-only private launcher controls. No repository Source import or native actor."""
import argparse
import ast
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import select
import signal
import shlex
import sys
import stat
import time

HERE=Path(__file__).resolve().parent
OUT=None
SUPERVISOR_BYTES=b'# SPDX-License-Identifier: MIT\n"""Linux child-group supervision: reserve the leader until signaling is over."""\nimport math\nimport os\nimport resource\nimport signal\nimport subprocess\nimport time\n\nRETIRE_SECONDS = 5\nTICK = 0.025\nPROC_LIMIT = 131072\n\n\ndef _stat(raw):\n    """Decode only PID/state/pgrp/session/starttime from bounded proc stat DATA."""\n    if type(raw) is not bytes or len(raw) > 4096:\n        raise ValueError(\'bounded proc stat required\')\n    head, separator, tail = raw.rpartition(b\')\')\n    fields = tail.split()\n    if not separator or b\'(\' not in head or len(fields) < 20:\n        raise ValueError(\'complete proc stat required\')\n    return (int(head.split(b\'(\', 1)[0]), fields[0], int(fields[2]),\n            int(fields[3]), int(fields[19]))\n\n\ndef _read_stat(pid):\n    fd = os.open(\'/proc/\' + str(pid) + \'/stat\', os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)\n    try:\n        return _stat(os.read(fd, 4097))\n    finally:\n        os.close(fd)\n\n\ndef _members(pid, started, deadline, live=False, reserved=False):\n    """One finite proc observation; unknown/read failures never mean absence."""\n    if reserved:\n        leader = _read_stat(pid)\n        if (leader[0], leader[2], leader[3], leader[4]) != (pid, pid, pid, started):\n            raise ValueError(\'reserved leader/session identity differs\')\n    result = set()\n    with os.scandir(\'/proc\') as entries:\n        for count, entry in enumerate(entries, 1):\n            if count > PROC_LIMIT or time.monotonic() >= deadline:\n                raise TimeoutError(\'bounded complete proc membership scan\')\n            if not entry.name.isascii() or not entry.name.isdecimal():\n                continue\n            try:\n                row = _read_stat(int(entry.name))\n            except ProcessLookupError:\n                continue\n            except FileNotFoundError:\n                continue\n            if row[0] != int(entry.name):\n                raise ValueError(\'proc member identity differs\')\n            if row[2:4] == (pid, pid) and not (live and row[1] in (b\'Z\', b\'X\')):\n                result.add((row[0], row[4], row[1]))\n    return result\n\n\ndef _limit():\n    resource.setrlimit(resource.RLIMIT_FSIZE, (512 * 1024**2, 512 * 1024**2))\n\n\ndef supervise(command, *, cwd, env, stdout, stderr, lock_fd, cap):\n    """Return bounded supervisor DATA; never unlock or close the caller\'s lease.\n\n    stdout/stderr are already-open handles. The caller owns this child\'s wait\n    status and must keep SIGCHLD at SIG_DFL. No poll/wait can release its PID\n    before the final group-signaling decision. Proc absence requires two empty\n    observations, including after reaping; it is process-group scope only.\n    """\n    start = time.monotonic()\n    child = None\n    deadline = start\n    leader_start = None\n    terminal = False\n    reserved = False\n    reservation_intact = False\n    ownership_lost = False\n    reaping = False\n    reaped = False\n    forced = False\n    timed_out = False\n    absent = False\n    code = None\n    terminal_code = None\n    error = None\n\n    def failure(exc):\n        nonlocal error\n        if error is None:\n            try:message = str(exc)[:500]\n            except BaseException:message = \'exception message unavailable\'\n            error = {\'type\': type(exc).__name__, \'message\': message}\n\n    def pause(until):\n        remaining = until - time.monotonic()\n        if remaining > 0:\n            time.sleep(min(TICK, remaining))\n\n    def peek():\n        nonlocal reserved, reservation_intact, ownership_lost, terminal_code\n        try:\n            row = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG)\n        except ChildProcessError:\n            reserved = False\n            reservation_intact = False\n            ownership_lost = True\n            raise ValueError(\'child wait ownership lost; group signaling refused\')\n        if row is None:\n            return False\n        if row.si_pid != child.pid or row.si_code not in (os.CLD_EXITED, os.CLD_KILLED, os.CLD_DUMPED):\n            raise ValueError(\'unexpected WNOWAIT child status\')\n        observed = row.si_status if row.si_code == os.CLD_EXITED else -row.si_status\n        if terminal_code is not None and terminal_code != observed:\n            raise ValueError(\'reserved terminal status changed\')\n        terminal_code = observed\n        return True\n\n    def members(live):\n        return _members(child.pid, leader_start, deadline, live=live, reserved=reserved)\n\n    def send(sig):\n        nonlocal forced, leader_start\n        if reaping or not reserved:\n            raise ValueError(\'group signaling after PID release refused\')\n        peek()  # ECHILD invalidates the reservation before any signal.\n        leader = _read_stat(child.pid)\n        if (leader[0], leader[2], leader[3]) != (child.pid, child.pid, child.pid):\n            raise ValueError(\'signaling requires the reserved exact session/group\')\n        if leader_start is not None and leader[4] != leader_start:\n            raise ValueError(\'reserved leader start identity changed\')\n        leader_start = leader[4]\n        forced = True\n        try:\n            os.killpg(child.pid, sig)\n        except ProcessLookupError:\n            pass\n\n    def await_terminal(until):\n        while time.monotonic() < until:\n            if peek():\n                return True\n            pause(until)\n        return peek() if time.monotonic() < deadline else False\n\n    def reap_and_observe():\n        nonlocal code, reaping, reserved, reaped, absent\n        # Once wait starts, even an interrupted/failed wait may have released\n        # the PID. No exception path may signal that numeric group again.\n        reaping = True\n        reserved = False\n        code = child.wait(timeout=max(0, deadline - time.monotonic()))\n        reaped = True\n        if type(code) is not int or code != terminal_code:\n            raise ValueError(\'reaped exit differs from reserved terminal status\')\n        empty = 0\n        while time.monotonic() < deadline:\n            empty = empty + 1 if not members(False) else 0\n            if empty == 2:\n                absent = True\n                return\n            pause(deadline)\n        raise TimeoutError(\'group absence not confirmed within cap after reap\')\n\n    try:\n        if (type(cap) not in (int, float) or not math.isfinite(cap) or cap <= RETIRE_SECONDS\n                or type(lock_fd) is not int or lock_fd < 0\n                or type(command) not in (tuple, list) or not command\n                or any(type(part) is not str or not part or \'\\x00\' in part for part in command)):\n            raise ValueError(\'typed finite cap/argv/inherited lock descriptor required\')\n        if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:\n            raise ValueError(\'exclusive SIG_DFL child wait ownership required\')\n        deadline = start + cap\n        run_deadline = deadline - RETIRE_SECONDS\n        child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=stdout,\n                                 stderr=stderr, cwd=cwd, env=env,\n                                 start_new_session=True, pass_fds=(lock_fd,),\n                                 preexec_fn=_limit)\n        reserved = True\n        reservation_intact = True\n        leader = _read_stat(child.pid)\n        if (leader[0], leader[2], leader[3]) != (child.pid, child.pid, child.pid):\n            raise ValueError(\'child must own its exact new group and session\')\n        leader_start = leader[4]\n        while time.monotonic() < run_deadline:\n            terminal = peek()\n            if terminal:\n                break\n            pause(run_deadline)\n        terminal = peek()\n        timed_out = not terminal or time.monotonic() >= run_deadline\n        live = members(True)\n        if not terminal or live:\n            send(signal.SIGTERM)\n            grace = min(deadline - 2, time.monotonic() + 2)\n            while time.monotonic() < grace:\n                terminal = peek()\n                live = members(True)\n                if terminal and not live:\n                    break\n                pause(grace)\n            terminal = peek()\n            live = members(True)\n            if not terminal or live:\n                send(signal.SIGKILL)\n        terminal = await_terminal(deadline - 0.1)\n        if terminal:\n            reap_and_observe()\n        else:\n            raise TimeoutError(\'child terminal status/reap not confirmed within cap\')\n    except BaseException as exc:\n        failure(exc)\n        if child is not None and not ownership_lost and not reaping:\n            try:\n                # Also covers interruption immediately after Popen assigned the\n                # child but before the following reservation bookkeeping.\n                reserved = True\n                reservation_intact = True\n                send(signal.SIGKILL)\n                if await_terminal(deadline - 0.1):\n                    reap_and_observe()\n            except BaseException as cleanup:\n                failure(cleanup)\n    seconds = time.monotonic() - start\n    return dict(exit=code, timeout=timed_out, group_absent=absent,\n                forced_retirement=forced, reaped=reaped,\n                pid_reserved_until_retirement=reservation_intact,\n                seconds=seconds, error=error,\n                passed=type(code) is int and code == 0 and not timed_out and not forced\n                and reaped and absent and error is None and seconds < cap)\n'
EXPECTED_HELPER_SHA='f662e720612d044dabdd04d8d7f2305fc01dd7431c28acf2f6cb4d0889a2b28c'
SUPERVISOR_SHA='bd165fcc806c2951698cc16e1610ffb12a0da95404b5c99aaf3cdc067c1ea0e4'
SOURCE_HELPER='/opt/native-security-v1/source/native/security_native_v1.py'
MAP='a'*64
SOURCE_COMMAND='/usr/bin/python3 -I -B '+SOURCE_HELPER+' --inside-image --map-sha256 '+MAP+' & security_owner=$!; security_status=0; wait "$security_owner" || security_status=$?; exit "$security_status"'
FIXTURE=r'''import argparse,fcntl,json,os,resource,signal,stat,subprocess,sys,time
resource.setrlimit(resource.RLIMIT_AS,(256*1024**2,256*1024**2))
resource.setrlimit(resource.RLIMIT_CPU,(3,3))
resource.setrlimit(resource.RLIMIT_FSIZE,(65536,65536))
resource.setrlimit(resource.RLIMIT_NOFILE,(64,64))
def identity(fd):
 s=os.fstat(fd)
 assert stat.S_ISREG(s.st_mode)and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1 and s.st_size==0
 return dict(dev=s.st_dev,inode=s.st_ino,mode=s.st_mode,uid=s.st_uid,gid=s.st_gid,nlink=s.st_nlink,bytes=s.st_size)
if len(sys.argv)>1 and sys.argv[1]=='--leasecheck':
 fd=os.open(sys.argv[2],os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BlockingIOError:print(json.dumps(dict(independent_NB_conflict=True)));raise SystemExit(0)
  raise RuntimeError('private fixture lease conflict missing')
 finally:os.close(fd)
if len(sys.argv)>1 and sys.argv[1]=='--grandchild':
 owner,fd=int(sys.argv[2]),int(sys.argv[3]);data=sys.stdin.buffer.read(3)
 assert owner>1 and os.getppid()==owner and len(data)<=2
 print(json.dumps(dict(pid=os.getpid(),ppid=os.getppid(),owner_pid=owner,owner_gt1=True,exact_direct_parent=True,FD=identity(fd),python_executable=sys.executable,stdin_hex=data.hex())))
 raise SystemExit(0)
p=argparse.ArgumentParser();p.add_argument('--inside-image',action='store_true',required=True);p.add_argument('--map-sha256',required=True);a=p.parse_args()
assert a.map_sha256=='a'*64
case=os.environ['FIXTURE_CASE'];fd=int(os.environ['FIXTURE_FD']);owner=os.getpid();parent=os.getppid()
assert owner>1 and parent>1
parent_cmd=open('/proc/'+str(parent)+'/cmdline','rb').read(8193)
assert len(parent_cmd)<=8192 and os.environ['FIXTURE_LAUNCH_COMMAND'].encode() in parent_cmd and b'-c\0' in parent_cmd
inherited=identity(fd);records=[]
for mode in ('DEVNULL','FINITE_DECLINE'):
 options=dict(stdin=subprocess.DEVNULL)if mode=='DEVNULL'else dict(input=b'n\n')
 r=subprocess.run([sys.executable,'-I','-B',__file__,'--grandchild',str(owner),str(fd)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=3,pass_fds=(fd,),**options)
 assert r.returncode==0 and len(r.stdout)<=4096 and r.stderr==b''
 v=json.loads(r.stdout);assert v['FD']==inherited and v['ppid']==owner and v['stdin_hex']==(''if mode=='DEVNULL'else'6e0a');records.append(dict(mode=mode,result=v))
print('FIXTURE_STDOUT case='+case,flush=True);print('FIXTURE_STDERR case='+case,file=sys.stderr,flush=True)
if case=='delayed_exit0':time.sleep(.20)
print(json.dumps(dict(case=case,owner_pid=owner,parent_pid=parent,retained_shell_command_exact=True,FD=inherited,grandchildren=records,python_executable=sys.executable,delay_complete=case=='delayed_exit0')),flush=True)
if case=='self_SIGTERM':os.kill(owner,signal.SIGTERM);raise RuntimeError('self signal did not terminate')
raise SystemExit(dict(exit0=0,exit1=1,exit37=37,delayed_exit0=0)[case])
'''

def need(value,why):
    if not value:raise ValueError(why)

def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())

def save(path,value):
    with path.open('x')as stream:
        json.dump(value,stream,sort_keys=True,indent=2);stream.write('\n');stream.flush();os.fsync(stream.fileno())

def bounded(path,cap=65536):
    need(path.stat().st_size<=cap,'bounded complete fixture output')
    with path.open('rb')as stream:raw=stream.read(cap+1)
    need(len(raw)<=cap,'fixture output cap');return raw

def source_binding(path):
    path=path.absolute();need(path==path.resolve(),'canonical maintained helper DATA')
    with path.open('rb')as stream:
        before=os.fstat(stream.fileno());need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and before.st_size<=2*1024**2,'bounded ordinary helper DATA')
        raw=stream.read(before.st_size+1);after=os.fstat(stream.fileno())
    fields=('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
    need(len(raw)==before.st_size and all(getattr(before,k)==getattr(after,k)==getattr(path.stat(),k)for k in fields)and pin(raw)['sha256']==EXPECTED_HELPER_SHA,'exact current helper body')
    tree=ast.parse(raw);functions=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='dockerfile'];need(len(functions)==1,'one Dockerfile function as DATA')
    def literal(node):
        if isinstance(node,ast.Constant)and type(node.value)is str:return node.value
        if isinstance(node,ast.Name)and node.id=='map_hash':return MAP
        if isinstance(node,ast.BinOp)and isinstance(node.op,ast.Add):return literal(node.left)+literal(node.right)
        raise ValueError('only string/map literal expression DATA allowed')
    matches=[]
    for node in ast.walk(functions[0]):
        if isinstance(node,ast.AugAssign)and isinstance(node.target,ast.Name)and node.target.id=='result':
            if any(isinstance(n,ast.Constant)and type(n.value)is str and '--inside-image --map-sha256 'in n.value for n in ast.walk(node.value)):matches.append(literal(node.value))
    need(matches==['RUN '+SOURCE_COMMAND+'\n'],'exercised launcher exactly matches maintained helper DATA')
    return dict(helper=pin(raw),launcher_literal=SOURCE_COMMAND,Source_imports=0,Source_function_or_emitter_calls=0)

def main():
    global OUT
    p=argparse.ArgumentParser();p.add_argument('--execute-once',action='store_true',required=True);p.add_argument('--results',type=Path,required=True);p.add_argument('--helper',type=Path,default=HERE/'overlay/native/security_native_v1.py');args=p.parse_args()
    os.umask(0o077);OUT=args.results.absolute();need(OUT==OUT.resolve()and OUT.parent.is_dir()and stat.S_IMODE(OUT.parent.stat().st_mode)==0o700 and not OUT.exists(),'fresh private0700 parent and unused canonical HOST fixture only');binding=source_binding(args.helper);OUT.mkdir(mode=0o700)
    resource.setrlimit(resource.RLIMIT_AS,(512*1024**2,512*1024**2));resource.setrlimit(resource.RLIMIT_CPU,(30,30));resource.setrlimit(resource.RLIMIT_NOFILE,(128,128))
    need(signal.getsignal(signal.SIGCHLD)==signal.SIG_DFL,'original direct wait owner')
    raw=SUPERVISOR_BYTES;need(pin(raw)['sha256']==SUPERVISOR_SHA,'whole exact embedded existing reserved supervisor')
    supervisor=OUT/'reserved_supervisor.py'
    with supervisor.open('xb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
    supervisor.chmod(0o600)
    s=importlib.util.spec_from_file_location('_security_layout_host_supervisor',supervisor);owned=importlib.util.module_from_spec(s);s.loader.exec_module(owned)
    fixture=OUT/'harmless_owner_fixture.py';fixture.write_text(FIXTURE);fixture.chmod(0o600)
    lock=OUT/'private-fixture.lock';fd=os.open(lock,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600);fcntl.flock(fd,fcntl.LOCK_EX)
    before=os.fstat(fd);owner=os.getpid();start=owned._read_stat(owner)[4];pidfd=os.pidfd_open(owner,0);deadline=time.monotonic()+60
    command=SOURCE_COMMAND.replace('/usr/bin/python3',shlex.quote(sys.executable),1).replace(SOURCE_HELPER,shlex.quote(str(fixture)),1);rows=[]
    def held():
        current=os.fstat(fd);need((current.st_dev,current.st_ino,current.st_mode,current.st_nlink,current.st_size)==(before.st_dev,before.st_ino,before.st_mode,1,0),'same private fixture FD identity')
        need(owned._read_stat(owner)[4]==start and not select.select([pidfd],[],[],0)[0],'same alive original HOST driver owner PIDFD/starttime')
        return dict(dev=current.st_dev,inode=current.st_ino,mode=stat.S_IMODE(current.st_mode),nlink=current.st_nlink,bytes=current.st_size,owner=owner,owner_starttime=start,owner_pidfd_alive=True,fdinfo=Path('/proc/self/fdinfo/'+str(fd)).read_text(),release='CLOSE_ONLY')
    save(OUT/'once-intent.json',dict(status='NEW_FINITE_HOST_PRIVATE_LAYOUT_CASES_ONLY',source_command=SOURCE_COMMAND,private_command=command,fixture_substitutions=['SOURCE_HELPER_TO_PRIVATE_FIXTURE','PYTHON_TO_MATRIX_SYS_EXECUTABLE'],fixture=pin(FIXTURE.encode()),supervisor=pin(raw),case_cap_seconds=10,global_cap_seconds=60,fixture_cpu_seconds=3,fixture_AS_bytes=256*1024**2,fixture_file_cap=65536,output_read_cap=65536,no_repository_Source_import=True,lease=held(),native_namespace_test=False,acceptance=False))
    def run(name,argv,env,expected):
        need(time.monotonic()<deadline,'whole HOST controls deadline');held();save(OUT/(name+'.intent.json'),dict(argv=argv,expected_shell_exit=expected,once=True,retry=False))
        with(OUT/(name+'.stdout')).open('xb')as stdout,(OUT/(name+'.stderr')).open('xb')as stderr:
            state=owned.supervise(argv,cwd=OUT,env=env,stdout=stdout,stderr=stderr,lock_fd=fd,cap=min(10,deadline-time.monotonic()))
        save(OUT/(name+'.process.json'),state);out,err=bounded(OUT/(name+'.stdout')),bounded(OUT/(name+'.stderr'))
        need(state['exit']==expected and state['reaped']is state['group_absent']is state['pid_reserved_until_retirement']is True and state['timeout']is state['forced_retirement']is False and state['error']is None,'expected exit and natural reserved WNOWAIT/reap/group absence')
        held();return out,err,state
    env=dict(PATH='/usr/bin:/bin',LC_ALL='C',TZ='UTC',PYTHONDONTWRITEBYTECODE='1')
    report=dict(status='NOT_COMPLETE',acceptance=False)
    try:
        out,err,state=run('private_FD_NB',[sys.executable,'-I','-B',str(fixture),'--leasecheck',str(lock)],env,0);need(json.loads(out)==dict(independent_NB_conflict=True)and not err,'fresh independent NB conflict')
        rows.append(dict(case='private_FD_NB',passed=True,process=state))
        for case,expected in [('exit0',0),('exit1',1),('exit37',37),('delayed_exit0',0),('self_SIGTERM',143)]:
            e=dict(env,FIXTURE_CASE=case,FIXTURE_FD=str(fd),FIXTURE_LAUNCH_COMMAND=command)
            out,err,state=run(case,['/bin/sh','-c',command,'security-layout-private-fixture'],e,expected)
            lines=out.splitlines();need(len(lines)==2 and lines[0]==('FIXTURE_STDOUT case='+case).encode(),'stdout retained exactly')
            value=json.loads(lines[1]);need(value['case']==case and value['owner_pid']>1 and value['retained_shell_command_exact']is True and value['python_executable']==sys.executable,'retained shell and actual HOST owner>1')
            expected_err=('FIXTURE_STDERR case='+case+'\n').encode();need(err==expected_err if case!='self_SIGTERM'else err.startswith(expected_err)and len(err)<4096,'stderr retained')
            need(all(g['result']['exact_direct_parent']is True and g['result']['ppid']==value['owner_pid']and g['result']['python_executable']==sys.executable for g in value['grandchildren']),'direct harmless child ownership')
            if case=='delayed_exit0':need(value['delay_complete']is True and state['seconds']>=.20,'explicit shell wait retained delayed owner')
            rows.append(dict(case=case,passed=True,expected_shell_exit=expected,stdout=pin(out),stderr=pin(err),fixture=value,process=state))
        report=dict(status='PASS_NEW_HOST_PRIVATE_PROCESS_LAYOUT_CONTROLS',python_version=str(sys.version_info.major)+'.'+str(sys.version_info.minor),python_executable=sys.executable,helper_binding=binding,embedded_supervisor=pin(SUPERVISOR_BYTES),failures=0,errors=0,cases=rows,case_count=len(rows),source_command=SOURCE_COMMAND,private_command=command,original_c_guard_changed=False,fixture_substitutions=['SOURCE_HELPER_TO_PRIVATE_FIXTURE','PYTHON_TO_MATRIX_SYS_EXECUTABLE'],repository_Source_imports=0,Source_constructor_emitter_calls=0,FD_payload_reads=0,native_C_compiler_probe_runtime_GPG_package_VM_namespace_actors=0,old_tests_readers_GET_POST_Git_API_primary_writes=0,no_post_reap_numeric_child_PID_queries=True,native_PID1_namespace_test=False,callback='UNQUALIFIED',source_binary_correspondence='OPEN',acceptance=False)
    except BaseException as error:
        report=dict(status='STOPPED_NEW_HOST_CONTROL_FAILURE_NO_REPLAY',type=type(error).__name__,message=str(error),completed_cases=rows,retry=False,acceptance=False)
        raise
    finally:
        try:report['final_lease']=held();save(OUT/'result.json',report)
        finally:os.close(fd);os.close(pidfd)
    print(json.dumps(dict(status=report['status'],case_count=report['case_count'],source_command=SOURCE_COMMAND,native_PID1_namespace_test=False,acceptance=False),sort_keys=True))

if __name__=='__main__':main()

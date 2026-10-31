# SPDX-License-Identifier: MIT
"""Runs only inside the marked diskless generic 16 KiB guest, without a GUI."""
import hashlib
import base64
import importlib.util
import json
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import sys
import time


def need(ok,reason):
    if not ok:raise ValueError(reason)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def read(path,cap=262144):
    info=path.lstat();need(stat.S_ISREG(info.st_mode) and not path.is_symlink() and info.st_size<=cap,'bounded regular guest file')
    data=path.read_bytes();need(len(data)<=cap,'guest file byte bound');return data


def snapshot(root):
    result={}
    for path in sorted(root.rglob('*')):
        need(len(result)<128,'configuration count bound');info=path.lstat()
        need(stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode),'configuration node type')
        result[str(path.relative_to(root))]=dict(mode=stat.S_IMODE(info.st_mode),uid=info.st_uid,gid=info.st_gid,
            sha256=sha(read(path)) if path.is_file() else None)
    return result


class CommandFailure(ValueError):
    def __init__(self,reason,row,stdout,stderr):
        super().__init__(reason)
        self.row,self.stdout,self.stderr=row,stdout,stderr


def proc_snapshot(leader,proc=Path('/proc')):
    # Never inspect unrelated host users when this pure helper is imported.
    if proc==Path('/proc') and os.getuid()!=23001:return dict(status='OUTSIDE_PRIVATE_UID',processes=[])
    rows=[];scanned=0
    try:
        for path in sorted(proc.iterdir(),key=lambda p:int(p.name) if p.name.isdecimal() else -1):
            if not path.name.isdecimal() or int(path.name)==os.getpid():continue
            scanned+=1
            if scanned>128:break
            try:
                text=read(path/'status',16384).decode();fields={line.split(':',1)[0]:line.split(':',1)[1].strip() for line in text.splitlines() if ':' in line}
                if '23001' not in fields.get('Uid','').split():continue
                selected={k:fields[k] for k in ('Name','State','Pid','PPid','Uid','Gid','Threads','SigPnd','ShdPnd','SigBlk','SigIgn','SigCgt') if k in fields}
                need(all(len(v)<=128 for v in selected.values()),'bounded private proc field')
                rows.append(dict(pid=int(path.name),fields=selected))
                if len(rows)==16:break
            except (OSError,ValueError,UnicodeError):continue
        return dict(status='OBSERVED_PRIVATE_UID_ONLY',leader=leader,leader_observed=any(r['pid']==leader for r in rows),processes=rows,limited=scanned>128 or len(rows)==16)
    except OSError:return dict(status='UNAVAILABLE',processes=[])


def sample(raw,limit,tail=False):
    value=raw[-limit:] if tail and limit else raw[:limit]
    return dict(bytes=len(raw),sha256=sha(raw),sample_base64=base64.b64encode(value).decode(),sample_complete=len(value)==len(raw),sample_offset=len(raw)-len(value) if tail and limit else 0)


def diagnostic_file(path,limit=0,tail=False,cap=65536):
    try:
        if not path.exists() and not path.is_symlink():return dict(status='ABSENT')
        need(not any(p.is_symlink() for p in (path,*path.parents)),'diagnostic alias refused')
        info=path.lstat();need(info.st_nlink==1,'diagnostic hardlink refused');raw=read(path,cap)
        result=dict(status='FILE',mode=stat.S_IMODE(info.st_mode),uid=info.st_uid,gid=info.st_gid,**sample(raw,limit,tail))
        if path.name=='notifications.jsonl':
            try:
                records=[json.loads(line) for line in raw.splitlines()]
                result.update(jsonl_valid=True,record_count=len(records),recorded_pids=[r['pid'] for r in records if isinstance(r,dict) and type(r.get('pid')) is int][:16])
            except (ValueError,KeyError):result.update(jsonl_valid=False,record_count=None)
        return result
    except (OSError,ValueError,UnicodeError) as error:return dict(status='UNAVAILABLE',error_type=type(error).__name__)


def failure_diagnostic(error,root,nonce,release,manifest_raw,home,before):
    names=('noninteractive','foreground','background','watch-rejection','disown','repeat-preserve','command-data','transport-failure','transport-timeout','disable','existing-function','existing-autoload','existing-variable','existing-wrapper','existing-public','no-bus','notify-send','timeout')
    cases=root/'cases';present=[n for n in names if (cases/n).is_dir() and not (cases/n).is_symlink()]
    leaves={'notifications.jsonl':(2048,False),'terminal.log':(2048,True),'events':(1024,True),
            'load-status':(128,False),'setup-status':(128,False),'status-1':(128,False),'status-2':(128,False),
            'prompt-1':(128,False),'prompt-2':(128,False),'notify-mode':(128,False),'bin/notify-send':(0,False)}
    observed={n:{leaf:diagnostic_file(cases/n/leaf,limit,tail) for leaf,(limit,tail) in leaves.items()} for n in present[-2:]}
    try:preserved=snapshot(home)==before
    except (OSError,ValueError):preserved=False
    value=dict(schema_version=1,status='FAILED_DRIVER_DIAGNOSTIC_ONLY',nonce=nonce,kernel=release,architecture=os.uname().machine,
        page_size=os.sysconf('SC_PAGE_SIZE'),uid=os.getuid(),acceptance_credit=False,payload_manifest_sha256=sha(manifest_raw),
        driver=error.row,stdout=sample(error.stdout,1024),stderr=sample(error.stderr,4096,True),
        original_receipt=diagnostic_file(cases/'receipt.json',8192),case_directories_present=present,cases=observed,
        outer_config_preserved_observed=preserved,
        fish_normal_exit='NOT_DIRECTLY_RECORDED; original driver finally asserts exit0 before propagating the foreground assertion',
        product_change='NONE',notification_manager='NOT_RUN')
    raw=json.dumps(value,sort_keys=True,separators=(',',':'))
    if len(raw.encode())>65536:
        # Keep exact receipt and process/exit metadata; explicitly limit transcripts.
        value['cases']={};value['transcripts_omitted_for_total_cap']=True
        raw=json.dumps(value,sort_keys=True,separators=(',',':'))
    need(len(raw.encode())<=65536,'failed-driver diagnostic total bound')
    return raw


def command(argv,env,expected=0,seconds=30):
    process=subprocess.Popen(argv,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
    poll=selectors.DefaultSelector();parts=[bytearray(),bytearray()];start=time.monotonic();last=start;natural=False;error=None;before={}
    try:
        for n,pipe in enumerate((process.stdout,process.stderr)):
            os.set_blocking(pipe.fileno(),False);poll.register(pipe,selectors.EVENT_READ,n)
        while poll.get_map() or os.waitid(os.P_PID,process.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT) is None:
            last=time.monotonic();need(last-start<seconds,'guest command deadline')
            for key,_ in poll.select(.05):
                data=os.read(key.fd,8192)
                if not data:poll.unregister(key.fileobj);continue
                need(sum(map(len,parts))+len(data)<=131072,'guest command output bound');parts[key.data].extend(data)
        natural=True
    except BaseException as caught:error=caught
    finally:
        before=proc_snapshot(process.pid)
        # Keep the leader unreaped until group signals, so its PID cannot be reused.
        for sig in (signal.SIGTERM,signal.SIGKILL):
            try:os.killpg(process.pid,sig)
            except ProcessLookupError:pass
        code=process.wait(timeout=5);poll.close();process.stdout.close();process.stderr.close()
    absent=None  # Preserve the original no-extra-signal path on monitor failure.
    if error is None:
        try:os.killpg(process.pid,0)
        except ProcessLookupError:absent=True
        else:absent=False
    out,err=map(bytes,parts)
    row=dict(argv=argv,exit=code,expected_exit=expected,natural_exit=natural,group_absent=absent,pid=process.pid,pgid=process.pid,seconds=round((last if error else time.monotonic())-start,6),
             stdout_bytes=len(out),stdout_sha256=sha(out),stderr_bytes=len(err),stderr_sha256=sha(err))
    if error is not None or code!=expected or not absent:
        row.update(error_type=type(error).__name__ if error else None,reason=str(error)[:160] if error else 'guest command exit/group differs',
                   proc_before_teardown=before,proc_after_teardown=proc_snapshot(process.pid))
        raise CommandFailure(row['reason'],row,out,err)
    return row,out


def payload_identity(manifest):
    for name,row in manifest['files'].items():
        path=Path('/')/name;raw=read(path,64*1024**2)
        need(len(raw)==row['bytes'] and sha(raw)==row['sha256'] and
             stat.S_IMODE(path.stat().st_mode)==row['mode'],'guest payload identity differs')


def owned_absent():
    others=[]
    for path in Path('/proc').iterdir():
        if not path.name.isdecimal() or int(path.name)==os.getpid():continue
        try:
            fields=(path/'status').read_text().splitlines()
            uid=next(line.split()[1:] for line in fields if line.startswith('Uid:'))
        except FileNotFoundError:continue
        if '23001' in uid:others.append(int(path.name))
    need(not others,'owned fixture process remains: '+str(others[:16]))
    return True


def foreground_probe(fixture,source,root):
    """Separate diagnostic only: preserve original driver, workload and product bytes."""
    need(not root.exists() and root.parent.is_dir(),'fresh private probe output required')
    root.mkdir(mode=0o700)
    os.umask(0o077)
    spec=importlib.util.spec_from_file_location('done16k_original_fixture',fixture)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    fish=__import__('shutil').which('fish');need(fish is not None,'Fish unavailable')
    session=None
    result=dict(schema_version=1,status='FOREGROUND_PROBE_ONLY',acceptance_credit=False,product_change='NONE',
        fixture_sha256=sha(read(fixture)),runtime_sha256=sha(read(source/'done.fish')),
        wrapper_sha256=sha(read(source/'opt-in.fish')),workload='sleep .12',threshold=80,
        intervention='Additional fixture event observers and exec-preserving timeout stderr recorder; separate fresh private case')
    try:
        session=module.Session.__new__(module.Session)
        session.__init__(fish,source/'opt-in.fish',root,'foreground');home=session.home
        # Observe the actual duration/activation without replacing product functions.
        observer='''function fixture_diagnostic_pre --on-event fish_preexec
if test "$argv[1]" = 'sleep .12'
functions --query __done_ended __done_notify caa_done_watch caa_done_disable
printf '%s' $status > "$HOME/probe-enabled"
printf '%s\\n' $caa_done_min_duration > "$HOME/probe-threshold"
printf '%s\\n' $caa_done_exclude > "$HOME/probe-exclusions"
end
end
function fixture_diagnostic_post --on-event fish_postexec
set -l outcome $status
if test "$argv[1]" = 'sleep .12'
printf '%s\\t%s\\n' "$CMD_DURATION" "$outcome" > "$HOME/probe-completion"
end
end'''
        # A single submitted line keeps the original fixture sequence/prompt contract.
        session.run(observer.replace('\n','; '))
        timeout=home/'bin/timeout';real=timeout.resolve(strict=True);timeout.unlink()
        import shlex
        timeout.write_text('#!/usr/bin/sh\nprintf T >> "$HOME/probe-timeout-entered"\nexec '+shlex.quote(str(real))+' "$@" 2>> "$HOME/probe-timeout-stderr"\n')
        timeout.chmod(0o700)
        before=len(module.rows(home));started=time.monotonic()
        rows=session.run('sleep .12');result.update(notifications_before=before,notifications_after=len(rows),
            notification_delta=len(rows)-before,seconds=round(time.monotonic()-started,6))
        leaves=('probe-enabled','probe-threshold','probe-exclusions','probe-completion','probe-timeout-entered','probe-timeout-stderr','notifications.jsonl')
        result['files']={leaf:diagnostic_file(home/leaf,2048) for leaf in leaves}
    except BaseException as error:
        result.update(error_type=type(error).__name__,reason=str(error)[:160])
    finally:
        if session is not None:
            try:session.close();result['fish_normal_exit']=True
            except BaseException as error:
                result.update(fish_normal_exit=False,close_error_type=type(error).__name__,close_reason=str(error)[:160])
                try:session.term.close()
                except OSError:pass
    # Run the original recorder in a separate fresh home, first through the
    # unchanged two-second transport and then directly. This diagnoses startup
    # failure/cost without relaxing the product timeout or granting acceptance.
    transport=module.prepare(root,'transport')
    recorder=transport/'bin/notify-send'
    env=module.environment(transport)
    timeout=transport/'bin/timeout'
    result['transport_commands']=[]
    for kind,argv in (
        ('bounded-timeout',[str(timeout),'--foreground','--signal=TERM','--kill-after=1s','2s','notify-send','--diagnostic-only']),
        ('direct-recorder',[str(recorder),'--diagnostic-only'])):
        try:row,out=command(argv,env,seconds=5);err=b''
        except CommandFailure as error:row,out,err=error.row,error.stdout,error.stderr
        result['transport_commands'].append(dict(kind=kind,command=row,stdout=sample(out,1024),stderr=sample(err,2048),
            notification_count=len(module.rows(transport)),recorder_sha256=sha(read(recorder))))
    need(sha(read(fixture))==result['fixture_sha256'] and sha(read(source/'done.fish'))==result['runtime_sha256'] and
         sha(read(source/'opt-in.fish'))==result['wrapper_sha256'],'probe source bytes changed')
    return result


def recorder_cases(root,proof,manifest):
    """Join each private recorder copy and its PID/count log to the captured native ELF."""
    result={};expected=manifest['files']['fixtures/notify-recorder']['sha256']
    for name,case_proof in proof['cases'].items():
        case=root/name;recorder=case/'bin/notify-send';exists=recorder.exists()
        need(exists==(name!='notify-send'),'original missing-recorder case differs')
        if exists:
            info=recorder.lstat()
            need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid==info.st_gid==23001 and
                stat.S_IMODE(info.st_mode)==0o700 and sha(read(recorder,1024**2))==expected,
                'private native recorder bytes/identity changed')
        log=case/'notifications.jsonl';raw=b''
        if log.exists():
            info=log.lstat();need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid==info.st_gid==23001 and
                stat.S_IMODE(info.st_mode)==0o600,'private notification log identity differs');raw=read(log,65536)
        lines=raw.splitlines(keepends=True);need(len(lines)<=32 and all(len(line)<4096 and line.endswith(b'\n') for line in lines),
            'bounded native recorder lines required')
        rows=[json.loads(line) for line in lines]
        need(all(set(row)=={'argv','pid'} and type(row['argv']) is list and all(type(v) is str for v in row['argv']) and
            type(row['pid']) is int and row['pid']>0 for row in rows),'native recorder argv/PID shape differs')
        need(type(case_proof['notifications']) is int and 0<=case_proof['notifications']<=len(rows) and (exists or not rows),'native recorder count/delta join differs')
        result[name]=dict(recorder_present=exists,recorder_sha256=expected if exists else None,
            notification_count=len(rows),fixture_notification_delta=case_proof['notifications'],
            recorded_pids=[row['pid'] for row in rows],notifications_sha256=sha(raw))
    return result


def exercise(nonce,release):
    need(os.geteuid()==0 and os.uname().machine=='aarch64' and os.uname().release==release and
         os.sysconf('SC_PAGE_SIZE')==16384 and 'fish_done16k=1' in Path('/proc/cmdline').read_text().split(),
         'marked generic16K Done guest required')
    need(not Path('/usr/bin/notify-send').exists(),'real notification transport must be absent')
    manifest_raw=read(Path('/payload.json'),1024**2);manifest=json.loads(manifest_raw);payload_identity(manifest)
    os.umask(0o077);root=Path('/tmp/done16k');root.mkdir(mode=0o700);os.chown(root,23001,23001)
    os.setgroups([]);os.setgid(23001);os.setuid(23001)
    need(os.getuid()==os.geteuid()==os.getgid()==23001,'private unprivileged guest identity')
    owned_absent();home=root/'user';home.mkdir(mode=0o700)
    for name in ('config','cache','data','state','runtime'):
        directory=home/name;directory.mkdir(mode=0o700);(directory/'sentinel').write_bytes(b'preserve user settings\n')
    temporary=root/'temporary';temporary.mkdir(mode=0o700);before=snapshot(home)
    env=dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TZ='UTC',HOME=str(home),TMPDIR=str(temporary),
        PYTHONDONTWRITEBYTECODE='1',DISPLAY='',WAYLAND_DISPLAY='',DBUS_SESSION_BUS_ADDRESS='unix:path=/no-real-bus',
        XDG_CONFIG_HOME=str(home/'config'),XDG_CACHE_HOME=str(home/'cache'),XDG_DATA_HOME=str(home/'data'),
        XDG_STATE_HOME=str(home/'state'),XDG_RUNTIME_DIR=str(home/'runtime'))
    argv=['/usr/bin/python3','-I','-B','/fixtures/done-native.py','--source','/usr/share/cachy-asahi/fish-done','--output',str(root/'cases')]
    try:row,out=command(argv,env,seconds=240)
    except CommandFailure as error:
        diagnostic=json.loads(failure_diagnostic(error,root,nonce,release,manifest_raw,home,before))
        diagnostic['test_transport']=manifest['test_transport']
        raw=json.dumps(diagnostic,sort_keys=True,separators=(',',':'));need(len(raw.encode())<=65536,'combined diagnostic byte bound')
        print('DONE16K_DIAGNOSTIC '+raw,flush=True)
        raise
    row['owned_processes_absent']=owned_absent()
    summary=json.loads(out);proof_raw=read(root/'cases/receipt.json');proof=json.loads(proof_raw)
    need(summary['status']=='PASS' and summary['cases']==18 and summary['receipt']==str(root/'cases/receipt.json') and
         proof['status']=='PASS' and len(proof['cases'])==18 and all(v['exit']==0 for v in proof['cases'].values()),
         'all eighteen unchanged case bodies with native C test transport required')
    need(proof['machine']=='aarch64' and proof['fish']=='fish, version 4.9.3' and
         proof['runtime_sha256']==manifest['files']['usr/share/cachy-asahi/fish-done/done.fish']['sha256'] and
         proof['wrapper_sha256']==manifest['files']['usr/share/cachy-asahi/fish-done/opt-in.fish']['sha256'],'actual Done source/platform differs')
    native_cases=recorder_cases(root/'cases',proof,manifest)
    preserved={}
    for name in proof['cases']:
        case=root/'cases'/name
        for leaf,raw in [('config/fish/config.fish',b'touch "$HOME/unexpected-rc"\n'),
                         ('data/fish/fish_history',b'preserve private existing history\n')]:
            path=case/leaf;info=path.lstat()
            need(read(path)==raw and stat.S_IMODE(info.st_mode)==0o600 and info.st_uid==info.st_gid==23001 and info.st_nlink==1,
                 'private case config/history bytes/ownership/mode changed')
        need(not (case/'unexpected-rc').exists() and not (case/'PWNED').exists(),'case caller data executed')
        preserved[name]=True
    need(snapshot(home)==before,'outer caller HOME/XDG files changed');payload_identity(manifest);owned_absent()
    return dict(status='PASS_GENERIC_16K_FISH_DONE_NATIVE_C_RECORDER_ADAPTED_PTY_ONLY',nonce=nonce,architecture='aarch64',page_size=16384,
        kernel=release,uid=os.getuid(),commands=[row],done=proof,test_transport=manifest['test_transport'],native_recorder_cases=native_cases,done_receipt_sha256=sha(proof_raw),case_inputs_preserved=preserved,
        config_preserved=True,payload_preserved=True,owned_processes_absent=True,payload_manifest_sha256=sha(manifest_raw),
        notification_transport='PRIVATE_NATIVE_C_NOTIFY_SEND_RECORDER_ONLY',notification_manager='NOT_RUN',DBus='NOT_RUN',display='NOT_RUN',
        package_registration='NOT_INSTALLED_EXACT_SOURCE_PAYLOADS_COPIED_ONLY',GUI='NOT_RUN',hardware='NOT_RUN',
        performance='NOT_RUN',release_admission=False)


if __name__=='__main__':
    try:
        if len(sys.argv)==3 and sys.argv[1]=='--foreground-probe':
            value=foreground_probe(Path('/fixtures/done.py'),Path('/usr/share/cachy-asahi/fish-done'),Path(sys.argv[2]))
            raw=json.dumps(value,sort_keys=True,separators=(',',':'));need(len(raw.encode())<=16384,'foreground probe byte bound')
            print(raw,flush=True)
        else:
            need(len(sys.argv)==3 and len(sys.argv[1])==32,'guest arguments')
            value=exercise(sys.argv[1],sys.argv[2]);raw=json.dumps(value,sort_keys=True,separators=(',',':'))
            need(len(raw.encode())<=65536,'guest report byte bound');print('DONE16K_REPORT '+raw,flush=True)
    except BaseException as error:
        print('DONE16K_ERROR '+type(error).__name__+': '+str(error)[:160],flush=True);raise

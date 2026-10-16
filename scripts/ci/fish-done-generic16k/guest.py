# SPDX-License-Identifier: MIT
"""Runs only inside the marked diskless generic 16 KiB guest, without a GUI."""
import hashlib
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


def command(argv,env,expected=0,seconds=30):
    process=subprocess.Popen(argv,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
    poll=selectors.DefaultSelector();parts=[bytearray(),bytearray()];start=time.monotonic()
    try:
        for n,pipe in enumerate((process.stdout,process.stderr)):
            os.set_blocking(pipe.fileno(),False);poll.register(pipe,selectors.EVENT_READ,n)
        while poll.get_map() or os.waitid(os.P_PID,process.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT) is None:
            need(time.monotonic()-start<seconds,'guest command deadline')
            for key,_ in poll.select(.05):
                data=os.read(key.fd,8192)
                if not data:poll.unregister(key.fileobj);continue
                need(sum(map(len,parts))+len(data)<=131072,'guest command output bound');parts[key.data].extend(data)
    finally:
        # Keep the leader unreaped until group signals, so its PID cannot be reused.
        for sig in (signal.SIGTERM,signal.SIGKILL):
            try:os.killpg(process.pid,sig)
            except ProcessLookupError:pass
        code=process.wait(timeout=5);poll.close();process.stdout.close();process.stderr.close()
    try:os.killpg(process.pid,0)
    except ProcessLookupError:absent=True
    else:absent=False
    need(code==expected and absent,'guest command exit/group differs: '+str(code)+' '+repr(argv[:5])+' '+repr(bytes(parts[0][-256:])+bytes(parts[1][-256:])))
    out,err=map(bytes,parts)
    return dict(argv=argv,exit=code,group_absent=absent,seconds=round(time.monotonic()-start,6),
                stdout_bytes=len(out),stdout_sha256=sha(out),stderr_bytes=len(err),stderr_sha256=sha(err)),out


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
    argv=['/usr/bin/python3','-I','-B','/fixtures/done.py','--source','/usr/share/cachy-asahi/fish-done','--output',str(root/'cases')]
    row,out=command(argv,env,seconds=240);row['owned_processes_absent']=owned_absent()
    summary=json.loads(out);proof_raw=read(root/'cases/receipt.json');proof=json.loads(proof_raw)
    need(summary['status']=='PASS' and summary['cases']==18 and summary['receipt']==str(root/'cases/receipt.json') and
         proof['status']=='PASS' and len(proof['cases'])==18 and all(v['exit']==0 for v in proof['cases'].values()),
         'all eighteen existing Done cases required')
    need(proof['machine']=='aarch64' and proof['fish']=='fish, version 4.9.3' and
         proof['runtime_sha256']==manifest['files']['usr/share/cachy-asahi/fish-done/done.fish']['sha256'] and
         proof['wrapper_sha256']==manifest['files']['usr/share/cachy-asahi/fish-done/opt-in.fish']['sha256'],'actual Done source/platform differs')
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
    return dict(status='PASS_GENERIC_16K_FISH_DONE_RECORDER_PTY_ONLY',nonce=nonce,architecture='aarch64',page_size=16384,
        kernel=release,uid=os.getuid(),commands=[row],done=proof,done_receipt_sha256=sha(proof_raw),case_inputs_preserved=preserved,
        config_preserved=True,payload_preserved=True,owned_processes_absent=True,payload_manifest_sha256=sha(manifest_raw),
        notification_transport='PRIVATE_NOTIFY_SEND_RECORDER_ONLY',notification_manager='NOT_RUN',DBus='NOT_RUN',display='NOT_RUN',
        package_registration='NOT_INSTALLED_EXACT_SOURCE_PAYLOADS_COPIED_ONLY',GUI='NOT_RUN',hardware='NOT_RUN',
        performance='NOT_RUN',release_admission=False)


if __name__=='__main__':
    try:
        need(len(sys.argv)==3 and len(sys.argv[1])==32,'guest arguments')
        value=exercise(sys.argv[1],sys.argv[2]);raw=json.dumps(value,sort_keys=True,separators=(',',':'))
        need(len(raw.encode())<=65536,'guest report byte bound');print('DONE16K_REPORT '+raw,flush=True)
    except BaseException as error:
        print('DONE16K_ERROR '+type(error).__name__+': '+str(error)[:160],flush=True);raise

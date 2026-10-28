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


def command(argv,env,expected=0):
    process=subprocess.Popen(argv,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
    poll=selectors.DefaultSelector();parts=[bytearray(),bytearray()];start=time.monotonic()
    try:
        for n,pipe in enumerate((process.stdout,process.stderr)):
            os.set_blocking(pipe.fileno(),False);poll.register(pipe,selectors.EVENT_READ,n)
        while poll.get_map() or os.waitid(os.P_PID,process.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT) is None:
            need(time.monotonic()-start<30,'guest command deadline')
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
    need(code==expected and absent,'guest command exit/group differs')
    out,err=map(bytes,parts)
    return dict(argv=argv,exit=code,group_absent=absent,seconds=round(time.monotonic()-start,6),
                stdout_bytes=len(out),stdout_sha256=sha(out),stderr_bytes=len(err),stderr_sha256=sha(err)),out


def payload_identity(manifest):
    for name,row in manifest['files'].items():
        path=Path('/')/name;raw=read(path,64*1024**2)
        need(len(raw)==row['bytes'] and sha(raw)==row['sha256'] and
             stat.S_IMODE(path.stat().st_mode)==row['mode'],'guest payload identity differs')


def exercise(nonce,release):
    need(os.geteuid()==0 and os.uname().machine=='aarch64' and os.uname().release==release and
         os.sysconf('SC_PAGE_SIZE')==16384 and 'welcome_doctor16k=1' in Path('/proc/cmdline').read_text().split(),
         'marked generic16K guest required')
    manifest_raw=read(Path('/payload.json'),1024**2);manifest=json.loads(manifest_raw);payload_identity(manifest)
    root=Path('/tmp/welcome16k');root.mkdir(mode=0o700);home=root/'user';home.mkdir(mode=0o700)
    for name in ('config','cache','data','state','runtime'):
        directory=home/name;directory.mkdir(mode=0o700);(directory/'sentinel').write_bytes(b'preserve user settings\n')
    reports=root/'reports';reports.mkdir(mode=0o700);temporary=root/'temporary';temporary.mkdir(mode=0o700)
    protected=snapshot(home)
    env=dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TZ='UTC',HOME=str(home),TMPDIR=str(temporary),
        PYTHONDONTWRITEBYTECODE='1',DISPLAY='',WAYLAND_DISPLAY='',DBUS_SESSION_BUS_ADDRESS='unix:path=/no-session',
        XDG_CONFIG_HOME=str(home/'config'),XDG_CACHE_HOME=str(home/'cache'),XDG_DATA_HOME=str(home/'data'),
        XDG_STATE_HOME=str(home/'state'),XDG_RUNTIME_DIR=str(home/'runtime'))
    commands=[]
    def call(tool,*args,expected=0):
        row,out=command(['/usr/bin/'+tool,*args],env,expected);commands.append(row);return out
    welcome='cachy-asahi-welcome';doctor='cachy-asahi-doctor'
    need(b'--status' in call(welcome,'--help'),'Welcome help differs')
    need(call(welcome,'--version')==b'cachy-asahi Welcome 0.1.0\n','Welcome version differs')
    text=call(welcome,'--status');status=json.loads(call(welcome,'--status','--json'))
    need(status['architecture']=='aarch64' and status['page_size']==16384 and status['kernel']==release and
         status['hardware_compatibility']=='not-assessed' and status['welcome_version']=='0.1.0' and
         status['package_database']=='unavailable' and len(status['packages'])==6 and
         all(r==dict(state='unknown',version=None) for r in status['packages'].values()),'actual Welcome16K platform/scope differs')
    need(b'Page size: 16384 bytes\n' in text and b'Hardware compatibility: not assessed\n' in text,'Welcome text differs')
    guides={}
    for name in ('first-run','updates','recovery'):
        expected=read(Path('/usr/share/doc/cachy-asahi-welcome')/(name+'.txt'))
        observed=call(welcome,'--guide',name);need(observed==expected,'installed guide bytes differ');guides[name]=sha(observed)
    need(call(welcome,'--guide','../../etc/shadow',expected=2)==b'','guide path refusal differs')
    need(b'--output' in call(doctor,'--help'),'Doctor help differs')
    printed=json.loads(call(doctor,'--json'));report=reports/'report.json'
    raw=call(doctor,'--json','--output',str(report));value=json.loads(raw);info=report.lstat()
    need(read(report)==raw and stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode)==0o600 and
         info.st_uid==0 and info.st_nlink==1,'private Doctor publication differs')
    for document in (printed,value):
        checks={r['check']:r for r in document['checks']};platform=checks['platform']['value']
        need(document['tool']=='cachy-asahi-doctor' and document['scope']=='local observations only' and
             platform==dict(architecture='aarch64',page_size_bytes=16384,kernel=release),'Doctor actual16K platform differs')
        need(all(r['state']=='unavailable' and r['value']['presence']=='unknown' for r in document['checks']
                 if r['check'].startswith('package/')),'unpacked fixture must not invent package registration')
    pin=sha(raw);outside=reports/'outside';outside.write_bytes(b'preserve outside report\n');outside.chmod(0o600)
    outside_pin=sha(read(outside));outside_info=outside.lstat()
    alias=reports/'alias';alias.symlink_to(outside.name)
    call(doctor,'--output',str(report),expected=2);call(doctor,'--output',str(alias),expected=2)
    fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_mtime_ns')
    need(sha(read(report))==pin and sha(read(outside))==outside_pin and alias.is_symlink() and
         all(getattr(report.lstat(),k)==getattr(info,k) and getattr(outside.lstat(),k)==getattr(outside_info,k) for k in fields),
         'existing/private report changed')
    need(snapshot(home)==protected,'existing config/private user state changed');payload_identity(manifest)
    need(len(commands)==13,'complete finite CLI set required')
    return dict(status='PASS_GENERIC_16K_WELCOME_DOCTOR_CLI_ONLY',nonce=nonce,architecture='aarch64',page_size=16384,
        kernel=release,commands=commands,guide_sha256=guides,private_report_mode='0600',no_overwrite='PASS',
        symlink_refusal='PASS',config_preserved=True,payload_preserved=True,report_sha256=pin,
        welcome_status=status,doctor_platform=platform,doctor_scope=value['scope'],payload_manifest_sha256=sha(manifest_raw),
        package_registration='NOT_INSTALLED_EXACT_PAYLOADS_UNPACKED_ONLY',GUI='NOT_RUN',hardware='NOT_RUN',
        performance='NOT_RUN',release_admission=False)


if __name__=='__main__':
    try:
        need(len(sys.argv)==3 and len(sys.argv[1])==32,'guest arguments')
        value=exercise(sys.argv[1],sys.argv[2]);raw=json.dumps(value,sort_keys=True,separators=(',',':'))
        need(len(raw.encode())<=65536,'guest report byte bound');print('WELCOME16K_REPORT '+raw,flush=True)
    except BaseException as error:
        print('WELCOME16K_ERROR '+type(error).__name__+': '+str(error)[:160],flush=True);raise SystemExit(1)

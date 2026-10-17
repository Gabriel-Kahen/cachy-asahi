# SPDX-License-Identifier: MIT
"""Fixed two-package/lock/process fixture inside the already guarded owned VM only."""
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import stat
import time
import management_contract as C

HOME=Path('/home/desktop574');CHANNEL=HOME/'management-channel';INPUTS=Path('/usr/local/share/desktop574/management-inputs')
TOOLS=('cachy-asahi-doctor','cachy-asahi-orphans')


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m


def identity(pid):
    path=Path('/proc')/str(pid);raw=(path/'stat').read_text();fields=raw[raw.rfind(')')+2:].split()
    uid=next(l for l in (path/'status').read_text().splitlines() if l.startswith('Uid:')).split()[1:]
    return dict(pid=pid,ppid=int(fields[1]),pgid=int(fields[2]),starttime=int(fields[19]),state=fields[0],uid=list(map(int,uid)),
        raw_argv=[os.fsdecode(v) for v in (path/'cmdline').read_bytes().split(b'\0') if v],exe=os.readlink(path/'exe'))


def find(tool,welcome_pid,previous):
    expected=['/usr/bin/cachy-asahi-'+tool,'--json' if tool=='doctor' else 'assess'];found=[]
    for p in Path('/proc').glob('[0-9]*'):
        try:
            row=identity(int(p.name))
            if row['pid'] in previous or row['uid']!=[23001]*4 or row['raw_argv'][-2:]!=expected:continue
            supervisor=identity(row['ppid'])
            if supervisor['ppid']!=welcome_pid or supervisor['uid']!=[23001]*4:continue
            C.need(row['pgid']==row['pid'] and row['exe'].startswith('/usr/bin/python'),'actual original helper interpreter/group required')
            found.append(dict(row,argv=expected,welcome_pid=welcome_pid,supervisor_pid=supervisor['pid'],supervisor_starttime=supervisor['starttime'],original_executable=expected[0],stopped=False))
        except (FileNotFoundError,ProcessLookupError,PermissionError):continue
    C.need(len(found)<=1,'ambiguous owned helper');return found[0] if found else None


def completion(fd,superfd):
    # Readiness observation only. Keep handles and the later full retirement,
    # group absence, inventory and database-preservation checks unchanged.
    return dict(helper_absent=fd is not None and bool(select.select([fd],[],[],0)[0]),
                supervisor_absent=superfd is not None and bool(select.select([superfd],[],[],0)[0]))


def metadata():
    result={};root=Path('/var/lib/pacman/local')
    excluded=[p for p in root.iterdir() if any(p.name.startswith(n+'-') for n in TOOLS)]
    for path in sorted(root.rglob('*')):
        if not path.is_file():continue
        if any(path.is_relative_to(p) for p in excluded):continue
        info=path.lstat();C.need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and len(result)<10000,'ordinary bounded nonselected metadata required')
        result[str(path.relative_to(root))]=dict(mode=stat.S_IMODE(info.st_mode),uid=info.st_uid,gid=info.st_gid,ino=info.st_ino,dev=info.st_dev,mtime_ns=info.st_mtime_ns,ctime_ns=info.st_ctime_ns,sha256=C.sha(C.read(path)))
    return result


def serve(base,session,env,logs,seconds):
    base.guard(True);C.need(os.getuid()==0 and 'cachy_asahi_welcome_management=1' in Path('/proc/cmdline').read_text().split(),'owned management4K VM required')
    products=json.loads(C.read(INPUTS/'products.json'));control=json.loads(C.read(INPUTS/'control.json'))
    api=load('management_fixture_installed',base.SHARE/'installed.py');L=load('management_fixture_lifecycle',base.SHARE/'accepted_lifecycle.py')
    pacman=api.pacman(L,control['signer'],public=str(INPUTS/'TEST-public.asc'))
    baseline=L.inventory();C.need(len(baseline)==594 and all(n in baseline for n in TOOLS),'exact594 installed management profile required')
    preserved=metadata();CHANNEL.mkdir(mode=0o700);os.chown(CHANNEL,23001,23001)
    nonce=os.urandom(16).hex();(CHANNEL/'nonce').write_text(nonce);(CHANNEL/'nonce').chmod(0o644)
    until=time.monotonic()+seconds;sequence=0;armed=None;observed=None;fd=None;superfd=None;holder=None;lock_identity=None
    def inventory():
        current=L.inventory();C.need(current in (baseline,{n:v for n,v in baseline.items() if n not in TOOLS}),'unexpected package composition');return current
    def unlock():
        nonlocal holder,lock_identity
        if holder is None:return
        info=Path('/var/lib/pacman/db.lck').lstat();C.need((info.st_dev,info.st_ino,info.st_mtime_ns,info.st_ctime_ns)==lock_identity,'foreign lock changed; no raw unlock allowed')
        C.need(holder.lib.alpm_trans_release(holder.handle)==0,'own fixture lock release failed');holder.close();holder=None;lock_identity=None
    try:
        while session.poll() is None:
            C.need(time.monotonic()<until,'managed session deadline')
            if armed and observed is None:
                observed=find(armed['tool'],armed['welcome_pid'],armed['previous'])
                if observed:
                    fd=os.pidfd_open(observed['pid']);superfd=os.pidfd_open(observed['supervisor_pid'])
                    if armed['stop']:
                        C.need(identity(observed['pid'])['starttime']==observed['starttime'],'helper changed before controlled stop')
                        signal.pidfd_send_signal(fd,signal.SIGSTOP);observed['stopped']=True
                    armed=None
            request=CHANNEL/('request-'+str(sequence)+'.json')
            if not request.exists():time.sleep(.002);continue
            data=json.loads(C.read(request,65536,23001));C.need(data.get('nonce')==nonce and data.get('sequence')==sequence and sequence<1024,'bounded fixture request identity')
            op=data.get('operation');answer=dict(nonce=nonce,sequence=sequence,operation=op,status='PASS')
            if op in ('remove','restore'):
                C.need(holder is None,'cannot transact under held fixture lock')
                if op=='remove':
                    C.need(inventory()==baseline,'tools already absent');L.command(pacman+['-R',*TOOLS],timeout=60)
                else:
                    C.need(len(inventory())==592,'tools must actually be absent')
                    archives=[]
                    for name in TOOLS:
                        row=products[name];path=INPUTS/row['archive'];C.need(path.parent==INPUTS and C.sha(C.read(path,8*1024**2))==row['sha256'],'exact signed helper archive required');archives.append(str(path))
                    L.command(pacman+['-U',*archives],timeout=60)
                answer['inventory']=inventory();C.need(metadata()==preserved,'nonselected database changed');answer['nonselected_database']='PRESERVED'
            elif op=='lock':
                C.need(holder is None and inventory()==baseline,'fresh full profile required for fixture lock')
                import runpy
                from types import SimpleNamespace
                M=SimpleNamespace(**runpy.run_path('/usr/bin/cachy-asahi-orphans',run_name='lock_counterpart'))
                holder=M.Installed(Path('/'),Path('/var/lib/pacman'))
                for name in ('alpm_trans_init','alpm_trans_release'):
                    f=getattr(holder.lib,name);f.argtypes=[ctypes.c_void_p,ctypes.c_int] if name.endswith('init') else [ctypes.c_void_p];f.restype=ctypes.c_int
                C.need(holder.lib.alpm_trans_init(holder.handle,0)==0,'actual fixture counterpart lock failed')
                info=Path('/var/lib/pacman/db.lck').lstat();lock_identity=(info.st_dev,info.st_ino,info.st_mtime_ns,info.st_ctime_ns);answer['lock']='OWN_REAL_ALPM_HANDLE'
            elif op=='unlock':unlock();answer['lock']='OWN_HANDLE_RELEASED'
            elif op=='arm':
                C.need(data.get('tool') in ('doctor','orphans') and type(data.get('welcome_pid')) is int and type(data.get('stop')) is bool,'fixed helper observer arguments')
                welcome=identity(data['welcome_pid']);C.need(welcome['uid']==[23001]*4 and welcome['raw_argv']==['/usr/bin/cachy-asahi-welcome'],'actual Welcome process required')
                if fd is not None:os.close(fd);fd=None
                if superfd is not None:os.close(superfd);superfd=None
                armed=dict(tool=data['tool'],welcome_pid=data['welcome_pid'],stop=data['stop'],previous={int(p.name) for p in Path('/proc').glob('[0-9]*')});observed=None
            elif op=='observed':answer.update(process=observed,**completion(fd,superfd))
            elif op=='retired':
                C.need(observed is not None and fd is not None and superfd is not None,'owned observed group absent')
                exited=bool(select.select([fd],[],[],0)[0]);superexited=bool(select.select([superfd],[],[],0)[0]);members=[]
                for p in Path('/proc').glob('[0-9]*'):
                    try:
                        if identity(int(p.name))['pgid']==observed['pgid']:members.append(int(p.name))
                    except (FileNotFoundError,ProcessLookupError,PermissionError):pass
                answer.update(helper_absent=exited,supervisor_absent=superexited,group_absent=not members,inventory=inventory(),nonselected_database='PRESERVED' if metadata()==preserved else 'CHANGED')
            else:raise ValueError('unknown fixture operation')
            reply=CHANNEL/('reply-'+str(sequence)+'.json');pending=reply.with_suffix('.pending')
            with pending.open('xb') as stream:stream.write(C.encoded(answer));stream.flush();os.fsync(stream.fileno())
            pending.chmod(0o644);C.need(not reply.exists(),'fresh fixture reply required');pending.rename(reply);sequence+=1
        return session.returncode
    finally:
        unlock()
        # Only a still-live held pidfd is signaled on failure. Product cleanup is independently required to pass.
        for handle in (fd,superfd):
            if handle is not None:
                if not select.select([handle],[],[],0)[0]:signal.pidfd_send_signal(handle,signal.SIGKILL)
                os.close(handle)
        C.need(metadata()==preserved and inventory()==baseline,'final GUI helper profile/nonselected database not restored')
        L.command(['/usr/bin/gpgconf','--homedir','/tmp/management-trust','--kill','all'])

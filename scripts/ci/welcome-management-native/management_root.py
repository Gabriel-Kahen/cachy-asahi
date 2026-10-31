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
import doctor_lifetime as DL

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



# Failure-only progress, not a Python stack or an attribution of a hot path.
# Use only the two already held process identities; never rescan /proc here.
PROGRESS_COUNT=7
PROGRESS_INTERVAL=5
PROGRESS_BYTES=16384


def progress_read(pid,name,cap):
    root=os.open('/proc/'+str(pid),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=root)
        try:
            raw=b''
            while len(raw)<=cap:
                part=os.read(fd,cap+1-len(raw))
                if not part:break
                raw+=part
            C.need(len(raw)<=cap,'progress field bound');return raw.decode('ascii')
        finally:os.close(fd)
    finally:os.close(root)


def progress_stat(raw):
    fields=raw[raw.rfind(')')+2:].split()
    C.need(len(fields)>=22 and len(fields[0])==1 and fields[0] in 'RSDZTtXxKWPIN','bounded process stat required')
    result=dict(state=fields[0],starttime=int(fields[19]),user_ticks=int(fields[11]),system_ticks=int(fields[12]))
    C.need(all(0<=result[k]<2**64 for k in ('starttime','user_ticks','system_ticks')),'progress counter range');return result


def progress_process(pid,starttime,handle):
    def exited():return bool(select.select([handle],[],[],0)[0])
    if exited():return dict(status='EXITED_HELD_PIDFD')
    before=progress_stat(progress_read(pid,'stat',4096));C.need(before['starttime']==starttime,'progress identity changed')
    status={}
    for line in progress_read(pid,'status',16384).splitlines():
        key,_,value=line.partition(':')
        if key in ('Uid','VmRSS','Threads'):status[key]=value.split()
    C.need(status.get('Uid')==['23001']*4 and len(status.get('Threads',[]))==1,'ordinary owned progress process required')
    rss=status.get('VmRSS');C.need(rss is not None and len(rss)==2 and rss[1]=='kB','progress RSS shape')
    io={}
    allowed={'rchar','wchar','syscr','syscw','read_bytes','write_bytes','cancelled_write_bytes'}
    for line in progress_read(pid,'io',4096).splitlines():
        key,sep,value=line.partition(':');C.need(sep and key in allowed and key not in io,'progress IO shape');io[key]=int(value)
    C.need(set(io)==allowed and all(0<=v<2**64 for v in io.values()),'complete progress IO counters')
    wchan=progress_read(pid,'wchan',256).strip()
    C.need(0<len(wchan)<=128 and all(c.isalnum() or c in '_+.-' for c in wchan),'progress wchan shape')
    after=progress_stat(progress_read(pid,'stat',4096))
    if exited():return dict(status='EXITED_DURING_SAMPLE')
    C.need(after['starttime']==starttime and all(after[k]>=before[k] for k in ('user_ticks','system_ticks')),'progress identity/counter drift')
    C.need(0<=int(rss[0])<2**64 and 0<int(status['Threads'][0])<2**32,'progress memory/thread counters')
    return dict(status='OBSERVED_NONATOMIC_COUNTERS',**after,rss_kib=int(rss[0]),threads=int(status['Threads'][0]),wchan=wchan,io=io)


class Progress:
    def __init__(self,observed,fd,superfd):
        self.started=time.monotonic();self.next=self.started;self.samples=[]
        self.identities=(('helper',observed['pid'],observed['starttime'],fd),
                         ('supervisor',observed['supervisor_pid'],observed['supervisor_starttime'],superfd))
        self.hz=os.sysconf('SC_CLK_TCK')
    def sample(self):
        now=time.monotonic()
        if now<self.next or len(self.samples)>=PROGRESS_COUNT:return
        self.next=now+PROGRESS_INTERVAL
        row=dict(elapsed_ms=int((now-self.started)*1000))
        for role,pid,start,fd in self.identities:
            try:row[role]=progress_process(pid,start,fd)
            except (OSError,ValueError,IndexError,UnicodeError) as error:
                row[role]=dict(status='UNAVAILABLE_OR_REFUSED',error_type=type(error).__name__)
        self.samples.append(row)
    def value(self):
        result=dict(schema_version=1,scope='HELD_OWNED_PROCESS_NONATOMIC_COUNTERS_NOT_STACK_OR_HOTPATH',
                    clock_ticks_per_second=self.hz,interval_seconds=PROGRESS_INTERVAL,max_samples=PROGRESS_COUNT,samples=self.samples)
        C.need(len(C.encoded(result))<=PROGRESS_BYTES,'progress receipt bound');return result


def metadata():
    result={};root=Path('/var/lib/pacman/local')
    excluded=[p for p in root.iterdir() if any(p.name.startswith(n+'-') for n in TOOLS)]
    for path in sorted(root.rglob('*')):
        if not path.is_file():continue
        if any(path.is_relative_to(p) for p in excluded):continue
        info=path.lstat();C.need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and len(result)<10000,'ordinary bounded nonselected metadata required')
        result[str(path.relative_to(root))]=dict(mode=stat.S_IMODE(info.st_mode),uid=info.st_uid,gid=info.st_gid,ino=info.st_ino,dev=info.st_dev,mtime_ns=info.st_mtime_ns,ctime_ns=info.st_ctime_ns,sha256=C.sha(C.read(path)))
    return result



def retirement_reply(operation,observed,fd,superfd,progress,inventory,metadata,preserved):
    """Fast held-process evidence; full preservation runs only after retirement."""
    C.need(operation in ('retired','retired-proof') and observed is not None and fd is not None and superfd is not None,'owned observed group absent')
    exited=bool(select.select([fd],[],[],0)[0]);superexited=bool(select.select([superfd],[],[],0)[0]);members=[]
    for p in Path('/proc').glob('[0-9]*'):
        try:
            if identity(int(p.name))['pgid']==observed['pgid']:members.append(int(p.name))
        except (FileNotFoundError,ProcessLookupError,PermissionError):pass
    answer=dict(process=observed,helper_absent=exited,supervisor_absent=superexited,group_absent=not members,
                group_members=members[:32],group_members_clipped=len(members)>32)
    if progress is not None:answer['gui_progress']=progress.value()
    if operation=='retired-proof':
        C.need(exited and superexited and not members,'preservation requires actual owned retirement')
        answer.update(inventory=inventory(),nonselected_database='PRESERVED' if metadata()==preserved else 'CHANGED')
    return answer


def restore_profile(L,pacman,products,baseline,preserved):
    """Restore only the two exact signed fixture removals, including on failure."""
    current=L.inventory();missing={n:v for n,v in baseline.items() if n not in TOOLS}
    C.need(current in (baseline,missing) and metadata()==preserved,'unknown fixture state; restoration refused')
    if current==missing:
        archives=[]
        for name in TOOLS:
            row=products[name];path=INPUTS/row['archive']
            C.need(path.parent==INPUTS and C.sha(C.read(path,8*1024**2))==row['sha256'],'exact signed helper archive required')
            archives.append(str(path))
        L.command(pacman+['-U',*archives],timeout=60)
    C.need(L.inventory()==baseline and metadata()==preserved,'final GUI helper profile/nonselected database not restored')



def issue_profile(profiles,retired_profiles,stage,nonce):
    C.need(stage==('minimal' if not profiles else 'overlay') and stage not in profiles and (not profiles or retired_profiles=={'minimal'}),'ordered fresh profile after previous retirement required')
    C.need(all(p['profile_nonce']!=nonce for p in profiles.values()),'fresh profile nonce required')
    owner=DL.parent(stage,nonce);profiles[stage]=owner;return owner


def serve(base,session,env,logs,deadline_ns):
    base.guard(True);C.need(os.getuid()==0 and 'cachy_asahi_welcome_management=1' in Path('/proc/cmdline').read_text().split(),'owned management4K VM required')
    products=json.loads(C.read(INPUTS/'products.json'));control=json.loads(C.read(INPUTS/'control.json'))
    api=load('management_fixture_installed',base.SHARE/'installed.py');L=load('management_fixture_lifecycle',base.SHARE/'accepted_lifecycle.py')
    pacman=api.pacman(L,control['signer'],public=str(INPUTS/'TEST-public.asc'))
    baseline=L.inventory();C.need(len(baseline)==594 and all(n in baseline for n in TOOLS),'exact594 installed management profile required')
    preserved=metadata();CHANNEL.mkdir(mode=0o700);os.chown(CHANNEL,23001,23001)
    nonce=os.urandom(16).hex();(CHANNEL/'nonce').write_text(nonce);(CHANNEL/'nonce').chmod(0o644)
    C.need(deadline_ns==DL.service_lease()['deadline_ns'],'original service deadline required')
    profiles={};retired_profiles=set()
    sequence=0;armed=None;observed=None;fd=None;superfd=None;holder=None;lock_identity=None;progress=None
    def inventory():
        current=L.inventory();C.need(current in (baseline,{n:v for n,v in baseline.items() if n not in TOOLS}),'unexpected package composition');return current
    def unlock():
        nonlocal holder,lock_identity
        if holder is None:return
        info=Path('/var/lib/pacman/db.lck').lstat();C.need((info.st_dev,info.st_ino,info.st_mtime_ns,info.st_ctime_ns)==lock_identity,'foreign lock changed; no raw unlock allowed')
        C.need(holder.lib.alpm_trans_release(holder.handle)==0,'own fixture lock release failed');holder.close();holder=None;lock_identity=None
    try:
        while session.poll() is None:
            C.need(time.monotonic_ns()<deadline_ns,'managed session deadline')
            if armed and observed is None:
                observed=find(armed['tool'],armed['welcome_pid'],armed['previous'])
                if observed:
                    fd=os.pidfd_open(observed['pid']);superfd=os.pidfd_open(observed['supervisor_pid'])
                    if armed['stop']:
                        C.need(identity(observed['pid'])['starttime']==observed['starttime'],'helper changed before controlled stop')
                        signal.pidfd_send_signal(fd,signal.SIGSTOP);observed['stopped']=True
                    progress=Progress(observed,fd,superfd)
                    armed=None
            if progress is not None:progress.sample()
            request=CHANNEL/('request-'+str(sequence)+'.json')
            if not request.exists():time.sleep(.002);continue
            data=json.loads(C.read(request,65536,23001));C.need(data.get('nonce')==nonce and data.get('sequence')==sequence and sequence<1024,'bounded fixture request identity')
            op=data.get('operation');answer=dict(nonce=nonce,sequence=sequence,operation=op,status='PASS')
            if op=='profile':
                stage=data.get('stage');nonce_value=data.get('profile_nonce')
                answer['profile_lease']=issue_profile(profiles,retired_profiles,stage,nonce_value)
            elif op=='profile-retired':
                stage=data.get('stage');owner=profiles.get(stage)
                C.need(owner is not None and stage not in retired_profiles and data.get('profile_nonce')==owner['profile_nonce'],'current profile retirement identity required')
                value=DL.capture(HOME/('doctor-'+stage+'-'+owner['profile_nonce']),stage,owner['profile_nonce'],data.get('terminal_pid'),data.get('terminal_exit'))
                proof=DL.validate(value,stage,owner['profile_nonce'],data.get('terminal_pid'),data.get('worker_pid'))
                C.need(proof['parent']==owner,'retired profile lease differs');retired_profiles.add(stage);answer['profile_retirement']=proof
            elif op in ('remove','restore'):
                C.need(holder is None,'cannot transact under held fixture lock')
                if op=='remove':
                    C.need(inventory()==baseline,'tools already absent');L.command(pacman+['-R',*TOOLS],timeout=60)
                else:
                    C.need(len(inventory())==592,'tools must actually be absent')
                    restore_profile(L,pacman,products,baseline,preserved)
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
                progress=None
                armed=dict(tool=data['tool'],welcome_pid=data['welcome_pid'],stop=data['stop'],previous={int(p.name) for p in Path('/proc').glob('[0-9]*')});observed=None
            elif op=='observed':
                answer.update(process=observed,**completion(fd,superfd))
                if progress is not None:answer['gui_progress']=progress.value()
            elif op in ('retired','retired-proof'):
                answer.update(retirement_reply(op,observed,fd,superfd,progress,inventory,metadata,preserved))
            else:raise ValueError('unknown fixture operation')
            reply=CHANNEL/('reply-'+str(sequence)+'.json');pending=reply.with_suffix('.pending')
            with pending.open('xb') as stream:stream.write(C.encoded(answer));stream.flush();os.fsync(stream.fileno())
            pending.chmod(0o644);C.need(not reply.exists(),'fresh fixture reply required');pending.rename(reply);sequence+=1
        if session.returncode==0:C.need(set(profiles)==retired_profiles=={'minimal','overlay'},'both profile companions must retire')
        return session.returncode
    finally:
        unlock()
        # Only a still-live held pidfd is signaled on failure. Product cleanup is independently required to pass.
        for handle in (fd,superfd):
            if handle is not None:
                if not select.select([handle],[],[],0)[0]:signal.pidfd_send_signal(handle,signal.SIGKILL)
                os.close(handle)
        try:restore_profile(L,pacman,products,baseline,preserved)
        finally:L.command(['/usr/bin/gpgconf','--homedir','/tmp/management-trust','--kill','all'])

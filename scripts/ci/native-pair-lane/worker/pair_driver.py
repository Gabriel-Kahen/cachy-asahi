"""Pair-v1 implementation proposal. Import alone never dispatches an actor.

Root must admit this Source, interpreter/stdlib, mechanics and actual Performance
helper bundle separately. No default selection/pin or workflow entry is supplied.
Exact corrected core and live-adapter Sources are integrated below; Root retains admission and dispatch.
"""
from contextlib import contextmanager
import hashlib
import json
import math
import os
from pathlib import Path
import resource
import re
import signal
import stat
import time
import types

LANE='native-topmem-fish-zsh-integrated-pairs-v3'
ENTRY_SHA='89723f0a0b2ef80391160f451e877f15fb1e0c4d9a4fec6dbbb8e0d66d8d0f24'
RECIPES_SHA = 'd8344c4c6c0e2c640da1e40f21c16035f93d4d9839c03b2ca093cf713f40b5ea'
FAMILIES = {'topmem': 'packages/tools/cachy-asahi-topmem', 'fish': 'packages/shells/cachy-asahi-fish-bang-bang', 'zsh': 'packages/shells/cachy-asahi-zsh-autosuggestions'}
CONTROL=(signal.SIGINT,signal.SIGTERM,signal.SIGALRM)


def need(value,reason):
    if not value:raise ValueError(reason)


def live(end):need(0<time.monotonic()<end,'pair-original-deadline')
def sha(raw):return hashlib.sha256(raw).hexdigest()
def packed(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def ident(row):return(row.st_dev,row.st_ino,row.st_mode,row.st_uid,row.st_gid,row.st_nlink,row.st_size,row.st_mtime_ns,row.st_ctime_ns)


def decode(raw):
    def unique(rows):
        result={}
        for key,value in rows:need(key not in result,'duplicate-json-key');result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:need(False,'nonfinite-json'))


# A pending slot is a containment handoff, never permission to retry disposal.
BOOTSTRAP_UNRELEASED=[]


class BootstrapCutoff:
    def __init__(self,end):
        need(type(end)in(int,float)and math.isfinite(end)and end>0,'bootstrap-end-type')
        self.end=end;self.last=None;self.stopped=False

    def check(self):
        need(not self.stopped,'bootstrap-cutoff-already-failed')
        try:
            now=time.monotonic()
            need(type(now)in(int,float)and math.isfinite(now)and 0<now<self.end and
                 (self.last is None or now>=self.last),'bootstrap-original-cutoff')
            self.last=now
        except BaseException:
            self.stopped=True;raise


class BootstrapFD:
    # Slots are allocated before open; registration itself allocates no record.
    __slots__=('fd','path','sha256','end','identity','attempted','uncertainty','closed')
    def __init__(self,row,end):
        self.fd=None;self.path=row['path'];self.sha256=row['sha256'];self.end=end
        self.identity=None;self.attempted=False;self.uncertainty=None;self.closed=False


def load_pin(row,end):
    """Read captured Source before its original cutoff; preserve unretired custody.

    The first observed exception wins. A call that starts while eligible can
    finish after the endpoint; post-checks refuse success without inventing
    preemption. After a failed guard no identity/read/close operation may start.
    A pending slot blocks every subsequent load/module until Root containment.
    """
    budget=BootstrapCutoff(end);budget.check()
    need(not BOOTSTRAP_UNRELEASED,'bootstrap-containment-required')
    need(type(row)is dict and set(row)=={'path','sha256'}and type(row['path'])is str,
         'loader-pin-shape')
    path=Path(row['path']);need(path.is_absolute()and '..'not in path.parts,'loader-path')
    holder=BootstrapFD(row,end);first=None;result=None
    try:
        budget.check();before=os.lstat(path);budget.check()
        need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and
             0<=before.st_size<=1024**2,'loader-file')
        budget.check();BOOTSTRAP_UNRELEASED.append(holder);holder.attempted=True
        # Cancellation before returned-FD registration remains an unknown slot.
        # No mask/late unmask operation is needed or inferred safe at the cutoff.
        budget.check();holder.fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
        budget.check()
        need(type(holder.fd)is int and holder.fd>=0,'loader-fd-unproved')
        budget.check();opened=os.fstat(holder.fd);budget.check()
        holder.identity=ident(opened);need(ident(before)==holder.identity,'loader-open-drift')
        data=bytearray()
        while len(data)<before.st_size:
            budget.check();block=os.pread(holder.fd,min(65536,before.st_size-len(data)),len(data));budget.check()
            need(type(block)is bytes and 0<len(block)<=before.st_size-len(data),'loader-short-read');data.extend(block)
        budget.check();held=os.fstat(holder.fd);budget.check()
        budget.check();named=os.lstat(path);budget.check()
        need(ident(before)==ident(held)==ident(named),'loader-source-drift')
        budget.check();digest=sha(data);budget.check()
        need(digest==row['sha256'],'loader-source-pin')
        budget.check();result=bytes(data);budget.check()
    except BaseException as error:first=error
    # Finite one-shot disposal. No descriptor discovery or guessed numeric retry.
    if holder.attempted:
        if type(holder.fd)is int and holder.fd>=0:
            try:
                budget.check();os.close(holder.fd);holder.fd=None;holder.closed=True
                budget.check()
            except BaseException as error:
                holder.uncertainty=error
                if first is None:first=error
        else:
            holder.uncertainty='open-outcome-unproved'
        if holder.closed:
            try:BOOTSTRAP_UNRELEASED.remove(holder)
            except BaseException as error:
                holder.uncertainty=error
                if first is None:first=error
                try:first.retained_bootstrap_resources=(holder,)
                except BaseException:pass
        else:
            if first is None:first=ValueError('bootstrap-fd-retirement-unproved')
            try:first.retained_bootstrap_resources=tuple(BOOTSTRAP_UNRELEASED)
            except BaseException:pass
    if first is not None:raise first
    budget.check();return result


def module(raw,label,*,end):
    """Pinned-buffer compilation/execution has the same nonrenewed cutoff."""
    budget=BootstrapCutoff(end);budget.check()
    need(not BOOTSTRAP_UNRELEASED,'bootstrap-containment-required')
    need(type(raw)is bytes and len(raw)<=1024**2 and type(label)is str,'bootstrap-module-buffer')
    budget.check();result=types.ModuleType(label);budget.check()
    budget.check();code=compile(raw,label,'exec');budget.check()
    budget.check();exec(code,result.__dict__);budget.check()
    return result


@contextmanager
def deferred():
    previous=signal.pthread_sigmask(signal.SIG_BLOCK,set(CONTROL));first=None
    try:yield
    except BaseException as error:first=error;raise
    finally:
        try:signal.pthread_sigmask(signal.SIG_SETMASK,previous)
        except BaseException:
            if first is None:raise


@contextmanager
def controls(end):
    """Raising cancellation handlers; restore each original handler and timer."""
    live(end);need(signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0),'existing-alarm-refused')
    previous={};first=None
    def cancel(number,frame):raise TimeoutError('pair-control-'+str(number))
    try:
        with deferred():
            for number in CONTROL:previous[number]=signal.getsignal(number);signal.signal(number,cancel)
            signal.setitimer(signal.ITIMER_REAL,max(0.000001,end-time.monotonic()))
        yield
    except BaseException as error:first=error;raise
    finally:
        errors=[]
        try:
            with deferred():
                try:signal.setitimer(signal.ITIMER_REAL,0)
                except BaseException as error:errors.append(error)
                for number,handler in previous.items():
                    try:signal.signal(number,handler)
                    except BaseException as error:errors.append(error)
        except BaseException as error:errors.append(error)
        if first is None and errors:raise errors[0]


def names(files,path,end,expected):
    fd=files.directory(path,end);live(end);actual=os.listdir(fd)
    need(len(actual)<=4096 and len(actual)==len(expected)and set(actual)==set(expected),'closed-directory-membership')
    files.verify(end)


def read(node,end,cap=8*1024**2):
    need(node[2][6]<=cap,'read-cap');raw=bytearray()
    while len(raw)<node[2][6]:
        live(end);block=os.pread(node[1],min(65536,node[2][6]-len(raw)),len(raw));need(block,'read-short');raw.extend(block)
    live(end);return bytes(raw)


def provision(inputs,hook_names,uid,gid):
    """Only runs in the positively owned writable provision container."""
    filenames=[item['filename']for item in inputs['packages']]
    need(len(filenames)==248 and all('\n'not in name and '/'not in name and "'"not in name for name in filenames),'provision-filenames')
    quoted=' '.join("'/tmp/deps/"+name+"'"for name in filenames)
    masks='\n'.join('ln -s /dev/null /builder-disabled-hooks/'+name for name in sorted(hook_names))
    return ('''#!/usr/bin/env bash
set -euo pipefail
[[ $(id -u) == 0 && $(uname -m) == aarch64 ]]
export LC_ALL=C TZ=UTC
mkdir -p /usr/share/pacman/keyrings /tmp/deps /builder-disabled-hooks
cp /keys/archlinuxarm.gpg /keys/archlinuxarm-trusted /keys/archlinuxarm-revoked /usr/share/pacman/keyrings/
cp /deps/* /tmp/deps/
cp /context/pacman.conf /etc/pacman.conf
'''+masks+'''
pacman-key --init
pacman-key --populate archlinuxarm
pacman -U --noconfirm --noscriptlet '''+quoted+'''
ldconfig
rm -rf /tmp/deps /var/cache/pacman/pkg/*
groupmod -g '''+str(gid)+''' alarm
usermod -u '''+str(uid)+''' -g alarm alarm
pacman -Q | LC_ALL=C sort >/builder-packages.lock
diff -u /context/expected-packages.lock /builder-packages.lock
''').encode()


def preflight(value,pins,environment):
    need(type(pins)is dict and set(pins)=={'contract','recipes','entry','helper_admission','integration','bootstrap_bytes'},'root-integrated-pin-set')
    end=value.get('workflow_end') if type(value)is dict else None
    need(type(end)in(int,float)and math.isfinite(end)and end>time.monotonic(),'root-original-end')
    E=end-360;budget=BootstrapCutoff(E);budget.check()
    contract=module(load_pin(pins['contract'],E),'pair_contract_pinned',end=E)
    raw=load_pin(pins['recipes'],E);budget.check()
    budget.check();manifest_sha=sha(raw);budget.check();need(manifest_sha==RECIPES_SHA,'fixed-recipe-manifest')
    budget.check();recipes=decode(raw);budget.check()
    budget.check();deadlines=contract.selection(value,environment,time.monotonic(),recipes);budget.check()
    need(deadlines=={'work_end':E,'cleanup_end':end-180,'publication_end':end},'integrated-original-end-binding')
    need(pins['entry']['sha256']==ENTRY_SHA and pins['helper_admission']==value['helper_bundle'],'root-original-entry-integration-pins')
    helper=module(load_pin({k:value['helper_bundle'][k] for k in ('path','sha256')},E),'pair_integrated_bootstrap',end=E)
    need(helper.API=='integrated-pairs-v3','integrated-bootstrap-api')
    source=types.SimpleNamespace(load_pin=load_pin,module=module,ENTRY_SHA=ENTRY_SHA)
    session=helper.Session(source,value,pins,clock=time.monotonic)
    mechanics={name:module(load_pin(row,E),'pair_'+name+'_pinned',end=E) for name,row in value['mechanics'].items()}
    budget.check();need(all(getattr(mechanics[n],'RECOVERY_BOUND',None)==180 for n in ('process_owner','custody')),'shared-180-recovery')
    need(mechanics['input_audit'].INSTALL_SCRIPTS_ARE_NOT_HOOKS is True,'install-metadata-not-hooks')
    session.authority.check();return contract,recipes,deadlines,session,mechanics



class Runtime:
    """Root-selected, held Source/tool/file custody; no arbitrary actor callback."""
    def __init__(self,value,deadlines,mechanics,session):
        self.session=session;self.authority=session.authority
        self.value=value;self.deadlines=deadlines;self.mechanics=mechanics
        self.files=mechanics['custody'].Files();self.tools={};self.owner=None;self.first=None
        self.process_records=[];self.retirement=[];self.paths={};self.rootfs=None
        self.owned_cids=set();self.owned_images=set()
        self.closed_dirs={}
        self.failure_records=[];self.failure_bytes=0
        self.failure_at=None;self.recovery_end=deadlines['cleanup_end']

    def fail(self,error):
        """One earliest failure clock shared by process, daemon and file recovery."""
        if self.authority.primary is not None:error=self.authority.primary
        if self.first is None:self.first=error
        self.session.fail(error)
        try:
            with deferred():
                now=time.monotonic();observed=getattr(error,'first_failure_at',None)
                if observed is None:observed=now
                if not(type(observed)in(int,float)and __import__('math').isfinite(observed)and
                       self.value['original_entry']<=observed<=now):
                    self.retirement.append('invalid-process-failure-clock');observed=self.value['original_entry']
                if self.failure_at is None or observed<self.failure_at:self.failure_at=observed
                self.recovery_end=min(self.recovery_end,self.failure_at+180)
        except BaseException:
            self.retirement.append('failure-clock-recording-unproved')
            self.recovery_end=min(self.recovery_end,self.value['original_entry']+180)

    def gate(self,end):
        self.authority.check(cleanup=self.first is not None or end>self.authority.E)
        live(end);self.files.verify(end)
        for path,expected in self.closed_dirs.items():names(self.files,path,end,expected)
        for tool in self.tools.values():tool.verify(end)
        row=os.lstat('/run/docker.sock')
        need(stat.S_ISSOCK(row.st_mode)and row.st_uid==0 and list(ident(row)[:6])==self.value['socket_identity'],'selected-daemon-socket')

    def call(self,kind,args,end,pass_fds=(),limit=2*1024**2):
        try:return self._call(kind,args,end,pass_fds,limit)
        except BaseException as error:
            self.fail(error);self.capture_failure(kind,error);raise

    def _call(self,kind,args,end,pass_fds,limit):
        end=min(end,self.recovery_end,self.session.clock.recovery_end)
        self.selector(kind,args,pass_fds)
        self.gate(end)
        base={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','TZ':'UTC',
              'HOME':str(self.paths['home'])}
        if kind=='docker':
            args=(args[0],'--host=unix:///run/docker.sock',*args[1:]);base['DOCKER_CONFIG']=str(self.paths['docker'])
            if self.rootfs is not None:pass_fds=tuple(sorted(set((*pass_fds,self.rootfs[1]))))
        result=self.mechanics['process_owner'].run(args,base,str(self.paths['root']),tool=self.tools[kind],
               work_end=end,cleanup_end=min(self.recovery_end,self.session.clock.recovery_end),pass_fds=pass_fds,limit=limit)
        self.process_records.append({'kind':kind,'identity':result['identity'],'scope':result['scope'],'code':result['code']})
        need(len(self.process_records)<=8192,'process-record-cap')
        if result['code']!=0:
            error=ValueError('selected-tool-failure');error.captured_stdout=result['stdout'][:limit]
            error.process_identity=result['identity'];error.exit_code=result['code']
            error.first_failure_at=result.get('first_failure_at')
            raise error
        if kind=='docker'and tuple(args[2:4])in(('container','inspect'),('image','inspect')):
            objects=decode(result['stdout'])
            need(type(objects)is list and len(objects)==1 and type(objects[0])is dict,'role-inspect-shape')
            item=objects[0];identifier=item.get('Id');labels=item.get('Config',{}).get('Labels')
            rows=self.owner.containers if args[2]=='container'else self.owner.images
            matches=[row for row in rows if labels==self.owner._labels(row['role'])and
                     (args[2]=='image'or item.get('Name')=='/'+row['name'])]
            if len(matches)==1:
                (self.owned_cids if args[2]=='container'else self.owned_images).add(identifier)
        self.gate(end);return result['stdout']

    def capture_failure(self,kind,error):
        """In-memory bounded diagnostics; never replace cause to publish a log."""
        try:
            raw=getattr(error,'captured_stdout',b'');raw=raw if type(raw)is bytes else b''
            raw=raw[:max(0,4*1024**2-self.failure_bytes)]
            if len(self.failure_records)<64:
                self.failure_records.append({'kind':kind,'error_type':type(error).__name__,'stdout':raw,
                    'identity':getattr(error,'process_identity',None),'exit_code':getattr(error,'exit_code',None)})
                self.failure_bytes+=len(raw)
        except BaseException:pass

    def selector(self,kind,args,pass_fds):
        """Finite CLI roles; ownership of mutations remains the pinned broker's job."""
        need(type(args)in(tuple,list)and 1<=len(args)<=256 and
             all(type(arg)is str and 0<len(arg)<=8192 and '\0'not in arg for arg in args),'role-argv-bound')
        if kind=='gpg':
            prefix=('/usr/bin/gpg','--batch','--no-options','--homedir',str(self.paths['gpg']),
                    '--no-autostart','--no-auto-check-trustdb','--no-auto-key-retrieve','--status-fd','1')
            need(tuple(args[:len(prefix)])==prefix,'gpg-role-prefix');tail=tuple(args[len(prefix):])
            need((len(tail)==2 and tail[0]=='--import')or(len(tail)==3 and tail[0]=='--verify'),'gpg-role-selector')
            need(all(re.fullmatch('/proc/self/fd/[0-9]+',path)and int(path.rsplit('/',1)[1])in pass_fds for path in tail[1:]),'gpg-held-inputs')
            return
        need(kind=='docker'and args[0]=='/usr/bin/docker','docker-role-tool');tail=tuple(args[1:])
        if tail in(('info','--format','{{json .ID}}'),('info','--format','{{json .}}')):return
        need(self.owner is not None,'docker-owned-role-required')
        if tail[:6]==('container','ls','--all','--no-trunc','--format','{{json .}}'):
            need(len(tail)==8 and tail[6]=='--filter'and tail[7]in
                 {filter for row in self.owner.containers for filter in
                  ('name=^/'+row['name']+'$',*(('id='+row['id'],)if row['id']is not None else()))},'docker-container-index-role');return
        if tail[:5]==('image','ls','--all','--no-trunc','--quiet'):
            allowed={()}|{tuple(arg for key,item in sorted(self.owner._labels(row['role']).items())
                    for arg in('--filter','label='+key+'='+item))for row in self.owner.images}
            need(tail[5:]in allowed,'docker-image-index-role');return
        if len(tail)==3 and tail[:2]in(('container','inspect'),('container','start'),('container','wait'),('container','logs')):
            need(re.fullmatch('[0-9a-f]{64}',tail[2])and(tail[1]=='inspect'or tail[2]in self.owned_cids),'docker-full-cid-role');return
        if len(tail)==4 and tail[:3]==('container','rm','--force'):
            need(re.fullmatch('[0-9a-f]{64}',tail[3])and tail[3]in self.owned_cids,'docker-full-rm-cid-role');return
        if len(tail)==3 and tail[:2]in(('image','inspect'),('image','rm')):
            need(re.fullmatch('sha256:[0-9a-f]{64}',tail[2])and(tail[1]=='inspect'or tail[2]in self.owned_images),'docker-full-image-role');return
        if tail[:4]==('image','import','--platform','linux/arm64'):
            expected=('image','import','--platform','linux/arm64',*self.owner._changes('rootfs'),
                      '--change','USER 0:0','--change','WORKDIR /',
                      '/proc/self/fd/'+str(self.rootfs[1]))
            need(tail==expected,'docker-import-role');return
        if tail[:3]==('container','commit','--pause=false'):
            expected=('container','commit','--pause=false',*self.owner._changes('compiler'),
                      '--change',f'USER {self.value["uid"]}:{self.value["gid"]}','--change','WORKDIR /tmp',
                      '--change','ENTRYPOINT []','--change','CMD []',tail[-1])
            need(tail==expected and tail[-1]in self.owned_cids and any(row['role']=='provision'and row['id']==tail[-1]
                 for row in self.owner.containers),'docker-owned-commit-role');return
        if tail[0]=='create':
            candidates=[]
            for row in self.owner.containers:
                options=('create','--name',row['name'],'--pull=never','--platform','linux/arm64',
                         '--network=none','--cpus=2','--memory=4g','--memory-swap=4g','--pids-limit=256',
                         '--cap-drop=ALL','--security-opt=no-new-privileges','--restart=no','--ipc=private',
                         '--cgroupns=private','--runtime=runc','--user',row['user'],'--entrypoint','/bin/bash')
                if row['role']!='provision':options+=('--read-only','--tmpfs','/tmp:rw,nosuid,nodev,exec,size=4g')
                else:options+=tuple(arg for cap in('CHOWN','DAC_OVERRIDE','FOWNER','SETGID','SETUID')for arg in('--cap-add',cap))
                options+=self.owner._label_args(row['role'])
                options+=tuple(arg for item in row['environment']for arg in('--env',item))
                options+=tuple(arg for mount in row['mounts']for arg in('--mount',
                         'type=bind,src='+mount['source']+',dst='+mount['target']+(',readonly'if mount['readonly']else'')))
                candidates.append((*options,row['image'],*row['command']))
            need(tail in candidates,'docker-exact-create-role');return
        raise ValueError('docker-finite-provision-role')

    def initialize(self):
        value=self.value;end=self.deadlines['work_end']
        self.authority.check();live(end)
        uid=os.getuid()
        self.authority.check();live(end)
        need(uid==value['uid'],'actual-native-identity')
        self.authority.check();live(end)
        gid=os.getgid()
        self.authority.check();live(end)
        need(gid==value['gid'],'actual-native-identity')
        self.authority.check();live(end)
        platform=os.uname()
        self.authority.check();live(end)
        need(platform.machine=='aarch64','actual-native-identity')
        self.authority.check();live(end)
        limits=resource.getrlimit(resource.RLIMIT_NOFILE)
        self.authority.check();live(end)
        need(limits[0]>=2048,'finite-fd-capacity')
        self.paths['root']=self.files.fresh(value['work_root'],end)
        for name in('home','docker','gpg','deps','keys','context','sources','outputs','auth'):
            self.paths[name]=self.files.fresh(self.paths['root']/name,end)
        for kind in('docker','gpg'):
            with deferred():self.tools[kind]=self.mechanics['process_owner'].VerifiedTool('/usr/bin/'+kind,value['tools'][kind],end=end)
        for path,pin in value['tool_closure'].items():
            node,_=self.files.file(path,end,sha=pin,uid=0,cap=128*1024**2)
            need(not node[2][2]&0o022,'linked-tool-not-root-controlled')
            # Every ancestor is root-controlled; no same-user loader replacement.
            for parent in Path(path).parents:
                self.authority.check();live(end)
                row=os.lstat(parent)
                self.authority.check();live(end)
                need(stat.S_ISDIR(row.st_mode)and row.st_uid==0 and not row.st_mode&0o022,'linked-tool-ancestor')
        self.gate(end)
        observed=decode(self.call('docker',('/usr/bin/docker','info','--format','{{json .}}'),end))
        need(type(observed)is dict and observed.get('ID')==value['daemon_id']and
             observed.get('Architecture')in('aarch64','arm64')and observed.get('OSType')=='linux',
             'fresh-native-daemon-identity')

    def bind_owner(self,journal,source_binding,context):
        runtime=self
        class SharedOwner(self.mechanics['container_owner'].Owner):
            def _cause(self,error):
                runtime.fail(error);super()._cause(error)
        value=self.value
        self.owner=SharedOwner(lambda argv,end:self.call('docker',argv,end),journal,
               work_end=self.deadlines['work_end'],cleanup_end=self.recovery_end,
               daemon_id=value['daemon_id'],source_sha=source_binding,context_sha=context,
               nonce=value['nonce'],uid=value['uid'],gid=value['gid'])
        return self.owner

    def clean(self):
        """Attempt all bounded retirement, preserving the original exception."""
        self.recovery_end=min(self.recovery_end,self.session.clock.recovery_end)
        summary={'status':'PASS','errors':[],'cause':None}
        with deferred():
            if self.owner is not None:
                self.owner.cleanup_end=min(self.owner.cleanup_end,self.recovery_end)
                try:summary=self.owner.cleanup()
                except BaseException as error:
                    self.fail(error)
                    summary={'status':'FAIL','errors':[{'error_type':type(error).__name__}],'cause':type(error).__name__}
            try:self.files.verify(min(self.recovery_end,self.session.clock.recovery_end))
            except BaseException as error:
                self.retirement.append('final-custody:'+type(error).__name__)
                self.fail(error)
            for kind,tool in reversed(list(self.tools.items())):
                try:live(min(self.recovery_end,self.session.clock.recovery_end));tool.close()
                except BaseException as error:
                    self.retirement.append(kind+':'+type(error).__name__)
                    self.fail(error)
            self.retirement.extend(self.files.close(end=lambda:min(self.recovery_end,self.session.clock.recovery_end)))
            try:live(min(self.recovery_end,self.session.clock.recovery_end))
            except BaseException as error:
                self.retirement.append('recovery-end-expired');self.fail(error)
        if self.retirement:
            summary['status']='FAIL';summary['errors'].extend({'retirement':error}for error in self.retirement)
        if summary['status']!='PASS'or summary['cause']is not None:
            if self.first is None:self.fail(ValueError('owned-resource-cleanup-unproved'))
        return summary


def authenticate(runtime,contract):
    files=runtime.files;value=runtime.value;end=runtime.deadlines['work_end'];audit=runtime.mechanics['input_audit']
    node,_=files.file(value['inputs_path'],end,sha=contract.INPUTS,cap=4*1024**2);inputs=decode(read(node,end))
    inventory,_=files.file(value['inventory_path'],end,sha=contract.INVENTORY,cap=1024**2)
    rows=audit.objects(inputs);names(files,value['cache'],end,{row['filename']for row in rows})
    cached={}
    for row in rows:
        cached[row['filename']],_=files.file(Path(value['cache'])/row['filename'],end,
               sha=row['sha256'],size=row['size'],uid=value['uid'],mode=0o600)
    names(files,value['cache'],end,set(cached));runtime.rootfs=cached[inputs['rootfs']['filename']]
    runtime.closed_dirs[value['cache']]=set(cached)
    gpg=('/usr/bin/gpg','--batch','--no-options','--homedir',str(runtime.paths['gpg']),
         '--no-autostart','--no-auto-check-trustdb','--no-auto-key-retrieve','--status-fd','1')
    key=cached['archlinuxarm.gpg'];runtime.call('gpg',(*gpg,'--import','/proc/self/fd/'+str(key[1])),end,(key[1],))
    hooks=set();auth=[]
    for index,item in enumerate([inputs['rootfs'],*inputs['packages']]):
        payload=cached[item['filename']];signature=cached[item['filename']+'.sig']
        raw=runtime.call('gpg',(*gpg,'--verify','/proc/self/fd/'+str(signature[1]),'/proc/self/fd/'+str(payload[1])),
                         end,(signature[1],payload[1]),1024**2)
        record=audit.signature(raw);files.write(runtime.paths['auth']/(str(index)+'.status'),raw,end)
        archive=audit.inspect(payload,end,rootfs=index==0,expected=None if index==0 else item)
        if index==0:
            canonical=lambda items:sorted(items,key=lambda row:row['name'])
            need(canonical(archive['inventory'])==canonical(inputs['rootfs_packages']),'exact-signed-rootfs-inventory')
        hooks.update(Path(name).name for name in archive['hooks']);auth.append({'filename':item['filename'],**record})
        files.verify(end)
    need(len(auth)==249,'all249-signatures');audit.hook_masks(hooks)
    for item in inputs['packages']:
        for name in(item['filename'],item['filename']+'.sig'):files.copy(cached[name],runtime.paths['deps']/name,end)
    for row in inputs['keyring_files']:files.copy(cached[row['filename']],runtime.paths['keys']/row['filename'],end)
    files.copy(inventory,runtime.paths['context']/'expected-packages.lock',end)
    files.write(runtime.paths['auth']/'records.json',packed(auth),end)
    names(files,runtime.paths['deps'],end,{name for item in inputs['packages']for name in(item['filename'],item['filename']+'.sig')})
    names(files,runtime.paths['keys'],end,{row['filename']for row in inputs['keyring_files']})
    runtime.closed_dirs[runtime.paths['deps']]={name for item in inputs['packages']for name in(item['filename'],item['filename']+'.sig')}
    runtime.closed_dirs[runtime.paths['keys']]={row['filename']for row in inputs['keyring_files']}
    return inputs,hooks


def snapshot(runtime,recipes,session):
    files=runtime.files;end=runtime.deadlines['work_end'];snapshots={}
    session.authority.check()
    for family,directory in FAMILIES.items():
        expected={Path(name).name for name in recipes if str(Path(name).parent)==directory}
        names(files,Path(runtime.value['source_root'])/directory,end,expected)
        target=files.fresh(runtime.paths['sources']/family,end);snapshots[family]=target
        for name,row in recipes.items():
            if str(Path(name).parent)!=directory:continue
            node,_=files.file(Path(runtime.value['source_root'])/name,end,sha=row['sha256'],size=row['bytes'],mode=row['mode'],cap=8*1024**2)
            files.copy(node,target/Path(name).name,end,mode=row['mode'])
        names(files,target,end,expected);files.verify(end);runtime.closed_dirs[target]=expected
        # All seven/twelve exact bytes pin the recipe; parse the retained SRCINFO.
        srcinfo=files.paths[str(target/'.SRCINFO')]
        need(recipe_metadata(read(srcinfo,end))==session.modules['pair_compare'].SELECTED_METADATA[family],'source19-recipe-metadata')
        session.authority.check()
    return snapshots


def recipe_metadata(raw):
    need(type(raw)is bytes and len(raw)<=65536,'srcinfo-bound')
    fields=('arch','depends','epoch','license','optdepends','pkgname','pkgrel','pkgver','sha256sums','source')
    result={k:[] for k in fields};result['epoch']=['0']
    for line in raw.decode('utf-8').splitlines():
        text=line.strip()
        if not text or text.startswith('#'):continue
        need(' = ' in text,'srcinfo-assignment')
        key,value=text.split(' = ',1)
        if key in result:
            if key=='epoch':result[key]=[]
            result[key].append(value)
    need(all(result[k] for k in ('arch','depends','license','pkgname','pkgrel','pkgver','sha256sums','source')),'srcinfo-required')
    return result



def builds(runtime,contract,recipes,session,snapshots,image,entry,pins):
    files=runtime.files;end=runtime.deadlines['work_end'];records={};evidence={};reservations={};tickets={}
    # All four exact full CIDs exist before the single four-output Admission.
    root=Path(pins['integration']['native']['checker_root'])
    for label in contract.LABELS:
        session.authority.check();family=label.split('-')[0]
        output=files.fresh(root/(runtime.value['nonce']+'-'+label),end)
        mounts=[{'source':str(snapshots[family]),'target':'/inputs','readonly':True},
                {'source':str(output),'target':'/out','readonly':False},
                {'source':str(entry),'target':'/builder-entry.sh','readonly':True},
                {'source':str(runtime.paths['context']/'expected-packages.lock'),'target':'/expected-packages.lock','readonly':True}]
        ticket=runtime.owner.reserve(label,image,mounts=mounts,command=['/builder-entry.sh'],
            environment=['CACHY_ASAHI_CONTAINER=1','SOURCE_DATE_EPOCH='+str(contract.EPOCH)])
        cid=runtime.owner.create(ticket);tickets[label]=(ticket,cid,output)
    need(len({cid for _,cid,_ in tickets.values()})==6,'four-created-full-cids')
    for label in contract.LABELS:
        ticket,cid,output=tickets[label];runtime.owner.start(ticket);code=runtime.owner.wait(ticket)
        completed=session.authority.check()
        canonical=session.driver_labels[label] if hasattr(session,'driver_labels') else {
            'topmem-1':'topmem-current-1','topmem-2':'topmem-current-2','fish-1':'fish-current-1','fish-2':'fish-current-2','zsh-1':'zsh-current-1','zsh-2':'zsh-current-2'}[label]
        row=runtime.owner._ticket(ticket)
        reservations[canonical]=session.capabilities.LeaseReservation(canonical,ticket,row,completed,runtime.owner.source_sha)
        files.write(output/'container.log',runtime.owner.logs(ticket),end)
        fd=files.directory(output,end);live(end);found=os.listdir(fd);live(end)
        need(1<=len(found)<=64 and len(set(found))==len(found) and all(n not in ('','.','..') and '/' not in n for n in found),'bounded-output-membership')
        rows={};nodes={}
        for name in sorted(found):
            node,digest=files.file(output/name,end,uid=runtime.value['uid'],cap=64*1024**2)
            mode=stat.S_IMODE(node[2][2]);need(mode in (0o600,0o644,0o755),'output-mode')
            rows[name]={'sha256':digest,'bytes':node[2][6],'mode':mode};nodes[name]=node
        required={'packages.lock','environment.txt','config.sha256','makepkg.conf','pacman.conf','generated.SRCINFO','container.log'}
        package=session.modules['pair_compare'].ARTIFACTS[family]
        need(required|{package}<=set(rows) and all(name.endswith('.log') for name in set(rows)-required-{package}),'closed-build-output-and-log-members')
        need(rows[package]['mode']==0o644 and rows[package]['bytes']<=4*1024**2 and rows['packages.lock']['mode']==0o644,'core-output-bounds')
        need(read(nodes['packages.lock'],end)==read(files.paths[str(runtime.paths['context']/'expected-packages.lock')],end),'build-exact341')
        need(recipe_metadata(read(nodes['generated.SRCINFO'],end))==session.modules['pair_compare'].SELECTED_METADATA[label.split('-')[0]],'actual-generated-recipe-metadata')
        files.verify(end);names(files,output,end,set(rows));runtime.closed_dirs[output]=set(rows)
        evidence[label]={'root':output,'nodes':nodes,'evidence':rows}
        fixture_report=None
        if family=='zsh':
            need('zsh-native-fixtures.log' in nodes and rows['zsh-native-fixtures.log']['bytes']<=262144,'zsh-fixture-log-required')
            fixture_report=contract.zsh_fixtures(decode(read(nodes['zsh-native-fixtures.log'],end)))
        records[label]={'label':label,'image_id':image,'container_id':cid,'exit_code':code,
          'source_date_epoch':contract.EPOCH,'status':'built-package-static-pass','evidence':rows,
          'recipe_rows_sha256':RECIPES_SHA,'helper_sha256':runtime.value['helper_bundle']['sha256'],'inventory_sha256':contract.INVENTORY}
        if family=='zsh':records[label]['zsh_fixture_report']=fixture_report
    bridge=session.prepare_checker(reservations,evidence,image,runtime.owner.context_sha)
    for old in contract.LABELS:
        canonical={'topmem-1':'topmem-current-1','topmem-2':'topmem-current-2','fish-1':'fish-current-1','fish-2':'fish-current-2','zsh-1':'zsh-current-1','zsh-2':'zsh-current-2'}[old]
        family=old.split('-')[0];common={k:bridge.expected[k] for k in session.modules['pair_compare'].COMMON}
        row={**common,'label':canonical,'container_id':records[old]['container_id'],'mode':'native','exit_code':records[old]['exit_code'],
            'recipe_inputs':bridge.expected['packages'][family]['recipe_inputs'],'recipe_metadata':bridge.expected['packages'][family]['recipe_metadata']}
        checked=bridge.check(canonical,bridge.routes['packages'][canonical],row)
        package=checked['summary']['artifact']
        need(checked['summary']['compressed_sha256']==records[old]['evidence'][package]['sha256'],'independent-runtime-package-sha')
        records[old]['checker_build']=checked
    private_gate=bridge.finish();comparisons={}
    for family,labels in (('topmem',contract.LABELS[:2]),('fish',contract.LABELS[2:4]),('zsh',contract.LABELS[4:])):
        strict=bridge.comparisons[family] if hasattr(bridge,'comparisons') else {
            'equalities':private_gate['packages'][family],'artifact':bridge.expected['packages'][family]['artifact']}
        need(all(strict['equalities'][k] is True for k in contract.GATES),'actual-strict-four-equalities')
        # Legacy envelope is derived only from the successfully issued strict gate.
        comparisons[family]={'labels':list(labels),'errors':[], 'packages':{strict['artifact']:dict(strict['equalities'])}}
    files.verify(end);session.authority.check();return records,comparisons,private_gate



def bounded_journal(runtime,path):
    files=runtime.files;end=runtime.deadlines['work_end']
    runtime.authority.check()
    files.journal(path,end) # Adopt the original mutable append FD during E.
    runtime.authority.check();node=files.paths[str(path)];total=0
    def guard():
        runtime.authority.check(cleanup=True)
        live(min(runtime.recovery_end,runtime.session.clock.recovery_end))
    def append(raw):
        nonlocal total
        guard();need(type(raw)is bytes and len(raw)<=256*1024 and total+len(raw)+1<=32*1024**2,'journal-cap')
        files.verify(min(runtime.recovery_end,runtime.session.clock.recovery_end));guard()
        data=raw+b'\n';position=0
        while position<len(data):
            guard();count=os.write(node[1],data[position:]);guard()
            need(type(count)is int and 0<count<=len(data)-position,'journal-short-write');position+=count
        guard();os.fsync(node[1]);guard();total+=len(data)
        files.verify(min(runtime.recovery_end,runtime.session.clock.recovery_end));guard()
    return append


def execute(value,pins,environment):
    """Run an admitted worker; return PRIVATE evidence for Root containment."""
    end=value.get('workflow_end') if type(value)is dict else None
    need(type(end)in(int,float)and math.isfinite(end)and end>time.monotonic(),'root-original-end')
    with controls(end):
        contract,recipes,deadlines,session,mechanics=preflight(value,pins,environment)
        runtime=Runtime(value,deadlines,mechanics,session);result=None;cleanup=None;helper_cleanup=None
        try:
            runtime.initialize();inputs,hooks=authenticate(runtime,contract)
            session.stage(runtime,recipes);session.load_graph()
            snapshots=snapshot(runtime,recipes,session);files=runtime.files;E=deadlines['work_end']
            node,_=files.file(pins['entry']['path'],E,sha=ENTRY_SHA,cap=1024**2)
            entry=files.copy(node,runtime.paths['root']/'builder-entry.sh',E,mode=0o755)
            pacman=b'[options]\nArchitecture = aarch64\nSigLevel = Required\nLocalFileSigLevel = Required\nHookDir = /builder-disabled-hooks\n'
            files.write(runtime.paths['context']/'pacman.conf',pacman,E,mode=0o644)
            script=provision(inputs,hooks,value['uid'],value['gid']);script_path=files.write(runtime.paths['root']/'provision.sh',script,E,mode=0o755)
            runtime.closed_dirs[runtime.paths['context']]={'pacman.conf','expected-packages.lock'}
            context=sha(packed({'inputs':contract.INPUTS,'inventory':contract.INVENTORY,'epoch':contract.EPOCH,
                'pacman':sha(pacman),'provision':sha(script),'uid':value['uid'],'gid':value['gid']}))
            source_binding=sha(packed({'job':contract.job_binding(value,RECIPES_SHA),'contract':pins['contract']['sha256'],
                'entry':ENTRY_SHA,'integration':{k:v for k,v in pins['integration'].items() if k!='native'}}))
            journal=bounded_journal(runtime,runtime.paths['root']/'resources.jsonl')
            runtime.bind_owner(journal,source_binding,context)
            files.verify(E);root_image=runtime.owner.import_rootfs('/proc/self/fd/'+str(runtime.rootfs[1]))
            mounts=[{'source':str(runtime.paths[n]),'target':'/'+n,'readonly':True} for n in ('deps','context','keys')]
            mounts.append({'source':str(script_path),'target':'/provision.sh','readonly':True})
            ticket=runtime.owner.reserve('provision',root_image,mounts=mounts,command=['/provision.sh'],environment=[])
            runtime.owner.create(ticket);runtime.owner.start(ticket);runtime.owner.wait(ticket)
            files.write(runtime.paths['root']/'provision.log',runtime.owner.logs(ticket),E);image=runtime.owner.commit(ticket)
            records,comparisons,gate=builds(runtime,contract,recipes,session,snapshots,image,entry,pins)
            result={'schema':1,'lane':LANE,'job':contract.job_binding(value,RECIPES_SHA),
                'inputs':{'sha256':contract.INPUTS,'inventory_sha256':contract.INVENTORY,'objects':501,'signatures':249,'source_date_epoch':contract.EPOCH},
                'image':{'id':image,'inventory_sha256':contract.INVENTORY,'platform':'linux/arm64','context_sha256':context,
                    'provision_sha256':sha(script),'daemon_id':value['daemon_id']},'builds':records,'comparisons':comparisons,
                'first_failure':None,'native_build':'PRIVATE_CHECKED','signing':'NOT RUN','lifecycle':'NOT RUN','hardware':'NOT RUN'}
            files.verify(E);session.authority.check()
        except BaseException as error:runtime.fail(error)
        finally:
            try:helper_cleanup=session.cleanup()
            except BaseException as error:runtime.fail(error)
            try:cleanup=runtime.clean()
            except BaseException as error:runtime.fail(error)
        if runtime.first is not None:
            try:runtime.first.pair_diagnostics={'private_result':result,'process_records':runtime.process_records,
                'failure_records':runtime.failure_records,'cleanup':cleanup,'helper_cleanup':helper_cleanup,
                'retained_session':session,'failure_at':runtime.failure_at,'recovery_end':runtime.recovery_end,
                'publication_end':deadlines['publication_end']}
            except BaseException:pass
            raise runtime.first
        need(cleanup['status']=='PASS' and cleanup['errors']==[] and cleanup['cause'] is None,'runtime-cleanup-required')
        result['cleanup']=cleanup
        session.clock.cleanup();session.authority.check(cleanup=True)
        # Returned mappings/contexts stay strongly held. Root must observe the
        # selected worker's actual exit/absence before publishing native PASS.
        return {'schema':1,'status':'PRIVATE_ROOT_CONTAINMENT_REQUIRED','result':result,'strict_gate':gate,
            'helper_cleanup':helper_cleanup,'capacity_tape':session.capacity_tape,'native_binding':dict(session.job),
            'native_selection':{'library':dict(session.library_row),'dependencies':pins['integration']['native']['dependencies'],
                'interpreter':pins['integration']['native']['interpreter'],'stdlib_binding':session.job['stdlib_binding']},
            'process_records':runtime.process_records,'publication_end':deadlines['publication_end'],
            'original_start':session.authority.start,'original_E':session.authority.E,'original_J':session.authority.J,
            'recovery_end':runtime.recovery_end,'retained_session':session,'publication_allowed':False}



if __name__=='__main__':
    raise SystemExit('REFUSED: callable integrated Source requires exact Root native selection and original guardian; no default dispatch')

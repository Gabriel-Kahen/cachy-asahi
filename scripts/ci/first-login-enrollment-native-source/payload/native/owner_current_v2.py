# SPDX-License-Identifier: MIT
"""Current onboarding owner successor. No operational work occurs on import.

Uses the held Commands/owned_process runner. A finite Docker proxy retains
create/inspect/start/remove observations around the unchanged generic builder.
Lifecycle has separate local and outer retirement phases; no live actor claims
its own absence. All entry points require an externally pinned Root admission.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import sys
import tempfile
import time

API='CURRENT_ONBOARDING_OWNED_CALLBACKS_V2'
OP='first-login-enrollment-ui-current-v2'
LABEL='org.cachy-asahi.current-onboarding'
DOCKER=['/usr/bin/docker','--host=unix:///var/run/docker.sock']
ROOT=Path(__file__).resolve().parents[5]
FAMILY='scripts/ci/first-login-enrollment-native-source'
ROUTE=FAMILY+'/successor_v2/owned_route.py'
DEPS={
 'scripts/workflows/developer_workflow.py':'531c124cde3fa41d46888acfc638c823196bb2f297b19ab68ab3d001b05f16ba',
 'scripts/virtual/owned_process.py':'83444522f4dfede67f6965ea75de8411b9e34510c04d40571fe439c223294e8f',
 FAMILY+'/payload/native/build_tools_tools_v2.py':'eb1ff0ee8aefc2c0e32b38520e1bf0dabcbb9308081a24e2f9c378366a3cab13',
 FAMILY+'/payload/native/build_tools_alpm_v2.py':'d4197495e0281aecfd590e76ed908cd1fcf46b1934bc02709e47a7dac49abb73',
 ROUTE:'43db41de72822cb8f4d875b6c1d17ffd5062770616ed303f63e299c13478dd86',
 FAMILY+'/successor_v2/native.py':'cde384acd8574ddfcb07f7316ad4d24349f5b958ac6b2cea48a3a6aff480c827',
 FAMILY+'/successor_v2/profile.json':'8ad3641649e395b1202363e3368f713f65252a743b12e3a8d69430e4f82bc171'}
_INSIDE=None


def need(value,why):
    if not value:raise ValueError(why)


def encoded(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def raw(path,cap=16*1024**2):
    p=Path(path);need(p.is_absolute() and not any(q.is_symlink() for q in (p,*p.parents)),'absolute nonaliased owner DATA')
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        a=os.fstat(fd);need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and 0<=a.st_size<=cap,'bounded single-link owner DATA')
        pieces=[];size=0
        while block:=os.read(fd,min(65536,cap+1-size)):
            pieces.append(block);size+=len(block);need(size<=cap,'owner DATA cap')
        b=os.fstat(fd);identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        need(size==a.st_size and identity(a)==identity(b)==identity(p.lstat()),'owner DATA changed while reading')
        return b''.join(pieces)
    finally:os.close(fd)


def save(path,value):
    path=Path(path);data=encoded(value)
    with path.open('xb') as stream:os.fchmod(stream.fileno(),0o600);stream.write(data)


def ref(row,cap=16*1024**2):
    need(type(row) is dict and set(row)=={'path','bytes','sha256'},'nonnull whole Root owner input')
    body=raw(row['path'],cap);need(pin(body)=={k:row[k] for k in ('bytes','sha256')},'Root owner input pin');return body


def module(name,path,body,extra=None):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec)
    if extra:m.__dict__.update(extra)
    sys.modules[name]=m;exec(compile(body,str(path),'exec'),m.__dict__);return m


def dependencies():
    bodies={n:raw(ROOT/n,128*1024) for n in DEPS}
    need(all(pin(b)['sha256']==DEPS[n] for n,b in bodies.items()),'whole held owner/route dependency closure')
    W=module('current_owner_workflow',ROOT/'scripts/workflows/developer_workflow.py',bodies['scripts/workflows/developer_workflow.py'])
    T=module('current_owner_tools',ROOT/(FAMILY+'/payload/native/build_tools_tools_v2.py'),bodies[FAMILY+'/payload/native/build_tools_tools_v2.py'])
    before=bodies[FAMILY+'/payload/native/build_tools_alpm_v2.py'];seam=b'import build_tools_tools_v2 as T'
    need(before.count(seam)==1,'one trusted ALPM helper import seam')
    after=before.replace(seam,b'T=__held_tools');need(after.replace(b'T=__held_tools',seam)==before,'exact held ALPM import inverse')
    A=module('current_owner_alpm',ROOT/(FAMILY+'/payload/native/build_tools_alpm_v2.py'),after,{'__held_tools':T})
    R=module('current_owner_route',ROOT/ROUTE,bodies[ROUTE])
    return W,T,A,R


def stage_token(grant):
    need(type(grant) is dict and grant.get('schema')==1 and grant.get('issuer')=='Root' and grant.get('approved') is True and
         grant.get('operation')==OP and grant.get('stage') in ('backend','ui','lifecycle') and
         type(grant.get('selector')) is str and grant['selector'],'distinct approved current owner stage')
    return hashlib.sha256(encoded(dict(binding=grant['binding'],selector=grant['selector'],stage=grant['stage']))).hexdigest()[:24]


def generic_intent(argv,grant,source,output,uid,gid):
    """The one declared generic-builder vector, before any Docker mutation."""
    token=stage_token(grant);source=Path(source);output=Path(output);stage=grant['stage']
    need(stage in ('backend','ui') and type(argv) is list,'generic current build stage')
    need(len(argv)==39 and argv[:4]==['docker','run','--rm','--name'] and
         re.fullmatch('cachy-asahi-[0-9a-f]{16}',argv[4]),'one exact fresh generic build name/vector')
    name=argv[4];image=grant['images'][stage]['id'];slot=None
    mounts={}
    for item in argv:
        if item.startswith('type=bind,src='):
            match=re.fullmatch(r'type=bind,src=([^,\n]+),dst=([^,\n]+)(,readonly)?',item)
            need(match is not None,'closed generic bind');dst=match[2]
            need(dst not in mounts,'unique generic bind destination');mounts[dst]=(match[1],match[3] is None)
    need(set(mounts)=={'/inputs','/out','/builder-entry.sh','/expected-packages.lock'},'four exact generic binds')
    for kind in (('ui',) if stage=='ui' else ('enrollment','first-login')):
        for label in ('a','b'):
            candidate=output/'builds'/(kind+'-'+label)
            if mounts['/out']==(str(candidate/'artifacts'),True):slot=candidate
    need(slot is not None and mounts=={'/inputs':(str(slot/'inputs'),False),'/out':(str(slot/'artifacts'),True),
         '/builder-entry.sh':(str(source/'scripts/build/container-entry.sh'),False),'/expected-packages.lock':(str(slot/'expected-packages.lock'),False)},'same current private build slot')
    epoch=str(grant['source_date_epoch'])
    expected=['docker','run','--rm','--name',name,'--pull=never','--platform','linux/arm64','--user',f'{uid}:{gid}',
      '--cap-drop=ALL','--security-opt=no-new-privileges','--read-only','--pids-limit','512','--memory','4g','--cpus','4',
      '--network','none','--tmpfs','/tmp:rw,nosuid,nodev,exec,size=4g','--env','CACHY_ASAHI_CONTAINER=1','--env','SOURCE_DATE_EPOCH='+epoch]
    for dst in ('/inputs','/out','/builder-entry.sh','/expected-packages.lock'):
        src,rw=mounts[dst];expected+=['--mount','type=bind,src='+src+',dst='+dst+('' if rw else ',readonly')]
    expected+=['--entrypoint','/bin/bash',image,'/builder-entry.sh']
    need(argv==expected,'every generic image/user/resource/security/network/entry operand')
    labels={LABEL:token,LABEL+'.operation':OP,LABEL+'.stage':stage,LABEL+'.source':grant['binding']['source']}
    create=DOCKER+['create',*argv[3:-4],'--memory-swap=4g']
    for key,value in labels.items():create+=['--label',key+'='+value]
    create+=argv[-4:]
    return dict(name=name,image=image,user=f'{uid}:{gid}',mounts=[(d,s,rw) for d,(s,rw) in mounts.items()],
                entrypoint=['/bin/bash'],cmd=['/builder-entry.sh'],labels=labels,readonly=True,create_argv=create,
                declared_argv=argv,slot=str(slot),capadd=[],tmpfs={'/tmp':'rw,nosuid,nodev,exec,size=4g'})


def inspect_container(row,intent,token):
    need(row['Name']=='/'+intent['name'] and re.fullmatch('[0-9a-f]{64}',row['Id']) and row['Image']==intent['image'], 'exact owned CID/name/image')
    c,h=row['Config'],row['HostConfig']
    need(c['User']==intent['user'] and c['Entrypoint']==intent['entrypoint'] and c['Cmd']==intent['cmd'] and
         all(c['Labels'].get(k)==v for k,v in intent['labels'].items()) and c['Labels'].get(LABEL)==token,'exact owned config/labels')
    need(h['NetworkMode']=='none' and h['ReadonlyRootfs'] is intent['readonly'] and h['Privileged'] is False and
         h['CapDrop']==['ALL'] and (h['CapAdd'] or [])==intent.get('capadd',[]) and h['SecurityOpt']==['no-new-privileges'] and
         not h.get('VolumesFrom') and h.get('Tmpfs',{})==intent.get('tmpfs',{}) and
         h.get('PidMode','')=='' and h.get('IpcMode','private')=='private' and h.get('UTSMode','')=='' and
         not h['Devices'] and not h['DeviceRequests'] and h['Memory']==4*1024**3 and h['MemorySwap']==4*1024**3 and
         h['NanoCpus']==4*10**9 and h['PidsLimit']==512 and h.get('Init') in (None,False) and not h.get('AutoRemove',False),
         'actual qualified current actor resources/isolation')
    got=[]
    for m in row['Mounts']:
        if m['Type']=='tmpfs':
            need(m['Destination'] in intent.get('tmpfs',{}) and m['RW'] is True,'exact declared private tmpfs');continue
        need(m['Type']=='bind','only exact owner bind mounts');got.append((m['Destination'],m['Source'],m['RW']))
    need(sorted(got)==sorted(tuple(x) for x in intent['mounts']),'exact inspected owner mounts')
    return row['Id']


def new_commands(W,where,home,timeout,deadline):
    where.mkdir(mode=0o700);remaining=min(600,deadline-time.monotonic())
    need(remaining>2,'owner deadline exhausted')
    return W.Commands(where,home,'/usr/bin:/bin',timeout=min(timeout,remaining),total=remaining,max_output=1024**2)


def command(commands,step,argv,expected=0):
    return commands.run(step,list(map(str,argv)),commands.output.parent,expected)


def absent(commands,name,step):
    value=command(commands,step,DOCKER+['container','ls','--all','--no-trunc','--filter','name=^/'+name+'$','--format','{{.ID}} {{.Names}}'])
    return not value.strip()


def retire_container(commands,intent,token,step):
    if absent(commands,intent['name'],step+'-query'):return dict(status='ABSENT',name=intent['name'])
    rows=json.loads(command(commands,step+'-inspect',DOCKER+['container','inspect',intent['name']]))
    need(type(rows) is list and len(rows)==1,'one exact inspected current container')
    cid=inspect_container(rows[0],intent,token)
    command(commands,step+'-remove',DOCKER+['container','rm','--force',cid])
    need(absent(commands,intent['name'],step+'-after'),'exact owned container remains after retirement')
    return dict(status='REMOVED_AND_ABSENT',name=intent['name'],cid=cid,inspection=rows[0])


def require_native_host():
    need(os.uname().sysname=='Linux' and os.uname().machine=='aarch64' and os.getuid()==os.geteuid()!=0,
         'actual non-root native aarch64 owner host')


def verify_daemon(commands):
    info=json.loads(command(commands,'native-daemon',DOCKER+['info','--format','{{json .}}']))
    need(info['OSType']=='linux' and info['Architecture'] in ('arm64','aarch64') and info['CgroupVersion']=='2' and
         all(info[k] is True for k in ('MemoryLimit','SwapLimit','CpuCfsQuota','PidsLimit')) and
         not any('rootless' in x or 'userns' in x for x in info['SecurityOptions']),
         'actual qualified native rootful cgroup-v2 daemon')


class HostSession:
    def __init__(self,grant,source,output,deps):
        self.grant,self.source,self.output,self.deps=grant,Path(source),Path(output),deps;self.cleanup=None;self.commands=None
    def __enter__(self):
        require_native_host();g=self.grant;token=stage_token(g);W,T,A,R=self.deps
        self.tools=T;self.token=token;self.deadline=time.monotonic()+min(g['resources']['total_seconds'],600)
        self.state=self.output/'owner-state';self.state.mkdir(mode=0o700);(self.state/'intents').mkdir(mode=0o700)
        self.home=self.state/'home';self.home.mkdir(mode=0o700)
        self.admin=new_commands(W,self.state/'admission',self.home,15,self.deadline)
        need(not command(self.admin,'fresh-owner-label',DOCKER+['ps','-aq','--filter','label='+LABEL+'='+token]).strip(),'fresh current owner namespace; no collision cleanup')
        verify_daemon(self.admin)
        self.commands=new_commands(W,self.output/'commands',self.home,g['resources']['build_seconds'],self.deadline-min(60,g['resources']['total_seconds']/4))
        wrapper=self.state/'bin';wrapper.mkdir(mode=0o700)
        manifest=dict(grant=g,source=str(self.source),output=str(self.output),deadline=self.commands.deadline,uid=os.getuid(),gid=os.getgid())
        save(self.state/'proxy.json',manifest)
        body='#!/bin/bash\nexec /usr/bin/python3 -I -B '+shlex.quote(str(Path(__file__).resolve()))+' --docker-proxy '+shlex.quote(str(self.state/'proxy.json'))+' -- "$@"\n'
        (wrapper/'docker').write_text(body);(wrapper/'docker').chmod(0o700);self.commands.env['PATH']=str(wrapper)+':/usr/bin:/bin'
        self.protected_before={str(p):T.snapshot_receipt(p) for p in (Path('/var/lib/pacman'),Path('/etc/pacman.conf'),Path('/etc/pacman.d/gnupg'),Path('/var/cache/pacman'))}
        try:
            self.prepare_trust();self.admin.env['HOME']=str(self.home);self.commands.env['HOME']=str(self.home)
        except BaseException:
            try:self.retire_trust()
            finally:raise
        self.facts=dict(operation=OP,stage=g['stage'],binding=g['binding'],image=g['images'][g['stage']]['id'],architecture=os.uname().machine,page_size=os.sysconf('SC_PAGE_SIZE'))
        return self
    def __exit__(self,kind,error,tb):
        W,T,A,R=self.deps;failures=[];retired=[]
        try:
            clean=new_commands(W,self.state/'retirement',self.home,15,self.deadline)
            for i,path in enumerate(sorted((self.state/'intents').glob('*.json'))):
                intent=json.loads(raw(path));retired.append(retire_container(clean,intent,self.token,'retire-'+str(i)))
                result_path=path.with_suffix('.result')
                need(result_path.is_file() and json.loads(raw(result_path))['status']=='PASS_OWNED_GENERIC_BUILD_PROXY','each proxy naturally completed; unknown nested retirement remains HOLD')
            need(not command(clean,'final-owner-label',DOCKER+['ps','-aq','--filter','label='+LABEL+'='+self.token]).strip(),'all exact current owner containers absent')
        except BaseException as later:failures.append(type(later).__name__+': '+str(later)[:1024])
        try:
            self.retire_trust()
            after={p:self.tools.snapshot_receipt(Path(p)) for p in self.protected_before}
            need(after==self.protected_before,'protected native host package state unchanged')
        except BaseException as later:failures.append(type(later).__name__+': '+str(later)[:1024])
        evidence=dict(stage=self.grant['stage'],binding=self.grant['binding'],retired=retired,failures=failures)
        save(self.state/'cleanup.json',evidence)
        okay=not failures
        self.cleanup=dict(status='PASS_OWNED_CURRENT_STAGE_RETIREMENT' if okay else 'HOLD_OWNED_CURRENT_STAGE_RETIREMENT',operation=OP,stage=self.grant['stage'],binding=self.grant['binding'],natural_retirement=okay,owned_container_absence_verified=okay,protected_state_unchanged=okay)
        if failures and error is None:raise ValueError('current owner cleanup uncertain')


def docker_proxy(path,args):
    m=json.loads(raw(path));g=m['grant'];token=stage_token(g)
    deps=dependencies();W,T,A,R=deps
    validate_owner(g,Path(m['source']),Path(m['output']),deps)
    need(m['uid']==os.getuid() and m['gid']==os.getgid() and
         time.monotonic()<m['deadline']<=time.monotonic()+min(600,g['resources']['total_seconds']), 'proxy current UID and finite common deadline')
    state=Path(path).parent;home=state/'home';slot=Path(tempfile.mkdtemp(prefix='proxy-',dir=state))
    C=new_commands(W,slot/'commands',home,min(180,g['resources']['build_seconds']),m['deadline'])
    if args==['image','inspect',g['images'][g['stage']]['id']]:
        result=command(C,'image-inspect',DOCKER+args);rows=json.loads(result)
        need(len(rows)==1 and rows[0]['Id']==args[-1] and rows[0]['Architecture']=='arm64' and rows[0]['Os']=='linux','actual selected arm64 image')
        sys.stdout.buffer.write(result);return
    if args==['info','--format','{{.Architecture}}']:
        result=command(C,'native-architecture',DOCKER+args);need(result.strip() in (b'aarch64',b'arm64'),'actual native builder daemon');sys.stdout.buffer.write(result);return
    if len(args)==3 and args[:2]==['rm','-f']:
        name=args[-1];need(re.fullmatch('cachy-asahi-[0-9a-f]{16}',name),'exact inherited timeout removal name')
        intent=json.loads(raw(state/'intents'/(name+'.json')));retire_container(C,intent,token,'inherited-timeout');return
    intent=generic_intent(['docker',*args],g,Path(m['source']),Path(m['output']),m['uid'],m['gid'])
    target=state/'intents'/(intent['name']+'.json');save(target,intent)
    need(absent(C,intent['name'],'fresh-name'),'fresh exact generic container name')
    result=dict(status='HOLD',name=intent['name']);primary=None
    try:
        creation_attempted=True
        cid=command(C,'create',intent['create_argv']).decode().strip();need(re.fullmatch('[0-9a-f]{64}',cid),'actual created CID')
        rows=json.loads(command(C,'inspect-created',DOCKER+['container','inspect',cid]));need(len(rows)==1 and inspect_container(rows[0],intent,token)==cid,'created owned current container')
        result['created']=rows[0]
        output=command(C,'start-attached',DOCKER+['container','start','--attach',cid])
        rows=json.loads(command(C,'inspect-terminal',DOCKER+['container','inspect',cid]));inspect_container(rows[0],intent,token)
        need(rows[0]['State']['Running'] is False and rows[0]['State']['ExitCode']==0 and rows[0]['State']['OOMKilled'] is False,'natural successful native build container')
        result['terminal']=rows[0];result['status']='PASS_OWNED_GENERIC_BUILD_PROXY'
        sys.stdout.buffer.write(output)
    except BaseException as error:primary=error;result['failure']=dict(type=type(error).__name__,message=str(error)[:1024]);raise
    finally:
        try:result['retirement']=retire_container(C,intent,token,'proxy-final')
        except BaseException as error:
            result['status']='HOLD';result['retirement_error']=str(error)[:1024]
            if primary is None:raise
        finally:save(target.with_suffix('.result'),result)


def signed_local_guard():
    need(_INSIDE is not None and os.getuid()==os.geteuid()==0 and os.uname().machine=='aarch64' and
         os.getpid()>1 and os.getppid()==1,'lifecycle only in the explicit root native child namespace')
    # procfs is a kernel pseudo-file (not the ordinary DATA reader).
    need(Path('/proc/1/comm').read_bytes()==b'bash\n','non-exec bash PID1 owns lifecycle child')


class PrivateTrust:
    def prepare_trust(self):
        self.work=Path(tempfile.mkdtemp(prefix='build-tools-test-',dir='/tmp'))
        self.work.chmod(0o700);self.homes=[str(self.work/'trust'),str(self.work/'home')]
        for home in self.homes:Path(home).mkdir(mode=0o700)
        self.home=Path(self.homes[1]);self.trust=Path(self.homes[0])
        self.verifier=['/usr/bin/gpg','--homedir',str(self.trust),'--batch','--no-auto-key-retrieve','--auto-key-locate','clear']
        self.fingerprint=self.grant['owner']['test_fingerprint']
        need(re.fullmatch('[0-9A-F]{40}',self.fingerprint),'explicit exact Root TEST primary')
        public=self.work/'public.asc';public.write_bytes(ref(self.grant['owner']['test_public_key']))
        command(self.admin,'import-root-test-public',self.verifier+['--import',str(public)])
        listing=command(self.admin,'current-primary',self.verifier+['--with-colons','--list-keys']).decode()
        values=[line.split(':')[9] for line in listing.splitlines() if line.startswith('fpr:')]
        need(values==[self.fingerprint],'one exact current Root TEST primary; no extra keys')
        trust=self.work/'ownertrust';trust.write_text(self.fingerprint+':6:\n')
        command(self.admin,'trust-current-test-primary',self.verifier+['--import-ownertrust',str(trust)])

    def verify_signatures(self,inputs):
        W,T,A,R=self.deps;N=R.native();verified={}
        rows={'setup8':inputs['setup8']}
        if self.grant['stage']=='ui':rows['first_login_backend']=inputs['first_login_backend']
        for key,row in rows.items():
            selection=R.signature(row['current_TEST_signature_verification'],row['archive'],row['signature'],time.time(),N)
            need(selection['fingerprint']==self.fingerprint and selection['public_key']==self.grant['owner']['test_public_key'],
                 'actual stage verifier uses the precise Root selected public TEST key')
            argv=self.verifier+['--status-fd=1','--verify',row['signature']['path'],row['archive']['path']]
            status=command(self.admin,'owner-current-signature-'+key,argv).decode();N.strict_signature(status,self.fingerprint)
            verified[key]=dict(archive=pin(ref(row['archive'])),signature=pin(ref(row['signature'])),
                public_test_key=pin(ref(selection['public_key'])),fingerprint=self.fingerprint,status_text=status,command=self.admin.records[-1])
        return dict(status='PASS_OWNED_CURRENT_STAGE_TEST_VERIFICATION',operation=OP,stage=self.grant['stage'],
            binding=self.grant['binding'],scope='DELEGATED_CURRENT_OWNER_GPG_NOT_ROOT_OBSERVATION',verified=verified)

    def retire_trust(self):
        if not hasattr(self,'work'):return None
        result=self.deps[1].retire_private(lambda step,argv:command(self.admin,step,argv),self.work,self.homes)
        need(result['homes_retired'] and result['no_sockets'] and result['private_directory_absent'] and not result['failures'],
             'all genuine private TEST homes retired')
        return result


class SignedSession(PrivateTrust):
    def __init__(self,grant,source,output,deps):
        self.grant,self.source,self.output,self.deps=grant,Path(source),Path(output),deps;self.cleanup=None
    def __enter__(self):
        signed_local_guard();W,T,A,R=self.deps;g=self.grant
        self.tools=T;self.deadline=min(time.monotonic()+min(g['resources']['total_seconds'],600),_INSIDE.get('deadline',float('inf')))
        self.protected_before=A.protected_state()
        # Administrative logs live outside the exact native lifecycle index.
        state=self.output/'owner-admin';state.mkdir(mode=0o700)
        self.admin=new_commands(W,state/'commands',Path('/nonexistent'),min(30,g['resources']['build_seconds']),self.deadline)
        self.failure=None
        try:
            self.prepare_trust();self.admin.env['HOME']=str(self.home)
            self.baseline=command(self.admin,'baseline-inventory',['/usr/bin/pacman','-Q'])
            need(b''.join(sorted(self.baseline.splitlines(keepends=True)))==R.reference(g['images']['lifecycle']['inventory_pin']),
                 'actual signed baseline equals qualified project-free372')
            self.reasons={flag:command(self.admin,'before-'+flag,['/usr/bin/pacman','-Qq'+flag]) for flag in ('e','d')}
            config=self.work/'pacman.conf';config.write_text('[options]\nArchitecture = aarch64\nSigLevel = Required\nLocalFileSigLevel = Required\nGPGDir = '+str(self.trust)+'\nHookDir = /builder-disabled-hooks\nLogFile = '+str(self.work/'pacman.log')+'\n')
            self.pacman=['--config',str(config)]
            self.commands=new_commands(W,self.output/'commands',self.home,g['resources']['build_seconds'],self.deadline)
            self.facts=dict(operation=OP,stage='lifecycle',binding=g['binding'],image=g['images']['lifecycle']['id'],architecture=os.uname().machine,page_size=os.sysconf('SC_PAGE_SIZE'),execution_domain='OWNED_SIGNED_IMAGE_LOCAL')
            return self
        except BaseException:
            # __exit__ is not called when __enter__ fails.
            try:self.retire_trust()
            finally:raise
    def protected_after(self):return self.deps[2].protected_state()
    def verify_state(self):need(self.protected_after()==self.protected_before,'complete protected state restoration')
    def __exit__(self,kind,error,tb):
        W,T,A,R=self.deps;failures=[];retirement=None;restored=False
        try:
            if error is not None:
                actual=command(self.admin,'failure-inventory',['/usr/bin/pacman','-Q']).decode().splitlines()
                names=[n for n in reversed(tuple(R.PROJECT)) if any(line.startswith(n+' ') for line in actual)]
                if names:command(self.admin,'failure-remove-projects',['/usr/bin/pacman',*self.pacman,'--noconfirm','-R',*names])
            need(command(self.admin,'restored-inventory',['/usr/bin/pacman','-Q'])==self.baseline,'exact baseline inventory restoration')
            for flag,before in self.reasons.items():
                need(command(self.admin,'after-'+flag,['/usr/bin/pacman','-Qq'+flag])==before,'exact package installation reasons restored')
            self.verify_state();restored=True
        except BaseException as later:failures.append(type(later).__name__+': '+str(later)[:1024])
        finally:
            try:retirement=self.retire_trust()
            except BaseException as later:failures.append(type(later).__name__+': '+str(later)[:1024])
            try:self.verify_state()
            except BaseException as later:restored=False;failures.append(type(later).__name__+': '+str(later)[:1024])
        okay=not failures and error is None and restored
        local=dict(status='PASS_LOCAL_STAGE_PENDING_OUTER_RETIREMENT' if okay else 'HOLD_LOCAL_STAGE',
            operation=OP,stage='lifecycle',binding=self.grant['binding'],body_success=error is None,
            protected_state_unchanged=restored and not failures,private_retirement=retirement,failures=failures)
        save(self.output/'owner-local.json',local)
        self.cleanup=dict(status='PENDING_OUTER_CONTAINER_RETIREMENT',operation=OP,stage='lifecycle',binding=self.grant['binding'],
            natural_retirement=okay,owned_container_absence_verified=False,protected_state_unchanged=okay)
        if not okay and error is None:raise ValueError('signed local restoration or private retirement failed')



HostSession.prepare_trust=PrivateTrust.prepare_trust
HostSession.verify_signatures=PrivateTrust.verify_signatures
HostSession.retire_trust=PrivateTrust.retire_trust


def validate_owner(grant,source,output,deps):
    stage_token(grant);W,T,A,R=deps;owner=grant['owner']
    inputs=json.loads(ref(owner['inputs']));profile=json.loads(raw(ROOT/(FAMILY+'/successor_v2/profile.json')))
    N,image=R.admission(grant,inputs,Path(source),profile,grant['stage'],time.time())
    need(owner['api']==API and grant['source_root']==str(source) and grant['output']==str(output) and
         type(grant['source_date_epoch']) is int and grant['source_date_epoch']==inputs['source_date_epoch'],
         'exact current owner API/source/output/epoch')
    need(owner['code']['path']==str(Path(__file__).resolve()) and ref(owner['code'])==raw(Path(__file__).resolve()),
         'whole Root-selected maintained owner implementation')
    ref(owner['test_public_key'],65536)
    for key in (('setup8','first_login_backend') if grant['stage']=='ui' else ('setup8',)):
        value=inputs[key];selection=R.signature(value['current_TEST_signature_verification'],value['archive'],value['signature'],time.time(),N)
        need(owner['test_fingerprint']==selection['fingerprint'] and owner['test_public_key']==selection['public_key'],
             'nonnull Root TEST policy joined before any daemon or GPG role')
    return inputs,profile


def open_current_session(grant,source,output):
    stage_token(grant)  # NULL/old grants fail before imports or callbacks.
    deps=dependencies();validate_owner(grant,source,output,deps)
    if grant['stage']=='lifecycle':signed_local_guard()
    return SignedSession(grant,source,output,deps) if grant['stage']=='lifecycle' else HostSession(grant,source,output,deps)


CAPABILITIES=['CHOWN','DAC_OVERRIDE','FOWNER','SETUID','SETGID']


def references(value):
    if type(value) is dict:
        if set(value)=={'path','bytes','sha256'}:yield value
        else:
            for item in value.values():yield from references(item)
    elif type(value) is list:
        for item in value:yield from references(item)


def signed_intent(grant,source,output,admission_path,inputs_path,code_refs):
    """Exact offline root ALPM actor; no Docker socket or host state mounts."""
    token=stage_token(grant);need(grant['stage']=='lifecycle','distinct lifecycle stage')
    source,output,admission_path,inputs_path=map(Path,(source,output,admission_path,inputs_path))
    need(grant['source_root']==str(source) and grant['output']==str(output) and
         str(admission_path)==grant['owner']['admission_path'] and str(inputs_path)==grant['owner']['inputs']['path'], 'Root-bound lifecycle operands')
    need(grant['owner']['lifecycle_capabilities']==CAPABILITIES,'finite Root-admitted ALPM/runuser capabilities')
    need(type(code_refs) is dict and all(Path(d).is_absolute() and type(v) is dict and set(v)=={'path','bytes','sha256'}
         for d,v in code_refs.items()),'closed whole code carrier mounts')
    manifest=grant['owner']['launch_manifest'];need(manifest in code_refs,'explicit Root-bound inside manifest path')
    owner_code=grant['owner']['code']
    needed={str(ROOT/n):sha for n,sha in DEPS.items()};needed[owner_code['path']]=owner_code['sha256']
    state=Path(manifest).parent
    need(all(code_refs.get(dst,{}).get('path')==str(state/('code-'+str(i))) for i,dst in enumerate(needed)) and
         code_refs[manifest]['path']==manifest,'private immutable executable carrier operands')
    need(set(code_refs)==set(needed)|{manifest} and all(code_refs[d]['sha256']==sha for d,sha in needed.items()),
         'exact held executable dependency carrier, no ambient code')
    mounts={str(source):(str(source),False),str(output.parent):(str(output.parent),True),
            str(admission_path):(str(admission_path),False),str(inputs_path):(str(inputs_path),False)}
    def add(dst,src,rw=False):
        dst,src=str(dst),str(src)
        need(',' not in dst+src and '\n' not in dst+src and Path(dst).is_absolute() and Path(src).is_absolute(),'closed absolute lifecycle mount')
        need(dst not in mounts or mounts[dst]==(src,rw),'no differing duplicate mount')
        mounts[dst]=(src,rw)
    for row in references(grant):add(row['path'],row['path'])
    for dst,row in code_refs.items():
        # Code DATA copied under the owner private carrier, mounted at its
        # maintained absolute filename to keep held dependency resolution exact.
        mounts.pop(dst,None);add(dst,row['path'])
    for row in grant['signed'].values():
        for field in ('archive','signature'):add(row[field],row[field])
    # Input references include official closure/Root decisions used locally.
    # They are supplied as an explicit bounded list derived from admitted inputs.
    for row in grant['owner']['input_references']:add(row['path'],row['path'])
    need(len(mounts)<=128 and len(set(mounts))==len(mounts),'finite exact lifecycle mount closure')
    for dst,(src,rw) in mounts.items():
        need(not (Path(dst).is_relative_to(output.parent) and dst!=str(output.parent)) and
             not (Path(src).is_relative_to(output.parent) and dst!=str(output.parent)),
             'output parent contains no executable/public input mount')
        need(dst not in ('/','/proc','/sys','/dev','/var/run/docker.sock','/run/docker.sock') and
             not Path(dst).is_relative_to('/etc') and not Path(dst).is_relative_to('/var/lib/pacman') and
             not Path(dst).is_relative_to('/root') and not Path(dst).is_relative_to('/home/alarm'),
             'no protected host state or daemon socket exposure')
    name='cachy-asahi-current-'+token+'-lifecycle';image=grant['images']['lifecycle']['id']
    labels={LABEL:token,LABEL+'.operation':OP,LABEL+'.stage':'lifecycle',LABEL+'.source':grant['binding']['source']}
    # Trailing status bookkeeping prevents Bash's last-command exec optimization.
    cmd=['-c','/usr/bin/python3 -I -B "$@"; status=$?; exit "$status"','current-onboarding',owner_code['path'],
         '--inside-lifecycle',manifest]
    argv=DOCKER+['create','--name',name,'--pull=never','--platform','linux/arm64','--user','0:0',
        '--cap-drop=ALL','--security-opt=no-new-privileges','--pids-limit','512','--memory','4g','--memory-swap=4g',
        '--cpus','4','--network','none','--init=false']
    for capability in CAPABILITIES:argv+=['--cap-add',capability]
    for key,value in labels.items():argv+=['--label',key+'='+value]
    for dst,(src,rw) in sorted(mounts.items()):argv+=['--mount','type=bind,src='+src+',dst='+dst+('' if rw else ',readonly')]
    argv+=['--entrypoint','/bin/bash',image,*cmd]
    return dict(name=name,image=image,user='0:0',mounts=[(d,s,rw) for d,(s,rw) in sorted(mounts.items())],
        entrypoint=['/bin/bash'],cmd=cmd,labels=labels,readonly=False,capadd=CAPABILITIES,tmpfs={},create_argv=argv)


def finalize_current(report,local,receipt,grant):
    """Pure evidence join; only the outer owner may call after actual retirement."""
    token=stage_token(grant);need(grant['stage']=='lifecycle','outer lifecycle finalization only')
    for row in (report,local,receipt):
        need(row['operation']==OP and row['stage']=='lifecycle' and row['binding']==grant['binding'],'same inner/outer stage binding')
    need(report['status']=='PENDING_OUTER_CURRENT_STAGE_RETIREMENT' and
         local['status']=='PASS_LOCAL_STAGE_PENDING_OUTER_RETIREMENT' and local['body_success'] is True and
         local['protected_state_unchanged'] is True and local['failures']==[],'successful local restoration still pending outer')
    need(receipt['status']=='PASS_OWNED_CURRENT_LIFECYCLE_RETIREMENT','actual outer retirement receipt')
    intent=receipt['intent']
    expected_intent=signed_intent(grant,Path(grant['source_root']),Path(grant['output']),
        Path(grant['owner']['admission_path']),Path(grant['owner']['inputs']['path']),receipt['code_refs'])
    need(intent==expected_intent,'exact reconstructed Root-bound lifecycle launch policy')
    created=receipt['created'];terminal=receipt['terminal'];retirement=receipt['retirement']
    need(intent['image']==grant['images']['lifecycle']['id'] and intent['labels'].get(LABEL)==token and
         intent['labels'].get(LABEL+'.stage')=='lifecycle' and intent['labels'].get(LABEL+'.source')==grant['binding']['source'] and
         intent['user']=='0:0' and intent['readonly'] is False and intent['capadd']==CAPABILITIES,'Root joined lifecycle intent')
    cid=inspect_container(created,intent,token);need(inspect_container(terminal,intent,token)==cid,'same exact created/terminal CID')
    need(terminal['State']['Running'] is False and terminal['State']['ExitCode']==0 and terminal['State']['OOMKilled'] is False and
         retirement['status']=='REMOVED_AND_ABSENT' and retirement['cid']==cid and
         inspect_container(retirement['inspection'],intent,token)==cid,'natural actor exit plus inspected exact CID removal/absence')
    rows={r['step']:r for r in receipt['commands']};need(len(rows)==len(receipt['commands']),'unique outer command receipts')
    expected={'create':intent['create_argv'],'inspect-created':DOCKER+['container','inspect',cid],
        'start-attached':DOCKER+['container','start','--attach',cid],
        'inspect-terminal':DOCKER+['container','inspect',cid],
        'retire-inspect':DOCKER+['container','inspect',intent['name']],
        'retire-remove':DOCKER+['container','rm','--force',cid],
        'retire-after':DOCKER+['container','ls','--all','--no-trunc','--filter','name=^/'+intent['name']+'$','--format','{{.ID}} {{.Names}}']}
    for step,argv in expected.items():
        row=rows[step];supervision=row['supervision']
        need(supervision['reaped'] is True and supervision['ownership']=='REAPED' and supervision['group_census']=='EMPTY_TWICE' and
             supervision['output_complete'] is True and supervision['timeout'] is False and supervision['signals']==[] and
             supervision['error'] is None and type(supervision['exit']) is int and supervision['exit']==0,'actual natural outer retirement commands')
        need(row['argv']==argv and row['expected']==0 and row['success'] is True,'exact successful outer command')
        natural=row['supervision'];need(natural['reaped'] is True and natural['ownership']=='REAPED' and natural['group_census']=='EMPTY_TWICE' and
            natural['output_complete'] is True and natural['timeout'] is False and natural['signals']==[] and natural['error'] is None and natural['exit']==0,
            'natural outer command supervision')
    need(rows['retire-after']['log_pin']==pin(b''),'successful exact absence query with empty output')
    result=dict(report);result['owner_cleanup']=dict(status='PASS_OWNED_CURRENT_STAGE_RETIREMENT',operation=OP,stage='lifecycle',
        binding=grant['binding'],natural_retirement=True,owned_container_absence_verified=True,protected_state_unchanged=True)
    result['outer_retirement']=receipt;result['status']='PASS_CURRENT_ONBOARDING_OWNED_STAGE_DATA_ONLY';return result


def inside_lifecycle(path):
    global _INSIDE
    manifest=json.loads(raw(path));grant=json.loads(ref(manifest['admission']))
    need(str(path)==grant['owner']['launch_manifest'] and manifest['admission']['path']==grant['owner']['admission_path'] and
         manifest['inputs']==grant['owner']['inputs'] and manifest['grant_sha256']==pin(encoded(grant))['sha256'] and
         type(manifest['host_uid']) is int and type(manifest['host_gid']) is int and manifest['host_uid']>0 and manifest['host_gid']>=0 and
         time.monotonic()<manifest['deadline']<=time.monotonic()+min(600,grant['resources']['total_seconds']), 'bound finite owned inside manifest')
    _INSIDE=manifest
    signed_local_guard()
    need(pin(encoded(grant))['sha256']==manifest['grant_sha256'],'inside exact external Root admission')
    need(str(path)==grant['owner']['launch_manifest'],'Root-bound inside launch path')
    _INSIDE=manifest;signed_local_guard()
    deps=dependencies();W,T,A,R=deps;inputs=json.loads(ref(manifest['inputs']))
    need(manifest['inputs']==grant['owner']['inputs'],'same externally pinned owner inputs')
    output=Path(grant['output']);profile=json.loads(raw(ROOT/(FAMILY+'/successor_v2/profile.json')))
    primary=None
    try:
        report=R.run_registered(stage='lifecycle',source=Path(grant['source_root']),profile=profile,inputs=inputs,grant=grant,
            output=output,open_session=open_current_session)
        need(report['status']=='PENDING_OUTER_CURRENT_STAGE_RETIREMENT','local role only emits pending outer retirement')
    except BaseException as error:primary=error;raise
    finally:
        # Export only this fresh output; host UID cannot otherwise read root0700.
        if output.is_dir():
            paths=[output,*output.rglob('*')];need(len(paths)<=4096,'bounded public output export')
            for target in paths:
                info=target.lstat();need(not target.is_symlink() and (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)), 'no output aliases/specials')
                os.chown(target,manifest['host_uid'],manifest['host_gid'])


def launch_lifecycle(admission_path,admission_sha256,inputs_path,source,output):
    require_native_host();body=raw(admission_path);need(pin(body)['sha256']==admission_sha256,'external Root admission SHA')
    grant=json.loads(body);need(grant['stage']=='lifecycle' and str(admission_path)==grant['owner']['admission_path'],'explicit Root-bound outer lifecycle entry only')
    deps=dependencies();W,T,A,R=deps;inputs,profile=validate_owner(grant,source,output,deps)
    need(grant['owner']['inputs']==dict(path=str(inputs_path),**pin(raw(inputs_path))) and not output.exists(),
         'fresh Root-bound lifecycle inputs/output')
    parent=output.parent;info=parent.lstat()
    need(parent.is_absolute() and not any(p.is_symlink() for p in (parent,*parent.parents)) and
         stat.S_ISDIR(info.st_mode) and info.st_uid==os.getuid() and stat.S_IMODE(info.st_mode)==0o700 and
         not list(parent.iterdir()),'fresh empty owned0700 output parent, no other host state exposed')
    actual_refs=list(references(inputs));need(grant['owner']['input_references']==actual_refs,'complete exact admitted input reference closure')
    for row in actual_refs:ref(row)
    need(grant['source_date_epoch']==inputs['source_date_epoch'],'same source epoch')
    manifest_path=Path(grant['owner']['launch_manifest']);state=manifest_path.parent
    need(manifest_path.name=='inside.json' and state.parent==Path('/tmp') and
         re.fullmatch('current-onboarding-owner-[A-Za-z0-9_-]{8,64}',state.name) and not state.exists() and
         not state.is_symlink(),'fresh Root-selected private launch state')
    state.mkdir(mode=0o700)
    home=state/'home';home.mkdir(mode=0o700);deadline=time.monotonic()+min(grant['resources']['total_seconds'],600)
    C=new_commands(W,state/'commands',home,min(180,grant['resources']['build_seconds']),deadline)
    # Root selects the fresh state path; no private key or daemon socket enters it.
    manifest=dict(admission=dict(path=str(admission_path),**pin(body)),inputs=grant['owner']['inputs'],
        grant_sha256=pin(encoded(grant))['sha256'],deadline=deadline,host_uid=os.getuid(),host_gid=os.getgid())
    save(manifest_path,manifest);code_refs={}
    for index,name in enumerate([*DEPS,str(Path(__file__).resolve())]):
        original=ROOT/name if name in DEPS else Path(name);data=raw(original,128*1024)
        carrier=state/('code-'+str(index));carrier.write_bytes(data);carrier.chmod(0o600)
        code_refs[str(original)]=dict(path=str(carrier),**pin(data))
    code_refs[str(manifest_path)]=dict(path=str(manifest_path),**pin(raw(manifest_path)))
    intent=signed_intent(grant,source,output,admission_path,inputs_path,code_refs);token=stage_token(grant)
    save(state/'intent.json',intent);receipt=dict(status='HOLD',operation=OP,stage='lifecycle',binding=grant['binding'],intent=intent,code_refs=code_refs)
    primary=None;creation_attempted=False
    try:
        need(not command(C,'fresh-owner-label',DOCKER+['ps','-aq','--filter','label='+LABEL+'='+token]).strip(),'fresh lifecycle namespace; no collision deletion')
        verify_daemon(C)
        need(absent(C,intent['name'],'fresh-name'),'fresh exact lifecycle name')
        creation_attempted=True
        cid=command(C,'create',intent['create_argv']).decode().strip();need(re.fullmatch('[0-9a-f]{64}',cid),'actual lifecycle CID')
        created=json.loads(command(C,'inspect-created',DOCKER+['container','inspect',cid]));need(len(created)==1 and inspect_container(created[0],intent,token)==cid,'actual created lifecycle config')
        receipt['created']=created[0]
        command(C,'start-attached',DOCKER+['container','start','--attach',cid])
        terminal=json.loads(command(C,'inspect-terminal',DOCKER+['container','inspect',cid]));need(len(terminal)==1 and inspect_container(terminal[0],intent,token)==cid,'same terminal lifecycle actor')
        receipt['terminal']=terminal[0]
        need(terminal[0]['State']['Running'] is False and terminal[0]['State']['ExitCode']==0 and terminal[0]['State']['OOMKilled'] is False,'natural successful lifecycle actor')
    except BaseException as error:primary=error;receipt['failure']=dict(type=type(error).__name__,message=str(error)[:1024]);raise
    finally:
        try:
            if creation_attempted:
                try:receipt['retirement']=retire_container(C,intent,token,'retire')
                except BaseException as error:
                    receipt['retirement_error']=str(error)[:1024]
                    if primary is None:raise
        finally:
            receipt['commands']=list(C.records);save(state/'receipt.json',receipt)
    receipt['status']='PASS_OWNED_CURRENT_LIFECYCLE_RETIREMENT'
    report=finalize_current(json.loads(raw(output/'route.json')),json.loads(raw(output/'owner-local.json')),receipt,grant)
    # Retain complete public receipts and retire private state before durable PASS.
    # A retention/cleanup failure leaves the original inner PENDING report.
    pending=state/'receipt.final.json';save(pending,receipt)
    shutil.copytree(state,output/'outer-owner')
    for relative in ('receipt.final.json','intent.json','commands/commands.json'):
        need(raw(state/relative)==raw(output/'outer-owner'/relative),'complete outer receipt retention')
    shutil.rmtree(state);need(not os.path.lexists(state),'private outer carrier retirement')
    temporary=output/'route.final.json';save(temporary,report);os.replace(temporary,output/'route.json')
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    entry=parser.add_mutually_exclusive_group(required=True)
    entry.add_argument('--docker-proxy',type=Path);entry.add_argument('--inside-lifecycle',type=Path)
    entry.add_argument('--launch-lifecycle',action='store_true')
    for name in ('admission','inputs','source','output'):parser.add_argument('--'+name,type=Path)
    parser.add_argument('--admission-sha256');parser.add_argument('--execute',action='store_true')
    parser.add_argument('rest',nargs=argparse.REMAINDER);args=parser.parse_args()
    need(sys.flags.isolated and sys.dont_write_bytecode and __debug__,'isolated unoptimized owner entry')
    if args.docker_proxy:
        values=args.rest[1:] if args.rest[:1]==['--'] else args.rest;docker_proxy(args.docker_proxy,values);return
    if args.inside_lifecycle:inside_lifecycle(args.inside_lifecycle);return
    need(args.execute and all(getattr(args,n) is not None for n in ('admission','admission_sha256','inputs','source','output')),
         'explicit Root-bound lifecycle launch operands')
    result=launch_lifecycle(args.admission,args.admission_sha256,args.inputs,args.source,args.output)
    print(json.dumps(dict(status=result['status'],operation=OP,stage='lifecycle')))


if __name__=='__main__':main()

#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Two-phase native route: Root grants source/resources; provider binds actual IDs."""
import argparse,hashlib,importlib.util,json,os,platform,re,signal,stat,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
OPERATION='rust199-source-reference-native-v1'
DOCKER=['/usr/bin/docker','--host=unix:///var/run/docker.sock']


def need(value,why):
    if not value:raise ValueError(why)


def encode(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def read(path,cap=4*1024**2):
    need(path.is_absolute() and all(not p.is_symlink() for p in (path,*path.parents)),'ordinary absolute Source/Root input')
    with path.open('rb') as f:
        before=os.fstat(f.fileno());need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size<=cap,'finite ordinary input')
        raw=f.read(cap+1);after=os.fstat(f.fileno())
    identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mode,s.st_mtime_ns,s.st_ctime_ns)
    need(len(raw)==before.st_size and identity(before)==identity(after)==identity(path.lstat()),'input changed or exceeded cap');return raw


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m


def source_gate(root,map_sha):
    need(re.fullmatch('[0-9a-f]{64}',map_sha or ''),'external Source map pin')
    raw=read(root/'source-map.json');need(hashlib.sha256(raw).hexdigest()==map_sha and stat.S_IMODE((root/'source-map.json').stat().st_mode)==0o644,'whole external Source map bytes/mode differ')
    m=json.loads(raw);need(m['schema']==1 and m['operation']==OPERATION and m['actual']==dict.fromkeys(('source','ref','run','job','approval','artifact','image')),'unexecuted exact Source DATA map')
    files={};directories=set();total=0
    for here,dirs,names in os.walk(root,followlinks=False):
        if Path(here)==root:
            if (root/'.git').exists():need((root/'.git').is_dir() and not (root/'.git').is_symlink(),'ordinary actual Source Git directory')
            dirs[:]=[n for n in dirs if n!='.git']
        for d in dirs:
            need(not (Path(here)/d).is_symlink(),'no Source directory aliases');directories.add(str((Path(here)/d).relative_to(root)))
        for name in names:
            p=Path(here)/name;n=p.relative_to(root).as_posix()
            need(n=='source-map.json' or n in m['files'],'unmapped Source member: '+n)
            if n=='source-map.json':continue
            body=read(p,64*1024**2);mode=stat.S_IMODE(p.stat().st_mode);total+=len(body)
            files[n]=dict(bytes=len(body),sha256=hashlib.sha256(body).hexdigest(),mode=mode)
    wanted={str(p) for name in m['files'] for p in Path(name).parents if str(p)!='.'}
    need(files==m['files'] and directories==wanted and len(files)<384 and total<=96*1024**2,'complete bounded Source bytes/modes/membership')
    marker=json.loads(read(root/'llvm256-rejoin.json'))
    need(type(marker['schema'])is int and marker['schema']==5 and marker['pending']is None and marker['scope']=='LLVM256_PUBLISHED_SOURCE_READER_REJOIN_ONLY_NO_ROLES','Source checkpoint pending: LLVM256 Reader static rejoin required before any role')
    return m


def natural(row):return row.get('natural_exit') is True and row.get('forced_cleanup') is False and row.get('group_absent') is True and row.get('retirement')=='REAPED' and row.get('ownership_lost') is False and row.get('leader_held_until_group_inspection') is True and row.get('exit_observed_via_waitpid') is True


def storage(path,disk,inodes):
    need(path.is_absolute() and path.is_dir() and not any(p.is_symlink() for p in (path,*path.parents)),'actual ordinary storage path')
    v=os.statvfs(path);need(v.f_bavail*v.f_frsize>=disk and v.f_favail>=inodes,'fresh disk/inode reserve')
    return dict(path=str(path),device=path.stat().st_dev,available_bytes=v.f_bavail*v.f_frsize,available_inodes=v.f_favail)


def readback(a,command):
    git=['/usr/bin/git','--no-replace-objects','--git-dir='+str(ROOT/'.git'),'--work-tree='+str(ROOT),'-c','protocol.allow=never','-c','core.fsmonitor=false']
    need(command(git+['rev-parse','--verify','HEAD']).stdout.decode().strip()==a['source']['sha'],'actual checked out Source HEAD')
    rows=command(git+['ls-tree','-rz','--full-tree',a['source']['sha']]).stdout;found={}
    for item in rows.split(b'\0'):
        if not item:continue
        meta,name=item.split(b'\t',1);mode,kind,digest=meta.decode().split();name=name.decode();body=read(ROOT/name,64*1024**2)
        need(kind=='blob' and digest==hashlib.sha1(b'blob '+str(len(body)).encode()+b'\0'+body).hexdigest() and mode==('100755' if (ROOT/name).stat().st_mode&0o111 else '100644'),'actual Git blob/mode differs')
        found[name]=dict(mode=mode,blob=digest)
    need(set(found)==set(json.loads(read(ROOT/'source-map.json'))['files'])|{'source-map.json'},'exact published Source Git membership')
    return dict(schema=1,status='PASS_PUBLISHED_SOURCE_DATA_READBACK',source=a['source'],files=found)


class Commands:
    def __init__(self,work,seconds):
        self.work=work;self.deadline=time.monotonic()+seconds;self.cleaning=False;self.cancelled=[False];self.on_tick=None;self.rows=[]
        self.owned=load('rust_v4_owned_child',ROOT/'helpers/owned_child.py');(work/'operations').mkdir(mode=0o700)
    def __call__(self,argv,log=None,timeout=60,check=True,**kwargs):
        need(self.cleaning or not self.cancelled[0],'Root cancellation before command')
        cap=min(timeout,self.deadline-time.monotonic());need(0<cap<=16200,'finite supervised phase command')
        need(set(kwargs)<={'capture_output','text','encoding','errors','stdout','stderr','env','stdin','input','cwd'},'fixed bootstrap callback subset')
        need(kwargs.get('stdout')in(None,subprocess.PIPE) and kwargs.get('stderr')in(None,subprocess.PIPE),'owned receipt streams required')
        env=dict(PATH='/usr/bin:/bin',HOME=str(self.work/'home'),LC_ALL='C',TZ='UTC',RUNNER_TEMP=os.environ['RUNNER_TEMP'],GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null',GIT_NO_REPLACE_OBJECTS='1',GIT_OPTIONAL_LOCKS='0',GIT_NO_LAZY_FETCH='1',GIT_TERMINAL_PROMPT='0')
        if kwargs.get('env')is not None:
            need(type(kwargs['env'])is dict and all(type(k)is type(v)is str for k,v in kwargs['env'].items()) and not {'GH_TOKEN','GITHUB_TOKEN'}&set(kwargs['env']),'no API token to bootstrap children');env=dict(kwargs['env'])
        row=dict(argv=list(map(str,argv)),lifecycle={},returncode=None);index=len(self.rows);self.rows.append(row)
        def tick():
            need(self.cleaning or not self.cancelled[0],'Root cancellation after owned witness')
            if self.on_tick is not None and not self.cleaning:self.on_tick()
        try:
            stdout=self.work/'operations'/f'{index:03}.stdout';stderr=self.work/'operations'/f'{index:03}.stderr'
            with stdout.open('xb')as out,stderr.open('xb')as err:
                result=self.owned.run(row['argv'],timeout=cap,cwd=kwargs.get('cwd',self.work),env=env,stdout=out,stderr=err,lifecycle=row['lifecycle'],stdout_limit=32*1024**2,stderr_limit=32*1024**2,on_tick=tick,**{k:kwargs[k]for k in ('stdin','input')if k in kwargs})
            out=read(stdout,32*1024**2);err=read(stderr,32*1024**2)
            row.update(returncode=result.returncode,stdout=dict(file=str(stdout.relative_to(self.work)),bytes=len(out),sha256=hashlib.sha256(out).hexdigest()),stderr=dict(file=str(stderr.relative_to(self.work)),bytes=len(err),sha256=hashlib.sha256(err).hexdigest()))
            need(natural(row['lifecycle']) and row['lifecycle']['exit']==result.returncode,'natural supervised command/group retirement')
            if log is not None:Path(log).write_bytes(out+err)
            if kwargs.get('text') or kwargs.get('encoding'):
                encoding=kwargs.get('encoding')or'utf-8';out=out.decode(encoding,kwargs.get('errors')or'strict');err=err.decode(encoding,kwargs.get('errors')or'strict')
            value=subprocess.CompletedProcess(argv,result.returncode,out,err)
            if check and value.returncode:raise subprocess.CalledProcessError(value.returncode,argv,out,err)
            return value
        finally:(self.work/'operations.json').write_bytes(encode(self.rows))


def environment_gate(dispatch,env):
    s=dispatch['source']
    need(env.get('GITHUB_REPOSITORY')=='Gabriel-Kahen/cachy-asahi' and env.get('GITHUB_EVENT_NAME')=='workflow_dispatch' and env.get('GITHUB_SHA')==s['sha'] and env.get('GITHUB_REF')==s['ref'] and env.get('GITHUB_RUN_ATTEMPT')=='1' and env.get('RUST199_OPERATION')==OPERATION and env.get('GITHUB_WORKFLOW_REF')=='Gabriel-Kahen/cachy-asahi/.github/workflows/native-arm-build.yml@'+s['ref'],'same-repository manual exactSource workflow attempt1')
    need(type(env.get('GITHUB_RUN_ID'))is str and re.fullmatch('[1-9][0-9]{0,19}',env['GITHUB_RUN_ID']),'actual current provider run')


def head_readback(root,source):
    git=root/'.git';need(git.is_dir() and not git.is_symlink(),'ordinary Source Git directory')
    raw=read(git/'HEAD',4096).decode().strip()
    if raw.startswith('ref: '):
        ref=raw[5:];need(re.fullmatch('refs/heads/codex/[A-Za-z0-9._/-]+',ref),'explicit Source branch HEAD');raw=read(git/ref,4096).decode().strip()
    need(raw==source,'actual checkout HEAD before secrets')


def dispatch_gate(args,env):
    source_gate(ROOT,args.map_sha256);gate=load('rust_v4_admission',ROOT/'admission.py');raw=read(args.admission,16384)
    need(hashlib.sha256(raw).hexdigest()==args.admission_sha256,'whole canonical Root dispatch pin')
    value=gate.decode(raw);need(raw==gate.dispatch_bytes(value),'compact canonical Root dispatch bytes');gate.validate_dispatch(value)
    need(value['source']['map_sha256']==args.map_sha256 and value['source']['approval']==args.approval_sha256,'independent Root review and raw admission digest')
    six={k:env.get(k)for k in ('SOURCE_SHA','SOURCE_MAP_SHA256','ROOT_APPROVAL_SHA256','ROOT_ADMISSION_SHA256','ROOT_ADMISSION_JSON','RUST199_OPERATION')}
    need(type(six['ROOT_ADMISSION_JSON'])is str and six['ROOT_ADMISSION_JSON'].encode()==raw and 0<len(raw)<=16384 and all(type(v)is str and 0<len(v)<=200 for k,v in six.items()if k!='ROOT_ADMISSION_JSON'),'exact six workflow inputs, only Root JSON has16KiB allowance')
    need(six['SOURCE_SHA']==value['source']['sha'] and six['SOURCE_MAP_SHA256']==args.map_sha256 and six['ROOT_APPROVAL_SHA256']==args.approval_sha256 and six['ROOT_ADMISSION_SHA256']==args.admission_sha256 and six['RUST199_OPERATION']==OPERATION,'six inputs join exact Root source/resource grant')
    environment_gate(value,env);head_readback(ROOT,value['source']['sha']);return gate,value,raw


def jobs_get(url,token):
    import urllib.request
    need(url.startswith('https://api.github.com/repos/Gabriel-Kahen/cachy-asahi/actions/runs/'),'fixed same-repository jobs API')
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*args,**kwargs):return None
    request=urllib.request.Request(url,headers={'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json'})
    with urllib.request.build_opener(NoRedirect).open(request,timeout=30)as response:
        need(response.status==200,'actual provider job metadata status');raw=response.read(1024**2+1)
    need(len(raw)<=1024**2,'bounded job metadata');return raw


def actual_provider(gate,dispatch,raw_sha,env,phase,fetch=jobs_get):
    environment_gate(dispatch,env);token=env.get('GH_TOKEN','');need(type(token)is str and token,'existing same-job token only')
    run=env['GITHUB_RUN_ID'];url='https://api.github.com/repos/Gabriel-Kahen/cachy-asahi/actions/runs/'+run+'/attempts/1/jobs?per_page=10'
    raw=fetch(url,token);need(type(raw)is bytes and len(raw)<=1024**2,'bounded actual provider response')
    jobs=gate.decode(raw);provider=gate.provider_binding(dispatch,raw_sha,env,jobs,phase)
    provider['job_metadata_sha256']=hashlib.sha256(raw).hexdigest()
    return provider,raw


def fresh_host(work,dispatch,command,image=None):
    need(platform.system()=='Linux' and platform.machine()=='aarch64' and os.getuid()==os.geteuid()==1001,'actual native nonroot runner')
    resources=dispatch['resources'];minimum=resources['minimum_host'];reserve=resources['active_reserve']
    memory=lambda:int(next(s.split()[1]for s in Path('/proc/meminfo').read_text().splitlines()if s.startswith('MemAvailable:')))*1024
    need(memory()>=minimum['memory_available_bytes'],'fresh actual host memory reserve')
    sock=Path('/var/run/docker.sock');before=sock.stat();need(stat.S_ISSOCK(before.st_mode) and before.st_uid==0,'actual root-owned native daemon socket')
    info=json.loads(command(DOCKER+['info','--format','{{json .}}'],timeout=30).stdout);version=json.loads(command(DOCKER+['version','--format','{{json .}}'],timeout=30).stdout)
    need((before.st_dev,before.st_ino)==(sock.stat().st_dev,sock.stat().st_ino) and info['OSType']=='linux' and info['Architecture']in('aarch64','arm64') and info['CgroupVersion']=='2' and not any('rootless'in s for s in info.get('SecurityOptions',[])),'stable local native rootful cgroupv2 daemon')
    paths=(work,Path(info['DockerRootDir']));records=[storage(p,minimum['disk_available_bytes_per_device'],minimum['available_inodes'])for p in paths]
    data=dict(info=info,version=version,storage=records,MemAvailable_bytes=memory());(work/'daemon.json').write_bytes(encode(data))
    def watch():
        need(memory()>=reserve['memory_bytes'],'active host memory reserve')
        for path in paths:storage(path,reserve['disk_bytes'],reserve['inodes'])
    command.on_tick=watch
    if image:
        rows=json.loads(command(DOCKER+['image','inspect',image],timeout=30).stdout);need(len(rows)==1 and rows[0]['Id']==image and rows[0]['Architecture']=='arm64' and rows[0]['Os']=='linux' and not rows[0]['Config'].get('Volumes'),'exact imported immutable normal image')
    return data


def run(args):
    gate,dispatch,raw=dispatch_gate(args,os.environ)
    if args.check_only:return 0
    need(args.execute,'separate explicit operational phase entry')
    phase=args.phase;resources=dispatch['resources'][phase];work=Path(os.environ['RUNNER_TEMP'])/'rust199-hosted'
    need(not work.exists() and work.parent.stat().st_uid==1001 and not work.parent.stat().st_mode&0o022 and not work.is_relative_to(ROOT) and not ROOT.is_relative_to(work),'fresh private disjoint phase work')
    minimum=dispatch['resources']['minimum_host'];storage(work.parent,minimum['disk_available_bytes_per_device'],minimum['available_inodes'])
    work.mkdir(mode=0o700);(work/'home').mkdir(mode=0o700);command=Commands(work,resources['native_seconds'])
    provider=None;boot=None;bootstrap=None;bootstrap_provider=None;report=dict(schema=4,status='FAIL',phase=phase,native_acceptance=False,holds_preserved=True,dispatch_sha256=hashlib.sha256(raw).hexdigest())
    handlers={s:signal.getsignal(s)for s in(signal.SIGINT,signal.SIGTERM)}
    def cancel(_s,_f):command.cancelled[0]=True
    try:
        for s in handlers:signal.signal(s,cancel)
        (work/'dispatch-admission.json').write_bytes(raw)
        (work/'source-readback.json').write_bytes(encode(readback(dispatch,command)))
        provider,jobs=actual_provider(gate,dispatch,report['dispatch_sha256'],os.environ,phase)
        (work/'provider-binding.json').write_bytes(encode(provider));(work/'job-metadata.json').write_bytes(jobs)
        fresh_host(work,dispatch,command)
        transfer=load('rust_v4_phase_transfer',ROOT/'hosted/phase_transfer.py')
        bootstrap=load('rust_v4_bootstrap',ROOT/'hosted/bootstrap.py')
        if phase=='bootstrap':
            materials=load('rust_v4_materials',ROOT/'hosted/materials.py')
            delivered=materials.acquire(ROOT,work,dispatch['delivery'],command,os.environ.get('GH_TOKEN',''))
            delivered['bootstrap']=materials.retained(ROOT,work,command)
            boot=bootstrap.run(ROOT,work,provider,dispatch,delivered,command)
            qualification=load('rust_v4_native_qualification',ROOT/'hosted/qualification.py')
            qual=qualification.run(ROOT,work,provider,dispatch,delivered,boot,command)
            report['transfer']=transfer.export(ROOT,work,dispatch,provider,delivered,boot,qual,command)
            report['status']='BOOTSTRAP_QUALIFIED_TRANSFER_DATA_EXPORTED'
        else:
            imported=transfer.import_phase(ROOT,work,dispatch,provider,args,command);delivered=imported['delivered'];boot=imported['boot'];qual=imported['qual']
            bootstrap_provider=imported['bootstrap_provider'];fresh_host(work,dispatch,command,boot['image'])
            bridge=dict(schema=4,status='PROVIDER_PHASE_BRIDGE',dispatch_sha256=report['dispatch_sha256'],bootstrap=bootstrap_provider,build=provider)
            a=gate.operational(dispatch,bridge,delivered,boot,qual,work)
            (work/'operational-admission.json').write_bytes(encode(a))
            report['producer']=load('rust_v4_producer',ROOT/'hosted/producer.py').run(ROOT,work,a,command)
            need(report['producer']['status']=='COMPLETED_EXPORTED_RETIRED','complete actual producer/export/retirement')
            report['status']='RUST199_BUILD_EXPORTED_RETIRED_PENDING_INDEPENDENT_READER'
    except BaseException as error:report['error']=type(error).__name__+': '+str(error)[:2048]
    finally:
        command.cleaning=True;command.on_tick=None;command.deadline=time.monotonic()+resources['cleanup_seconds']
        try:
            if bootstrap is not None:
                if phase=='build' and bootstrap_provider is None:
                    report['image_retirement']=dict(status='NOT_APPLICABLE_IMPORTER_OWNS_FAILED_IMPORT_RETIREMENT')
                else:
                    owner_provider=provider if phase=='bootstrap' else bootstrap_provider
                    report['image_retirement']=bootstrap.retire(ROOT,work,owner_provider,boot,command)
        except BaseException as error:report.update(status='FAIL',cleanup_error=type(error).__name__+': '+str(error)[:2048])
        for s,h in handlers.items():signal.signal(s,h)
        (work/'hosted.json').write_bytes(encode(report))
    return 0 if report['status']in('BOOTSTRAP_QUALIFIED_TRANSFER_DATA_EXPORTED','RUST199_BUILD_EXPORTED_RETIRED_PENDING_INDEPENDENT_READER') else 2


if __name__=='__main__':
    need(sys.flags.isolated and not sys.flags.optimize,'isolated unoptimized phase entry')
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--admission',type=Path,required=True)
    for name in ('admission-sha256','approval-sha256','map-sha256'):p.add_argument('--'+name,required=True)
    p.add_argument('--phase',choices=('bootstrap','build'),required=True);p.add_argument('--check-only',action='store_true');p.add_argument('--execute',action='store_true')
    for name in ('bootstrap-artifact-id','bootstrap-artifact-sha256','bootstrap-job-id','bootstrap-manifest-sha256'):p.add_argument('--'+name)
    raise SystemExit(run(p.parse_args()))

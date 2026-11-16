# SPDX-License-Identifier: MIT
"""Actual cap0 assembly/probe phase; runtime proofs never substitute for Root grants."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import tarfile
import time

DOCKER=['/usr/bin/docker','--host=unix:///var/run/docker.sock']
EXPORT_CAP=128*1024**2
LLVM='/opt/cachy-asahi/llvm23-source-reference'
PROBES=[['/stage0/bin/rustc','-vV'],['/stage0/bin/rustc','-vV'],['/stage0/bin/rustc','--print','sysroot'],['/stage0/bin/cargo','--version'],['/stage0/bin/rustdoc','--version'],[LLVM+'/bin/llvm-config','--version'],[LLVM+'/bin/llvm-config','--targets-built'],['/usr/bin/gcc','-dumpmachine'],[LLVM+'/bin/ld.lld','--version']]


def need(value,why):
    if not value:raise ValueError(why)


def encode(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def sha(path,tick=lambda:None):
    h=hashlib.sha256()
    with Path(path).open('rb')as source:
        while True:
            tick();block=source.read(1024**2)
            if not block:break
            h.update(block)
    return h.hexdigest()
def load(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m


def options(P,name,volume,image,inputs,root,materials,phase,pin,labels):
    argv=DOCKER+['create','--name',name,*P.label_options(labels),'--cpus=2','--memory=8g','--memory-swap=8g','--pids-limit=512','--init','--read-only','--network=none','--ipc=private','--cgroupns=private','--restart=no','--log-driver=none','--hostname=rust199-qualification','--cap-drop=ALL','--security-opt=no-new-privileges','--user=1001:1001','--ulimit=nofile=1024:1024','--ulimit=core=0:0','--workdir=/work','--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m,uid=1001,gid=1001','--tmpfs=/run:rw,noexec,nosuid,nodev,size=8m,uid=1001,gid=1001']
    for row in P.mount_specs(volume,inputs,root,materials,'prepare'if phase=='data'else'makepkg'):argv+=['--mount',P.mount_option(row)]
    return argv+['--env','QUALIFICATION_SHA256='+pin,'--entrypoint=/usr/bin/python',image,'-I','-B','/source/actor/qualify.py',phase]


def inspect_actor(P,row,name,volume,image,inputs,root,materials,phase,pin,labels,volume_path):
    P.inspect_identity(row,name,image,labels);P.inspect_domain(row,8*1024**3,512,'1001:1001',[])
    config,host=row['Config'],row['HostConfig'];need(config['Entrypoint']==['/usr/bin/python'] and config['Cmd']==['-I','-B','/source/actor/qualify.py',phase] and config['Hostname']=='rust199-qualification' and config['WorkingDir']=='/work','exact qualification actor vector')
    env=dict(item.split('=',1)for item in config['Env']);need(env.get('QUALIFICATION_SHA256')==pin and not any(k.startswith(('LD_','PYTHON','GH_TOKEN','GITHUB_TOKEN')) for k in env),'only explicit qualification grant, no credentials/loaders')
    need(host['Tmpfs']=={'/tmp':'rw,noexec,nosuid,nodev,size=64m,uid=1001,gid=1001','/run':'rw,noexec,nosuid,nodev,size=8m,uid=1001,gid=1001'},'bounded qualification tmpfs')
    P.inspect_mounts(row,P.mount_specs(volume,inputs,root,materials,'prepare'if phase=='data'else'makepkg'),volume,volume_path)
    need(row['State']['Status']=='created' and not row['State']['Running'],'inspect before qualification start')


def bounded_info(max_headers,tick=lambda:None):
    state={'headers':0,'ended':False}
    class Info(tarfile.TarInfo):
        @classmethod
        def fromtarfile(cls,archive):return cls._fromtarfile(archive)
        @classmethod
        def _fromtarfile(cls,archive,*,dircheck=True):
            tick()
            block=archive.fileobj.read(512)
            if block==bytes(512):state['ended']=True
            else:
                state['headers']+=1;need(state['headers']<=max_headers,'tar raw header count cap')
            item=(cls._frombuf(block,archive.encoding,archive.errors,dircheck=dircheck) if hasattr(cls,'_frombuf') else cls.frombuf(block,archive.encoding,archive.errors))
            item.offset=archive.fileobj.tell()-512;return item._proc_member(archive)
        def _proc_pax(self,archive):
            need(0<=self.size<=65536,'tar PAX metadata cap');return super()._proc_pax(archive)
        def _proc_gnulong(self,archive):
            need(0<=self.size<=65536,'tar GNU long-name cap');return super()._proc_gnulong(archive)
        def _proc_sparse(self,*args):raise ValueError('sparse tar refused')
        _proc_gnusparse_00=_proc_sparse;_proc_gnusparse_01=_proc_sparse;_proc_gnusparse_10=_proc_sparse
    return Info,state


def end_tar(archive,state,tick=lambda:None):
    tail=0
    while True:
        tick();block=archive.fileobj.read(65536)
        if not block:break
        tail+=len(block);need(not any(block) and tail<=16*1024**2,'bounded zero-only tar tail')
    need(state['ended'] and tail>=512 and archive.fileobj.tell()%512==0,'complete tar termination required')


def unpack(path,destination,tick=lambda:None):
    tick();need(not destination.exists() and path.stat().st_size<=EXPORT_CAP,'fresh bounded qualification DATA extraction');destination.mkdir(mode=0o700);seen=set();total=0
    info,state=bounded_info(256,tick)
    with tarfile.open(path,mode='r|',tarinfo=info)as stream:
        for member in stream:
            need(not member.sparse and not any(k.startswith('GNU.sparse')for k in member.pax_headers),'sparse qualification DATA refused');name=PurePosixPath(member.name)
            if member.isdir() and str(name)=='output':continue
            need(member.isfile() and len(name.parts)==2 and name.parts[0]=='output' and re.fullmatch('[A-Za-z0-9._-]{1,128}',name.name) and name.name not in seen,'flat ordinary qualification DATA only')
            seen.add(name.name);total+=member.size;need(len(seen)<=128 and member.size<=32*1024**2 and total<=80*1024**2,'finite qualification DATA namespace')
            target=destination/name.name
            with stream.extractfile(member)as source,target.open('xb')as out:
                while True:
                    tick();block=source.read(1024**2)
                    if not block:break
                    out.write(block)
            target.chmod(0o444);stream.members.clear()
        end_tar(stream,state,tick)
    return destination


def validate_result(value,provider,boot):
    need(value['schema']==4 and value['status']=='PASS_NATIVE_SOURCE_QUALIFICATION_ONLY' and value['binding']==provider['source'] and value['dispatch_sha256']==provider['dispatch_sha256'] and value['provider_phase_sha256']==hashlib.sha256(encode(provider)).hexdigest(),'actual qualification joins this Source/provider/pregrant')
    need(value['image_id']==boot['image'] and value['rootfs_tree_sha256']==boot['rootfs_tree_sha256'] and value['native_acceptance']is False and value['holds_preserved']is True,'actual normal image/rootfs and held acceptance')
    ro=value['readonly_stage0'];need(ro['paths']==['/stage0','/work/build/stage0'] and all(ro[k]is True for k in ('readonly','namespace_permissions_verified','write_attempts_denied','alias_write_attempts_denied')) and [r['errno']for r in ro['attempts']]==[30,30],'actual EROFS evidence for both stage0 aliases')
    rows=value['probe_receipts'];need(len(rows)==9,'nine actual native probe receipts')
    for row,expected in zip(rows,PROBES):
        need(row['argv']==expected and row['returncode']==0 and P_natural(row['lifecycle']),'all probe children naturally retired')
    for k in ('stage0_tree_sha256','qualified_llvm_tree_sha256','library_cargo_config_sha256','source_tree_sha256'):need(re.fullmatch('[0-9a-f]{64}',value[k]),'whole actual qualification tree hash')


def P_natural(life):return life.get('natural_exit')is True and life.get('forced_cleanup')is False and life.get('group_absent')is True and life.get('retirement')=='REAPED' and life.get('ownership_lost')is False and life.get('leader_held_until_group_inspection')is True and life.get('exit_observed_via_waitpid')is True and life.get('exit')==0


def run(root,work,provider,plan,delivered,boot,command):
    root,work=Path(root),Path(work);need(plan['reviews']['stage0']is True and plan['reviews']['source']is True and plan['reviews']['llvm_material']is True,'separate Root qualification/source/LLVM reviews')
    audit_path=Path(delivered['files']['source_audit']['local_path']);audit=json.loads(audit_path.read_bytes());need(encode(audit)==encode(plan['source_audit']),'exact Root source audit body, not a generated review')
    P=load('rust_qualification_domain',root/'hosted/producer.py');V=P.V
    binding=provider['source'];owner=V.binding(binding,boot['image'],provider['dispatch_sha256']);base='rust199-qual-'+owner['token'];owner.update(init=base+'-init',prepare=base+'-data',makepkg=base+'-probe',volume=base+'-work')
    actors=dict(init=owner['init'],data=owner['prepare'],probe=owner['makepkg']);volume=owner['volume'];labels={role:P.labels(binding,owner['token'],'qualification-'+role)for role in (*actors,'volume')}
    out=work/'qualification';out.mkdir(mode=0o700);inputs=out/'inputs';inputs.mkdir(mode=0o755)
    materials={r['name']:Path(r['local_path'])for r in delivered['materials']}
    q=dict(schema=4,status='ROOT_PREGRANTED_NATIVE_SOURCE_QUALIFICATION_ONLY',qualification_allowed=True,holds_preserved=plan['holds_preserved'],provider=provider,image_id=boot['image'],rootfs_tree_sha256=boot['rootfs_tree_sha256'],source_audit=audit,materials={r['name']:{k:r[k]for k in ('bytes','sha256')}for r in delivered['materials']},volume_owner=owner)
    raw=encode(q);(inputs/'qualification.json').write_bytes(raw);(inputs/'qualification.json').chmod(0o444);pin=hashlib.sha256(raw).hexdigest()
    report=dict(schema=4,status='FAIL',provider=provider,image=boot['image'],volume=volume,actors=actors,intents=[],errors=[],cleanup=[],native_acceptance=False)
    deadline=min(command.deadline,time.monotonic()+1800);ids={};report['container_ids']=ids;volume_path=None;latest=None;failure=None
    def tick():
        need(time.monotonic()<min(deadline,command.deadline),'qualification aggregate1800s/global deadline')
        need(command.cleaning or not command.cancelled[0],'qualification cancellation')
        if command.on_tick is not None and not command.cleaning:command.on_tick()
    def save():(out/'controller.json').write_bytes(encode(report))
    def call(argv,timeout=60,check=True):
        tick()
        cap=min(timeout,deadline-time.monotonic());need(cap>0,'qualification aggregate1800s cap');return command(argv,timeout=cap,check=check)
    def one(argv):
        rows=json.loads(call(argv).stdout);need(type(rows)is list and len(rows)==1,'one actual daemon observation');return rows[0]
    def created(role,result):ids[role]=P.created_id(result.stdout);save()
    def intent(kind,name,role):report['intents'].append(dict(kind=kind,name=name,role=role));save()
    def identity(row,name,role):P.inspect_identity(row,name,boot['image'],labels[role]);need(row['Id']==ids[role],'same captured qualification container')
    def export(name):
        path=out/'export.tar';life={};old=resource.getrlimit(resource.RLIMIT_FSIZE);cap=min([EXPORT_CAP]+[v for v in old if v!=resource.RLIM_INFINITY]);need(cap==EXPORT_CAP,'never relax inherited export file limit')
        try:
            resource.setrlimit(resource.RLIMIT_FSIZE,(cap,old[1]))
            tick()
            with path.open('xb')as output,(out/'export.stderr').open('xb')as error:result=command.owned.run(DOCKER+['cp',name+':/work/output','-'],timeout=min(120,deadline-time.monotonic(),command.deadline-time.monotonic()),cwd=work,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},stdout=output,stderr=error,lifecycle=life,stdout_limit=EXPORT_CAP,stderr_limit=16*1024**2,on_tick=tick)
            need(result.returncode==0 and P_natural(life),'natural bounded qualification export');report['export']=dict(bytes=path.stat().st_size,sha256=sha(path,tick),lifecycle=life)
        finally:resource.setrlimit(resource.RLIMIT_FSIZE,old);save()
    save()
    try:
        need(not set(actors.values())&set(call(DOCKER+['container','ls','--all','--format','{{.Names}}']).stdout.decode().splitlines()) and volume not in call(DOCKER+['volume','ls','--quiet']).stdout.decode().splitlines(),'fresh complete qualification namespace')
        intent('volume',volume,'volume');call(DOCKER+['volume','create','--driver=local',*P.label_options(labels['volume']),volume]);row=one(DOCKER+['volume','inspect',volume]);need(row['Name']==volume and row['Driver']=='local' and not row.get('Options') and row['Labels']==labels['volume'],'exact local qualification volume');volume_path=Path(row['Mountpoint'])
        intent('container',actors['data'],'data');created('data',call(options(P,actors['data'],volume,boot['image'],inputs,root,materials,'data',pin,labels['data'])));row=one(DOCKER+['container','inspect',actors['data']]);identity(row,actors['data'],'data');inspect_actor(P,row,actors['data'],volume,boot['image'],inputs,root,materials,'data',pin,labels['data'],volume_path)
        intent('container',actors['init'],'init');created('init',call(P.init_options(actors['init'],volume,boot['image'],labels['init'],owner)));row=one(DOCKER+['container','inspect',actors['init']]);identity(row,actors['init'],'init');P.inspect_init(row,actors['init'],volume,boot['image'],labels['init'],volume_path,owner)
        started=call(DOCKER+['start','--attach',actors['init']],60);row=one(DOCKER+['container','inspect',actors['init']]);identity(row,actors['init'],'init');P.inspect_init(row,actors['init'],volume,boot['image'],labels['init'],volume_path,owner,created=False);P.finished(row)
        need(len(started.stdout)<=16384,'bounded actual initializer receipt');initialized=json.loads(started.stdout);V.verify_receipt(initialized,owner);(inputs/'volume-initialization.json').write_bytes(encode(initialized));(inputs/'volume-initialization.json').chmod(0o444);report['initialization']=initialized
        for phase,budget in (('data',900),('probe',180)):
            name=actors[phase]
            if phase=='probe':intent('container',name,phase);created(phase,call(options(P,name,volume,boot['image'],inputs,root,materials,phase,pin,labels[phase])))
            row=one(DOCKER+['container','inspect',name]);identity(row,name,phase);inspect_actor(P,row,name,volume,boot['image'],inputs,root,materials,phase,pin,labels[phase],volume_path)
            if phase in ids:need(row['Id']==ids[phase],'same prepared qualification actor')
            ids[phase]=row['Id'];(out/(phase+'-inspect.json')).write_bytes(encode(row));latest=name;call(DOCKER+['start','--attach',name],budget);row=one(DOCKER+['container','inspect',name]);identity(row,name,phase);P.finished(row);(out/(phase+'-finished.json')).write_bytes(encode(row))
        export(latest);data=unpack(out/'export.tar',out/'data',tick);value=json.loads((data/'native-qualification.json').read_bytes());validate_result(value,provider,boot);need(value['source_audit']==audit,'Root audit unchanged through qualifier');tick()
        files={('native_qualification'if path.name=='native-qualification.json'else'qualification_'+path.name):dict(local_path=str(path),bytes=path.stat().st_size,sha256=sha(path,tick))for path in sorted(data.iterdir())}
        report['status']='PASS_NATIVE_SOURCE_QUALIFICATION_ONLY';report['result']=value
    except BaseException as error:
        failure=error;report['errors'].append(type(error).__name__+': '+str(error)[:1500])
        if latest is not None and not (out/'export.tar').exists() and time.monotonic()<deadline-30:
            try:
                phase=next(role for role,name in actors.items() if name==latest);row=one(DOCKER+['container','inspect',latest]);identity(row,latest,phase)
                if row['State']['Status']not in ('created','exited'):
                    report['forced_cleanup']=True;report['errors'].append('forced stop before diagnostic export');call(DOCKER+['stop','--time=1',latest],15);row=one(DOCKER+['container','inspect',latest]);identity(row,latest,phase)
                need(row['State']['Status']=='exited' and not row['State']['Running'],'diagnostic export only after stopped actor')
                export(latest);report['diagnostic_export_only']=True
            except BaseException as diagnostic:report['errors'].append('diagnostic export: '+str(diagnostic))
    finally:
        previous=(command.cleaning,command.deadline);command.cleaning=True;command.deadline=time.monotonic()+300;deadline=command.deadline
        for item in reversed(report['intents']):
            try:
                kind,name,role=item['kind'],item['name'],item['role'];present=call(DOCKER+[kind,'ls','--all','--format','{{.Names}}']if kind=='container'else DOCKER+['volume','ls','--quiet']).stdout.decode().splitlines()
                if name not in present:continue
                row=one(DOCKER+[kind,'inspect',name])
                if kind=='container':
                    P.inspect_identity(row,name,boot['image'],labels[role]);need(role not in ids or row['Id']==ids[role],'same acknowledged qualification CID during cleanup');live=row['State']['Status']not in ('created','exited')
                    if live:report['errors'].append('forced qualification retirement');report['forced_cleanup']=True
                    call(DOCKER+['container','rm']+(['--force']if live else[])+[row['Id']])
                else:need(row['Name']==volume and row['Driver']=='local' and row['Labels']==labels['volume'] and not row.get('Options'),'exact owned volume retirement');call(DOCKER+['volume','rm',name])
                report['cleanup'].append(name)
            except BaseException as error:report['errors'].append('cleanup: '+str(error))
        try:
            need(not set(actors.values())&set(call(DOCKER+['container','ls','--all','--format','{{.Names}}']).stdout.decode().splitlines()) and volume not in call(DOCKER+['volume','ls','--quiet']).stdout.decode().splitlines(),'actual qualification resources absent');report['owned_resources_absent']=True
        except BaseException as error:report['errors'].append(str(error))
        command.cleaning,command.deadline=previous
        if report['errors'] or not report.get('owned_resources_absent'):report['status']='FAIL'
        save()
    if failure is not None:raise failure
    need(report['status']=='PASS_NATIVE_SOURCE_QUALIFICATION_ONLY','qualification retirement failed')
    result=report['result'];deadline=command.deadline;path=out/'controller.json';files['qualification_controller']=dict(local_path=str(path),bytes=path.stat().st_size,sha256=sha(path,tick))
    return dict(result,proof_path=files['native_qualification']['local_path'],proof_sha256=files['native_qualification']['sha256'],files=files)

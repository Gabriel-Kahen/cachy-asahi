# SPDX-License-Identifier: MIT
"""Actual cap0 assembly/probe phase; runtime proofs never substitute for Root grants."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import stat
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


def options(P,name,volume,image,inputs,root,materials,phase,pin,labels,volume_path):
    argv=DOCKER+['create','--name',name,*P.label_options(labels),'--cpus=2','--memory=8g','--memory-swap=8g','--pids-limit=512','--init','--read-only','--network=none','--ipc=private','--cgroupns=private','--restart=no','--log-driver=none','--hostname=rust199-qualification','--cap-drop=ALL','--security-opt=no-new-privileges','--user=1001:1001','--ulimit=nofile=1024:1024','--ulimit=core=0:0','--workdir=/work','--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m,uid=1001,gid=1001','--tmpfs=/run:rw,noexec,nosuid,nodev,size=8m,uid=1001,gid=1001']
    for row in P.mount_specs(volume,inputs,root,materials,'prepare'if phase=='data'else'makepkg',volume_path):argv+=['--mount',P.mount_option(row)]
    return argv+['--env','QUALIFICATION_SHA256='+pin,'--entrypoint=/usr/bin/python',image,'-I','-B','/source/actor/qualify.py',phase]


def inspect_actor(P,row,name,volume,image,inputs,root,materials,phase,pin,labels,volume_path):
    P.inspect_identity(row,name,image,labels);P.inspect_domain(row,8*1024**3,512,'1001:1001',[])
    config,host=row['Config'],row['HostConfig'];need(config['Entrypoint']==['/usr/bin/python'] and config['Cmd']==['-I','-B','/source/actor/qualify.py',phase] and config['Hostname']=='rust199-qualification' and config['WorkingDir']=='/work','exact qualification actor vector')
    env=dict(item.split('=',1)for item in config['Env']);need(env.get('QUALIFICATION_SHA256')==pin and not any(k.startswith(('LD_','PYTHON','GH_TOKEN','GITHUB_TOKEN')) for k in env),'only explicit qualification grant, no credentials/loaders')
    need(host['Tmpfs']=={'/tmp':'rw,noexec,nosuid,nodev,size=64m,uid=1001,gid=1001','/run':'rw,noexec,nosuid,nodev,size=8m,uid=1001,gid=1001'},'bounded qualification tmpfs')
    P.inspect_mounts(row,P.mount_specs(volume,inputs,root,materials,'prepare'if phase=='data'else'makepkg',volume_path),volume,volume_path,kernel_proof_required=phase=='probe')
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


def kernel_proofs(value,provider,boot,directory=None):
    M=load('hosted_qualification_kernel_mount_proof',Path(__file__).parent.parent/'actor/mount_proof.py')
    proofs=value['kernel_mount_proofs'];need(set(proofs)=={'qualification-data','qualification-probe'},'both required actual kernel preentry proofs')
    def body(row):
        need(type(row)is dict and set(row)=={'file','bytes','sha256'} and type(row['bytes'])is int and 0<row['bytes']<=M.MAX_BYTES and re.fullmatch('[A-Za-z0-9.-]{1,128}',row['file'])and re.fullmatch('[0-9a-f]{64}',row['sha256']),'fixed bounded kernel evidence descriptor')
        if directory is not None:path=Path(directory)/row['file']
        else:
            item=value['files']['qualification_'+row['file']];need({k:item[k]for k in('bytes','sha256')}=={k:row[k]for k in('bytes','sha256')},'relocated kernel evidence whole descriptor');path=Path(item['local_path'])
        need(path.is_absolute()and '..'not in path.parts and not any(p.is_symlink()for p in(path,*path.parents)),'ordinary kernel evidence path')
        with path.open('rb')as stream:
            before=os.fstat(stream.fileno());need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and before.st_size==row['bytes'],'exact ordinary kernel evidence')
            raw=stream.read(row['bytes']+1);after=os.fstat(stream.fileno())
        key=lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
        need(key(before)==key(after)==key(path.lstat())and M.pin(raw)=={k:row[k]for k in('bytes','sha256')},'stable whole kernel evidence bytes');return raw
    plan_raw=body(value['qualification_plan']);plan=json.loads(plan_raw)
    need(plan['provider']==provider and plan['image_id']==boot['image']and plan['rootfs_tree_sha256']==boot['rootfs_tree_sha256']and plan['qualification_allowed']is True and plan['holds_preserved']is True,'same pregranted qualifier plan/provider/image')
    result={};observed={}
    for phase,envelope in proofs.items():
        need(set(envelope)=={'receipt','mountinfo'}and envelope['receipt']['file']=='kernel-mount-proof-'+phase+'.json'and envelope['mountinfo']['file']=='kernel-mountinfo-'+phase+'.raw','exact kernel qualifier evidence namespace')
        receipt=json.loads(body(envelope['receipt']));raw=body(envelope['mountinfo']);ctx=dict(source=provider['source'],dispatch_sha256=provider['dispatch_sha256'],input_admission_sha256=hashlib.sha256(plan_raw).hexdigest(),image_id=boot['image'],volume_token=plan['volume_owner']['token'],phase=phase)
        M.validate(raw,receipt,ctx);need(receipt['mountinfo']==envelope['mountinfo'],'same retained raw mountinfo descriptor');result[phase]=envelope['receipt']['sha256'];observed[phase]=receipt['mounts']['/work']
    need(all(observed['qualification-data'][k]==observed['qualification-probe'][k]for k in('device','root','fs_type','source','super_options')),'same initialized work filesystem/root across qualifier phases')
    rows=json.loads(body(value['data_commands']));need(type(rows)is list and len(rows)==5 and all(r['returncode']==0 and P_natural(r['lifecycle'])and r['kernel_mount_proof_sha256']==result['qualification-data']for r in rows),'all five data children naturally retired after kernel proof')
    return result


def validate_result(value,provider,boot,directory=None):
    need(value['schema']==4 and value['status']=='PASS_NATIVE_SOURCE_QUALIFICATION_ONLY' and value['binding']==provider['source'] and value['dispatch_sha256']==provider['dispatch_sha256'] and value['provider_phase_sha256']==hashlib.sha256(encode(provider)).hexdigest(),'actual qualification joins this Source/provider/pregrant')
    need(value['image_id']==boot['image'] and value['rootfs_tree_sha256']==boot['rootfs_tree_sha256'] and value['native_acceptance']is False and value['holds_preserved']is True,'actual normal image/rootfs and held acceptance')
    P=load('qualification_owned_bind_replay',Path(__file__).with_name('producer.py'));owner=P.V.binding(provider['source'],boot['image'],provider['dispatch_sha256']);volume='rust199-qual-'+owner['token']+'-work';P.replay_work_bind(value['owned_work_bind'],volume,P.labels(provider['source'],owner['token'],'qualification-volume'))
    ro=value['readonly_stage0'];need(ro['paths']==['/stage0','/work/build/stage0'] and all(ro[k]is True for k in ('readonly','namespace_permissions_verified','write_attempts_denied','alias_write_attempts_denied')) and [r['errno']for r in ro['attempts']]==[30,30],'actual EROFS evidence for both stage0 aliases')
    kernel=kernel_proofs(value,provider,boot,directory)
    rows=value['probe_receipts'];need(len(rows)==9,'nine actual native probe receipts')
    for row,expected in zip(rows,PROBES):
        need(row['argv']==expected and row['returncode']==0 and P_natural(row['lifecycle'])and row['kernel_mount_proof_sha256']==kernel['qualification-probe'],'all probe children naturally retired after kernel proof')
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
    deadline=min(command.deadline,time.monotonic()+1800);ids={};report['container_ids']=ids;volume_path=None;workspace=None;latest=None;failure=None
    previous_tick=command.on_tick
    def tick():
        need(time.monotonic()<min(deadline,command.deadline),'qualification aggregate1800s/global deadline')
        need(command.cleaning or not command.cancelled[0],'qualification cancellation')
        if workspace is not None and not command.cleaning:workspace.check()
        if previous_tick is not None and not command.cleaning:previous_tick()
    def save():(out/'controller.json').write_bytes(encode(report))
    def call(argv,timeout=60,check=True):
        tick()
        if workspace is not None and not command.cleaning:workspace.check()
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
    command.on_tick=tick
    save()
    try:
        need(not set(actors.values())&set(call(DOCKER+['container','ls','--all','--format','{{.Names}}']).stdout.decode().splitlines()) and volume not in call(DOCKER+['volume','ls','--quiet']).stdout.decode().splitlines(),'fresh complete qualification namespace')
        daemon_raw=call(DOCKER+['info','--format',P.DAEMON_BIND_INFO_FORMAT],30).stdout;prior=json.loads((work/'daemon.json').read_bytes())['info'];info=P.decode(daemon_raw);need(all(info[k]==prior[k]for k in('ID','DockerRootDir')),'same already admitted local daemon')
        workspace=P.workspace_module().Lease(work,volume,daemon_raw,labels['volume'],root);report['owned_work_bind']=workspace.bind_source(binding);report['workspace_lifecycle']=[dict(status='CREATED_HELD',after_operation_count=len(command.rows),workspace_node=workspace.worknode,nonce=workspace.proof['nonce'])];volume_path=workspace.path;save()
        intent('container',actors['data'],'data');created('data',call(options(P,actors['data'],volume,boot['image'],inputs,root,materials,'data',pin,labels['data'],volume_path)));row=one(DOCKER+['container','inspect',actors['data']]);identity(row,actors['data'],'data');inspect_actor(P,row,actors['data'],volume,boot['image'],inputs,root,materials,'data',pin,labels['data'],volume_path)
        intent('container',actors['init'],'init');created('init',call(P.init_options(actors['init'],volume,boot['image'],labels['init'],owner,volume_path)));row=one(DOCKER+['container','inspect',actors['init']]);identity(row,actors['init'],'init');P.inspect_init(row,actors['init'],volume,boot['image'],labels['init'],volume_path,owner)
        started=call(DOCKER+['start','--attach',actors['init']],60);row=one(DOCKER+['container','inspect',actors['init']]);identity(row,actors['init'],'init');P.inspect_init(row,actors['init'],volume,boot['image'],labels['init'],volume_path,owner,created=False);P.finished(row)
        need(len(started.stdout)<=16384,'bounded actual initializer receipt');initialized=json.loads(started.stdout);V.verify_receipt(initialized,owner);workspace.check();need(initialized['before']==initialized['after']==workspace.worknode,'same held owned directory initializer inode');(inputs/'volume-initialization.json').write_bytes(encode(initialized));(inputs/'volume-initialization.json').chmod(0o444);report['initialization']=initialized
        for phase,budget in (('data',900),('probe',180)):
            name=actors[phase]
            if phase=='probe':intent('container',name,phase);created(phase,call(options(P,name,volume,boot['image'],inputs,root,materials,phase,pin,labels[phase],volume_path)))
            row=one(DOCKER+['container','inspect',name]);identity(row,name,phase);inspect_actor(P,row,name,volume,boot['image'],inputs,root,materials,phase,pin,labels[phase],volume_path)
            if phase in ids:need(row['Id']==ids[phase],'same prepared qualification actor')
            ids[phase]=row['Id'];(out/(phase+'-inspect.json')).write_bytes(encode(row));latest=name;call(DOCKER+['start','--attach',name],budget);row=one(DOCKER+['container','inspect',name]);identity(row,name,phase);P.finished(row);(out/(phase+'-finished.json')).write_bytes(encode(row))
        export(latest);data=unpack(out/'export.tar',out/'data',tick);value=json.loads((data/'native-qualification.json').read_bytes());value['owned_work_bind']=report['owned_work_bind'];validate_result(value,provider,boot,data);need(value['source_audit']==audit,'Root audit unchanged through qualifier');tick()
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
                else:raise ValueError('no volume or foreign resource cleanup')
                report['cleanup'].append(name)
            except BaseException as error:report['errors'].append('cleanup: '+str(error))
        try:
            need(not set(actors.values())&set(call(DOCKER+['container','ls','--all','--format','{{.Names}}']).stdout.decode().splitlines()) and volume not in call(DOCKER+['volume','ls','--quiet']).stdout.decode().splitlines(),'actual qualification actors absent')
            if workspace is not None:
                retired=workspace.retire(lambda:need(time.monotonic()<command.deadline,'workspace cleanup deadline'));retired['after_operation_count']=len(command.rows);report['workspace_lifecycle'].append(retired)
            report['owned_resources_absent']=workspace is not None
        except BaseException as error:report['errors'].append(str(error))
        if workspace is not None:workspace.close()
        command.cleaning,command.deadline=previous;command.on_tick=previous_tick
        if report['errors'] or not report.get('owned_resources_absent'):report['status']='FAIL'
        save()
    if failure is not None:raise failure
    need(report['status']=='PASS_NATIVE_SOURCE_QUALIFICATION_ONLY','qualification retirement failed')
    result=report['result'];deadline=command.deadline;path=out/'controller.json';files['qualification_controller']=dict(local_path=str(path),bytes=path.stat().st_size,sha256=sha(path,tick))
    return dict(result,owned_work_bind=report['owned_work_bind'],proof_path=files['native_qualification']['local_path'],proof_sha256=files['native_qualification']['sha256'],files=files)

# SPDX-License-Identifier: MIT
"""Explicit v2 owned-volume initialization; unchanged v1 nonroot Python actor."""
import hashlib
import json
import os
from pathlib import Path
import resource
import shutil
import subprocess
import time

DOCKER=['/usr/bin/docker','--host=unix:///var/run/docker.sock']
PREFIX='/opt/cachy-asahi/llvm23-source-reference'


def options(name,volume,image,inputs,source,admission,owner,volume_admission):
    return DOCKER+['create','--name',name,'--label','cachy-asahi.operation=llvm23-source-reference-native-v2','--label','cachy-asahi.llvm-work.source='+owner['source'],'--label','cachy-asahi.llvm-work.token='+owner['token'],'--label','cachy-asahi.llvm-work.role=builder','--cpus=2','--memory=8g','--memory-swap=8g','--pids-limit=512','--init','--read-only','--network=none','--hostname=llvm23-native','--cap-drop=ALL','--security-opt=no-new-privileges','--user=1001:1001','--ulimit=nofile=1024:1024','--ulimit=core=0:0','--workdir=/work','--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m,uid=1001,gid=1001','--tmpfs=/run:rw,noexec,nosuid,nodev,size=8m,uid=1001,gid=1001','--mount',f'type=volume,src={volume},dst=/work,volume-nocopy','--mount',f'type=bind,src={inputs},dst=/inputs,readonly','--mount',f'type=bind,src={source},dst=/source,readonly','--env','ADMISSION_SHA256='+admission,'--env','WORK_VOLUME_ADMISSION_SHA256='+volume_admission,'--entrypoint=/usr/bin/bash',image,'--noprofile','--norc','/inputs/actor/entry.sh']


def inspect_actor(actor,name,volume,image,inputs,source,owner,volume_admission):
    def need(ok,why):
        if not ok:raise ValueError(why)
    host=actor['HostConfig'];config=actor['Config']
    need(actor['Name']=='/'+name and actor['Image']==image and config['User']=='1001:1001' and config['Hostname']=='llvm23-native' and config['WorkingDir']=='/work','actual immutable actor identity')
    need(host['ReadonlyRootfs'] and host['NetworkMode']=='none' and host['CapDrop']==['ALL'] and not host.get('CapAdd') and host['SecurityOpt']==['no-new-privileges'] and not host['Privileged'] and host.get('UsernsMode','')=='','actual Rootful cap0/NNP/RO/no-network domain')
    need(host['Memory']==host['MemorySwap']==8*1024**3 and host['NanoCpus']==2000000000 and host['PidsLimit']==512 and host['Init'] is True,'actual finite cgroup create operands')
    mounts={m['Destination']:m for m in actor['Mounts']}
    need(set(mounts)=={'/work','/inputs','/source'},'exact three actor mounts')
    need(mounts['/work']['Type']=='volume' and mounts['/work']['Name']==volume and mounts['/work']['RW'],'one owned work volume')
    for path,target in [(inputs,'/inputs'),(source,'/source')]:
        need(mounts[target]['Type']=='bind' and mounts[target]['Source']==str(path) and not mounts[target]['RW'],'exact readonly actor DATA mount')
    need(all(config['Labels'].get(k)==v for k,v in {'cachy-asahi.operation':'llvm23-source-reference-native-v2','cachy-asahi.llvm-work.source':owner['source'],'cachy-asahi.llvm-work.token':owner['token'],'cachy-asahi.llvm-work.role':'builder'}.items())and 'WORK_VOLUME_ADMISSION_SHA256='+volume_admission in config['Env'],'actual source/token-bound builder')
    declared=[m for m in host['Mounts']if m['Target']=='/work'];need(len(declared)==1 and declared[0]['Type']=='volume'and declared[0]['Source']==volume and declared[0]['VolumeOptions']['NoCopy']is True,'explicit builder nocopy')
    need(config['Entrypoint']==['/usr/bin/bash'] and config['Cmd']==['--noprofile','--norc','/inputs/actor/entry.sh'],'exact entry body')


def run(root,work,binding,image,source,command):
    spec=__import__('importlib.util',fromlist=['util'])
    s=spec.spec_from_file_location('llvm_producer_common',root/'hosted/common.py');c=spec.module_from_spec(s);s.loader.exec_module(c)
    V=c.load('llvm_v2_owned_volume',root/'hosted/volume.py');policy=c.decode(c.read(root/'policy.json'));out=work/'llvm-build';out.mkdir(mode=0o700)
    inputs=out/'inputs';inputs.mkdir(mode=0o755)
    for name in ['actor','helpers','packages']:
        shutil.copytree(root/name,inputs/name)
    shutil.copy2(root/'contract.json',inputs/'contract.json');shutil.copy2(source['archive'],inputs/'archive.tar.xz')
    candidate=c.load('llvm_candidate_pure_data',root/'packages/port/llvm23-source-reference/reference.py')
    sourcepath=Path(source['root']);source_tree=candidate.tree_digest(sourcepath)
    admission=dict(schema=1,mode='ROOTFUL_CONTAINER_NO_BWRAP_V1',operation=V.INNER,source=dict(sha=binding['source'],ref=binding['ref'].removeprefix('refs/heads/')),run=binding['run'],job=binding['job'],approval=binding['approval'],image=image,source_map_sha256=binding['source_map_sha256'],contract_sha256=c.pin(c.read(root/'contract.json'))['sha256'],source_tree_sha256=source_tree,expected349_sha256='579981195b654d8cdf142e4101dfc2bfffbc3576eed50f23796a06e90cf57453',input_signature_audit_sha256=c.pin(c.read(work/'bootstrap/signatures.json',8*1024**2))['sha256'],holds_preserved=True)
    raw=c.encode(admission);(inputs/'admission.json').write_bytes(raw)
    owner=V.owner(binding);name,init,volume=(owner[k]for k in('actor','init','volume'));volume_body=c.encode(V.admission(owner));(inputs/'volume-admission.json').write_bytes(volume_body);volume_sha=c.pin(volume_body)['sha256']
    report=dict(schema=1,status='FAIL',binding=binding,image=image,admission_sha256=c.pin(raw)['sha256'],source_intake=source,inputs_path=str(inputs),actor=name,init=init,volume=volume,cleanup=[],actual_created=False,native_acceptance=False,volume_owner=owner,inner_operation=V.INNER,volume_admission_sha256=volume_sha)
    def save():(out/'producer.json').write_bytes(c.encode(report))
    save();prior_tick=command.on_tick;last=[0]
    def watch():
        if time.monotonic()-last[0]<1:return
        last[0]=time.monotonic()
        available=int(next(s.split()[1] for s in Path('/proc/meminfo').read_text().splitlines() if s.startswith('MemAvailable:')))*1024
        c.need(available>=4*1024**3,'active host memory reserve exhausted')
        for path in (out,Path(c.decode(c.read(work/'daemon.json'))['info']['DockerRootDir'])):
            v=os.statvfs(path);c.need(v.f_bavail*v.f_frsize>=1024**3,'active byte reserve exhausted')
    command.on_tick=watch
    def call(argv,timeout=60,check=True):return command(argv,timeout=timeout,check=check)
    def export():
        def export_tick():
            c.need(not command.cancelled[0] and time.monotonic()<command.deadline-300,'Root cancellation/deadline during export')
            watch()
        path=out/'export.tar';lifecycle={};cap=policy['export_bytes'];previous=resource.getrlimit(resource.RLIMIT_FSIZE)
        try:
            resource.setrlimit(resource.RLIMIT_FSIZE,(min(cap,previous[1]) if previous[1]!=resource.RLIM_INFINITY else cap,previous[1]))
            with path.open('xb') as output,(out/'export-stderr.log').open('xb') as error:
                result=command.owned.run(DOCKER+['cp',name+':/work/output','-'],timeout=min(1200,command.deadline-time.monotonic()-300),env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},stdout=output,stderr=error,lifecycle=lifecycle,stdout_limit=cap,stderr_limit=16*1024**2,on_tick=export_tick)
            c.need(result.returncode==0 and lifecycle.get('natural_exit') and lifecycle.get('retirement')=='REAPED' and lifecycle.get('group_absent') and not lifecycle.get('forced_cleanup'),'natural bounded export required')
            with path.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
            report['export']=dict(bytes=path.stat().st_size,sha256=digest,lifecycle=lifecycle,file='export.tar')
        finally:
            resource.setrlimit(resource.RLIMIT_FSIZE,previous);report['export_lifecycle']=lifecycle;save()
    try:
        for item in(name,init):c.need(not call(DOCKER+['container','ls','--all','--format','{{.Names}}','--filter','name=^'+item+'$']).stdout.strip(),'fresh actor/initializer namespace')
        c.need(not call(DOCKER+['volume','ls','--quiet','--filter','name=^'+volume+'$']).stdout.strip(),'fresh volume namespace')
        report['actual_created']=True;save()
        call(DOCKER+['volume','create',*[x for k,v in V.labels(owner,'work').items()for x in('--label',k+'='+v)],volume])
        volume_row=c.decode(call(DOCKER+['volume','inspect',volume]).stdout)[0];V.volume_identity(volume_row,owner);(out/'volume-before.json').write_bytes(c.encode(volume_row))
        # Both mounts exist, with nocopy, BEFORE the final ownership mutation.
        call(options(name,volume,image,inputs,sourcepath,c.pin(raw)['sha256'],owner,volume_sha))
        actual=c.decode(call(DOCKER+['inspect',name]).stdout)[0];inspect_actor(actual,name,volume,image,inputs,sourcepath,owner,volume_sha)
        (out/'actor-inspect.json').write_bytes(c.encode(actual))
        call(V.init_options(owner,image));initial=c.decode(call(DOCKER+['inspect',init]).stdout)[0];V.inspect_init(initial,owner,image);(out/'initializer-before.json').write_bytes(c.encode(initial))
        initialized=c.decode(call(DOCKER+['start','--attach',init],timeout=120).stdout);V.receipt(initialized,owner)
        final_init=c.decode(call(DOCKER+['inspect',init]).stdout)[0];V.inspect_init(final_init,owner,image)
        c.need(final_init['State']['Status']=='exited'and final_init['State']['ExitCode']==0 and not final_init['State']['Running']and final_init['State']['Pid']==0 and not final_init['State']['OOMKilled'],'natural initializer completion')
        (out/'initializer-after.json').write_bytes(c.encode(final_init));(out/'volume-initialization.json').write_bytes(c.encode(initialized));(inputs/'volume-initialization.json').write_bytes(c.encode(initialized));report['volume_initialization']=initialized;save()
        # The shell pre-entry validates the actual same empty volume as uid1001.
        failure=None
        try:call(DOCKER+['start','--attach',name],timeout=14400)
        except BaseException as error:failure=error;report['first_actor_failure']=type(error).__name__+': '+str(error)[:1024];save()
        try:export()
        except BaseException as error:
            report['export_error']=type(error).__name__+': '+str(error)[:1024];save()
            if failure is None:raise
        if failure:raise failure
        finished=c.decode(call(DOCKER+['inspect',name]).stdout)[0];(out/'actor-finished.json').write_bytes(c.encode(finished))
        c.need(finished['State']['Status']=='exited' and finished['State']['ExitCode']==0 and not finished['State']['OOMKilled'],'actual natural container completion')
        report['actor_completed']=True
    except BaseException as error:report['error']=type(error).__name__+': '+str(error)[:2048]
    finally:
        command.on_tick=None;command.cleaning=True;original_deadline=command.deadline;command.deadline=time.monotonic()+300
        if report['actual_created']:
            for item in (name,init):
                try:
                    result=call(DOCKER+['container','inspect',item],check=False)
                    if result.returncode==0:
                        actor=c.decode(result.stdout)[0]
                        V.container_identity(actor,item,image,owner,'builder'if item==name else'initializer')
                        if item==name:inspect_actor(actor,name,volume,image,inputs,sourcepath,owner,volume_sha)
                        else:V.inspect_init(actor,owner,image)
                        if actor['State']['Running']:report.setdefault('cleanup_errors',[]).append('owned container required forced retirement: '+item)
                        call(DOCKER+['rm','-f',item]);report['cleanup'].append(item)
                except BaseException as error:report.setdefault('cleanup_errors',[]).append(str(error))
            try:
                inspect=c.decode(call(DOCKER+['volume','inspect',volume]).stdout)[0]
                V.volume_identity(inspect,owner)
                call(DOCKER+['volume','rm',volume]);report['cleanup'].append(volume)
                containers=call(DOCKER+['container','ls','--all','--format','{{.Names}}']).stdout.decode().splitlines();volumes=call(DOCKER+['volume','ls','--quiet']).stdout.decode().splitlines()
                c.need(not {name,init}&set(containers) and volume not in volumes,'owned actor resources still present')
                report['owned_resources_absent']=True
            except BaseException as error:report.setdefault('cleanup_errors',[]).append(str(error))
        command.deadline=original_deadline;command.cleaning=False;command.on_tick=prior_tick
        if report.get('actor_completed') and report.get('owned_resources_absent') and not report.get('cleanup_errors'):report['status']='COMPLETED_EXPORTED_RETIRED'
        save()
    return report

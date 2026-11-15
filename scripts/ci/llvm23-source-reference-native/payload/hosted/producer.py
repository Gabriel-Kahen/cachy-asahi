# SPDX-License-Identifier: MIT
"""One owned native Root container, explicit separate mode; no nested bwrap fallback."""
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


def options(name,volume,image,inputs,source,admission):
    return DOCKER+['create','--name',name,'--label','cachy-asahi.operation=llvm23-source-reference-native-v1','--cpus=2','--memory=8g','--memory-swap=8g','--pids-limit=512','--init','--read-only','--network=none','--hostname=llvm23-native','--cap-drop=ALL','--security-opt=no-new-privileges','--user=1001:1001','--ulimit=nofile=1024:1024','--ulimit=core=0:0','--workdir=/work','--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m,uid=1001,gid=1001','--tmpfs=/run:rw,noexec,nosuid,nodev,size=8m,uid=1001,gid=1001','--mount',f'type=volume,src={volume},dst=/work','--mount',f'type=bind,src={inputs},dst=/inputs,readonly','--mount',f'type=bind,src={source},dst=/source,readonly','--env','ADMISSION_SHA256='+admission,'--entrypoint=/usr/bin/bash',image,'--noprofile','--norc','/inputs/actor/entry.sh']


def inspect_actor(actor,name,volume,image,inputs,source):
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
    need(config['Entrypoint']==['/usr/bin/bash'] and config['Cmd']==['--noprofile','--norc','/inputs/actor/entry.sh'],'exact entry body')


def run(root,work,binding,image,source,command):
    spec=__import__('importlib.util',fromlist=['util'])
    s=spec.spec_from_file_location('llvm_producer_common',root/'hosted/common.py');c=spec.module_from_spec(s);s.loader.exec_module(c)
    policy=c.decode(c.read(root/'policy.json'));out=work/'llvm-build';out.mkdir(mode=0o700)
    inputs=out/'inputs';inputs.mkdir(mode=0o755)
    for name in ['actor','helpers','packages']:
        shutil.copytree(root/name,inputs/name)
    shutil.copyfile(root/'contract.json',inputs/'contract.json');shutil.copyfile(source['archive'],inputs/'archive.tar.xz')
    candidate=c.load('llvm_candidate_pure_data',root/'packages/port/llvm23-source-reference/reference.py')
    sourcepath=Path(source['root']);source_tree=candidate.tree_digest(sourcepath)
    admission=dict(schema=1,mode='ROOTFUL_CONTAINER_NO_BWRAP_V1',operation=c.OPERATION,source=dict(sha=binding['source'],ref=binding['ref'].removeprefix('refs/heads/')),run=binding['run'],job=binding['job'],approval=binding['approval'],image=image,source_map_sha256=binding['source_map_sha256'],contract_sha256=c.pin(c.read(root/'contract.json'))['sha256'],source_tree_sha256=source_tree,expected349_sha256='579981195b654d8cdf142e4101dfc2bfffbc3576eed50f23796a06e90cf57453',input_signature_audit_sha256=c.pin(c.read(work/'bootstrap/signatures.json',8*1024**2))['sha256'],holds_preserved=True)
    raw=c.encode(admission);(inputs/'admission.json').write_bytes(raw)
    token=hashlib.sha256((binding['source']+binding['run']+binding['job']).encode()).hexdigest()[:24]
    name='llvm23-'+token;init=name+'-init';volume=name+'-work'
    report=dict(schema=1,status='FAIL',binding=binding,image=image,admission_sha256=c.pin(raw)['sha256'],source_intake=source,inputs_path=str(inputs),actor=name,init=init,volume=volume,cleanup=[],actual_created=False,native_acceptance=False)
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
        c.need(not call(DOCKER+['container','ls','--all','--format','{{.Names}}','--filter','name=^'+name+'$']).stdout.strip(),'fresh actor namespace')
        c.need(not call(DOCKER+['volume','ls','--quiet','--filter','name=^'+volume+'$']).stdout.strip(),'fresh volume namespace')
        report['actual_created']=True;save()  # mutation intent precedes uncertain CLI completion
        call(DOCKER+['volume','create','--label','cachy-asahi.operation='+c.OPERATION,volume])
        call(DOCKER+['create','--name',init,'--label','cachy-asahi.operation='+c.OPERATION,'--cpus=2','--memory=128m','--memory-swap=128m','--pids-limit=32','--network=none','--read-only','--user=0:0','--cap-drop=ALL','--cap-add=CHOWN','--security-opt=no-new-privileges','--mount',f'type=volume,src={volume},dst=/work','--entrypoint=/usr/bin/chown',image,'1001:1001','/work'])
        call(DOCKER+['start','--attach',init])
        call(options(name,volume,image,inputs,sourcepath,c.pin(raw)['sha256']))
        actual=c.decode(call(DOCKER+['inspect',name]).stdout)[0];inspect_actor(actual,name,volume,image,inputs,sourcepath)
        (out/'actor-inspect.json').write_bytes(c.encode(actual))
        failure=None
        try:call(DOCKER+['start','--attach',name],timeout=14400)
        except BaseException as error:failure=error;call(DOCKER+['stop','--time=1',name],timeout=15,check=False)
        export()
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
                        c.need(actor['Image']==image and actor['Config']['Labels'].get('cachy-asahi.operation')==c.OPERATION,'owned cleanup identity mismatch')
                        call(DOCKER+['rm','-f',item]);report['cleanup'].append(item)
                except BaseException as error:report.setdefault('cleanup_errors',[]).append(str(error))
            try:
                inspect=c.decode(call(DOCKER+['volume','inspect',volume]).stdout)[0]
                c.need(inspect['Name']==volume and inspect['Labels'].get('cachy-asahi.operation')==c.OPERATION,'owned volume cleanup identity mismatch')
                call(DOCKER+['volume','rm',volume]);report['cleanup'].append(volume)
                containers=call(DOCKER+['container','ls','--all','--format','{{.Names}}']).stdout.decode().splitlines();volumes=call(DOCKER+['volume','ls','--quiet']).stdout.decode().splitlines()
                c.need(not {name,init}&set(containers) and volume not in volumes,'owned actor resources still present')
                report['owned_resources_absent']=True
            except BaseException as error:report.setdefault('cleanup_errors',[]).append(str(error))
        command.deadline=original_deadline;command.cleaning=False;command.on_tick=prior_tick
        if report.get('actor_completed') and report.get('owned_resources_absent') and not report.get('cleanup_errors'):report['status']='COMPLETED_EXPORTED_RETIRED'
        save()
    return report

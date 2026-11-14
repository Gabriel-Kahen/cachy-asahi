#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Finite clean Perl 5.42.3 source builds; no host package installation."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import uuid

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
BASE='archlinux@sha256:fcee73ea1b96e236248f53a213f71276cc9072d9025b58bce9915e32f19963ae'
RUNTIME_SHA='253494be99c21c83743b384b2c06cd1627023ffaf54f0cbbd271bde80572f70a'
LIMITS=['--cpus=2','--memory=4g','--memory-swap=4g','--pids-limit=256']


def need(value,message):
    if not value:raise ValueError(message)


def check_host():
    try:
        from compression import zstd
    except ImportError as error:
        raise ValueError('host Python 3.14 compression.zstd required for bounded archive inspection') from error


def ordinary(path,maximum):
    path=Path(path);info=path.lstat()
    need(stat.S_ISREG(info.st_mode) and 0<=info.st_size<=maximum,'ordinary bounded file required')
    return info


def identity(path):
    path=Path(path);info=ordinary(path,64*1024**2)
    with path.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
    need(path.stat().st_size==info.st_size,'input size changed during read')
    return dict(bytes=info.st_size,sha256=digest)


def text(path,maximum):
    ordinary(path,maximum)
    with path.open('rb') as stream:body=stream.read(maximum+1)
    need(len(body)<=maximum,'export exceeded read bound')
    return body.decode()


def log_contains(path,token):
    ordinary(path,64*1024**2);token=token.encode();tail=b'';total=0;found=False
    with path.open('rb') as stream:
        while block:=stream.read(65536):
            total+=len(block);need(total<=64*1024**2,'log exceeded read bound')
            data=tail+block;found|=token in data;tail=data[-len(token):]
    return found


def verify_inputs(recipe,source):
    pins=json.loads((HERE/'inputs.json').read_bytes())
    need({p.name for p in recipe.iterdir() if p.name!='__pycache__'}==set(pins['files']),'frozen recipe namespace changed')
    for name,row in pins['files'].items():need(identity(recipe/name)==row,'recipe input changed: '+name)
    need(identity(source)=={k:pins['source'][k] for k in ['bytes','sha256']},'source archive changed')
    return pins


def build_options(name,image,volume,snapshot):
    return ['docker','create','--name',name,'--label','cachy-asahi.operation=perl5423-host',*LIMITS,
        '--init','--read-only','--network=none','--hostname=perl5423-host','--cap-drop=ALL',
        '--security-opt=no-new-privileges','--user=1000:1000','--ulimit=nofile=1024:1024','--ulimit=core=0:0',
        '--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m,uid=1000,gid=1000',
        '--tmpfs=/run:rw,noexec,nosuid,nodev,size=8m,uid=1000,gid=1000',
        '--mount',f'type=volume,src={volume},dst=/work',
        '--mount',f'type=bind,src={snapshot},dst=/inputs,readonly',
        '--entrypoint=/usr/bin/bash',image,'/inputs/build.sh']


def validate_actor(row,image,volume,snapshot):
    host,config=row['HostConfig'],row['Config']
    need(row['Image']==image and config['User']=='1000:1000' and config['Hostname']=='perl5423-host','fixed image/user/hostname required')
    need(host['NanoCpus']==2000000000 and host['Memory']==host['MemorySwap']==4294967296 and host['PidsLimit']==256,'exact actor resources required')
    need(host['NetworkMode']=='none' and host['ReadonlyRootfs'] and host['Init'],'offline readonly init actor required')
    need(host['CapDrop']==['ALL'] and host['CapAdd'] in (None,[]) and host['SecurityOpt']==['no-new-privileges'],'unprivileged capability/NNP contract required')
    need(not host['Privileged'] and not host['Devices'],'privileged/device actor refused')
    mounts={m['Destination']:m for m in row['Mounts']}
    need(len(row['Mounts'])==2 and set(mounts)=={'/inputs','/work'},'unexpected actor mount')
    need(mounts['/inputs']['Type']=='bind' and not mounts['/inputs']['RW'] and mounts['/inputs']['Source']==str(snapshot),'exact readonly input snapshot required')
    need(mounts['/work']['Type']=='volume' and mounts['/work']['RW'] and mounts['/work']['Name']==volume,'exact private work volume required')
    return {key:host[key] for key in ['NanoCpus','Memory','MemorySwap','PidsLimit','NetworkMode','ReadonlyRootfs','Init','CapDrop','SecurityOpt']}


def cleanup_absent(argv,text):
    prefix='Error response from daemon: ';name=argv[-1]
    expected={'rm':prefix+'No such container: '+name,'volume':prefix+'get '+name+': no such volume',
              'image':prefix+'No such image: '+name}
    return text.strip()==expected.get(argv[1])


def check_export(export,pins):
    need(text(export/'makepkg-exit.txt',64).strip()=='0','full recipe failed')
    for expected in ('pkgname = perl','pkgver = 5.42.3-1.2','arch = x86_64'):
        need(expected in text(export/'PKGINFO',1024**2).splitlines(),'archive identity differs')
    need('pkgbuild_sha256sum = '+pins['files']['PKGBUILD']['sha256'] in text(export/'BUILDINFO',1024**2).splitlines(),'archive recipe binding differs')
    need(log_contains(export/'makepkg.log','All tests successful.'),'complete upstream harness success missing')
    smoke=json.loads(text(export/'staged-smoke.json',65536))
    need(smoke['version']=='v5.42.3' and len(smoke['shared_objects'])>=5,'actual staged candidate extensions required')
    environment=json.loads(text(export/'environment.json',1024**2))
    need(environment['uid']==environment['gid']==1000 and environment['uname'][-1]=='x86_64','actual unprivileged x86 build required')
    need(environment['cgroup']=={'cpu.max':'200000 100000','memory.max':'4294967296','memory.swap.max':'0','pids.max':'256'},'actual actor cgroup limits differ')
    archive=export/'perl-5.42.3-1.2-x86_64.pkg.tar.zst'
    spec=importlib.util.spec_from_file_location('perl_data_inspector',HERE/'inspect_archive.py')
    inspector=importlib.util.module_from_spec(spec);spec.loader.exec_module(inspector)
    rows=inspector.read_rows(archive);payload=inspector.validate(rows,pins)
    (export/'payload-map.json').write_text(json.dumps(rows,sort_keys=True,indent=2)+'\n')
    return dict(archive=identity(archive),payload=payload,
        export_files={p.name:identity(p) for p in export.iterdir() if p.is_file()})


def main():
    need(sys.flags.isolated and not sys.flags.optimize,'run with python3 -I without optimization')
    check_host()
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--builds',type=int,choices=(1,2),default=2)
    args=parser.parse_args();recipe=ROOT/'packages/port/perl5423-source-candidate'
    pins=verify_inputs(recipe,args.source)
    runtime_path=ROOT/'scripts/port/fdk-native-stage/runtime.py'
    need(identity(runtime_path)['sha256']==RUNTIME_SHA,'existing finite runner changed')
    spec=importlib.util.spec_from_file_location('perl_finite_runtime',runtime_path)
    runtime=importlib.util.module_from_spec(spec);spec.loader.exec_module(runtime)
    out=args.output.absolute()
    need(not out.exists() and not any(p.is_symlink() for p in (out,*out.parents)),'fresh ordinary private output required')
    out.mkdir(mode=0o700);(out/'logs').mkdir(mode=0o700)
    snapshot=out/'inputs';(snapshot/'recipe').mkdir(parents=True)
    for name in pins['files']:shutil.copyfile(recipe/name,snapshot/'recipe'/name)
    shutil.copyfile(args.source,snapshot/pins['source']['name'])
    for name in ('build.sh','provenance.py','staged_smoke.pl'):shutil.copyfile(HERE/name,snapshot/name)
    for path in snapshot.rglob('*'):
        if path.is_file():path.chmod(0o444)
    token=uuid.uuid4().hex[:16];provision='perl5423-provision-'+token;image='cachy-asahi-perl5423-host:'+token
    builds=[dict(name='perl5423-build-'+token+'-'+str(i),init='perl5423-init-'+token+'-'+str(i),
                 volume='perl5423-work-'+token+'-'+str(i)) for i in range(1,args.builds+1)]
    env={k:v for k,v in os.environ.items() if k in ('PATH','HOME','XDG_RUNTIME_DIR','DOCKER_HOST','DOCKER_CONTEXT')}
    runner=runtime.Runner(4800,env,out/'logs')
    report={'schema':1,'status':'HOLD','base':BASE,'controller_pid':os.getpid(),'inputs':pins,
        'helper_files':{p.name:identity(p) for p in HERE.iterdir() if p.is_file()},'operations':[],'cleanup':[],
        'planned_resources':dict(provision=provision,image=image,builds=builds),'builds':[],
        'limits':['x86_64 host only; native ARM/16K/M2 NOT RUN','No installed/ABI/performance/legal/release acceptance','Historical r3/repack/lifecycle results are separate']}
    def save():(out/'report.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    def command(argv,timeout=60,check=True):
        save()
        try:result=runner.run(argv,timeout=timeout,log=f'{len(report["operations"]):02d}.log')
        except BaseException as error:
            report['operations'].append(dict(argv=argv,failure=type(error).__name__+': '+str(error)));save();raise
        report['operations'].append(dict(argv=argv,returncode=result.returncode));save()
        need(not check or result.returncode==0,'command failed: retained operation '+str(len(report['operations'])-1))
        return result
    cancelled=False
    try:
        with runtime.cancellation_handlers():
            row=json.loads(command(['docker','image','inspect',BASE]).stdout)[0]
            need(row['Id']=='sha256:'+BASE.split('sha256:')[1] and row['Architecture']=='amd64','exact cached official image required')
            command(['docker','create','--name',provision,*LIMITS,'--network=host',
                '--mount',f'type=bind,src={HERE},dst=/driver,readonly','--entrypoint=/usr/bin/bash',BASE,'/driver/provision.sh'])
            command(['docker','start','--attach',provision],timeout=900)
            image_id=command(['docker','commit',provision,image],timeout=120).stdout.decode().strip()
            report['provisioned_image']=image_id
            for index,item in enumerate(builds,1):
                command(['docker','volume','create',item['volume']])
                command(['docker','create','--name',item['init'],*LIMITS,'--network=none','--read-only','--cap-drop=ALL',
                    '--cap-add=CHOWN','--security-opt=no-new-privileges','--mount',f'type=volume,src={item["volume"]},dst=/work',
                    '--entrypoint=/usr/bin/chown',image,'1000:1000','/work'])
                command(['docker','start','--attach',item['init']])
                command(build_options(item['name'],image,item['volume'],snapshot))
                details=json.loads(command(['docker','inspect',item['name']]).stdout)[0]
                actor=validate_actor(details,image_id,item['volume'],snapshot)
                (out/f'actor-{index}.json').write_text(json.dumps(details,indent=2)+'\n')
                result=command(['docker','start','--attach',item['name']],timeout=1500,check=False)
                export=out/f'build-{index}'
                command(['docker','cp',item['name']+':/work/output',str(export)],timeout=120)
                record={'actor':actor,'returncode':result.returncode,'export':export.name}
                report['builds'].append(record)
                need(result.returncode==0,'full dependency-checked recipe failed')
                record.update(check_export(export,pins))
                verify_inputs(recipe,args.source);save()
            if len(report['builds'])==2:
                report['archive_bytes_equal']=report['builds'][0]['archive']==report['builds'][1]['archive']
                before=json.loads((out/'build-1/payload-map.json').read_bytes());after=json.loads((out/'build-2/payload-map.json').read_bytes())
                report['repeated_payload_comparison']={'added':sorted(set(after)-set(before)),'removed':sorted(set(before)-set(after)),
                    'changed':[n for n in before if n in after and before[n]!=after[n]],
                    'usr_payload_equal':{n:r for n,r in before.items() if n.startswith('usr')}=={n:r for n,r in after.items() if n.startswith('usr')}}
            report['status']='PASS_CLEAN_HOST_X86_64_SOURCE_BUILDS'
    except BaseException as error:
        cancelled=isinstance(error,runtime.Cancelled)
        report['status']='CANCELLED' if cancelled else 'HOLD_BUILD_FAILED'
        report['failure']=type(error).__name__+': '+str(error)
        if not cancelled:raise
    finally:
        harvest=runtime.Runner(60,env,out/'logs')
        with runtime.defer_signals():
            report['partial_exports']=[]
            for index,item in enumerate(builds,1):
                if (out/f'build-{index}').exists():continue
                # A Docker actor outlives its interrupted CLI. Stop only this
                # registered actor before preserving any partial log snapshot.
                try:
                    observed=harvest.run(['docker','inspect',item['name']],timeout=5)
                    if observed.returncode:
                        report['partial_exports'].append(dict(build=index,status='ACTOR_NOT_OBSERVED'));continue
                    stop=harvest.run(['docker','stop','--time=1',item['name']],timeout=5)
                    need(stop.returncode==0,'owned actor stop failed')
                    result=harvest.run(['docker','cp',item['name']+':/work/output',str(out/f'partial-build-{index}')],timeout=20)
                    report['partial_exports'].append(dict(build=index,returncode=result.returncode,
                        output=result.stdout.decode(errors='replace')[-2048:]))
                except BaseException as error:report['partial_exports'].append(dict(build=index,error=str(error)))
            cleanup=runtime.Runner(180,env,out/'logs')
            actions=[['docker','rm','-f',item[key]] for item in reversed(builds) for key in ('name','init')]
            actions+=[['docker','rm','-f',provision]]
            actions+=[['docker','volume','rm',item['volume']] for item in builds]
            actions+=[['docker','image','rm',image]]
            for argv in actions:
                try:
                    result=cleanup.run(argv,timeout=20)
                    text=result.stdout.decode(errors='replace')
                    report['cleanup'].append(dict(argv=argv,returncode=result.returncode,absent=cleanup_absent(argv,text),output=text[-2048:]))
                except BaseException as error:report['cleanup'].append(dict(argv=argv,error=str(error)))
            try:
                containers=cleanup.run(['docker','container','ls','--all','--format','{{.Names}}'],timeout=15)
                volumes=cleanup.run(['docker','volume','ls','--quiet'],timeout=15)
                images=cleanup.run(['docker','image','ls','--format','{{.Repository}}:{{.Tag}}'],timeout=15)
                need(containers.returncode==volumes.returncode==images.returncode==0,'owned absence observation failed')
                names={provision}|{item[key] for item in builds for key in ('name','init')}
                need(not names&set(containers.stdout.decode().splitlines()),'owned container remains')
                need(not {item['volume'] for item in builds}&set(volumes.stdout.decode().splitlines()),'owned work volume remains')
                need(image not in images.stdout.decode().splitlines(),'owned derived image remains')
                report['owned_resources_absence_verified']=True
            except BaseException as error:
                report['cleanup'].append(dict(error='absence observation: '+str(error)))
                report['owned_resources_absence_verified']=False
        if any(row.get('returncode')!=0 and not row.get('absent') for row in report['cleanup']):report['status']='HOLD_OWNED_CLEANUP'
        try:report['original_inputs_unchanged']=verify_inputs(recipe,args.source)==pins
        except BaseException as error:
            report['original_inputs_unchanged']=False
            report['status']='HOLD_ORIGINAL_INPUTS_CHANGED'
            report['input_recheck_failure']=type(error).__name__+': '+str(error)
        save()
    print(report['status'])
    return 130 if cancelled else 0 if report['status']=='PASS_CLEAN_HOST_X86_64_SOURCE_BUILDS' else 2


if __name__=='__main__':raise SystemExit(main())

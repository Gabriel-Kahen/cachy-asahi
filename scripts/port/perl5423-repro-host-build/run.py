#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Fixed Perl 1.3 sequential host pair; refuse insufficient capacity before actors."""
import argparse
from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import uuid

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
OLD=HERE.parent/'perl5423-host-build'
MIB=1024**2
ARCHIVE='perl-5.42.3-1.3-x86_64.pkg.tar.zst'
TIME='Sun Aug  2 00:00:00 UTC 2026'


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module)
    return module


# Authenticate executable helpers before importing any of them.
import hashlib
PINS=json.loads((HERE/'inputs.json').read_bytes())
for name,row in PINS['helpers'].items():
    path=ROOT/name
    if path.is_symlink() or not path.is_file() or path.stat().st_size!=row['bytes'] or hashlib.sha256(path.read_bytes()).hexdigest()!=row['sha256']:
        raise ValueError('pinned read-only helper changed: '+name)
old=load('perl12_readonly',OLD/'run.py')
capacity=load('perl_capacity',ROOT/'scripts/update/capacity.py')
runtime=load('perl_runtime',ROOT/'scripts/port/fdk-native-stage/runtime.py')
inspector=load('perl_inspector',OLD/'inspect_archive.py')
need=old.need


def verify(recipe,source):
    need({p.name for p in recipe.iterdir()}==set(PINS['files']),'exact 1.3 recipe namespace required')
    for name,row in PINS['files'].items():need(old.identity(recipe/name)==row,'1.3 input changed: '+name)
    need(old.identity(source)=={k:PINS['source'][k] for k in ('bytes','sha256')},'source archive changed')


def guard(docker_root,output,phase,*,prepared=False,committing=False,work=False,inputs=False,exports=2,statvfs=None,meminfo=None):
    """Remaining demand plus one reserve per filesystem, aggregated by st_dev."""
    rows=[dict(path=docker_root,bytes=((0 if prepared else 1024 if committing else 2048)+(0 if work else 2048))*MIB,inodes=80000),
          dict(path=output,bytes=((0 if inputs else 64)+256*exports)*MIB,inodes=12000)]
    devices={}
    for row in rows:devices.setdefault(Path(row['path']).stat().st_dev,row['path'])
    rows.extend(dict(path=p,bytes=1024*MIB,inodes=10000) for p in devices.values())
    # Preserve refusal observations, including the exact unmet byte/inode budget.
    observations=[]
    for row in rows:
        s=(statvfs or os.statvfs)(row['path'])
        observations.append({**row,'path':str(row['path']),'device':Path(row['path']).stat().st_dev,
            'available_bytes':s.f_bavail*s.f_frsize,'available_inodes':s.f_favail})
    mem=meminfo if meminfo is not None else Path('/proc/meminfo').read_text()
    available=int(next(line.split()[1] for line in mem.splitlines() if line.startswith('MemAvailable:')))*1024
    record=dict(phase=phase,requirements=observations,MemAvailable_bytes=available,required_memory_bytes=8192*MIB)
    try:
        capacity.check(rows,statvfs=statvfs)
        need(available>=8192*MIB,'4 GiB actor plus 4 GiB host memory reserve required')
    except ValueError as error:
        record.update(status='HOLD_CAPACITY',failure=str(error));return record
    return {**record,'status':'PASS'}


@contextmanager
def scratch(directory):
    previous=tempfile.tempdir
    try:
        tempfile.tempdir=str(directory)
        yield
    finally:tempfile.tempdir=previous


def check_export(export):
    need(old.text(export/'makepkg-exit.txt',64).strip()=='0','full recipe failed')
    for expected in ('pkgname = perl','pkgver = 5.42.3-1.3','arch = x86_64'):
        need(expected in old.text(export/'PKGINFO',MIB).splitlines(),'exact 1.3 archive required')
    need('pkgbuild_sha256sum = '+PINS['files']['PKGBUILD']['sha256'] in old.text(export/'BUILDINFO',MIB).splitlines(),'recipe binding differs')
    need(old.log_contains(export/'makepkg.log','All tests successful.'),'full upstream harness success missing')
    need(old.text(export/'source-config.over',128)=="cf_time='"+TIME+"'\n",'generated source override differs')
    need(old.text(export/'staged-cf-time.txt',128)==TIME+'\n','actual staged Config time differs')
    smoke=json.loads(old.text(export/'staged-smoke.json',65536))
    need(smoke['version']=='v5.42.3' and len(smoke['shared_objects'])>=5,'actual staged core C extensions required')
    environment=json.loads(old.text(export/'environment.json',MIB))
    need(environment['uid']==environment['gid']==1000 and environment['uname'][-1]=='x86_64','actual unprivileged x86 required')
    need(environment['cgroup']=={'cpu.max':'200000 100000','memory.max':'4294967296','memory.swap.max':'0','pids.max':'256'},'actual resource bounds differ')
    with scratch(export.parent):rows=inspector.read_rows(export/ARCHIVE)
    payload=inspector.validate(rows,PINS)
    (export/'payload-map.json').write_text(json.dumps(rows,sort_keys=True,indent=2)+'\n')
    return dict(archive=old.identity(export/ARCHIVE),payload=payload,
        export_files={p.name:old.identity(p) for p in export.iterdir() if p.is_file()})


def compare(first,second):
    before=json.loads((first/'payload-map.json').read_bytes());after=json.loads((second/'payload-map.json').read_bytes())
    return dict(archive_bytes_equal=old.identity(first/ARCHIVE)==old.identity(second/ARCHIVE),
        added=sorted(set(after)-set(before)),removed=sorted(set(before)-set(after)),
        changed=[n for n in before if n in after and before[n]!=after[n]],all_payload_entries_equal=before==after)


class CapacityOnlyComplete(Exception):pass


def main():
    need(sys.flags.isolated and not sys.flags.optimize,'python -I without optimization required');old.check_host()
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--capacity-only',action='store_true');args=parser.parse_args()
    recipe=ROOT/'packages/port/perl5423-repro-candidate';verify(recipe,args.source)
    out=args.output.absolute();need(not out.exists() and not any(p.is_symlink() for p in (out,*out.parents)),'fresh ordinary output required')
    out.mkdir(mode=0o700);(out/'logs').mkdir(mode=0o700)
    env={k:v for k,v in os.environ.items() if k in ('PATH','HOME','XDG_RUNTIME_DIR','DOCKER_HOST','DOCKER_CONTEXT')}
    runner=runtime.Runner(4800,env,out/'logs')
    token=uuid.uuid4().hex[:16];provision='perl13-provision-'+token;image='cachy-asahi-perl13:'+token
    items=[dict(name=f'perl13-build-{token}-{i}',init=f'perl13-init-{token}-{i}',volume=f'perl13-work-{token}-{i}') for i in (1,2)]
    report=dict(schema=1,status='HOLD',inputs=PINS,operations=[],capacity=[],builds=[],retired=[],cleanup=[],
        controller_files={name:old.identity(HERE/name) for name in ('run.py','build.sh','inputs.json','test_driver.py')},
        planned_resources=dict(provision=provision,image=image,builds=items),
        limits=['host x86_64 only; native ARM/16K/M2 NOT RUN','No installation, external XS, performance, legal-policy or release acceptance'])
    def save():(out/'report.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    def command(argv,timeout=60,check=True):
        save()
        try:result=runner.run(argv,timeout=timeout,log=f'{len(report["operations"]):02d}.log')
        except BaseException as error:
            report['operations'].append(dict(argv=argv,failure=type(error).__name__+': '+str(error)));save();raise
        report['operations'].append(dict(argv=argv,returncode=result.returncode));save()
        need(not check or result.returncode==0,'command failed; see retained operations')
        return result
    def admission(phase,**kwargs):
        row=guard(docker_root,out,phase,**kwargs);report['capacity'].append(row);save()
        need(row['status']=='PASS','capacity admission refused: '+phase)
    def absence(command,containers,volumes,images=()):
        for kind,names,argv in [('containers',containers,['docker','container','ls','--all','--format','{{.Names}}']),
                ('volumes',volumes,['docker','volume','ls','--quiet']),
                ('images',images,['docker','image','ls','--format','{{.Repository}}:{{.Tag}}'])]:
            if not names:continue
            result=command(argv);need(result.returncode==0 and not set(names)&set(result.stdout.decode().splitlines()),'owned '+kind+' remain or absence observation failed')
    def retire(item):
        for key in ('name','init'):command(['docker','rm','-f',item[key]])
        command(['docker','volume','rm',item['volume']])
        absence(command,[item['name'],item['init']],[item['volume']])
        report['retired'].append(item);save()
    started=False;cancelled=False
    try:
        with runtime.cancellation_handlers():
            endpoint=env.get('DOCKER_HOST') if env.get('DOCKER_HOST') and not env.get('DOCKER_CONTEXT') else json.loads(command(['docker','context','inspect','--format','{{json .Endpoints.docker.Host}}']).stdout)
            need(endpoint.startswith('unix:///') and stat.S_ISSOCK(Path(endpoint[7:]).stat().st_mode),'local Unix Docker endpoint required for local capacity accounting')
            report['docker_endpoint']=endpoint
            docker_root=Path(command(['docker','info','--format','{{.DockerRootDir}}']).stdout.decode().strip())
            need(docker_root.is_absolute() and docker_root.is_dir(),'observable local Docker root required')
            report['docker_root']=str(docker_root)
            admission('whole-pair-before-input-allocation')
            if args.capacity_only:
                report['status']='PASS_CAPACITY_ONLY_NO_ACTORS'
                raise CapacityOnlyComplete()
            snapshot=out/'inputs';(snapshot/'recipe').mkdir(parents=True)
            for name in PINS['files']:shutil.copyfile(recipe/name,snapshot/'recipe'/name)
            shutil.copyfile(args.source,snapshot/PINS['source']['name'])
            for name in ('provenance.py','staged_smoke.pl'):shutil.copyfile(OLD/name,snapshot/name)
            shutil.copyfile(HERE/'build.sh',snapshot/'build.sh')
            for p in snapshot.rglob('*'):
                if p.is_file():p.chmod(0o444)
            verify(snapshot/'recipe',snapshot/PINS['source']['name'])
            row=json.loads(command(['docker','image','inspect',old.BASE]).stdout)[0]
            need(row['Id']=='sha256:'+old.BASE.split('sha256:')[1] and row['Architecture']=='amd64','exact cached official base required')
            admission('before-provision',inputs=True);started=True
            command(['docker','create','--name',provision,*old.LIMITS,'--network=host','--mount',f'type=bind,src={OLD},dst=/driver,readonly','--entrypoint=/usr/bin/bash',old.BASE,'/driver/provision.sh'])
            command(['docker','start','--attach',provision],timeout=900)
            admission('before-image-commit',committing=True,inputs=True)
            image_id=command(['docker','commit',provision,image],timeout=120).stdout.decode().strip();report['provisioned_image']=image_id
            command(['docker','rm',provision])
            for index,item in enumerate(items,1):
                need(len(report['retired'])==index-1,'previous work volume must be retired before allocation')
                admission(f'before-volume-{index}',prepared=True,inputs=True,exports=3-index)
                command(['docker','volume','create',item['volume']])
                command(['docker','create','--name',item['init'],*old.LIMITS,'--network=none','--read-only','--cap-drop=ALL','--cap-add=CHOWN','--security-opt=no-new-privileges','--mount',f'type=volume,src={item["volume"]},dst=/work','--entrypoint=/usr/bin/chown',image,'1000:1000','/work'])
                command(['docker','start','--attach',item['init']])
                admission(f'before-actor-{index}',prepared=True,inputs=True,exports=3-index)
                command(old.build_options(item['name'],image,item['volume'],snapshot))
                details=json.loads(command(['docker','inspect',item['name']]).stdout)[0]
                actor=old.validate_actor(details,image_id,item['volume'],snapshot)
                (out/f'actor-{index}.json').write_text(json.dumps(details,indent=2)+'\n')
                result=command(['docker','start','--attach',item['name']],timeout=1500,check=False)
                admission(f'before-export-{index}',prepared=True,work=True,inputs=True,exports=3-index)
                export=out/f'build-{index}';command(['docker','cp',item['name']+':/work/output',str(export)],timeout=120)
                need(result.returncode==0,'full dependency-checked recipe failed')
                record=dict(actor=actor,returncode=result.returncode,**check_export(export));report['builds'].append(record);save()
                verify(recipe,args.source)
                # Accepted export and its complete identities are durable before retirement.
                retire(item)
            report['comparison']=compare(out/'build-1',out/'build-2')
            matched=report['comparison']['archive_bytes_equal'] and report['comparison']['all_payload_entries_equal']
            report['status']='PASS_HOST_PAIR_BYTE_IDENTICAL' if matched else 'HOLD_HOST_PAIR_DIFFERENT'
    except CapacityOnlyComplete:pass
    except BaseException as error:
        cancelled=isinstance(error,runtime.Cancelled);report['failure']=type(error).__name__+': '+str(error)
        report['status']='CANCELLED' if cancelled else 'HOLD_CAPACITY' if report['capacity'] and report['capacity'][-1]['status']=='HOLD_CAPACITY' else 'HOLD_BUILD_FAILED'
    finally:
        if started:
            harvest=runtime.Runner(60,env,out/'logs');report['partial_logs']=[]
            with runtime.defer_signals():
                for index,item in enumerate(items,1):
                    if item in report['retired']:continue
                    try:
                        observed=harvest.run(['docker','inspect',item['name']],timeout=5)
                        if observed.returncode:continue
                        result=harvest.run(['docker','stop','--time=1',item['name']],timeout=5)
                        need(result.returncode==0,'owned actor stop failed')
                        s=os.statvfs(out)
                        need(s.f_bavail*s.f_frsize>=1056*MIB,'partial log harvest requires 32 MiB plus 1 GiB reserve')
                        target=f'partial-build-{index}.tar'
                        result=harvest.run(['docker','cp',item['name']+':/work/output/makepkg.log','-'],timeout=20,limit=8*MIB,log=target)
                        report['partial_logs'].append(dict(build=index,returncode=result.returncode,tar_data_only=target,identity=old.identity(out/'logs'/target)))
                    except BaseException as error:report['partial_logs'].append(dict(build=index,error=str(error),note='bounded DATA log may be truncated; never accepted as build output'))
            cleanup=runtime.Runner(180,env,out/'logs')
            with runtime.defer_signals():
                actions=[['docker','rm','-f',i[k]] for i in reversed(items) for k in ('name','init')]
                actions+=[['docker','rm','-f',provision]]+[['docker','volume','rm',i['volume']] for i in items]+[['docker','image','rm',image]]
                for argv in actions:
                    try:
                        result=cleanup.run(argv,timeout=20);body=result.stdout.decode(errors='replace')
                        report['cleanup'].append(dict(argv=argv,returncode=result.returncode,absent=old.cleanup_absent(argv,body),output=body[-2048:]))
                    except BaseException as error:report['cleanup'].append(dict(argv=argv,error=str(error)))
                try:
                    absence(lambda argv:cleanup.run(argv,timeout=15),
                        [provision]+[i[k] for i in items for k in ('name','init')],
                        [i['volume'] for i in items],[image])
                    report['owned_resources_absence_verified']=True
                except BaseException as error:
                    report['owned_resources_absence_verified']=False
                    report['cleanup'].append(dict(error='absence observation: '+str(error)))
                if any(r.get('returncode')!=0 and not r.get('absent') for r in report['cleanup']):report['status']='HOLD_OWNED_CLEANUP'
        try:verify(recipe,args.source);report['original_inputs_unchanged']=True
        except BaseException as error:report.update(status='HOLD_INPUTS_CHANGED',input_failure=str(error))
        save()
    print(report['status'])
    return 130 if cancelled else 0 if report['status'] in ('PASS_HOST_PAIR_BYTE_IDENTICAL','PASS_CAPACITY_ONLY_NO_ACTORS') else 2


if __name__=='__main__':raise SystemExit(main())

#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Proposed finite clean ARM pair; only independently Root-qualified operands run."""
import argparse
import importlib.util
import os
import resource
from pathlib import Path
import shutil
import stat
import subprocess
import time
import uuid

ROOT=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('perl_producer_common',ROOT/'common.py')
common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)


def options(item,image,inputs,c):
    return ['/usr/bin/docker','--host=unix:///var/run/docker.sock','create','--name',item['name'],
        '--label','cachy-asahi.operation='+c['operation'],'--cpus=2','--memory=4g','--memory-swap=4g','--pids-limit=256',
        '--init','--read-only','--network=none','--hostname=perl5423-native','--cap-drop=ALL','--security-opt=no-new-privileges',
        '--user=1001:1001','--ulimit=nofile=1024:1024','--ulimit=core=0:0',
        *['--tmpfs='+name+':'+value for name,value in c['domain']['tmpfs'].items()],
        '--mount',f'type=volume,src={item["volume"]},dst=/work',
        '--mount',f'type=bind,src={inputs},dst=/inputs,readonly',
        '--env','ADAPTER_ADMISSION_SHA256='+item['admission_sha256'],
        '--entrypoint=/usr/bin/bash',image,'--noprofile','--norc','/inputs/entry.sh']


def image_identity(row,expected):
    common.need(row['Id']==expected and row['Architecture']=='arm64' and row['Os']=='linux' and
        not row.get('Config',{}).get('Volumes'),'actual native image identity/no inherited anonymous volumes')


def _run(args,cancelled):
    c=common.decode(common.read(ROOT/'contract.json'))
    ar=common.read(args.admission);qr=common.read(args.qualification)
    common.need(common.pin(ar)['sha256']==args.admission_sha256 and common.pin(qr)['sha256']==args.qualification_sha256,'external Root operand hashes')
    a,q=common.decode(ar),common.decode(qr)
    common.need(common.encode(a)==ar and common.encode(q)==qr,'canonical Root admission/qualification DATA required')
    common.need(a['qualification_sha256']==args.qualification_sha256,'Root qualification binding')
    common.admission(a,q,c);source_map=common.source(ROOT,a['source_map_sha256'])
    diagnostic=common.diagnostic(q,getattr(args,'nested_namespace_diagnostic',None))
    out=common.path(args.output)
    common.need(not out.exists() and not out.is_relative_to(ROOT) and not ROOT.is_relative_to(out),'fresh disjoint output')
    common.need(out.parent.stat().st_uid==os.getuid() and not stat.S_IMODE(out.parent.stat().st_mode)&0o022,'owned private output parent')
    out.mkdir(mode=0o700);(out/'logs').mkdir(mode=0o700)
    owned=common.helper('owned_child.py');deadline=time.monotonic()+c['resources']['pair_seconds'];cleanup_deadline=None;monitor=None
    token='perl-native-'+a['run']+'-'+uuid.uuid4().hex[:12]
    items=[dict(name=token+'-'+str(i),init=token+'-init-'+str(i),volume=token+'-work-'+str(i),admission_sha256=args.admission_sha256) for i in (1,2)]
    report=dict(schema=1,status='FAIL_NATIVE_PAIR',native_acceptance=False,admission_sha256=args.admission_sha256,qualification_sha256=args.qualification_sha256,domain_sha256=c['domain_sha256'],source_map_sha256=a['source_map_sha256'],operations=[],builds=[],retired=[],cleanup=[],planned=items,capacity=[])
    def save():(out/'report.json').write_bytes(common.encode(report))
    def command(argv,seconds=30,check=True,cleanup=False,data_file=None):
        if not cleanup:common.check_cancelled(cancelled)
        now=time.monotonic();end=cleanup_deadline if cleanup else deadline-c['resources']['cleanup_seconds']
        cap=min(seconds,end-now);common.need(cap>2,'finite pair/cleanup deadline before command')
        row=dict(argv=argv,log=f'logs/{len(report["operations"]):03d}.log',success=False);lifecycle={};result=None
        if data_file is not None:row['stdout']=data_file
        def tick():
            if not cleanup:common.check_cancelled(cancelled)
            if monitor is not None and (argv[2]=='cp' or argv[2:4]==['start','--attach']):monitor()
        try:
            with (out/row['log']).open('xb') as log:
                if data_file is None:
                    result=owned.run(argv,timeout=cap,cwd=out,env=dict(PATH='/usr/bin',HOME=str(out),LC_ALL='C',TZ='UTC'),stdout=log,stderr=subprocess.STDOUT,lifecycle=lifecycle,stdout_limit=8*1024**2,on_tick=tick)
                else:
                    # Scoped soft FSIZE is inherited by the owned CLI; unlike
                    # polling stdout size it prevents writing beyond the tar cap.
                    previous=resource.getrlimit(resource.RLIMIT_FSIZE)
                    bound=min([c['resources']['export_tar_bytes']]+[value for value in previous if value!=resource.RLIM_INFINITY])
                    common.need(bound>0,'existing file-size resource budget unavailable')
                    try:
                        resource.setrlimit(resource.RLIMIT_FSIZE,(bound,previous[1]))
                        with (out/data_file).open('xb') as stream:
                            result=owned.run(argv,timeout=cap,cwd=out,env=dict(PATH='/usr/bin',HOME=str(out),LC_ALL='C',TZ='UTC'),stdout=stream,stderr=log,lifecycle=lifecycle,stdout_limit=bound,stderr_limit=8*1024**2,on_tick=tick)
                    finally:
                        resource.setrlimit(resource.RLIMIT_FSIZE,previous)
                        restored=resource.getrlimit(resource.RLIMIT_FSIZE)
                        row['fsize']=dict(before=list(previous),inherited_soft=bound,after=list(restored))
                        common.need(restored==previous,'file-size limit restoration failed')
                    row['stdout_pin']=common.pin(common.read(out/data_file,bound))
            if not cleanup:common.check_cancelled(cancelled)
            row.update(returncode=result.returncode,lifecycle=lifecycle)
            common.need(common.natural(lifecycle,zero=False) and lifecycle['exit']==result.returncode and (not check or result.returncode==0),'command failure or uncertain/forced retirement')
            row['success']=True
        finally:
            row['lifecycle']=lifecycle;report['operations'].append(row);save()
        return common.read(out/row['log'],8*1024**2),row['log']
    docker=['/usr/bin/docker','--host=unix:///var/run/docker.sock']
    created=False
    try:
        image_raw,_=command(docker+['image','inspect',a['image']]);image=common.decode(image_raw)[0]
        image_identity(image,a['image'])
        (out/'image.json').write_bytes(image_raw)
        arch,_=command(docker+['info','--format','{{.Architecture}}'])
        common.need(arch.strip() in (b'arm64',b'aarch64'),'actual native daemon required')
        data_root,_=command(docker+['info','--format','{{.DockerRootDir}}']);docker_root=common.path(data_root.decode().strip())
        def capacity(phase,work=True,exports=2,inputs=True):
            # The signed image already belongs to Root's admitted bootstrap.
            # Reserve only remaining adapter allocations, never relabel image
            # preparation as bounded by this actor contract.
            demands=[(docker_root,(2*1024**3 if work else 0)),(out,(64*1024**2 if inputs else 0)+exports*c['resources']['output_export_bytes'])]
            grouped={}
            for p,size in demands:
                info=os.statvfs(p);device=p.stat().st_dev
                d=grouped.setdefault(device,dict(paths=[],required_bytes=1024**3,available_bytes=info.f_bavail*info.f_frsize,available_inodes=info.f_favail,total_inodes=info.f_files))
                d['paths'].append(str(p));d['required_bytes']+=size;d['available_bytes']=min(d['available_bytes'],info.f_bavail*info.f_frsize);d['available_inodes']=min(d['available_inodes'],info.f_favail);d['total_inodes']=min(d['total_inodes'],info.f_files)
                # Unknown/dynamic pools need a separate proven model; no zero acceptance.
                common.need(info.f_files>0 and 0<info.f_favail<=info.f_files,'fixed inode capacity unavailable; separate filesystem qualification required')
                common.need(info.f_favail>=120000,'future source/work/export inode reserve')
            memory=int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemAvailable:')))*1024
            record=dict(phase=phase,filesystems=grouped,MemAvailable_bytes=memory,status='PASS')
            if not all(d['available_bytes']>=d['required_bytes'] for d in grouped.values()) or memory<8*1024**3:record['status']='HOLD_CAPACITY'
            report['capacity'].append(record);save();common.need(record['status']=='PASS','native pair capacity refused')
        initial_containers,clog=command(docker+['container','ls','--all','--format','{{.Names}}'])
        initial_volumes,vlog=command(docker+['volume','ls','--quiet'])
        common.need(not {x[k] for x in items for k in ('name','init')}&set(initial_containers.decode().splitlines()) and not {x['volume'] for x in items}&set(initial_volumes.decode().splitlines()),'planned resources already exist')
        (out/'initial-containers.txt').write_bytes(initial_containers);(out/'initial-volumes.txt').write_bytes(initial_volumes)
        report['initial_container_log']=clog;report['initial_volume_log']=vlog
        last_watch=[0.0]
        report['active_reserve']=dict(samples=0,minimum_bytes={},minimum_MemAvailable_bytes=None)
        def watch():
            if time.monotonic()-last_watch[0]<1:return
            last_watch[0]=time.monotonic();record=report['active_reserve'];record['samples']+=1
            for p in (docker_root,out):
                v=os.statvfs(p);key=str(p.stat().st_dev);available=v.f_bavail*v.f_frsize
                record['minimum_bytes'][key]=min(record['minimum_bytes'].get(key,available),available)
                common.need(available>=1024**3,'active disk reserve exhausted')
            available=int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemAvailable:')))*1024
            record['minimum_MemAvailable_bytes']=min(record['minimum_MemAvailable_bytes'] or available,available)
            common.need(available>=4*1024**3,'active host memory reserve exhausted')
        monitor=watch
        capacity('before-input-snapshot')
        inputs=out/'inputs';inputs.mkdir(mode=0o755);report['inputs']=str(inputs)
        for name in ('common.py','runtime.py','entry.py','entry.sh','contract.json','helper-pins.json'):
            shutil.copyfile(ROOT/name,inputs/name)
        shutil.copytree(ROOT/'helpers',inputs/'helpers');shutil.copytree(ROOT/'packet/recipe',inputs/'recipe')
        shutil.copyfile(ROOT/'packet/sources'/c['source_name'],inputs/c['source_name'])
        shutil.copyfile(ROOT/'packet/packet-map.json',inputs/'packet-map.json')
        (inputs/'admission.json').write_bytes(ar);(inputs/'qualification.json').write_bytes(qr)
        if diagnostic is not None:(inputs/'nested-namespace-diagnostic.json').write_bytes(diagnostic)
        (inputs/'adapter-source-map.json').write_bytes(common.read(ROOT/'source-map.json'))
        for i,item in enumerate(items,1):
            common.need(len(report['retired'])==i-1,'previous volume retirement required')
            capacity(f'before-volume-{i}',exports=3-i,inputs=False);created=True
            command(docker+['volume','create',item['volume']])
            command(docker+['create','--name',item['init'],'--cpus=2','--memory=4g','--memory-swap=4g','--pids-limit=256','--network=none','--read-only','--user=0:0','--cap-drop=ALL','--cap-add=CHOWN','--security-opt=no-new-privileges','--mount',f'type=volume,src={item["volume"]},dst=/work','--entrypoint=/usr/bin/chown',a['image'],'1001:1001','/work'])
            command(docker+['start','--attach',item['init']])
            capacity(f'before-actor-{i}',exports=3-i,inputs=False)
            command(options(item,a['image'],inputs,c))
            inspect_raw,inspect_log=command(docker+['inspect',item['name']]);actor=common.decode(inspect_raw)[0]
            common.inspect_actor(actor,a['image'],item['volume'],inputs,c)
            (out/f'actor-{i}.json').write_bytes(common.encode(actor))
            started,error=None,None
            try:started,_=command(docker+['start','--attach',item['name']],seconds=c['resources']['build_seconds'])
            except BaseException as failure:error=failure
            if error is not None:
                command(docker+['stop','--time=1',item['name']],seconds=10,check=False)
            capacity(f'before-export-{i}',work=False,exports=3-i,inputs=False)
            data_file=f'export-{i}.tar'
            command(docker+['cp',item['name']+':/work/output','-'],seconds=120,data_file=data_file)
            exporter=common.load('perl_bounded_export',ROOT/'data_export.py')
            exported=exporter.parse(common.read(out/data_file,c['resources']['export_tar_bytes']))
            destination=out/f'build-{i}';destination.mkdir(mode=0o700)
            for name,(body,mode) in exported.items():
                with (destination/name).open('xb') as stream:stream.write(body)
                (destination/name).chmod(mode)
            if error is not None:raise error
            archive=common.read(out/f'build-{i}'/'perl-5.42.3-1.3-aarch64.pkg.tar.zst',c['resources']['archive_bytes'])
            report['builds'].append(dict(**item,inspect_log=inspect_log,archive=common.pin(archive)))
            for name in (item['name'],item['init']):command(docker+['rm',name])
            command(docker+['volume','rm',item['volume']])
            containers,clog=command(docker+['container','ls','--all','--format','{{.Names}}'])
            volumes,vlog=command(docker+['volume','ls','--quiet'])
            common.need(not {item['name'],item['init']}&set(containers.decode().splitlines()) and item['volume'] not in volumes.decode().splitlines(),'owned retirement absence unproven')
            report['retired'].append(dict(name=item['name'],init=item['init'],volume=item['volume'],container_list_log=clog,volume_list_log=vlog));save()
        common.need(report['builds'][0]['archive']==report['builds'][1]['archive'],'complete raw archives differ')
        report['status']='PASS_NATIVE_PAIR'
    except BaseException as error:report['failure']=type(error).__name__+': '+str(error)
    finally:
        cleanup_deadline=min(deadline,time.monotonic()+c['resources']['cleanup_seconds'])
        if created:
            for item in reversed(items):
                for argv in [docker+['rm','-f',item['name']],docker+['rm','-f',item['init']],docker+['volume','rm',item['volume']]]:
                    try:
                        raw,log=command(argv,check=False,cleanup=True)
                        code=report['operations'][-1]['returncode']
                        if code:
                            expected=('Error response from daemon: get '+argv[-1]+': no such volume') if argv[2:4]==['volume','rm'] else ('Error response from daemon: No such container: '+argv[-1])
                            common.need(code==1 and raw.decode().strip()==expected,'unexpected cleanup refusal')
                        report['cleanup'].append(dict(argv=argv,log=log,returncode=code))
                    except BaseException as error:report['cleanup'].append(dict(argv=argv,error=str(error)))
            try:
                raw,_=command(docker+['container','ls','--all','--format','{{.Names}}'],cleanup=True);(out/'final-containers.txt').write_bytes(raw)
                rawv,_=command(docker+['volume','ls','--quiet'],cleanup=True);(out/'final-volumes.txt').write_bytes(rawv)
                names={x[k] for x in items for k in ('name','init')};volumes={x['volume'] for x in items}
                common.need(not names&set(raw.decode().splitlines()) and not volumes&set(rawv.decode().splitlines()),'owned final resources remain')
                report['owned_resources_absence_verified']=True
            except BaseException as error:report.update(status='FAIL_NATIVE_PAIR',cleanup_failure=str(error))
        if any('error' in row for row in report['cleanup']):report['status']='FAIL_NATIVE_PAIR'
        if len(report['builds'])!=2 or len(report['retired'])!=2 or not report.get('owned_resources_absence_verified'):report['status']='FAIL_NATIVE_PAIR'
        if cancelled[0]:report.update(status='FAIL_NATIVE_PAIR',cancelled=True)
        save()
    return 0 if report['status']=='PASS_NATIVE_PAIR' else 2


def run(args):
    with common.cancellation_scope() as cancelled:return _run(args,cancelled)


if __name__=='__main__':
    import sys
    common.need(sys.flags.isolated and not sys.flags.optimize,'isolated unoptimized Root entry required')
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('admission','admission-sha256','qualification','qualification-sha256','output'):p.add_argument('--'+name,required=True)
    p.add_argument('--nested-namespace-diagnostic')
    raise SystemExit(run(p.parse_args()))

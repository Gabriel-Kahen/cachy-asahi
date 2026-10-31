#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Owned disk-backed16K consumer of an existing original574 owner's snapshot."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import signal
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as C
import adapter

def qemu(kernel,boot,volume):
    # Same disk-backed direct kernel boot as the full installer VM. This lane
    # supplies an actual verified16K Image and a separate disposable data disk.
    return ['/usr/bin/qemu-system-aarch64','-nodefaults','-machine','virt','-accel','tcg,thread=multi','-cpu','max','-smp','2','-m','4096','-nic','none','-display','none','-monitor','none','-no-reboot',
        '-kernel',str(kernel),'-append','console=ttyAMA0 root=/dev/vda ro rootwait init=/init-installed16k caa_gnu_installed16k=1',
        '-drive','if=none,id=boot,format=raw,readonly=on,file='+str(boot),'-device','virtio-blk-pci,drive=boot',
        '-drive','if=none,id=volume,format=raw,file='+str(volume),'-device','virtio-blk-pci,drive=volume','-serial','stdio']

def protocol(raw,selection):
    C.need(len(raw)<=16*1024**2,'UART bound')
    prefix=('GNU_INSTALLED16K '+selection['nonce']+' ').encode()
    lines=[line.rstrip(b'\r') for line in raw.splitlines() if line.startswith(b'GNU_INSTALLED16K ')]
    C.need(len(lines)==3 and all(line.startswith(prefix) for line in lines),'complete nonce-bound VM protocol')
    events=[C.decode(line[len(prefix):]) for line in lines]
    C.need([r['event'] for r in events]==['boot','result','exit'],'ordered three events only')
    boot,result,exit=events
    nofile=boot.pop('observer_nofile',None);C.need(type(nofile) is dict and set(nofile)=={'before','after','scope'} and type(nofile['before']) is list and len(nofile['before'])==2 and all(type(n) is int and 0<n<=2**31-1 for n in nofile['before']) and nofile['before'][0]<=nofile['before'][1] and nofile['after']==[8192,8192] and all(type(n) is int for n in nofile['after']) and nofile['scope']=='NATIVE_TRIAL_8192_BOTH_INHERITED_BY_LIFECYCLE_CHILD','exact inherited observer8192 readback')
    C.need(boot==dict(event='boot',page_size=16384,kernel=selection['kernel']['release'],architecture='aarch64',kernel_profile_sha256=selection['kernel_profile_sha256']),'actual kernel/profile join')
    C.need(result['status']==C.PASS and result['page_size']==16384 and result['normal_runtime_observations']==8 and result['hardware']=='NOT_RUN' and result['release']=='NOT_ADMITTED' and result['source_nodes_sha256']==selection['source_nodes_sha256'],'actual complete lifecycle result required')
    C.need(exit==dict(event='exit',status=C.PASS,cleanup='PASS_OWNED_CLONES_REMOVED'),'guest clone retirement required')
    C.need(result['capabilities']['status']=='EXACT_SOURCE_MAP_PRESERVED' and result['capabilities']['cases']==2 and result['capabilities']['stages']==8 and result['capabilities']['source_capabilities_sha256']==selection['capabilities_sha256'],'exact16 capability observations required')
    isolation=result['isolation'];C.need(isolation['status']=='PASS_OBSERVED_NATIVE_CAPS_AND_MOUNT_FENCE' and isolation['mask']==2149843195 and isolation['no_new_privs']==1 and isolation['seccomp']==2 and isolation['raw_block_devices']==[] and isolation['writable_source_alias'] is False and isolation['mount_flags']==[15,4096],'actual bounded child authority required')
    files=result['files'];C.need(type(files) is dict and len(files)<=256 and result['bytes']==sum(r['bytes'] for r in files.values())<=512*1024**2,'bounded complete evidence manifest')
    C.need('result.json' in files and sum(n.endswith('-root.json.gz') for n in files)==16,'all16 complete root snapshots required')
    for name,row in files.items():
        C.need(re.fullmatch(r'(result\.json|isolation\.json|command-[0-9]{3}\.(stdout|stderr)|(pristine|modified)-[a-z0-9-]+(-root\.json\.gz|\.log))',name) and set(row)=={'bytes','sha256'} and type(row['bytes']) is int and 0<=row['bytes']<=64*1024**2 and re.fullmatch('[0-9a-f]{64}',row['sha256']),'closed bounded evidence file')
    return result

def execute(args):
    accepted=C.gate(args.acceptances)  # BEFORE output creation, native credentials or actors.
    C.check_source(args.workspace)
    C.need(os.getuid()==os.geteuid()>0 and os.uname().machine=='aarch64' and os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_ARCH')=='ARM64','ordinary native ARM disposable CI only')
    C.need(not any(k.startswith(('DOCKER_','LD_')) for k in os.environ),'daemon/loader overrides refused')
    for path in (args.workspace,args.owner,args.base,args.kernel_work,args.acceptances,args.output.parent):
        C.need(path.is_absolute() and path.is_dir() and not any(p.is_symlink() for p in (path,*path.parents)) and ',' not in str(path),'ordinary explicit paths required')
    C.need(args.output.parent==Path('/tmp') and not args.output.exists() and not any(args.output.is_relative_to(p) or p.is_relative_to(args.output) for p in (args.owner,args.workspace,args.base,args.kernel_work,args.acceptances)),'fresh separate direct/tmp consumer output')
    owner=C.decode(C.read(args.owner/'owner.json'));base=C.decode(C.read(args.base/'report.json'))
    C.need(owner['status']=='PASS_LIFECYCLE_PENDING_ORDERED_PRODUCER_CLEANUP' and owner['image']==base['image'] and owner['producer_token']==base['ownership']['token'],'live owned original574 snapshot handoff after native controls')
    C.need(shutil.disk_usage(args.output.parent).free>=48*C.GIB,'48GiB root/disk/evidence reserve required')
    source=args.workspace;runner=args.owner/'lifecycle-runner';inputs=args.owner/'inputs';held=args.owner/'data/original574'
    native=C.load('native_configuration',runner/'common.py');index,_,_,_=native.configuration(inputs,C.row(inputs/'lifecycle-input.json')['sha256']);native.helpers(source)
    C.need(index['source_nodes_sha256']==owner['source_snapshot']['observation']['node_sha256'] and index['image_id']==owner['image'],'exact current complete source snapshot/input join')
    helper=C.load('kernel_helper',source/'scripts/ci/managed-gui-generic16k/build_kernel.py');K=C.load('kernel_contract',source/'scripts/ci/managed-gui-generic16k/kernel_contract.py')
    receipt=C.decode(C.read(args.kernel_receipt,65536))
    for name in ('helper','fragment','image','config'):
        path=Path(receipt[name]['path']);C.need(path.is_relative_to(args.kernel_work) and not any(p.is_symlink() for p in (path,*path.parents)),'owned kernel input paths required')
    fragment=C.read(source/'scripts/ci/managed-gui-generic16k/kernel.fragment')
    profile,image,config=K.from_receipt(receipt,helper,fragment,C.row(source/'scripts/ci/managed-gui-generic16k/build_kernel.py')['sha256'],C.sha(fragment))
    C.need(C.row(Path(receipt['helper']['path']))['sha256']==profile['helper_sha256'] and C.row(Path(receipt['fragment']['path']))['sha256']==profile['fragment_sha256'],'actual copied kernel source differs')
    text,derivation=adapter.derive(source)
    # Hold the existing producer directory lease through ALL VM/consumer teardown.
    lease=os.open(args.base,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
    args.output.mkdir(mode=0o700);out=args.output;disks=out/'disks';disks.mkdir();public=out/'public';public.mkdir()
    selection=dict(source_sha=owner['source_sha'],nonce=os.urandom(16).hex(),kernel=profile,kernel_profile_sha256=C.sha((json.dumps(profile,sort_keys=True,indent=2)+'\n').encode()),input_index_sha256=C.row(inputs/'lifecycle-input.json')['sha256'],adapter_sha256=C.sha(text.encode()),source_nodes_sha256=index['source_nodes_sha256'],capabilities_sha256=index['source_capabilities_sha256'])
    C.need(re.fullmatch('[0-9a-f]{40}',selection['source_sha']) and selection['source_sha']==os.environ['SOURCE_SHA']==os.environ['WORKFLOW_SHA'],'exact progress source/workflow identity')
    C.save(out/'selection.json',selection);C.save(public/'kernel-profile.json',profile);C.save(public/'kernel-receipt.json',receipt);C.save(public/'adapter.json',derivation)
    shutil.copyfile(image,out/'Image');C.need(C.row(out/'Image')==profile['Image'],'actual copied16K Image differs')
    runtime=C.load('process_runtime',source/'scripts/ci/glibc-owned-runtime/runner.py')
    report=dict(status='FAIL',source_sha=selection['source_sha'],output_uid=os.getuid(),output_gid=os.getgid(),token=selection['nonce'],image=index['image_id'],actors=[],commands=[],prerequisites=accepted,hardware='NOT_RUN',release='NOT_ADMITTED',producer_cleanup='BORROWED_NOT_ATTEMPTED',kernel_cleanup='BORROWED_NOT_ATTEMPTED')
    def save():C.save(out/'owner.json',report)
    def command(argv,seconds=30,cap=2*1024**2,allow_failure=False):
        row,stdout,stderr,error=runtime.run_command(argv,out,dict(native.ENV,HOME=str(out),TMPDIR=str(out)),seconds,cap)
        number=len(report['commands']);report['commands'].append(row);save()
        (public/('owner-command-%03d.stdout'%number)).write_bytes(stdout);(public/('owner-command-%03d.stderr'%number)).write_bytes(stderr)
        if error:raise error
        C.need(row['group_absence_verified'] and (allow_failure or row['exit_code']==0),'owned command exit/group absence')
        return row,stdout,stderr
    def inspect(name):
        row,stdout,stderr=command(['/usr/bin/docker','container','inspect',name],allow_failure=True)
        if row['exit_code']:
            message=(stdout+stderr).decode(errors='replace').lower();C.need(row['exit_code']==1 and name in message and ('no such object' in message or 'no such container' in message),'container absence unknown');return None
        values=C.decode(stdout);C.need(len(values)==1,'exact one container identity');return values[0]
    def owned(value,actor):
        C.need(value['Name']=='/'+actor['name'] and value['Image']==index['image_id'] and value['Config']['Labels'].get(C.LABEL)==selection['nonce'] and actor['id'] in (None,value['Id']),'foreign actor preserved');return value['Id']
    def actor(role,script,target):
        name='caa-gnu-installed16k-'+selection['nonce']+'-'+role;C.need(inspect(name) is None,'fresh actor name')
        row=dict(name=name,id=None,status='RESERVED');report['actors'].append(row);save()
        argv=['/usr/bin/docker','run','--name',name,'--label',C.LABEL+'='+selection['nonce'],'--pull=never','--platform=linux/arm64','--network=none','--read-only',('--user='+str(os.getuid())+':'+str(os.getgid()) if role=='export' else '--user=0:0'),'--cap-drop=ALL','--security-opt=no-new-privileges','--pids-limit=128','--memory=4g','--cpus=2','--tmpfs=/tmp:rw,nosuid,nodev,size=256m']
        if role in ('prepare','scrub'):argv+=['--cap-add='+n for n in ('CHOWN','DAC_OVERRIDE','FOWNER','FSETID','SETFCAP')]
        argv+=['--env=CAA_INSTALLED16K_PREPARE=1','--env=PYTHONDONTWRITEBYTECODE=1','--env=INPUT_INDEX_SHA256='+selection['input_index_sha256'],'--env=OUTPUT_UID='+str(os.getuid()),'--env=OUTPUT_GID='+str(os.getgid())]
        mounts=[(held,'/held',True),(source,'/source',True),(inputs,'/inputs',True),(runner,'/runner',True),(C.HERE,'/installed16k',True),(out,'/selection',True),(target,'/out',False)]
        if role=='export':mounts.append((disks,'/disks',True))
        for path,dest,ro in mounts:argv+=['--mount','type=bind,src='+str(path)+',dst='+dest+(',readonly' if ro else '')]
        argv+=['--entrypoint=/usr/bin/python3',index['image_id'],'-I','-B','/installed16k/'+script]
        result=command(argv,seconds=2400,allow_failure=True);observed=inspect(name);C.need(observed is not None,'retained actor identity');row.update(id=owned(observed,row),status='EXITED');save();C.need(result[0]['exit_code']==0,'owned '+role+' failed')
    def retire():
        for item in reversed(report['actors']):
            if item['status']=='PASS_ABSENCE_VERIFIED':continue
            value=inspect(item['name'])
            if value is not None:command(['/usr/bin/docker','rm','--force',owned(value,item)])
            C.need(inspect(item['name']) is None,'owned container remains');item['status']='PASS_ABSENCE_VERIFIED';save()
    error=None
    try:
        save();actor('prepare','prepare.py',disks)
        prepared=C.decode(C.read(disks/'prepared.json'));C.need(prepared['status']=='PREPARED_FULL574_DISKS_NOT_EXECUTED' and prepared['base_packages']==574 and prepared['adapter']==derivation,'complete source disk preparation required')
        for name in ('boot','volume'):C.need(C.row(disks/(name+'.raw'))==prepared[name],'sealed disk bytes differ')
        row,uart,_=command(qemu(out/'Image',disks/'boot.raw',disks/'volume.raw'),seconds=10800,cap=16*1024**2)
        report['guest']=protocol(uart,selection);C.save(out/'guest-files.json',report['guest']['files'])
        actor('export','export.py',public)
        for name,pin in report['guest']['files'].items():C.ref(public,dict(path='guest/'+name,**pin),64*1024**2)
        report['status']='PASS_VM_AWAITING_CONSUMER_TEARDOWN'
    except BaseException as caught:error=caught;report.update(error_type=type(caught).__name__,error=str(caught)[:1024])
    finally:
        try:
            retire()
            C.need(all(r['group_absence_verified'] for r in report['commands']),'unknown child group; backing data preserved')
            if error is not None and (disks/'volume.raw').is_file():
                qemus=[(n,r) for n,r in enumerate(report['commands']) if r['argv'][0]=='/usr/bin/qemu-system-aarch64']
                if len(qemus)==1 and qemus[0][1]['group_absence_verified'] is True:
                    C.save(out/'failure-diagnostics.json',dict(status='FIXED_READONLY_DIAGNOSTICS_AFTER_QEMU_ABSENCE',nonce=selection['nonce'],source_sha=selection['source_sha'],qemu_command_index=qemus[0][0]))
                    try:actor('export','export.py',public)
                    except BaseException as caught:report['failure_diagnostic_error_type']=type(caught).__name__
                    finally:retire()
                    C.need(all(r['group_absence_verified'] for r in report['commands']),'diagnostic child group unknown; disks preserved')
            if (disks/'stage').exists() or (disks/'stage').is_symlink():
                actor('scrub','scrub.py',disks);retire()
            C.need(not (disks/'stage').exists() and not (disks/'stage').is_symlink(),'private preparation roots remain')
            # No privileged mounted host filesystems exist; only owned disk files.
            for path in (disks/'boot.raw',disks/'volume.raw',out/'Image'):
                if path.exists():C.need(path.is_file() and not path.is_symlink(),'ordinary owned disk cleanup');path.unlink()
            report['consumer_cleanup']='PASS_ALL_ACTORS_GROUPS_AND_DISKS_REMOVED'
            if error is None:report['status']=C.PASS
        except BaseException as caught:report.update(cleanup_error=str(caught)[:512])
        save();C.save(public/'owner.json',report)
        try:
            retained={};total=0
            for path in sorted(public.rglob('*')):
                if path.is_dir() and not path.is_symlink():continue
                name=path.relative_to(public).as_posix();C.read(path,64*1024**2);pin=C.row(path);total+=pin['bytes'];retained[name]=pin
                C.need(len(retained)<=320 and total<=544*1024**2,'aggregate public evidence bound')
            C.save(public/'retention.json',dict(status='BOUNDED_SOURCE_DERIVED_METADATA_AND_LOGS_ONLY',owner_status=report['status'],files=retained,bytes=total,source_payload='NOT_EXPORTED',disk_images='NOT_EXPORTED',hardware='NOT_RUN',release='NOT_ADMITTED'))
        except BaseException as caught:
            report.update(status='FAIL',retention_error=str(caught)[:512]);save();C.save(public/'owner.json',report)
        os.close(lease)
    return int(report['status']!=C.PASS)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode',choices=('preflight','run'))
    for name in ('workspace','acceptances','owner','base','kernel-work','kernel-receipt','output'):p.add_argument('--'+name,type=Path,required=name in ('workspace','acceptances'))
    args=p.parse_args();C.gate(args.acceptances);C.check_source(args.workspace)
    if args.mode=='preflight':return 0
    C.need(all(getattr(args,n.replace('-','_')) is not None for n in ('owner','base','kernel-work','kernel-receipt','output')),'explicit consumer paths required')
    return execute(args)

if __name__=='__main__':
    def cancel(*_):raise KeyboardInterrupt('installed16K coordinator cancelled')
    for sig in (signal.SIGTERM,signal.SIGINT):signal.signal(sig,cancel)
    raise SystemExit(main())

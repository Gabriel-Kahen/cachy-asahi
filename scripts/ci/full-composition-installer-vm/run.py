#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Owned, offline generic ARM VM route for the declared initial587 installer."""
import argparse
import hashlib
import importlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import time
import uuid

GIB=1024**3
MAX_UART=64*1024**2
MAX_EVENT=1024**2
EXPECTED_LOCK='2198942a546f4714587c810fe174d4457121960f3a7b1dbaa276e9f970f322c7'
BUILDER_LOCK='cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac'
PASS_FLAGS=('committed','namespace_barrier','payload_verified','ownership_verified','database_verified',
            'preservation_verified','private_trust_verified','parent_inventory_preserved',
            'source_cache_preserved','process_retirement','ordinary_parent_nnp_cap0',
            'numeric_namespace_verified','root_guest_payload_verified','parent_payload_verified','numeric_ownership_verified')


def need(ok, reason):
    if not ok: raise ValueError(reason)


def sha(path):
    with Path(path).open('rb') as stream: return hashlib.file_digest(stream,'sha256').hexdigest()


def save(path,value): Path(path).write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')


def selected_module(name,path):
    path=ordinary(path)
    spec=importlib.util.spec_from_file_location('_full_installer_vm_host_'+name,path)
    module=importlib.util.module_from_spec(spec)
    sys.modules[spec.name]=module
    spec.loader.exec_module(module)
    need(Path(module.__file__).resolve()==path.resolve(),'selected module origin differs')
    return module


def load_json(path):
    def pairs(rows):
        value={}
        for key,item in rows:
            need(key not in value,'duplicate JSON key'); value[key]=item
        return value
    def constant(value): raise ValueError('nonfinite JSON refused')
    return json.loads(Path(path).read_text(),object_pairs_hook=pairs,parse_constant=constant)


def relative(name):
    need(type(name) is str and name and '\\' not in name and
         all(x not in ('','.','..') for x in name.split('/')) and
         all(32<=ord(c)<127 for c in name),'unsafe relative path')
    return name


def ordinary(path,directory=False):
    path=Path(path)
    need(path.is_absolute() and all(not p.is_symlink() for p in (path,*path.parents)), 'ordinary absolute input required')
    need(path.is_dir() if directory else path.is_file(),'input missing')
    return path


def row(path): return {'sha256':sha(path),'bytes':path.stat().st_size}


def input_files(ready,manifest):
    need(manifest['schema_version']==1 and manifest['status']=='READY_SIGNED_INITIAL587' and
         len(manifest['packages'])==587 and len({r['name'] for r in manifest['packages']})==587,
         'actual signed full587 export required')
    pins={'manifest.json':row(ready/'manifest.json')}
    need(manifest['expected_lock']['sha256']==EXPECTED_LOCK and manifest['builder_lock']['sha256']==BUILDER_LOCK and
         manifest['preparation']['base_inventory_sha256']==BUILDER_LOCK,'held full composition lock selection differs')
    for selection in ('expected_lock','builder_lock'):
        item=manifest[selection]; name=relative(item['path'])
        path=ordinary(ready/name)
        need(sha(path)==item['sha256'],'producer lock differs')
        pins[name]=row(path)
    for item in manifest['keyrings']:
        pins[relative(item['path'])]={'sha256':item['sha256'],'bytes':item['size']}
    for item in manifest['packages']:
        for field,prefix in (('archive',''),('signature','signature_')):
            name=relative(item[field])
            need(name not in pins,'duplicate cache file')
            pins[name]={'sha256':item[prefix+'sha256'],'bytes':item[prefix+'size']}
    need(sum(r['bytes'] for r in pins.values())<=4*GIB+16*1024**2,'finite compressed input bound exceeded')
    for name,item in pins.items():
        path=ordinary(ready/name)
        need(path.stat().st_nlink==1 and row(path)==item,'input hash/size/link differs: '+name)
    return pins


def parse_protocol(data,nonce,complete=False):
    need(len(data)<=MAX_UART,'UART output bound exceeded')
    events=[]
    lines=data.splitlines(keepends=True)
    if lines and not lines[-1].endswith((b'\n',b'\r')):
        need(not complete or not lines[-1].startswith(b'FULL_INSTALLER '),'truncated final protocol line')
        lines=lines[:-1]
    for line in lines:
        line=line.rstrip(b'\r\n')
        if not line.startswith(b'FULL_INSTALLER '): continue
        parts=line.split(b' ',2)
        need(len(parts)==3 and parts[1].decode('ascii')==nonce and len(parts[2])<=MAX_EVENT,
             'protocol nonce/size differs')
        def pairs(rows):
            result={}
            for key,value in rows:
                need(key not in result,'duplicate event key'); result[key]=value
            return result
        event=json.loads(parts[2],object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite event'))
        need(type(event) is dict and event.get('event') in ('boot','result','exit'), 'closed VM event required')
        events.append(event)
    need(len(events)<=3 and [r['event'] for r in events]==['boot','result','exit'][:len(events)],
         'VM protocol ordering/duplicates differ')
    return events


def validate_completion(events,nonce,common,profile_sha256=None):
    need(len(events)==3,'complete VM result/exit protocol required')
    boot,result,exit_event=events
    need(type(boot.get('uid')) is int and type(boot.get('page_size')) is int and
         boot==dict(event='boot',scope='generic-arm-full-installer-software',
                   page_size=4096,kernel=common.KERNEL,uid=0),
         'generic4K boot identity differs')
    status='PASS_FULL_COMPOSITION_INSTALLER'
    need(result.get('status')==status and
         exit_event==dict(event='exit',status=status,cleanup='PASS'), 'guest installer failed/incomplete')
    need(all(result.get(key) is True for key in PASS_FLAGS) and result.get('phase')=='complete' and
         type(result.get('package_count')) is int and result['package_count']==587 and
         result.get('expected_lock_sha256')==EXPECTED_LOCK and
         result.get('hooks')==result.get('scriptlets')=='DISABLED' and
         result.get('hardware')=='NOT RUN' and result.get('native_container_P0')=='UNCHANGED-FAILED',
         'complete installer commit/payload/ownership/preservation/barrier proof required')
    if profile_sha256 is not None:
        need(result.get('profile_sha256')==profile_sha256 and result.get('nonce')==nonce,
             'installer result selected profile/nonce differs')
    return result


def qemu_argv(kernel,image):
    return ['/usr/bin/qemu-system-aarch64','-nodefaults','-machine','virt-11.1','-accel','tcg,thread=multi',
        '-cpu','max','-smp','2','-m','4096','-nic','none','-display','none','-monitor','none',
        '-audiodev','none,id=noaudio','-no-reboot','-kernel',str(kernel),
        '-append','console=ttyAMA0 root=/dev/vda rw rootwait systemd.unit=full-installer.target cachy_asahi_virtual_proof=1',
        '-drive','if=none,id=root,format=raw,snapshot=on,file='+str(image),
        '-device','virtio-blk-pci,drive=root','-serial','file:/out/serial.log']


def vm(sha256):
    sys.path.insert(0,'/runner/virtual')
    common=importlib.import_module('common')
    sys.path.insert(0,'/candidate')
    preparation=importlib.import_module('prepare')
    c,_=preparation.verify_contract(Path('/selection/vm-contract.json'),sha256,common,input_bytes=False)
    f=common.guard(preparation=False)
    need(f['nonce']==c['nonce'] and f['image_id']==c['active_image'],'VM active image binding differs')
    for mount in ('/code','/candidate','/selection','/tooling-cache','/prepared'):
        need('ro' in f['mounts'].get(mount,{}).get('flags',[]),'readonly VM input required')
    prepared=common.json_load('/prepared/disk.json')
    need(prepared['status']=='PREPARED' and prepared['nonce']==c['nonce'] and
         prepared['contract_sha256']==sha256 and
         prepared['package_inventory']==c['tooling_inventory'],'prepared disk receipt differs')
    kernel,image=Path('/prepared/prepared/Image'),Path('/prepared/prepared/guest.raw')
    need(common.digest(kernel)==common.IMAGE_SHA==prepared['kernel_sha256'] and
         common.digest(image)==prepared['guest_image_sha256'],'prepared kernel/disk differs')
    need(common.free_bytes('/out')>=12*GIB,'VM snapshot/target/evidence capacity below12GiB')
    checks=((['--version'],'version 11.1.2'),(['-machine','help'],'virt-11.1'),(['-accel','help'],'tcg'))
    for arguments,expected in checks:
        observed=common.bounded(['/usr/bin/qemu-system-aarch64',*arguments],timeout=15,limit=128*1024)
        need(observed['error'] is None and observed['returncode']==0 and expected in observed['stdout'],
             'held QEMU capability unavailable')
    report=dict(status='FAIL',nonce=c['nonce'],scope='generic4K-full587-installer-software-only',
                guest='NOT RUN',qemu_cleanup='UNKNOWN',hardware_validation='NOT RUN')
    owner=None; completed_at=None
    start=time.monotonic()
    def cancelled(*_): raise InterruptedError('VM owner cancelled')
    previous={sig:signal.signal(sig,cancelled) for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGALRM)}
    signal.setitimer(signal.ITIMER_REAL,5400)
    try:
        owner=common.LoggedProcess(qemu_argv(kernel,image),'/out/qemu.log',limit=MAX_UART,owner_signals_only=True,
                                   env=dict(os.environ,TMPDIR='/out'))
        while True:
            need(time.monotonic()-start<5400,'5400s VM deadline')
            need(owner.error is None,'QEMU log overflow/drain failure')
            serial=Path('/out/serial.log')
            if serial.exists():
                need(serial.stat().st_size<=MAX_UART,'UART output overflow')
                events=parse_protocol(serial.read_bytes(),c['nonce'])
                if len(events)==3 and completed_at is None: completed_at=time.monotonic()
            if completed_at is not None: need(time.monotonic()-completed_at<90,'guest natural poweroff deadline')
            terminal=common.terminal(owner.process)
            if terminal is not None:
                need(terminal.si_code==os.CLD_EXITED and terminal.si_status==0,'QEMU did not exit naturally with zero status')
                report['natural_exit']=True
                break
            time.sleep(.1)
        # Reserve through last kill, then verify the owned group disappeared.
        common.reap(owner.process,verify_absence=True); report['qemu_cleanup']='PASS'
        need(owner.process.returncode==0 and report.get('natural_exit') is True,'natural QEMU exit required')
        owner.thread.join(timeout=5)
        need(not owner.thread.is_alive() and owner.error is None,'QEMU log drain retirement failed')
        events=parse_protocol(Path('/out/serial.log').read_bytes(),c['nonce'],complete=True)
        report['guest']=validate_completion(events,c['nonce'],common,c['runner_files']['installer-profile.json']['sha256'])
        report['status']='PASS'
    except BaseException as error:
        report.update(status='FAIL',error_type=type(error).__name__,error=str(error)[:512])
        raise
    finally:
        signal.setitimer(signal.ITIMER_REAL,0)
        cleanup_error=None
        if owner is not None and owner.process.returncode is None:
            try:
                common.reap(owner.process,verify_absence=True)
                owner.thread.join(timeout=5)
                need(not owner.thread.is_alive(),'QEMU drain thread remains')
                report['qemu_cleanup']='PASS'
            except BaseException as error:
                report['qemu_cleanup']='FAIL'; report['status']='FAIL'; cleanup_error=error
        for sig,handler in previous.items(): signal.signal(sig,handler)
        report['elapsed_seconds']=round(time.monotonic()-start,3)
        save('/out/vm.json',report)
        if cleanup_error is not None: raise cleanup_error


def container_args(c,phase,image,mounts,output,name):
    args=['docker','create','--name',name,'--label','cachy-asahi.full-installer='+c['nonce'],
        '--network=none','--cap-drop=ALL','--security-opt=no-new-privileges',
        '--pids-limit=256','--cpus=2','--memory='+('6g' if phase=='vm' else '2g'),
        '--env=CACHY_ASAHI_DISPOSABLE_VIRTUAL=1','--env=CACHY_ASAHI_VIRTUAL_NONCE='+c['nonce'],
        '--env=CACHY_ASAHI_IMAGE_ID='+image]
    if phase=='vm': args+=['--user=23001:23001']
    else:
        for cap in ('CHOWN','DAC_OVERRIDE','FOWNER','FSETID'): args+=['--cap-add='+cap]
    if phase!='tooling': args+=['--read-only']
    # Tooling trust lives in the owned overlay, then is deleted before commit.
    if phase!='tooling': args+=['--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=256m']
    for source,target in mounts:
        args+=['--mount','type=bind,src='+str(source)+',dst='+target+',readonly']
    args+=['--mount','type=bind,src='+str(output)+',dst=/out','--entrypoint=/usr/bin/python3',image,
           '-I','-B','/candidate/'+('run.py' if phase=='vm' else 'prepare.py')]
    return args


def host(args):
    need(platform.machine()=='aarch64' and os.getuid()!=0,'native ARM nonroot coordinator required')
    for key in ('ready','code','candidate','tooling_cache'):
        setattr(args,key,ordinary(getattr(args,key),directory=True))
    manifest=load_json(args.ready/'manifest.json')
    need(sha(args.ready/'manifest.json')==args.manifest_sha256,'selected producer manifest differs')
    image=manifest['preparation']['image_id']
    need(re.fullmatch('sha256:[0-9a-f]{64}',image),'immutable producer image required')
    common=selected_module('common',args.code/'scripts/virtual/common.py')
    # File identity binds all imported primitives and staged installer dependencies.
    inputs=input_files(args.ready,manifest)
    base=common.inventory((args.ready/manifest['builder_lock']['path']).read_text())
    lock=load_json(args.code/'scripts/virtual/tooling.lock.json')
    prepare=selected_module('prepare',args.candidate/'prepare.py')
    expected=prepare.union_inventory(base,lock['packages'])
    need(args.output.is_absolute() and args.output.parent==Path('/tmp') and not args.output.exists(),
         'fresh owned /tmp VM work directory required')
    args.output.mkdir(mode=0o700)
    save(args.output/'actor-state.json',dict(state='PRE_ACTORS',purpose='full-composition-installer-vm'))
    # Profile output belongs to this controller; the source candidate stays readonly.
    candidate=args.output/'candidate'; candidate.mkdir()
    for name in ('run.py','prepare.py','guest.py','installer.py','profile.py','numeric_vm.py'):
        shutil.copyfile(ordinary(args.candidate/name),candidate/name)
    profile=selected_module('profile',candidate/'profile.py')
    need(Path(profile.__file__).resolve()==candidate/'profile.py','selected profile module origin differs')
    selected=profile.build(args.ready,args.code,candidate)
    code_files=selected['code_files']
    need(type(code_files) is dict and 1<=len(code_files)<=256,'finite source closure required')
    if args.code_files is not None: need(set(args.code_files)==set(code_files),'explicit source list differs from held profile')
    for name,item in code_files.items():
        need(row(ordinary(args.code/relative(name)))==item,'profile source closure differs')
    for name in ('scripts/virtual/common.py','scripts/virtual/audit_tooling.py','scripts/virtual/tooling.lock.json'):
        need(name in code_files,'missing generic source dependency')
    runner_files={name:row(ordinary(candidate/name)) for name in
                  ('run.py','prepare.py','guest.py','installer.py','profile.py','numeric_vm.py','installer-profile.json','payload.json')}
    token=uuid.uuid4().hex
    c=dict(schema_version=1,purpose='full-composition-installer-vm',nonce=token,
           source_commit=manifest['preparation']['sources']['code'],active_image=image,
           output_uid=os.getuid(),output_gid=os.getgid(),builder_inventory=base,tooling_inventory=expected,
           tooling_lock_sha256=sha(args.code/'scripts/virtual/tooling.lock.json'),code_files=code_files,
           runner_files=runner_files,input_files=inputs)
    need(subprocess.check_output(['git','-C',str(args.code),'rev-parse','HEAD'],text=True,timeout=15).strip()==c['source_commit'],
         'selected source checkout revision differs')
    subprocess.run(['git','-C',str(args.code),'diff','--exit-code','HEAD','--',*code_files],
                   check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)
    result=dict(status='FAIL',phase='tooling',container_cleanup='UNKNOWN',image_cleanup='UNKNOWN',
                producer_cleanup='NOT OWNED BY VM CONTROLLER',hardware_validation='NOT RUN')
    owned=[]; derived=None; commit_attempted=False
    derived_tag='cachy-asahi-full-installer:'+token
    result['owned_image_tag']=derived_tag
    def cancelled(*_): raise InterruptedError('VM controller cancelled/deadline')
    previous={sig:signal.signal(sig,cancelled) for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGALRM)}
    signal.setitimer(signal.ITIMER_REAL,9600)
    def command(argv,seconds=60):
        observed=common.bounded(list(map(str,argv)),timeout=seconds,limit=4*1024**2)
        need(observed['error'] is None and observed['returncode']==0,'owned controller command failed: '+str(argv[0]))
        return observed['stdout'].strip()
    try:
        save(args.output/'actor-state.json',dict(state='STARTED',purpose='full-composition-installer-vm'))
        need(command(['docker','image','inspect','--format={{.Id}}',image])==image,
             'producer immutable image missing')
        for phase in ('tooling','disk','vm'):
            result['phase']=phase
            selection=args.output/('selection-'+phase); selection.mkdir()
            save(selection/'vm-contract.json',c)
            output=args.output/phase; output.mkdir(mode=0o777 if phase=='vm' else 0o755)
            if phase=='vm': output.chmod(0o777) # Isolated UID23001 only; parent0700 and sole bind.
            mounts=[(args.ready,'/inputs'),(args.code,'/code'),(args.code/'scripts','/runner'),
                    (candidate,'/candidate'),(args.tooling_cache,'/tooling-cache'),(selection,'/selection')]
            if phase=='vm': mounts.append((args.output/'disk','/prepared'))
            name='cachy-full-installer-'+token+'-'+phase
            owned.append(name) # Register before the daemon may create it, including cancellation.
            command(container_args(c,phase,c['active_image'],mounts,output,name)+
                (['--vm'] if phase=='vm' else [phase])+['--contract-sha256',sha(selection/'vm-contract.json')])
            command(['docker','start','-a',name],5500 if phase=='vm' else 1900)
            receipt=load_json(output/('vm.json' if phase=='vm' else phase+'.json'))
            need(receipt['status']=={'tooling':'TOOLING_READY','disk':'PREPARED','vm':'PASS'}[phase],
                 phase+' receipt failed')
            if phase=='tooling':
                commit_attempted=True
                derived=command(['docker','commit',name,derived_tag],120)
                need(re.fullmatch('sha256:[0-9a-f]{64}',derived) and derived!=image,'new private tooling image required')
                c['active_image']=derived
        for directory,pins in ((args.code,code_files),(args.ready,inputs)):
            for name,item in pins.items():
                need(row(ordinary(directory/name))==item,'source/cache changed during owned VM trial')
        need(command(['docker','image','inspect','--format={{.Id}}',image])==image,
             'borrowed producer image identity changed')
        result['source_cache_preservation']='PASS'
        result['producer_image_preservation']='PASS-immutable-image-identity'
        result.update(status='PASS',guest=receipt)
    finally:
        signal.setitimer(signal.ITIMER_REAL,0)
        faults=[]
        for name in reversed(owned):
            try:
                inspected=common.bounded(['docker','inspect',name],timeout=20)
                need(inspected['error'] is None,'container ownership lookup failed')
                if inspected['returncode']!=0:
                    need('No such' in inspected['stderr'],'ambiguous container ownership'); continue
                metadata=json.loads(inspected['stdout'])
                need(len(metadata)==1 and metadata[0]['Config']['Labels'].get('cachy-asahi.full-installer')==token,
                     'container ownership token differs')
                identity=metadata[0]['Id']
                need(re.fullmatch('[0-9a-f]{64}',identity),'immutable container ID missing')
                command(['docker','rm','-f',identity])
                observed=common.bounded(['docker','inspect',identity],timeout=20)
                need(observed['error'] is None and observed['returncode']!=0 and 'No such' in observed['stderr'],
                     'owned container absence not established')
            except BaseException: faults.append('container:'+name)
        result['container_cleanup']='FAIL' if faults else 'PASS'
        if derived is not None:
            try:
                command(['docker','image','rm','--no-prune',derived])
                observed=common.bounded(['docker','image','inspect',derived],timeout=20)
                need(observed['error'] is None and observed['returncode']!=0 and 'No such image' in observed['stderr'],
                     'owned derived image absence not established')
                result['image_cleanup']='PASS'
            except BaseException: faults.append('derived-image'); result['image_cleanup']='FAIL'
        elif commit_attempted:
            # A cancelled daemon commit may outlive its CLI. Retain its unique
            # tag and report uncertainty rather than claiming an absent image.
            faults.append('image-commit-terminal-state-unknown')
            result['image_cleanup']='UNKNOWN'
        else: result['image_cleanup']='NOT CREATED'
        # Preserve bounded reports; remove only this controller's private disks,
        # QEMU COW files and selected cache-free staging paths.
        for phase in ('tooling','disk','vm'):
            folder=args.output/phase
            if folder.exists():
                for name in (phase+'.json','serial.log'):
                    source=folder/name
                    if source.is_file() and not source.is_symlink(): shutil.copyfile(source,args.output/(phase+'-'+name))
                try: shutil.rmtree(folder)
                except OSError: faults.append('private-'+phase)
        result['private_cleanup']='FAIL' if faults else 'PASS'
        if faults: result['status']='FAIL'
        save(args.output/'result.json',result)
        for sig,handler in previous.items(): signal.signal(sig,handler)
        need(not faults,'owned VM resource cleanup failed')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vm',action='store_true')
    parser.add_argument('--contract-sha256')
    for name in ('ready','code','candidate','tooling-cache','output'): parser.add_argument('--'+name,type=Path)
    parser.add_argument('--manifest-sha256')
    parser.add_argument('--code-files',nargs='+')
    args=parser.parse_args()
    if args.vm:
        need(args.contract_sha256,'VM selection pin required'); vm(args.contract_sha256)
    else:
        need(all(getattr(args,name) is not None for name in
            ('ready','code','candidate','tooling_cache','output','manifest_sha256')),'complete source/producer inputs required')
        host(args)


if __name__=='__main__': main()

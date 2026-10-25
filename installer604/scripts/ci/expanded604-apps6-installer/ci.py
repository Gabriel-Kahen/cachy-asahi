#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fresh signed604 target through the accepted installer and independent readback."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import platform
import shutil
import signal
import sys
from types import SimpleNamespace
import contract as C
import adapter

PURPOSE='expanded604-apps6-installer'
PRODUCER_PATHS=('preparation_source','product','updater','desktop','updater_v2_source','native','fdk','cache','setup4_pair')
PUBLIC=('producer.json','producer-cleanup.json','result.json','tooling-tooling.json','disk-disk.json','vm-vm.json')


def parser():
    value=argparse.ArgumentParser(description=__doc__)
    for name in ('implementation',*PRODUCER_PATHS,*C.CARRIERS,*C.DECISIONS,'audio_inputs','output'):
        value.add_argument('--'+name.replace('_','-'),type=Path,required=True)
    value.add_argument('--implementation-revision',required=True)
    return value


def vm_retired(output):
    if not output.exists():return True
    try:
        receipt=C.read(output/'result.json')
        return receipt['container_cleanup']=='PASS' and receipt['image_cleanup'] in ('PASS','NOT CREATED')
    except (OSError,ValueError,KeyError):
        try:return C.read(output/'actor-state.json')==dict(state='PRE_ACTORS',purpose=PURPOSE)
        except (OSError,ValueError):return False


def cleanup_ready(path,owner):
    C.safe(path)
    C.need(owner['purpose']==PURPOSE and path==Path(owner['output'])/'ready604' and
         C.read(path.parent/'owner.json')==owner,'exact owned604 cache lease/path required')
    if not path.exists():return
    C.need(path.stat().st_uid==os.getuid(),'owned604 cache owner differs')
    entries=list(path.rglob('*'));C.need(len(entries)<=2000,'original cache cleanup node bound')
    for entry in entries:
        C.safe(entry);C.need(entry.is_file() or entry.is_dir(),'owned604 cleanup special node refused')
    for name in ('packages','keys'):
        if (path/name).exists():(path/name).chmod(0o700)
    shutil.rmtree(path)


def main(argv=None):
    args=parser().parse_args(argv)
    policy=C.policy()  # First gate, before source/carrier observations, output or actors.
    for name,value in vars(args).items():
        if isinstance(value,Path):setattr(args,name,C.safe(value.absolute()))
    C.need(C.revision(args.implementation)==args.implementation_revision,'exact implementation revision required')
    C.verify_source(args.implementation);C.legacy(args.legacy_source)
    args.code=args.implementation
    composition,summary,accepted=C.inputs(args,policy)
    C.need(platform.machine()=='aarch64' and os.getuid()==os.geteuid()>0,'ordinary native ARM coordinator required')
    C.need(args.output.parent==Path('/tmp') and not args.output.exists(),'fresh owned direct /tmp output required')
    output=args.output;producer_output=output.with_name(output.name+'-producer');vm_output=output.with_name(output.name+'-vm')
    C.need(not producer_output.exists() and not vm_output.exists(),'fresh producer/VM siblings required')
    output.mkdir(mode=0o700)
    owner=dict(schema_version=1,purpose=PURPOSE,token=os.urandom(16).hex(),output=str(output),
         producer=str(producer_output),vm=str(vm_output),legacy_source=C.LEGACY)
    (output/'owner.json').write_bytes(C.encoded(owner))
    result=dict(status='FAIL',scope='GENERIC4K_APPS6_SIGNED604_FRESH_INSTALLER_SOFTWARE_ONLY',hardware='NOT_RUN',
         release='NOT_ADMITTED',native_container_P0='UNCHANGED-FAILED',producer='NOT_RUN',vm='NOT_RUN',
         producer_cleanup='NOT_RUN',prerequisites=accepted,expected604_sha256=C.TARGET_SHA,
         implementation_source=args.implementation_revision,legacy_source=C.LEGACY,input_summary=summary['summary'])
    producer=C.load('_fresh604_producer',args.legacy_source/'scripts/ci/full-composition-installer-vm/producer.py')
    old_ci=C.load('_fresh604_original_ci',args.legacy_source/'scripts/ci/full-composition-installer-vm/ci.py')
    materializer=C.scoped_load('_fresh604_materializer',C.HERE.parent/'expanded604-apps6/materializer.py',{'contract':C.COMPOSITION})
    ready604=output/'ready604';candidate=output/'candidate';cache=output/'tooling-cache'
    def cancelled(*_):raise InterruptedError('fresh604 installer cancelled/deadline')
    prior={sig:signal.signal(sig,cancelled) for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGALRM)}
    try:
        original=SimpleNamespace(**{name:getattr(args,name) for name in PRODUCER_PATHS},
             code=args.legacy_source,code_revision=C.LEGACY,output=producer_output)
        ready=producer.prepare(original);result['producer']='READY_SIGNED_INITIAL587'
        materializer.prepare(ready,producer_output,args.eight_source,args.seven_source,args.audio_inputs,args.legacy_source,
             ready604,composition,args.management_source,args.setup_source,args.welcome_source,args.implementation,args.apps6_source,args.apps6_native_source)
        result['expanded604']='READY_SIGNED_EXPANDED604'
        adapter.materialize(args.legacy_source,candidate)
        vm=C.load('_fresh604_vm',candidate/'run.py');preparation=C.load('_fresh604_prepare',candidate/'prepare.py')
        paths=list(sys.path)
        try:
            sys.path.insert(0,str(args.legacy_source/'scripts/virtual'))
            auditor=C.load('_fresh604_tooling',args.legacy_source/'scripts/virtual/audit_tooling.py')
            lock=C.read(args.legacy_source/'scripts/virtual/tooling.lock.json');auditor.validate_lock(lock)
            downloads=old_ci.selected_tooling_inputs(ready604,lock,preparation,auditor)
            C.need(len(downloads)<=64 and len({row['filename'] for row in downloads})==len(downloads),'original finite tooling bound')
            cache.mkdir(mode=0o700)
            with ThreadPoolExecutor(max_workers=4) as pool:list(pool.map(lambda row:auditor.fetch(row,cache,True),downloads))
            vm.host(SimpleNamespace(ready=ready604,manifest_sha256=C.sha(ready604/'manifest.json'),code=args.legacy_source,
                 candidate=candidate,tooling_cache=cache,output=vm_output,code_files=None))
        finally:sys.path[:]=paths
        receipt=C.read(vm_output/'result.json')
        C.need(receipt['status']=='PASS' and all(receipt[k]=='PASS' for k in ('container_cleanup','image_cleanup','private_cleanup')),
             'fresh604 VM owner result incomplete')
        result.update(status='PASS',vm='PASS',vm_owner=receipt)
    except BaseException as error:result.update(status='FAIL',error_type=type(error).__name__,error=str(error)[:2048])
    finally:
        signal.setitimer(signal.ITIMER_REAL,0);safe=vm_retired(vm_output)
        # The604 public verifier is outside the target and must retire before its backing inputs.
        verifier=producer_output/'private/expanded604-verifier'
        if verifier.exists() or verifier.is_symlink():
            safe=False;result.update(status='FAIL',expanded_cache_cleanup='RETAINED_PUBLIC_VERIFIER_ABSENCE_UNKNOWN')
        if safe:
            try:cleanup_ready(ready604,owner);result['expanded_cache_cleanup']='PASS'
            except BaseException as error:result.update(status='FAIL',expanded_cache_cleanup='FAIL',expanded_cleanup_error=str(error)[:512]);safe=False
        if safe and (producer_output/'producer-owner.json').is_file():
            try:
                cleanup=producer.cleanup(producer_output);C.need(cleanup['status']=='PASS','producer cleanup failed');result['producer_cleanup']='PASS'
            except BaseException as error:result.update(status='FAIL',producer_cleanup='FAIL',cleanup_error=str(error)[:512])
        elif not safe:result.update(status='FAIL',producer_cleanup='RETAINED_VM_OR_VERIFIER_OR_CACHE_CLEANUP_UNKNOWN')
        for origin,label in ((producer_output/'public','producer'),(vm_output,'vm')):
            if origin.is_dir():
                for name in PUBLIC:
                    path=origin/name
                    if path.is_file() and not path.is_symlink() and path.stat().st_size<=4*1024**2:
                        shutil.copyfile(path,output/(label+'-'+name))
        if (candidate/'adapter.json').is_file():shutil.copyfile(candidate/'adapter.json',output/'adapter.json')
        serial=vm_output/'vm-serial.log'
        if serial.is_file() and not serial.is_symlink() and serial.stat().st_size<=64*1024**2:
            with serial.open('rb') as stream:
                stream.seek(max(0,serial.stat().st_size-65536));(output/'vm-serial-tail.log').write_bytes(stream.read(65536))
        if result['producer_cleanup']!='PASS':result['status']='FAIL'
        try:
            if safe:
                for path in (cache,candidate,vm_output):
                    if path.exists():shutil.rmtree(path)
            result['caller_private_cleanup']='PASS' if safe else 'RETAINED_VM_OR_VERIFIER_OR_CACHE_CLEANUP_UNKNOWN'
        except OSError as error:result.update(status='FAIL',caller_private_cleanup='FAIL',private_cleanup_error=str(error)[:512])
        result['owned_paths']=[str(producer_output),str(vm_output)]
        (output/'result.json').write_bytes(C.encoded(result))
        for sig,handler in prior.items():signal.signal(sig,handler)
    return int(result['status']!='PASS')


if __name__=='__main__':raise SystemExit(main())

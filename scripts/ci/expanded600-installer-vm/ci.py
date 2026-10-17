#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Future signed600 producer -> held generic VM, blocked pending Root acceptance."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
from types import SimpleNamespace
import contract as C
import adapter
import materializer


def vm_retired(output):
    if not output.exists():return True
    try:
        receipt=C.read(output/'result.json')
        return receipt['container_cleanup']=='PASS' and receipt['image_cleanup'] in ('PASS','NOT CREATED')
    except (OSError,ValueError,KeyError):
        try:return C.read(output/'actor-state.json')==dict(state='PRE_ACTORS',purpose='expanded600-installer-vm')
        except (OSError,ValueError):return False


def cleanup_ready(path,owner):
    C.safe(path)
    C.need(owner['purpose']=='expanded600-installer-vm' and path==Path(owner['output'])/'ready600' and
           C.read(path.parent/'owner.json')==owner,'owned600 cache lease/path differs')
    if not path.exists():return
    C.need(path.stat().st_uid==os.getuid(),'owned600 cache owner differs')
    entries=list(path.rglob('*'));C.need(len(entries)<=2000,'owned600 cleanup node bound')
    for entry in entries:
        C.safe(entry);C.need(entry.is_file() or entry.is_dir(),'owned600 cleanup special node refused')
    for name in ('packages','keys'):
        directory=path/name
        if directory.exists():directory.chmod(0o700)
    shutil.rmtree(path)


def own_source(source,revision):
    C.safe(source)
    C.need(C.revision(source)==revision and len(revision)==40,'held implementation source differs')
    pins=C.read(C.HERE/'source-manifest.json')
    for name,row in pins.items():C.checked(source,dict(path=name,**row))
    manifest=str((C.HERE/'source-manifest.json').relative_to(source))
    subprocess.run(['git','-C',str(source),'diff','--exit-code','HEAD','--',*pins,manifest],
                   check=True,capture_output=True,timeout=15)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('implementation','legacy-source','preparation-source','product','updater','desktop','updater-v2-source',
                 'native','fdk','cache','setup4-pair','seven-pairs','eight-pairs','audio-inputs','output'):
        parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--implementation-revision',required=True);args=parser.parse_args()
    policy=C.policy() # This must precede native guards, output creation and all actors.
    for name,value in vars(args).items():
        if isinstance(value,Path):setattr(args,name,C.safe(value.absolute()))
    own_source(args.implementation,args.implementation_revision);C.legacy(args.legacy_source)
    C.need(C.revision(args.seven_pairs)==policy['retained_seven_source'] and
           C.revision(args.eight_pairs)==policy['eight_pair_source'],'exact seven/eight-pair sources required')
    decisions=C.prerequisites(args.eight_pairs,policy)
    materializer.accepted_pairs(args.eight_pairs,args.seven_pairs,args.legacy_source,policy)
    C.need(platform.machine()=='aarch64' and os.getuid()==os.geteuid()>0,'ordinary native ARM coordinator required')
    C.need(args.output.parent==Path('/tmp') and not args.output.exists(),'fresh owned direct /tmp output required')
    output=args.output;output.mkdir(mode=0o700)
    producer_output=output.with_name(output.name+'-producer');vm_output=output.with_name(output.name+'-vm')
    C.need(not producer_output.exists() and not vm_output.exists(),'fresh owned producer/VM siblings required')
    owner=dict(schema_version=1,purpose='expanded600-installer-vm',token=os.urandom(16).hex(),
               output=str(output),producer=str(producer_output),vm=str(vm_output),legacy_source=C.LEGACY)
    (output/'owner.json').write_bytes(C.encoded(owner))
    result=dict(status='FAIL',scope='GENERIC4K_SIGNED600_FRESH_INSTALLER_SOFTWARE_ONLY',hardware='NOT_RUN',
        native_container_P0='UNCHANGED-FAILED',producer='NOT_RUN',vm='NOT_RUN',producer_cleanup='NOT_RUN',
        prerequisites=decisions,expected600_sha256=C.AFTER,implementation_source=args.implementation_revision,legacy_source=C.LEGACY)
    producer=C.load('_installer600_producer',args.legacy_source/'scripts/ci/full-composition-installer-vm/producer.py')
    old_ci=C.load('_installer600_prior_ci',args.legacy_source/'scripts/ci/full-composition-installer-vm/ci.py')
    expanded=output/'ready600';candidate=output/'candidate';cache=output/'tooling-cache'
    def cancelled(*_):raise InterruptedError('expanded600 installer cancelled/deadline')
    prior={sig:signal.signal(sig,cancelled) for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGALRM)}
    try:
        original_args=SimpleNamespace(**vars(args),code=args.legacy_source,code_revision=C.LEGACY)
        original_args.output=producer_output
        ready=producer.prepare(original_args);result['producer']='READY_SIGNED_INITIAL587'
        materializer.prepare(ready,producer_output,args.eight_pairs,args.seven_pairs,args.audio_inputs,args.legacy_source,expanded,policy)
        result['expanded600']='READY_SIGNED_EXPANDED600'
        adapter.materialize(args.legacy_source,candidate)
        vm=C.load('_installer600_vm',candidate/'run.py');preparation=C.load('_installer600_prepare',candidate/'prepare.py')
        sys.path.insert(0,str(args.legacy_source/'scripts/virtual'))
        auditor=C.load('_installer600_tooling_auditor',args.legacy_source/'scripts/virtual/audit_tooling.py')
        lock=C.read(args.legacy_source/'scripts/virtual/tooling.lock.json');auditor.validate_lock(lock)
        downloads=old_ci.selected_tooling_inputs(expanded,lock,preparation,auditor)
        C.need(len(downloads)<=64 and len({r['filename'] for r in downloads})==len(downloads),'finite distinct held tooling inputs required')
        cache.mkdir(mode=0o700)
        with ThreadPoolExecutor(max_workers=4) as pool:list(pool.map(lambda row:auditor.fetch(row,cache,True),downloads))
        vm.host(SimpleNamespace(ready=expanded,manifest_sha256=C.sha(expanded/'manifest.json'),code=args.legacy_source,
            candidate=candidate,tooling_cache=cache,output=vm_output,code_files=None))
        receipt=C.read(vm_output/'result.json')
        C.need(receipt['status']=='PASS' and receipt['container_cleanup']=='PASS' and receipt['image_cleanup']=='PASS' and
               receipt['private_cleanup']=='PASS','expanded600 VM owner result incomplete')
        result.update(status='PASS',vm='PASS',vm_owner=receipt)
    except BaseException as error:result.update(status='FAIL',error_type=type(error).__name__,error=str(error)[:2048])
    finally:
        signal.setitimer(signal.ITIMER_REAL,0)
        safe=vm_retired(vm_output)
        if safe:
            try:cleanup_ready(expanded,owner);result['expanded_cache_cleanup']='PASS'
            except BaseException as error:result.update(status='FAIL',expanded_cache_cleanup='FAIL',expanded_cleanup_error=str(error)[:512]);safe=False
        if safe and (producer_output/'producer-owner.json').is_file():
            try:
                cleanup=producer.cleanup(producer_output);C.need(cleanup['status']=='PASS','producer cleanup failed');result['producer_cleanup']='PASS'
            except BaseException as error:result.update(status='FAIL',producer_cleanup='FAIL',cleanup_error=str(error)[:512])
        elif not safe:result.update(status='FAIL',producer_cleanup='RETAINED_VM_OR_CACHE_CLEANUP_UNKNOWN')
        for origin,label in ((producer_output/'public','producer'),(vm_output,'vm')):
            if origin.is_dir():
                for name in ('producer.json','producer-cleanup.json','result.json','tooling-tooling.json','disk-disk.json','vm-vm.json'):
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
            result['caller_private_cleanup']='PASS' if safe else 'RETAINED_VM_OR_CACHE_CLEANUP_UNKNOWN'
        except OSError as error:result.update(status='FAIL',caller_private_cleanup='FAIL',private_cleanup_error=str(error)[:512])
        result['owned_paths']=[str(producer_output),str(vm_output)]
        (output/'result.json').write_bytes(C.encoded(result))
        for sig,handler in prior.items():signal.signal(sig,handler)
    return int(result['status']!='PASS')


if __name__=='__main__':raise SystemExit(main())

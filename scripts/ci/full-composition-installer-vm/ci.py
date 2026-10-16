#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One future native producer -> generic VM call, with ordered scoped cleanup."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import sys
from types import SimpleNamespace

HERE=Path(__file__).resolve().parent


def need(ok,reason):
    if not ok: raise ValueError(reason)


def load(name,path):
    spec=importlib.util.spec_from_file_location('_installer_ci_'+name,path)
    value=importlib.util.module_from_spec(spec); sys.modules[spec.name]=value
    spec.loader.exec_module(value); return value


def sha(path):
    with path.open('rb') as stream: return hashlib.file_digest(stream,'sha256').hexdigest()


def vm_retired(output):
    if not output.exists(): return True
    try:
        receipt=json.loads((output/'result.json').read_bytes())
        return receipt['container_cleanup']=='PASS' and receipt['image_cleanup'] in ('PASS','NOT CREATED')
    except (OSError,ValueError,KeyError):
        try: return json.loads((output/'actor-state.json').read_bytes())==dict(state='PRE_ACTORS',purpose='full-composition-installer-vm')
        except (OSError,ValueError): return False


def selected_tooling_inputs(ready, lock, preparation, auditor):
    manifest=json.loads((ready/'manifest.json').read_bytes())
    builder=ready/'builder-packages.lock'
    need(manifest['builder_lock']['path']==builder.name and
         sha(builder)==manifest['builder_lock']['sha256']==preparation.BUILDER_LOCK,
         'exact original574 builder lock required before tooling acquisition')
    base=dict(line.split() for line in builder.read_text().splitlines())
    return preparation.tooling_inputs(base,lock,auditor.signature)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('code','preparation-source','product','updater','desktop','updater-v2-source',
                 'native','fdk','cache','setup4-pair','output'):
        parser.add_argument('--'+name,required=True,type=Path)
    parser.add_argument('--code-revision',required=True)
    args=parser.parse_args()
    need(platform.machine()=='aarch64' and os.getuid()!=0,'disposable native ARM nonroot caller required')
    need(args.output.is_absolute() and args.output.parent==Path('/tmp') and not args.output.exists(), 'fresh owned /tmp result directory required')
    args.output.mkdir(mode=0o700)
    producer_output=args.output.with_name(args.output.name+'-producer')
    vm_output=args.output.with_name(args.output.name+'-vm')
    need(not producer_output.exists() and not vm_output.exists(),'fresh producer/VM sibling paths required')
    producer,vm=load('producer',HERE/'producer.py'),load('vm',HERE/'run.py')
    result=dict(status='FAIL',scope='generic4K-signed-initial587-fresh-installer-software',
        producer='NOT RUN',vm='NOT RUN',producer_cleanup='NOT RUN',hardware='NOT RUN',native_container_P0='UNCHANGED-FAILED')
    def cancelled(*_): raise InterruptedError('full installer caller cancelled/deadline')
    previous={sig:signal.signal(sig,cancelled) for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGALRM)}
    # The CI step owns the absolute15600s deadline; nested owners retain
    # their own finite timers. SIGTERM still enters ordered cleanup here.
    try:
        producer_args=SimpleNamespace(**vars(args)); producer_args.output=producer_output
        ready=producer.prepare(producer_args)
        result['producer']='READY_SIGNED_INITIAL587'
        # Reuse the exact generic tooling lock/fetcher. Downloads are pinned data;
        # authentication and installation happen only in the owned tooling child.
        sys.path.insert(0,str(args.code/'scripts/virtual'))
        auditor=load('tooling_auditor',args.code/'scripts/virtual/audit_tooling.py')
        lock=json.loads((args.code/'scripts/virtual/tooling.lock.json').read_bytes()); auditor.validate_lock(lock)
        cache=args.output/'tooling-cache'; cache.mkdir()
        preparation=load('prepare',HERE/'prepare.py')
        downloads=selected_tooling_inputs(ready,lock,preparation,auditor)
        need(len(downloads)<=64 and len({r['filename'] for r in downloads})==len(downloads),'bounded distinct tooling inputs required')
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(lambda row:auditor.fetch(row,cache,True),downloads))
        vm.host(SimpleNamespace(ready=ready,manifest_sha256=sha(ready/'manifest.json'),code=args.code,
            candidate=HERE,tooling_cache=cache,output=vm_output,code_files=None))
        receipt=json.loads((vm_output/'result.json').read_bytes())
        need(receipt['status']=='PASS' and receipt['container_cleanup']=='PASS' and
             receipt['image_cleanup']=='PASS' and receipt['private_cleanup']=='PASS','VM owner result incomplete')
        result.update(status='PASS',vm='PASS',vm_owner=receipt)
    except BaseException as error:
        result.update(status='FAIL',error_type=type(error).__name__,error=str(error)[:1024])
    finally:
        # Cleanup keeps the same ownership order on failure. Never remove producer
        # inputs while any VM container/image actor has uncertain retirement.
        signal.setitimer(signal.ITIMER_REAL,0)
        safe=vm_retired(vm_output)
        if safe and (producer_output/'producer-owner.json').is_file():
            try:
                cleanup=producer.cleanup(producer_output); result['producer_cleanup']=cleanup['status']
                need(cleanup['status']=='PASS','producer cleanup incomplete')
            except BaseException as error:
                result.update(status='FAIL',producer_cleanup='FAIL',cleanup_error=str(error)[:512])
        elif not safe: result.update(status='FAIL',producer_cleanup='RETAINED-VM-RETIREMENT-UNKNOWN')
        for origin,label in ((producer_output/'public','producer'),(vm_output,'vm')):
            if origin.is_dir():
                for name in ('producer.json','producer-cleanup.json','result.json','tooling-tooling.json','disk-disk.json','vm-vm.json'):
                    path=origin/name
                    if path.is_file() and not path.is_symlink() and path.stat().st_size<=4*1024**2:
                        shutil.copyfile(path,args.output/(label+'-'+name))
        serial=vm_output/'vm-serial.log'
        if serial.is_file() and not serial.is_symlink() and serial.stat().st_size<=64*1024**2:
            with serial.open('rb') as source:
                source.seek(max(0,serial.stat().st_size-65536))
                (args.output/'vm-serial-tail.log').write_bytes(source.read(65536))
        if result['producer_cleanup']!='PASS': result['status']='FAIL'
        result['owned_work_paths']=[str(producer_output),str(vm_output)]
        try:
            if safe:
                cache=args.output/'tooling-cache'
                if cache.exists(): shutil.rmtree(cache)
                if vm_output.exists(): shutil.rmtree(vm_output)
            result['caller_private_cleanup']='PASS' if safe else 'RETAINED-VM-RETIREMENT-UNKNOWN'
        except OSError as error:
            result.update(status='FAIL',caller_private_cleanup='FAIL',private_cleanup_error=str(error)[:512])
        (args.output/'result.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
        for sig,handler in previous.items(): signal.signal(sig,handler)
    print(json.dumps(dict(status=result['status'],result=str(args.output/'result.json')),sort_keys=True))
    return int(result['status']!='PASS')


if __name__=='__main__': sys.exit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Owned native producer, actual signed ALPM604 and current Welcome4 in the held16384 guest."""
import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import sys
from types import SimpleNamespace
import contract as C
import adapter
import context604
PRODUCER_PATHS=('preparation_source','product','updater','desktop','updater_v2_source','native','fdk','cache','setup4_pair')
CARRIERS=('legacy_source','eight_source','seven_source','management_source','setup_source','welcome_source')
DECISIONS=('fresh600_decisions','native604_decisions','gui_decisions')


def parser():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('implementation',*PRODUCER_PATHS,*CARRIERS,*DECISIONS,'audio_inputs','output','kernel_work','kernel_receipt'):
        p.add_argument('--'+name.replace('_','-'),type=Path,required=True)
    p.add_argument('--implementation-revision',required=True);return p


def retired(report,controller):
    return controller is not None and controller['natural_exit'] is True and controller['group_absent'] is True and \
        len(report.get('cleanup',[]))==14 and all(r.get('exit',0)==0 for r in report['cleanup']) and \
        any(r.get('guest_disk_removed') is True for r in report['cleanup']) and report.get('base_reference_cleanup',{}).get('ok') is True


def preflight(args):
    value=C.policy()  # Before all observations, output creation, secrets or actors.
    C.need(C.revision(args.implementation)==args.implementation_revision,'exact source revision required');C.check_source(args.implementation)
    accepted=C.decisions(args.native604_decisions,args.gui_decisions,value)
    installer=C.load(args.implementation,'scripts/ci/expanded604-current-management-installer/contract.py')
    args.code=args.implementation;installer.legacy(args.legacy_source)
    composition,summary,original=installer.inputs(args,installer.policy())
    C.need(original['native604']==accepted['native604'],'same exact native604 Root decision required by both gates')
    assets=C.assets(args.gui_decisions,value['welcome4_gui'])
    return value,accepted,composition,summary,assets,installer


def main(argv=None):
    args=parser().parse_args(argv);value,accepted,composition,summary,assets,installer=preflight(args)
    C.need(platform.machine()=='aarch64' and os.getuid()==os.geteuid()>0 and os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_ARCH')=='ARM64','ordinary explicit native ARM CI only')
    C.need(args.output.parent==Path('/tmp') and not args.output.exists() and not args.output.is_symlink(),'fresh direct /tmp owner output')
    output=args.output;producer_output=output.with_name(output.name+'-producer')
    runner=Path(os.environ['RUNNER_TEMP'])/'expanded604-current-management-managed16k-runner';runtime=Path(os.environ['RUNNER_TEMP'])/'expanded604-current-management-managed16k-runtime'
    C.need(runner.is_absolute() and not any(p.is_symlink() for p in (runner,*runner.parents)) and runner.parent.stat().st_uid==os.getuid(),'ordinary owned runner parent required')
    C.need(not any(p.exists() or p.is_symlink() for p in (producer_output,runner,runtime)),'fresh owned consumer/producer siblings required')
    output.mkdir(mode=0o700);C.save(output/'owner.json',dict(purpose=C.SCOPE,output=str(output),producer=str(producer_output),runner=str(runner),runtime=str(runtime),token=os.urandom(16).hex()))
    report=dict(status='FAIL',scope=C.SCOPE,source_sha=args.implementation_revision,prerequisites=accepted,hardware='NOT_RUN',release='NOT_ADMITTED',visual_review='NOT_RUN',graphics_acceleration='NOT_RUN',cleanup='NOT_RUN')
    producer=installer.load('_604_gui_original_producer',args.legacy_source/'scripts/ci/full-composition-installer-vm/producer.py')
    materializer=installer.scoped_load('_604_gui_materializer',args.implementation/'scripts/ci/expanded604-current-management/materializer.py',{'contract':installer.COMPOSITION})
    held_support=C.load(args.implementation,'scripts/ci/managed-gui-generic16k/support.py')
    missing=object();previous_support=sys.modules.get('support',missing)
    try:
        sys.modules['support']=held_support;R=C.load(args.implementation,'scripts/ci/managed-gui-generic16k/run.py')
    finally:
        if previous_support is missing:sys.modules.pop('support',None)
        else:sys.modules['support']=previous_support
    controller=None;raw={};started=False
    def cancelled(*_):raise InterruptedError('owned604 GUI coordinator cancelled')
    previous={s:signal.signal(s,cancelled) for s in (signal.SIGTERM,signal.SIGINT)}
    try:
        original=SimpleNamespace(**{n:getattr(args,n) for n in PRODUCER_PATHS},code=args.legacy_source,code_revision=installer.LEGACY,output=producer_output)
        ready=producer.prepare(original);ready604=output/'ready604'
        materializer.prepare(ready,producer_output,args.eight_source,args.seven_source,args.audio_inputs,args.legacy_source,ready604,composition,args.management_source,args.setup_source,args.welcome_source,args.implementation)
        adapter.prepare(args.implementation,runner,assets,ready604);context604.prepare(args.implementation,runner,ready604)
        shutil.copyfile(C.HERE/'context604.py',runner/'context604.py')
        profile,receipt,image,config=R.kernel(SimpleNamespace(kernel_work=args.kernel_work,kernel_receipt=args.kernel_receipt,source=args.implementation))
        shutil.copyfile(image,runner/'diagnostic.Image');C.save(runner/'kernel-profile.json',profile,65536)
        C.need(C.sha(C.read(runner/'diagnostic.Image',256*1024**2))==profile['Image']['sha256'],'actual copied diagnostic Image differs')
        source_rows={p.name:dict(bytes=p.stat().st_size,sha256=C.sha(C.read(p))) for p in runner.iterdir() if p.is_file() and p.name not in ('diagnostic.Image','runner-proof.json')}
        C.save(runner/'runner-proof.json',dict(status='DERIVED_SOURCE_ONLY',files=source_rows,native='NOT_RUN',hardware='NOT_RUN'))
        files={p.name:dict(bytes=p.stat().st_size,sha256=C.sha(C.read(p))) for p in runner.iterdir() if p.is_file() and p.name!='diagnostic.Image'}
        C.save(output/'generated-runner.json',files)
        started=True
        controller=R.supervise([sys.executable,'-B',runner/'desktop574_runtime.py','--source',args.implementation,'--base-dir',producer_output/'private/desktop574','--output',runtime],output/'controller.log')
        raw=C.json_read(runtime/'runtime.json',16*1024**2)
        report.update(controller=controller,runtime_status=raw['status'],kernel_build=receipt,kernel_config=C.read(config,262144).decode(),diagnostic_kernel=profile)
        C.need(controller['exit']==0 and raw['status']==C.PASS and raw['runtime_package_count']==604 and raw['configuration']=='desktop-container-verifier-pass','actual installed604 GUI runtime failed')
        C.need(retired(raw,controller),'all original14 consumer cleanup records required')
        report['status']='PASS_CONSUMERS_AWAITING_PRODUCER_RETIREMENT'
    except BaseException as error:report.update(status='FAIL',error_type=type(error).__name__,error=str(error)[:2048])
    finally:
        safe=not started or retired(raw,controller)
        if (producer_output/'private/expanded604-verifier').exists() or (producer_output/'private/expanded604-verifier').is_symlink():safe=False
        # Preserve producer backing roots if any consumer/VM actor absence is uncertain.
        if safe and (producer_output/'producer-owner.json').is_file():
            try:report['producer_cleanup']=producer.cleanup(producer_output)
            except BaseException as error:report.update(status='FAIL',producer_cleanup_error=str(error)[:512]);safe=False
        if not safe:report.update(status='FAIL',cleanup='RETAINED_CONSUMER_OR_PRODUCER_ABSENCE_UNKNOWN')
        if safe:
            try:
                if report['status']=='PASS_CONSUMERS_AWAITING_PRODUCER_RETIREMENT':
                    C.need(report['producer_cleanup']['status']=='PASS','original producer retirement required')
                    report.update(status=C.FINAL,cleanup='PASS')
                report['runtime']=raw
                C.save(output/'result.json',report)
                retain=C.load(args.implementation,C.PREFIX+'retain.py');retain.retain(output,producer_output,runtime,runner,args.kernel_work,args.implementation)
                if report['status']==C.FINAL:
                    shutil.rmtree(args.kernel_work);C.need(not args.kernel_work.exists(),'owned kernel work remains')
                    (runner/'diagnostic.Image').unlink();C.need(not (runner/'diagnostic.Image').exists(),'owned copied Image remains')
                    report.update(kernel_work_removed=True,runtime_Image_removed=True)
                # Exact owned staging only, after consumers AND original producer have retired.
                for p in (runner/'ready604',output/'ready604'):
                    if p.is_dir():
                        for sub in ('packages','keys'):
                            if (p/sub).is_dir():(p/sub).chmod(0o700)
                        p.chmod(0o700);shutil.rmtree(p)
                for p in (runner/'install-context',):
                    if p.is_dir():shutil.rmtree(p)
            except BaseException as error:report.update(status='FAIL',cleanup='FAIL',cleanup_error=str(error)[:512])
        C.save(output/'result.json',report)
        public=output/'public';public.mkdir(mode=0o700,exist_ok=True)
        if not (public/'retention.json').exists():
            # Failure evidence is bounded and public-only even when actor absence is unknown.
            for path,name,cap in ((output/'result.json','result.json',16*1024**2),(output/'controller.log','controller.log',16*1024**2),
                    (producer_output/'public/producer.json','producer/producer.json',4*1024**2),(producer_output/'public/producer-cleanup.json','producer/producer-cleanup.json',4*1024**2),
                    (runtime/'runtime.json','runtime/runtime.json',16*1024**2),(runtime/'guest.log','runtime/guest.log',8*1024**2),(runtime/'events.log','runtime/events.log',8*1024**2)):
                if path.is_file() and not path.is_symlink():
                    raw=C.read(path,cap);target=public/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
            files={};total=0
            for path in sorted(public.rglob('*')):
                if path.is_file():
                    raw=C.read(path);total+=len(raw);C.need(total<=128*1024**2 and len(files)<256,'failure public export bound')
                    files[path.relative_to(public).as_posix()]=dict(bytes=len(raw),sha256=C.sha(raw))
            C.save(public/'retention.json',dict(schema_version=1,status='NOT_ACCEPTED',files=files,bytes=total,scope=C.SCOPE,hardware='NOT_RUN'))
        if (output/'public/retention.json').exists():
            shutil.copyfile(output/'result.json',output/'public/result.json')
            receipt=C.json_read(output/'public/retention.json');raw=C.read(output/'result.json');receipt['files']['result.json']=dict(bytes=len(raw),sha256=C.sha(raw))
            receipt['owner_final_status']=report['status'];receipt['ordered_private_cleanup']=report['cleanup']
            receipt['bytes']=sum(r['bytes'] for r in receipt['files'].values());C.need(receipt['bytes']<=128*1024**2,'final public total cap')
            if report['status']!=C.FINAL:receipt['status']='NOT_ACCEPTED'
            C.save(output/'public/retention.json',receipt)
        for sig,handler in previous.items():signal.signal(sig,handler)
    return int(report['status']!=C.FINAL)
if __name__=='__main__':raise SystemExit(main())

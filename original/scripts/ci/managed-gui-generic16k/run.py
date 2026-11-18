#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit disposable CI adapter for the unchanged full GUI trial and owned16K Image."""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parent))
import support as s

PASS='PASS_INSTALLED_WELCOME_DOCTOR_MANAGED_GUI_GENERIC16K_METADATA'
AWAITING='PASS_GUI16K_AWAITING_PRODUCER_RETIREMENT'
FINAL='PASS_GENERIC16K_INSTALLED_GUI_METADATA_PIXELS_PENDING_REVIEW'


def ordinary(path):
    path=Path(path)
    s.need(path.is_absolute() and not any(p.is_symlink() for p in (path,*path.parents)) and
           stat.S_ISDIR(path.lstat().st_mode) and path.stat().st_uid==os.getuid(),'owned ordinary directory required')
    return path


def supervise(argv,log,seconds=2050,cap=16*1024**2):
    child=subprocess.Popen(list(map(str,argv)),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,start_new_session=True)
    poll=selectors.DefaultSelector();data=bytearray();started=time.monotonic();natural=False
    try:
        os.set_blocking(child.stdout.fileno(),False);poll.register(child.stdout,selectors.EVENT_READ)
        while poll.get_map() or os.waitid(os.P_PID,child.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT) is None:
            s.need(time.monotonic()-started<seconds,'owned GUI controller deadline')
            for key,_ in poll.select(.05):
                raw=os.read(key.fd,65536)
                if not raw:poll.unregister(key.fileobj);continue
                s.need(len(data)+len(raw)<=cap,'owned GUI controller output bound');data.extend(raw)
        natural=True
    finally:
        # Keep the unreaped session leader through every group cleanup signal.
        for sig in (signal.SIGTERM,signal.SIGKILL):
            try:os.killpg(child.pid,sig)
            except ProcessLookupError:pass
        code=child.wait(timeout=5);poll.close();child.stdout.close();log.write_bytes(data)
    try:os.killpg(child.pid,0)
    except ProcessLookupError:absent=True
    else:absent=False
    s.need(natural and absent,'natural controller exit and group retirement required')
    return dict(exit=code,natural_exit=natural,group_absent=absent,seconds=round(time.monotonic()-started,6),
        bytes=len(data),sha256=s.sha(data))


def kernel(args):
    work=ordinary(args.kernel_work)
    s.need(work==Path(os.environ['RUNNER_TEMP'])/'managed-gui16k-kernel','exact owned kernel work required')
    receipt=json.loads(s.read(args.kernel_receipt,65536));helper=s.load(args.source,'scripts/ci/managed-gui-generic16k/build_kernel.py')
    K=s.load(args.source,'scripts/ci/managed-gui-generic16k/kernel_contract.py')
    s.need(args.kernel_receipt==work/'helper/built/build-receipt.json' and
           Path(receipt['helper']['path'])==work/'helper/build_kernel.py' and
           Path(receipt['fragment']['path'])==work/'helper/kernel.fragment' and
           Path(receipt['image']['path'])==work/'helper/built/build/arch/arm64/boot/Image' and
           Path(receipt['config']['path'])==work/'helper/built/build/.config','owned kernel paths differ')
    for field in ('helper','fragment','image','config'):
        target=Path(receipt[field]['path']);s.need(not any(p.is_symlink() for p in (target,*target.parents)),'kernel path symlink refused')
    fragment=s.read(s.HERE/'kernel.fragment')
    profile,image,config=K.from_receipt(receipt,helper,fragment,s.sha(s.read(s.HERE/'build_kernel.py')),s.sha(fragment))
    # Bind the actual copied build helper and fragment too, not only the receipt strings.
    s.need(s.sha(s.read(Path(receipt['helper']['path'])))==profile['helper_sha256'] and
           s.sha(s.read(Path(receipt['fragment']['path'])))==profile['fragment_sha256'],'actual build helper/fragment drift')
    return profile,receipt,image,config


def stage_proof(args):
    proof=json.loads(s.read(args.proof,128*1024));manifest=json.loads(s.read(args.manifest,512*1024))
    s.need(proof['status']=='SOURCE_PROOF_PASS' and proof['generated_runner']=='PASS' and
           proof['manifest_sha256']==s.sha(s.read(args.manifest,512*1024)) and
           proof['job_token']==args.job_token and proof['source_sha']==args.source_commit==proof['workflow_sha'],
           'immutable source/generated runner proof required')
    for name,row in manifest['generated_runner'].items():
        p=Path(name);s.need(not p.is_absolute() and '..' not in p.parts,'unsafe generated path')
        raw=s.read(args.runner/p);s.need(len(raw)==row['bytes'] and s.sha(raw)==row['sha256'],'generated runner drift')
    return proof


def trial(args):
    s.check_source(args.source)
    if not args.execute:return dict(status='SOURCE_INPUTS_VERIFIED_NOT_EXECUTED',scope=s.SCOPE)
    s.need(platform.system()=='Linux' and platform.machine()=='aarch64' and os.getuid()==os.geteuid()>0 and
           os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_ARCH')=='ARM64' and
           s.HERE==args.source/'scripts/ci/managed-gui-generic16k','explicit adopted disposable native CI required')
    s.need(re.fullmatch('[0-9a-f]{40}',args.source_commit) and re.fullmatch('[0-9a-f]{16}',args.job_token),'source/job identity required')
    s.need(args.runner==Path(os.environ['RUNNER_TEMP'])/'managed-gui16k-runner' and
           args.output==Path(os.environ['RUNNER_TEMP'])/'managed-gui16k-runtime','exact owned runtime locations required')
    ordinary(args.runner);stage_proof(args)
    base=json.loads(s.read(args.base_dir/'report.json',512*1024))
    s.need(base['status']=='PASS_NATIVE_OFFLINE_574_TRANSACTION' and base['ownership']['token']==args.job_token and
           base['ownership']['build_complete'] is True and base['ownership']['probe_complete'] is True,
           'successful exact owned574 producer required')
    profile,receipt,image,config=kernel(args)
    for name in ('diagnostic.Image','kernel-profile.json'):
        s.need(not (args.runner/name).exists() and not (args.runner/name).is_symlink(),'fresh runtime kernel payload required')
    shutil.copyfile(image,args.runner/'diagnostic.Image');s.save(args.runner/'kernel-profile.json',profile,65536)
    s.need(s.sha(s.read(args.runner/'diagnostic.Image',256*1024**2))==profile['Image']['sha256'],'copied diagnostic Image differs')
    actor=None;failure=None
    try:
        actor=supervise([sys.executable,'-B',args.runner/'desktop574_runtime.py','--source',args.source,
            '--base-dir',args.base_dir,'--output',args.output],args.runner/'controller.log')
    except BaseException as error:failure=dict(type=type(error).__name__,reason=str(error)[:512])
    args.output.mkdir(mode=0o700,exist_ok=True)
    path=args.output/'runtime.json'
    report=json.loads(s.read(path)) if path.exists() else dict(status='FAIL',error='controller produced no runtime receipt')
    original=report['status']
    report.update(scope=s.SCOPE,source_sha=args.source_commit,job_token=args.job_token,kernel_build=receipt,
        kernel_config=s.read(config,262144).decode(),diagnostic_kernel=profile,controller=actor,producer_cleanup='PENDING')
    shutil.copyfile(args.runner/'controller.log',args.output/'controller.log')
    report['controller_runtime_status']=original
    if failure:report.update(status='FAIL',controller_failure=failure)
    elif actor['exit']==0 and original==PASS:report['status']=AWAITING
    else:report['status']='FAIL'
    s.save(path,report);return report


def finalize(args):
    report=json.loads(s.read(args.output/'runtime.json'));base=json.loads(s.read(args.base_dir/'report.json',512*1024))
    try:
        cleanup=base['owned_cleanup'];actor=report['controller']
        s.need(report['status']==AWAITING and report['controller_runtime_status']==PASS and
               report['job_token']==args.job_token==base['ownership']['token'] and actor['exit']==0 and
               actor['natural_exit'] is True and actor['group_absent'] is True and
               len(report['cleanup'])==14 and all(row.get('exit',0)==0 for row in report['cleanup']) and
               any(row.get('guest_disk_removed') is True for row in report['cleanup']) and
               report['base_reference_cleanup']['ok'] is True and cleanup['status']=='PASS' and
               cleanup['probe']['absence_verified'] is True and cleanup['image']['absence_verified'] is True and
               cleanup['image']['id']==report['base_image'],'ordered GUI/producer retirement required')
        ordinary(args.runner);work=ordinary(args.kernel_work)
        s.need(args.runner==Path(os.environ['RUNNER_TEMP'])/'managed-gui16k-runner' and
               work==Path(os.environ['RUNNER_TEMP'])/'managed-gui16k-kernel' and
               Path(report['kernel_build']['helper']['path'])==work/'helper/build_kernel.py','completed owned kernel work required')
        image=args.runner/'diagnostic.Image'
        s.need(s.sha(s.read(image,256*1024**2))==report['diagnostic_kernel']['Image']['sha256'],'completed kernel copy identity differs')
        shutil.rmtree(work);s.need(not work.exists(),'owned kernel work remains')
        image.unlink();s.need(not image.exists(),'copied runtime Image remains')
        report.update(status=FINAL,producer_cleanup=cleanup,kernel_work_removed=True,runtime_Image_removed=True,
            hardware='NOT_RUN',graphics_acceleration='NOT_RUN',visual_review='NOT_RUN',release_admission=False)
    except BaseException as error:report.update(status='FAIL',finalize_error=dict(type=type(error).__name__,reason=str(error)[:512]))
    s.save(args.output/'runtime.json',report);return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('mode',choices=('trial','finalize'))
    for name in ('source','runner','base-dir','output','kernel-work'):parser.add_argument('--'+name,type=Path,required=True)
    for name in ('kernel-receipt','proof','manifest'):parser.add_argument('--'+name,type=Path)
    parser.add_argument('--source-commit');parser.add_argument('--job-token',required=True);parser.add_argument('--execute',action='store_true')
    args=parser.parse_args()
    def interrupted(*_):raise KeyboardInterrupt('owned GUI16K adapter interrupted')
    signal.signal(signal.SIGTERM,interrupted)
    result=trial(args) if args.mode=='trial' else finalize(args)
    print(json.dumps(dict(status=result['status'],scope=s.SCOPE)))
    raise SystemExit(result['status']=='FAIL')

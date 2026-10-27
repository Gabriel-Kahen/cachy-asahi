#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Held source proof, consumer retirement, original574 cleanup, finite export."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
import closed as C


def prove(root,output):
    m=C.verify(root);caller=C.load(root/'scripts/ci/welcome-native/ci/caller.py','held_source_caller')
    result=caller.prove(root,m,os.environ)
    result['manifest_sha256']=C.digest(root/C.MANIFEST)
    result['consumer_token']=hashlib.sha256(('setup8-real-shells:'+result['run_id']+':'+result['run_attempt']+':'+result['source_sha']).encode()).hexdigest()[:32]
    C.save(output,result)
    return result


def cleanup(root,base,runtime,proof_path,output):
    proof=json.loads(C.read(proof_path));C.verify(root,proof['manifest_sha256']);held=C.held_job(root)
    result=dict(status='FAIL',consumer='NOT_OBSERVED',producer='NOT_RETIRED')
    try:
        result['consumer']=held.retire_consumers(runtime,base,proof)
        if (base/'report.json').exists():
            row=held.invoke(['python3','-I','-B',str(root/'scripts/ci/maintained_desktop574.py'),'cleanup','--inputs',str(root/'scripts/ci/maintained-desktop574-inputs.json'),'--output',str(base),'--job-token',proof['job_token']])
            C.need(row.returncode==0,'held original574 cleanup failed; preserve unknown ownership')
            result['producer']=json.loads(C.read(base/'report.json'))['owned_cleanup']
            C.need(result['producer']['status']=='PASS','producer retirement unverified')
        else:result['producer']='NOT_STARTED'
        result['status']='PASS_ORDERED_CONSUMER_THEN_PRODUCER_CLEANUP'
    except Exception as error:result.update(error_type=type(error).__name__,error=str(error)[:512])
    C.save(output,result);return result


def retain(root,base,runtime,proof_path,cleanup_path,output):
    C.need(not output.exists(),'fresh finite export required');output.mkdir(mode=0o755)
    result=dict(status='FAIL_OR_INCOMPLETE',files={},errors=[],total_bytes=0,actual_source=None,actual_ref=None,actual_run=None,physical_M2='NOT_RUN',signed_release='NOT_RUN')
    def copy(path,name,cap=16*1024**2):
        try:
            raw=C.read(path,cap);C.need(len(result['files'])<320 and result['total_bytes']+len(raw)<=96*1024**2,'closed export count/byte cap')
            target=output/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
            result['files'][name]=C.pin(raw);result['total_bytes']+=len(raw)
        except Exception as error:result['errors'].append(name+': '+str(error)[:160])
    proof=json.loads(C.read(proof_path));m=C.verify(root,proof['manifest_sha256'])
    copy(proof_path,'source-proof.json');copy(cleanup_path,'ordered-cleanup.json')
    # Retain all source and explicitly classified154 DATA, never image/rootfs/dependency cache.
    for name in sorted(C.files(root)):copy(root/name,'source/'+name)
    for name in ('report.json','installed-packages.lock','retained-inputs.json'):copy(base/name,'base/'+name)
    for name in ('owner.json','command.json','report.json','lifecycle.stdout','lifecycle.stderr'):copy(runtime/name,'runtime/'+name)
    native=runtime/'native'
    for name in ('native-report.json','trial.json','reinstall.json','adopted-reaping.json','alpm-observations.json','user-profiles.tar.xz','user-profile-xattrs.json','pacman.conf'):
        copy(native/name,'native/'+name,32*1024**2 if name.endswith('.xz') else 16*1024**2)
    for component in m['components']:
        for suffix in ('-build.stdout','-build.stderr'):copy(native/(component+suffix),'native/'+component+suffix)
    for phase in ('install','repeat-install','remove','reinstall','final-remove'):
        for suffix in ('.stdout','.stderr'):copy(native/(phase+suffix),'native/'+phase+suffix)
    try:
        raw=json.loads(C.read(native/'native-report.json'));run=C.load(C.HERE/'run.py','real_shell_result_gate');run.validate(raw)
        for row in raw['builds']:
            n=row['archive'];C.need(not Path(n).is_absolute() and '..' not in Path(n).parts,'safe built archive reference required')
            copy(native/n,'native/'+n,8*1024**2);C.need(result['files']['native/'+n]['sha256']==row['sha256'],'native package archive hash differs')
        ordered=json.loads(C.read(cleanup_path));owner=json.loads(C.read(runtime/'owner.json'));producer=json.loads(C.read(base/'report.json'));consumer=json.loads(C.read(runtime/'report.json'))
        C.need(producer['status']=='PASS_NATIVE_OFFLINE_574_TRANSACTION' and producer['ownership']['token']==proof['job_token'] and producer['owned_cleanup']['status']=='PASS' and producer['owned_cleanup']['image']==dict(id=producer['image'],absence_verified=True),'fresh producer/source/retirement join differs')
        C.need(consumer['status']=='PASS_FINITE_NATIVE_REAL_SHELLS_PENDING_ORDERED_RETIREMENT' and consumer['image']==producer['image']==owner['image'] and consumer['ownership_token']==proof['consumer_token']==owner['token'] and consumer['base_lock_sha256']==C.digest(base/'installed-packages.lock'),'consumer image/ownership join differs')
        C.need(ordered['status']=='PASS_ORDERED_CONSUMER_THEN_PRODUCER_CLEANUP' and ordered['consumer']['status']=='PASS_CONSUMERS_RETIRED' and len(owner['containers'])==len(ordered['consumer']['containers'])==1 and ordered['consumer']['containers'][0]['container']==owner['containers'][0] and ordered['consumer']['containers'][0]['absence_verified'] is True and ordered['producer']==producer['owned_cleanup'],'one consumer then producer retirement required')
        reaping=json.loads(C.read(native/'adopted-reaping.json'));C.need(len(reaping)==10 and C.digest(native/'adopted-reaping.json')==raw['adopted_reaping_sha256'],'eight completed builds and two ordinary trials require adopted-child drain receipts')
        observations=json.loads(C.read(native/'alpm-observations.json'));C.need(len(observations)==5 and all(r['preserved'] is True and r['user_before']==r['user_after'] for r in observations) and [len(r['inventory']) for r in observations]==[583,583,574,583,574] and C.digest(native/'alpm-observations.json')==raw['alpm_observations_sha256'],'retained five-phase inventory/user/payload observations differ')
        C.need(C.digest(native/'user-profiles.tar.xz')==raw['user_archive']['sha256'] and C.digest(native/'user-profile-xattrs.json')==raw['user_xattrs_sha256'],'retained raw user state archive/xattrs join differs')
        C.need(not result['errors'],'finite retention incomplete')
        result['status']='PASS_FINITE_NATIVE_REAL_SHELLS_RETIRED'
    except Exception as error:result['errors'].append(str(error)[:512])
    C.save(output/'retention.json',result);return result


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('phase',choices=('proof','cleanup','retain'))
    for n in ('source','base','runtime','proof','cleanup','output'):p.add_argument('--'+n,type=Path)
    a=p.parse_args();root=C.safe(a.source.absolute())
    if a.phase=='proof':value=prove(root,a.proof.absolute())
    elif a.phase=='cleanup':value=cleanup(root,a.base.absolute(),a.runtime.absolute(),a.proof.absolute(),a.output.absolute())
    else:value=retain(root,a.base.absolute(),a.runtime.absolute(),a.proof.absolute(),a.cleanup.absolute(),a.output.absolute())
    print(json.dumps(value,indent=2));raise SystemExit(value['status'] not in ('SOURCE_PROOF_PASS','PASS_ORDERED_CONSUMER_THEN_PRODUCER_CLEANUP','PASS_FINITE_NATIVE_REAL_SHELLS_RETIRED'))

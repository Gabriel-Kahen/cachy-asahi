#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Root-only offline preparation; no implicit preparation or boot invocation."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import sys
import time

HERE=Path(__file__).resolve().parent


def module(name):
    spec=importlib.util.spec_from_file_location('stage0_prepare_'+name,HERE/(name+'.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m


def arguments(parser):
    for name in ('base','base-first-boot-report','materials','kernel-bundle','qemu-metadata','guest-inputs','publication','authority','output'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--authority-sha256',required=True)


def main():
    p=argparse.ArgumentParser(description=__doc__);arguments(p);p.add_argument('--allow-prepare',action='store_true');a=p.parse_args()
    if not (a.allow_prepare and sys.flags.isolated and sys.dont_write_bytecode and not sys.flags.optimize):p.error('explicit Root preparation with python -I -B required')
    started=time.monotonic();K,R=module('contracts'),module('runtime');K.END=started+555
    auth,base,reference,kernel,tool,spec,guest=K.preflight(a,'prepare')
    # Every missing/null/publication/Root/resource/material/guest-input gate above
    # precedes output creation, any daemon query, raw clone or actor submission.
    out=a.output;os.umask(0o077);out.mkdir(mode=0o700);inputs=out/'inputs';inputs.mkdir(mode=0o700);work=out/'actor-work';work.mkdir(mode=0o700)
    manifest=dict(operation=K.OP,work_deadline_monotonic=started+555,authority=auth,source_lock=K.source(),base_files=reference['files'],original_marker=reference['original_marker'],kernel_bundle=kernel,qemu_metadata=tool,archives=spec['archives'],guest_inputs=guest)
    (inputs/'input-manifest.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
    B=K.helper('reference_controller.py');state=B.Cancellation();scope=None
    report=dict(status='HOLD',operation=K.OP,VM_boot='NOT RUN',native16K='UNQUALIFIED',M2='UNQUALIFIED',release='UNQUALIFIED');deadline=started+555
    def cmd(label,argv,seconds=30):return R.command(argv,out,label,seconds,deadline)
    state.__enter__();route=R.transport(auth);route_entered=False
    try:
        route.__enter__();route_entered=True
        security=json.loads(cmd('rootless',['docker','info','--format','{{json .SecurityOptions}}']))
        K.need('name=rootless' in security,'qualified rootless owner daemon required')
        image=json.loads(cmd('image',['docker','image','inspect',K.IMAGE]))[0];K.need(image['Id']==K.IMAGE,'exact qualified owner image required')
        name='cachy-rust16k-prepare-'+secrets.token_hex(12);labels=dict(image['Config'].get('Labels') or {});labels.update({'org.cachy-asahi.rust16k-owner':str(os.getuid()),'org.cachy-asahi.rust16k-operation':name})
        mounts=[('bind',str(a.base),'/base',False),('bind',str(a.materials),'/materials',False),('bind',str(a.kernel_bundle),'/kernel',False),('bind',str(HERE),'/code',False),('bind',str(inputs),'/inputs',False),('bind',str(work),'/work',True)]
        class Scope(B.OwnedContainer):
            def call(self,argv,limit):
                return R.docker_call(argv,self.out,limit,shared_deadline=started+(597 if state.cleaning else 555),defer_cancel=state.cleaning)
            def validate(self,row):
                K.need(row['Name']=='/'+name and row['Image']==K.IMAGE and row['Config']['Labels']==labels and row['Config']['Entrypoint']==['/usr/bin/python3'] and row['Config']['Cmd']==['-I','-B','/code/prepare_image.py'],'fixed owned preparation identity')
                K.need(len(row['Mounts'])==len(mounts) and {(x['Type'],x['Source'],x['Destination'],x['RW']) for x in row['Mounts']}==set(mounts),'exact preparation mounts')
                h=row['HostConfig'];K.need(h['NetworkMode']=='none' and h['ReadonlyRootfs'] is True and h['CapDrop']==['ALL'] and not h.get('CapAdd') and not h['Privileged'] and not h['Devices'] and h['Init'] is True and h['SecurityOpt']==['no-new-privileges'] and h['Memory']==h['MemorySwap']==3*K.GIB and h['NanoCpus']==2000000000 and h['PidsLimit']==256,'finite cap0 preparation domain')
        scope=Scope(name,out/'prepare.cid',K.IMAGE,labels,a.base,out);K.need(scope.listing(time.monotonic()+8) is None,'fresh owned preparation name')
        argv=['docker','create','--cidfile',str(scope.cidfile),'--name',name,'--init','--pull=never','--read-only','--network=none','--cap-drop=ALL','--security-opt=no-new-privileges','--cpus=2','--memory=3g','--memory-swap=3g','--pids-limit=256','--tmpfs','/tmp:rw,nodev,nosuid,noexec,size=32m']
        for key,value in labels.items():argv+=['--label',key+'='+value]
        for kind,source,target,rw in mounts:argv+=['--mount','type='+kind+',source='+source+',target='+target+('' if rw else ',readonly')]
        argv+=['--env','CACHY_RUST_STAGE0_PREPARE=1','--entrypoint','/usr/bin/python3',K.IMAGE,'-I','-B','/code/prepare_image.py']
        scope.submitted=True;cmd('create',argv);scope.recover(time.monotonic()+8);cmd('offline-prepare',['docker','start','-a',name],570)
        terminal=scope.recover(time.monotonic()+8);K.need(terminal['State']['ExitCode']==0 and terminal['State']['OOMKilled'] is False and terminal['State']['Running'] is False,'natural offline container completion')
        assembly=work/'assembly';prepared=K.load(assembly/'prepared.json')
        K.need(prepared['operation']==K.OP and prepared['source_lock']==K.source() and prepared['nonce']!=base['nonce'] and prepared['baseline_nonce']==base['nonce'],'distinct fresh extension with retained PAM nonce')
        for n,row in prepared['files'].items():K.checked(assembly/n,row)
        K.checked(assembly/'ownership.json',prepared['ownership'])
        shutil.copy2(a.base/'credentials.json',assembly/'credentials.json');(assembly/'credentials.json').chmod(0o600);K.checked(assembly/'credentials.json',auth['credentials'])
        K.baseline(a.base,a.base_first_boot_report)
        report.update(status='PREPARED_NOT_BOOTED',assembly=str(assembly),prepared=K.pin(assembly/'prepared.json'))
    except BaseException as error:report['failure']=dict(category=type(error).__name__,message=str(error)[:1024])
    finally:
        state.cleaning=True;K.END=started+600
        try:
            if scope is not None:scope.cleanup(report)
        except BaseException as error:report.setdefault('cleanup_errors',[]).append(dict(step='owned-container-cleanup',category=type(error).__name__,message=str(error)[:1024]))
        finally:
            if state.pending or report.get('cleanup_errors') or not report.get('owned_container_absence_verified'):report['status']='HOLD_CLEANUP_OR_CANCELLED'
            try:(out/'preparation.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
            finally:
                try:
                    if route_entered:route.__exit__(None,None,None)
                finally:state.__exit__()
    return 0 if report['status']=='PREPARED_NOT_BOOTED' else 1


if __name__=='__main__':raise SystemExit(main())

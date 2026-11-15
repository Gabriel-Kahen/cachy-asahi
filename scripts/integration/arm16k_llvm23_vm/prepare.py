#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Separate Root-authorized offline preparation; never boots or installs a package."""
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


def ops():
    s=importlib.util.spec_from_file_location('llvm23_host_prepare_ops',HERE/'ops.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m


def execute(a,T):
    # Preflight performs every Root/source/package/Reader/runtime/resource gate
    # before this function creates output or queries the selected daemon.
    ctx=T.preflight(a,'prepare');K,R,B,O,D=T.modules();limits=ctx['limits']
    cleanup_end=ctx['final_deadline']
    K.need(type(ctx['deadline'])is type(cleanup_end)is int and time.monotonic()<ctx['deadline']<cleanup_end,'original finite Root phase deadlines')
    out=K.ordinary(a.output)
    K.need(not out.exists() and out.parent.is_dir() and out.parent.stat().st_uid==os.getuid() and not out.parent.stat().st_mode&0o022,'fresh owned private preparation output')
    paths={k:K.ordinary(ctx['paths'][k])for k in('base','materials','kernel_bundle','packet')}
    K.need(all(not(out==p or out in p.parents or p in out.parents)for p in(*paths.values(),HERE)),'preparation output disjoint from inputs/Source')
    os.umask(0o077);out.mkdir(mode=0o700);inputs=out/'inputs';work=out/'actor-work';inputs.mkdir(mode=0o700);work.mkdir(mode=0o700)
    (inputs/'input-manifest.json').write_bytes(K.canonical(dict(ctx=ctx,phase='prepare',deadline=ctx['deadline'])))
    guard=None;state=B.Cancellation();scope=None;entered=False
    report=dict(status='HOLD',operation=K.OP,VM='NOT RUN',ALPM='NOT RUN',compiler='NOT RUN',Root_acceptance=None)
    route=R.transport(ctx['authority'],deadline=ctx['deadline']);state.__enter__()
    previous_guard=getattr(R,'LIVE_GUARD',None)
    def observe():
        if guard is None:return
        if not state.cleaning:guard();return
        try:guard()
        except BaseException as error:
            if not report.get('cleanup_guard_failure'):
                report['cleanup_guard_failure']=dict(category=type(error).__name__,message=str(error)[:512])
    def cmd(label,argv,**kw):
        observe();end=cleanup_end if state.cleaning else ctx['deadline']
        result=R.command(argv,out,label,max(1,end-time.monotonic()),end,defer_cancel=state.cleaning,**kw);observe();return result
    try:
        guard=T.guard(ctx,out);R.LIVE_GUARD=observe;guard()
        route.__enter__();entered=True
        K.need('name=rootless'in json.loads(cmd('rootless',['docker','info','--format','{{json .SecurityOptions}}'])),'actual selected rootless daemon')
        image_id=ctx['tool']['image_id'];image=json.loads(cmd('image',['docker','image','inspect',image_id]))[0]
        K.need(image['Id']==image_id,'exact Root-qualified tool image')
        name='cachy-llvm23-prepare-'+secrets.token_hex(12);labels=dict(image['Config'].get('Labels')or{})
        labels.update({'org.cachy-asahi.llvm23-owner':str(os.getuid()),'org.cachy-asahi.llvm23-operation':name})
        mounts=[('bind',str(paths['base']/'guest.raw'),'/base/guest.raw',False),('bind',str(paths['base']/'prepared.json'),'/base/prepared.json',False),
                ('bind',str(paths['kernel_bundle']),'/kernel',False),('bind',str(paths['packet']),'/packet',False),
                ('bind',str(inputs),'/inputs',False),('bind',str(HERE),'/code',False),('bind',str(work),'/work',True)]
        actor= T.load('prepare_image')
        mounts += [('bind',str(paths['materials']/leaf),'/materials/'+leaf,False)for leaf in actor.MATERIALS.values()]
        temporary='/tmp:rw,nodev,nosuid,noexec,size='+str(limits['logs_cap_bytes'])
        class Scope(B.OwnedContainer):
            def call(self,argv,deadline):
                observe();value=R.docker_call(argv,self.out,deadline,shared_deadline=cleanup_end if state.cleaning else ctx['deadline'],defer_cancel=state.cleaning);observe();return value
            def validate(self,row):
                K.need(row['Name']=='/'+name and row['Image']==image_id and row['Config']['Labels']==labels and row['Config']['User']=='0:0' and row['Config']['Entrypoint']==['/usr/bin/python3'] and row['Config']['Cmd']==['-I','-B','/code/prepare_image.py'],'exact owned offline actor identity')
                K.need(len(row['Mounts'])==len(mounts) and {(x['Type'],x['Source'],x['Destination'],x['RW'])for x in row['Mounts']}==set(mounts),'exact credential-free eleven preparation mounts')
                h=row['HostConfig'];K.need(h['ReadonlyRootfs']is True and h['NetworkMode']=='none' and h['CapDrop']==['ALL'] and not h.get('CapAdd') and not h['Privileged'] and not h['Devices'] and not h.get('DeviceRequests') and h.get('PidMode','')!='host' and h.get('IpcMode','')!='host' and h['Init']is True and h['SecurityOpt']==['no-new-privileges'] and h['Memory']==h['MemorySwap']==limits['owner_memory_bytes'] and h['NanoCpus']==limits['cpus']*10**9 and h['PidsLimit']==limits['pids'],'actual finite Root-selected cap0/no-swap preparation domain')
        scope=Scope(name,out/'prepare.cid',image_id,labels,paths['base'],out)
        K.need(scope.listing(min(ctx['deadline'],time.monotonic()+8))is None,'fresh preparation actor name')
        argv=['docker','create','--cidfile',str(scope.cidfile),'--name',name,'--user','0:0','--init','--pull=never','--read-only','--network=none','--cap-drop=ALL','--security-opt=no-new-privileges','--cpus='+str(limits['cpus']),'--memory='+str(limits['owner_memory_bytes']),'--memory-swap='+str(limits['owner_memory_bytes']),'--pids-limit='+str(limits['pids']),'--tmpfs',temporary]
        for k,v in labels.items():argv+=['--label',k+'='+v]
        for kind,source,target,rw in mounts:argv+=['--mount','type='+kind+',source='+source+',target='+target+(''if rw else',readonly')]
        argv+=['--env','CACHY_LLVM23_PREPARE=1','--entrypoint','/usr/bin/python3',image_id,'-I','-B','/code/prepare_image.py']
        scope.submitted=True;cmd('create',argv);scope.recover(min(ctx['deadline'],time.monotonic()+8))
        cmd('offline-prepare',['docker','start','-a',name])
        terminal=scope.recover(min(ctx['deadline'],time.monotonic()+8))
        K.need(terminal['State']['ExitCode']==0 and terminal['State']['OOMKilled']is False and terminal['State']['Running']is False,'natural successful preparation retirement')
        assembly=work/'assembly';prepared=K.load(assembly/'prepared.json',64*1024**2)
        K.need(prepared['status']=='PREPARED_LLVM23_IMAGE_NOT_BOOTED' and prepared['source_lock']==ctx['source_lock'] and prepared['nonce']==ctx['nonce'] and prepared['baseline_nonce']==ctx['base']['nonce'],'exact Root packet/prepared/original PAM lineage')
        K.need(set(prepared['files'])=={'guest.raw','Image','kernel.config'},'exact prepared output files')
        for n,row in prepared['files'].items():K.need(K.pin(assembly/n,row['bytes'])==row,'prepared whole output pin')
        K.need(K.pin(assembly/'ownership.json',64*1024**2)==prepared['ownership'],'whole preparation ownership report')
        observe();T.recheck(ctx);observe()
        credentials=paths['base']/'credentials.json';expected=ctx['authority']['credentials']
        K.need(K.pin(credentials)==expected and credentials.stat().st_uid==os.getuid() and credentials.stat().st_mode&0o777==0o600,'exact private original PAM credentials, host only')
        shutil.copy2(credentials,assembly/'credentials.json');(assembly/'credentials.json').chmod(0o600)
        K.need(K.pin(assembly/'credentials.json')==expected,'private host-only credential copy differs')
        observe()
        report.update(status='PREPARED_LLVM23_IMAGE_NOT_BOOTED',assembly=str(assembly),prepared=K.pin(assembly/'prepared.json',64*1024**2))
    except BaseException as error:report['failure']=dict(category=type(error).__name__,message=str(error)[:1024])
    finally:
        state.cleaning=True
        ctx['active_deadline']=cleanup_end
        try:
            if scope is not None:T.load('boot').cleanup_owned(scope,report,cleanup_end)
        except BaseException as error:report.setdefault('cleanup_errors',[]).append(dict(step='owned-container-cleanup',category=type(error).__name__,message=str(error)[:1024]))
        finally:
            if state.pending or report.get('cleanup_errors') or report.get('cleanup_guard_failure') or not report.get('owned_container_absence_verified'):report['status']='HOLD_CLEANUP_OR_CANCELLED'
            try:
                if callable(getattr(guard,'close',None)):guard.close()
            finally:
                R.LIVE_GUARD=previous_guard
                (out/'preparation.json').write_bytes(K.canonical(report))
                try:
                    if entered:route.__exit__(None,None,None)
                finally:state.__exit__()
    return report


def main():
    T=ops();p=argparse.ArgumentParser(description=__doc__);T.arguments(p);p.add_argument('--allow-prepare',action='store_true');a=p.parse_args()
    T.load('contracts').need(a.allow_prepare and sys.flags.isolated and sys.dont_write_bytecode and __debug__ and os.getuid()==os.geteuid()!=0,'explicit ordinary isolated preparation authority')
    report=execute(a,T);print(json.dumps(report,sort_keys=True));return 0 if report['status']=='PREPARED_LLVM23_IMAGE_NOT_BOOTED'else 1


if __name__=='__main__':raise SystemExit(main())

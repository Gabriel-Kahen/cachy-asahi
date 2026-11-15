#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Separate explicit Root boot; preparation never calls this operational entry."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import sys
import tempfile
import time

HERE=Path(__file__).resolve().parent


def module(name):
    s=importlib.util.spec_from_file_location('rust_stage0_boot_'+name,HERE/(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m


def main():
    parser=argparse.ArgumentParser(description=__doc__);module('prepare').arguments(parser)
    parser.add_argument('--prepared',type=Path,required=True);parser.add_argument('--prepared-sha256',required=True);parser.add_argument('--allow-boot',action='store_true');a=parser.parse_args()
    if not(a.allow_boot and sys.flags.isolated and sys.dont_write_bytecode and not sys.flags.optimize):parser.error('explicit Root boot with python -I -B required')
    started=time.monotonic();K,R,P=module('contracts'),module('runtime'),module('protocol');K.END=started+555
    auth,base,reference,kernel,tool,spec,guest=K.preflight(a,'boot')
    source=K.ordinary(a.prepared);K.need(source!=a.output and source not in a.output.parents and a.output not in source.parents,'prepared inputs and output must be disjoint');K.need(K.pin(source/'prepared.json')['sha256']==a.prepared_sha256 and auth['prepared']==K.pin(source/'prepared.json'),'Root must select exact new prepared clone')
    m=K.load(source/'prepared.json')
    K.need(m['status']=='PREPARED_NOT_BOOTED' and m['operation']==K.OP and m['source_lock']==K.source() and m['kernel_bundle']==kernel and m['qemu_metadata']==tool and m['base_files']==reference['files'] and m['original_marker']==reference['original_marker'] and m['baseline_nonce']==base['nonce'] and re.fullmatch('[0-9a-f]{32}',m['nonce']) and m['nonce']!=m['baseline_nonce'],'exact fresh prepared lineage')
    K.need(set(m['files'])=={'guest.raw','Image','kernel.config'},'exact prepared file membership required')
    for name,row in m['files'].items():K.checked(source/name,row)
    K.checked(source/'ownership.json',m['ownership']);K.checked(source/'credentials.json',auth['credentials'])
    secret=K.load(source/'credentials.json',4096);K.need(secret['username']=='builder' and re.fullmatch('[A-Za-z0-9_-]{24,128}',secret['password']),'private original PAM login credentials')
    for name in ('guest.raw','Image','kernel.config'):K.need(name in m['files'],'complete prepared immutable input files')
    K.need(m['files']['Image']==kernel['files']['Image'] and m['files']['kernel.config']==kernel['files']['config'] and m['raw_logical_bytes']==m['files']['guest.raw']['bytes']==reference['files']['guest.raw']['bytes'] and m['raw_logical_bytes']<=K.RESOURCES['raw_cap_bytes'],'exact RTC kernel and raw cap')
    # No daemon/clone/actor before all Root/publication/material/source/credential checks.
    out=a.output;os.umask(0o077);out.mkdir(mode=0o700);deadline=started+555
    marker=source/'rust-stage0-attempt.json'
    with marker.open('x') as stream:json.dump(dict(operation=K.OP,nonce=m['nonce'],prepared_sha256=a.prepared_sha256,authority_sha256=a.authority_sha256),stream)
    B=K.helper('reference_controller.py');state=B.Cancellation();scope=None;serial=qmp=qfile=None
    report=dict(status='HOLD',operation=K.OP,scope='emulated ARM16K Rust1.98 stage0 software fixture only',native16K='UNQUALIFIED',M2='UNQUALIFIED',performance='NOT MEASURED',release='UNQUALIFIED',guest_shutdown='NOT QUALIFIED; QMP emulator quit after normal PAM logout')
    def cmd(label,argv,seconds=20):return R.command(argv,out,label,seconds,deadline)
    state.__enter__();route=R.transport(auth);route_entered=False
    try:
        route.__enter__();route_entered=True
        K.need('name=rootless' in json.loads(cmd('rootless',['docker','info','--format','{{json .SecurityOptions}}'])),'qualified rootless owner daemon required')
        image=json.loads(cmd('image',['docker','image','inspect',K.IMAGE]))[0];K.need(image['Id']==K.IMAGE,'exact tool image required')
        name='cachy-rust16k-'+secrets.token_hex(12);labels=dict(image['Config'].get('Labels') or {});labels.update({'org.cachy-asahi.rust16k-owner':str(os.getuid()),'org.cachy-asahi.rust16k-nonce':m['nonce'],'org.cachy-asahi.rust16k-input':a.prepared_sha256})
        mounts={('bind',str(source),'/inputs',False),('bind',str(HERE),'/code',False),('bind',str(out),'/work',True)}
        class Scope(B.OwnedContainer):
            def call(self,argv,limit):
                return R.docker_call(argv,self.out,limit,shared_deadline=started+(597 if state.cleaning else 555),defer_cancel=state.cleaning)
            def validate(self,row):
                K.need(row['Name']=='/'+name and row['Image']==K.IMAGE and row['Config']['Labels']==labels and row['Config']['Entrypoint']==['/usr/bin/python3'] and row['Config']['Cmd']==['-I','-B','/code/vm_actor.py'],'exact new Rust VM actor identity')
                K.need(len(row['Mounts'])==3 and {(x['Type'],x['Source'],x['Destination'],x['RW']) for x in row['Mounts']}==mounts,'exact Rust VM actor mounts')
                h=row['HostConfig'];K.need(h['ReadonlyRootfs'] is True and h['NetworkMode']=='none' and h['CapDrop']==['ALL'] and not h.get('CapAdd') and not h['Privileged'] and not h['Devices'] and h['Init'] is False and h['SecurityOpt']==['no-new-privileges'] and h['Memory']==h['MemorySwap']==3*K.GIB and h['NanoCpus']==2000000000 and h['PidsLimit']==256,'actual finite software-VM domain required')
        scope=Scope(name,out/'container.cid',K.IMAGE,labels,source,out);K.need(scope.listing(time.monotonic()+8) is None,'fresh owned boot name required')
        (out/'host-epoch.json').write_text(json.dumps(dict(nonce=m['nonce'],utc_ns=time.time_ns(),monotonic_ns=time.monotonic_ns(),deadline_monotonic=started+555))+'\n')
        argv=['docker','create','--cidfile',str(scope.cidfile),'--name',name,'--init=false','--pull=never','--read-only','--network=none','--cap-drop=ALL','--security-opt=no-new-privileges','--cpus=2','--memory=3g','--memory-swap=3g','--pids-limit=256','--tmpfs','/tmp:rw,nodev,nosuid,noexec,size=32m']
        for key,value in labels.items():argv+=['--label',key+'='+value]
        for kind,src,target,rw in sorted(mounts):argv+=['--mount','type='+kind+',source='+src+',target='+target+('' if rw else ',readonly')]
        argv+=['--env','CACHY_RUST_STAGE0_BOOT=1','--entrypoint','/usr/bin/python3',K.IMAGE,'-I','-B','/code/vm_actor.py']
        scope.submitted=True;cmd('create',argv);observed=scope.recover(time.monotonic()+8);report['container_id']=observed['Id'];report['runtime']=observed['HostConfig'];cmd('start',['docker','start',name])
        with tempfile.TemporaryDirectory(prefix='rust16k-sockets-') as short:
            link=Path(short)/'out';link.symlink_to(out,target_is_directory=True)
            for node in ('serial.sock','qmp.sock'):
                until=min(deadline,time.monotonic()+15)
                while not(out/node).exists() and time.monotonic()<until:time.sleep(.05)
                st=(out/node).lstat();K.need(stat.S_ISSOCK(st.st_mode) and st.st_uid==os.getuid(),'owned VM Unix sockets required')
            qmp=socket.socket(socket.AF_UNIX);qmp.settimeout(5);qmp.connect(str(link/'qmp.sock'));qfile=qmp.makefile('rwb',buffering=0)
            def reply():
                line=qfile.readline(65537);K.need(0<len(line)<=65536,'bounded QMP reply');return json.loads(line)
            K.need('QMP' in reply(),'actual QMP greeting required');sequence=0
            def rpc(method):
                nonlocal sequence
                K.need(method in ('qmp_capabilities','quit'),'fixed QMP capabilities/quit only');sequence+=1;ident='rust16k-'+str(sequence)
                qfile.write(json.dumps(dict(execute=method,id=ident)).encode()+b'\n')
                for _ in range(64):
                    row=reply()
                    if row.get('id')==ident:K.need('error' not in row,'QMP request failed');return
                raise ValueError('bounded matching QMP response absent')
            rpc('qmp_capabilities');stream=socket.socket(socket.AF_UNIX);stream.connect(str(link/'serial.sock'));serial=B.Serial(stream,deadline-20)
            report.update(P.journey(serial,secret['password'],m['baseline_nonce'],m['nonce'],B.parse_frame))
            rpc('quit');report['QMP_quit_requested']=True
        cmd('normal-container-wait',['docker','wait',name]);finished=scope.recover(time.monotonic()+8)
        K.need(finished['State']['ExitCode']==0 and finished['State']['OOMKilled'] is False and finished['State']['Running'] is False,'natural zero-exit owner completion')
        retirement=K.load(out/'qemu-retirement.json');K.need(R.natural(retirement) and not retirement.get('actor_cancelled'),'natural QEMU quit/reap/group absence required');report['QEMU_retirement']=retirement
        epoch=K.load(out/'host-epoch.json')['utc_ns']//10**9
        P.validate(report['rust'],K.pin(HERE/'data/expected111.lock')['sha256'],epoch,int(time.time()))
        preservation=K.load(out/'postboot-preservation.json')
        K.need(preservation['status']=='PASS_COMPLETE_POSTBOOT_PRESERVATION' and preservation['nonce']==m['nonce'] and preservation['source_lock']==m['source_lock'] and preservation['ownership']==m['ownership'] and preservation['packages']==111 and all(preservation.get(k) is True for k in ('all111_unchanged','PAM_boot_unchanged','prefix_unchanged')),'complete post-QMP all111/PAM/prefix preservation required')
        report['postboot_preservation']=preservation
        K.need(K.pin(source/'prepared.json')['sha256']==a.prepared_sha256,'prepared manifest changed during boot')
        for n,row in m['files'].items():K.checked(source/n,row)
        K.baseline(a.base,a.base_first_boot_report)
        report['status']='PASS_EMULATED_ARM16K_RUST_STAGE0_FIXTURE_ONLY'
    except BaseException as error:report['failure']=dict(category=type(error).__name__,message=str(error)[:1024])
    finally:
        state.cleaning=True;K.END=started+600
        try:
            for label,handle in (('serial',serial.stream if serial is not None else None),('qmp-file',qfile),('qmp-socket',qmp)):
                try:
                    if label=='serial' and serial is not None:(out/'serial.redacted.log').write_bytes(bytes(serial.data).replace(secret['password'].encode(),b'[REDACTED TEST PASSWORD]'))
                    if handle is not None:handle.close()
                except BaseException as error:report.setdefault('cleanup_errors',[]).append(dict(step=label,category=type(error).__name__,message=str(error)[:1024]))
        finally:
            try:
                if scope is not None:scope.cleanup(report)
            except BaseException as error:report.setdefault('cleanup_errors',[]).append(dict(step='owned-container-cleanup',category=type(error).__name__,message=str(error)[:1024]))
            finally:
                if state.pending or report.get('cleanup_errors') or not report.get('owned_container_absence_verified'):report['status']='HOLD_CLEANUP_OR_CANCELLED'
                try:(out/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
                finally:
                    try:
                        if route_entered:route.__exit__(None,None,None)
                    finally:state.__exit__()
    return 0 if report['status']=='PASS_EMULATED_ARM16K_RUST_STAGE0_FIXTURE_ONLY' else 1


if __name__=='__main__':raise SystemExit(main())

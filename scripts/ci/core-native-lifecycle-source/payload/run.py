#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Future exact-image lifecycle owner. UNBOUND policy refuses before any actor."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import signal
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as C


def inspect(name,command):
    row=command(['/usr/bin/docker','container','inspect',name],allow_failure=True)
    if row['code']:
        text=(row['out']+row['err']).decode(errors='replace').lower()
        C.need(row['code']==1 and name.lower() in text and ('no such container' in text or 'no such object' in text),'unknown container absence')
        return None
    values=json.loads(row['out']);C.need(len(values)==1,'one container identity');return values[0]


def owned(value,name,image,token):
    C.need(value['Name']=='/'+name and value['Image']==image and value['Config']['Labels'].get(C.LABEL)==token and re.fullmatch('[0-9a-f]{64}',value['Id']),'foreign container preserved')
    return value['Id']


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('inputs','source-root','held-root','output'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--apparmor-state',type=Path,required=True)
    parser.add_argument('--input-sha256',required=True);args=parser.parse_args()
    index,_,_,_=C.configuration(args.inputs,args.input_sha256)  # No mkdir, Docker or mutation before accepted gates.
    C.need(not any(n.startswith(('DOCKER_','LD_')) for n in os.environ),'daemon/loader overrides refused')
    for path in (args.inputs,args.source_root,args.held_root,args.output.parent):
        C.need(path.is_absolute() and path.is_dir() and not any(p.is_symlink() for p in (path,*path.parents)) and ',' not in str(path),'ordinary explicit source/output paths')
    C.need(args.held_root!=Path('/') and not args.output.exists() and not any(args.output.is_relative_to(p) or p.is_relative_to(args.output) for p in (args.inputs,args.source_root,args.held_root)),'fresh separate lifecycle output/source')
    C.need(shutil.disk_usage(args.output.parent).free>=20*1024**3,'20GiB isolated root/evidence reserve')
    api=C.helpers(args.source_root)
    apparmor=C.load('trial_apparmor_owner',args.source_root/'scripts/ci/glibc-gnu-trial-apparmor/profile.py')
    profile=apparmor.binding(args.apparmor_state,index['token'],'lifecycle',index['image_id'])
    args.output.mkdir(mode=0o700);private=args.output/'private';private.mkdir(mode=0o700);public=args.output/'public';public.mkdir(mode=0o700)
    lease=os.open(args.output/'lease',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC,0o600);fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
    report=dict(status='FAIL',token=index['token'],image_id=index['image_id'],actors=[],commands=[],source='READONLY_ORIGINAL574',producer_cleanup='ROOT_OWNS_NOT_ATTEMPTED',hardware='NOT_RUN',release_admission=False)
    def save():(args.output/'owner.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    def command(argv,allow_failure=False,seconds=30):
        row,out,err,error=api['runtime'].run_command(argv,args.output,dict(C.ENV,HOME=str(private),TMPDIR=str(private)),seconds,1024**2)
        number=len(report['commands']);report['commands'].append(row);save()
        (public/('owner-command-%03d.stdout'%number)).write_bytes(out)
        (public/('owner-command-%03d.stderr'%number)).write_bytes(err)
        if error:raise error
        C.need(row['group_absence_verified'] and (allow_failure or row['exit_code']==0),'owned command exit/group retirement')
        return dict(code=row['exit_code'],out=out,err=err)
    def launch(role,script,seconds):
        name='caa-glibc-provider-'+index['token']+'-'+role
        C.need(inspect(name,command) is None,'fresh owned actor name')
        actor=dict(role=role,name=name,status='RESERVED',id=None);report['actors'].append(actor);save()
        argv=['/usr/bin/docker','run','--name',name,'--label',C.LABEL+'='+index['token'],'--pull=never','--platform=linux/arm64','--user=0:0','--network=none','--read-only',
            '--cap-drop=ALL','--security-opt=no-new-privileges','--pids-limit=512','--memory=4g','--cpus=2','--ulimit=nofile=8192:8192','--tmpfs=/tmp:rw,nosuid,nodev,size=128m',
            '--env=CACHY_GNU_PROVIDER_LIFECYCLE=1','--env=INPUT_INDEX_SHA256='+args.input_sha256,'--env=OUTPUT_UID='+str(os.getuid()),'--env=OUTPUT_GID='+str(os.getgid()),'--env=PYTHONDONTWRITEBYTECODE=1']
        if role=='trial':argv+=['--security-opt=apparmor='+profile['name'],'--env=GNU_TRIAL_APPARMOR_PROFILE='+profile['name']]
        caps=('CHOWN','DAC_OVERRIDE','FOWNER','FSETID','KILL','SETUID','SETGID','SYS_CHROOT','SYS_ADMIN','SETFCAP') if role=='trial' else ('CHOWN','DAC_OVERRIDE','FOWNER')
        argv+=['--cap-add='+cap for cap in caps]
        mounts=[(args.inputs,'/inputs',True),(args.source_root,'/source',True),(args.held_root,'/held',True),(C.HERE,'/runner',True),(private,'/work',False),(public,'/out',False)]
        for source,target,readonly in mounts:argv+=['--mount','type=bind,src='+str(source)+',dst='+target+(',readonly' if readonly else '')]
        argv+=['--entrypoint=/usr/bin/python3',index['image_id'],'-I','-B','/runner/'+script]
        result=command(argv,allow_failure=True,seconds=seconds)
        observed=inspect(name,command);C.need(observed is not None,'retained actor identity')
        actor.update(id=owned(observed,name,index['image_id'],index['token']),exit=result['code'],status='EXITED');save()
        actor['apparmor']=apparmor.docker_profile(observed,index['token'],'lifecycle',role);save()
        return result
    def retire():
        errors=[]
        for actor in reversed(report['actors']):
            if actor['status']=='PASS_ABSENCE_VERIFIED':continue
            try:
                value=inspect(actor['name'],command)
                if value is not None:
                    cid=owned(value,actor['name'],index['image_id'],index['token']);C.need(actor['id'] in (None,cid),'owned CID drift')
                    actor['id']=cid;save();command(['/usr/bin/docker','rm','--force',cid])
                C.need(inspect(actor['name'],command) is None,'actor remains');actor['status']='PASS_ABSENCE_VERIFIED';save()
            except BaseException as error:actor.update(status='FAIL_OR_UNKNOWN',error=str(error)[:256]);errors.append(actor['name']);save()
        C.need(not errors,'consumer actor retirement unknown; producer must remain')
    error=None
    try:
        save();result=launch('trial','container.py',3600)
        C.need(result['code']==0,'installed provider lifecycle child failed')
        child=json.loads(C.read(public/'result.json',8*1024**2));C.validate_child(index,child)
        for case in C.CASES:api['capabilities'].scope.receipt(child['cases'][case]['copy_lifetime']['copy']['gnu_bind_scope'],case)
        C.need(child.get('apparmor',{}).get('status')=='PASS_INSIDE_OWNED_TRIAL_APPARMOR_ENFORCE' and child['apparmor']['name']==profile['name'],'inside owned enforced trial profile proof required')
        report['apparmor']=child['apparmor']
        report['capabilities']=dict(status='ALL_SOURCE_AND_COPY_STAGE_MAPS_EXACT',source_capabilities_sha256=index['source_capabilities_sha256'],cases=2)
        report['lifecycle']='PASS'
    except BaseException as caught:error=caught;report.update(error_type=type(caught).__name__,error=str(caught)[:512])
    finally:
        try:
            retire()
            if any(private.iterdir()):
                result=launch('scrub','scrub.py',180);C.need(result['code']==0,'owned failed-root scrub failed');retire()
            C.need(not any(private.iterdir()),'lifecycle roots remain after actor retirement')
            private.rmdir();report['root_cleanup']='PASS_OWNED_ROOTS_REMOVED'
            C.need(all(a['status']=='PASS_ABSENCE_VERIFIED' for a in report['actors']),'all actors absent')
            report['actor_cleanup']='PASS_ALL_ABSENCE_VERIFIED'
            if error is None:report['status']='PASS_CORE7_INSTALLED_AND_TEARDOWN'
        except BaseException as caught:report.update(cleanup_error_type=type(caught).__name__,cleanup_error=str(caught)[:512])
        save();os.close(lease)
    print(json.dumps(dict(status=report['status'],receipt=str(args.output/'owner.json'))))
    return int(report['status']!='PASS_CORE7_INSTALLED_AND_TEARDOWN')

if __name__=='__main__':
    def cancelled(*_):raise KeyboardInterrupt()
    for sig in (signal.SIGINT,signal.SIGTERM):signal.signal(sig,cancelled)
    raise SystemExit(main())

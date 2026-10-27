#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exact-source planner in the owned native image; no package/image mutation."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from types import SimpleNamespace
HERE=Path(__file__).resolve().parent
DOCKER=('/usr/bin/docker','--host=unix:///var/run/docker.sock')
LABEL='org.cachy-asahi.offline-batch-plan'


def need(value,message):
    if not value:raise ValueError(message)


def save(path,value):
    with Path(path).open('x')as out:json.dump(value,out,sort_keys=True,indent=2);out.write('\n')


def local(argv,timeout=20):
    return subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,timeout=timeout)


def retire(owner,capture=local):
    name=owner['name'];token=owner['token'];image=owner['image']
    need(type(token)is str and re.fullmatch('[0-9a-f]{32}',token)and name=='offline-batch-plan-'+token and type(image)is str and re.fullmatch('sha256:[0-9a-f]{64}',image),'finite planner owner')
    shown=capture([*DOCKER,'container','inspect',name],10)
    if shown.returncode==0:
        rows=json.loads(shown.stdout);need(type(rows)is list and len(rows)==1 and type(rows[0])is dict,'one owned planner container')
        row=rows[0];entries=row['Mounts']
        need(type(entries)is list and len(entries)in(2,3)and all(type(p)is dict for p in entries),'finite planner mount ownership required')
        binds=[p for p in entries if p.get('Type')=='bind']
        need(len(binds)==2 and all(type(p.get('RW'))is bool for p in binds)and
             all(p.get('Type')=='bind' or p.get('Type')=='tmpfs'and p.get('Destination')=='/tmp'and p.get('RW')is True for p in entries),'planner mount ownership differs')
        mounts={(p.get('Source'),p.get('Destination'),p['RW'])for p in binds}
        need(row['Name']=='/'+name and row['Image']==image and row['Config']['Image']==image and row['Config']['Labels'].get(LABEL)==token and
             mounts=={(p,p,False)for p in owner['mount_roots']},'planner live ownership differs')
        removed=capture([*DOCKER,'rm','-f',name],10);need(removed.returncode==0,'owned planner removal failed')
    absence=capture([*DOCKER,'ps','-aq','--filter','name=^/'+name+'$'],10)
    need(absence.returncode==0 and not absence.stdout.strip(),'planner absence not established')
    return dict(status='PASS',name=name,image=image,absence_verified=True)


def execute(path,expected):
    path=Path(path).absolute();work=path.parent.parent
    binding=path.parent/'runtime-binding.json'
    need(path==path.resolve() and path.is_file() and path.stat().st_nlink==1 and binding==binding.resolve() and binding.is_file() and binding.stat().st_nlink==1 and binding.stat().st_size<=16*1024**2,'ordinary planner input/runtime binding required')
    runtime=json.loads(binding.read_text())
    spec=importlib.util.spec_from_file_location('_transport_owner',HERE/'owner.py');O=importlib.util.module_from_spec(spec);spec.loader.exec_module(O)
    args=SimpleNamespace(**{k:Path(runtime[k])for k in('source_root','work','cache','public','proof')},
        source_sha=runtime['identity']['source_sha'],feature_code_sha=runtime['identity']['feature_code_sha'],
        manifest_sha256=runtime['manifest_sha256'],mode='batches',execute=True)
    _,own=O.admitted(args);need(own==runtime['identity'] and Path(args.work)==work,'native planner identity/work differs')
    raw=O.read(path);need(O.sha(raw)==expected==runtime['input_sha256'],'planner input pin differs')
    base=O.load(work/'bootstrap-owner.json');image=base['image']
    need(base['status']=='PASS_FRESH_SIGNED_ORIGINAL341_BOOTSTRAP' and base['identity']==own and runtime['image']==image and type(image)is str and re.fullmatch('sha256:[0-9a-f]{64}',image),'planner qualified image differs')
    details=local([*DOCKER,'image','inspect',image],10);need(details.returncode==0 and O.require_image(json.loads(details.stdout)[0],own)==image,'planner owned image unavailable')
    feature=O.feature_root();O.feature_files(feature)
    token=os.urandom(16).hex();name='offline-batch-plan-'+token
    owner=dict(name=name,token=token,image=image,mount_roots=[str(feature),str(work)],purpose='readonly-native-planner',identity=own)
    save(path.parent/('planner-owner-'+token+'.json'),owner)
    command=[*DOCKER,'run','--rm','--name',name,'--label',LABEL+'='+token,'--label',O.LABEL+'='+own['token'],
        '--pull=never','--platform=linux/arm64','--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges',
        '--pids-limit','128','--memory','1g','--cpus','1','--user',str(os.getuid())+':'+str(os.getgid()),
        '--tmpfs','/tmp:rw,nosuid,nodev,exec,size=64m']
    for root in owner['mount_roots']:command+=['--mount','type=bind,src='+root+',dst='+root+',readonly']
    command+=['--entrypoint','/usr/bin/python3',image,'-I','-B',str(feature/'scripts/maintenance/rebuild_plan.py'),'--input',str(path),'--input-sha256',expected]
    save(path.parent/('planner-command-'+token+'.json'),dict(argv=command,owner=owner))
    try:
        result=local(command,90)
        need(type(result.returncode)is int and type(result.stdout)is bytes and type(result.stderr)is bytes and len(result.stdout)+len(result.stderr)<=16*1024**2,'planner output bound/type differs')
        (path.parent/('planner-'+token+'.stdout')).write_bytes(result.stdout);(path.parent/('planner-'+token+'.stderr')).write_bytes(result.stderr)
        need(result.returncode==0,'actual native planner refused')
        need(json.loads(result.stdout)['input']['sha256']==expected,'actual native planner input differs')
    finally:save(path.parent/('planner-retired-'+token+'.json'),retire(owner))
    need(O.read(path)==raw and O.load(work/'bootstrap-owner.json')==base,'planner input/producer changed')
    O.feature_files(feature)
    return result.stdout


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--input',type=Path,required=True);p.add_argument('--input-sha256',required=True);a=p.parse_args()
    try:sys.stdout.buffer.write(execute(a.input,a.input_sha256))
    except(OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError)as e:print(str(e),file=sys.stderr);raise SystemExit(2)

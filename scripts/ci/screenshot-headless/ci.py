#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""One Root-registered hosted software screenshot trial. No local default."""
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import secrets
import shutil
import stat
import subprocess
import sys
import time
import urllib.parse
import urllib.request

HERE=Path(__file__).resolve().parent
SOURCE=HERE.parents[2]
KEYS={'schema','lane','source_commit','ref','source_lock_sha256','runtime_lock_sha256','base_image_digest','peer_receipt_sha256'}
LANE='screenshot-headless-software-v1'

def need(ok,message):
    if not ok:raise ValueError(message)

def sha(data):return hashlib.sha256(data).hexdigest()

def registration(env):
    plan=json.loads(env.get('ROOT_PLAN','null'))
    need(isinstance(plan,dict) and set(plan)==KEYS,'Root plan exact schema')
    need(type(plan['schema']) is int and plan['schema']==1 and plan['lane']==LANE,'Root plan lane/schema')
    for key in ('source_lock_sha256','runtime_lock_sha256','peer_receipt_sha256'):
        need(isinstance(plan[key],str) and re.fullmatch('[0-9a-f]{64}',plan[key]),'Root plan digest')
    need(isinstance(plan['source_commit'],str) and re.fullmatch('[0-9a-f]{40}',plan['source_commit']) is not None,'Source commit')
    need(isinstance(plan['base_image_digest'],str) and re.fullmatch('sha256:[0-9a-f]{64}',plan['base_image_digest']) is not None,'base image digest')
    need(env.get('GITHUB_ACTIONS')=='true' and env.get('GITHUB_EVENT_NAME')=='workflow_dispatch','manual hosted trial only')
    need(env.get('GITHUB_SHA')==env.get('GITHUB_WORKFLOW_SHA')==plan['source_commit'],'registered Source/workflow SHA')
    need(isinstance(plan['ref'],str) and env.get('GITHUB_REF')==plan['ref'] and plan['ref'].startswith('refs/heads/codex/'),'registered branch ref')
    return plan

def verify_source(plan):
    raw=(HERE/'source.lock.json').read_bytes();need(sha(raw)==plan['source_lock_sha256'],'Root Source lock hash')
    lock=json.loads(raw);need(lock['schema']==1 and lock['lane']==LANE,'Source lock schema')
    for row in lock['files']:
        p=SOURCE/row['path'];need(p.resolve().is_relative_to(SOURCE),'Source path containment')
        s=p.lstat();need(stat.S_ISREG(s.st_mode) and not p.is_symlink(),'Source regular file')
        b=p.read_bytes();need(len(b)==row['bytes'] and sha(b)==row['sha256'] and stat.S_IMODE(s.st_mode)==row['mode'],'Source bytes/mode')
    raw=(HERE/'runtime.lock.json').read_bytes();need(sha(raw)==plan['runtime_lock_sha256'],'Root runtime lock hash')
    runtime=json.loads(raw);need(runtime['base']['image'].endswith('@'+plan['base_image_digest']),'Root base pin')
    need(('FROM '+runtime['base']['image']+'\n').encode() in (HERE/'Containerfile').read_bytes(),'Containerfile pinned base')
    return runtime

def fetch_package(row,target):
    url=row['url'];parsed=urllib.parse.urlsplit(url)
    need(parsed.scheme=='https' and parsed.hostname in {'deb.debian.org','security.debian.org'} and not parsed.username,'official HTTPS package URL')
    need(0<row['bytes']<=128*1024**2 and re.fullmatch('[0-9a-f]{64}',row['sha256']),'bounded pinned package')
    digest=hashlib.sha256();count=0
    with urllib.request.urlopen(url,timeout=30) as response, target.open('xb') as out:
        final=urllib.parse.urlsplit(response.url)
        need(final.scheme=='https' and final.hostname in {'deb.debian.org','security.debian.org'},'official redirect')
        while chunk:=response.read(1024**2):
            count+=len(chunk);need(count<=row['bytes'],'package size overflow');digest.update(chunk);out.write(chunk)
    need(count==row['bytes'] and digest.hexdigest()==row['sha256'],'package exact bytes/hash')

def main():
    plan=registration(os.environ);runtime=verify_source(plan)
    # Registration and all Source checks precede downloads, Docker or evidence mutation.
    root=Path(os.environ['RUNNER_TEMP']).resolve()/('screenshot-'+os.environ['GITHUB_RUN_ID']+'-'+os.environ['GITHUB_RUN_ATTEMPT'])
    root.mkdir(mode=0o700);evidence=root/'evidence';evidence.mkdir(mode=0o700)
    context=root/'context';context.mkdir(mode=0o700);debs=context/'debs';debs.mkdir(mode=0o700)
    shutil.copyfile(HERE/'Containerfile',context/'Dockerfile')
    staged=root/'source';staged.mkdir(mode=0o755)
    for row in json.loads((HERE/'source.lock.json').read_bytes())['files']:
        target=staged/row['path'];target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(SOURCE/row['path'],target);target.chmod(row['mode'])
    start=time.monotonic();cid=None;first=None;checks={};commands=[];name=None;image=None
    def command(args,name,timeout=60,capture=False,allow_failure=False):
        need(args[0]=='docker','finite Docker command set');args=['docker','--context','default',*args[1:]]
        log=evidence/(name+'.log')
        stdout=evidence/(name+'.stdout')
        def output_limit():resource.setrlimit(resource.RLIMIT_FSIZE,(16*1024**2,16*1024**2))
        with log.open('xb') as out,stdout.open('xb') as captured:
            r=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=captured if capture else out,stderr=out,timeout=timeout,check=False,preexec_fn=output_limit)
        commands.append({'argv':args,'code':r.returncode,'log':log.name})
        if not allow_failure:need(r.returncode==0,name+' failed')
        if capture:
            need(stdout.stat().st_size<=4*1024**2,'bounded Docker response');r.stdout=stdout.read_bytes()
        return r
    try:
        need(not os.environ.get('DOCKER_HOST') and not os.environ.get('DOCKER_CONTEXT'),'hosted default Docker endpoint only')
        command(['docker','version'],'docker-version',30)
        command(['docker','info'],'docker-info',30)
        (evidence/'host-os-release.txt').write_bytes(Path('/etc/os-release').read_bytes())
        need(len(runtime['packages'])==196 and sum(p['bytes'] for p in runtime['packages'])<=128*1024**2,'finite runtime closure')
        for i,row in enumerate(runtime['packages']):
            need(time.monotonic()-start<480,'download deadline')
            fetch_package(row,debs/(str(i)+'.deb'))
        (evidence/'runtime.lock.json').write_bytes((HERE/'runtime.lock.json').read_bytes())
        (evidence/'root-plan.json').write_text(json.dumps(plan,sort_keys=True,indent=2)+'\n')
        command(['docker','pull','--platform=linux/amd64',runtime['base']['image']],'pull',180)
        iid=root/'image.id'
        command(['docker','build','--network=none','--platform=linux/amd64','--iidfile',str(iid),str(context)],'build',300)
        image=iid.read_text().strip();need(re.fullmatch('sha256:[0-9a-f]{64}',image),'built image ID')
        (evidence/'image-id.txt').write_text(image+'\n')
        uid=str(os.getuid())+':'+str(os.getgid())
        name='screenshot-'+secrets.token_hex(16)
        args=['docker','create','--name',name,'--label','cachy-asahi.screenshot-owner='+name,'--cidfile',str(root/'container.id'),'--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--pids-limit=128','--memory=512m','--cpus=2','--user',uid,'--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777','--shm-size=16m','--mount','type=bind,src='+str(staged)+',dst=/source,readonly','--mount','type=bind,src='+str(evidence)+',dst=/evidence',image]
        r=command(args,'create',30,True);cid=r.stdout.decode().strip();need(re.fullmatch('[0-9a-f]{64}',cid),'owned exact container ID')
        r=command(['docker','inspect',cid],'inspect-before',30,True)
        inspected=json.loads(r.stdout)[0];h=inspected['HostConfig'];config=inspected['Config']
        need(h['NetworkMode']=='none' and h['ReadonlyRootfs'] and not h['Privileged'] and not h.get('Devices') and not h.get('DeviceRequests'),'container isolation')
        need(h['CapDrop']==['ALL'] and 'no-new-privileges' in h['SecurityOpt'] and h['PidsLimit']==128 and h['Memory']==512*1024**2,'container limits')
        need(config['User']==uid and not config['Tty'] and not config['OpenStdin'],'unprivileged noninteractive container')
        (evidence/'container-before.json').write_bytes(r.stdout)
        trial=command(['docker','start','--attach',cid],'trial',220,allow_failure=True)
        r=command(['docker','inspect',cid],'inspect-after',30,True);after=json.loads(r.stdout)[0]
        (evidence/'container-after.json').write_bytes(r.stdout)
        need(trial.returncode==0,'trial command failed')
        need(after['State']['Status']=='exited' and after['State']['ExitCode']==0 and not after['State']['OOMKilled'],'clean trial exit')
        result=json.loads((evidence/'result.json').read_bytes())
        need(result['status']=='SOFTWARE_SCREENSHOT_PASS' and result['positive_capture']=='THREE_REAL_COLOR_CHECKED_CAPTURES' and result['first_failure'] is None and result['runtime_remaining']==[],'actual capture and cleanup results')
        checks={'trial_pass':True,'image_id':image,'container_exit':0}
    except BaseException as error:first={'type':type(error).__name__,'message':str(error)}
    finally:
        if name:
            try:
                r=command(['docker','inspect',name],'cleanup-identify',30,True,True)
                need(r.returncode==0,'owned container identity unresolved')
                owned=json.loads(r.stdout)[0]
                need(owned['Name']=='/'+name and owned['Config']['Labels'].get('cachy-asahi.screenshot-owner')==name and owned['Image']==image,'exact owned cleanup target')
                cid=owned['Id'];need(re.fullmatch('[0-9a-f]{64}',cid),'owned cleanup ID')
                command(['docker','rm','--force',cid],'retire',30)
                r=command(['docker','inspect',cid],'retired-inspect',30,True,True)
                need(r.returncode!=0 and b'No such object' in (evidence/'retired-inspect.log').read_bytes(),'owned container retirement')
                checks['container_retired']=True
            except BaseException as error:
                if first is None:first={'type':type(error).__name__,'message':str(error)}
                else:checks['cleanup_failure']=str(error)
        passed=first is None and checks.get('container_retired') is True
        (evidence/'ci-result.json').write_text(json.dumps({'status':'SOFTWARE_SCREENSHOT_PASS' if passed else 'SOFTWARE_SCREENSHOT_FAIL','first_failure':first,'checks':checks,'commands':commands,'elapsed_seconds':time.monotonic()-start,'ARM_Hyprland_M2_acceptance':False},sort_keys=True,indent=2)+'\n')
    return 0 if passed else 1

if __name__=='__main__':raise SystemExit(main())

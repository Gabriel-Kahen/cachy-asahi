#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""One Root-registered hosted software screenshot trial. No local default."""
import hashlib
import importlib.util
import json
import os
import platform
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
LANE='screenshot-headless-native-software-v1'
HELPER_ROLE='packages/desktop/cachy-asahi-hyprland-settings/cachy-asahi-screenshot'
HELPER_SHA='5a920a5dd7a40463417a9b15e64a6620acfe7b2328960bf7014c9f587c4b69a8'

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
    need(runtime['platform']=='linux/arm64' and len(runtime['packages'])==196 and all(p['architecture'] in ('arm64','all') for p in runtime['packages']),'exact ARM64 runtime selection')
    return runtime

def native_host():
    record={'system':platform.system(),'machine':platform.machine(),'kernel':platform.uname()._asdict(),'uid':os.getuid(),'gid':os.getgid()}
    need(record['system']=='Linux' and record['machine'] in ('aarch64','arm64') and record['uid']!=0,'native nonroot Linux ARM host required')
    need(not os.environ.get('DOCKER_HOST') and not os.environ.get('DOCKER_CONTEXT'),'hosted default local Docker endpoint only')
    return record

def native_daemon(info):
    need(isinstance(info,dict) and info.get('OSType')=='linux' and info.get('Architecture') in ('aarch64','arm64'),'native local Linux ARM Docker daemon required')
    return {'architecture':info['Architecture'],'os':info['OSType'],'server_version':info.get('ServerVersion')}

def native_context(info):
    need(isinstance(info,list) and len(info)==1 and info[0].get('Name')=='default','exact default Docker context')
    endpoint=info[0]['Endpoints']['docker']['Host']
    need(endpoint in ('unix:///var/run/docker.sock','unix:///run/docker.sock'),'local default Docker Unix endpoint required')
    return endpoint

def native_image(info,image):
    need(isinstance(info,list) and len(info)==1 and info[0].get('Id')==image and info[0].get('Architecture')=='arm64' and info[0].get('Os')=='linux','built image must be exact native linux/arm64 identity')
    return info[0]

def helper_record(path):
    node=path.lstat();need(stat.S_ISREG(node.st_mode) and not path.is_symlink() and node.st_size==8523,'bounded archive helper regular file')
    raw=path.read_bytes()
    need(len(raw)==8523 and sha(raw)==HELPER_SHA and stat.S_IMODE(node.st_mode)==0o755,'exact native archive helper bytes/mode')
    return {'bytes':len(raw),'sha256':sha(raw),'mode':'0755'}

def archive_helper(target,token):
    # Only the Source-locked library is loaded; registration and verify_source
    # have already authenticated it and the fixed candidate contract.
    spec=importlib.util.spec_from_file_location('screenshot_native_archive_input',HERE/'archive_input.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    need(json.loads((HERE/'candidate-input.lock.json').read_bytes())==module.CONTRACT,'Source-locked exact archive input contract')
    record=module.acquire_helper(target,token=token)
    need(isinstance(record,dict) and type(record.get('schema_version')) is int and record['schema_version']==1 and record.get('status')=='AUTHENTICATED_NATIVE_ARCHIVE_HELPER','native archive acquisition record')
    need(all(type(record.get(k)) is int for k in ('run_id','run_attempt','workflow_id','job_id')),'archive origin integer identities')
    need(record.get('repository')=='Gabriel-Kahen/cachy-asahi' and record.get('run_id')==38571648129 and record.get('run_attempt')==1 and record.get('source_commit')=='92a3f0612c558b91accc15cd6495d98d6463b943' and record.get('workflow_id')==381664314 and record.get('job_id')==115917195186,'exact native archive origin')
    need(record['tgz']=={'frame':'native-evidence','bytes':1275070,'sha256':'dea293276f1e465012fa17fab39e8a7c28ee6003e53a0c0d5a54db4061e55a4d'},'exact original native evidence frame')
    need(record['package']=={'member':'native-evidence/cachy-asahi-hyprland-settings-1/artifacts/cachy-asahi-hyprland-settings-0.1.0-2-any.pkg.tar.xz','bytes':12740,'sha256':'0b22b778ec83d8b98d98d06fa4f016bd4e3f581b69efa83d6526c5265c2adf5e'},'exact native candidate archive')
    need(record['helper']=={'member':'usr/bin/cachy-asahi-screenshot',**helper_record(target)},'actual extracted helper equals locked Source role')
    return record

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
    root=Path(os.environ['RUNNER_TEMP']).resolve()/('screenshot-native-'+os.environ['GITHUB_RUN_ID']+'-'+os.environ['GITHUB_RUN_ATTEMPT'])
    root.mkdir(mode=0o700);evidence=root/'evidence';evidence.mkdir(mode=0o700)
    context=root/'context';context.mkdir(mode=0o700);debs=context/'debs';debs.mkdir(mode=0o700)
    shutil.copyfile(HERE/'Containerfile',context/'Dockerfile')
    staged=root/'source';staged.mkdir(mode=0o755)
    token=os.environ.pop('NATIVE_INPUT_READ_TOKEN',None)
    for row in json.loads((HERE/'source.lock.json').read_bytes())['files']:
        target=staged/row['path'];target.parent.mkdir(parents=True,exist_ok=True)
        if row['path']!=HELPER_ROLE:
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
        host=native_host()
        local_context=command(['docker','context','inspect','default'],'context-inspect',30,True)
        host['docker_endpoint']=native_context(json.loads(local_context.stdout))
        (evidence/'docker-context.json').write_bytes(local_context.stdout)
        command(['docker','version'],'docker-version',30)
        daemon=command(['docker','info','--format','{{json .}}'],'docker-info',30,True)
        host['docker']=native_daemon(json.loads(daemon.stdout))
        (evidence/'native-host.json').write_text(json.dumps(host,sort_keys=True,indent=2)+'\n')
        archive=archive_helper(staged/HELPER_ROLE,token);token=None
        (evidence/'archive-input.json').write_text(json.dumps(archive,sort_keys=True,indent=2)+'\n')
        for row in json.loads((HERE/'source.lock.json').read_bytes())['files']:
            target=staged/row['path'];node=target.lstat();raw=target.read_bytes()
            need(stat.S_ISREG(node.st_mode) and not target.is_symlink() and len(raw)==row['bytes'] and sha(raw)==row['sha256'] and stat.S_IMODE(node.st_mode)==row['mode'],'complete staged Source including native archive helper')
        (evidence/'host-os-release.txt').write_bytes(Path('/etc/os-release').read_bytes())
        need(len(runtime['packages'])==196 and sum(p['bytes'] for p in runtime['packages'])<=128*1024**2,'finite runtime closure')
        for i,row in enumerate(runtime['packages']):
            need(time.monotonic()-start<480,'download deadline')
            fetch_package(row,debs/(str(i)+'.deb'))
        (evidence/'runtime.lock.json').write_bytes((HERE/'runtime.lock.json').read_bytes())
        (evidence/'root-plan.json').write_text(json.dumps(plan,sort_keys=True,indent=2)+'\n')
        command(['docker','pull','--platform=linux/arm64',runtime['base']['image']],'pull',180)
        iid=root/'image.id'
        command(['docker','build','--network=none','--platform=linux/arm64','--iidfile',str(iid),str(context)],'build',300)
        image=iid.read_text().strip();need(re.fullmatch('sha256:[0-9a-f]{64}',image),'built image ID')
        (evidence/'image-id.txt').write_text(image+'\n')
        inspected_image=command(['docker','image','inspect',image],'image-inspect',30,True)
        native_image(json.loads(inspected_image.stdout),image)
        (evidence/'image-inspect.json').write_bytes(inspected_image.stdout)
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
        need(result['native_execution']['system']=='Linux' and result['native_execution']['machine'] in ('aarch64','arm64') and result['native_execution']['interpreter']['e_machine']==183 and result['native_execution']['loader']['e_machine']==183,'running native ARM interpreter evidence')
        checks={'trial_pass':True,'image_id':image,'container_exit':0,'native_execution':result['native_execution'],'native_archive_helper':archive['helper']}
    except BaseException as error:
        first={'type':type(error).__name__,'message':str(error)}
        try:
            if type(error).__name__=='Refusal' and type(error).__module__=='screenshot_native_archive_input' and str(error)=='archive-input-download-origin':
                origin=getattr(error,'archive_origin',None)
                if (type(origin) is dict and set(origin)=={'request_role','hop','check','scheme','hostname','port','userinfo_present'}
                    and type(origin['request_role']) is str and origin['request_role'] in ('run_attempt','job','attempt_logs')
                    and type(origin['hop']) is int and 0<=origin['hop']<=2
                    and type(origin['check']) is str and origin['check'] in ('shape','route')
                    and type(origin['userinfo_present']) is bool
                    and (origin['scheme'] is None or (type(origin['scheme']) is str and re.fullmatch(r'[a-z][a-z0-9+.-]{0,15}',origin['scheme'])))
                    and (origin['hostname'] is None or (type(origin['hostname']) is str and len(origin['hostname'])<=253 and re.fullmatch(r'(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}',origin['hostname']) and origin['hostname'].rsplit('.',1)[-1].lower() not in ('localhost','localdomain','local','internal','home','lan','corp','private','intranet','invalid','test','example','onion','arpa')))
                    and (origin['port'] is None or (type(origin['port']) is int and 0<=origin['port']<=65535))):
                    first['archive_origin']=dict(origin)
        except Exception:
            pass  # Preserve the primary failure if diagnostic validation fails.
        try:
            if type(error).__name__=='Refusal' and type(error).__module__=='screenshot_native_archive_input':
                cleanup=getattr(error,'archive_cleanup',None)
                if type(cleanup) is str and cleanup=='UNRESOLVED':
                    first['archive_cleanup']='UNRESOLVED'
        except Exception:
            pass  # Cleanup telemetry cannot replace the original failure.
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
        (evidence/'ci-result.json').write_text(json.dumps({'status':'SOFTWARE_SCREENSHOT_PASS' if passed else 'SOFTWARE_SCREENSHOT_FAIL','first_failure':first,'checks':checks,'commands':commands,'elapsed_seconds':time.monotonic()-start,'native_ARM_capture':passed,'Hyprland_M2_hardware_acceptance':False,'full_settings_installation':'NOT_RUN'},sort_keys=True,indent=2)+'\n')
    return 0 if passed else 1

if __name__=='__main__':raise SystemExit(main())

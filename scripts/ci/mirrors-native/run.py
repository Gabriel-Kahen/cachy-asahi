#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reuse the accepted Welcome fresh-build helper on the exact owned574 image."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import time
import hashlib
import stat
import contract as C

HERE=Path(__file__).resolve().parent
ENV=dict(PATH='/usr/bin:/bin',LANG='C.UTF-8',LC_ALL='C.UTF-8',TZ='UTC')


def save(path,value):
    temp=path.with_suffix('.pending');temp.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n');temp.replace(path)


def pair_gate(result):
    C.need(result['status']=='contents-reproduced' and not result['errors'] and len(result['packages'])==1 and
           all(all(row[k] is True for k in ('installed_contents_equal','pkginfo_equal','bytes_equal','buildinfo_equal'))
               for row in result['packages'].values()),'both payload and complete archive bytes must reproduce')


def signing_job(source,token,proof_path):
    C.safe(proof_path);info=proof_path.lstat()
    C.need(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and info.st_nlink==1 and info.st_size<=65536 and not(info.st_mode&0o022),'owned bounded source proof required')
    proof=json.loads(proof_path.read_bytes());sha=proof['source_sha'];run=proof['run_id'];attempt=proof['run_attempt']
    C.need(re.fullmatch('[0-9a-f]{40}',sha) and sha==proof['workflow_sha']==os.environ.get('SOURCE_SHA')==os.environ.get('GITHUB_SHA')==os.environ.get('GITHUB_WORKFLOW_SHA') and run==os.environ.get('GITHUB_RUN_ID') and attempt==os.environ.get('GITHUB_RUN_ATTEMPT')=='1','genuine current job identity required')
    C.need(re.fullmatch('[1-9][0-9]{0,19}',run) and proof['status']=='SOURCE_PROOF_PASS' and proof['job_token']==hashlib.sha256(('product-build-pair:'+run+':'+attempt+':'+sha).encode()).hexdigest()[:16] and proof['consumer_token']==token==hashlib.sha256(('mirrors-consumer:'+run+':'+attempt+':'+sha).encode()).hexdigest()[:32],'source/job token binding differs')
    manifest=json.loads((source/'scripts/ci/mirrors-native/source-manifest.json').read_bytes())
    J=C.load('signed_runner_source_proof',source/'scripts/ci/mirrors-native/job.py')
    C.need(proof['source_files']==len(manifest['files']) and proof['workflow_binding']==J.workflow_binding(source,manifest),'complete source/workflow proof differs')
    C.need(type(proof['issued_epoch']) is int and proof['issued_epoch']<=time.time()+5<=proof['issued_epoch']+6000,'current bounded job proof required')
    return dict(source_sha=sha,run_id=run,run_attempt=attempt,proof_issued_epoch=proof['issued_epoch'],consumer_token=token)


def execute(source,base_dir,out,token,proof_path):
    C.need(platform.system()=='Linux' and platform.machine()=='aarch64' and os.getuid()==os.geteuid()>0 and
           not any(k.startswith('DOCKER_') for k in os.environ),'ordinary native ARM host required')
    for p in (source,base_dir,out):C.safe(p)
    C.need(not out.exists() and not any(out.is_relative_to(p) or p.is_relative_to(out) for p in (source,base_dir)),
           'fresh separate consumer output required')
    C.need(re.fullmatch('[0-9a-f]{32}',token),'explicit consumer token required');C.verify_source(source)
    job_binding=signing_job(source,token,proof_path)
    original=json.loads((base_dir/'report.json').read_text());image=(base_dir/'image-id').read_text().strip()
    C.need(original.get('status')=='PASS_NATIVE_OFFLINE_574_TRANSACTION' and original['image']==image and
           re.fullmatch('sha256:[0-9a-f]{64}',image),'accepted owned574 image required')
    shared=C.load('accepted_tools_build',source/'scripts/ci/welcome-native/run.py');shared.C=C
    common=C.load('tools_logged',source/'scripts/virtual/common.py')
    checks=C.load('tools_checks',source/'scripts/checks/package_checks.py')
    sys.path[:0]=[str(source/'scripts/build'),str(source/'scripts/checks')]
    bind=C.load('tools_binding',source/'scripts/build/build.py')
    comparison=C.load('tools_compare',source/'scripts/build/compare.py')
    lock=base_dir/'installed-packages.lock';base=shared.inventory(lock.read_text())
    selected=json.loads((source/'scripts/ci/maintained-desktop574-inputs.json').read_text())
    C.need(len(base)==574 and base=={r['name']:r['version'] for r in selected['packages']},'exact574 base lock required')
    dependencies=sorted({relation for name in C.NAMES for key in ('depends','makedepends','checkdepends')
                         for relation in C.recipe(source,name)['metadata'].get(key,[])})
    out.mkdir(mode=0o700);lease=os.open(out/'consumer.lock',os.O_CREAT|os.O_EXCL|os.O_RDWR|os.O_CLOEXEC,0o600)
    fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB);(out/'home').mkdir(mode=0o700)
    owner=dict(schema_version=1,token=token,image=image,label=C.LABEL,containers=[]);save(out/'owner.json',owner)
    report=dict(status='FAIL',scope='ONE_UNSELECTED_MIRROR_CANDIDATE',base_image=image,base_count=574,
        base_lock_sha256=C.digest(lock),products={},hardware='NOT_RUN',performance='NOT_MEASURED',
        original_selected_inventory='UNCHANGED',commands=[],ownership_token=token)
    env=dict(ENV,HOME=str(out/'home'));active=None;first=None

    def command(argv,log,seconds):
        nonlocal active
        report['commands'].append(dict(argv=argv,log=str(log.relative_to(out))))
        active=common.LoggedProcess(argv,log,env=env,limit=16*1024**2);error=None
        try:active.process.wait(timeout=seconds);active.finish();C.need(active.process.returncode==0,'command failed: '+log.name)
        except BaseException as caught:error=caught
        finally:
            if active.process.poll() is None:
                try:os.killpg(active.process.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                active.process.wait(timeout=5)
            try:active.finish()
            except BaseException as caught:
                if error is None:error=caught
            active=None
        if error is not None:raise error

    def capture(argv):
        row=subprocess.run(argv,env=env,capture_output=True,timeout=30)
        C.need(row.returncode==0 and len(row.stdout)+len(row.stderr)<=1024**2,'native observer failed')
        return row.stdout.decode().strip()

    class Owners(list):
        def append(self,name):
            C.need(len(self)<5 and re.fullmatch(r'cachy-asahi-product-(?:(?:probe|signer|lifecycle)-)?[0-9a-f]{32}',name) and name not in self,
                   'closed consumer actor set required')
            super().append(name);owner['containers']=list(self);save(out/'owner.json',owner)
    containers=Owners();plain_docker=shared.docker
    def docker(*args,**kwargs):return plain_docker(*args,**kwargs)+['--label='+C.LABEL+'='+token]
    shared.docker=docker
    previous={s:signal.signal(s,lambda *_:(_ for _ in ()).throw(TimeoutError('tools lane deadline/cancellation')))
              for s in (signal.SIGINT,signal.SIGTERM,signal.SIGALRM)}
    signal.setitimer(signal.ITIMER_REAL,2350)
    try:
        C.need(capture(['docker','context','show'])=='default' and
               json.loads(capture(['docker','context','inspect','default']))[0]['Endpoints']['docker']['Host']=='unix:///var/run/docker.sock' and
               capture(['docker','info','--format','{{.Architecture}}']) in ('aarch64','arm64') and
               capture(['docker','image','inspect','--format','{{.Os}}/{{.Architecture}}',image])=='linux/arm64',
               'local native ARM daemon and image required')
        probe='cachy-asahi-product-probe-'+os.urandom(16).hex();containers.append(probe)
        command(docker(image,probe,out)+['--entrypoint=/bin/bash',image,'-c',
            '/usr/bin/pacman -T \"$@\" >/dev/null && /usr/bin/pacman -Q','tools-dependencies',*dependencies],out/'base-inventory.log',30)
        C.need(shared.inventory((out/'base-inventory.log').read_text())==base,'actual image inventory differs')
        products={}
        for name in C.NAMES:
            pair=[shared.build(source,out,base,image,lock,name,side,selected['source_date_epoch'],command,containers,checks,bind)
                  for side in ('a','b')]
            result=comparison.compare(*(row['directory'] for row in pair));pair_gate(result)
            save(out/(name+'-comparison.json'),result)
            report['products'][name]=dict(version=C.version(source,name),comparison=result,builds=[dict(
                archive=row['archive'].name,sha256=C.digest(row['archive']),payload=row['payload'],tests=row['tests']) for row in pair])
            products[name]=dict(archive=pair[0]['archive'].name,sha256=C.digest(pair[0]['archive']),
                                version=C.version(source,name),payload=pair[0]['payload'])
        signing_context=out/'signing-inputs';signing_context.mkdir();signing_products={}
        for side in ('a','b'):
            directory=signing_context/side;directory.mkdir();archive=out/(C.NAMES[0]+'-'+side)/'artifacts'/products[C.NAMES[0]]['archive']
            shutil.copyfile(archive,directory/archive.name)
            signing_products[side]=dict(archive='/inputs/'+side+'/'+archive.name,bytes=archive.stat().st_size,sha256=C.digest(archive))
        signing_input=dict(job=job_binding,products=signing_products);save(signing_context/'signing-input.json',signing_input)
        signed=out/'signing';signed.mkdir(mode=0o700);signer='cachy-asahi-product-signer-'+os.urandom(16).hex();containers.append(signer)
        command(docker(image,signer,signed)+['--env=CACHY_ASAHI_MIRRORS_TEST_SIGNER=1',
            '--mount',f'type=bind,src={signing_context},dst=/inputs,readonly',
            '--mount',f'type=bind,src={HERE},dst=/runner,readonly',
            '--entrypoint=/usr/bin/python3',image,'-I','-B','/runner/signer_actor.py'],out/'signer.log',120)
        auth=C.load('mirror_native_signer_contract',HERE/'test_auth.py');signing=json.loads((signed/'signing.json').read_bytes())
        auth.validate_signing(signing,job_binding,signing_products);report['signing']=signing
        context=out/'lifecycle-inputs';context.mkdir();save(context/'base.json',base)
        save(context/'signing-job.json',job_binding);save(context/'signing-input.json',signing_input);shutil.copytree(signed,context/'signed')
        name=C.NAMES[0];products[name]['archive_b']='build-b/'+products[name]['archive']
        products[name]['sha256_b']=signing_products['b']['sha256'];save(context/'products.json',products)
        (context/'build-b').mkdir();shutil.copyfile(signing_context/'b'/products[name]['archive'],context/products[name]['archive_b'])
        for name in C.NAMES:
            shutil.copyfile(out/(name+'-a')/'artifacts'/products[name]['archive'],context/products[name]['archive'])
            shutil.copytree(source/'packages/tools'/name,context/'sources'/name)
        container='cachy-asahi-product-lifecycle-'+os.urandom(16).hex();containers.append(container)
        command(docker(image,container,out,root=True)+['--env=CACHY_ASAHI_TOOLS_LIFECYCLE=1',
            '--mount',f'type=bind,src={context},dst=/inputs,readonly',
            '--mount',f'type=bind,src={source}/scripts/ci/welcome-native,dst=/accepted,readonly',
            '--mount',f'type=bind,src={HERE},dst=/runner,readonly',
            '--entrypoint=/usr/bin/python3',image,'-I','-B','/runner/installed.py'],out/'lifecycle.log',600)
        life=json.loads((out/'lifecycle.json').read_text());C.validate_lifecycle(life)
        report.update(lifecycle=life,dependencies=dependencies,status='PASS_NATIVE_MIRRORS_PAIR_AND_LIFECYCLE')
    except BaseException as error:first=error;report.update(error=str(error)[:1024],error_type=type(error).__name__)
    finally:
        signal.setitimer(signal.ITIMER_REAL,0)
        save(out/'report.json',report);os.close(lease)
        for s,handler in previous.items():signal.signal(s,handler)
    # The always-run job cleanup acquires this lease, retires labeled consumers, then the original producer.
    return int(first is not None)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('source','base-dir','output'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--consumer-token',required=True);parser.add_argument('--proof',type=Path,required=True);args=parser.parse_args()
    raise SystemExit(execute(args.source.absolute(),args.base_dir.absolute(),args.output.absolute(),args.consumer_token,args.proof.absolute()))

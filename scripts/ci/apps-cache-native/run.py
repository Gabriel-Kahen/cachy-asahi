#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Runtime pair first, exact owned dependency images, Apps pair and independent Cache pair."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
from types import SimpleNamespace
import contract as C

ENV=dict(PATH='/usr/bin:/bin',LANG='C.UTF-8',LC_ALL='C.UTF-8',TZ='UTC')


def save(path,value):
    temp=path.with_suffix('.pending');temp.write_bytes(C.encoded(value));temp.replace(path)


def public_tree(path):
    for item in (path,*path.rglob('*')):
        if not item.is_symlink():item.chmod(0o755 if item.is_dir() else 0o644)


def execute(source,base_dir,out,token):
    C.policy() # Before native checks, imports, output/leases, keys or actors.
    C.verify_source(source)
    C.need(platform.system()=='Linux' and platform.machine()=='aarch64' and os.getuid()==os.geteuid()>0 and
        not any(k.startswith('DOCKER_') for k in os.environ),'ordinary native ARM coordinator required')
    for path in (source,base_dir,out):C.safe(path)
    C.need(not out.exists() and not any(out.is_relative_to(p) or p.is_relative_to(out) for p in (source,base_dir)), 'fresh separate runtime output required')
    C.need(re.fullmatch('[0-9a-f]{32}',token),'explicit proof-bound consumer token required')
    original=C.read(base_dir/'report.json');image=(base_dir/'image-id').read_text().strip()
    C.need(original['status']=='PASS_NATIVE_OFFLINE_574_TRANSACTION' and original['image']==image and
        re.fullmatch('sha256:[0-9a-f]{64}',image),'accepted owned574 producer required')
    shared=C.load('apps_cache_shared_builder',source/'scripts/ci/welcome-native/run.py');shared.C=C
    tools=C.load('apps_cache_pair_gate',source/'scripts/ci/tools-native/run.py');tools.C=C
    common=C.load('apps_cache_logged',source/'scripts/virtual/common.py')
    checks=C.load('apps_cache_checks',source/'scripts/checks/package_checks.py')
    sys.path[:0]=[str(source/'scripts/build'),str(source/'scripts/checks')]
    bind=C.load('apps_cache_artifact_bind',source/'scripts/build/build.py');compare=C.load('apps_cache_compare',source/'scripts/build/compare.py')
    producer=C.load('apps_cache_image_owner',source/'scripts/ci/maintained_desktop574.py')
    lock=base_dir/'installed-packages.lock';base=shared.inventory(lock.read_text())
    selected=C.read(source/'scripts/ci/maintained-desktop574-inputs.json')
    C.need(len(base)==574 and C.digest(lock)==C.BASE and base=={r['name']:r['version'] for r in selected['packages']} and
        not set(C.NAMES)&base.keys() and 'pyalpm' not in base,'exact original574 and absent candidate namespace required')
    out.mkdir(mode=0o700);(out/'home').mkdir(mode=0o700)
    report=dict(status='FAIL',scope='THREE_UNSELECTED_APPS_RUNTIME_CACHE_CANDIDATES',base_image=image,base_count=574,
        products={},hardware='NOT_RUN',plans_applied='NOT_APPLIED',cache_cleanup='NOT_RUN',commands=[],ownership_token=token)
    groups={};leases=[];active=None;first=None;env=dict(ENV,HOME=str(out/'home'))
    class Owners(list):
        def __init__(self,key,actor_image,base_path):
            super().__init__();self.path=out/key;self.path.mkdir(mode=0o700);self.image=actor_image
            fd=os.open(self.path/'consumer.lock',os.O_CREAT|os.O_EXCL|os.O_RDWR|os.O_CLOEXEC,0o600)
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);leases.append(fd)
            self.record=dict(schema_version=1,token=token,image=actor_image,label=C.LABEL,containers=[])
            save(self.path/'owner.json',self.record);groups[key]=dict(base=str(base_path),runtime=str(self.path),image=actor_image)
            save(out/'groups.json',groups)
        def append(self,name):
            C.need(len(self)<8 and re.fullmatch(r'cachy-asahi-product-(?:(?:probe|lifecycle)-)?[0-9a-f]{32}',name) and name not in self,'original bounded consumer actor set required')
            super().append(name);self.record['containers']=list(self);save(self.path/'owner.json',self.record)
    base_actors=Owners('base-consumers',image,base_dir)
    def command(argv,log,seconds):
        nonlocal active
        report['commands'].append(dict(argv=list(map(str,argv)),log=str(log.relative_to(out))))
        active=common.LoggedProcess(list(map(str,argv)),log,env=env,limit=16*1024**2);error=None
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
        result=subprocess.run(list(map(str,argv)),env=env,capture_output=True,timeout=30)
        C.need(result.returncode==0 and len(result.stdout)+len(result.stderr)<=1024**2,'bounded native daemon observer failed')
        return result.stdout.decode().strip()
    plain_docker=shared.docker
    def docker(*args,**kwargs):return plain_docker(*args,**kwargs)+['--label='+C.LABEL+'='+token]
    shared.docker=docker
    def build_pair(name,actor_image,actor_base,actor_lock,actors):
        pair=[shared.build(source,out,actor_base,actor_image,actor_lock,name,side,selected['source_date_epoch'],command,actors,checks,bind) for side in ('a','b')]
        comparison=compare.compare(*(r['directory'] for r in pair));tools.pair_gate(comparison)
        save(out/(name+'-comparison.json'),comparison)
        report['products'][name]=dict(version=C.version(source,name),comparison=comparison,build_image=actor_image,
            build_inventory_sha256=C.digest(actor_lock),builds=[dict(archive=r['archive'].name,sha256=C.digest(r['archive']),payload=r['payload'],tests=r['tests']) for r in pair])
        return dict(archive=pair[0]['archive'].name,sha256=C.digest(pair[0]['archive']),version=C.version(source,name),payload=pair[0]['payload'])
    def runner_context(context):
        runner=context/'runner';runner.mkdir()
        for name in ('contract.py','input-policy.json','installed.py','runtime_image.py','lifecycle.py'):shutil.copyfile(C.HERE/name,runner/name)
        accepted=runner/'accepted';accepted.mkdir()
        shutil.copyfile(source/'scripts/ci/welcome-native/lifecycle.py',accepted/'lifecycle.py')
        shutil.copyfile(source/'scripts/ci/full-root-upgrade/root_upgrade.py',accepted/'root_upgrade.py')
        return runner
    def dependency_image(role,context,script):
        directory=out/(role+'-image');directory.mkdir(mode=0o700)
        dep_token=hashlib.sha256((token+':'+role).encode()).hexdigest()[:16]
        ownership=producer.owner_begin(directory,dep_token)
        record=dict(status='BUILDING_OWNED_DEPENDENCY_IMAGE',scope=role,ownership=ownership,image=None,build_returncode=None)
        producer.save_report(directory,record)
        actor='cachy-asahi-product-'+os.urandom(16).hex();base_actors.append(actor)
        runner=runner_context(context);public_tree(context)
        phase_output=out/(role+'-output');phase_output.mkdir(mode=0o700)
        command(docker(image,actor,phase_output,root=True)+['--env=CACHY_ASAHI_APPS_CACHE_OPERATION='+role,
            '--mount',f'type=bind,src={context},dst=/inputs,readonly','--mount',f'type=bind,src={runner},dst=/runner,readonly',
            '--entrypoint=/usr/bin/python3',image,'-I','-B','/runner/'+script],out/(role+'-install.log'),600)
        for name in ('runtime575.lock','runtime-image.json'):
            shutil.copyfile(phase_output/name,out/name)
        # Persist the lease before an unknown commit outcome; original retire_owned refuses incomplete producers.
        ownership['build_started']=True;producer.save_report(directory,record)
        command(['docker','commit','--change','LABEL '+producer.OWNER_LABEL+'='+dep_token,actor,ownership['image_tag']],out/(role+'-commit.log'),120)
        dep_image=capture(['docker','image','inspect','--format','{{.Id}}',ownership['image_tag']])
        metadata=producer.inspect_image(dep_image,dep_token)
        C.need(metadata['Id']==dep_image and dep_image not in ownership['before_images'],'fresh exact owned dependency image required')
        ownership.update(build_complete=True,image=dep_image);record.update(status='PASS_OWNED_SIGNED_DEPENDENCY_IMAGE',image=dep_image,build_returncode=0)
        (directory/'image-id').write_text(dep_image+'\n');producer.save_report(directory,record)
        return directory,dep_image
    previous={s:signal.signal(s,lambda *_:(_ for _ in ()).throw(TimeoutError('apps/cache native deadline/cancellation')))
        for s in (signal.SIGINT,signal.SIGTERM,signal.SIGALRM)};signal.setitimer(signal.ITIMER_REAL,2350)
    try:
        C.need(capture(['docker','context','show'])=='default' and json.loads(capture(['docker','context','inspect','default']))[0]['Endpoints']['docker']['Host']=='unix:///var/run/docker.sock' and
            capture(['docker','info','--format','{{.Architecture}}']) in ('aarch64','arm64') and capture(['docker','image','inspect','--format','{{.Os}}/{{.Architecture}}',image])=='linux/arm64','local native daemon/image required')
        deps=sorted({r for name in (C.ROLES['runtime'],C.ROLES['cache']) for k in ('depends','makedepends','checkdepends') for r in C.recipe(source,name)['metadata'].get(k,[])})
        probe='cachy-asahi-product-probe-'+os.urandom(16).hex();base_actors.append(probe)
        probe_output=out/'probe-output';probe_output.mkdir(mode=0o700)
        command(docker(image,probe,probe_output)+['--entrypoint=/bin/bash',image,'-c','/usr/bin/pacman -T "$@" >/dev/null && /usr/bin/pacman -Q','runtime-dependencies',*deps],out/'base-inventory.log',30)
        C.need(shared.inventory((out/'base-inventory.log').read_text())==base,'actual574 image inventory differs')
        products={C.ROLES['runtime']:build_pair(C.ROLES['runtime'],image,base,lock,base_actors)}
        context=out/'runtime-context';context.mkdir();save(context/'products.json',products);save(context/'base.json',base)
        runtime_archive=out/(C.ROLES['runtime']+'-a/artifacts')/products[C.ROLES['runtime']]['archive'];shutil.copyfile(runtime_archive,context/runtime_archive.name)
        signer_api=C.load('apps_cache_existing_TEST_signer',source/'scripts/ci/full-development-composition/run.py')
        signer=signer_api.sign(context,out,[context/runtime_archive.name]);report['signer']=dict(fingerprint=signer,authority='EPHEMERAL_TEST_ONLY')
        subprocess.run(['gpgconf','--homedir',str(out/'test-signing'),'--kill','all'],check=True,capture_output=True,timeout=20)
        apps_deps=sorted({r for k in ('depends','makedepends','checkdepends') for r in C.recipe(source,C.ROLES['apps'])['metadata'].get(k,[])})
        save(context/'control.json',dict(signer=signer,apps_dependencies=apps_deps))
        runtime_dir,runtime_image=dependency_image('runtime-dependency-image',context,'runtime_image.py')
        runtime_base=base|{C.ROLES['runtime']:products[C.ROLES['runtime']]['version']};runtime_lock=out/'runtime575.lock'
        C.need(shared.inventory(runtime_lock.read_text())==runtime_base,'actual575 runtime build inventory differs')
        apps_actors=Owners('apps-consumers',runtime_image,runtime_dir)
        products[C.ROLES['apps']]=build_pair(C.ROLES['apps'],runtime_image,runtime_base,runtime_lock,apps_actors)
        products[C.ROLES['cache']]=build_pair(C.ROLES['cache'],image,base,lock,base_actors)
        life=out/'lifecycle-inputs';life.mkdir();runner=runner_context(life);save(life/'base.json',base);save(life/'products.json',products)
        shutil.copyfile(context/'TEST-public.asc',life/'TEST-public.asc')
        release=C.load('apps_cache_unchanged_signing',source/'scripts/release/release.py');keyenv=release.gpg_env(out/'test-signing',out/'signer-runtime')
        for name,product in products.items():
            archive=out/(name+'-a/artifacts')/product['archive'];shutil.copyfile(archive,life/archive.name)
            release.sign(life/archive.name,signer,keyenv)
        subprocess.run(['gpgconf','--homedir',str(out/'test-signing'),'--kill','all'],check=True,capture_output=True,timeout=20)
        save(life/'control.json',dict(signer=signer))
        fixture_source=out/'fixture-source'
        for name in ('scripts/release/test_release.py','scripts/release/release.py','scripts/release/source_delivery.py'):
            path=fixture_source/name;path.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source/name,path)
        save(out/'fixture-control.json',dict(signer=signer));public_tree(fixture_source)
        actor='cachy-asahi-product-'+os.urandom(16).hex();base_actors.append(actor)
        fixture_output=out/'synthetic-output';fixture_output.mkdir(mode=0o700)
        command(docker(image,actor,fixture_output)+['--env=CACHY_ASAHI_CATALOG_FIXTURE=1','--mount',f'type=bind,src={fixture_source},dst=/fixture-source,readonly',
            '--mount',f'type=bind,src={out}/fixture-control.json,dst=/fixture-control.json,readonly','--mount',f'type=bind,src={out}/test-signing,dst=/authority',
            '--mount',f'type=bind,src={C.HERE}/catalog_fixture.py,dst=/catalog_fixture.py,readonly','--entrypoint=/usr/bin/python3',image,'-I','-B','/catalog_fixture.py'],out/'catalog-fixture.log',180)
        shutil.copytree(fixture_output/'catalog-fixture',out/'catalog-fixture',symlinks=True)
        shutil.copytree(out/'catalog-fixture',life/'catalog-fixture',symlinks=True);public_tree(life)
        actor='cachy-asahi-product-lifecycle-'+os.urandom(16).hex();base_actors.append(actor)
        lifecycle_output=out/'lifecycle-output';lifecycle_output.mkdir(mode=0o700)
        command(docker(image,actor,lifecycle_output,root=True)+['--env=CACHY_ASAHI_APPS_CACHE_OPERATION=lifecycle','--mount',f'type=bind,src={life},dst=/inputs,readonly',
            '--mount',f'type=bind,src={runner},dst=/runner,readonly','--entrypoint=/usr/bin/python3',image,'-I','-B','/runner/lifecycle.py'],out/'lifecycle.log',600)
        shutil.copyfile(lifecycle_output/'lifecycle.json',out/'lifecycle.json')
        lifecycle=C.read(out/'lifecycle.json');C.validate_lifecycle(lifecycle)
        report.update(status='PASS_NATIVE_APPS_RUNTIME_CACHE_PAIRS_AND_INSTALLED_LIFECYCLE',lifecycle=lifecycle,cache_cleanup='APPLIED_DISPOSABLE_FIXTURES_ONLY',declared_dependency=None,installed_count=574+len(products))
    except BaseException as error:first=error;report.update(error=str(error)[:1024],error_type=type(error).__name__)
    finally:
        signal.setitimer(signal.ITIMER_REAL,0);save(out/'report.json',report)
        for fd in leases:os.close(fd)
        for sig,handler in previous.items():signal.signal(sig,handler)
    return int(first is not None)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('source','base-dir','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--consumer-token',required=True);a=p.parse_args()
    raise SystemExit(execute(a.source.absolute(),a.base_dir.absolute(),a.output.absolute(),a.consumer_token))

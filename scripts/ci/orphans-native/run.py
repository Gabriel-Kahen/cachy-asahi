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
import contract as C

HERE=Path(__file__).resolve().parent
ENV=dict(PATH='/usr/bin:/bin',LANG='C.UTF-8',LC_ALL='C.UTF-8',TZ='UTC')


def save(path,value):
    temp=path.with_suffix('.pending');temp.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n');temp.replace(path)


def pair_gate(result):
    C.need(result['status']=='contents-reproduced' and not result['errors'] and len(result['packages'])==1 and
           all(all(row[k] is True for k in ('installed_contents_equal','pkginfo_equal','bytes_equal','buildinfo_equal'))
               for row in result['packages'].values()),'both payload and complete archive bytes must reproduce')


def execute(source,base_dir,out,token):
    C.policy()
    C.need(platform.system()=='Linux' and platform.machine()=='aarch64' and os.getuid()==os.geteuid()>0 and
           not any(k.startswith('DOCKER_') for k in os.environ),'ordinary native ARM host required')
    for p in (source,base_dir,out):C.safe(p)
    C.need(not out.exists() and not any(out.is_relative_to(p) or p.is_relative_to(out) for p in (source,base_dir)),
           'fresh separate consumer output required')
    C.need(re.fullmatch('[0-9a-f]{32}',token),'explicit consumer token required');C.verify_source(source)
    original=json.loads((base_dir/'report.json').read_text());image=(base_dir/'image-id').read_text().strip()
    C.need(original.get('status')=='PASS_NATIVE_OFFLINE_574_TRANSACTION' and original['image']==image and
           re.fullmatch('sha256:[0-9a-f]{64}',image),'accepted owned574 image required')
    shared=C.load('accepted_orphans_build',source/'scripts/ci/welcome-native/run.py');shared.C=C
    common=C.load('orphans_logged',source/'scripts/virtual/common.py')
    checks=C.load('orphans_checks',source/'scripts/checks/package_checks.py')
    sys.path[:0]=[str(source/'scripts/build'),str(source/'scripts/checks')]
    bind=C.load('orphans_binding',source/'scripts/build/build.py')
    comparison=C.load('orphans_compare',source/'scripts/build/compare.py')
    lock=base_dir/'installed-packages.lock';base=shared.inventory(lock.read_text())
    selected=json.loads((source/'scripts/ci/maintained-desktop574-inputs.json').read_text())
    C.need(C.digest(lock)==C.BASE and len(base)==574 and not set(C.NAMES)&base.keys() and base=={r['name']:r['version'] for r in selected['packages']},'exact574 base lock required')
    dependencies=sorted({relation for name in C.NAMES for key in ('depends','makedepends','checkdepends')
                         for relation in C.recipe(source,name)['metadata'].get(key,[])})
    out.mkdir(mode=0o700);lease=os.open(out/'consumer.lock',os.O_CREAT|os.O_EXCL|os.O_RDWR|os.O_CLOEXEC,0o600)
    fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB);(out/'home').mkdir(mode=0o700)
    owner=dict(schema_version=1,token=token,image=image,label=C.LABEL,containers=[]);save(out/'owner.json',owner)
    report=dict(status='FAIL',scope='ONE_UNSELECTED_READONLY_ORPHAN_CANDIDATE',base_image=image,base_count=574,
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
            C.need(len(self)<4 and re.fullmatch(r'cachy-asahi-product-(?:(?:probe|lifecycle)-)?[0-9a-f]{32}',name) and name not in self,
                   'closed consumer actor set required')
            super().append(name);owner['containers']=list(self);save(out/'owner.json',owner)
    containers=Owners();plain_docker=shared.docker
    def docker(*args,**kwargs):return plain_docker(*args,**kwargs)+['--label='+C.LABEL+'='+token]
    shared.docker=docker
    previous={s:signal.signal(s,lambda *_:(_ for _ in ()).throw(TimeoutError('orphans lane deadline/cancellation')))
              for s in (signal.SIGINT,signal.SIGTERM,signal.SIGALRM)}
    signal.setitimer(signal.ITIMER_REAL,2100)
    try:
        C.need(capture(['docker','context','show'])=='default' and
               json.loads(capture(['docker','context','inspect','default']))[0]['Endpoints']['docker']['Host']=='unix:///var/run/docker.sock' and
               capture(['docker','info','--format','{{.Architecture}}']) in ('aarch64','arm64') and
               capture(['docker','image','inspect','--format','{{.Os}}/{{.Architecture}}',image])=='linux/arm64',
               'local native ARM daemon and image required')
        probe='cachy-asahi-product-probe-'+os.urandom(16).hex();containers.append(probe)
        command(docker(image,probe,out)+['--entrypoint=/bin/bash',image,'-c',
            '/usr/bin/pacman -T \"$@\" >/dev/null && /usr/bin/pacman -Q','orphans-dependencies',*dependencies],out/'base-inventory.log',30)
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
        context=out/'lifecycle-inputs';context.mkdir();save(context/'products.json',products);save(context/'base.json',base)
        for name in C.NAMES:
            shutil.copyfile(out/(name+'-a')/'artifacts'/products[name]['archive'],context/products[name]['archive'])
        signer_api=C.load('orphans_TEST_signer',source/'scripts/ci/full-development-composition/run.py')
        signer=signer_api.sign(context,out,[context/products[C.PRODUCT]['archive']])
        report['signer']=dict(fingerprint=signer,authority='EPHEMERAL_TEST_ONLY_OUTSIDE_UNTRUSTED_ACTORS')
        subprocess.run(['gpgconf','--homedir',str(out/'test-signing'),'--kill','all'],check=True,capture_output=True,timeout=20)
        save(context/'control.json',dict(signer=signer))
        # Public context contains only the accepted archive, detached signature and verification key.
        for path in (context,*context.rglob('*')):path.chmod(0o755 if path.is_dir() else 0o644)
        runner=context/'runner';runner.mkdir()
        for name in ('contract.py','input-policy.json','installed.py','fixture.py','lifecycle.py'):shutil.copyfile(HERE/name,runner/name)
        accepted=runner/'accepted';accepted.mkdir()
        shutil.copyfile(source/'scripts/ci/welcome-native/lifecycle.py',accepted/'lifecycle.py')
        shutil.copyfile(source/'scripts/ci/full-root-upgrade/root_upgrade.py',accepted/'root_upgrade.py')
        lifecycle_output=out/'lifecycle-output';lifecycle_output.mkdir(mode=0o700)
        container='cachy-asahi-product-lifecycle-'+os.urandom(16).hex();containers.append(container)
        command(docker(image,container,lifecycle_output,root=True)+['--env=CACHY_ASAHI_ORPHANS_OPERATION=lifecycle',
            '--mount',f'type=bind,src={context},dst=/inputs,readonly',
            '--mount',f'type=bind,src={runner},dst=/runner,readonly',
            '--entrypoint=/usr/bin/python3',image,'-I','-B','/runner/lifecycle.py'],out/'lifecycle.log',1200)
        shutil.copyfile(lifecycle_output/'lifecycle.json',out/'lifecycle.json')
        shutil.copytree(lifecycle_output/'public-reports',out/'public-reports')
        life=json.loads((out/'lifecycle.json').read_text());C.validate_lifecycle(life)
        report.update(lifecycle=life,dependencies=dependencies,status='PASS_NATIVE_ORPHANS_PAIR_AND_READONLY_LIFECYCLE',removal='NOT_IMPLEMENTED')
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
    parser.add_argument('--consumer-token',required=True);args=parser.parse_args()
    raise SystemExit(execute(args.source.absolute(),args.base_dir.absolute(),args.output.absolute(),args.consumer_token))

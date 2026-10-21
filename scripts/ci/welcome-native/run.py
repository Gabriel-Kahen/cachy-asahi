#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Four offline fresh native builds and one disposable two-product lifecycle."""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import time
import contract as C

HERE=Path(__file__).resolve().parent
ENV={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8','TZ':'UTC'}


def save(path,value):path.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')


def inventory(text):
    rows=[line.split() for line in text.splitlines()]
    C.need(rows and all(len(r)==2 for r in rows) and len(dict(rows))==len(rows),'invalid inventory')
    return dict(rows)


def docker(image,name,output, *, root=False):
    argv=['docker','run','--name',name,'--pull=never','--platform=linux/arm64','--network=none',
        '--cap-drop=ALL','--security-opt=no-new-privileges','--pids-limit=256','--memory=3g','--cpus=4',
        '--user','0:0' if root else f'{os.getuid()}:{os.getgid()}',
        '--tmpfs','/tmp:rw,nosuid,nodev,exec,size=2g','--mount',f'type=bind,src={output},dst=/out']
    if root:
        argv += ['--cap-add='+c for c in ('CHOWN','DAC_OVERRIDE','FOWNER','FSETID','SETUID','SETGID')]
    else:argv += ['--read-only']
    return argv


def build(source,out,base,image,lock,name,side,epoch,execute,containers,checks,bind):
    C.verify_source(source)
    directory=out/(name+'-'+side);directory.mkdir();inputs=directory/'inputs'
    shutil.copytree(source/C.RECIPES[name],inputs)
    reviewed=C.recipe(source,name);artifacts=directory/'artifacts';artifacts.mkdir()
    C.need({str(f.relative_to(inputs)):C.digest(f) for f in inputs.rglob('*') if f.is_file()}==reviewed['input_sha256'],
           'fresh recipe snapshot differs from reviewed inputs')
    expected=directory/'expected-packages.lock';shutil.copyfile(lock,expected)
    container='cachy-asahi-product-'+os.urandom(16).hex();containers.append(container)
    argv=docker(image,container,artifacts)+[
        '--env=CACHY_ASAHI_CONTAINER=1','--env=SOURCE_DATE_EPOCH='+str(epoch),
        '--mount',f'type=bind,src={inputs},dst=/inputs,readonly',
        '--mount',f'type=bind,src={expected},dst=/expected-packages.lock,readonly',
        '--mount',f'type=bind,src={source}/scripts/build/container-entry.sh,dst=/builder-entry.sh,readonly',
        '--entrypoint=/bin/bash',image,'/builder-entry.sh']
    provenance=dict(status='building',image=image,image_id=image,mode='native',source_date_epoch=epoch,
        recipe_inputs=reviewed['input_sha256'],recipe_metadata=reviewed['metadata'],
        expected_packages_sha256=C.digest(expected),entry_script_sha256=C.digest(source/'scripts/build/container-entry.sh'),
        clean_environment_id=container,command=argv,hardware_status='NOT RUN')
    save(directory/'provenance.json',provenance)
    execute(argv,directory/'build.log',240)
    required=('environment.txt','packages.lock','config.sha256','makepkg.conf','pacman.conf','generated.SRCINFO')
    C.need(all((artifacts/n).is_file() and not (artifacts/n).is_symlink() for n in required),'build evidence incomplete')
    C.need(inventory((artifacts/'packages.lock').read_text())==base,'build inventory differs')
    bind.bind_generated(reviewed['metadata'],checks.metadata((artifacts/'generated.SRCINFO').read_text()))
    archives=[f for f in artifacts.glob('*.pkg.tar.*') if not f.name.endswith('.sig')]
    C.need(len(archives)==1,'exact one package required; debug/split outputs require explicit review')
    package=checks.package(archives[0]);errors=bind.bind_artifact(reviewed['metadata'],package,reviewed['input_sha256']['PKGBUILD'])
    C.need(not errors,'artifact metadata differs: '+str(errors))
    payload=C.payload(package,source,name);elf=None
    if name==C.NAME:
        # Tar extraction is confined to one in-memory member, never a filesystem extraction.
        proc=None
        if archives[0].name.endswith('.zst'):
            proc=subprocess.Popen(['zstd','-dc','--',str(archives[0])],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            archive=tarfile.open(fileobj=proc.stdout,mode='r|')
        else:archive=tarfile.open(archives[0],mode='r:*')
        try:
            with archive as tar:
                data=None
                for member in tar:
                    if checks.clean_name(member.name)=='usr/bin/'+name:
                        C.need(member.isfile() and member.size<=4*1024**2,'Welcome ELF cap')
                        data=tar.extractfile(member).read()
                C.need(data is not None,'Welcome executable absent')
            if proc:
                proc.stdout.close();diagnostic=proc.stderr.read(4097)
                C.need(proc.wait(timeout=10)==0 and len(diagnostic)<=4096,'package decompressor failed')
            elf=C.elf(data,checks)
        finally:
            if proc:
                if proc.poll() is None:proc.kill();proc.wait(timeout=5)
                proc.stdout.close();proc.stderr.close()
    tests=C.check_log(directory/'build.log',name)
    validation=dict(package=package,elf=elf,tests=tests,payload=payload,errors=[])
    save(directory/'validation.json',validation)
    provenance.update(status='built-package-static-pass',artifacts={archives[0].name:C.digest(archives[0])},
        files={'artifacts/'+f.name:C.digest(f) for f in artifacts.iterdir() if f.is_file()})
    provenance['files'].update({n:C.digest(directory/n) for n in ('build.log','validation.json','expected-packages.lock')})
    save(directory/'provenance.json',provenance)
    return dict(directory=directory,archive=archives[0],payload=payload,elf=elf,tests=tests)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('source','base-dir','output'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();source,base_dir,out=(C.safe(p.absolute()) for p in (args.source,args.base_dir,args.output))
    C.need(platform.system()=='Linux' and platform.machine() in ('aarch64','arm64') and
           os.getuid()==os.geteuid()>0 and not any(k.startswith('DOCKER_') for k in os.environ),'ordinary native ARM host required')
    C.need(not out.exists() and not out.is_relative_to(source) and not out.is_relative_to(base_dir),'fresh separate output required')
    C.verify_source(source);C.activation(source);out.mkdir(mode=0o700);(out/'home').mkdir(mode=0o700)
    env=dict(ENV,HOME=str(out/'home'));common=C.load('product_logged',source/'scripts/virtual/common.py')
    checks=C.load('product_checks',source/'scripts/checks/package_checks.py')
    sys.path.insert(0,str(source/'scripts/build'));sys.path.insert(0,str(source/'scripts/checks'))
    bind=C.load('product_build_binding',source/'scripts/build/build.py');comparison=C.load('product_comparison',source/'scripts/build/compare.py')
    report=dict(status='FAIL',scope='UNSELECTED_WELCOME8_BUILD_PAIR_ONLY_NO_ALPM_GUI' ,hardware='NOT_RUN',GUI='NOT_RUN',
                products={},commands=[],cleanup=[],original_ten_composition='UNCHANGED')
    containers=[];active=None;first=None

    def execute(argv,log,seconds):
        nonlocal active
        report['commands'].append(dict(argv=argv,log=str(log.relative_to(out))))
        active=common.LoggedProcess(argv,log,env=env,limit=16*1024**2)
        error=None
        try:
            active.process.wait(timeout=seconds);active.finish()
            C.need(active.process.returncode==0,'command failed: '+log.name)
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
        value=subprocess.check_output(argv,env=env,text=True,stderr=subprocess.DEVNULL,timeout=30)
        C.need(len(value)<=1024**2,'capture cap');return value.strip()

    def interrupted(*_):raise TimeoutError('product trial cancelled/deadline')
    previous={sig:signal.signal(sig,interrupted) for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGALRM)}
    signal.setitimer(signal.ITIMER_REAL,1800)
    try:
        original=json.loads((base_dir/'report.json').read_text())
        C.need(original.get('status')=='PASS_NATIVE_OFFLINE_574_TRANSACTION','successful owned574 base required')
        image=(base_dir/'image-id').read_text().strip();C.need(re.fullmatch('sha256:[0-9a-f]{64}',image) and original['image']==image,'base image differs')
        C.need(capture(['docker','context','show'])=='default' and
            json.loads(capture(['docker','context','inspect','default']))[0]['Endpoints']['docker']['Host']=='unix:///var/run/docker.sock',
            'local default Docker required')
        C.need(capture(['docker','info','--format','{{.Architecture}}']) in ('aarch64','arm64') and
            capture(['docker','image','inspect','--format','{{.Os}}/{{.Architecture}}',image])=='linux/arm64','native ARM daemon/image required')
        lock=base_dir/'installed-packages.lock';base=inventory(lock.read_text())
        selected=json.loads((source/'scripts/ci/maintained-desktop574-inputs.json').read_text())
        C.need(len(base)==574 and base=={r['name']:r['version'] for r in selected['packages']},'exact574 lock required')
        probe='cachy-asahi-product-probe-'+os.urandom(16).hex();containers.append(probe)
        execute(['docker','run','--name',probe,'--pull=never','--network=none','--read-only','--cap-drop=ALL',
                 '--security-opt=no-new-privileges','--entrypoint=/usr/bin/pacman',image,'-Q'],out/'base-inventory.log',30)
        C.need(inventory((out/'base-inventory.log').read_text())==base,'actual base inventory differs')
        report.update(base_image=image,base_count=574,base_lock_sha256=C.digest(lock));products={}
        for name in C.NAMES:
            pair=[build(source,out,base,image,lock,name,side,selected['source_date_epoch'],execute,containers,checks,bind)
                  for side in ('a','b')]
            result=comparison.compare(*(r['directory'] for r in pair))
            C.need(result['status']=='contents-reproduced' and not result['errors'],'fresh build content comparison failed')
            save(out/(name+'-comparison.json'),result)
            report['products'][name]=dict(comparison=result,builds=[dict(archive=r['archive'].name,sha256=C.digest(r['archive']),
                payload=r['payload'],elf=r['elf'],tests=r['tests']) for r in pair])
            products[name]=dict(archive=pair[0]['archive'].name,sha256=C.digest(pair[0]['archive']),version=C.VERSIONS[name],payload=pair[0]['payload'])
        report['status']='PASS_NATIVE_WELCOME8_BUILD_PAIR_CONTENTS_ONLY'
    except BaseException as error:first=error;report.update(error=str(error)[:1024],error_type=type(error).__name__)
    finally:
        signal.setitimer(signal.ITIMER_REAL,0)
        for name in reversed(containers):
            row=dict(container=name,status='FAIL')
            try:
                execute(['docker','rm','-f',name],out/('cleanup-'+name+'.log'),20)
                remaining=capture(['docker','container','ls','-a','--filter','name=^/'+name+'$','--format','{{.Names}}'])
                C.need(not remaining,'owned container remained');row['status']='PASS';row['absence_verified']=True
            except BaseException as error:
                row['error']=str(error)[:512]
                if first is None:first=error
            report['cleanup'].append(row)
        report['status']=report['status'] if first is None else 'FAIL'
        save(out/'report.json',report)
        for sig,handler in previous.items():signal.signal(sig,handler)
    return int(first is not None)


if __name__=='__main__':raise SystemExit(main())

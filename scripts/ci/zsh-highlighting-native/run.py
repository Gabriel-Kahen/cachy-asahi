#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Two unchanged highlighting builds plus signed disposable install/terminal/removal."""
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
import traceback

ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent
sys.path[:0]=[str(ROOT/'scripts/ci'),str(ROOT/'scripts/checks')]
import native_arm as native
from package_checks import recipe,PACKAGE_METADATA

RECIPE='packages/tools/cachy-asahi-zsh-syntax-highlighting'
BUILDER_SHA='6ca8813aa7a704251d842e1d7e05404aa56e4029067ccacb57b0a7a3c8af80e5'
INPUTS_SHA='b2a234c76c3a820382238023203a8b699a503153f63b938376fd16433c4d90f9'
PACKAGES_SHA='cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac'
AUTOSUGGEST={'opt-in.zsh':'692bca1e9ba1a2e9bd32de08cb6ffa5d15b19f85b48e1c08d85a48e41fe6f768',
            'zsh-autosuggestions.zsh':'eec7ba8f7a71414ace0ea0fab0908d005b24cf65d83b169c0ff97815d3cfc51a'}


def need(value,message):
    if not value:raise ValueError(message)


def command(argv,log,timeout):
    with log.open('wb') as stream:
        child=subprocess.Popen(list(map(str,argv)),stdin=subprocess.DEVNULL,stdout=stream,
            stderr=subprocess.STDOUT,start_new_session=True)
        try:code=child.wait(timeout=timeout)
        except BaseException:
            for sig,seconds in ((signal.SIGTERM,5),(signal.SIGKILL,5)):
                try:os.killpg(child.pid,sig)
                except ProcessLookupError:pass
                try:child.wait(timeout=seconds);break
                except subprocess.TimeoutExpired:continue
            raise
        need(code==0,'fixed native command failed: '+log.name)


def preflight(args):
    need(platform.system()=='Linux' and platform.machine() in ('aarch64','arm64') and
         os.getuid()==os.geteuid()>0 and os.getgid()==os.getegid(),'ordinary native ARM host required')
    need(not any(k.startswith('DOCKER_') and k!='DOCKER_CONFIG' for k in os.environ),'Docker overrides refused')
    need(re.fullmatch('[0-9a-f]{40}',args.source_commit or ''),'exact Source required')
    need(native.run(['git','-C',str(ROOT),'rev-parse','HEAD'],timeout=10)==args.source_commit,'Source checkout differs')
    paths=(ROOT,args.base,args.output)
    need(all(p.is_absolute() and '..' not in p.parts and not any(c in str(p) for c in ',\r\n') and
         not any(q.is_symlink() for q in (p,*p.parents)) for p in paths),'ordinary absolute paths required')
    need(args.base.is_dir() and not args.output.exists() and not (args.base/'image-id').exists(),'seeded base/new trial output required')
    need(all(not a.is_relative_to(b) and not b.is_relative_to(a) for i,a in enumerate(paths) for b in paths[i+1:]),'separate source/base/output required')
    need(json.loads((args.base/'seed-report.json').read_text())['status']=='SIX_EXACT_EXISTING_SEED_FILES_READY','same-job574 seed required')
    helper=ROOT/'scripts/ci/maintained_desktop574.py';inputs=ROOT/'scripts/ci/maintained-desktop574-inputs.json'
    need(native.sha(helper)==BUILDER_SHA and native.sha(inputs)==INPUTS_SHA,'held8d8 builder/input pins differ')
    selected=['scripts/ci','scripts/build','scripts/checks',RECIPE,'packages/shells/cachy-asahi-zsh-autosuggestions']
    subprocess.run(['git','-C',str(ROOT),'diff','--exit-code','HEAD','--',*selected],check=True,timeout=10,stdout=subprocess.DEVNULL)
    for relative in (RECIPE,'scripts/ci/zsh-highlighting-native'):
        names=native.run(['git','-C',str(ROOT),'ls-tree','-r','--name-only',args.source_commit,'--',relative],timeout=10).splitlines()
        need(set(names)=={str(p.relative_to(ROOT)) for p in (ROOT/relative).rglob('*') if p.is_file()},'unreviewed source path')
        for name in names:
            raw=subprocess.check_output(['git','-C',str(ROOT),'show',args.source_commit+':'+name],timeout=10)
            need(not (ROOT/name).is_symlink() and (ROOT/name).read_bytes()==raw,'exact Source bytes differ')
    for name,pin in AUTOSUGGEST.items():
        need(native.sha(ROOT/'packages/shells/cachy-asahi-zsh-autosuggestions'/name)==pin,'held autosuggestions fixture differs')
    reviewed=recipe(ROOT/RECIPE/'PKGBUILD');data=reviewed['metadata']
    need(not reviewed['errors'] and data.get('pkgname')==[Path(RECIPE).name] and data.get('pkgver')==['0.8.1.dev.e6683f2'] and
         data.get('pkgrel')==['1'] and data.get('arch')==['any'] and data.get('depends')==['zsh>=4.3.11'] and
         set(data.get('license',()))=={'BSD-3-Clause','MIT'} and not data.get('install'),'fixed highlighting recipe required')
    return json.loads(inputs.read_bytes()),reviewed


def payload(build,reviewed):
    validation=json.loads((build/'validation.json').read_text());record=json.loads((build/'provenance.json').read_text())
    need(record['status']=='built-package-static-pass' and record['mode']=='native' and not validation['errors'] and
         len(validation['artifacts'])==1 and 'Starting check()' in (build/'build.log').read_text(),'native recipe checks failed')
    rows=validation['artifacts'][0]['members'];actual={p:r for p,r in rows.items() if p not in PACKAGE_METADATA and r['type']!='5'}
    runtime=(['zsh-syntax-highlighting.zsh','.version','.revision-hash','opt-in.zsh']+
             ['highlighters/'+name+'/'+name+'-highlighter.zsh' for name in
              ('brackets','cursor','line','main','pattern','regexp','root')])
    expected={'usr/share/cachy-asahi/zsh-syntax-highlighting/'+p:Path(p).name for p in runtime}
    expected.update({'usr/share/doc/'+Path(RECIPE).name+'/'+p:p for p in ('usage.md','README.md','INSTALL.md')})
    expected.update({'usr/share/licenses/'+Path(RECIPE).name+'/'+p:p for p in ('NOTICE','LICENSE.upstream','LICENSE.project')})
    need(len(expected)==17 and set(actual)==set(expected),'exact17 regular payload required')
    for name,source in expected.items():
        need(actual[name]['type']=='0' and actual[name]['mode']==0o644 and actual[name]['sha256']==reviewed[source],'payload bytes/mode differs')
    archives=list((build/'artifacts').glob('*.pkg.tar.*'));need(len(archives)==1,'one native package required')
    need(record['artifacts'][archives[0].name]==native.sha(archives[0]),'archive/provenance differs')
    return archives[0],{p:{k:r[k] for k in ('mode','sha256')} for p,r in actual.items()}


def cleanup(base,output,started,docker,bootstrap_started,bootstrap_completed,before_images,lifecycle):
    result={'status':'PASS','containers':[],'image':'NOT CREATED'}
    names=[lifecycle] if lifecycle else []
    for attempt in started:
        try:
            name=json.loads((output/f'build-{attempt}/provenance.json').read_text())['clean_environment_id']
            need(re.fullmatch('cachy-asahi-[0-9a-f]{16}',name),'owned build name required');names.append(name)
        except (OSError,ValueError,KeyError):result['status']='FAIL';result['containers'].append({'attempt':attempt,'absence_verified':False})
    for name in names:
        try:
            query=docker+['container','ls','-a','--filter','name=^/'+name+'$','--format','{{.Names}}']
            before=native.run(query,timeout=10);need(before in ('',name),'ambiguous owned container')
            if before:native.run(docker+['rm','-f',name],timeout=20)
            need(native.run(query,timeout=10)=='','owned container remains');result['containers'].append({'name':name,'absence_verified':True})
        except (OSError,ValueError,subprocess.SubprocessError):result['status']='FAIL';result['containers'].append({'name':name,'absence_verified':False})
    try:
        path=base/'image-id'
        if bootstrap_started and not bootstrap_completed:
            # An iid cannot prove retirement of 8d8's unnamed probe/backend.
            result.update(status='FAIL',bootstrap_retirement='UNKNOWN',
                          image={'status':'UNKNOWN','absence_verified':False,'removal':'NOT ATTEMPTED'})
        elif path.exists():
            need(bootstrap_started and bootstrap_completed,'completed bootstrap image required')
            image=path.read_text().strip();need(re.fullmatch('sha256:[0-9a-f]{64}',image),'immutable image required')
            need(before_images is not None,'image ownership baseline unavailable')
            if image in before_images:
                result.update(status='FAIL',image={'id':image,'status':'PREEXISTING_PRESERVED',
                              'absence_verified':False,'removal':'NOT ATTEMPTED'})
            else:
                native.run(docker+['image','rm','--no-prune',image],timeout=30)
                need(image not in native.run(docker+['image','ls','-a','--no-trunc','-q'],timeout=10).splitlines(),'bootstrap image remains')
                result['image']={'id':image,'absence_verified':True}
        elif bootstrap_started:result.update(status='FAIL',image={'status':'UNKNOWN','absence_verified':False})
    except (OSError,ValueError,subprocess.SubprocessError):result.update(status='FAIL',image={'status':'FAIL','absence_verified':False})
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--source-commit',required=True)
    parser.add_argument('--base',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();inputs,reviewed=preflight(args);output=args.output;output.mkdir(mode=0o700)
    summary=output/'summary';summary.mkdir();native.save(summary/'recipe.json',reviewed)
    reviewed_path=summary/'reviewed-inputs.json';native.save(reviewed_path,reviewed['input_sha256'])
    report={'status':'FAIL','Source':args.source_commit,'pair':'NOT RUN','installed_terminal':'NOT RUN','lifecycle':'NOT RUN',
            'upgrade':'NOT RUN','target_hardware':'NOT RUN','release_trust':'NOT ESTABLISHED','cancelled':False}
    docker=['docker','--host=unix:///var/run/docker.sock'];started=[];bootstrap_started=False;bootstrap_completed=False;before_images=None;lifecycle=None
    def cancel(*_):raise KeyboardInterrupt()
    previous={sig:signal.signal(sig,cancel) for sig in (signal.SIGINT,signal.SIGTERM)}
    try:
        images=native.run(docker+['image','ls','-a','--no-trunc','-q'],timeout=10).splitlines()
        need(all(re.fullmatch('sha256:[0-9a-f]{64}',v) for v in images),'pre-bootstrap image inventory differs')
        before_images=set(images);native.save(summary/'before-images.json',sorted(before_images))
        bootstrap_started=True
        command([sys.executable,'-I','-B',ROOT/'scripts/ci/maintained_desktop574.py','build',
                 '--inputs',ROOT/'scripts/ci/maintained-desktop574-inputs.json','--output',args.base],summary/'bootstrap.log',2400)
        base_report=json.loads((args.base/'report.json').read_text());image=(args.base/'image-id').read_text().strip()
        need(base_report['status']=='PASS_NATIVE_OFFLINE_574_TRANSACTION' and base_report['image']==image and
             re.fullmatch('sha256:[0-9a-f]{64}',image) and native.sha(args.base/'installed-packages.lock')==PACKAGES_SHA,'574 builder handoff differs')
        bootstrap_completed=True
        archive=None;members=None
        for attempt in (1,2):
            started.append(attempt);build=output/f'build-{attempt}'
            command([sys.executable,'-B',ROOT/'scripts/build/build.py',ROOT/RECIPE,'--image',image,'--mode','native',
                '--source-date-epoch',str(inputs['source_date_epoch']),'--network','none','--expected-packages',args.base/'installed-packages.lock',
                '--reviewed-inputs',reviewed_path,'--timeout','120','--output',build],summary/f'build-{attempt}.log',180)
            current,payload_rows=payload(build,reviewed['input_sha256'])
            if archive is None:archive,members=current,payload_rows
        command([sys.executable,'-B',ROOT/'scripts/build/compare.py',output/'build-1',output/'build-2','--require-bytes'],summary/'compare.json',120)
        report['pair']='PASS';bundle=output/'lifecycle-inputs';bundle.mkdir()
        shutil.copyfile(archive,bundle/archive.name);shutil.copyfile(args.base/'installed-packages.lock',bundle/'packages.lock')
        native.save(bundle/'package.json',{'name':Path(RECIPE).name,'version':'0.8.1.dev.e6683f2-1','archive':archive.name,
            'sha256':native.sha(archive),'payload':members})
        fixture=output/'fixture-autosuggestions';fixture.mkdir()
        for name in AUTOSUGGEST:shutil.copyfile(ROOT/'packages/shells/cachy-asahi-zsh-autosuggestions'/name,fixture/name)
        lifecycle='cachy-asahi-highlight-'+os.urandom(8).hex()
        command(docker+['run','--rm','--pull=never','--name',lifecycle,'--platform=linux/arm64','--user=0:0','--network=none',
            '--cap-drop=ALL','--cap-add=CHOWN','--cap-add=SETUID','--cap-add=SETGID','--cap-add=DAC_OVERRIDE',
            '--security-opt=no-new-privileges','--pids-limit=128','--memory=1g','--cpus=2','--tmpfs=/tmp:rw,nosuid,nodev,size=128m',
            '--mount','type=bind,src='+str(bundle)+',dst=/inputs,readonly',
            '--mount','type=bind,src='+str(fixture)+',dst=/fixture-autosuggestions,readonly',
            '--mount','type=bind,src='+str(HERE/'container.py')+',dst=/container.py,readonly',
            '--mount','type=bind,src='+str(HERE/'terminal.py')+',dst=/terminal.py,readonly',
            '--entrypoint=/usr/bin/python3',image,'-I','-B','/container.py'],summary/'lifecycle.log',300)
        result=json.loads((summary/'lifecycle.log').read_text());need(result['status']=='PASS' and len(result['checkpoints'])==4,'signed lifecycle failed')
        native.save(summary/'lifecycle.json',result);report.update(status='PASS',installed_terminal='PASS',lifecycle='PASS',
            base_inventory_sha256=PACKAGES_SHA,final_inventory_sha256=result['final_inventory_sha256'],package_sha256=native.sha(archive))
    except (KeyboardInterrupt,OSError,ValueError,KeyError,subprocess.SubprocessError) as error:
        report.update(error_kind=type(error).__name__,traceback=traceback.format_exc(limit=10),cancelled=isinstance(error,KeyboardInterrupt))
    finally:
        interrupted=[]
        for sig in previous:signal.signal(sig,lambda signum,_:interrupted.append(signum))
        try:
            report['bootstrap_started']=bootstrap_started;report['bootstrap_completed']=bootstrap_completed
            report['cleanup']=cleanup(args.base,output,started,docker,bootstrap_started,bootstrap_completed,before_images,lifecycle)
            if report['cleanup']['status']!='PASS':report['status']='FAIL'
            if interrupted:report.update(status='FAIL',cancelled=True)
            native.save(summary/'result.json',report)
        finally:
            for sig,handler in previous.items():signal.signal(sig,handler)
    return int(report['status']!='PASS')


if __name__=='__main__':sys.exit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build three fixed audio Rust package pairs on a signed 350-package ARM base."""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import sys
import traceback

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'scripts/ci'))
import native_arm as native
import scoped_build as scoped

INPUTS_SHA = '7297c9fa299e65484cdb46fc4d149af5815627a385d3050c5c884cd0cc3889c2'
PACKAGES_SHA = 'd6b50a41e5e1c1880faedfbd6a1eebad6d271901c0a42923af5c8e977f23e963'
SCOPED_SHA = 'cf4efa8b19b3743cf6b7e8aca9f7494119556e765781529d5b1cdd4266c19cff'


def need(value,message):
    if not value: raise ValueError(message)


def preflight(args):
    need(platform.system() == 'Linux' and platform.machine() in ('aarch64','arm64') and
         os.getuid() == os.geteuid() > 0 and os.getgid() == os.getegid(), 'ordinary native ARM host required')
    need(not any(k.startswith('DOCKER_') and k != 'DOCKER_CONFIG' for k in os.environ), 'Docker overrides refused')
    need(re.fullmatch('[0-9a-f]{40}',args.source_commit or ''), 'exact reviewed Source required')
    need(native.run(['git','-C',str(ROOT),'rev-parse','HEAD'],timeout=10) == args.source_commit, 'checkout differs')
    paths=(ROOT,args.cache,args.output)
    need(all(p.is_absolute() and '..' not in p.parts and not any(c in str(p) for c in ',\n\r') and
         not any(q.is_symlink() for q in (p,*p.parents)) for p in paths), 'ordinary absolute paths required')
    need(args.cache.is_dir() and args.cache.stat().st_uid == os.getuid() and not args.output.exists(), 'owned seeded cache/new output required')
    need(all(not a.is_relative_to(b) and not b.is_relative_to(a) for i,a in enumerate(paths) for b in paths[i+1:]), 'separate source/cache/output required')
    selected=['scripts/ci/asahi-audio-rust','scripts/ci/native_arm.py','scripts/build','scripts/checks']+[r['path'] for r in scoped.RECIPES]
    subprocess.run(['git','-C',str(ROOT),'diff','--exit-code','HEAD','--',*selected],check=True,timeout=10,stdout=subprocess.DEVNULL)
    for row in scoped.RECIPES:
        directory=ROOT/row['path'];report=scoped.recipe(directory/'PKGBUILD');need(not report['errors'], 'recipe checks failed')
        names=native.run(['git','-C',str(ROOT),'ls-tree','-r','--name-only',args.source_commit,'--',row['path']],timeout=10).splitlines()
        need(set(names) == {str(p.relative_to(ROOT)) for p in directory.rglob('*') if p.is_file()}, 'untracked recipe input')
        for name in names:
            raw=subprocess.check_output(['git','-C',str(ROOT),'show',args.source_commit+':'+name],timeout=30)
            need(not (ROOT/name).is_symlink() and (ROOT/name).read_bytes() == raw, 'recipe differs from reviewed Source')
    need(native.sha(HERE/'scoped_build.py') == SCOPED_SHA and native.sha(HERE/'expected-packages.lock') == PACKAGES_SHA, 'build checks/inventory changed')
    return native.load_pinned(HERE/'inputs.lock.json',INPUTS_SHA)


def cleanup(output,docker,bootstrap_started,started):
    result={'status':'PASS','containers':[],'image':'NOT CREATED'}
    for relative in started:
        try:
            record=json.loads((output/relative/'provenance.json').read_text())
            name=record['clean_environment_id'];need(re.fullmatch('cachy-asahi-[0-9a-f]{16}',name), 'owned build container required')
            query=docker+['container','ls','-a','--filter','name=^/'+name+'$','--format','{{.Names}}']
            before=native.run(query,timeout=10);need(before in ('',name), 'ambiguous owned container query')
            if before:native.run(docker+['rm','-f',name],timeout=20)
            need(native.run(query,timeout=10) == '', 'owned container remains')
            result['containers'].append({'name':name,'absence_verified':True})
        except (OSError,ValueError,KeyError,subprocess.SubprocessError):
            result['status']='FAIL';result['containers'].append({'build':relative,'absence_verified':False})
    try:
        path=output/'native/image-id'
        if path.exists():
            image=path.read_text().strip();need(re.fullmatch('sha256:[0-9a-f]{64}',image), 'owned immutable image required')
            native.run(docker+['image','rm','--no-prune',image],timeout=30)
            need(image not in native.run(docker+['image','ls','-a','--no-trunc','-q'],timeout=10).splitlines(), 'owned image remains')
            result['image']={'id':image,'absence_verified':True}
        elif bootstrap_started:result.update(status='FAIL',image={'status':'UNKNOWN','absence_verified':False})
    except (OSError,ValueError,subprocess.SubprocessError):result.update(status='FAIL',image={'status':'FAIL','absence_verified':False})
    return result


def run(args):
    inputs=preflight(args);output=args.output;output.mkdir(mode=0o700)
    bootstrap=output/'native';bootstrap.mkdir();summary=output/'summary';summary.mkdir()
    report={'status':'FAIL','source_commit':args.source_commit,'scope':'BUILD ONLY','inputs_sha256':INPUTS_SHA,
            'installation':'NOT RUN','hardware':'NOT RUN','services':'NOT RUN','target_trust':'NOT ESTABLISHED',
            'selected_for_release':False,'cancelled':False,'pairs':{}}
    docker=['docker','--host=unix:///var/run/docker.sock'];started=[];bootstrap_started=False
    def cancel(*_):raise KeyboardInterrupt()
    previous={sig:signal.signal(sig,cancel) for sig in (signal.SIGINT,signal.SIGTERM)}
    try:
        native.save(bootstrap/'inputs.lock.json',inputs);probe=native.probe(bootstrap);docker=['docker','--host='+probe['docker_endpoint']]
        native.audit(inputs,args.cache,bootstrap);bootstrap_started=True;image=native.build(inputs,args.cache,bootstrap,{})
        need(native.sha(bootstrap/'packages.lock') == PACKAGES_SHA, 'exact350 compiler differs')
        for row in scoped.RECIPES:
            name=row['name'];reviewed=summary/(name+'-reviewed-inputs.json');native.save(reviewed,row['input_sha256'])
            builds=[]
            for attempt in (1,2):
                relative=name+'-build-'+str(attempt);started.append(relative);build=output/relative;builds.append(build)
                native.run([sys.executable,'-B',str(HERE/'scoped_build.py'),'build',str(ROOT/row['path']),
                    '--image',image,'--mode','native','--source-date-epoch',str(inputs['source_date_epoch']),
                    '--network','none','--expected-packages',str(bootstrap/'packages.lock'),'--reviewed-inputs',str(reviewed),
                    '--timeout','900','--output',str(build)],summary/(relative+'.log'),960)
                need('Starting check()' in (build/'build.log').read_text(), 'structural recipe checks not run')
            native.run([sys.executable,'-B',str(HERE/'scoped_build.py'),'compare',*[str(p) for p in builds],
                        '--require-bytes'],summary/(name+'-compare.json'),120)
            report['pairs'][name]={'status':'PASS','version':row['version'],'checks':'metadata/payload/AArch64/structural16K/bytes','audio_execution':'NOT RUN'}
        report.update(status='PASS',image=image,expected_packages=350,packages_sha256=PACKAGES_SHA)
    except (KeyboardInterrupt,OSError,ValueError,KeyError,subprocess.SubprocessError) as error:
        report.update(error_kind=type(error).__name__,traceback=traceback.format_exc(limit=10),cancelled=isinstance(error,KeyboardInterrupt))
    finally:
        interrupted=[]
        for sig in previous:signal.signal(sig,lambda signum,_:interrupted.append(signum))
        try:
            report['cleanup']=cleanup(output,docker,bootstrap_started,started)
            if report['cleanup']['status'] != 'PASS':report['status']='FAIL'
            if interrupted:report.update(status='FAIL',cancelled=True)
            native.save(summary/'result.json',report)
        finally:
            for sig,handler in previous.items():signal.signal(sig,handler)
    return int(report['status'] != 'PASS')


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--source-commit',required=True)
    parser.add_argument('--cache',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    return run(parser.parse_args())


if __name__ == '__main__':sys.exit(main())

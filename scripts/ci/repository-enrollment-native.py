#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build the fixed setup/repository package twice on the signed native ARM base."""
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

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/ci'))
sys.path.insert(0, str(ROOT / 'scripts/checks'))
import native_arm as native
from package_checks import recipe, PACKAGE_METADATA

RECIPE = 'packages/settings/cachy-asahi-setup'
INPUTS_SHA = 'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f'
PACKAGES_SHA = 'fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25'
PAYLOAD = {'usr/bin/cachy-asahi-setup': ('cachy-asahi-setup', 0o755),
           'usr/bin/cachy-asahi-repository': ('cachy-asahi-repository', 0o755),
           **{'usr/share/doc/cachy-asahi-setup/' + n: (n, 0o644) for n in ('README.md', 'repository-enrollment.md')},
           **{'usr/share/licenses/cachy-asahi-setup/' + n: (n, 0o644) for n in ('NOTICE', 'LICENSE')}}


def need(value, message):
    if not value: raise ValueError(message)


def preflight(args):
    need(platform.system() == 'Linux' and platform.machine() in ('aarch64', 'arm64') and
         os.getuid() == os.geteuid() > 0 and os.getgid() == os.getegid(), 'ordinary native ARM host required')
    need(not any(os.environ.get(k) for k in ('DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH','DOCKER_API_VERSION')),
         'Docker overrides refused')
    need(re.fullmatch('[0-9a-f]{40}', args.source_commit or ''), 'exact candidate Source required')
    need(native.run(['git','-C',str(ROOT),'rev-parse','HEAD'], timeout=10) == args.source_commit, 'candidate checkout differs')
    subprocess.run(['git','-C',str(ROOT),'diff','--exit-code','HEAD','--','scripts/ci','scripts/build','scripts/checks',
                    'scripts/setup','scripts/repository','docs/repository-enrollment.md','LICENSE',RECIPE],
                   check=True, timeout=10, stdout=subprocess.DEVNULL)
    paths = (ROOT, args.cache, args.output)
    need(all(p.is_absolute() and '..' not in p.parts and not any(c in str(p) for c in ',\n\r') and
             not p.is_symlink() and not any(q.is_symlink() for q in p.parents) for p in paths), 'absolute ordinary paths required')
    need(args.cache.is_dir() and not args.output.exists(), 'seeded cache and new output required')
    need(all(not a.is_relative_to(b) and not b.is_relative_to(a) for i,a in enumerate(paths) for b in paths[i+1:]),
         'source/cache/output must be separate')
    report = recipe(ROOT / RECIPE / 'PKGBUILD'); data = report['metadata']
    need(not report['errors'] and data.get('pkgname') == ['cachy-asahi-setup'] and data.get('pkgver') == ['0.1.0'] and
         data.get('pkgrel') == ['4'] and data.get('arch') == ['any'] and data.get('license') == ['MIT'] and
         set(data.get('depends', ())) == {'python>=3.11','gnupg','pacman'} and not data.get('install'), 'fixed candidate recipe required')
    names = native.run(['git','-C',str(ROOT),'ls-tree','-r','--name-only',args.source_commit,'--',RECIPE], timeout=10).splitlines()
    need(set(names) == {str(p.relative_to(ROOT)) for p in (ROOT/RECIPE).rglob('*') if p.is_file()}, 'unreviewed recipe path')
    for name in names:
        raw = subprocess.check_output(['git','-C',str(ROOT),'show',args.source_commit+':'+name], timeout=10)
        need(not (ROOT/name).is_symlink() and (ROOT/name).read_bytes() == raw, 'candidate recipe input differs from exact Source')
    return native.load_pinned(ROOT/'scripts/ci/inputs.lock.json', INPUTS_SHA), report


def cleanup(output, docker, bootstrap_started, started):
    result = {'status':'PASS', 'containers':[], 'image':'NOT CREATED'}
    for attempt in started:
        try:
            record = json.loads((output/f'build-{attempt}/provenance.json').read_text())
            name = record['clean_environment_id']; need(re.fullmatch('cachy-asahi-[0-9a-f]{16}', name), 'owned build name required')
            query = docker+['container','ls','-a','--filter','name=^/'+name+'$','--format','{{.Names}}']
            before = native.run(query, timeout=10); need(before in ('',name), 'ambiguous build container')
            if before: native.run(docker+['rm','-f',name], timeout=20)
            need(native.run(query, timeout=10) == '', 'build container remains')
            result['containers'].append({'name':name,'absence_verified':True})
        except (OSError, ValueError, KeyError, subprocess.SubprocessError):
            result['status']='FAIL';result['containers'].append({'attempt':attempt,'absence_verified':False})
    try:
        path = output/'native/image-id'
        if path.exists():
            image = path.read_text().strip(); need(re.fullmatch('sha256:[0-9a-f]{64}',image), 'owned bootstrap image required')
            native.run(docker+['image','rm','--no-prune',image], timeout=30)
            need(image not in native.run(docker+['image','ls','-a','--no-trunc','-q'], timeout=10).splitlines(), 'bootstrap image remains')
            result['image']={'id':image,'absence_verified':True}
        elif bootstrap_started: result.update(status='FAIL',image={'status':'UNKNOWN','absence_verified':False})
    except (OSError, ValueError, subprocess.SubprocessError):
        result.update(status='FAIL',image={'status':'FAIL','absence_verified':False})
    return result


def payload(output, reviewed):
    record = json.loads((output/'provenance.json').read_text())
    validation = json.loads((output/'validation.json').read_text())
    need(record['status'] == 'built-package-static-pass' and not validation['errors'] and len(validation['artifacts']) == 1,
         'native package validation failed')
    need('Starting check()' in (output/'build.log').read_text(), 'native recipe checks/help were not run')
    members = validation['artifacts'][0]['members']
    actual = {n:r for n,r in members.items() if n not in PACKAGE_METADATA and r['type'] != '5'}
    need(set(actual) == set(PAYLOAD), 'unexpected package payload')
    for name,(source,mode) in PAYLOAD.items():
        row=actual[name];need(row['type']=='0' and row['mode']==mode and row['sha256']==reviewed[source], 'packaged input or mode differs')


def run(args):
    inputs, reviewed = preflight(args)
    output=args.output;output.mkdir(mode=0o700);bootstrap=output/'native';bootstrap.mkdir();summary=output/'summary';summary.mkdir()
    report={'status':'FAIL','source_commit':args.source_commit,'recipe':RECIPE,'inputs_sha256':INPUTS_SHA,
            'hardware_validation':'NOT RUN','repository_trust':'NOT RUN','installation':'NOT RUN','selected_for_release':False,'cancelled':False}
    docker=['docker','--host=unix:///var/run/docker.sock'];bootstrap_started=False;started=[]
    def cancel(*_): raise KeyboardInterrupt()
    previous={sig:signal.signal(sig,cancel) for sig in (signal.SIGINT,signal.SIGTERM)}
    try:
        native.save(summary/'recipe.json',reviewed);native.save(summary/'reviewed-inputs.json',reviewed['input_sha256'])
        for source,canonical,copied in (('setup','scripts/setup/setup.py','cachy-asahi-setup'),
              ('repository','scripts/repository/enroll.py','cachy-asahi-repository'),
              ('repository-doc','docs/repository-enrollment.md','repository-enrollment.md')):
            native.run([sys.executable,'-B',str(ROOT/RECIPE/'check-sync.py'),'--source',source,'--canonical',str(ROOT/canonical),
                        '--copy',str(ROOT/RECIPE/copied),'--license',str(ROOT/'LICENSE')], summary/(source+'-sync.log'), 30)
        native.save(bootstrap/'inputs.lock.json',inputs)
        probe=native.probe(bootstrap);docker=['docker','--host='+probe['docker_endpoint']]
        native.audit(inputs,args.cache,bootstrap);bootstrap_started=True
        image=native.build(inputs,args.cache,bootstrap,{})
        need(native.sha(bootstrap/'packages.lock') == PACKAGES_SHA,'341-package inventory differs')
        for attempt in (1,2):
            started.append(attempt);build=output/f'build-{attempt}'
            native.run([sys.executable,'-B',str(ROOT/'scripts/build/build.py'),str(ROOT/RECIPE),'--image',image,'--mode','native',
                '--source-date-epoch',str(inputs['source_date_epoch']),'--network','none','--expected-packages',str(bootstrap/'packages.lock'),
                '--reviewed-inputs',str(summary/'reviewed-inputs.json'),'--timeout','300','--output',str(build)], summary/f'build-{attempt}.log',360)
            payload(build,reviewed['input_sha256'])
        native.run([sys.executable,'-B',str(ROOT/'scripts/build/compare.py'),str(output/'build-1'),str(output/'build-2'),
                    '--require-bytes'],summary/'compare.json',120)
        report.update(status='PASS',image=image,packages_sha256=PACKAGES_SHA,package_pair='PASS',
                      recipe_metadata_payload='PASS',native_recipe_checks_and_inert_help='PASS')
    except (KeyboardInterrupt, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        report.update(error_kind=type(error).__name__,error_traceback=traceback.format_exc(limit=10),cancelled=isinstance(error,KeyboardInterrupt))
    finally:
        interrupted=[]
        for sig in previous:signal.signal(sig,lambda signum,_:interrupted.append(signum))
        try:
            report['cleanup']=cleanup(output,docker,bootstrap_started,started)
            if report['cleanup']['status'] != 'PASS':report['status']='FAIL'
            native.save(summary/'result.json',report)
            if interrupted:
                report.update(status='FAIL',cancelled=True);native.save(summary/'result.json',report)
        finally:
            for sig,handler in previous.items():signal.signal(sig,handler)
    return int(report['status'] != 'PASS')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-commit',required=True);parser.add_argument('--cache',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    return run(parser.parse_args())


if __name__ == '__main__':sys.exit(main())

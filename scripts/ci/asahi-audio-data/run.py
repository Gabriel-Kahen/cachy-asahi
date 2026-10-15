#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""BUILD ONLY: two pinned Asahi data pairs; never install or activate platform data."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import traceback

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(ROOT/'scripts/ci'), str(ROOT/'scripts/checks'), str(ROOT/'scripts/build')]
import native_arm as native
import package_checks as checks

INPUTS = 'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f'
BASE = 'fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25'
NAMES = ('asahi-audio', 'alsa-ucm-conf-asahi')


def need(ok, message):
    if not ok: raise ValueError(message)


def load(name, path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


def recipe_report(path, inputs, policy):
    report = checks.recipe(path)
    name = report['metadata'].get('pkgname', [''])[0]
    need(name in NAMES and report['input_sha256'] == inputs['packages/platform/'+name], 'fixed data recipe input bytes differ')
    need(sorted(report['errors']) == policy[name]['recipe_errors'], 'unexpected recipe error')
    # Preserve the generic rejection in the exported report, after exact-set validation.
    return dict(report, errors=[], status='build-only-data-static-pass',
                generic_guard_status=report['status'], build_only_protected_errors=report['errors'])


def package_report(path, policy):
    report = checks.package(path)
    name = report['metadata'].get('.PKGINFO', {}).get('pkgname', [''])[0]
    need(name in NAMES and sorted(report['errors']) == policy[name]['package_errors'], 'unexpected package error')
    need(report['metadata']['.PKGINFO'].get('pkgver')==[policy[name]['version']], 'fixed data package version required')
    actual = {p:r for p,r in report['members'].items() if p not in checks.PACKAGE_METADATA and r['type'] != '5'}
    expected = policy[name]['payload']
    need(not report['elf'] and '.INSTALL' not in report['members'] and set(actual) == set(expected), 'exact non-executable data payload required')
    directories={str(parent) for path in expected for parent in Path(path).parents if str(parent)!='.'}
    need({p for p,r in report['members'].items() if r['type']=='5'}==directories, 'unreviewed or missing payload directory')
    for member, row in report['members'].items():
        need(row['type'] in ('0','5') and row['uid'] == row['gid'] == 0, 'ordinary root-owned files/directories only')
        if row['type']=='5': need(row['mode']==0o755, 'unexpected directory mode')
        else: need(not row['mode'] & 0o111, 'no executable file permitted')
    for path, row in actual.items():
        need(row['type']=='0' and row['mode']==expected[path]['mode']==0o644 and row['sha256']==expected[path]['sha256'],
             'data/license payload bytes or mode differ: '+path)
    return dict(report, errors=[], status='build-only-data-static-pass',
                generic_guard_status=report['status'], build_only_protected_errors=report['errors'])


def build_api(directory, inputs, policy):
    """Reuse unchanged builder code; stage its one explicit --nodeps entry variant."""
    directory.mkdir()
    shutil.copyfile(ROOT/'scripts/build/build.py', directory/'build.py')
    original = (ROOT/'scripts/build/container-entry.sh').read_text()
    anchor = 'makepkg --cleanbuild --clean --force --log --noconfirm'
    need(original.count(anchor)==1, 'reviewed makepkg entry anchor differs')
    (directory/'container-entry.sh').write_text(original.replace(anchor,anchor+' --nodeps'))
    api = load('asahi_data_existing_build', directory/'build.py')
    api.recipe = lambda p: recipe_report(p,inputs,policy)
    api.package = lambda p: package_report(p,policy)
    compare = load('asahi_data_existing_compare', ROOT/'scripts/build/compare.py')
    compare.package = lambda p: package_report(p,policy)
    return api,compare


def preflight(args):
    need(re.fullmatch('[0-9a-f]{40}',args.source_commit or '') and
         native.run(['git','-C',str(ROOT),'rev-parse','HEAD'],timeout=10)==args.source_commit, 'exact clean candidate Source required')
    subprocess.run(['git','-C',str(ROOT),'diff','--exit-code','HEAD','--','packages/platform','scripts/ci','scripts/build','scripts/checks'],
                   check=True,stdout=subprocess.DEVNULL,timeout=10)
    need(os.getuid()==os.geteuid()>0 and not any(os.environ.get(k) for k in
         ('DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH','DOCKER_API_VERSION')), 'ordinary local Docker caller required')
    paths=(ROOT,args.output,args.cache)
    need(all(p.is_absolute() and '..' not in p.parts and not any(c in str(p) for c in ',\n\r') and
         not any(q.is_symlink() for q in (p,*p.parents)) for p in paths), 'canonical ordinary paths required')
    need(args.cache.is_dir() and not args.output.exists() and all(not a.is_relative_to(b) and not b.is_relative_to(a)
         for i,a in enumerate(paths) for b in paths[i+1:]), 'source/seeded cache/new output must be separate')
    contexts=json.loads(native.run(['docker','context','inspect'],timeout=10))
    need(len(contexts)==1 and contexts[0]['Endpoints']['docker']['Host'] in
         ('unix:///var/run/docker.sock','unix:///run/docker.sock'), 'active Docker context must be local')
    inputs=json.loads((HERE/'inputs.json').read_text());policy=json.loads((HERE/'payload.json').read_text())
    need(set(inputs)=={'packages/platform/'+n for n in NAMES} and set(policy)==set(NAMES), 'exact two-package development scope required')
    for name in NAMES: recipe_report(ROOT/'packages/platform'/name/'PKGBUILD',inputs,policy)
    return native.load_pinned(ROOT/'scripts/ci/inputs.lock.json',INPUTS),inputs,policy


def invoke(api, argv):
    before=sys.argv
    try:
        sys.argv=[str(api.__file__),*map(str,argv)]
        need(api.main()==0,'data package build failed')
    finally: sys.argv=before


def run(args):
    base,inputs,policy=preflight(args)
    output=args.output;output.mkdir(mode=0o700)
    bootstrap=output/'native';bootstrap.mkdir();summary=output/'summary';summary.mkdir()
    cleanup_api=load('asahi_data_existing_cleanup',ROOT/'scripts/ci/repository-enrollment-native.py')
    docker=['docker','--host=unix:///var/run/docker.sock'];bootstrap_started=False;started=[]
    result={'status':'FAIL','source_commit':args.source_commit,'build_only':True,'selected_for_release':False,
            'runtime_dependencies':'DECLARED-BUT-NOT-RESOLVED','installation':'NOT RUN','services':'NOT RUN','hardware':'NOT RUN'}
    def cancel(*_): raise KeyboardInterrupt()
    previous={sig:signal.signal(sig,cancel) for sig in (signal.SIGINT,signal.SIGTERM)}
    try:
        native.save(bootstrap/'inputs.lock.json',base)
        old=os.environ.get('DOCKER_HOST');os.environ['DOCKER_HOST']='unix:///var/run/docker.sock'
        try: probe=native.probe(bootstrap)
        finally:
            if old is None:os.environ.pop('DOCKER_HOST',None)
            else:os.environ['DOCKER_HOST']=old
        docker=['docker','--host='+probe['docker_endpoint']]
        native.audit(base,args.cache,bootstrap);bootstrap_started=True
        image=native.build(base,args.cache,bootstrap,{})
        need(native.sha(bootstrap/'packages.lock')==BASE,'unchanged341 builder required')
        api,compare=build_api(output/'builder',inputs,policy)
        native.save(summary/'build-only-policy.json',{'recipe_inputs':inputs,'package_policy':policy,
            'nodeps':True,'generic_guards_modified':False,'entry_script_sha256':native.sha(output/'builder/container-entry.sh')})
        for name in NAMES:
            reviewed=summary/(name+'-inputs.json');native.save(reviewed,inputs['packages/platform/'+name])
            builds=[]
            for attempt in (1,2):
                tag=name+'-'+str(attempt);started.append(tag);target=output/('build-'+tag);builds.append(target)
                invoke(api,[ROOT/'packages/platform'/name,'--image',image,'--mode','native','--network','none',
                    '--source-date-epoch',base['source_date_epoch'],'--timeout','180','--expected-packages',bootstrap/'packages.lock',
                    '--reviewed-inputs',reviewed,'--output',target])
            comparison=compare.compare(*builds)
            need(not comparison['errors'] and all(p['bytes_equal'] for p in comparison['packages'].values()), 'native exact-byte pair differs')
            native.save(summary/(name+'-compare.json'),comparison)
        result.update(status='PASS',native_builds=4,byte_comparisons=2)
    except (KeyboardInterrupt,OSError,ValueError,KeyError,subprocess.SubprocessError) as error:
        result.update(error=str(error),traceback=traceback.format_exc(limit=10),cancelled=isinstance(error,KeyboardInterrupt))
    finally:
        interrupted=[]
        for sig in previous:signal.signal(sig,lambda signum,_:interrupted.append(signum))
        try:
            result['cleanup']=cleanup_api.cleanup(output,docker,bootstrap_started,started)
            if result['cleanup']['status']!='PASS':result['status']='FAIL'
            if interrupted:result.update(status='FAIL',cancelled=True)
            native.save(summary/'result.json',result)
        finally:
            for sig,handler in previous.items():signal.signal(sig,handler)
    return int(result['status']!='PASS')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-commit',required=True);parser.add_argument('--cache',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    return run(parser.parse_args())


if __name__=='__main__':raise SystemExit(main())

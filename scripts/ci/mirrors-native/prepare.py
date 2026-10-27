#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Construct a new closed source context; never edits canonical files or runs actors."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

HERE=Path(__file__).resolve().parent
LANE='scripts/ci/mirrors-native'
NAME='cachy-asahi-mirrors'


def need(ok,message):
    if not ok:raise ValueError(message)


def row(path):
    need(not any(p.is_symlink() for p in (path,*path.parents)) and path.is_file() and path.stat().st_size<=16*1024**2,'ordinary bounded source file required')
    raw=path.read_bytes();return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def save(path,value):path.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')


def prepare(source,output,recipe,package_source=None):
    need(source.is_absolute() and output.is_absolute() and not output.exists() and not any(
        p.is_symlink() for path in (source,output,recipe) for p in (path,*path.parents)),'fresh ordinary context paths required')
    need(not source.is_relative_to(output) and not recipe.is_relative_to(output),'output must not contain source')
    need(package_source is None or re.fullmatch('[0-9a-f]{40}',package_source),'exact candidate source SHA required')
    pins=json.loads((HERE/'infrastructure-pins.json').read_bytes())
    for name,expected in pins.items():need(row(source/name)==expected,'original infrastructure drift: '+name)
    names={p.name for p in recipe.iterdir()}
    need(names=={'PKGBUILD',NAME,'test_mirrors.py','README.md','NOTICE','LICENSE'} and
         all(p.is_file() and not p.is_symlink() and p.stat().st_size<=1024**2 for p in recipe.iterdir()),'exact bounded mirror recipe required')
    files={p.name:row(p) for p in sorted(recipe.iterdir())}
    if package_source:
        for name,expected in files.items():
            raw=subprocess.check_output(['git','-C',str(source),'show',package_source+':packages/tools/'+NAME+'/'+name],timeout=20)
            need(dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())==expected,'published candidate source differs: '+name)
    output.mkdir(mode=0o700)
    for name in pins:
        target=output/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source/name,target)
    shutil.copytree(recipe,output/'packages/tools'/NAME)
    target=output/LANE;target.mkdir(parents=True)
    for path in sorted(HERE.iterdir()):
        if path.is_file() and path.name not in ('source-manifest.json','source-pins.json','input-policy.json'):shutil.copyfile(path,target/path.name)
    policy=dict(schema_version=1,candidate_source=package_source,actual_source=None,actual_ref=None,actual_run=None,
        scope='CONTROLLED_LOCAL_SNAPSHOT_ONLY',native='NOT_RUN',candidate_files=files)
    save(target/'input-policy.json',policy)
    source_pins={p.relative_to(output).as_posix():row(p)['sha256'] for p in sorted(output.rglob('*')) if p.is_file()}
    save(target/'source-pins.json',source_pins)
    manifest=dict(schema_version=1,scope='ONE_UNSELECTED_MIRROR_CANDIDATE',native_runtime='NOT_RUN',
        files={p.relative_to(output).as_posix():row(p) for p in sorted(output.rglob('*')) if p.is_file()},
        workflow_binding=dict(paths=['.github/workflows/native-arm-mirrors-candidate.yml','.github/workflows/native-arm-build.yml'],
                              method='EXACT_RENDERED_PINNED_TEMPLATE_EQUALITY_BEFORE_SECRETS'))
    need(len(manifest['files'])<=128,'source closure cap');save(target/'source-manifest.json',manifest)
    workflow=output/'.github/workflows/native-arm-mirrors-candidate.yml';workflow.parent.mkdir(parents=True)
    text=(HERE/'workflow.yml.in').read_text()
    for marker,path in (('@JOB_SHA256@',target/'job.py'),('@MANIFEST_SHA256@',target/'source-manifest.json')):
        need(text.count(marker)==1,'single workflow checksum marker required');text=text.replace(marker,row(path)['sha256'])
    workflow.write_text(text)
    # The registered dispatch path is a second byte-identical local file.
    shutil.copyfile(workflow,workflow.with_name('native-arm-build.yml'))
    authorization=dict(files={p.relative_to(output).as_posix():row(p) for p in sorted(output.rglob('*')) if p.is_file()},
        workflow_binding=dict(paths=['.github/workflows/native-arm-mirrors-candidate.yml','.github/workflows/native-arm-build.yml'],
                              method='EXACT_RENDERED_PINNED_TEMPLATE_EQUALITY_BEFORE_SECRETS'))
    save(output.parent/(output.name+'-authorization.json'),authorization)
    return dict(status='CLOSED_SOURCE_ONLY',files=len(authorization['files']),candidate_source=package_source,
                actual_source=None,actual_ref=None,actual_run=None,native='NOT_RUN')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--recipe',type=Path);p.add_argument('--package-source');a=p.parse_args()
    print(json.dumps(prepare(a.source.absolute(),a.output.absolute(),a.recipe.absolute() if a.recipe else a.source.absolute()/'packages/tools'/NAME,a.package_source),sort_keys=True))

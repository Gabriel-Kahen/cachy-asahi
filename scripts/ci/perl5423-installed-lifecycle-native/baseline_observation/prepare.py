#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Seal finite baseline-observation Source as DATA; never run a hosted role."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import resource

HERE=Path(__file__).resolve().parent
OPERATION='perl5423-baseline-observation-native-v1'
ACTUAL={k:None for k in ('source','ref','run','job','approval','authority','image','container','reader','artifact')}
FS_SHA='7c7b8ce846603d76da1db7de58573fa76642871aae7082fa36b32a54856585d7'
ALIASES=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-perl5423-baseline-observation-v1.yml')
PAYLOAD=frozenset('hosted/'+name+'.py' for name in ('common','entry','bootstrap','observer','reader'))
STATIC=('LICENSE','expected349.lock','policy.json','observer-policy.json','root-admission.TEMPLATE.json','held-source.json')

if hashlib.sha256((HERE/'filesystem.py').read_bytes()).hexdigest()!=FS_SHA:
    raise ValueError('held Source DATA filesystem helper changed')
spec=importlib.util.spec_from_file_location('baseline_observation_source_filesystem',HERE/'filesystem.py')
fs=importlib.util.module_from_spec(spec);spec.loader.exec_module(fs)


def encode(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def frozen_original(frozen):
    expected=fs.decode(fs.read(HERE/'held-source.json')[0])
    previous=fs.MAX_FILES
    try:fs.MAX_FILES=320;before=fs.snapshot(frozen)
    finally:fs.MAX_FILES=previous
    fs.need(len(before)==272 and 'source-map.json' in before,'complete frozen272 Source required')
    raw=before['source-map.json'][0]
    fs.need(fs.pin(raw)['sha256']==expected['frozen_bootstrap_source_map_sha256'],'exact frozen272 Source map required')
    manifest=fs.decode(raw)
    fs.need(manifest['schema']==1 and all(value is None for value in manifest['actual'].values()),'frozen Source actual selectors must remain null')
    fs.need(fs.descriptors({name:row for name,row in before.items() if name!='source-map.json'})==manifest['files'],'complete frozen Source byte/mode/membership join')
    original={name:row for name,row in before.items() if name.startswith('original/')}
    fs.need(len(original)==200,'exact original200 bootstrap closure')
    nested='original/native/source-map.json'
    fs.need(fs.pin(original[nested][0])['sha256']==expected['original_source_map_sha256'],'exact original200 Source map required')
    inner=fs.decode(original[nested][0])
    fs.need(fs.descriptors({name.removeprefix('original/'):row for name,row in original.items() if name!=nested})==inner['files'],'complete internal original200 Source byte/mode/membership join')
    fs.need(fs.pin(original['original/native/expected349.lock'][0])['sha256']==expected['expected349_sha256'],'fixed genuine349 inventory Source')
    return original,expected


def render(frozen):
    original,expected=frozen_original(frozen)
    payload=fs.snapshot(HERE/'payload')
    fs.need(set(payload)==PAYLOAD,'complete fixed passive/coordinator payload closure required')
    files=dict(original);files.update(payload)
    for name in STATIC:files[name]=fs.read(HERE/name)
    fs.need(files['expected349.lock'][0]==original['original/native/expected349.lock'][0],'observer inventory must match original349 exactly')
    policy=fs.decode(files['observer-policy.json'][0]);resources=fs.decode(files['policy.json'][0])
    fs.need(policy.get('schema')==1 and policy.get('operation')==resources.get('operation')==OPERATION,'separate baseline observation policy operation required')
    admission=fs.decode(files['root-admission.TEMPLATE.json'][0])
    fs.need(admission.get('status')=='UNADMITTED' and all(admission.get(key) is None for key in ('source','ref','source_map_sha256','authority','approval','image','run','job')),'constructor cannot issue actual Root authority')
    contract=dict(schema=1,operation=OPERATION,actual=ACTUAL,
        frozen_bootstrap_source_map_sha256=expected['frozen_bootstrap_source_map_sha256'],
        original_source_map_sha256=expected['original_source_map_sha256'],
        expected349_sha256=expected['expected349_sha256'],
        observer_policy_sha256=fs.pin(files['observer-policy.json'][0])['sha256'],
        capture='ORIGINAL_BASELINE_OBSERVATION_DATA_ONLY',
        mutation_qualification='NOT_ISSUED; separate future Root review/admission required',holds_preserved=True)
    files['contract.json']=(encode(contract),0o644)
    workflow=fs.read(HERE/'workflow.yml.in')[0]
    fs.need(workflow.count(b'__COMMON_SHA__')==workflow.count(b'__ENTRY_SHA__')==1,'exact workflow guard placeholders required')
    workflow=workflow.replace(b'__COMMON_SHA__',fs.pin(files['hosted/common.py'][0])['sha256'].encode()).replace(b'__ENTRY_SHA__',fs.pin(files['hosted/entry.py'][0])['sha256'].encode())
    for alias in ALIASES:files[alias]=(workflow,0o644)
    inverse=dict(schema=1,actual=ACTUAL,held=fs.descriptors(original),before_tree=fs.tree(original),
        additions=sorted(set(files)-set(original)|{'inverse.json','source-map.json'}),
        operation='REMOVE_EXACT_ADDITIONS_RESTORES_ORIGINAL200_BYTES_AND_GIT_MODES')
    files['inverse.json']=(encode(inverse),0o644)
    undo={name:row for name,row in files.items() if name not in inverse['additions']}
    fs.need(fs.descriptors(undo)==inverse['held'] and fs.tree(undo)==inverse['before_tree'],'complete exact Source inverse required')
    files['source-map.json']=(encode(dict(schema=1,actual=ACTUAL,files=fs.descriptors(files),scope='BASELINE_OBSERVATION_SOURCE_ONLY_NO_MUTATION_QUALIFICATION')),0o644)
    fs.need(len(files)<=256 and sum(len(raw) for raw,_ in files.values())<=96*1024**2,'bounded standalone Source packet')
    return files


def construct(frozen,output):
    frozen,output=fs.absolute(frozen),fs.absolute(output)
    fs.need(not any(output.is_relative_to(path) or path.is_relative_to(output) for path in (frozen,HERE)),'fresh disjoint Source output required')
    files=render(frozen);previous=fs.MAX_FILES
    try:fs.MAX_FILES=256;fs.publish(files,output)
    finally:fs.MAX_FILES=previous
    return dict(status='SEALED_BASELINE_OBSERVATION_SOURCE_DATA_ONLY',files=len(files),bytes=sum(len(raw) for raw,_ in files.values()),source_map=fs.pin(files['source-map.json'][0]),prospective_tree=fs.tree(files),actual=ACTUAL,mutation_qualification='NOT_ISSUED')


if __name__=='__main__':
    resource.setrlimit(resource.RLIMIT_AS,(512*1024**2,512*1024**2))
    parser=argparse.ArgumentParser(description=__doc__)
    for key in ('frozen-source','output'):parser.add_argument('--'+key,type=Path,required=True)
    args=parser.parse_args();print(json.dumps(construct(args.frozen_source,args.output),sort_keys=True))

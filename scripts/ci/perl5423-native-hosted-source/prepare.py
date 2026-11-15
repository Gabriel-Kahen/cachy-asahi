#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Compose one finite hosted Source from exact retained DATA; no roles/publication."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

HERE=Path(__file__).resolve().parent;REPO=HERE.parents[2]
HELPER=REPO/'scripts/ci/native-build-namespace-preflight/prepare.py'
HELPER_SHA='7c7b8ce846603d76da1db7de58573fa76642871aae7082fa36b32a54856585d7'
if hashlib.sha256(HELPER.read_bytes()).hexdigest()!=HELPER_SHA:raise ValueError('held filesystem DATA helper differs')
spec=importlib.util.spec_from_file_location('hosted_source_filesystem',HELPER);atomic=importlib.util.module_from_spec(spec);spec.loader.exec_module(atomic)
ACTUAL=dict(source=None,ref=None,run=None,job=None,reader=None,authority=None,approval=None,artifact=None,image=None)
MAX_FILES=320;MAX_BYTES=96*1024**2


def encode(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def compose(before,additions):
    atomic.need(not set(before)&set(additions) and not {'inverse.json','source-map.json'}&set(additions),'additions-only closed hosted Source')
    inverse=dict(schema=1,held=atomic.descriptors(before),before_tree=atomic.tree(before),additions=sorted(set(additions)|{'inverse.json','source-map.json'}),operation='REMOVE_EXACT_ADDITIONS_RESTORES_ALL260_HELD_BYTES_AND_MODES',actual=ACTUAL)
    files={**before,**additions,'inverse.json':(encode(inverse),0o644)}
    files['source-map.json']=(encode(dict(schema=1,actual=ACTUAL,scope='PROPOSED_CLOSED_HOSTED_PERL_SOURCE_ONLY',files=atomic.descriptors(files))),0o644)
    undo={name:row for name,row in files.items() if name not in inverse['additions']}
    atomic.need(undo==before and atomic.tree(undo)==inverse['before_tree'],'complete emitted inverse')
    atomic.need(len(files)<=MAX_FILES and sum(len(b) for b,_ in files.values())<=MAX_BYTES,'finite hosted Source budget')
    return files


def render(original,packet,profile_sha):
    raw,_=atomic.read(HERE/'profile.json',1024**2);atomic.need(atomic.pin(raw)['sha256']==profile_sha,'whole Root-reviewed hosted profile')
    profile=atomic.decode(raw);atomic.need(profile['actual']==ACTUAL,'Source/run/job/Reader/authority selectors NULL')
    old=atomic.snapshot(Path(original));atomic.need(atomic.descriptors(old)==profile['original']['files'] and len(old)==200 and atomic.tree(old)==profile['original']['tree'],'complete retained original3937 readback')
    commit,_=atomic.read(REPO/'scripts/ci/perl5423-repro-native-source/references/namespace-commit.raw')
    atomic.need(atomic.oid(b'commit',commit).hex()==profile['original']['source']=='3937d8b9f3210f4e9868bf19f01dfa22de64ddfe' and commit.startswith(b'tree '+profile['original']['tree'].encode()+b'\n'),'whole historical original commit/tree provenance')
    adapter=REPO/'scripts/ci/perl5423-native-adapter';body,_=atomic.read(adapter/'prepare.py')
    atomic.need(atomic.pin(body)['sha256']==profile['adapter']['constructor_sha256'],'whole held v2 constructor')
    spec=importlib.util.spec_from_file_location('held_adapter_source_constructor',adapter/'prepare.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    component=module.render(Path(packet),profile['adapter']['profile_sha256'])
    atomic.need(len(component)==60 and atomic.pin(component['source-map.json'][0])['sha256']==profile['adapter']['component_map_sha256'],'complete exact v2 Perl component')
    before={**{'original/'+n:r for n,r in old.items()},**{'perl/'+n:r for n,r in component.items()}}
    additions={'hosted/original-commit.raw':(commit,0o644)}
    for name,row in profile['payload'].items():
        atomic.relative(name);body,mode=atomic.read(HERE/'payload'/name)
        atomic.need(dict(**atomic.pin(body),mode=mode)==row,'whole hosted payload differs: '+name)
        if name.endswith('.yml.in'):
            text=body.decode().replace('__COMMON_SHA__',profile['payload']['hosted/common.py']['sha256']).replace('__ENTRY_SHA__',profile['payload']['hosted/entry.py']['sha256'])
            atomic.need('__COMMON_SHA__' not in text and '__ENTRY_SHA__' not in text,'resolved workflow guard pins')
            body=text.encode();additions[name.removesuffix('.in')]=(body,mode)
            additions['.github/workflows/native-arm-build.yml']=(body,mode)
        else:additions[name]=(body,mode)
    atomic.need(additions['.github/workflows/native-arm-build.yml']==additions['.github/workflows/native-arm-perl5423-v2.yml'],'exact new dedicated alias')
    return compose(before,additions)


def construct(original,packet,profile_sha,output):
    original,packet,output=(atomic.absolute(p) for p in (original,packet,output))
    frozen=[REPO/n for n in ('scripts','packages','docs','manifests','.github','.git','tests')]+[original,packet]
    atomic.need(not any(output.is_relative_to(p) or p.is_relative_to(output) for p in frozen),'fresh disjoint Source DATA output')
    files=render(original,packet,profile_sha)
    # Same pinned no-replace filesystem publication, with an explicit finite
    # readback limit for the compound260+ Source; component bounds are unchanged.
    previous=atomic.MAX_FILES
    try:atomic.MAX_FILES=MAX_FILES;atomic.publish(files,output)
    finally:atomic.MAX_FILES=previous
    return dict(status='CONSTRUCTED_HOSTED_SOURCE_DATA_ONLY',files=len(files),bytes=sum(len(b) for b,_ in files.values()),map=atomic.pin(files['source-map.json'][0]),prospective_tree=atomic.tree(files),actual=ACTUAL,native_acceptance=False)


if __name__=='__main__':
    atomic.need(sys.flags.isolated and not sys.flags.optimize,'isolated unoptimized Source DATA constructor')
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('original-source','packet','profile-sha256','output'):p.add_argument('--'+name,required=True)
    a=p.parse_args();print(json.dumps(construct(Path(a.original_source),Path(a.packet),a.profile_sha256,Path(a.output)),sort_keys=True))

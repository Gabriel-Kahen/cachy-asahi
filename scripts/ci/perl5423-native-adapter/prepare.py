#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Emit proposed finite adapter Source DATA, never publish a ref or execute roles."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
HELPER=ROOT/'scripts/ci/native-build-namespace-preflight/prepare.py'
SHA='7c7b8ce846603d76da1db7de58573fa76642871aae7082fa36b32a54856585d7'
if hashlib.sha256(HELPER.read_bytes()).hexdigest()!=SHA:raise ValueError('held filesystem helper differs')
spec=importlib.util.spec_from_file_location('perl_source_atomic',HELPER)
atomic=importlib.util.module_from_spec(spec);spec.loader.exec_module(atomic)


def encode(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def render(packet,profile_sha):
    raw,_=atomic.read(HERE/'profile.json',1024**2)
    atomic.need(atomic.pin(raw)['sha256']==profile_sha,'whole Root-reviewed adapter profile')
    p=atomic.decode(raw);atomic.need(p['actual']==dict(source=None,ref=None,run=None,job=None,approval=None,artifact=None,image=None),'proposed selectors NULL')
    original=atomic.snapshot(Path(packet));mapraw=original['packet-map.json'][0]
    atomic.need(atomic.pin(mapraw)['sha256']==p['packet_map_sha256'],'exact frozen37-file packet')
    m=atomic.decode(mapraw);atomic.need(len(original)==37 and atomic.descriptors({n:r for n,r in original.items() if n!='packet-map.json'})==m['files'],'complete immutable packet readback')
    before={'packet/'+n:r for n,r in original.items()};additions={}
    for name,row in p['files'].items():
        atomic.relative(name);body,mode=atomic.read(HERE/name)
        atomic.need(dict(**atomic.pin(body),mode=mode)==row,'adapter source operand differs: '+name)
        additions[name]=(body,mode)
    return compose(before,additions,p['actual'])


def compose(before,additions,actual):
    """Pure additions-only Source transform with whole emitted inverse proof."""
    atomic.need(not set(before)&set(additions) and not {'inverse.json','source-map.json'}&set(additions),'adapter/packet/generated-leaf collision')
    after={**before,**additions}
    inverse_receipt=dict(schema=1,before_tree=atomic.tree(before),held=atomic.descriptors(before),additions=sorted(set(additions)|{'inverse.json','source-map.json'}),inverse='REMOVE_EXACT_ADDITIONS_RESTORES_EVERY_HELD_BYTE_AND_MODE',actual=actual)
    after['inverse.json']=(encode(inverse_receipt),0o644)
    source_map=dict(schema=1,actual=actual,files=atomic.descriptors(after),scope='PROPOSED_PERL_ARM_ADAPTER_SOURCE_ONLY_NO_ADMISSION')
    after['source-map.json']=(encode(source_map),0o644)
    undo={name:row for name,row in after.items() if name not in inverse_receipt['additions']}
    atomic.need(undo==before and atomic.tree(undo)==inverse_receipt['before_tree'],'complete emitted Source inverse failed')
    atomic.need(len(after)<=80 and sum(len(b) for b,_ in after.values())<=48*1024**2,'fixed finite Source closure')
    return after


def construct(packet,profile_sha,output):
    output=atomic.absolute(output);packet=atomic.absolute(packet)
    frozen=[ROOT/n for n in ('packages','scripts','docs','manifests','.github','.git','tests')]+[packet]
    atomic.need(not any(output.is_relative_to(p) or p.is_relative_to(output) for p in frozen),'fresh output disjoint from all frozen inputs')
    files=render(packet,profile_sha);atomic.publish(files,output)
    return dict(status='CONSTRUCTED_PROPOSED_SOURCE_DATA_ONLY',files=len(files),bytes=sum(len(b) for b,_ in files.values()),map=atomic.pin(files['source-map.json'][0]),prospective_tree=atomic.tree(files),actual=dict(source=None,ref=None,run=None,job=None,approval=None,artifact=None,image=None),namespace='SEPARATE_MATCHING_QUALIFICATION_NOT_RUN',native_acceptance=False)


if __name__=='__main__':
    atomic.need(sys.flags.isolated and not sys.flags.optimize,'isolated unoptimized Source constructor')
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--packet',type=Path,required=True);p.add_argument('--profile-sha256',required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();print(json.dumps(construct(a.packet,a.profile_sha256,a.output),sort_keys=True))

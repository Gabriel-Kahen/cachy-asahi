#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Exact transfer-authorization-only Source successor; no acquisition or actors."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import resource

HERE=Path(__file__).resolve().parent
helper=HERE.parent/'filesystem.py'
if hashlib.sha256(helper.read_bytes()).hexdigest()!='7c7b8ce846603d76da1db7de58573fa76642871aae7082fa36b32a54856585d7':
    raise ValueError('held filesystem DATA helper differs')
s=importlib.util.spec_from_file_location('rust_v8_source_filesystem',helper);fs=importlib.util.module_from_spec(s);s.loader.exec_module(fs);fs.MAX_FILES=512
PARENT=dict(files=318,bytes=42401750,tree='0c1e096dbfb34515f80937c5d0973ca384bcfb69',map_sha256='33bececb45d84997ea5b19a64100629bb3fe76c2e61faa9d4a1a86b947febad6')
ACTUAL=dict.fromkeys(('source','ref','run','job','approval','artifact','image'))
SCOPE='RUST199_PHASE_TRANSFER_PROVIDER_SUCCESSOR_V8'
MARKER='phase-transfer-v8.json'
REPLACED={'admission.py','hosted/entry.py','hosted/phase_transfer.py','.github/workflows/native-arm-build.yml','.github/workflows/native-arm-rust199-source-reference-v1.yml'}
POLICY='hosted/phase-transfer-provider-policy.json'
LEAVES=REPLACED|{POLICY}
ARCHIVE='previous-v7/'


def encode(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def identity(files):
    return dict(files=len(files),bytes=sum(len(raw)for raw,mode in files.values()),tree=fs.tree(files),map_sha256=fs.pin(files['source-map.json'][0])['sha256'])


def capture(directory):
    files=fs.snapshot(directory);fs.need(identity(files)==PARENT,'whole genuine frozen318 parent bytes/modes/tree/map')
    fs.need(fs.decode(files['source-map.json'][0])['files']==fs.descriptors({n:r for n,r in files.items()if n!='source-map.json'}),'complete318 declared namespace')
    return files


def render(before):
    fs.need(identity(before)==PARENT,'exact318 parent only')
    payload=fs.snapshot(HERE/'payload');fs.need(set(payload)==LEAVES and all(mode==0o644 for raw,mode in payload.values()),'finite transfer-only overlay')
    fs.need(not any(n.startswith(ARCHIVE)for n in before)and POLICY not in before and MARKER not in before,'fresh versioned successor namespace')
    files=dict(before);changes={}
    for name in sorted(REPLACED|{'source-map.json'}):files[ARCHIVE+name]=before[name]
    for name,row in payload.items():
        changes[name]=dict(before=fs.descriptors({name:before[name]})[name]if name in before else None,after=fs.descriptors({name:row})[name]);files[name]=row
    marker=dict(schema=8,scope=SCOPE,parent=PARENT,changes=changes,archives=sorted(ARCHIVE+n for n in REPLACED|{'source-map.json'}),
                resources_changed=False,recipe_changed=False,carrier_transport_changed=False,holds_preserved=True,
                unadmitted=True,Root_grants=None,dispatch=None,actual=ACTUAL)
    files[MARKER]=(encode(marker),0o644)
    old=fs.decode(before['source-map.json'][0]);old['files']=fs.descriptors({n:r for n,r in files.items()if n!='source-map.json'})
    files['source-map.json']=(encode(old),0o644)
    fs.need(undo(files)==before,'complete byte/mode/namespace inverse to318')
    fs.need(all(files[name]==row for name,row in before.items()if name not in REPLACED|{'source-map.json'}),'all compiler/recipe/notices/resources/material joins unchanged')
    return files


def undo(files):
    marker=fs.decode(files[MARKER][0]);fs.need(marker['schema']==8 and marker['scope']==SCOPE and marker['parent']==PARENT
        and marker['actual']==ACTUAL and marker['Root_grants']is None and marker['unadmitted']is True,'unissued exact inverse marker')
    old_map=files[ARCHIVE+'source-map.json'];fs.need(fs.pin(old_map[0])['sha256']==PARENT['map_sha256'],'whole archived318 map')
    old=fs.decode(old_map[0]);expected=set(old['files'])|{'source-map.json'}
    extra={MARKER,POLICY}|{ARCHIVE+n for n in REPLACED|{'source-map.json'}}
    fs.need(set(files)==expected|extra,'closed successor namespace before inverse')
    current_map=fs.decode(files['source-map.json'][0]);fs.need(current_map['actual']==ACTUAL and current_map['files']==fs.descriptors({n:r for n,r in files.items()if n!='source-map.json'}),'whole current Source map before inverse')
    restored={name:row for name,row in files.items()if name not in extra}
    for name in REPLACED:
        fs.need(fs.descriptors({name:files[name]})[name]==marker['changes'][name]['after'],'exact inverse replacement')
        restored[name]=files[ARCHIVE+name]
    restored['source-map.json']=old_map
    fs.need(identity(restored)==PARENT and old['files']==fs.descriptors({n:r for n,r in restored.items()if n!='source-map.json'}),'all318 original leaves restored')
    return restored


def inputs():
    return fs.descriptors({n:r for n,r in fs.snapshot(HERE).items()if n not in('constructor-profile.json','prospective.DATA.json')})


def construct(parent,output,expected):
    parent,output=map(fs.absolute,(parent,output));raw=fs.read(HERE/'constructor-profile.json')[0]
    fs.need(fs.pin(raw)['sha256']==expected,'external whole constructor profile pin')
    profile=fs.decode(raw);fs.need(profile['schema']==8 and profile['parent']==PARENT and profile['scope']==SCOPE
        and profile['actual']==ACTUAL and profile['unadmitted']is True and profile['constructor_files']==inputs(),'complete exact unissued constructor closure')
    fs.need(not any(output.is_relative_to(p)or p.is_relative_to(output)for p in(parent,HERE)),'fresh disjoint private Source output')
    files=render(capture(parent));result=identity(files);fs.need(all(profile[k]==v for k,v in result.items()),'whole profiled successor identity')
    fs.publish(files,output);return dict(schema=8,status=SCOPE,unadmitted=True,actual=ACTUAL,native='NOT RUN',**result)


if __name__=='__main__':
    resource.setrlimit(resource.RLIMIT_AS,(512*1024**2,)*2)
    p=argparse.ArgumentParser(description=__doc__)
    for key in ('parent','output'):p.add_argument('--'+key,type=Path,required=True)
    p.add_argument('--profile-sha256',required=True);a=p.parse_args();print(json.dumps(construct(a.parent,a.output,a.profile_sha256),sort_keys=True))

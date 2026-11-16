#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Exact HTTP-User-Agent-only Source successor; no acquisition or actors."""
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
s=importlib.util.spec_from_file_location('rust_v9_source_filesystem',helper);fs=importlib.util.module_from_spec(s);s.loader.exec_module(fs);fs.MAX_FILES=512
PARENT=dict(files=326,bytes=42590643,tree='7db8b512209a275ec9fc4f37006e18b8e5839a6d',map_sha256='382ccdcf2d8abf8fcc739fe917ed35b4cf1cbaa00617393d6fa42614d366cdf4')
ACTUAL=dict.fromkeys(('source','ref','run','job','approval','artifact','image'))
SCOPE='RUST199_HTTP_USER_AGENT_SUCCESSOR_V9'
USER_AGENT='cachy-asahi/rust199-source-reference-v9'
MARKER='http-user-agent-v9.json'
REPLACED={'hosted/materials.py','hosted/entry.py','hosted/phase_transfer.py','.github/workflows/native-arm-build.yml','.github/workflows/native-arm-rust199-source-reference-v1.yml'}
LEAVES=REPLACED
ARCHIVE='previous-v8/'


def encode(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def identity(files):
    return dict(files=len(files),bytes=sum(len(raw)for raw,mode in files.values()),tree=fs.tree(files),map_sha256=fs.pin(files['source-map.json'][0])['sha256'])


def capture(directory):
    files=fs.snapshot(directory);fs.need(identity(files)==PARENT,'whole genuine frozen326 parent bytes/modes/tree/map')
    fs.need(fs.decode(files['source-map.json'][0])['files']==fs.descriptors({n:r for n,r in files.items()if n!='source-map.json'}),'complete326 declared namespace')
    return files


def check_delta(before,payload):
    seams={
        'hosted/materials.py':("headers={'Accept-Encoding':'identity','Accept':", "headers={'User-Agent':'"+USER_AGENT+"','Accept-Encoding':'identity','Accept':"),
        'hosted/phase_transfer.py':("header={'Accept-Encoding':'identity'}", "header={'User-Agent':'"+USER_AGENT+"','Accept-Encoding':'identity'}")}
    for name,(old,new)in seams.items():
        old,new=old.encode(),new.encode();body,mode=before[name];current,current_mode=payload[name]
        fs.need(mode==current_mode==0o644 and body.count(old)==current.count(new)==1 and body.replace(old,new)==current and current.replace(new,old)==body,'one exact public User-Agent header and full transport inverse')
    name='hosted/entry.py';body,mode=before[name];current,current_mode=payload[name]
    checkpoint=("    marker=json.loads(read(root/'http-user-agent-v9.json'))\n"
        "    need(marker['schema']==9 and marker['scope']=='RUST199_HTTP_USER_AGENT_SUCCESSOR_V9' and marker['unadmitted']is True and marker['actual']==dict.fromkeys(('source','ref','run','job','approval','artifact','image')) and marker['Root_grants']is None and marker['user_agent']=='"+USER_AGENT+"','explicit unissued HTTP User-Agent successor checkpoint')\n").encode()
    fs.need(mode==current_mode==0o644 and body.count(b'    return m\n')==1 and current.count(checkpoint)==1 and current.replace(checkpoint,b'')==body,'only version9 Source checkpoint added to current entry')
    old_pin=fs.pin(body)['sha256'].encode();new_pin=fs.pin(current)['sha256'].encode()
    aliases=['.github/workflows/native-arm-build.yml','.github/workflows/native-arm-rust199-source-reference-v1.yml']
    for name in aliases:
        body,mode=before[name];current,current_mode=payload[name]
        fs.need(mode==current_mode==0o644 and body.count(old_pin)==current.count(new_pin)==2 and body.replace(old_pin,new_pin)==current and current.replace(new_pin,old_pin)==body,'only current entry whole-pin workflow substitution')
    fs.need(before[aliases[0]]==before[aliases[1]] and payload[aliases[0]]==payload[aliases[1]],'identical generic and alias workflow bodies')


def render(before):
    fs.need(identity(before)==PARENT,'exact326 parent only')
    payload=fs.snapshot(HERE/'payload');fs.need(set(payload)==LEAVES and all(mode==0o644 for raw,mode in payload.values()),'finite HTTP-header-only overlay')
    fs.need(not any(n.startswith(ARCHIVE)for n in before)and MARKER not in before,'fresh versioned successor namespace')
    check_delta(before,payload)
    files=dict(before);changes={}
    for name in sorted(REPLACED|{'source-map.json'}):files[ARCHIVE+name]=before[name]
    for name,row in payload.items():
        changes[name]=dict(before=fs.descriptors({name:before[name]})[name]if name in before else None,after=fs.descriptors({name:row})[name]);files[name]=row
    marker=dict(schema=9,scope=SCOPE,parent=PARENT,user_agent=USER_AGENT,changes=changes,archives=sorted(ARCHIVE+n for n in REPLACED|{'source-map.json'}),
                resources_changed=False,recipe_changed=False,carrier_transport_changed=False,metadata_normalization_changed=False,request_bounds_changed=False,holds_preserved=True,
                unadmitted=True,Root_grants=None,dispatch=None,actual=ACTUAL)
    files[MARKER]=(encode(marker),0o644)
    old=fs.decode(before['source-map.json'][0]);old['files']=fs.descriptors({n:r for n,r in files.items()if n!='source-map.json'})
    files['source-map.json']=(encode(old),0o644)
    fs.need(undo(files)==before,'complete byte/mode/namespace inverse to326')
    fs.need(all(files[name]==row for name,row in before.items()if name not in REPLACED|{'source-map.json'}),'all compiler/recipe/notices/resources/material joins unchanged')
    return files


def undo(files):
    marker=fs.decode(files[MARKER][0]);fs.need(marker['schema']==9 and marker['scope']==SCOPE and marker['parent']==PARENT and marker['user_agent']==USER_AGENT
        and marker['actual']==ACTUAL and marker['Root_grants']is None and marker['dispatch']is None and marker['unadmitted']is True and marker['holds_preserved']is True
        and all(marker[k]is False for k in ('resources_changed','recipe_changed','carrier_transport_changed','metadata_normalization_changed','request_bounds_changed'))
        and set(marker['changes'])==REPLACED and marker['archives']==sorted(ARCHIVE+n for n in REPLACED|{'source-map.json'}),'unissued exact inverse marker')
    old_map=files[ARCHIVE+'source-map.json'];fs.need(fs.pin(old_map[0])['sha256']==PARENT['map_sha256'],'whole archived326 map')
    old=fs.decode(old_map[0]);expected=set(old['files'])|{'source-map.json'}
    extra={MARKER}|{ARCHIVE+n for n in REPLACED|{'source-map.json'}}
    fs.need(set(files)==expected|extra,'closed successor namespace before inverse')
    current_map=fs.decode(files['source-map.json'][0]);fs.need(current_map['actual']==ACTUAL and current_map['files']==fs.descriptors({n:r for n,r in files.items()if n!='source-map.json'}),'whole current Source map before inverse')
    restored={name:row for name,row in files.items()if name not in extra}
    for name in REPLACED:
        fs.need(fs.descriptors({name:files[name]})[name]==marker['changes'][name]['after'],'exact inverse replacement')
        restored[name]=files[ARCHIVE+name]
    restored['source-map.json']=old_map
    fs.need(identity(restored)==PARENT and old['files']==fs.descriptors({n:r for n,r in restored.items()if n!='source-map.json'}),'all326 original leaves restored')
    return restored


def inputs():
    return fs.descriptors({n:r for n,r in fs.snapshot(HERE).items()if n not in('constructor-profile.json','prospective.DATA.json')})


def construct(parent,output,expected):
    parent,output=map(fs.absolute,(parent,output));raw=fs.read(HERE/'constructor-profile.json')[0]
    fs.need(fs.pin(raw)['sha256']==expected,'external whole constructor profile pin')
    profile=fs.decode(raw);fs.need(profile['schema']==9 and profile['parent']==PARENT and profile['scope']==SCOPE
        and profile['actual']==ACTUAL and profile['Root_review']is None and profile['accepted']is None and profile['unadmitted']is True and profile['constructor_files']==inputs(),'complete exact unissued constructor closure')
    fs.need(not any(output.is_relative_to(p)or p.is_relative_to(output)for p in(parent,HERE)),'fresh disjoint private Source output')
    files=render(capture(parent));result=identity(files);fs.need(all(profile[k]==v for k,v in result.items()),'whole profiled successor identity')
    fs.publish(files,output);return dict(schema=9,status=SCOPE,unadmitted=True,actual=ACTUAL,native='NOT RUN',**result)


if __name__=='__main__':
    resource.setrlimit(resource.RLIMIT_AS,(512*1024**2,)*2)
    p=argparse.ArgumentParser(description=__doc__)
    for key in ('parent','output'):p.add_argument('--'+key,type=Path,required=True)
    p.add_argument('--profile-sha256',required=True);a=p.parse_args();print(json.dumps(construct(a.parent,a.output,a.profile_sha256),sort_keys=True))

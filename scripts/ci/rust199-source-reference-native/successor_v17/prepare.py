#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Exact manifest observational timing Source successor; no acquisition or actors."""
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
s=importlib.util.spec_from_file_location('rust_v17_source_filesystem',helper);fs=importlib.util.module_from_spec(s);s.loader.exec_module(fs);fs.MAX_FILES=512
PARENT=dict(files=364,bytes=43652864,tree='305db479cf93b6abfd441311fb66db047230530e',map_sha256='bd1d5d61836ee3284142884d22cf0f80ccb5d6c285dd8ca4b218708db2551406')
ACTUAL=dict.fromkeys(('source','ref','run','job','approval','artifact','image'))
SCOPE='RUST199_MANIFEST_OBSERVED_TIMINGS_SUCCESSOR_V17'
USER_AGENT='cachy-asahi/rust199-source-reference-v9'
MARKER='manifest-observed-timings-v17.json'
REPLACED={'hosted/phase_transfer.py'}
ADDED=set()
LEAVES=REPLACED|ADDED
ARCHIVE='previous-v16/'


def encode(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def identity(files):
    return dict(files=len(files),bytes=sum(len(raw)for raw,mode in files.values()),tree=fs.tree(files),map_sha256=fs.pin(files['source-map.json'][0])['sha256'])


def capture(directory):
    files=fs.snapshot(directory);fs.need(identity(files)==PARENT,'whole genuine frozen364 parent bytes/modes/tree/map')
    fs.need(fs.decode(files['source-map.json'][0])['files']==fs.descriptors({n:r for n,r in files.items()if n!='source-map.json'}),'complete364 declared namespace')
    return files


def check_delta(before,payload):
    old=before['hosted/phase_transfer.py'][0]
    insertion=b"def decode_manifest(raw):\n # Timings are observations in the relocated envelope, never authority or limits.\n need(type(raw)is bytes and len(raw)<=4*MIB,'finite transfer manifest JSON')\n def pairs(rows):\n  out={}\n  for k,v in rows:need(k not in out,'duplicate transfer manifest JSON key');out[k]=v\n  return out\n def invalid(_):raise ValueError('nonfinite transfer manifest JSON')\n def observed(token):\n  value=float(token);need(math.isfinite(value),'finite observed transfer timing');return value\n value=json.loads(raw,object_pairs_hook=pairs,parse_float=observed,parse_constant=invalid)\n need(type(value)is dict,'transfer manifest JSON object')\n def visit(item,path=()):\n  timing=path==('metadata','boot','normal_phase_deadline')or(len(path)==6 and path[:3]==('metadata','qual','probe_receipts')and type(path[3])is int and 0<=path[3]<9 and path[4:]==('lifecycle','elapsed_seconds'))\n  if timing:need(type(item)in(int,float)and item>=0,'nonnegative numeric observed transfer timing')\n  if type(item)is float:need(timing,'float outside exact observed transfer timing paths')\n  elif type(item)is dict:\n   for key,child in item.items():visit(child,path+(key,))\n  elif type(item)is list:\n   for index,child in enumerate(item):visit(child,path+(index,))\n visit(value);return value\n\n"
    expected=old.replace(b'import json\n',b'import json\nimport math\n').replace(b'\ndef ordinary(path):',b'\n'+insertion+b'def ordinary(path):').replace(b'manifest=decode(raw_manifest)',b'manifest=decode_manifest(raw_manifest)')
    fs.need(old.count(b'import json\n')==old.count(b'\ndef ordinary(path):')==old.count(b'manifest=decode(raw_manifest)')==1 and payload['hosted/phase_transfer.py']==(expected,before['hosted/phase_transfer.py'][1]),'only manifest observational timing decoding changes; strict authority decoder and every acceptance/cap/load/actor byte unchanged')


def render(before):
    fs.need(identity(before)==PARENT,'exact364 parent only')
    payload=fs.snapshot(HERE/'payload');fs.need(set(payload)==LEAVES and all(mode==0o644 for raw,mode in payload.values()),'finite manifest timing overlay')
    fs.need(not ADDED&set(before)and not any(n.startswith(ARCHIVE)for n in before)and MARKER not in before,'fresh versioned successor namespace')
    check_delta(before,payload)
    files=dict(before);changes={}
    for name in sorted(REPLACED|{'source-map.json'}):files[ARCHIVE+name]=before[name]
    for name,row in payload.items():
        changes[name]=dict(before=fs.descriptors({name:before[name]})[name]if name in before else None,after=fs.descriptors({name:row})[name]);files[name]=row
    marker=dict(schema=17,scope=SCOPE,parent=PARENT,kernel_preentry_required=True,manifest_observed_timings=True,source_enforced_order=True,changes=changes,archives=sorted(ARCHIVE+n for n in REPLACED|{'source-map.json'}),
                resources_changed=False,recipe_changed=False,workflows_changed=False,metadata_headers_changed=False,carrier_transport_changed=False,metadata_normalization_changed=False,request_bounds_changed=False,holds_preserved=True,
                unadmitted=True,Root_grants=None,dispatch=None,actual=ACTUAL)
    files[MARKER]=(encode(marker),0o644)
    old=fs.decode(before['source-map.json'][0]);old['files']=fs.descriptors({n:r for n,r in files.items()if n!='source-map.json'})
    files['source-map.json']=(encode(old),0o644)
    fs.need(undo(files)==before,'complete byte/mode/namespace inverse to364')
    fs.need(all(files[name]==row for name,row in before.items()if name not in REPLACED|{'source-map.json'}),'all compiler/recipe/notices/resources/material joins unchanged')
    return files


def undo(files):
    marker=fs.decode(files[MARKER][0]);fs.need(marker['schema']==17 and marker['scope']==SCOPE and marker['parent']==PARENT and marker['kernel_preentry_required']is True and marker['manifest_observed_timings']is True and marker['source_enforced_order']is True
        and marker['actual']==ACTUAL and marker['Root_grants']is None and marker['dispatch']is None and marker['unadmitted']is True and marker['holds_preserved']is True
        and all(marker[k]is False for k in ('resources_changed','recipe_changed','workflows_changed','metadata_headers_changed','carrier_transport_changed','metadata_normalization_changed','request_bounds_changed'))
        and set(marker['changes'])==LEAVES and marker['archives']==sorted(ARCHIVE+n for n in REPLACED|{'source-map.json'}),'unissued exact inverse marker')
    old_map=files[ARCHIVE+'source-map.json'];fs.need(fs.pin(old_map[0])['sha256']==PARENT['map_sha256'],'whole archived364 map')
    old=fs.decode(old_map[0]);expected=set(old['files'])|{'source-map.json'}
    extra={MARKER}|ADDED|{ARCHIVE+n for n in REPLACED|{'source-map.json'}}
    fs.need(set(files)==expected|extra,'closed successor namespace before inverse')
    current_map=fs.decode(files['source-map.json'][0]);fs.need(current_map['actual']==ACTUAL and current_map['files']==fs.descriptors({n:r for n,r in files.items()if n!='source-map.json'}),'whole current Source map before inverse')
    restored={name:row for name,row in files.items()if name not in extra}
    for name in LEAVES:
        fs.need(fs.descriptors({name:files[name]})[name]==marker['changes'][name]['after'],'exact inverse replacement/addition')
        if name in REPLACED:restored[name]=files[ARCHIVE+name]
    restored['source-map.json']=old_map
    fs.need(identity(restored)==PARENT and old['files']==fs.descriptors({n:r for n,r in restored.items()if n!='source-map.json'}),'all364 original leaves restored')
    return restored


def inputs():
    return fs.descriptors({n:r for n,r in fs.snapshot(HERE).items()if n not in('constructor-profile.json','prospective.DATA.json')})


def construct(parent,output,expected):
    parent,output=map(fs.absolute,(parent,output));raw=fs.read(HERE/'constructor-profile.json')[0]
    fs.need(fs.pin(raw)['sha256']==expected,'external whole constructor profile pin')
    profile=fs.decode(raw);fs.need(profile['schema']==17 and profile['parent']==PARENT and profile['scope']==SCOPE
        and profile['actual']==ACTUAL and profile['Root_review']is None and profile['accepted']is None and profile['unadmitted']is True and profile['constructor_files']==inputs(),'complete exact unissued constructor closure')
    fs.need(not any(output.is_relative_to(p)or p.is_relative_to(output)for p in(parent,HERE)),'fresh disjoint private Source output')
    files=render(capture(parent));result=identity(files);fs.need(all(profile[k]==v for k,v in result.items()),'whole profiled successor identity')
    fs.publish(files,output);return dict(schema=17,status=SCOPE,unadmitted=True,actual=ACTUAL,native='NOT RUN',**result)


if __name__=='__main__':
    resource.setrlimit(resource.RLIMIT_AS,(512*1024**2,)*2)
    p=argparse.ArgumentParser(description=__doc__)
    for key in ('parent','output'):p.add_argument('--'+key,type=Path,required=True)
    p.add_argument('--profile-sha256',required=True);a=p.parse_args();print(json.dumps(construct(a.parent,a.output,a.profile_sha256),sort_keys=True))

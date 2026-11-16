#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Exact kernel-mount-preentry-only Source successor; no acquisition or actors."""
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
s=importlib.util.spec_from_file_location('rust_v15_source_filesystem',helper);fs=importlib.util.module_from_spec(s);s.loader.exec_module(fs);fs.MAX_FILES=512
PARENT=dict(files=355,bytes=43408000,tree='3fbb71b78e06cdb9aa219c596a41fda3ccc29280',map_sha256='4a85015fbcb513f8af71ae0d313abc4927faa50682dbf0b6ebfee8f339352bfa')
ACTUAL=dict.fromkeys(('source','ref','run','job','approval','artifact','image'))
SCOPE='RUST199_EXTERNAL_OWNED_JOB_DIRECTORY_SUCCESSOR_V15'
USER_AGENT='cachy-asahi/rust199-source-reference-v9'
MARKER='owned-job-directory-v15.json'
REPLACED={'hosted/producer.py','hosted/qualification.py','hosted/volume.py'}
ADDED={'hosted/owned_dir.py'}
LEAVES=REPLACED|ADDED
ARCHIVE='previous-v14/'


def encode(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def identity(files):
    return dict(files=len(files),bytes=sum(len(raw)for raw,mode in files.values()),tree=fs.tree(files),map_sha256=fs.pin(files['source-map.json'][0])['sha256'])


def capture(directory):
    files=fs.snapshot(directory);fs.need(identity(files)==PARENT,'whole genuine frozen355 parent bytes/modes/tree/map')
    fs.need(fs.decode(files['source-map.json'][0])['files']==fs.descriptors({n:r for n,r in files.items()if n!='source-map.json'}),'complete355 declared namespace')
    return files


def check_delta(before,payload):
    import ast
    allowed={'hosted/producer.py':({'work_path','replay_work_bind','init_options','inspect_init','run'},{'workspace_module'},{'owned_work_bind'}),'hosted/qualification.py':({'run'},set(),set()),'hosted/volume.py':({'verify_receipt'},set(),set())}
    for name,(changed,added,removed)in allowed.items():
        old=before[name][0].decode();new=payload[name][0].decode()
        def functions(text):return {n.name:ast.get_source_segment(text,n)for n in ast.parse(text).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
        a,b=functions(old),functions(new)
        def frame(text):return [ast.dump(n,include_attributes=False)for n in ast.parse(text).body if not isinstance(n,(ast.FunctionDef,ast.ClassDef))and not(isinstance(n,ast.Assign)and name=='hosted/volume.py' and any(isinstance(t,ast.Name)and t.id=='INIT_CODE'for t in n.targets)) and not(isinstance(n,ast.Expr)and isinstance(n.value,ast.Constant)and isinstance(n.value.value,str))]
        fs.need(frame(old)==frame(new)and set(b)==(set(a)-removed)|added,'finite external-directory helper additions/removal only; no policy/module frame changes')
        fs.need(all(a[k]==b[k]for k in a if k not in changed|removed),'only owned directory setup/cleanup and exact no-mutation receipt functions change')
        if name=='hosted/producer.py':
            expected=a['init_options'].replace("'--read-only', '--user=0:0', '--cap-drop=ALL', '--cap-add=CHOWN',", "'--read-only', '--user=1001:1001', '--cap-drop=ALL',")
            fs.need(b['init_options']==expected,'initializer authority reduction only; every resource operand unchanged')
            expected=a['inspect_init'].replace("inspect_domain(actor, 128 * 1024**2, 32, '0:0', ['CHOWN'])", "inspect_domain(actor, 128 * 1024**2, 32, '1001:1001', [])").replace('only exact nonrecursive chmod-before-CHOWN initialization','only exact nonrecursive owned-directory verification').replace('inspect exact unstarted CHOWN actor','inspect exact unstarted cap0 verifier')
            fs.need(b['inspect_init']==expected,'exact reduced-authority initializer inspection')
    fs.need(payload['hosted/volume.py'][0].count(b'os.fchmod(')==0 and payload['hosted/volume.py'][0].count(b'os.fchown(')==0,'initializer does not mutate host ownership/mode')



def render(before):
    fs.need(identity(before)==PARENT,'exact355 parent only')
    payload=fs.snapshot(HERE/'payload');fs.need(set(payload)==LEAVES and all(mode==0o644 for raw,mode in payload.values()),'finite mount/CID custody overlay')
    fs.need(not ADDED&set(before)and not any(n.startswith(ARCHIVE)for n in before)and MARKER not in before,'fresh versioned successor namespace')
    check_delta(before,payload)
    files=dict(before);changes={}
    for name in sorted(REPLACED|{'source-map.json'}):files[ARCHIVE+name]=before[name]
    for name,row in payload.items():
        changes[name]=dict(before=fs.descriptors({name:before[name]})[name]if name in before else None,after=fs.descriptors({name:row})[name]);files[name]=row
    marker=dict(schema=15,scope=SCOPE,parent=PARENT,kernel_preentry_required=True,external_owned_job_directory_setup=True,source_enforced_order=True,changes=changes,archives=sorted(ARCHIVE+n for n in REPLACED|{'source-map.json'}),
                resources_changed=False,recipe_changed=False,workflows_changed=False,metadata_headers_changed=False,carrier_transport_changed=False,metadata_normalization_changed=False,request_bounds_changed=False,holds_preserved=True,
                unadmitted=True,Root_grants=None,dispatch=None,actual=ACTUAL)
    files[MARKER]=(encode(marker),0o644)
    old=fs.decode(before['source-map.json'][0]);old['files']=fs.descriptors({n:r for n,r in files.items()if n!='source-map.json'})
    files['source-map.json']=(encode(old),0o644)
    fs.need(undo(files)==before,'complete byte/mode/namespace inverse to355')
    fs.need(all(files[name]==row for name,row in before.items()if name not in REPLACED|{'source-map.json'}),'all compiler/recipe/notices/resources/material joins unchanged')
    return files


def undo(files):
    marker=fs.decode(files[MARKER][0]);fs.need(marker['schema']==15 and marker['scope']==SCOPE and marker['parent']==PARENT and marker['kernel_preentry_required']is True and marker['external_owned_job_directory_setup']is True and marker['source_enforced_order']is True
        and marker['actual']==ACTUAL and marker['Root_grants']is None and marker['dispatch']is None and marker['unadmitted']is True and marker['holds_preserved']is True
        and all(marker[k]is False for k in ('resources_changed','recipe_changed','workflows_changed','metadata_headers_changed','carrier_transport_changed','metadata_normalization_changed','request_bounds_changed'))
        and set(marker['changes'])==LEAVES and marker['archives']==sorted(ARCHIVE+n for n in REPLACED|{'source-map.json'}),'unissued exact inverse marker')
    old_map=files[ARCHIVE+'source-map.json'];fs.need(fs.pin(old_map[0])['sha256']==PARENT['map_sha256'],'whole archived355 map')
    old=fs.decode(old_map[0]);expected=set(old['files'])|{'source-map.json'}
    extra={MARKER}|ADDED|{ARCHIVE+n for n in REPLACED|{'source-map.json'}}
    fs.need(set(files)==expected|extra,'closed successor namespace before inverse')
    current_map=fs.decode(files['source-map.json'][0]);fs.need(current_map['actual']==ACTUAL and current_map['files']==fs.descriptors({n:r for n,r in files.items()if n!='source-map.json'}),'whole current Source map before inverse')
    restored={name:row for name,row in files.items()if name not in extra}
    for name in LEAVES:
        fs.need(fs.descriptors({name:files[name]})[name]==marker['changes'][name]['after'],'exact inverse replacement/addition')
        if name in REPLACED:restored[name]=files[ARCHIVE+name]
    restored['source-map.json']=old_map
    fs.need(identity(restored)==PARENT and old['files']==fs.descriptors({n:r for n,r in restored.items()if n!='source-map.json'}),'all355 original leaves restored')
    return restored


def inputs():
    return fs.descriptors({n:r for n,r in fs.snapshot(HERE).items()if n not in('constructor-profile.json','prospective.DATA.json')})


def construct(parent,output,expected):
    parent,output=map(fs.absolute,(parent,output));raw=fs.read(HERE/'constructor-profile.json')[0]
    fs.need(fs.pin(raw)['sha256']==expected,'external whole constructor profile pin')
    profile=fs.decode(raw);fs.need(profile['schema']==15 and profile['parent']==PARENT and profile['scope']==SCOPE
        and profile['actual']==ACTUAL and profile['Root_review']is None and profile['accepted']is None and profile['unadmitted']is True and profile['constructor_files']==inputs(),'complete exact unissued constructor closure')
    fs.need(not any(output.is_relative_to(p)or p.is_relative_to(output)for p in(parent,HERE)),'fresh disjoint private Source output')
    files=render(capture(parent));result=identity(files);fs.need(all(profile[k]==v for k,v in result.items()),'whole profiled successor identity')
    fs.publish(files,output);return dict(schema=15,status=SCOPE,unadmitted=True,actual=ACTUAL,native='NOT RUN',**result)


if __name__=='__main__':
    resource.setrlimit(resource.RLIMIT_AS,(512*1024**2,)*2)
    p=argparse.ArgumentParser(description=__doc__)
    for key in ('parent','output'):p.add_argument('--'+key,type=Path,required=True)
    p.add_argument('--profile-sha256',required=True);a=p.parse_args();print(json.dumps(construct(a.parent,a.output,a.profile_sha256),sort_keys=True))

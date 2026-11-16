#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Rejoin exact published LLVM260 and Reader7 DATA to Rust304; execute no roles."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import resource

HERE=Path(__file__).resolve().parent
FS_SHA='7c7b8ce846603d76da1db7de58573fa76642871aae7082fa36b32a54856585d7'
path=HERE.parent/'filesystem.py'
if hashlib.sha256(path.read_bytes()).hexdigest()!=FS_SHA:raise ValueError('held filesystem DATA helper differs')
spec=importlib.util.spec_from_file_location('rust_v6_source_fs',path);fs=importlib.util.module_from_spec(spec);spec.loader.exec_module(fs);fs.MAX_FILES=512
PARENT=dict(public_source='1401a37dee4c58b1338a6068655486d96235d4e6',factory_commit='2c8dc932c9c942d4caa7b1019c7b61eefa091322',files=304,bytes=41520480,tree='04e08a4aa6dc3515dedc780b8ebfbe29e303a47b',map_sha256='221e27f96259a2b3951bb7a9d95cc2540ba3ac504815895f7b81feb0a74f6241',profile_sha256='a02ad02873640666f3ef1429086a21a2cfe8de3b34820d9df8c9763a5dc48b95')
LLVM=dict(sha='031bf1634429446cd0068f4842d56af276cf40f4',ref='refs/heads/codex/llvm23-source-reference-native-v2-20261115-r3',tree='a973e46f51174d1cc3523b66af7a7794b3e66c46',map_sha256='75426d36fae416d1bc3606b8d1a7165408964996bb6467e3223842612221e187',files=260,bytes=40989000,profile_sha256='e558255048be9808a08f024cad0cd8b609f8239eafb1b497b08d8149f862c383',operation='llvm23-source-reference-native-v2')
ACTUAL=dict.fromkeys(('source','ref','run','job','approval','artifact','image'))
PENDING=None
OPERATION='rust199-source-reference-native-v1'
REVISION='llvm260-reader7-rejoin.json'
SCOPE='LLVM260_READER7_PROSPECTIVE_REJOIN_ONLY_NO_ROLES'
WORKFLOWS=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-rust199-source-reference-v1.yml')
READER='llvm-v2/independent-reader-v7/'
READER_COMMIT='0e8af913091fb85db1d10bc1b35bb35e7be6cfbd'
READER_LEAVES={READER+leaf for leaf in ('reader.py','base.py','storage.py','inverse-frame.json','pins.json','derivation.json','binding.TEMPLATE.json','buildinfo.py','architecture-profile.json')}
PUBLICATION='llvm-v2/publication.json'
LLVM_LEAVES=(('policy.json','policy.json','policy_pin'),('hosted/reader.py','reader.py','reader_program'),('contract.json','contract.json','contract_pin'),('candidate-map.json','candidate-map.json','candidate_map_pin'))


def encode(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def capture(directory,identity):
    rows=fs.snapshot(directory);raw,mode=rows['source-map.json']
    fs.need(mode==0o644 and len(rows)==identity['files'] and sum(len(v)for v,_ in rows.values())==identity['bytes'] and fs.tree(rows)==identity['tree'] and fs.pin(raw)['sha256']==identity['map_sha256'],'whole exact Source bytes/modes/tree/map')
    fs.need(fs.descriptors({n:v for n,v in rows.items()if n!='source-map.json'})==json.loads(raw)['files'],'complete input Source map membership');return rows


def reader_pins(files,metadata):
    independent=metadata['independent_reader'];present={n for n in files if n.startswith(READER)}
    fs.need(metadata['pending']is None and type(independent)is dict and set(independent)=={'path','bytes','sha256','files'} and present==READER_LEAVES,'complete static Reader7 nine-leaf DATA closure; no invented profile')
    fs.need(independent['path']=='scripts/port/llvm23-native-independent-reader/v7/reader.py' and set(independent['files'])=={n.removeprefix(READER)for n in READER_LEAVES},'exact Reader7 program and nine pinned leaves')
    for leaf,pin in independent['files'].items():
        fs.need(files[READER+leaf][1]==0o644 and fs.pin(files[READER+leaf][0])==pin,'whole Reader7 static leaf bytes/mode '+leaf)
    fs.need({k:independent[k]for k in ('bytes','sha256')}==independent['files']['reader.py'],'Reader7 entrypoint joins nine-leaf closure')


def architecture_inputs(files,llvm_source):
    profile=json.loads(files[READER+'architecture-profile.json'][0])
    expected={'expected349.lock','original/bootstrap/scripts/ci/inputs.lock.json','original/native/input-profile.json'}
    counts=dict(installed_rows=349,rootfs_rows=165,original_selected_rows=248,selected_rows=256,fixed_addition_rows=8)
    fs.need(type(profile['schema'])is int and profile['schema']==1 and profile['kind']=='LLVM23_SOURCE260_BASE349_ARCHITECTURE_METADATA_V1' and all(type(profile[k])is int and profile[k]==v for k,v in counts.items()),'exact Source260/base349 architecture metadata counts and kind')
    fs.need(profile['basis']=='SOURCE_PINNED_SIGNED_BOOTSTRAP_INPUT_METADATA_NOT_OUTPUT_BUILDINFO' and profile['allowed_architectures']==['aarch64','any'] and all(profile[k]is None for k in ('Root_grants','actual_selectors','required_external_architecture_input')),'architecture derives only from pinned Source inputs; no extra input or grants')
    fs.need(set(profile['files'])==expected,'exact three architecture Source operands')
    for name,pin in profile['files'].items():fs.need(fs.pin(llvm_source[name][0])==pin,'whole LLVM260 architecture input pin '+name)


def publication(files,metadata):
    raw,mode=files[PUBLICATION];value=json.loads(raw)
    fs.need(mode==0o644 and fs.pin(raw)==metadata['publication_pin'] and value==metadata['publication'],'exact Root public readback body and whole-file pin')
    fs.need(value['issuer']=='Root' and value['status']=='PASS_COMPLETE_PUBLIC_GIT_READBACK_DATA_ONLY' and value['source']==LLVM['sha'] and value['ref']==LLVM['ref'] and value['tree']==LLVM['tree'] and value['source_map_sha256']==LLVM['map_sha256'] and value['files']==LLVM['files'] and value['bytes']==LLVM['bytes'] and value['native']==value['M2']=='NOT RUN','public Source readback remains separate from native/M2 roles')
    return value


def template(before,metadata,policy):
    value=json.loads(before);llvm=value['llvm']
    value.update(schema=4,status='UNADMITTED',source=dict.fromkeys(value['source']),resources=policy,once=True,retry=False,holds_preserved=True)
    value['reviews']={k:False for k in value['reviews']};value['claims']={k:False for k in value['claims']}
    value['source_audit']={k:False if type(v)is bool else None for k,v in value['source_audit'].items()}
    value['bootstrap']=dict(qualification_allowed=False,network_during_qualification=False,transfer_redirect_hosts=None)
    delivery=value['delivery'];delivery.update(status='UNADMITTED',holds_preserved=True)
    for name in ('llvm_original','stage0_carrier','root_proof_carrier'):
        delivery[name]={k:v if k=='repository' else False if k=='accepted_by_root' else None for k,v in delivery[name].items()}
    llvm['source']=dict(sha=LLVM['sha'],ref=LLVM['ref'],run=None,job=None);llvm['source_identity']=metadata['identity']
    llvm['policy']=dict(**metadata['policy_pin'],resources=metadata['policy']);llvm['publication']=metadata['publication']
    for name in ('artifact','original'):llvm[name]=dict.fromkeys(llvm[name])
    for name in ('archive','signature','public_test_key','verification_proof','root_decision'):
        for key in ('bytes','sha256','local_path','fingerprint'):
            if key in llvm[name]:llvm[name][key]=None
    descriptor=lambda name:dict(path='/inputs/'+name,local_path=None,bytes=None,sha256=None)
    llvm['reader']=dict(program=metadata['independent_reader'],binding=descriptor('llvm-v2-reader-binding.json'),result=descriptor('llvm-v2-reader.json'))
    return encode(value)


def render(before,llvm_source):
    fs.need(len(before)==PARENT['files'] and fs.tree(before)==PARENT['tree'],'exact frozen304 Rust parent')
    fs.need(len(llvm_source)==LLVM['files'] and fs.tree(llvm_source)==LLVM['tree'],'exact published LLVM260 DATA input')
    payload=fs.snapshot(HERE/'payload');metadata=json.loads(payload['llvm-v2/source.json'][0])
    fs.need(metadata['identity']==LLVM and set(metadata['actual'])=={'job','original','package','publication','reader','root_acceptance','run'} and metadata['actual']['publication']==metadata['publication_pin'] and all(v is None for k,v in metadata['actual'].items()if k!='publication'),'genuine publication pin known; all six future actual roles remain NULL')
    files={n:v for n,v in before.items()if n!='source-map.json'};files.update(payload)
    for source,target,key in LLVM_LEAVES:
        fs.need(files['llvm-v2/'+target]==llvm_source[source] and fs.pin(llvm_source[source][0])=={k:metadata[key][k]for k in ('bytes','sha256')},'exact published LLVM leaf '+source)
    fs.need(metadata['policy']==json.loads(llvm_source['policy.json'][0]) and metadata['reader_development_commit']==READER_COMMIT,'exact published LLVM policy and archived Reader development identity');reader_pins(files,metadata);architecture_inputs(files,llvm_source);publication(files,metadata)
    workflow=(HERE/'workflow.yml.in').read_bytes();fs.need(workflow.count(b'__ENTRY_SHA__')==2,'two unchanged workflow entry hash seams')
    parent_entry=fs.pin(before['hosted/entry.py'][0])['sha256'].encode()
    fs.need(all(before[n][0]==workflow.replace(b'__ENTRY_SHA__',parent_entry) and before[n][1]==0o644 for n in WORKFLOWS),'whole parent workflow template except entry digest')
    workflow=workflow.replace(b'__ENTRY_SHA__',fs.pin(files['hosted/entry.py'][0])['sha256'].encode())
    for name in WORKFLOWS:files[name]=(workflow,0o644)
    policy=json.loads(files['resource-policy.json'][0]);files['root-admission.TEMPLATE.json']=(template(before['root-admission.TEMPLATE.json'][0],metadata,policy),before['root-admission.TEMPLATE.json'][1])
    allowed={'admission.py','hosted/entry.py','llvm-v2/source.json',PUBLICATION,'root-admission.TEMPLATE.json',*WORKFLOWS}|{'llvm-v2/'+target for _,target,_ in LLVM_LEAVES}
    fs.need(set(files)-set(before)<=READER_LEAVES|{PUBLICATION},'only new Reader static leaves and genuine publication DATA may be added')
    protected={n:v for n,v in before.items()if n!='source-map.json' and n not in allowed}
    fs.need(all(files.get(n)==v for n,v in protected.items()),'all other304 parent leaves/modes including archived v3/v4 Readers, resources, recipes, actors and historical v4/v5 markers preserved')
    changes={n:dict(before=fs.descriptors({n:before[n]})[n]if n in before else None,after=fs.descriptors({n:files[n]})[n])for n in sorted(files)if before.get(n)!=files[n]}
    revision=dict(schema=6,parent=PARENT,llvm=LLVM,pending=metadata['pending'],changes=changes,protected=fs.descriptors(protected),actual=ACTUAL,scope=SCOPE)
    files[REVISION]=(encode(revision),0o644);files['source-map.json']=(encode(dict(schema=1,operation=OPERATION,actual=ACTUAL,files=fs.descriptors(files))),0o644)
    fs.need(undo(files,before,revision)==before,'whole exact304 inverse')
    fs.need(len(files)<=512 and sum(len(raw)for raw,_ in files.values())<=96*1024**2,'finite Source rejoin');return files


def undo(files,before,revision):
    fs.need(revision['schema']==6 and revision['parent']==PARENT and revision['llvm']==LLVM and revision['scope']==SCOPE and files[REVISION]==(encode(revision),0o644),'exact rejoin inverse metadata')
    fs.need(files['source-map.json']==(encode(dict(schema=1,operation=OPERATION,actual=ACTUAL,files=fs.descriptors({n:v for n,v in files.items()if n!='source-map.json'}))),0o644),'exact successor whole-map inverse operand')
    restored=dict(files);restored.pop('source-map.json');restored.pop(REVISION)
    for name,row in revision['changes'].items():
        fs.need(fs.descriptors({name:restored[name]})[name]==row['after'],'exact inverse successor operand')
        if name in before:
            fs.need(fs.descriptors({name:before[name]})[name]==row['before'],'exact inverse parent operand');restored[name]=before[name]
        else:restored.pop(name)
    restored['source-map.json']=before['source-map.json'];fs.need(restored==before and fs.tree(restored)==PARENT['tree'],'complete304 inverse');return restored


def inputs():return fs.descriptors({n:v for n,v in fs.snapshot(HERE).items()if n not in ('constructor-profile.json','validation.json')})


def construct(rust_parent,llvm_source,output,profile_sha):
    rust_parent,llvm_source,output=map(fs.absolute,(rust_parent,llvm_source,output));raw=fs.read(HERE/'constructor-profile.json')[0]
    fs.need(fs.pin(raw)['sha256']==profile_sha,'external whole constructor profile required');profile=json.loads(raw);pending=json.loads(fs.read(HERE/'payload/llvm-v2/source.json')[0])['pending']
    fs.need(profile['parent']==PARENT and profile['llvm']==LLVM and profile['pending']==pending and profile['actual']==ACTUAL and profile['constructor_files']==inputs(),'whole reviewed constructor closure')
    fs.need(not any(output.is_relative_to(p)or p.is_relative_to(output)for p in (rust_parent,llvm_source,HERE)),'fresh disjoint Source output')
    files=render(capture(rust_parent,PARENT),capture(llvm_source,LLVM));fs.need(fs.tree(files)==profile['tree'] and fs.pin(files['source-map.json'][0])['sha256']==profile['map_sha256'],'exact profiled Source rejoin')
    fs.publish(files,output);return dict(status='CONSTRUCTED_V6_LLVM260_READER7_REJOIN_DATA_ONLY',pending=pending,files=len(files),bytes=sum(len(v)for v,_ in files.values()),tree=fs.tree(files),map=fs.pin(files['source-map.json'][0]),actual=ACTUAL,native='NOT_RUN')


if __name__=='__main__':
    resource.setrlimit(resource.RLIMIT_AS,(512*1024**2,)*2);p=argparse.ArgumentParser(description=__doc__)
    for n in ('rust-parent','llvm-source','output'):p.add_argument('--'+n,required=True,type=Path)
    p.add_argument('--profile-sha256',required=True);a=p.parse_args();print(json.dumps(construct(a.rust_parent,a.llvm_source,a.output,a.profile_sha256),sort_keys=True))

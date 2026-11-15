#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Rejoin exact published LLVM256 Source DATA to Rust298; execute no roles."""
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
spec=importlib.util.spec_from_file_location('rust_v5_source_fs',path);fs=importlib.util.module_from_spec(spec);spec.loader.exec_module(fs);fs.MAX_FILES=512
PARENT=dict(development_commit='7e1d4d6e5b0d8958bca755914b05fd190a4d0590',files=298,bytes=41419617,tree='b85b1c6f22a378c1518bfffb25330c509666b57a',map_sha256='233a863c73b1ef051fae047a16486a86a7efaffadc8d06d2bcf034e22f7c831e',profile_sha256='90c8193a83296a8acb4b10776fe3436f2e3109bc9fbed5dc01da3a8e9f775a3e')
LLVM=dict(sha='365a763bc515a1b3550cc804536ddbf66353aac8',ref='refs/heads/codex/llvm23-source-reference-native-v2-20261115-r2',tree='f251f3b7c7e152943ce85bc012f97305934e8fd8',map_sha256='22f6f8a9d3eabf4de16c853cf67183b67beca4e702e26c5b492066e94194735c',files=256,bytes=40919517,profile_sha256='78d4decc97c57dc0e75d7e4ac097b4f32699fd4ae0fb15d1e35e0a45a566ae7d',operation='llvm23-source-reference-native-v2')
ACTUAL=dict.fromkeys(('source','ref','run','job','approval','artifact','image'))
PENDING='NEW_LLVM256_READER_STATIC_CODE_REQUIRED'
OPERATION='rust199-source-reference-native-v1'
REVISION='llvm256-rejoin.json'
SCOPE='LLVM256_PUBLISHED_SOURCE_READER_REJOIN_ONLY_NO_ROLES'
WORKFLOWS=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-rust199-source-reference-v1.yml')
READER='llvm-v2/independent-reader-v4/'
READER_LEAVES={READER+leaf for leaf in ('reader.py','base.py','profile.json','pins.json')}
PUBLICATION='llvm-v2/publication.json'
LLVM_LEAVES=(('policy.json','policy.json','policy_pin'),('hosted/reader.py','reader.py','reader_program'),('contract.json','contract.json','contract_pin'),('candidate-map.json','candidate-map.json','candidate_map_pin'))


def encode(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def capture(directory,identity):
    rows=fs.snapshot(directory);raw,mode=rows['source-map.json']
    fs.need(mode==0o644 and len(rows)==identity['files'] and sum(len(v)for v,_ in rows.values())==identity['bytes'] and fs.tree(rows)==identity['tree'] and fs.pin(raw)['sha256']==identity['map_sha256'],'whole exact Source bytes/modes/tree/map')
    fs.need(fs.descriptors({n:v for n,v in rows.items()if n!='source-map.json'})==json.loads(raw)['files'],'complete input Source map membership');return rows


def reader_pins(files,metadata):
    pending=metadata.get('pending');independent=metadata['independent_reader'];present=set(files)&READER_LEAVES
    if pending is not None:
        fs.need(pending==PENDING and independent is None and not present,'pending Reader has no invented program tuple or leaves');return
    fs.need(type(independent)is dict and present==READER_LEAVES,'complete new Reader static DATA required')
    for leaf,pin in (('reader.py',independent),('base.py',independent['base']),('profile.json',independent['profile']),('pins.json',independent['pins'])):
        fs.need(fs.pin(files[READER+leaf][0])=={k:pin[k]for k in ('bytes','sha256')},'whole new Reader static leaf pin '+leaf)


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
    fs.need(len(before)==PARENT['files'] and fs.tree(before)==PARENT['tree'],'exact frozen298 Rust parent')
    fs.need(len(llvm_source)==LLVM['files'] and fs.tree(llvm_source)==LLVM['tree'],'exact published LLVM256 DATA input')
    payload=fs.snapshot(HERE/'payload');metadata=json.loads(payload['llvm-v2/source.json'][0])
    fs.need(metadata['identity']==LLVM and set(metadata['actual'])=={'job','original','package','publication','reader','root_acceptance','run'} and metadata['actual']['publication']==metadata['publication_pin'] and all(v is None for k,v in metadata['actual'].items()if k!='publication'),'genuine publication pin known; all six future actual roles remain NULL')
    files={n:v for n,v in before.items()if n!='source-map.json'};files.update(payload)
    for source,target,key in LLVM_LEAVES:
        fs.need(files['llvm-v2/'+target]==llvm_source[source] and fs.pin(llvm_source[source][0])=={k:metadata[key][k]for k in ('bytes','sha256')},'exact published LLVM leaf '+source)
    fs.need(metadata['policy']==json.loads(llvm_source['policy.json'][0]),'exact published LLVM policy body');reader_pins(files,metadata);publication(files,metadata)
    workflow=(HERE/'workflow.yml.in').read_bytes();fs.need(workflow.count(b'__ENTRY_SHA__')==2,'two unchanged workflow entry hash seams')
    parent_entry=fs.pin(before['hosted/entry.py'][0])['sha256'].encode()
    fs.need(all(before[n][0]==workflow.replace(b'__ENTRY_SHA__',parent_entry) and before[n][1]==0o644 for n in WORKFLOWS),'whole parent workflow template except entry digest')
    workflow=workflow.replace(b'__ENTRY_SHA__',fs.pin(files['hosted/entry.py'][0])['sha256'].encode())
    for name in WORKFLOWS:files[name]=(workflow,0o644)
    policy=json.loads(files['resource-policy.json'][0]);files['root-admission.TEMPLATE.json']=(template(before['root-admission.TEMPLATE.json'][0],metadata,policy),before['root-admission.TEMPLATE.json'][1])
    allowed={'admission.py','hosted/entry.py','llvm-v2/source.json','root-admission.TEMPLATE.json',*WORKFLOWS}|{'llvm-v2/'+target for _,target,_ in LLVM_LEAVES}
    fs.need(set(files)-set(before)<=READER_LEAVES|{PUBLICATION},'only new Reader static leaves and genuine publication DATA may be added')
    protected={n:v for n,v in before.items()if n!='source-map.json' and n not in allowed}
    fs.need(all(files.get(n)==v for n,v in protected.items()),'all other298 parent leaves/modes including archived v3 Reader, resources, recipes, actors and historical v4 marker preserved')
    changes={n:dict(before=fs.descriptors({n:before[n]})[n]if n in before else None,after=fs.descriptors({n:files[n]})[n])for n in sorted(files)if before.get(n)!=files[n]}
    revision=dict(schema=5,parent=PARENT,llvm=LLVM,pending=metadata['pending'],changes=changes,protected=fs.descriptors(protected),actual=ACTUAL,scope=SCOPE)
    files[REVISION]=(encode(revision),0o644);files['source-map.json']=(encode(dict(schema=1,operation=OPERATION,actual=ACTUAL,files=fs.descriptors(files))),0o644)
    fs.need(undo(files,before,revision)==before,'whole exact298 inverse')
    fs.need(len(files)<=512 and sum(len(raw)for raw,_ in files.values())<=96*1024**2,'finite Source rejoin');return files


def undo(files,before,revision):
    fs.need(revision['schema']==5 and revision['parent']==PARENT and revision['llvm']==LLVM and revision['scope']==SCOPE and files[REVISION]==(encode(revision),0o644),'exact rejoin inverse metadata')
    fs.need(files['source-map.json']==(encode(dict(schema=1,operation=OPERATION,actual=ACTUAL,files=fs.descriptors({n:v for n,v in files.items()if n!='source-map.json'}))),0o644),'exact successor whole-map inverse operand')
    restored=dict(files);restored.pop('source-map.json');restored.pop(REVISION)
    for name,row in revision['changes'].items():
        fs.need(fs.descriptors({name:restored[name]})[name]==row['after'],'exact inverse successor operand')
        if name in before:
            fs.need(fs.descriptors({name:before[name]})[name]==row['before'],'exact inverse parent operand');restored[name]=before[name]
        else:restored.pop(name)
    restored['source-map.json']=before['source-map.json'];fs.need(restored==before and fs.tree(restored)==PARENT['tree'],'complete298 inverse');return restored


def inputs():return fs.descriptors({n:v for n,v in fs.snapshot(HERE).items()if n not in ('constructor-profile.json','validation.json')})


def construct(rust_parent,llvm_source,output,profile_sha):
    rust_parent,llvm_source,output=map(fs.absolute,(rust_parent,llvm_source,output));raw=fs.read(HERE/'constructor-profile.json')[0]
    fs.need(fs.pin(raw)['sha256']==profile_sha,'external whole constructor profile required');profile=json.loads(raw);pending=json.loads(fs.read(HERE/'payload/llvm-v2/source.json')[0])['pending']
    fs.need(profile['parent']==PARENT and profile['llvm']==LLVM and profile['pending']==pending and profile['actual']==ACTUAL and profile['constructor_files']==inputs(),'whole reviewed constructor closure')
    fs.need(not any(output.is_relative_to(p)or p.is_relative_to(output)for p in (rust_parent,llvm_source,HERE)),'fresh disjoint Source output')
    files=render(capture(rust_parent,PARENT),capture(llvm_source,LLVM));fs.need(fs.tree(files)==profile['tree'] and fs.pin(files['source-map.json'][0])['sha256']==profile['map_sha256'],'exact profiled Source rejoin')
    fs.publish(files,output);return dict(status='CONSTRUCTED_V5_LLVM256_REJOIN_DATA_ONLY',pending=pending,files=len(files),bytes=sum(len(v)for v,_ in files.values()),tree=fs.tree(files),map=fs.pin(files['source-map.json'][0]),actual=ACTUAL,native='NOT_RUN')


if __name__=='__main__':
    resource.setrlimit(resource.RLIMIT_AS,(512*1024**2,)*2);p=argparse.ArgumentParser(description=__doc__)
    for n in ('rust-parent','llvm-source','output'):p.add_argument('--'+n,required=True,type=Path)
    p.add_argument('--profile-sha256',required=True);a=p.parse_args();print(json.dumps(construct(a.rust_parent,a.llvm_source,a.output,a.profile_sha256),sort_keys=True))

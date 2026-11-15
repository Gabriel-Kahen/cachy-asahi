#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Build a finite v4 Source checkpoint from exact local DATA; no operational role."""
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
spec=importlib.util.spec_from_file_location('rust_v4_source_fs',path);fs=importlib.util.module_from_spec(spec);spec.loader.exec_module(fs);fs.MAX_FILES=512
PARENT=dict(development_commit='2682c9b62a362836690e28bbfbb443f9c240e54d',files=286,bytes=41158325,tree='9baf15a44fd60792299d2260d7c0d0473319b31e',map_sha256='6169aa50524527f00b4829bf34b882a5abb2912bbc1eabe5562ddc76f20509cd',profile_sha256='1702cde18560918351c2ac4edce176ee6fffffb5f326a7169a871a644220c0a2')
LLVM=dict(sha=None,ref=None,tree='2f90eaaaa532d14574c0ce1f1c93b02310f44d91',map_sha256='5c19a2699856e081712d159c551ce496919938bd456f2182c0c905f03cbd2ef0',files=253,bytes=40862047,profile_sha256='aa5e19a9df3da4dbead98ca975a2f791c7a1995cbad398ec76be5231999b6d35',operation='llvm23-source-reference-native-v2')
ACTUAL=dict.fromkeys(('source','ref','run','job','approval','artifact','image'))
OPERATION='rust199-source-reference-native-v1'
PENDING='LLVM253_SUPERSEDED_CAPFIX_SOURCE_REJOIN_REQUIRED_BEFORE_PUBLICATION_OR_RUN'

def encode(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()

def capture(directory,identity):
    rows=fs.snapshot(directory);raw,mode=rows['source-map.json']
    fs.need(mode==0o644 and len(rows)==identity['files'] and sum(len(v)for v,_ in rows.values())==identity['bytes'] and fs.tree(rows)==identity['tree'] and fs.pin(raw)['sha256']==identity['map_sha256'],'whole exact Source bytes/modes/tree/map')
    fs.need(fs.descriptors({n:v for n,v in rows.items()if n!='source-map.json'})==json.loads(raw)['files'],'complete input Source map membership');return rows

def template(before,metadata,policy):
    llvm=json.loads(before)['llvm'];llvm['source']=dict(sha=None,ref=None,run=None,job=None)
    descriptor=lambda name:dict(path='/inputs/'+name,local_path=None,bytes=None,sha256=None)
    llvm['source_identity']=metadata['identity'];llvm['policy']=dict(**metadata['policy_pin'],resources=metadata['policy'])
    llvm['publication']=None;llvm['reader']=dict(program=metadata['independent_reader'],binding=descriptor('llvm-v2-reader-binding.json'),result=descriptor('llvm-v2-reader.json'))
    def carrier():return dict(repository='Gabriel-Kahen/cachy-asahi',id=None,run=None,job=None,source=None,bytes=None,sha256=None,metadata_sha256=None,job_metadata_sha256=None,redirect_hosts=None,members=None,accepted_by_root=False)
    return encode(dict(schema=4,status='UNADMITTED',source=dict(sha=None,ref=None,map_sha256=None,approval=None,run=None,job=None),resources=policy,once=True,retry=False,holds_preserved=True,reviews={k:False for k in ('source','bootstrap_image','stage0','upstream_source','llvm_material','build_resources','retirement','trust','privacy','scheduler')},source_audit=dict(status=None,library_cargo_config_sha256=None,consumed_git_dependencies_and_paths_reviewed=False,compiler_rt_libunwind_members_and_notices_reviewed=False,retained_source_authentication_rejoined=False),delivery=dict(schema=1,status='UNADMITTED',holds_preserved=True,llvm_original=carrier(),stage0_carrier=carrier(),root_proof_carrier=carrier(),sources='PINNED_HTTPS'),bootstrap=dict(qualification_allowed=False,network_during_qualification=False,transfer_redirect_hosts=None),llvm=llvm,claims=dict(root_authenticated=False,native_acceptance=False,hardware_acceptance=False,release_acceptance=False)))

def render(before,llvm_source):
    fs.need(len(before)==PARENT['files'] and fs.tree(before)==PARENT['tree'],'exact frozen286 Rust parent')
    fs.need(len(llvm_source)==LLVM['files'] and fs.tree(llvm_source)==LLVM['tree'],'exact checkpoint LLVM253 DATA input')
    files={n:v for n,v in before.items()if n!='source-map.json'};payload=fs.snapshot(HERE/'payload');metadata=json.loads(payload['llvm-v2/source.json'][0])
    fs.need(metadata['identity']==LLVM and all(v is None for v in metadata['actual'].values()),'unpublished checkpoint metadata; acceptance remains NULL')
    fs.need(payload['frozen/rust199-admission-v1.py']==before['frozen/rust199-admission-v1.py'],'all prior qualification gates retained byteexact')
    fs.need(fs.pin(payload['frozen/bootstrap349.py'][0])['sha256']=='27e17683ba185d6959307b081ab86be4c7740ef5dbb8dff9c850670eda2ec008','exact frozen signed349 helper')
    for source,target,key in (('policy.json','policy.json','policy_pin'),('hosted/reader.py','reader.py','reader_program'),('contract.json','contract.json','contract_pin'),('candidate-map.json','candidate-map.json','candidate_map_pin')):
        fs.need(payload['llvm-v2/'+target]==llvm_source[source] and fs.pin(llvm_source[source][0])=={k:metadata[key][k]for k in ('bytes','sha256')},'exact checkpoint LLVM leaf '+source)
    independent=metadata['independent_reader']
    for leaf,pin in (('reader.py',independent),('base.py',independent['base']),('profile.json',independent['profile']),('pins.json',independent['pins'])):
        fs.need(fs.pin(payload['llvm-v2/independent-reader-v3/'+leaf][0])=={k:pin[k]for k in ('bytes','sha256')},'exact archived independent Reader DATA '+leaf)
    files.update(payload);workflow=(HERE/'workflow.yml.in').read_bytes();fs.need(workflow.count(b'__ENTRY_SHA__')==2,'two workflow entry hash seams')
    workflow=workflow.replace(b'__ENTRY_SHA__',fs.pin(payload['hosted/entry.py'][0])['sha256'].encode())
    for name in ('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-rust199-source-reference-v1.yml'):files[name]=(workflow,0o644)
    policy=json.loads(payload['resource-policy.json'][0]);files['root-admission.TEMPLATE.json']=(template(before['root-admission.TEMPLATE.json'][0],metadata,policy),0o644)
    for name in ('contract.json','builder-audit.json'):
        value=json.loads(before[name][0]);value['native_successor_v4']=dict(status='SOURCE_CHECKPOINT_ONLY',pending=PENDING,dispatch_inputs=['source_sha','source_map_sha256','approval_sha256','root_admission_sha256','root_admission_json','operation'],resource_policy=fs.pin(payload['resource-policy.json'][0]),provider_ids='JOIN_ACTUAL_RUN_AND_PHASE_JOB_INSIDE_WORKFLOW_BEFORE_PRODUCER',llvm_identity=LLVM,actual=ACTUAL)
        files[name]=(encode(value),before[name][1])
    changed=set(payload)|{'.github/workflows/native-arm-build.yml','.github/workflows/native-arm-rust199-source-reference-v1.yml','root-admission.TEMPLATE.json','contract.json','builder-audit.json','source-map.json'}
    protected={n:v for n,v in before.items()if n not in changed}
    fs.need(all(files[n]==v for n,v in protected.items()),'candidate/source/intake/recipe/flags/legacy checkpoints preserved')
    changes={n:dict(before=fs.descriptors({n:before[n]})[n]if n in before else None,after=fs.descriptors({n:files[n]})[n])for n in sorted(files)if before.get(n)!=files[n]}
    revision=dict(schema=4,parent=PARENT,llvm=LLVM,pending=PENDING,changes=changes,protected=fs.descriptors(protected),actual=ACTUAL,scope='TWO_JOB_SIX_INPUT_NATIVE_QUALIFICATION_SOURCE_CHECKPOINT_NO_ROLES')
    files['native-successor-v4.json']=(encode(revision),0o644);files['source-map.json']=(encode(dict(schema=1,operation=OPERATION,actual=ACTUAL,files=fs.descriptors(files))),0o644)
    fs.need(undo(files,before,revision)==before,'whole exact286 inverse')
    fs.need(len(files)<=512 and sum(len(raw)for raw,_ in files.values())<=96*1024**2,'finite Source checkpoint');return files

def undo(files,before,revision):
    restored=dict(files);restored.pop('source-map.json');restored.pop('native-successor-v4.json')
    for name,row in revision['changes'].items():
        fs.need(fs.descriptors({name:restored[name]})[name]==row['after'],'exact inverse successor operand')
        if name in before:
            fs.need(fs.descriptors({name:before[name]})[name]==row['before'],'exact inverse parent operand');restored[name]=before[name]
        else:restored.pop(name)
    restored['source-map.json']=before['source-map.json'];fs.need(restored==before and fs.tree(restored)==PARENT['tree'],'complete286 inverse');return restored

def inputs():return fs.descriptors({n:v for n,v in fs.snapshot(HERE).items()if n not in ('constructor-profile.json','validation.json')})

def construct(rust_parent,llvm_source,output,profile_sha):
    rust_parent,llvm_source,output=map(fs.absolute,(rust_parent,llvm_source,output));raw=fs.read(HERE/'constructor-profile.json')[0]
    fs.need(fs.pin(raw)['sha256']==profile_sha,'external whole constructor profile required');profile=json.loads(raw)
    fs.need(profile['parent']==PARENT and profile['llvm']==LLVM and profile['pending']==PENDING and profile['actual']==ACTUAL and profile['constructor_files']==inputs(),'whole reviewed constructor closure')
    fs.need(not any(output.is_relative_to(p)or p.is_relative_to(output)for p in (rust_parent,llvm_source,HERE)),'fresh disjoint Source output')
    files=render(capture(rust_parent,PARENT),capture(llvm_source,LLVM));fs.need(fs.tree(files)==profile['tree'] and fs.pin(files['source-map.json'][0])['sha256']==profile['map_sha256'],'exact profiled Source checkpoint')
    fs.publish(files,output);return dict(status='CONSTRUCTED_V4_SOURCE_CHECKPOINT_DATA_ONLY',pending=PENDING,files=len(files),bytes=sum(len(v)for v,_ in files.values()),tree=fs.tree(files),map=fs.pin(files['source-map.json'][0]),actual=ACTUAL,native='NOT_RUN')

if __name__=='__main__':
    resource.setrlimit(resource.RLIMIT_AS,(512*1024**2,)*2);p=argparse.ArgumentParser(description=__doc__)
    for n in ('rust-parent','llvm-source','output'):p.add_argument('--'+n,required=True,type=Path)
    p.add_argument('--profile-sha256',required=True);a=p.parse_args();print(json.dumps(construct(a.rust_parent,a.llvm_source,a.output,a.profile_sha256),sort_keys=True))

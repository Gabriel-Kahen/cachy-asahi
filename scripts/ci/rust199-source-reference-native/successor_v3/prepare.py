#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Exact Rust279/LLVM251 rejoin as DATA; never invokes a Reader or native role."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import resource

HERE=Path(__file__).resolve().parent
FS_SHA='7c7b8ce846603d76da1db7de58573fa76642871aae7082fa36b32a54856585d7'
file=HERE.parent/'filesystem.py'
if hashlib.sha256(file.read_bytes()).hexdigest()!=FS_SHA:raise ValueError('held filesystem DATA helper differs')
spec=importlib.util.spec_from_file_location('rust_rejoin_source_fs',file);fs=importlib.util.module_from_spec(spec);spec.loader.exec_module(fs);fs.MAX_FILES=384
PARENT=dict(development_commit='587e9ab77f8e1a203fc212c947b3d7592f24b835',files=279,bytes=41059447,tree='bf13742624519979a44de9806e721df607b0033a',map_sha256='f322975e18491a9c5b528da32be310bebef38d76a26c5b5a3097a4d8a4ae9fb1',profile_sha256='6802e3138a6cb2e362df0ea2759424c4f03895122778f183179bd241293ec2ad')
LLVM=dict(sha='6d0243dc8f5cf4ee5b9316b8c804f14a3236ecb0',ref='refs/heads/codex/llvm23-source-reference-native-v2-20261115',tree='87f5aa3537474c2dd33a02c50e869ea5fb25e7b4',map_sha256='809f57839dfd574b7abf0c65535321aeac08c58608d4f9597f936a7af78fb3a2',files=251,bytes=40807998,profile_sha256='587145a6935726e7efe898963f126da1fe399dbde157930f83a1826e5e513e4b',operation='llvm23-source-reference-native-v2')
ACTUAL=dict.fromkeys(('source','ref','run','job','approval','artifact','image'))
OPERATION='rust199-source-reference-native-v1'


def encode(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def capture(directory,identity):
    rows=fs.snapshot(directory);raw,mode=rows['source-map.json']
    fs.need(mode==0o644 and len(rows)==identity['files'] and sum(len(raw) for raw,_ in rows.values())==identity['bytes'] and
            fs.tree(rows)==identity['tree'] and fs.pin(raw)['sha256']==identity['map_sha256'],'whole exact Source input bytes/modes/tree/map')
    fs.need(fs.descriptors({n:v for n,v in rows.items() if n!='source-map.json'})==json.loads(raw)['files'],'complete input Source map membership');return rows


def actor_entry(raw):
    old=b"need(len(seen)==11,'complete eleven Root external proof operands')"
    new=b"need(len(seen)==13,'complete thirteen Root external proof operands')"
    fs.need(raw.count(old)==1,'exact prior actor proof namespace seam');out=raw.replace(old,new)
    fs.need(out.replace(new,old)==raw,'whole actor namespace literal inverse');return out


def template(before,metadata):
    a=json.loads(before);a['status']='UNADMITTED';llvm=a['llvm'];llvm['source'].update(sha=LLVM['sha'],ref=LLVM['ref'])
    llvm['source_identity']=metadata['identity'];llvm['policy']=dict(**metadata['policy_pin'],resources=metadata['policy'])
    descriptor=lambda name:dict(path='/inputs/'+name,local_path=None,bytes=None,sha256=None)
    llvm['reader']=dict(program=metadata['reader_program'],binding=descriptor('llvm-v2-reader-binding.json'),result=descriptor('llvm-v2-reader.json'))
    return encode(a)


def render(before,llvm_source):
    fs.need(len(before)==PARENT['files'] and fs.tree(before)==PARENT['tree'],'exact frozen279 Rust parent')
    fs.need(len(llvm_source)==LLVM['files'] and fs.tree(llvm_source)==LLVM['tree'],'exact published251 LLVM v2 Source')
    files={n:v for n,v in before.items() if n!='source-map.json'};payload=fs.snapshot(HERE/'payload')
    allowed={'admission.py','frozen/rust199-admission-v1.py','llvm-v2/source.json','llvm-v2/policy.json','llvm-v2/reader.py','llvm-v2/contract.json','llvm-v2/candidate-map.json'}
    fs.need(set(payload)==allowed,'finite LLVM v2 gate/static-evidence overlay')
    fs.need(payload['frozen/rust199-admission-v1.py']==before['admission.py'],'exact unchanged old gate retained for all prior qualifications')
    metadata=json.loads(payload['llvm-v2/source.json'][0]);fs.need(metadata['identity']==LLVM and all(value is None for value in metadata['actual'].values()),'only published Source identity known; runtime acceptance remains NULL')
    for source,target,key in [('policy.json','policy.json','policy_pin'),('hosted/reader.py','reader.py','reader_program'),('contract.json','contract.json','contract_pin'),('candidate-map.json','candidate-map.json','candidate_map_pin')]:
        fs.need(payload['llvm-v2/'+target]==llvm_source[source] and fs.pin(llvm_source[source][0])=={k:metadata[key][k] for k in ('bytes','sha256')},'whole LLVM v2 policy/Reader/recipe snapshot join: '+source)
    fs.need(json.loads(llvm_source['policy.json'][0])==metadata['policy'],'exact full v2 policy, including initializer budget')
    contract=json.loads(llvm_source['contract.json'][0]);fs.need(contract['outer_delegation']['operation']==LLVM['operation'] and contract['outer_delegation']['frozen_python_actor'] is True and contract['package_name']=='cachy-asahi-llvm23-source-reference-23.1.1-1-aarch64.pkg.tar.zst','exact v2 delegation and frozen private package')
    files.update(payload);files['actor/entry.py']=(actor_entry(before['actor/entry.py'][0]),before['actor/entry.py'][1])
    files['root-admission.TEMPLATE.json']=(template(before['root-admission.TEMPLATE.json'][0],metadata),before['root-admission.TEMPLATE.json'][1])
    for name in ('contract.json','builder-audit.json'):
        value=json.loads(before[name][0]);value['llvm_input_rejoin']=dict(revision=3,source_identity=LLVM,policy=metadata['policy_pin'],reader_program=metadata['reader_program'],runtime=metadata['actual'],root_decision_required=True)
        files[name]=(encode(value),before[name][1])
    protected={n:v for n,v in before.items() if n not in ('admission.py','actor/entry.py','root-admission.TEMPLATE.json','contract.json','builder-audit.json','source-map.json')}
    fs.need(all(files[n]==v for n,v in protected.items()),'candidate/intake/flags/work-volume producer/resources/legacy checkpoints unchanged')
    changes={n:dict(before=fs.descriptors({n:before[n]})[n] if n in before else None,after=fs.descriptors({n:files[n]})[n]) for n in sorted(files) if before.get(n)!=files[n]}
    revision=dict(schema=1,revision=3,parent=PARENT,llvm=LLVM,changes=changes,protected=fs.descriptors(protected),actual=ACTUAL,scope='LLVM_V2_SOURCE_POLICY_READER_ROOT_DECISION_REJOIN_ONLY_NO_ROLES')
    files['llvm-v2-rejoin.json']=(encode(revision),0o644)
    files['source-map.json']=(encode(dict(schema=1,operation=OPERATION,actual=ACTUAL,files=fs.descriptors(files))),0o644)
    fs.need(undo(files,before,revision)==before,'whole exact279 parent inverse')
    fs.need(len(files)<=384 and sum(len(raw) for raw,_ in files.values())<=96*1024**2,'finite prospective Source');return files


def undo(files,before,revision):
    restored=dict(files);restored.pop('source-map.json');restored.pop('llvm-v2-rejoin.json')
    for name,row in revision['changes'].items():
        fs.need(fs.descriptors({name:restored[name]})[name]==row['after'],'exact inverse successor operand')
        if name in before:
            fs.need(fs.descriptors({name:before[name]})[name]==row['before'],'exact inverse parent operand');restored[name]=before[name]
        else:restored.pop(name)
    restored['source-map.json']=before['source-map.json'];fs.need(restored==before and fs.tree(restored)==PARENT['tree'],'complete279 inverse');return restored


def inputs():return fs.descriptors({n:v for n,v in fs.snapshot(HERE).items() if n not in ('constructor-profile.json','validation.json')})


def construct(rust_parent,llvm_source,output,profile_sha):
    rust_parent,llvm_source,output=map(fs.absolute,(rust_parent,llvm_source,output));raw=fs.read(HERE/'constructor-profile.json')[0]
    fs.need(fs.pin(raw)['sha256']==profile_sha,'external whole successor profile SHA required');p=json.loads(raw)
    fs.need(p['parent']==PARENT and p['llvm']==LLVM and p['actual']==ACTUAL and p['constructor_files']==inputs(),'whole reviewed constructor closure')
    fs.need(not any(output.is_relative_to(path) or path.is_relative_to(output) for path in (rust_parent,llvm_source,HERE)),'fresh disjoint Source output')
    files=render(capture(rust_parent,PARENT),capture(llvm_source,LLVM));fs.need(fs.tree(files)==p['tree'] and fs.pin(files['source-map.json'][0])['sha256']==p['map_sha256'],'exact reviewed Source successor')
    fs.publish(files,output);return dict(status='CONSTRUCTED_LLVM_V2_REJOIN_DATA_ONLY',files=len(files),bytes=sum(len(raw) for raw,_ in files.values()),tree=fs.tree(files),map=fs.pin(files['source-map.json'][0]),actual=ACTUAL,llvm_runtime=p['llvm_runtime'],native='NOT_RUN')


if __name__=='__main__':
    resource.setrlimit(resource.RLIMIT_AS,(512*1024**2,)*2);p=argparse.ArgumentParser(description=__doc__)
    for n in ('rust-parent','llvm-source','output'):p.add_argument('--'+n,required=True,type=Path)
    p.add_argument('--profile-sha256',required=True);a=p.parse_args();print(json.dumps(construct(a.rust_parent,a.llvm_source,a.output,a.profile_sha256),sort_keys=True))

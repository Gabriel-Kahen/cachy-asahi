#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Construct finite prospective Rust Source DATA; never import candidate code."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import resource

HERE=Path(__file__).resolve().parent
FS_SHA='7c7b8ce846603d76da1db7de58573fa76642871aae7082fa36b32a54856585d7'
if hashlib.sha256((HERE/'filesystem.py').read_bytes()).hexdigest()!=FS_SHA:raise ValueError('held filesystem DATA helper changed')
spec=importlib.util.spec_from_file_location('rust_source_fs',HERE/'filesystem.py');fs=importlib.util.module_from_spec(spec);spec.loader.exec_module(fs)
fs.MAX_FILES=384
OPERATION='rust199-source-reference-native-v1'
ACTUAL=dict.fromkeys(('source','ref','run','job','approval','artifact','image'))
CANDIDATE='dd6871d566661c4fe9eba055ae19e1e017e0b69d'
NAMES={'.SRCINFO','LICENSE.packaging','PKGBUILD','README.md','admission.example.json','bootstrap.toml','inputs.json','reference.py','test_reference.py'}


def encode(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def recipe(raw):
    result=raw;changes=[]
    for phase in ('prepare','build','package'):
        old=f'  python -I "$srcdir/reference.py" {phase} --work "$srcdir"'+(' --destination "$pkgdir"' if phase=='package' else '')+' || return'
        new=f'  /usr/bin/python -I -B /source/actor/entry.py {phase} || return'
        fs.need(result.count(old.encode())==1,'exact dd6871d5 recipe seam: '+phase)
        result=result.replace(old.encode(),new.encode());changes.append(dict(before=old,after=new,count=1))
    inverse=result
    for row in reversed(changes):inverse=inverse.replace(row['after'].encode(),row['before'].encode())
    fs.need(inverse==raw,'native recipe literal inverse')
    return result,changes


def render(frozen):
    deriv=json.loads((HERE/'derivation.json').read_bytes());before=fs.snapshot(frozen)
    source_map=before.pop('source-map.json')
    fs.need(fs.pin(source_map[0])['sha256']==deriv['frozen_source_map_sha256'] and source_map[1]==0o644,'exact LLVM Source DATA map')
    fs.need(fs.descriptors(before)==json.loads(source_map[0])['files'],'complete retained LLVM Source byte/mode/membership join')
    before['source-map.json']=source_map
    fs.need(fs.tree(before)==deriv['frozen_source_tree'],'exact retained LLVM Source tree')
    original={n:v for n,v in before.items() if n.startswith('original/')}
    fs.need(len(original)==200,'exact original200 dependency/signature/bootstrap Source')
    candidate=fs.snapshot(HERE/'candidate');intake=fs.snapshot(HERE/'intake')
    fs.need(set(candidate)==NAMES and fs.descriptors(candidate)==deriv['candidate_files'],'exact nine-file dd6871d5 snapshot')
    fs.need(fs.descriptors(intake)==deriv['intake_files'],'whole retained stage0 intake bytes/modes/membership')
    cp=json.loads(candidate['inputs.json'][0]);pins=json.loads(intake['evidence-pins.json'][0])
    for name,digest in pins.items():fs.need(fs.pin(intake[name][0])['sha256']==digest,'retained stage0 evidence changed: '+name)
    fs.need(not any(n.endswith(('.tar.xz','.pkg.tar.zst')) or '/work/' in '/'+n for n in intake),'no opaque archives in Source DATA')
    files=dict(original)
    files.update({'packages/port/rust199-source-reference/'+n:v for n,v in candidate.items()})
    files.update({'stage0-intake/'+n:v for n,v in intake.items()})
    for n,v in fs.snapshot(HERE/'payload').items():
        if not Path(n).name.startswith('test_'):files[n]=v
    for name in ('admission.py','policy.json','root-admission.TEMPLATE.json','expected349.lock','LICENSE','derivation.json','filesystem.py','builder-audit.json'):
        files[name]=fs.read(HERE/name)
    effective,seams=recipe(candidate['PKGBUILD'][0]);files['recipe/PKGBUILD']=(effective,0o644)
    files['recipe-derivation.json']=(encode(dict(schema=1,candidate_commit=CANDIDATE,changes=seams,before=fs.pin(candidate['PKGBUILD'][0]),after=fs.pin(effective),inverse='REPLACE_EXACT_THREE_NATIVE_HOOKS_RESTORES_ORIGINAL_RECIPE_BYTES',other_changes=[])),0o644)
    files['candidate-map.json']=(encode(dict(schema=1,commit=CANDIDATE,files=fs.descriptors(candidate))),0o644)
    files['contract.json']=(encode(dict(schema=1,operation=OPERATION,candidate=dict(commit=CANDIDATE,files=fs.descriptors(candidate)),stage0_intake=dict(files=fs.descriptors(intake),runtime_qualified=False,archive_bytes=108298076,signature_authentication='NOT_PERFORMED_TLS_AND_HASH_ONLY',candidate_join='SAME_THREE_ARCHIVE_PINS_ONLY_NOT_QUALIFICATION_OF_DD6871D5'),holds=cp['holds'],actual=ACTUAL)),0o644)
    workflow=(HERE/'workflow.yml.in').read_bytes().replace(b'__ENTRY_SHA__',fs.pin(files['hosted/entry.py'][0])['sha256'].encode())
    fs.need(b'__ENTRY_SHA__' not in workflow,'resolved workflow entry gate')
    for name in ('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-rust199-source-reference-v1.yml'):files[name]=(workflow,0o644)
    inverse=dict(schema=1,held=fs.descriptors(original),before_tree=fs.tree(original),additions=sorted(set(files)-set(original)|{'inverse.json','source-map.json'}),actual=ACTUAL)
    files['inverse.json']=(encode(inverse),0o644)
    undone={n:v for n,v in files.items() if n not in inverse['additions']}
    fs.need(fs.descriptors(undone)==inverse['held'] and fs.tree(undone)==inverse['before_tree'],'full original200 byte/mode inverse')
    files['source-map.json']=(encode(dict(schema=1,operation=OPERATION,actual=ACTUAL,files=fs.descriptors(files))),0o644)
    fs.need(len(files)<=384 and sum(len(raw) for raw,_ in files.values())<=96*1024**2,'finite Git-safe Source DATA budget')
    return files


def profile_inputs():
    files={}
    for name in ('candidate','intake','payload'):
        files.update({name+'/'+n:v for n,v in fs.snapshot(HERE/name).items()})
    for name in ('prepare.py','filesystem.py','admission.py','policy.json','root-admission.TEMPLATE.json','derivation.json','expected349.lock','workflow.yml.in','LICENSE','builder-audit.json'):
        files[name]=fs.read(HERE/name)
    return fs.descriptors(files)


def construct(frozen,output,profile_sha):
    frozen,output=map(fs.absolute,(frozen,output));raw=fs.read(HERE/'constructor-profile.json')[0]
    fs.need(fs.pin(raw)['sha256']==profile_sha,'external reviewed constructor-profile SHA required')
    p=json.loads(raw);fs.need(p['constructor_files']==profile_inputs() and p['actual']==ACTUAL,'all frozen constructor bytes/modes/membership')
    fs.need(str(frozen)==p['frozen_source'],'exact retained Source operand')
    fs.need(not any(output.is_relative_to(q) or q.is_relative_to(output) for q in (frozen,HERE)),'fresh disjoint Source output')
    files=render(frozen)
    fs.need(fs.tree(files)==p['prospective_tree'] and fs.pin(files['source-map.json'][0])['sha256']==p['map_sha256'],'whole reviewed Source result')
    fs.publish(files,output)
    return dict(status='CONSTRUCTED_SOURCE_DATA_ONLY',files=len(files),bytes=sum(len(raw) for raw,_ in files.values()),prospective_tree=fs.tree(files),source_map=fs.pin(files['source-map.json'][0]),actual=ACTUAL,native='NOT_RUN',stage0='NOT_RUN',installation='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')


if __name__=='__main__':
    resource.setrlimit(resource.RLIMIT_AS,(512*1024**2,512*1024**2))
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--frozen-source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--profile-sha256',required=True)
    a=p.parse_args();print(json.dumps(construct(a.frozen_source,a.output,a.profile_sha256),sort_keys=True))

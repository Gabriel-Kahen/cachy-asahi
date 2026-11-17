#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite diagnostic-only Source rebind over the exact retained Source179."""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

HERE=Path(__file__).resolve().parent
FAMILY='scripts/ci/first-login-enrollment-native-source'
PREFIX=FAMILY+'/successor_v5_source'
OLD_PROGRAM=FAMILY+'/successor_v4_source/program.json'
PROVENANCE='provenance/v5'
SOURCE179=dict(files=179,bytes=45330627,tree='5128864b3c17f230d5045361014b41ce31b72767',
    source_map=dict(bytes=35107,sha256='063a34c64d9e9ad21e6c2bd5c4e0a147f88890061cd79fb13587bc1e37e9d7f4'))
HELPERS={'successor_v4_source/prepare.py':dict(bytes=36564,sha256='72ab4cd782f4bb2376a4fbc8642b4e783b56f2663685b87e4727eae1efbb78df'),
    'prepare.py':dict(bytes=15159,sha256='f0c9d7aaaad08ab78130aae3fb4b3e6b1856173f6b5c8e3ee83163d8b5ede395')}
REPLACEMENTS={
    'hosted_launcher':dict(member=FAMILY+'/payload/native/hosted_current_v3.py',bytes=66059,sha256='5685fa9149242fd878ce81ddbe4368a0f6317de71c654962311de4fdb631fa14'),
    'material_domain_executor':dict(member=FAMILY+'/payload/native/material_domain_current_v3.py',bytes=40975,sha256='da8e397a63e02c11758d08bf2c45ecf14d94029f6311f4fcb4a09ad420624c8b'),
    'materials_stager':dict(member=FAMILY+'/payload/native/stage_materials_current_v3_python_v1.py',bytes=35550,sha256='58c5d0842c17a914239b5f24e9e1ac2987ad8ec9ce9e2a03e63a04f2e2e99282')}


def load_helpers():
    modules=[]
    for name,wanted in HELPERS.items():
        path=HERE.parent/name
        if path!=path.resolve()or path.is_symlink()or path.stat().st_nlink!=1:raise ValueError('ordinary maintained DATA helper')
        raw=path.read_bytes()
        if dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())!=wanted:raise ValueError('whole maintained DATA helper')
        spec=importlib.util.spec_from_file_location('diagnostic_v5_'+str(len(modules)),path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);modules.append(module)
    V4,H=modules;P=V4.load_v3()
    return V4,P,P.C,H


def validate_basis(files):
    V4,P,C,H=load_helpers()
    C.need(len(files)==SOURCE179['files']and sum(len(v[0])for v in files.values())==SOURCE179['bytes']
        and H.tree(files)==SOURCE179['tree'],'exact complete Source179 namespace/body/mode')
    raw,mode=files['source-map.json'];C.need(mode==0o644 and files['source.lock.json']==(raw,mode)
        and C.pin(raw)==SOURCE179['source_map'],'exact Source179 map aliases')
    source=C.decode(raw);C.need(source['files']==C.descriptors({n:v for n,v in files.items()if n not in('source-map.json','source.lock.json')})
        and all(v is None for v in source['actual'].values()),'complete unissued Source179 map')
    original=V4.inverse_v3(files)
    C.need(len(original)==V4.SOURCE139['files']and sum(len(v[0])for v in original.values())==V4.SOURCE139['bytes']
        and C.pin(original['source-map.json'][0])==dict(bytes=V4.SOURCE139['map_bytes'],sha256=V4.SOURCE139['map_sha256']),
        'complete exact original139 inverse')


def load_basis(root):
    V4,P,C,H=load_helpers();source,_=C.source(root,SOURCE179['source_map']['sha256'])
    rows=dict(source['files']);rows.update({n:dict(SOURCE179['source_map'],mode=0o644)for n in('source-map.json','source.lock.json')})
    files={n:C.read(Path(root)/n,row)for n,row in rows.items()}
    validate_basis(files);return files


def inverse_v4(files):
    V4,P,C,H=load_helpers();value=C.decode(files[PREFIX+'/inverse.json'][0])
    C.need(set(value)=={'schema','kind','basis','remove','restore','actual_acceptance'}and type(value['schema'])is int
        and value['schema']==5 and value['kind']=='DIAGNOSTIC_SOURCE_V5_TO_SOURCE179_INVERSE_DATA_ONLY'
        and value['basis']==SOURCE179 and value['actual_acceptance']is None,'fixed Source179 inverse schema')
    original=files[PROVENANCE+'/source179-map.json'];C.need(original[1]==0o644 and C.pin(original[0])==SOURCE179['source_map'],'retained Source179 map')
    expected=C.decode(original[0])['files'];added=set(files)-set(expected)-{'source-map.json','source.lock.json'}
    wanted={PROVENANCE+'/source179-map.json',PROVENANCE+'/rebind.json',*(PREFIX+'/'+n for n in('program.json','inverse.json','prepare.py','README.md')),
        *(PROVENANCE+'/original/'+row['member']for row in REPLACEMENTS.values())}
    C.need(type(value['remove'])is list and len(set(value['remove']))==len(value['remove'])and set(value['remove'])==added==wanted,'exact inverse additions')
    result={n:v for n,v in files.items()if n not in added and n not in('source-map.json','source.lock.json')}
    C.need(set(value['restore'])=={v['member']for v in REPLACEMENTS.values()},'exact three original body restorations')
    for name,backup in value['restore'].items():
        C.need(backup==PROVENANCE+'/original/'+name and dict(C.pin(files[backup][0]),mode=files[backup][1])==expected[name],
            'whole original replacement body/mode')
        result[name]=files[backup]
    C.need(C.descriptors(result)==expected,'full Source179 inverse namespace/body/mode')
    result['source-map.json']=result['source.lock.json']=original
    validate_basis(result);return result


def inverse_v3(files):return load_helpers()[0].inverse_v3(inverse_v4(files))


def rebind(files,replacements,*,commit,constructor_files):
    """Pure finite transformation; assemble supplies verified committed operands."""
    V4,P,C,H=load_helpers();validate_basis(files)
    C.need(type(commit)is str and re.fullmatch('[0-9a-f]{40}',commit),'full actual reviewed code revision')
    C.need(type(replacements)is dict and set(replacements)==set(REPLACEMENTS),'exact diagnostic replacement roles')
    C.need(type(constructor_files)is dict and set(constructor_files)=={'prepare.py','README.md'},'finite construction closure')
    for role,row in REPLACEMENTS.items():
        raw,mode=replacements[role];C.need(type(raw)is bytes and type(mode)is int and mode==0o644
            and C.pin(raw)=={k:row[k]for k in('bytes','sha256')},'exact committed diagnostic body: '+role)
    for raw,mode in constructor_files.values():C.need(type(raw)is bytes and 0<len(raw)<=C.MAX_FILE and type(mode)is int and mode==0o644,'ordinary finite construction member')
    result=dict(files);old=C.decode(files[OLD_PROGRAM][0]);registry=copy.deepcopy(old)
    C.need(len(old['roles'])==27 and len(old['delegation_programs'])==25 and len(old['staging_materials'])==5
        and all(v is None for v in old['actual'].values()),'unchanged unissued27-role/25-program staging registry')
    changes={};added={PROVENANCE+'/source179-map.json':files['source-map.json']}
    for role,row in REPLACEMENTS.items():
        name=row['member'];C.need(old['roles'][role]['member']==name and name in files,'same original operational role member')
        backup=PROVENANCE+'/original/'+name;added[backup]=files[name];result[name]=replacements[role]
        registry['roles'][role]=dict(row)
        changes[role]=dict(member=name,original=dict(C.pin(files[name][0]),mode=files[name][1]),replacement=dict(C.pin(result[name][0]),mode=result[name][1]),original_member=backup)
    provenance=dict(schema=5,kind='COMMITTED_SOURCE179_DIAGNOSTIC_REBIND_V5',operation=V4.OP,basis=SOURCE179,
        diagnostics_commit=commit,replacements=changes,construction={PREFIX+'/'+n:dict(C.pin(v[0]),mode=v[1])for n,v in constructor_files.items()},actual=dict.fromkeys(V4.ACTUAL))
    added[PROVENANCE+'/rebind.json']=(V4.encode(provenance),0o644)
    registry.update(schema=5,kind='DELEGATED_CURRENT_DIAGNOSTIC_PROGRAM_REGISTRY_V5',basis_closure_commit=registry.pop('closure_commit'),
        diagnostics_commit=commit,rebind_provenance=dict(member=PROVENANCE+'/rebind.json',**C.pin(added[PROVENANCE+'/rebind.json'][0])))
    registry['delegation_programs']=V4.delegation_programs(registry['roles'],result)
    C.need(len(registry['delegation_programs'])==25,'same25 canonical programs')
    added[PREFIX+'/program.json']=(V4.encode(registry),0o644)
    for name,value in constructor_files.items():added[PREFIX+'/'+name]=value
    inverse=PREFIX+'/inverse.json'
    added[inverse]=(V4.encode(dict(schema=5,kind='DIAGNOSTIC_SOURCE_V5_TO_SOURCE179_INVERSE_DATA_ONLY',basis=SOURCE179,
        remove=sorted([*added,inverse]),restore={v['member']:PROVENANCE+'/original/'+v['member']for v in REPLACEMENTS.values()},actual_acceptance=None)),0o644)
    C.need(not set(added)&set(result),'no new metadata collision or adoption');result.update(added)
    source=C.decode(files['source-map.json'][0]);source['files']=C.descriptors({n:v for n,v in result.items()if n not in('source-map.json','source.lock.json')})
    result['source-map.json']=result['source.lock.json']=(V4.encode(source),0o644)
    C.need(len(result)<=C.MAX_FILES and sum(len(v[0])for v in result.values())<=C.MAX_TOTAL
        and all(0<len(v[0])<=C.MAX_FILE and v[1]in(0o644,0o755)for v in result.values()),'unchanged complete Source caps')
    C.need(inverse_v4(result)==files,'complete original179 byte/mode inverse')
    original139=inverse_v3(result)
    profile=dict(schema=5,kind='UNISSUED_CURRENT_ONBOARDING_DIAGNOSTIC_SOURCE_PROFILE_V5',operation=V4.OP,
        files=len(result),bytes=sum(len(v[0])for v in result.values()),prospective_tree=H.tree(result),source_map=C.pin(result['source-map.json'][0]),
        program=dict(path=PREFIX+'/program.json',**C.pin(added[PREFIX+'/program.json'][0])),delegation_programs=registry['delegation_programs'],
        staging_materials=registry['staging_materials'],materials=C.decode(result['inputs/delegated-materials-v4.json'][0])['materials'],
        diagnostics_commit=commit,source179_basis=SOURCE179,original139=dict(files=len(original139),bytes=sum(len(v[0])for v in original139.values()),
            source_map=C.pin(original139['source-map.json'][0]),tree=H.tree(original139)),actual=dict.fromkeys((*V4.ACTUAL,'artifact','Reader','Root_acceptance')))
    C.need(len(profile['materials'])+len(profile['staging_materials'])==64,'same59+5 materials')
    return result,profile


def assemble(repo,basis_root,revision):
    V4,P,C,H=load_helpers();P.commit(repo,revision);files=load_basis(basis_root)
    replacements={role:P.blob(repo,revision,row['member'],dict(bytes=row['bytes'],sha256=row['sha256'],mode=0o644))for role,row in REPLACEMENTS.items()}
    construction={name:P.blob(repo,revision,PREFIX+'/'+name)for name in('prepare.py','README.md')}
    for name,value in construction.items():C.need(value==C.read(HERE/name),'executing construction closure is committed at selected revision')
    return rebind(files,replacements,commit=revision,constructor_files=construction)


def main():
    V4,P,C,H=load_helpers();C.need(sys.flags.isolated and sys.dont_write_bytecode and __debug__,'isolated unoptimized DATA constructor')
    parser=argparse.ArgumentParser(description=__doc__)
    for name in('repo','basis','output'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--revision',required=True);args=parser.parse_args()
    files,profile=assemble(args.repo,args.basis,args.revision);P.publish(files,args.output)
    print(json.dumps(profile,sort_keys=True,indent=2))


if __name__=='__main__':main()

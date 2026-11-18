#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite written-span capture rebind over the exact retained Source188."""
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
PREFIX=FAMILY+'/successor_v6_source'
OLD_PROGRAM=FAMILY+'/successor_v5_source/program.json'
PROVENANCE='provenance/v6'
SOURCE188=dict(files=188,bytes=45544942,tree='50bf7aab34ee5497f12d078709354aa69b0cdb9d',
    source_map=dict(bytes=37091,sha256='ba06925244cd010ab2223325e2e324d4d3b469befbea5e7eb8e0de68383d4908'))
V5_PIN=dict(bytes=11245,sha256='91ac3c40014b5752d936fb5247d28a20b73ba0e5a1499615af11b47eb544909c')
REPLACEMENTS={
    'hosted_launcher':dict(member=FAMILY+'/payload/native/hosted_current_v3.py',bytes=66263,sha256='f8387c748f31698b45656998248f099a8207bb58f7f9d7e70ef53a73be286d97'),
    'material_domain_executor':dict(member=FAMILY+'/payload/native/material_domain_current_v3.py',bytes=42462,sha256='ead51cfa3bcf4b74fbccc8c469926c71fbb72edefcf9525b297e1737fde3ab8f')}


def load_helpers():
    path=HERE.parent/'successor_v5_source/prepare.py'
    if path!=path.resolve()or path.is_symlink()or path.stat().st_nlink!=1:raise ValueError('ordinary maintained v5 helper')
    raw=path.read_bytes()
    if dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())!=V5_PIN:raise ValueError('whole unchanged v5 constructor')
    spec=importlib.util.spec_from_file_location('capture_v6_basis_v5',path)
    V5=importlib.util.module_from_spec(spec);spec.loader.exec_module(V5)
    V4,P,C,H=V5.load_helpers()
    return V5,V4,P,C,H


def validate_basis(files):
    V5,V4,P,C,H=load_helpers()
    C.need(len(files)==SOURCE188['files']and sum(len(v[0])for v in files.values())==SOURCE188['bytes']
        and H.tree(files)==SOURCE188['tree'],'exact complete Source188 namespace/body/mode')
    raw,mode=files['source-map.json'];C.need(mode==0o644 and files['source.lock.json']==(raw,mode)
        and C.pin(raw)==SOURCE188['source_map'],'exact Source188 map aliases')
    source=C.decode(raw);C.need(source['files']==C.descriptors({n:v for n,v in files.items()if n not in('source-map.json','source.lock.json')})
        and all(v is None for v in source['actual'].values()),'complete unissued Source188 map')
    original=V5.inverse_v4(files)
    C.need(len(original)==V5.SOURCE179['files']and H.tree(original)==V5.SOURCE179['tree'],'complete exact Source179 inverse')
    V5.inverse_v3(files)


def load_basis(root):
    V5,V4,P,C,H=load_helpers();source,_=C.source(root,SOURCE188['source_map']['sha256'])
    rows=dict(source['files']);rows.update({n:dict(SOURCE188['source_map'],mode=0o644)for n in('source-map.json','source.lock.json')})
    files={n:C.read(Path(root)/n,row)for n,row in rows.items()}
    validate_basis(files);return files


def inverse_v5(files):
    V5,V4,P,C,H=load_helpers();value=C.decode(files[PREFIX+'/inverse.json'][0])
    C.need(set(value)=={'schema','kind','basis','remove','restore','actual_acceptance'}and type(value['schema'])is int
        and value['schema']==6 and value['kind']=='CAPTURE_SOURCE_V6_TO_SOURCE188_INVERSE_DATA_ONLY'
        and value['basis']==SOURCE188 and value['actual_acceptance']is None,'fixed Source188 inverse schema')
    original=files[PROVENANCE+'/source188-map.json'];C.need(original[1]==0o644 and C.pin(original[0])==SOURCE188['source_map'],'retained Source188 map')
    expected=C.decode(original[0])['files'];added=set(files)-set(expected)-{'source-map.json','source.lock.json'}
    wanted={PROVENANCE+'/source188-map.json',PROVENANCE+'/rebind.json',*(PREFIX+'/'+n for n in('program.json','inverse.json','prepare.py','README.md')),
        *(PROVENANCE+'/original/'+row['member']for row in REPLACEMENTS.values())}
    C.need(type(value['remove'])is list and len(set(value['remove']))==len(value['remove'])and set(value['remove'])==added==wanted,'exact inverse additions')
    result={n:v for n,v in files.items()if n not in added and n not in('source-map.json','source.lock.json')}
    C.need(set(value['restore'])=={v['member']for v in REPLACEMENTS.values()},'exact two original body restorations')
    for name,backup in value['restore'].items():
        C.need(backup==PROVENANCE+'/original/'+name and dict(C.pin(files[backup][0]),mode=files[backup][1])==expected[name],
            'whole original replacement body/mode')
        result[name]=files[backup]
    C.need(C.descriptors(result)==expected,'full Source188 inverse namespace/body/mode')
    result['source-map.json']=result['source.lock.json']=original
    validate_basis(result);return result


def inverse_v4(files):return load_helpers()[0].inverse_v4(inverse_v5(files))
def inverse_v3(files):return load_helpers()[0].inverse_v3(inverse_v5(files))


def rebind(files,replacements,*,commit,constructor_files):
    """Pure finite transformation; assemble supplies verified committed operands."""
    V5,V4,P,C,H=load_helpers();validate_basis(files)
    C.need(type(commit)is str and re.fullmatch('[0-9a-f]{40}',commit),'full actual reviewed code revision')
    C.need(type(replacements)is dict and set(replacements)==set(REPLACEMENTS),'exact capture replacement roles')
    C.need(type(constructor_files)is dict and set(constructor_files)=={'prepare.py','README.md'},'finite construction closure')
    for role,row in REPLACEMENTS.items():
        raw,mode=replacements[role];C.need(type(raw)is bytes and type(mode)is int and mode==0o644
            and C.pin(raw)=={k:row[k]for k in('bytes','sha256')},'exact committed capture body: '+role)
    for raw,mode in constructor_files.values():C.need(type(raw)is bytes and 0<len(raw)<=C.MAX_FILE and type(mode)is int and mode==0o644,'ordinary finite construction member')
    result=dict(files);old=C.decode(files[OLD_PROGRAM][0]);registry=copy.deepcopy(old)
    C.need(old['schema']==5 and old['kind']=='DELEGATED_CURRENT_DIAGNOSTIC_PROGRAM_REGISTRY_V5'
        and len(old['roles'])==27 and len(old['delegation_programs'])==25 and len(old['staging_materials'])==5
        and all(v is None for v in old['actual'].values()),'unchanged unissued Source188 schema5 registry')
    changes={};added={PROVENANCE+'/source188-map.json':files['source-map.json']}
    for role,row in REPLACEMENTS.items():
        name=row['member'];C.need(old['roles'][role]['member']==name and name in files,'same original operational role member')
        backup=PROVENANCE+'/original/'+name;added[backup]=files[name];result[name]=replacements[role]
        registry['roles'][role]=dict(row)
        changes[role]=dict(member=name,original=dict(C.pin(files[name][0]),mode=files[name][1]),replacement=dict(C.pin(result[name][0]),mode=result[name][1]),original_member=backup)
    provenance=dict(schema=6,kind='COMMITTED_SOURCE188_WRITTEN_SPAN_CAPTURE_REBIND_V6',operation=V4.OP,basis=SOURCE188,
        capture_commit=commit,replacements=changes,construction={PREFIX+'/'+n:dict(C.pin(v[0]),mode=v[1])for n,v in constructor_files.items()},actual=dict.fromkeys(V4.ACTUAL))
    added[PROVENANCE+'/rebind.json']=(V4.encode(provenance),0o644)
    registry.update(schema=6,kind='DELEGATED_CURRENT_CAPTURE_PROGRAM_REGISTRY_V6',capture_commit=commit,
        capture_rebind_provenance=dict(member=PROVENANCE+'/rebind.json',**C.pin(added[PROVENANCE+'/rebind.json'][0])))
    registry['delegation_programs']=V4.delegation_programs(registry['roles'],result)
    C.need(len(registry['delegation_programs'])==25,'same25 canonical programs')
    added[PREFIX+'/program.json']=(V4.encode(registry),0o644)
    for name,value in constructor_files.items():added[PREFIX+'/'+name]=value
    inverse=PREFIX+'/inverse.json'
    added[inverse]=(V4.encode(dict(schema=6,kind='CAPTURE_SOURCE_V6_TO_SOURCE188_INVERSE_DATA_ONLY',basis=SOURCE188,
        remove=sorted([*added,inverse]),restore={v['member']:PROVENANCE+'/original/'+v['member']for v in REPLACEMENTS.values()},actual_acceptance=None)),0o644)
    C.need(not set(added)&set(result),'no new metadata collision or adoption');result.update(added)
    source=C.decode(files['source-map.json'][0]);source['files']=C.descriptors({n:v for n,v in result.items()if n not in('source-map.json','source.lock.json')})
    result['source-map.json']=result['source.lock.json']=(V4.encode(source),0o644)
    C.need(len(result)<=C.MAX_FILES and sum(len(v[0])for v in result.values())<=C.MAX_TOTAL
        and all(0<len(v[0])<=C.MAX_FILE and v[1]in(0o644,0o755)for v in result.values()),'unchanged complete Source caps')
    C.need(inverse_v5(result)==files,'complete original188 byte/mode inverse')
    original139=inverse_v3(result)
    profile=dict(schema=6,kind='UNISSUED_CURRENT_ONBOARDING_CAPTURE_SOURCE_PROFILE_V6',operation=V4.OP,
        files=len(result),bytes=sum(len(v[0])for v in result.values()),prospective_tree=H.tree(result),source_map=C.pin(result['source-map.json'][0]),
        program=dict(path=PREFIX+'/program.json',**C.pin(added[PREFIX+'/program.json'][0])),delegation_programs=registry['delegation_programs'],
        staging_materials=registry['staging_materials'],materials=C.decode(result['inputs/delegated-materials-v4.json'][0])['materials'],
        capture_commit=commit,source188_basis=SOURCE188,source179_basis=V5.SOURCE179,
        original139=dict(files=len(original139),bytes=sum(len(v[0])for v in original139.values()),
            source_map=C.pin(original139['source-map.json'][0]),tree=H.tree(original139)),actual=dict.fromkeys((*V4.ACTUAL,'artifact','Reader','Root_acceptance')))
    C.need(len(profile['materials'])+len(profile['staging_materials'])==64,'same59+5 materials')
    return result,profile


def assemble(repo,basis_root,revision):
    V5,V4,P,C,H=load_helpers();P.commit(repo,revision);files=load_basis(basis_root)
    replacements={role:P.blob(repo,revision,row['member'],dict(bytes=row['bytes'],sha256=row['sha256'],mode=0o644))for role,row in REPLACEMENTS.items()}
    construction={name:P.blob(repo,revision,PREFIX+'/'+name)for name in('prepare.py','README.md')}
    for name,value in construction.items():C.need(value==C.read(HERE/name),'executing construction closure is committed at selected revision')
    return rebind(files,replacements,commit=revision,constructor_files=construction)


def main():
    V5,V4,P,C,H=load_helpers();C.need(sys.flags.isolated and sys.dont_write_bytecode and __debug__,'isolated unoptimized DATA constructor')
    parser=argparse.ArgumentParser(description=__doc__)
    for name in('repo','basis','output'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--revision',required=True);args=parser.parse_args()
    files,profile=assemble(args.repo,args.basis,args.revision);P.publish(files,args.output)
    print(json.dumps(profile,sort_keys=True,indent=2))


if __name__=='__main__':main()

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite nested-transport diagnostic rebind over exact retained Source196."""
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
PREFIX=FAMILY+'/successor_v7_source'
OLD_PROGRAM=FAMILY+'/successor_v6_source/program.json'
PROVENANCE='provenance/v7'
SOURCE196=dict(files=196,bytes=45726789,tree='e85302474308dbf579b79bd6d501f5ad86b66bbb',
    source_map=dict(bytes=38809,sha256='a8f5ab1c1ceee9f3450634e14dd172d7421d6fe49d8e17ce680cb4cfe43da86a'))
V6_PIN=dict(bytes=10836,sha256='4cc618d1259732bd83013d012d600b913a330a6233e82f33c5803a4d72637138')
REPLACEMENTS={
    'materials_stager':dict(member=FAMILY+'/payload/native/stage_materials_current_v3_python_v1.py',bytes=43592,sha256='3ddfdb3f1981f154348ab67e051cec0ea2bedda04dbb3596a9b285797662ef51'),
    'material_domain_executor':dict(member=FAMILY+'/payload/native/material_domain_current_v3.py',bytes=44646,sha256='2df9c12d402e86187cd11e4b35e957b562dd2ccfc7c5229e21fc4d7d97e2e17f'),
    'hosted_launcher':dict(member=FAMILY+'/payload/native/hosted_current_v3.py',bytes=68455,sha256='e6e8fdadc7dd125649a6c9f1bb393fed8a033bda0b8512f2f5c250345e54743f')}
OPERANDS={role:PREFIX+'/payload/'+name for role,name in (
    ('materials_stager','stager.py'),('material_domain_executor','material_domain.py'),('hosted_launcher','hosted.py'))}


def load_helpers():
    path=HERE.parent/'successor_v6_source/prepare.py'
    if path!=path.resolve()or path.is_symlink()or path.stat().st_nlink!=1:raise ValueError('ordinary maintained v6 helper')
    raw=path.read_bytes()
    if dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())!=V6_PIN:raise ValueError('whole unchanged v6 constructor')
    spec=importlib.util.spec_from_file_location('transport_v7_basis_v6',path)
    V6=importlib.util.module_from_spec(spec);spec.loader.exec_module(V6)
    V5,V4,P,C,H=V6.load_helpers()
    return V6,V5,V4,P,C,H


def validate_basis(files):
    V6,V5,V4,P,C,H=load_helpers()
    C.need(len(files)==SOURCE196['files']and sum(len(v[0])for v in files.values())==SOURCE196['bytes']
        and H.tree(files)==SOURCE196['tree'],'exact complete Source196 namespace/body/mode')
    raw,mode=files['source-map.json'];C.need(mode==0o644 and files['source.lock.json']==(raw,mode)
        and C.pin(raw)==SOURCE196['source_map'],'exact Source196 map aliases')
    source=C.decode(raw);C.need(source['files']==C.descriptors({n:v for n,v in files.items()if n not in('source-map.json','source.lock.json')})
        and all(v is None for v in source['actual'].values()),'complete unissued Source196 map')
    original=V6.inverse_v5(files)
    C.need(len(original)==V6.SOURCE188['files']and sum(len(v[0])for v in original.values())==V6.SOURCE188['bytes']
        and H.tree(original)==V6.SOURCE188['tree'],'complete exact Source188 inverse')
    V6.inverse_v4(files);V6.inverse_v3(files)


def load_basis(root):
    V6,V5,V4,P,C,H=load_helpers();source,_=C.source(root,SOURCE196['source_map']['sha256'])
    rows=dict(source['files']);rows.update({n:dict(SOURCE196['source_map'],mode=0o644)for n in('source-map.json','source.lock.json')})
    files={n:C.read(Path(root)/n,row)for n,row in rows.items()}
    validate_basis(files);return files


def inverse_v6(files):
    V6,V5,V4,P,C,H=load_helpers();value=C.decode(files[PREFIX+'/inverse.json'][0])
    C.need(set(value)=={'schema','kind','basis','remove','restore','actual_acceptance'}and type(value['schema'])is int
        and value['schema']==7 and value['kind']=='TRANSPORT_SOURCE_V7_TO_SOURCE196_INVERSE_DATA_ONLY'
        and value['basis']==SOURCE196 and value['actual_acceptance']is None,'fixed Source196 inverse schema')
    original=files[PROVENANCE+'/source196-map.json'];C.need(original[1]==0o644 and C.pin(original[0])==SOURCE196['source_map'],'retained Source196 map')
    expected=C.decode(original[0])['files'];added=set(files)-set(expected)-{'source-map.json','source.lock.json'}
    wanted={PROVENANCE+'/source196-map.json',PROVENANCE+'/rebind.json',*(PREFIX+'/'+n for n in('program.json','inverse.json','prepare.py','README.md')),
        *(PROVENANCE+'/original/'+row['member']for row in REPLACEMENTS.values())}
    C.need(type(value['remove'])is list and len(set(value['remove']))==len(value['remove'])and set(value['remove'])==added==wanted,'exact inverse additions')
    result={n:v for n,v in files.items()if n not in added and n not in('source-map.json','source.lock.json')}
    C.need(set(value['restore'])=={v['member']for v in REPLACEMENTS.values()},'exact three original body restorations')
    for name,backup in value['restore'].items():
        C.need(backup==PROVENANCE+'/original/'+name and dict(C.pin(files[backup][0]),mode=files[backup][1])==expected[name],
            'whole original replacement body/mode')
        result[name]=files[backup]
    C.need(C.descriptors(result)==expected,'full Source196 inverse namespace/body/mode')
    result['source-map.json']=result['source.lock.json']=original
    validate_basis(result);return result


def inverse_v5(files):return load_helpers()[0].inverse_v5(inverse_v6(files))
def inverse_v4(files):return load_helpers()[0].inverse_v4(inverse_v6(files))
def inverse_v3(files):return load_helpers()[0].inverse_v3(inverse_v6(files))


def rebind(files,replacements,*,commit,constructor_files):
    """Pure finite transformation; assemble supplies verified committed operands."""
    V6,V5,V4,P,C,H=load_helpers();validate_basis(files)
    C.need(type(commit)is str and re.fullmatch('[0-9a-f]{40}',commit),'full actual reviewed code revision')
    C.need(type(replacements)is dict and set(replacements)==set(REPLACEMENTS),'exact transport diagnostic replacement roles')
    C.need(type(constructor_files)is dict and set(constructor_files)=={'prepare.py','README.md'},'finite construction closure')
    for role,row in REPLACEMENTS.items():
        raw,mode=replacements[role];C.need(type(raw)is bytes and type(mode)is int and mode==0o644
            and C.pin(raw)=={k:row[k]for k in('bytes','sha256')},'exact committed transport diagnostic body: '+role)
    for raw,mode in constructor_files.values():C.need(type(raw)is bytes and 0<len(raw)<=C.MAX_FILE and type(mode)is int and mode==0o644,'ordinary finite construction member')
    result=dict(files);old=C.decode(files[OLD_PROGRAM][0]);registry=copy.deepcopy(old)
    C.need(old['schema']==6 and old['kind']=='DELEGATED_CURRENT_CAPTURE_PROGRAM_REGISTRY_V6'
        and len(old['roles'])==27 and len(old['delegation_programs'])==25 and len(old['staging_materials'])==5
        and all(v is None for v in old['actual'].values()),'unchanged unissued Source196 schema6 registry')
    changes={};added={PROVENANCE+'/source196-map.json':files['source-map.json']}
    for role,row in REPLACEMENTS.items():
        name=row['member'];C.need(old['roles'][role]['member']==name and name in files,'same original operational role member')
        backup=PROVENANCE+'/original/'+name;added[backup]=files[name];result[name]=replacements[role]
        registry['roles'][role]=dict(row)
        changes[role]=dict(member=name,original=dict(C.pin(files[name][0]),mode=files[name][1]),replacement=dict(C.pin(result[name][0]),mode=result[name][1]),original_member=backup,operand=OPERANDS[role])
    provenance=dict(schema=7,kind='COMMITTED_SOURCE196_TRANSPORT_DIAGNOSTIC_REBIND_V7',operation=V4.OP,basis=SOURCE196,
        transport_commit=commit,replacements=changes,construction={PREFIX+'/'+n:dict(C.pin(v[0]),mode=v[1])for n,v in constructor_files.items()},actual=dict.fromkeys(V4.ACTUAL))
    added[PROVENANCE+'/rebind.json']=(V4.encode(provenance),0o644)
    registry.update(schema=7,kind='DELEGATED_CURRENT_TRANSPORT_PROGRAM_REGISTRY_V7',transport_commit=commit,
        transport_rebind_provenance=dict(member=PROVENANCE+'/rebind.json',**C.pin(added[PROVENANCE+'/rebind.json'][0])))
    registry['delegation_programs']=V4.delegation_programs(registry['roles'],result)
    C.need(len(registry['delegation_programs'])==25,'same25 canonical programs')
    added[PREFIX+'/program.json']=(V4.encode(registry),0o644)
    for name,value in constructor_files.items():added[PREFIX+'/'+name]=value
    inverse=PREFIX+'/inverse.json'
    added[inverse]=(V4.encode(dict(schema=7,kind='TRANSPORT_SOURCE_V7_TO_SOURCE196_INVERSE_DATA_ONLY',basis=SOURCE196,
        remove=sorted([*added,inverse]),restore={v['member']:PROVENANCE+'/original/'+v['member']for v in REPLACEMENTS.values()},actual_acceptance=None)),0o644)
    C.need(not set(added)&set(result),'no new metadata collision or adoption');result.update(added)
    source=C.decode(files['source-map.json'][0]);source['files']=C.descriptors({n:v for n,v in result.items()if n not in('source-map.json','source.lock.json')})
    result['source-map.json']=result['source.lock.json']=(V4.encode(source),0o644)
    C.need(len(result)<=C.MAX_FILES and sum(len(v[0])for v in result.values())<=C.MAX_TOTAL
        and all(0<len(v[0])<=C.MAX_FILE and v[1]in(0o644,0o755)for v in result.values()),'unchanged complete Source caps')
    C.need(inverse_v6(result)==files,'complete original196 byte/mode inverse')
    original139=inverse_v3(result)
    profile=dict(schema=7,kind='UNISSUED_CURRENT_ONBOARDING_TRANSPORT_SOURCE_PROFILE_V7',operation=V4.OP,
        files=len(result),bytes=sum(len(v[0])for v in result.values()),prospective_tree=H.tree(result),source_map=C.pin(result['source-map.json'][0]),
        program=dict(path=PREFIX+'/program.json',**C.pin(added[PREFIX+'/program.json'][0])),delegation_programs=registry['delegation_programs'],
        staging_materials=registry['staging_materials'],materials=C.decode(result['inputs/delegated-materials-v4.json'][0])['materials'],
        transport_commit=commit,source196_basis=SOURCE196,source188_basis=V6.SOURCE188,source179_basis=V5.SOURCE179,
        original139=dict(files=len(original139),bytes=sum(len(v[0])for v in original139.values()),
            source_map=C.pin(original139['source-map.json'][0]),tree=H.tree(original139)),actual=dict.fromkeys((*V4.ACTUAL,'artifact','Reader','Root_acceptance')))
    C.need(len(profile['materials'])+len(profile['staging_materials'])==64,'same59+5 materials')
    return result,profile


def assemble(repo,basis_root,revision):
    V6,V5,V4,P,C,H=load_helpers();P.commit(repo,revision);files=load_basis(basis_root)
    replacements={role:P.blob(repo,revision,OPERANDS[role],dict(bytes=row['bytes'],sha256=row['sha256'],mode=0o644))for role,row in REPLACEMENTS.items()}
    construction={name:P.blob(repo,revision,PREFIX+'/'+name)for name in('prepare.py','README.md')}
    for name,value in construction.items():C.need(value==C.read(HERE/name),'executing construction closure is committed at selected revision')
    return rebind(files,replacements,commit=revision,constructor_files=construction)


def main():
    V6,V5,V4,P,C,H=load_helpers();C.need(sys.flags.isolated and sys.dont_write_bytecode and __debug__,'isolated unoptimized DATA constructor')
    parser=argparse.ArgumentParser(description=__doc__)
    for name in('repo','basis','output'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--revision',required=True);args=parser.parse_args()
    files,profile=assemble(args.repo,args.basis,args.revision);P.publish(files,args.output)
    print(json.dumps(profile,sort_keys=True,indent=2))


if __name__=='__main__':main()

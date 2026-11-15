#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Finite Source DATA constructor. Never runs a build, container, acquisition or role."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import resource
import stat

HERE=Path(__file__).resolve().parent
ACTUAL=dict(source=None,ref=None,run=None,job=None,reader=None,authority=None,approval=None,artifact=None,image=None)
FS_SHA='7c7b8ce846603d76da1db7de58573fa76642871aae7082fa36b32a54856585d7'
if hashlib.sha256((HERE/'filesystem.py').read_bytes()).hexdigest()!=FS_SHA:raise ValueError('held DATA filesystem helper changed')
spec=importlib.util.spec_from_file_location('llvm23_source_filesystem',HERE/'filesystem.py');fs=importlib.util.module_from_spec(spec);spec.loader.exec_module(fs)


def encode(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def desc(files):return fs.descriptors(files)


def render(frozen,candidate,evidence):
    deriv=json.loads((HERE/'derivation.json').read_bytes())
    fs.MAX_FILES=320
    before=fs.snapshot(frozen);frozen_map=before['source-map.json'][0]
    fs.need(fs.pin(frozen_map)['sha256']==deriv['frozen_source_map_sha256'],'exact frozen Perl25dc Source map required')
    fs.need(desc({n:v for n,v in before.items() if n!='source-map.json'})==json.loads(frozen_map)['files'] and before['source-map.json'][1]==0o644,'complete frozen Source byte/mode/membership join')
    original={n.removeprefix('original/'):v for n,v in before.items() if n.startswith('original/')}
    fs.need(len(original)==200,'exact complete original200 dependency/signature/bootstrap source')
    candidate_rows={}
    for path in sorted(candidate.rglob('*')):
        if path.is_file() and '__pycache__' not in path.parts and path.name!='validation.json':
            relative=path.relative_to(candidate).as_posix();fs.relative(relative);candidate_rows[relative]=fs.read(path)
    fs.need(6<=len(candidate_rows)<=32,'finite LLVM candidate snapshot')
    pins=json.loads(candidate_rows['inputs.json'][0])
    for name,pin in pins['files'].items():fs.need(hashlib.sha256(candidate_rows[name][0]).hexdigest()==pin,'candidate file pin changed: '+name)
    actor=fs.snapshot(HERE/'payload/actor');actor={n:v for n,v in actor.items() if '__pycache__' not in n and not n.startswith('test_')}
    runtime_names=['PKGBUILD','reference.py','build.sh','inputs.json','admission.example.json','LICENSE.packaging']
    contract=dict(schema=1,mode='ROOTFUL_CONTAINER_NO_BWRAP_V1',operation='llvm23-source-reference-native-v1',source={k:pins['archive'][k] for k in ('bytes','sha256')},source_url=pins['archive']['url'],package_name='cachy-asahi-llvm23-source-reference-23.1.1-1-aarch64.pkg.tar.zst',candidate_files={k:desc({k:candidate_rows[k]})[k] for k in runtime_names},actor_files=desc(actor),owned_child=desc({'owned_child.py':fs.read(HERE/'payload/helpers/owned_child.py')})['owned_child.py'],actual=ACTUAL,holds=pins['holds'])
    files={'original/'+n:v for n,v in original.items()}
    files.update({'packages/port/llvm23-source-reference/'+n:v for n,v in candidate_rows.items()})
    files.update({'actor/'+n:v for n,v in actor.items()})
    files['candidate-map.json']=(encode(dict(schema=1,files=desc(candidate_rows),actual=ACTUAL)),0o644)
    component_sha=fs.pin(files['candidate-map.json'][0])['sha256']
    for path in sorted((HERE/'payload').rglob('*')):
        if not path.is_file() or 'actor' in path.relative_to(HERE/'payload').parts or '__pycache__' in path.parts:continue
        name=path.relative_to(HERE/'payload').as_posix();raw,mode=fs.read(path)
        if name=='hosted/common.py':raw=raw.replace(b'__CANDIDATE_MAP_SHA__',component_sha.encode())
        files[name]=(raw,mode)
    for source,target in [(HERE/'LICENSE',Path('LICENSE')),(HERE/'policy.json',Path('policy.json')),(HERE/'expected349.lock',Path('expected349.lock')),(HERE/'builder-audit.json',Path('builder-audit.json')),(HERE/'derivation.json',Path('derivation.json')),(HERE/'root-admission.TEMPLATE.json',Path('root-admission.TEMPLATE.json'))]:files[str(target)]=fs.read(source)
    for relative,pin in pins['evidence'].items():
        raw,mode=fs.read(evidence/relative);fs.need(hashlib.sha256(raw).hexdigest()==pin,'retained upstream evidence changed: '+relative)
        target='evidence/authentication.json' if relative==pins['authentication_report'] else 'evidence/'+Path(relative).name
        fs.need(target not in files,'evidence filename collision');files[target]=(raw,mode)
    auth=json.loads(files['evidence/authentication.json'][0])['source_signatures']['llvm']
    fs.need(auth['signature_mathematics']=='PASS' and auth['archive']['sha256']==pins['archive']['sha256'],'retained source authentication must join before constructing role-capable packet')
    files['contract.json']=(encode(contract),0o644)
    workflow=(HERE/'workflow.yml.in').read_bytes().replace(b'__COMMON_SHA__',fs.pin(files['hosted/common.py'][0])['sha256'].encode()).replace(b'__ENTRY_SHA__',fs.pin(files['hosted/entry.py'][0])['sha256'].encode())
    fs.need(b'__COMMON_SHA__' not in workflow and b'__ENTRY_SHA__' not in workflow,'workflow guard pins unresolved')
    for name in ['.github/workflows/native-arm-build.yml','.github/workflows/native-arm-llvm23-source-reference-v1.yml']:files[name]=(workflow,0o644)
    inverse=dict(schema=1,before_tree=fs.tree({'original/'+n:v for n,v in original.items()}),held=desc({'original/'+n:v for n,v in original.items()}),additions=sorted(set(files)-{'original/'+n for n in original}|{'inverse.json','source-map.json'}),operation='REMOVE_EXACT_NEW_ADDITIONS_RESTORES_ORIGINAL200_BYTES_AND_MODES',actual=ACTUAL)
    files['inverse.json']=(encode(inverse),0o644)
    undo={n:v for n,v in files.items() if n not in inverse['additions']}
    fs.need(desc(undo)==inverse['held'] and fs.tree(undo)==inverse['before_tree'],'whole inverse failed')
    files['source-map.json']=(encode(dict(schema=1,scope='LLVM23_NATIVE_SOURCE_PACKET_ONLY',actual=ACTUAL,files=desc(files))),0o644)
    fs.need(len(files)<=320 and sum(len(b) for b,_ in files.values())<=96*1024**2,'finite standalone Source budget')
    return files


def verify_profile(expected):
    raw=(HERE/'constructor-profile.json').read_bytes()
    fs.need(fs.pin(raw)['sha256']==expected,'Root-reviewed constructor profile SHA differs')
    profile=json.loads(raw)
    for name,row in profile['constructor_files'].items():
        fs.relative(name);fs.need(desc({name:fs.read(HERE/name)})[name]==row,'constructor profile input differs: '+name)
    for name,row in profile['candidate_files'].items():
        fs.relative(name);path=Path(profile['operands']['candidate'])/name
        fs.need(desc({name:fs.read(path)})[name]==row,'candidate checkpoint input differs: '+name)
    return profile


def construct(frozen,candidate,evidence,output,profile_sha=None):
    frozen,candidate,evidence,output=[fs.absolute(p) for p in (frozen,candidate,evidence,output)]
    fs.need(not any(output.is_relative_to(p) or p.is_relative_to(output) for p in (frozen,candidate,HERE/'payload',evidence/'packages',evidence/'scripts',evidence/'.git')),'disjoint fresh Source output required')
    profile=verify_profile(profile_sha) if profile_sha else None
    if profile:
        fs.need([str(p) for p in (frozen,candidate,evidence)]==[profile['operands'][k] for k in ('frozen_source','candidate','evidence_root')],'checkpoint constructor operands differ')
    files=render(frozen,candidate,evidence)
    if profile:
        fs.need(fs.pin(files['source-map.json'][0])['sha256']==profile['expected_source_map_sha256'] and fs.tree(files)==profile['expected_prospective_tree'],'constructed Source differs from reviewed checkpoint')
    previous=fs.MAX_FILES
    try:fs.MAX_FILES=320;fs.publish(files,output)
    finally:fs.MAX_FILES=previous
    return dict(status='CONSTRUCTED_SOURCE_DATA_ONLY',files=len(files),bytes=sum(len(b) for b,_ in files.values()),map=fs.pin(files['source-map.json'][0]),prospective_tree=fs.tree(files),actual=ACTUAL,native_acceptance=False)


if __name__=='__main__':
    resource.setrlimit(resource.RLIMIT_AS,(512*1024**2,512*1024**2))
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['frozen-source','candidate','evidence-root','output']:p.add_argument('--'+name,required=True,type=Path)
    p.add_argument('--profile-sha256',required=True)
    a=p.parse_args();print(json.dumps(construct(a.frozen_source,a.candidate,a.evidence_root,a.output,a.profile_sha256),sort_keys=True))

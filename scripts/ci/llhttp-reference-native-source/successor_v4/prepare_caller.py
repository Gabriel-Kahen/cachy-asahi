#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Complete Source85 canonical carrier DATA; never issues or enters Root roles."""
import argparse
import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import stat

HERE=Path(__file__).resolve().parent
PREFIX='scripts/ci/llhttp-reference-native-source/owner/'
PARENT_SEAL=dict(bytes=4783,sha256='0755affc981561f1136b6936b6dcaedacadafc78adc8114e8999efec0b871973')
SOURCE_TUPLE=dict(tree='0a5bae34a6339354116933cad916d60cc78adda4',source_files=85,source_bytes=1120826,
    source_map=dict(bytes=18199,sha256='9a4b43eedecd09e5e1edc68677620ccd17a38a1bed8218fdb429b65b04715645'),
    owner_program=dict(bytes=7672,sha256='55a5f176ef39d39ee1b93b0873f0d183b76efa61e847fe4afeda3437f110b4e7'),
    policy=dict(bytes=3269,sha256='35fde476943dca9f85dda902a47016e84c64b4438e28ad0492eab2881ba74f78'),
    workflow_body=dict(bytes=6201,sha256='2ba05dea048406382cf0285c1a73f56b8671c8a322ffd2636ae41ddc64d82c99'))
OPERATOR='packet/operator-DRAFT/llhttp_once.py'
PRIMITIVE='packet/operator-DRAFT/llhttp_dispatch_once.py'
OPERATION='llhttp-reference-mount-class-diagnostics-v4'
CANDIDATE_SOURCE='d7eb16cb611c655bc2cca65501dd30c8bdfbe03f'
CANDIDATE_REF='codex/llhttp-reference-native-source-20261117-r4'
METADATA_PATH=Path('/home/gabe/Documents/ChatGPT/cachy-asahi/artifacts/development/orchestrator-resume-20261114/Root-llhttp85-delegated-publication-r1/delegated-publication-result.json')
METADATA_PIN=dict(bytes=1155,sha256='0d34e30a206a6bb0942e446053907161fb147e02060bb7f0ae11ff2ab4e3763f')

def need(value,why):
    if not value:raise ValueError(why)

def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encode(value):return (json.dumps(value,indent=2,sort_keys=True,allow_nan=False)+'\n').encode()
def ordinary(path):
    path=Path(path);need(path.is_absolute() and path==path.resolve() and not any(p.is_symlink() for p in (path,*path.parents)),'ordinary absolute DATA path');return path

def read(path,cap=2*1024**2):
    path=ordinary(path);before=path.lstat();need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and not before.st_mode&0o022 and 0<before.st_size<=cap,'bounded ordinary carrier DATA')
    raw=path.read_bytes();after=path.lstat();identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    need(identity(before)==identity(after) and len(raw)==before.st_size,'stable complete carrier DATA');return raw

def tree(bodies):
    def oid(kind,raw):return hashlib.sha1(kind.encode()+b' '+str(len(raw)).encode()+b'\0'+raw).digest()
    def walk(prefix):
        names={n[len(prefix):].split('/')[0] for n in bodies if n.startswith(prefix)};rows=[]
        for name in names:
            path=prefix+name;leaf=path in bodies;rows.append(((name if leaf else name+'/').encode(),(b'100644' if leaf else b'40000')+b' '+name.encode()+b'\0'+(oid('blob',bodies[path]) if leaf else walk(path+'/'))))
        return oid('tree',b''.join(row for _,row in sorted(rows)))
    return walk('').hex()

def validate_parent(bodies):
    need(len(bodies)==26 and sum(map(len,bodies.values()))==312318 and pin(bodies['packet-seal.DATA.json'])==PARENT_SEAL,'whole exact26 predecessor carrier')
    rows=json.loads(bodies['packet-seal.DATA.json'])['files']
    need(set(bodies)==set(rows)|{'packet-seal.DATA.json'} and all(dict(pin(bodies[n]),mode=0o600)==row for n,row in rows.items()),'all26 original body/mode pins')
    return bodies

def parent_bodies(parent):
    parent=ordinary(parent);seal=read(parent/'packet-seal.DATA.json');need(pin(seal)==PARENT_SEAL,'independent immutable Source76 carrier seal')
    names={str(p.relative_to(parent)) for p in parent.rglob('*') if p.is_file() or p.is_symlink()};need(len(names)==26,'complete26 parent namespace')
    bodies={n:read(parent/n) for n in sorted(names)}
    need(all(stat.S_IMODE((parent/n).stat().st_mode)==0o600 for n in names),'all26 private carrier modes')
    return validate_parent(bodies)

def source_binding(source):
    source=ordinary(source);raw=read(source/'source-map.json');need(pin(raw)==SOURCE_TUPLE['source_map'],'exact whole Source85 map')
    value=json.loads(raw);rows=value['files'];names={str(p.relative_to(source)) for p in source.rglob('*') if p.is_file() or p.is_symlink()}
    need(names==set(rows)|{'source-map.json'} and len(names)==85 and all(v is None for v in value['actual'].values()),'complete85 unissued namespace')
    bodies={n:read(source/n) for n in sorted(names)}
    need(all(dict(pin(bodies[n]),mode=stat.S_IMODE((source/n).stat().st_mode))==row for n,row in rows.items()) and stat.S_IMODE((source/'source-map.json').stat().st_mode)==0o644,'whole85 Source bodies/modes')
    need(sum(map(len,bodies.values()))==SOURCE_TUPLE['source_bytes'] and tree(bodies)==SOURCE_TUPLE['tree'],'complete85 bytes and physical tree')
    for name,key in ((PREFIX+'owner-program.json','owner_program'),(PREFIX+'policy.json','policy'),('.github/workflows/native-arm-llhttp-reference-source.yml','workflow_body')):need(pin(bodies[name])==SOURCE_TUPLE[key],'whole85 '+key)
    metadata=read(METADATA_PATH);need(pin(metadata)==METADATA_PIN,'exact Root-relayed delegated metadata receipt')
    result=json.loads(metadata)
    need(result['status']=='DELEGATED_PUBLICATION_READBACK_COMPLETE' and result['source']==CANDIDATE_SOURCE and result['ref']=='refs/heads/'+CANDIDATE_REF and result['tree']==SOURCE_TUPLE['tree'] and result['source_map']==SOURCE_TUPLE['source_map'] and result['program']==SOURCE_TUPLE['owner_program'] and result['policy']==SOURCE_TUPLE['policy'] and result['files']==85 and result['bytes']==1120826 and result['public_API_blob_join'] is True and result['public_clone_complete'] is True and result['Root_native_authority'] is None,'metadata-only exact Source85 publication; no native authority')
    return dict(SOURCE_TUPLE,source_root=str(source),source_CID=CANDIDATE_SOURCE,source_ref='refs/heads/'+CANDIDATE_REF,runtime54_profile=None,Root_authority=None,Root_entry='NOT RUN',native_pair='NOT RUN',delegated_metadata_result=dict(path=str(METADATA_PATH),**METADATA_PIN))

def replace(text,before,after):
    need(before in text and before!=after,'exact finite metadata binding seam');return text.replace(before,after)

def render(original,binding,script,test,policy=None):
    new=dict(original);old=json.loads(original['binding.DATA.json'])
    policy=read(Path(binding['source_root'])/PREFIX/'policy.json') if policy is None else policy
    need(pin(policy)==SOURCE_TUPLE['policy'],'exact Source85 policy in carrier')
    for name in (OPERATOR,PRIMITIVE):
        text=original[name].decode()
        for before,after in ((old['source_map']['sha256'],binding['source_map']['sha256']),(old['tree'],binding['tree']),(repr(old['policy']),repr(binding['policy'])),(repr(old['owner_program']),repr(binding['owner_program']))):text=replace(text,before,after)
        if name==OPERATOR:
            before="CANDIDATE_SOURCE='28dae2796f6f50f42da19be89618c5fda0549d2c';CANDIDATE_REF='codex/llhttp-reference-native-source-20261117-r3';PROPOSED_REF='codex/llhttp-reference-native-source-20261117-r3';"
            text=replace(text,before,'CANDIDATE_SOURCE='+repr(CANDIDATE_SOURCE)+';CANDIDATE_REF='+repr(CANDIDATE_REF)+';PROPOSED_REF='+repr(CANDIDATE_REF)+';')
            text=replace(text,"selected=='28dae2796f6f50f42da19be89618c5fda0549d2c'",'selected==CANDIDATE_SOURCE ')
            for before,after in (("source_files=76,source_bytes=1053728","source_files=85,source_bytes=1120826"),("public['files']==76 and public['bytes']==1053728","public['files']==85 and public['bytes']==1120826"),('dict(bytes=16377,sha256=MAP)','dict(bytes=18199,sha256=MAP)'),('len(rows)==75','len(rows)==84'),("==1053728 and all(r['mode']","==1120826 and all(r['mode']"),("OP='llhttp-reference-payload-retirement-v3'","OP='"+OPERATION+"'")):text=replace(text,before,after)
        else:
            text=replace(text,"MAP='",'CANDIDATE_SOURCE='+repr(CANDIDATE_SOURCE)+';CANDIDATE_REF='+repr(CANDIDATE_REF)+"\nMAP='")
            text=replace(text,"source=='28dae2796f6f50f42da19be89618c5fda0549d2c'",'source==CANDIDATE_SOURCE')
            text=replace(text,"ref=='codex/llhttp-reference-native-source-20261117-r3'",'ref==CANDIDATE_REF')
        new[name]=text.encode()
    text=new[OPERATOR].decode();text=replace(text,"PRIMITIVE_SHA='af65cafc4fd88c8edd8a10c2d9ec2d2ea43e64fcf6b9193a8d5f767621a8cbf2'","PRIMITIVE_SHA="+repr(pin(new[PRIMITIVE])['sha256']));new[OPERATOR]=text.encode()
    name='issue_root_packet.DRAFT.py';text=original[name].decode();node=next(n for n in ast.parse(text).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='SOURCE' for t in n.targets));text=replace(text,ast.get_source_segment(text,node),'SOURCE=Path('+repr(binding['source_root'])+')');new[name]=text.encode()
    new['packet/operator-DRAFT/policy.json']=policy
    binding=dict(binding,opbindings={n:pin(new[n]) for n in (OPERATOR,PRIMITIVE,'issue_root_packet.DRAFT.py','packet/make_root_config.DRAFT.py')})
    new['binding.DATA.json']=encode(binding)
    inputs=json.loads(original['ROOT-INPUTS.UNISSUED.json'])
    for name in inputs:
        if name not in ('Root_entry','status'):inputs[name]=None
    inputs.update(status='SOURCE85_METADATA_BOUND_NATIVE_OPERANDS_UNISSUED',Root_entry='NOT RUN',source_CID=CANDIDATE_SOURCE,source_ref='refs/heads/'+CANDIDATE_REF,delegated_metadata_result=dict(path=str(METADATA_PATH),**METADATA_PIN));new['ROOT-INPUTS.UNISSUED.json']=encode(inputs)
    new['HANDOFF.md']=('''# Complete Source85 canonical ONCE DRAFT

This complete carrier binds the exact85-file Source map/tree/program/policy and
restores every26 Source76 parent body/mode through full-files-inverse.DATA.json.
Candidate metadata alone is bound to d7eb16cb611c655bc2cca65501dd30c8bdfbe03f,
refs/heads/codex/llhttp-reference-native-source-20261117-r4, from the separately
Root-relayed whole receipt. Publication adoption, registration, runtime54 profile,
Root context, admission/runtime/authority, role label, nonce, time and output
remain NULL. Root must separately review and issue all fresh operational inputs.
No Root native truth or authority is supplied by these files.

The literal issuer, joiner, canonical operator and primitive preserve runtime54,
custody, global10GET/two-sweep EMPTY, Main CAS, once/onePOST/noRetry, CLOSE_ONLY,
deadlines/resources and failed-owner retirement. The filesystem guard is unchanged;
Source85 adds diagnostic-only mount observations. Native87 remains HOLD/pairNOTRUN.
Workflow420972285 and6201B/2ba05dea body are unchanged; current registration must
be independently refreshed. Historical logs under predecessor-metadata/source76
are Source76 evidence, not new controls. No role/lease/POST/OriginalGET/native actor
or Root issuance was performed. Run only DATA controls until Root supplies inputs.
''').encode()
    for name in ('controls-Python-3.12.13.DATA.log','controls-Python-3.14.7.DATA.log'):new['predecessor-metadata/source76/'+name]=new.pop(name)
    new['prepare-carrier.py']=script;new['test_canonical_cli.DATA.py']=test
    return new

def inverse(value):
    if isinstance(value,(str,Path)):
        root=ordinary(value);bodies={str(p.relative_to(root)):read(p) for p in root.rglob('*') if p.is_file() or p.is_symlink()}
        need(all(stat.S_IMODE((root/n).stat().st_mode)==0o600 for n in bodies),'whole private successor modes')
    else:bodies=value
    seal=json.loads(bodies['packet-seal.DATA.json']);need(set(bodies)==set(seal['files'])|{'packet-seal.DATA.json'} and all(dict(pin(bodies[n]),mode=0o600)==r for n,r in seal['files'].items()),'complete sealed successor namespace/bytes/modes')
    need(seal['Root_authority'] is None and seal['role_label'] is None and seal['actual_POSTs']==0,'unissued carrier seal')
    proof=json.loads(bodies['full-files-inverse.DATA.json']);need(proof['parent_seal']==PARENT_SEAL and len(proof['files'])==26,'complete26 inverse ledger')
    old={}
    for name,row in proof['files'].items():
        raw=base64.b64decode(row['body_base64'],validate=True);need(pin(raw)==row['pin'] and row['mode']==0o600,'whole original inverse body');old[name]=raw
    validate_parent(old)
    binding=json.loads(bodies['binding.DATA.json']);need(all(binding[k]==v for k,v in SOURCE_TUPLE.items()) and binding['source_CID']==CANDIDATE_SOURCE and binding['source_ref']=='refs/heads/'+CANDIDATE_REF and binding['delegated_metadata_result']==dict(path=str(METADATA_PATH),**METADATA_PIN) and binding['Root_authority'] is None,'exact85 metadata only; no native authority')
    expected=render(old,binding,bodies['prepare-carrier.py'],bodies['test_canonical_cli.DATA.py'],bodies['packet/operator-DRAFT/policy.json'])
    for name,raw in expected.items():
        if name not in ('full-files-inverse.DATA.json','packet-seal.DATA.json'):need(bodies[name]==raw,'whole finite caller projection: '+name)
    need(set(expected)==set(bodies),'whole successor carrier namespace')
    return old

def construct(parent,source,output):
    parent,source,output=map(ordinary,(parent,source,output));need(not output.exists() and not output.is_relative_to(parent) and not output.is_relative_to(source),'fresh disjoint carrier output')
    original=parent_bodies(parent);binding=source_binding(source)
    script=read(Path(__file__).resolve());test_path=HERE/'test_caller_data.py'
    if not test_path.exists():test_path=HERE/'test_canonical_cli.DATA.py'
    new=render(original,binding,script,read(test_path))
    new['full-files-inverse.DATA.json']=encode(dict(status='COMPLETE_SOURCE76_26_LEAF_INVERSE_DATA_ONLY',parent_files=26,parent_seal=PARENT_SEAL,files={n:dict(pin=pin(raw),mode=0o600,body_base64=base64.b64encode(raw).decode()) for n,raw in sorted(original.items())},Root_authority=None))
    new['packet-seal.DATA.json']=encode(dict(status='SOURCE85_FULL_CANONICAL_ONCE_DRAFT_NATIVE_INPUTS_UNBOUND',files={n:dict(pin(raw),mode=0o600) for n,raw in sorted(new.items()) if n!='packet-seal.DATA.json'},Root_authority=None,role_label=None,runtime54_profile=None,actual_source_metadata=CANDIDATE_SOURCE,source_ref='refs/heads/'+CANDIDATE_REF,actual_POSTs=0))
    inverse(new);need(len(new)<40 and sum(map(len,new.values()))<2*1024**2,'bounded complete carrier DATA')
    output.mkdir(mode=0o700)
    for name,raw in new.items():
        path=output/name;path.parent.mkdir(parents=True,exist_ok=True)
        with path.open('xb') as stream:stream.write(raw)
        path.chmod(0o600)
    for path in output.rglob('*.py'):ast.parse(read(path),filename=str(path))
    return dict(status='SOURCE85_DRAFT_ONLY',files=len(new),bytes=sum(map(len,new.values())),binding=json.loads(new['binding.DATA.json']),operator=pin(new[OPERATOR]),primitive=pin(new[PRIMITIVE]),issuer=pin(new['issue_root_packet.DRAFT.py']),joiner=pin(new['packet/make_root_config.DRAFT.py']),seal=pin(new['packet-seal.DATA.json']),Root_authority=None)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('parent','source','output'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();print(json.dumps(construct(a.parent,a.source,a.output),indent=2,sort_keys=True))

#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Prepare an unissued canonical ONCE caller for this exact new Source, no roles."""
import argparse
import ast
import importlib.util
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('llhttp_go_va_source_data',HERE/'prepare.py');P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
PARENT_OPERATOR=dict(bytes=25875,sha256='1412509d2099f3f898374a4217e0760bd06711b3d291304e2aa59e05074f117f')
PARENT_PRIMITIVE=dict(bytes=7703,sha256='4bb0a9e6cf5416748d5eabcf79f7c72e53651bd640ca6f3cea740d551f40a1a9')
NAMES=('llhttp_once.py','llhttp_dispatch_once.py','admission.TEMPLATE.json','runtime.TEMPLATE.json','authority.TEMPLATE.json','config.TEMPLATE.json','publication.TEMPLATE.json','source-review.TEMPLATE.json','workflow-registration.TEMPLATE.json','operational-context.TEMPLATE.json')

def construct(parent,source,output):
    parent,source,output=map(P.ordinary,(parent,source,output));P.need(not output.exists()and not output.is_relative_to(parent)and not output.is_relative_to(source),'fresh disjoint caller DATA')
    bodies={str(n.relative_to(source)):P.read(n)for n in source.rglob('*')if n.is_file()};P.inverse(bodies)
    P.need(P.pin(bodies['source-map.json'])==dict(bytes=14771,sha256='00a7b3ced2bbf21303734d32cf9dde10e7db5e724b0c1b4857f7ab7e5a685998')and P.tree(bodies)=='ff40c38eb5062ace3b46cb2f2c4c8c32fc010a00','only this exact reviewed Source68 caller binding')
    value=json.loads(bodies['source-map.json']);P.need(set(bodies)==set(value['files'])|{'source-map.json'}and len(bodies)==68 and all(dict(P.pin(bodies[n]),mode=0o644)==row for n,row in value['files'].items()),'whole exact new68 Source')
    ops=parent/'packet/operator-DRAFT';P.need(P.pin(P.read(ops/'llhttp_once.py'))==PARENT_OPERATOR and P.pin(P.read(ops/'llhttp_dispatch_once.py'))==PARENT_PRIMITIVE,'exact held Source62 canonical caller')
    originals={'packet/operator-DRAFT/'+n:P.read(ops/n)for n in NAMES}
    for n in('issue_root_packet.DRAFT.py','packet/make_root_config.DRAFT.py'):originals[n]=P.read(parent/n)
    originals['packet/operator-DRAFT/policy.json']=P.read(ops/'policy.json')
    seal_raw=P.read(parent/'packet-seal.DATA.json');P.need(P.pin(seal_raw)==dict(bytes=4382,sha256='af43b22c771b94a8761727362995d373faacff83370177811d1b94b0a9348ccb'),'whole held Source62 canonical carrier seal')
    held=json.loads(seal_raw)['files']
    for name,raw in originals.items():P.need(P.pin(raw)=={k:held[name][k]for k in('bytes','sha256')},'whole sealed canonical issuer/operator/primitive/joiner/template: '+name)
    new=dict(originals);old_policy=json.loads(P.read(ops/'policy.json'));new_policy=bodies[P.PREFIX+'policy.json'];old_program=dict(bytes=3074,sha256='5fee47ac31788de8aaa4afcd7042dc1c3b686e953bb19a65c7cac138262f2112');new_program=P.pin(bodies[P.PREFIX+'owner-program.json'])
    for name in('packet/operator-DRAFT/llhttp_once.py','packet/operator-DRAFT/llhttp_dispatch_once.py'):
        text=new[name].decode().replace(P.PARENT_MAP['sha256'],P.pin(bodies['source-map.json'])['sha256']).replace(P.PARENT_TREE,P.tree(bodies)).replace(repr(old_program),repr(new_program)).replace(repr(P.pin(P.read(ops/'policy.json'))),repr(P.pin(new_policy)))
        text=text.replace("source=='b36a1a6dba7dd42d55646582f3d1fa2002d78d5f'", "source!='b36a1a6dba7dd42d55646582f3d1fa2002d78d5f'")
        text=text.replace("selected=='b36a1a6dba7dd42d55646582f3d1fa2002d78d5f'", "selected!='b36a1a6dba7dd42d55646582f3d1fa2002d78d5f'")
        text=text.replace("ref=='codex/llhttp-reference-native-source-20261117-r1'", "re.fullmatch('codex/[A-Za-z0-9._/-]+',ref or '')")
        text=text.replace("PROPOSED_REF='codex/llhttp-reference-native-source-20261117-r1'",'PROPOSED_REF=None').replace('need(ref==PROPOSED_REF,',"need(re.fullmatch('codex/[A-Za-z0-9._/-]+',ref),")
        text=text.replace("registration['registration_commit']=='5a29b868a9f3e35908f9af9753f64ffb3061f7a0'", "re.fullmatch('[0-9a-f]{40}',registration['registration_commit']or '')")
        text=text.replace("source_files=62,source_bytes=928551",f"source_files=68,source_bytes={sum(map(len,bodies.values()))}")
        text=text.replace("public['files']==62 and public['bytes']==928551",f"public['files']==68 and public['bytes']=={sum(map(len,bodies.values()))}")
        text=text.replace("dict(bytes=13601,sha256=MAP)",f"dict(bytes={len(bodies['source-map.json'])},sha256=MAP)")
        text=text.replace("len(rows)==61",'len(rows)==67').replace("==928551 and all(r['mode']",f"=={sum(map(len,bodies.values()))} and all(r['mode']")
        text=text.replace("OP='llhttp-reference-hosted-native-v1'","OP='llhttp-reference-go-cli-va-v2'")
        new[name]=text.encode()
    op='packet/operator-DRAFT/llhttp_once.py';prim='packet/operator-DRAFT/llhttp_dispatch_once.py'
    text=new[op].decode();tree=ast.parse(text);node=next(n for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='PRIMITIVE_SHA'for t in n.targets));text=text.replace(ast.get_source_segment(text,node),'PRIMITIVE_SHA='+repr(P.pin(new[prim])['sha256']));new[op]=text.encode()
    # The physical Source output is DATA; CID/ref/publication remain separately required.
    text=new['issue_root_packet.DRAFT.py'].decode();before="SOURCE=Path('/home/gabe/Documents/ChatGPT/cachy-asahi/artifacts/development/orchestrator-resume-20261114/Root-llhttp62-source-r1/closed-source-tree')";P.need(text.count(before)==1,'one explicit new Source operand seam');text=text.replace(before,'SOURCE=Path('+repr(str(source))+')');new['issue_root_packet.DRAFT.py']=text.encode()
    new['packet/operator-DRAFT/policy.json']=new_policy
    proof=dict(status='CANONICAL_CALLER_SOURCE_PREPARATION_ONLY',files={name:dict(predecessor=dict(path=str(parent/name),**P.pin(raw)),successor=dict(path=str(output/name),**P.pin(new[name])),seams=[dict(before=raw.decode(),after=new[name].decode(),count=1)]if raw!=new[name]else[])for name,raw in originals.items()})
    new['full-files-inverse.DATA.json']=P.encode(proof)
    new['ROOT-INPUTS.UNISSUED.json']=P.encode(dict(status='UNISSUED_NEW_GO_DOCKER_CLI_VA_OPERATION',source=None,ref=None,publication=None,registration=None,runtime54_profile=None,operational_context=None,role_label=None,nonce=None,created_utc=None,expires_utc=None,output=None,documents_output=None,current_retirement=None,live_domains=None,custody=None,resources=None,source349_cache=None,Root_entry='NOT RUN'))
    binding=dict(source_root=str(source),source_CID=None,source_ref=None,tree=P.tree(bodies),source_map=P.pin(bodies['source-map.json']),source_files=68,source_bytes=sum(map(len,bodies.values())),owner_program=new_program,policy=P.pin(new_policy),workflow_body=P.pin(bodies['.github/workflows/native-arm-llhttp-reference-source.yml']),runtime54_profile=None,Root_authority=None,Root_entry='NOT RUN',native_ARM='NOT RUN')
    new['binding.DATA.json']=P.encode(binding)
    output.mkdir(mode=0o700)
    for name,raw in new.items():
        path=output/name;path.parent.mkdir(parents=True,exist_ok=True)
        with path.open('xb')as stream:stream.write(raw)
        path.chmod(0o600)
    for path in output.rglob('*.py'):ast.parse(path.read_bytes(),filename=str(path))
    return dict(files=len(new),bytes=sum(map(len,new.values())),binding=binding,operator=P.pin(new[op]),primitive=P.pin(new[prim]),issuer=P.pin(new['issue_root_packet.DRAFT.py']))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in('parent','source','output'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();print(json.dumps(construct(a.parent,a.source,a.output),indent=2,sort_keys=True))

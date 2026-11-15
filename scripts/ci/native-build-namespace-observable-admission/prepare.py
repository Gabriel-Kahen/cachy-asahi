#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One observable Source admission DATA adapter; never enter a role or publish Source."""
import argparse
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
from types import SimpleNamespace

HERE=Path(__file__).resolve().parent
BASE=HERE.parent/'native-build-namespace-admission-preparation'
SOURCE_ROOT=Path('/home/gabe/Documents/ChatGPT/cachy-asahi-namespace-observable-source-20261114')
PINNED={'prepare.py':'c5d7de8c4c3c02485767c57b9057d6fc74caeea0d208cb939c5f997d157b8cac',
        'namespace_guard.py':'9d1b8eb0ba155511f47ee34974f7a7ff7199b6c9341e9d099b6410d08833b599'}

def need(v,s):
    if not v:raise ValueError(s)

def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

G=module('observable_admission_guard',HERE/'namespace_guard.py')


def base():
    """Reuse exact original pure filesystem/seal/render helpers; no role import."""
    raw={name:(BASE/name).read_bytes()for name in PINNED}
    need(all(hashlib.sha256(raw[n]).hexdigest()==sha for n,sha in PINNED.items()),'frozen admission helper bytes')
    old=module('held_namespace_guard',BASE/'namespace_guard.py')
    scope=dict(globals(),G=old,HERE=BASE,SOURCE_ROOT=Path('/home/gabe/Documents/ChatGPT/cachy-asahi/artifacts/development/orchestrator-resume-20261114/native-build-namespace-preflight-source-r2'),PIN=old.pin)
    names={'need','encoded','read','obj','source_tree','inputs','render','publish'}
    nodes=[n for n in ast.parse(raw['prepare.py']).body if isinstance(n,ast.FunctionDef)and n.name in names]
    need({n.name for n in nodes}==names,'exact finite reusable helper set')
    exec(compile(ast.Module(body=nodes,type_ignores=[]),str(BASE/'prepare.py'),'exec'),scope)
    return SimpleNamespace(**scope)


def swap(raw):
    text=raw.decode()
    for old,new in [('6b5b5a8f20ad2698c2d7f14a8f59c9b0ad5da165',G.SOURCE),('codex/native-build-namespace-preflight-v2-20261114',G.REF),('a825d475d248f2254070d256d23780c4ef2d0f4b',G.TREE),('97a44c4c7cb206704bf76e9fd1f1afb2266278c2',G.PARENT),('7474683e198759876dcee6b31a036473f2129da351fce3bcc8e37770b4a70f79',G.MAP),('100346','106215'),('2292e492bf33fea2d079525165293e47e2d817deed71495a3b80d3090a406aa5',G.READER['sha256']),('NAMESPACE_PREFLIGHT','NAMESPACE_OBSERVABLE'),('EXACT_NAMESPACE_PREFLIGHT','EXACT_NAMESPACE_OBSERVABLE'),('ROOT_BOUND_NAMESPACE_FACTORY_CI_MAIN','ROOT_BOUND_NAMESPACE_OBSERVABLE_FACTORY_CI_MAIN'),('PR433','PR437')]:text=text.replace(old,new)
    return text.encode()


def inputs(root,factory=None,factory_sha=None,runtime=None,runtime_sha=None,extras=None,extras_sha=None):
    B=base();data=B.inputs(B.SOURCE_ROOT)
    publication=B.obj(B.read(HERE/'Root-published-source-full200.json'))
    need(G.pin(B.read(HERE/'Root-published-source-full200.json'))==dict(bytes=51826,sha256='5e9f5b219da9c6c3a713a650916fbad4dcc18a0823bd40dceb664da52142b466'),'exact independent Root Source publication DATA')
    rows={n:dict(bytes=r['bytes'],sha256=r['sha256'],mode=r['mode'],oid=r['blob'])for n,r in publication['files'].items()}
    G.publication(publication,B.read(HERE/'source.raw'),rows)
    profile=B.obj(B.read(HERE/'source-profile.json'));need(G.pin(B.read(HERE/'source-profile.json'))['sha256']==G.PROFILE,'exact reviewed source profile')
    G.source_delta(profile,data['rows'],rows)
    need(B.read(HERE/'parent.raw')==data['templates']['source.raw'],'genuine published parent6b raw bytes')
    total=B.source_tree(root,rows)
    templates={n:swap(raw)for n,raw in data['templates'].items()}
    templates.update({'source-publication.ACTUAL.json':B.read(HERE/'Root-published-source-full200.json'),'source-full200.json':B.encoded(rows),'source.raw':B.read(HERE/'source.raw'),'parent-full200.json':B.encoded(data['rows']),'source-profile.json':B.read(HERE/'source-profile.json'),'runtime54.py':B.read(HERE/'runtime54.py')})
    external=data['external'];binding=None;runtime_binding=None
    def external_json(path,sha):
        raw=B.read(path);need(G.pin(raw)['sha256']==sha,'explicit independent Root operand whole pin');external[str(path)]=G.pin(raw);return B.obj(raw)
    if factory:
        binding=G.factory(external_json(factory,factory_sha));proofs=[]
        for key in ('factory_merge','factory_CI'):
            row=binding[key];raw=B.read(Path(row['path']));need(G.pin(raw)=={k:row[k]for k in('bytes','sha256')},'actual Root factory proof pin');external[row['path']]=G.pin(raw);proofs.append(B.obj(raw))
        G.factory_proofs(binding,*proofs)
    else:need(factory_sha is None,'no factory pin without binding')
    if runtime:
        value=external_json(runtime,runtime_sha);module('observable_runtime54_data',HERE/'runtime54.py').profile(value)
        runtime_binding=dict(path=str(runtime),**external[str(runtime)])
    else:need(runtime_sha is None,'no runtime pin without profile')
    templates['runtime54-binding.json']=B.encoded(runtime_binding or dict(path=None,bytes=None,sha256=None))
    registry=B.obj(templates['Root-namespace-x86-certificates.json'])
    if extras:
        added=external_json(extras,extras_sha)
        need(type(added)is dict and set(added)=={'schema','certificates','native_permission','resource_permission'}and added['schema']==1 and added['native_permission']is added['resource_permission']is False,'Root exact-body classifications grant no resource/native permission')
        for row in added['certificates']:
            value=external_json(Path(row['path']),row['sha256'])
            need(value.get('issuer')=='Root'and value.get('independently_classified')is True and value.get('native_permission')is value.get('CI_success_claim')is False,'independent Root extra classification only')
            need(row not in registry['certificates'],'duplicate Root extra ref');registry['certificates'].append(row)
        need(len(registry['certificates'])<=8,'finite exact extra registry')
    else:need(extras_sha is None,'no extras pin without registry')
    templates['Root-namespace-x86-certificates.json']=B.encoded(registry)
    authority=B.obj(templates['Root-authority.TEMPLATE.json'])
    authority['namespace_x86_body_certificates']=registry['certificates']
    authority['classification']='CANONICAL_HEAVY_NON_KERNEL_EXACT_NAMESPACE_OBSERVABLE_V1'
    held=[key.replace('same_inode55_','same_inode54_')for key in authority['reviews']if not key.startswith(('exact_Source36_','exact_corrected_Source6b_','genuine_PR437_'))]
    authority['reviews']={key:None for key in ('exact_Source69455_parent6b_four_leaf_inverse196_complete200_map199','exact_tools16_UNQUIET_iidfile_and_matching_Reader106215_failure_visibility','genuine_PR437_complete_batch_inverse_factory_subset9_bothPython50controls','independent_fresh_external_Root_runtime54_full_FD_identity_no_mutation',*held)}
    authority['scope']+=' Observable family changes exactly four leaves, retains196 and uses tools16/unquiet with iidfile. Full diagnostic output remains subject to unchanged ordinary privacy refusal; no namespace outcome is guaranteed or inferred.'
    templates['Root-authority.TEMPLATE.json']=B.encoded(authority)
    templates['factory-binding.TEMPLATE.json']=B.encoded(dict(schema=1,issuer='Root',approved=None,status='ROOT_MUST_BIND_PR437_OBSERVABLE_FACTORY_CI_MAIN',pull_request=437,reviewed_factory='d6b86264d2fb6243e0ccde4a95e2a7f50804420e',baseline_main='208bd08d7f14c76468ff4c8fb18c357f37120070',factory_Main=None,factory_head=None,expected_CI_checks=None,factory_merge=dict(path=None,bytes=None,sha256=None),factory_CI=dict(path=None,bytes=None,sha256=None)))
    native=templates['ROOT-NATIVE-ONCE.py'].decode()
    a=native.index('def bootstrap():');b=native.index('\ndef verify_packet(',a)
    native=native[:a]+'''def bootstrap():
 need(__debug__,'optimized Python forbidden')
 raw=(T/'input-seal.json').read_bytes();need(pin(raw)['sha256']==INPUT_SEAL,'fixed bounded authority')
 index=json.loads(raw)
 for name,row in index.items():need(pin(Path(name).read_bytes())==row,'held authority '+name)
 path=DEV/'security200-v5-ci-feedback-development-20261031/capture.py'
 C=load('_platform_matrix_custody',path,index[str(path)]['sha256'])
 path=T/'runtime54.py';runtime=load('_observable_runtime54',path,index[str(path)]['sha256'])
 C.runtime_lock_identity=runtime.factory(T/'runtime54-binding.json',index[str(T/'runtime54-binding.json')])
 U,S,L=C.modules();return C,U,S,L

'''+native[b:]
    point=" need(type(binding)is dict and binding.get('status')=='ROOT_BOUND_NAMESPACE_OBSERVABLE_FACTORY_CI_MAIN' and binding.get('approved')is True,'PR437 factory CI/Main binding pending; HOLD before bootstrap or role output')"
    need(native.count(point)==1,'one pending factory gate')
    native=native.replace(point,point+"\n need(type(facts.get('runtime54_profile'))is dict,'Root runtime54 attestation pending; HOLD before bootstrap or role output')")
    native=native.replace("publication_status='PUBLIC_SOURCE_DATA_ONLY_NOT_NATIVE_ADMISSION'","publication_status='PUBLISHED_SOURCE_200_BODY_QUALIFIED_ACTORS_NOT_ADMITTED'")
    old_view="view=OUT/'publication-for-original9d';view.mkdir(mode=0o700);write(view/'publication.json',U.read(PUB/'publication.json'))"
    new_view="view=OUT/'publication-for-original9d';view.mkdir(mode=0o700);save(view/'publication.json',dict(source=SOURCE,ref=REF))\n  save(OUT/'original9d-publication-projection.json',dict(Root_publication=pin(U.read(PUB/'publication.json')),Root_ref=obj(PUB/'publication.json')['ref'],dispatch_view=dict(source=SOURCE,ref=REF),Source_publication=False))"
    need(native.count(old_view)==1,'one explicit full-ref to original9d short-ref view seam')
    native=native.replace(old_view,new_view).replace('# Give unchanged9d a genuine complete local200 view and unmodified receipt.','# Give unchanged9d a complete local200 view and explicit short-ref dispatch projection.')
    templates['ROOT-NATIVE-ONCE.py']=native.encode()
    return dict(templates=templates,external=external,binding=binding,source_root=str(root),rows=rows,source_bytes=total,runtime54_profile=runtime_binding)


def render(data,output):
    B=base();raw=B.read(BASE/'prepare.py');tree=ast.parse(raw)
    definition=ast.get_source_segment(raw.decode(),next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='render'))
    for old,new in [("HERE.parent/'native-build-namespace-preflight/parent.raw'","HERE/'parent.raw'"),('PR433','PR437'),('8d4ec359bf05dda455eb772077b4edf37de53002','d6b86264d2fb6243e0ccde4a95e2a7f50804420e'),('factory_reviewed_correction','factory_reviewed_factory'),('295d838936371ce7376fc5b71c47232b155bd0b3','208bd08d7f14c76468ff4c8fb18c357f37120070')]:
        need(old in definition,'finite render seam '+old);definition=definition.replace(old,new)
    definition=definition.replace("Root_authority=None,Root_fresh_live_reservation=None", "runtime54_profile=data.get('runtime54_profile'),Root_authority=None,Root_fresh_live_reservation=None")
    scope=dict(vars(B),HERE=HERE,G=G)
    exec(compile(definition,'<observable finite render adapter>','exec'),scope)
    return scope['render'](data,output)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source-root',type=Path,default=SOURCE_ROOT);p.add_argument('--output',type=Path)
    for name in ('factory-binding','runtime54-profile','x86-extras'):
        p.add_argument('--'+name,type=Path);p.add_argument('--'+name+'-sha256')
    a=p.parse_args();data=inputs(a.source_root,a.factory_binding,a.factory_binding_sha256,a.runtime54_profile,a.runtime54_profile_sha256,a.x86_extras,a.x86_extras_sha256)
    if a.output:base().publish(render(data,a.output),a.output)
    print(json.dumps(dict(status='OBSERVABLE_ADMISSION_SOURCE_DATA_ONLY',source=G.SOURCE,source_files=200,source_bytes=data['source_bytes'],factory_CI_Main_pending=data['binding']is None,runtime54_pending=data['runtime54_profile']is None,resource_authority=None,Native_POSTs=0,Original_GETs=0,Reader_calls=0,packet_written=a.output is not None),sort_keys=True))

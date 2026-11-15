#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compose exact Source3937 admission DATA, with every Root role unentered."""
import argparse
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

HERE=Path(__file__).resolve().parent
HELD_SHA='a2694deae052150baa30089c37c59da24d2d2f8eda95aaf985519212ea00086c'


def need(ok,why):
    if not ok:raise ValueError(why)


def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def read(path,cap=4*1024**2):
    path=Path(path)
    need(path.is_absolute() and path==path.resolve() and not any(p.is_symlink()for p in(path,*path.parents)),'canonical admission DATA operand')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    state=lambda s:tuple(getattr(s,n)for n in('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns'))
    try:
        before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<before.st_size<=cap,'bounded ordinary admission DATA')
        with os.fdopen(os.dup(fd),'rb')as f:raw=f.read(cap+1)
        need(len(raw)==before.st_size and state(before)==state(os.fstat(fd))==state(path.lstat()),'stable whole admission DATA')
        return raw
    finally:os.close(fd)


def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value)
    return value


G=module('_context_admission_guard',HERE/'namespace_guard.py')


def held(root):
    root=Path(root);manifest_raw=read(HERE/'held-inputs.json');need(pin(manifest_raw)['sha256']==HELD_SHA,'fixed whole held composer closure')
    manifest=json.loads(manifest_raw)
    need(root.is_absolute() and root.name=='native-build-namespace-observable-admission' and root==root.resolve(),'explicit canonical held admission directory')
    for name,row in manifest['files'].items():need(pin(read(root.parent/name))==row,'held Mainab6 composer DATA/code '+name)
    A=module('_held_observable_admission_DATA',root/'prepare.py')
    return A,manifest


def definition(raw,name):
    nodes=[n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)and n.name==name]
    need(len(nodes)==1,'one selected DATA helper definition')
    return ast.get_source_segment(raw.decode(),nodes[0])


def rewrite(text,changes):
    for old,new in changes:
        need(text.count(old)==1,'one finite composer seam '+old[:90]);text=text.replace(old,new,1)
    return text


def template_binding():
    return dict(schema=1,issuer='Root',approved=None,status='ROOT_MUST_BIND_NEW_CONTEXT_FACTORY_CI_MAIN',
        source=G.SOURCE,ref='refs/heads/'+G.REF,tree=G.TREE,parent=G.PARENT,map_sha256=G.MAP,profile_sha256=G.PROFILE,reader=G.READER,
        source_factory_reviewed='559c4ffcd1116fb7f353680f8e9221c651367ab0',baseline_main=G.BASELINE_MAIN,
        pull_request=None,reviewed_factory=None,factory_head=None,factory_Main=None,factory_files_sha256=None,expected_CI_checks=None,
        factory_merge=dict(path=None,bytes=None,sha256=None),factory_CI=dict(path=None,bytes=None,sha256=None))


def inputs(A,root,factory=None,factory_sha=None,runtime=None,runtime_sha=None,extras=None,extras_sha=None):
    B=A.base();raw=read(A.HERE/'prepare.py');original=definition(raw,'inputs')
    factory_manifest=read(HERE/'factory-files.json')
    changes=[
      ("dict(bytes=51826,sha256='5e9f5b219da9c6c3a713a650916fbad4dcc18a0823bd40dceb664da52142b466')","dict(bytes=50625,sha256='b522b296a2b302312df9ef93b88e8ea90e1a40fa3eb7be6eb976bfa21c025811')"),
      ("mode=r['mode'],oid=r['blob']","mode='100755'if r['mode']==493 else'100644',oid=r['oid']"),
      ("G.source_delta(profile,data['rows'],rows)","parent_rows=B.obj(B.read(HERE/'parent-full200.json'));G.source_delta(profile,parent_rows,rows)"),
      ("B.read(HERE/'parent.raw')==data['templates']['source.raw']","B.read(HERE/'parent.raw')==B.read(HELD_ROOT/'source.raw')"),
      ("B.encoded(data['rows'])","B.encoded(parent_rows)"),
      ("proofs=[]","need(binding['factory_files_sha256']==FACTORY_SHA,'exact Root-bound new factory manifest');proofs=[]"),
      ("G.factory_proofs(binding,*proofs)",
       "def merge_proof(row):\n            G.proof_row(row);raw=B.read(Path(row['path']))\n            need(G.pin(raw)=={k:row[k]for k in('bytes','sha256')},'actual Root merge-action evidence pin')\n            external[row['path']]=G.pin(raw);return B.obj(raw)\n        G.factory_proofs(binding,*proofs,merge_proof)"),
      ("authority['scope']+=' Observable family changes exactly four leaves, retains196 and uses tools16/unquiet with iidfile. Full diagnostic output remains subject to unchanged ordinary privacy refusal; no namespace outcome is guaranteed or inferred.'",
       "authority['scope']+=' Original alarm1001 family changes six leaves, retains194, preserves the original USER alarm/PID1/argv/baseline domain without account mutation. Tools16/unquiet with iidfile, ordinary privacy refusal and no inferred namespace outcome remain exact.'"),
      ("'exact_Source69455_parent6b_four_leaf_inverse196_complete200_map199'","'exact_Source3937_parent69455_six_leaf_inverse194_complete200_map199_original_alarm1001'"),
      ("'genuine_PR437_complete_batch_inverse_factory_subset9_bothPython50controls'","'genuine_new_factory_complete_batch_inverse_subset10_reviewed_tested_Main_bothPython_context_controls'"),
      ("templates['factory-binding.TEMPLATE.json']=B.encoded(dict(schema=1,issuer='Root',approved=None,status='ROOT_MUST_BIND_PR437_OBSERVABLE_FACTORY_CI_MAIN',pull_request=437,reviewed_factory='d6b86264d2fb6243e0ccde4a95e2a7f50804420e',baseline_main='208bd08d7f14c76468ff4c8fb18c357f37120070',factory_Main=None,factory_head=None,expected_CI_checks=None,factory_merge=dict(path=None,bytes=None,sha256=None),factory_CI=dict(path=None,bytes=None,sha256=None)))",
       "templates['factory-binding.TEMPLATE.json']=B.encoded(template_binding())")]
    adapted=rewrite(original,changes)
    adapted=adapted.replace('NAMESPACE_OBSERVABLE','NAMESPACE_CONTEXT').replace('PR437 factory CI/Main binding pending','new context factory CI/Main binding pending')
    inverse=adapted.replace('NAMESPACE_CONTEXT','NAMESPACE_OBSERVABLE').replace('new context factory CI/Main binding pending','PR437 factory CI/Main binding pending')
    inverse=rewrite(inverse,[(new,old)for old,new in reversed(changes)])
    need(inverse==original,'exact inverse restores the complete held input composer')
    # swap() is the held old6b→published-family literal adapter, in a private new G scope.
    swap_scope=dict(vars(A),G=G);exec(compile(definition(raw,'swap'),'<held finite source tuple adapter>','exec'),swap_scope)
    def swap(raw):
        return swap_scope['swap'](raw).replace(b'NAMESPACE_OBSERVABLE',b'NAMESPACE_CONTEXT').replace(b'PR437 factory CI/Main binding pending',b'new context factory CI/Main binding pending')
    scope=dict(vars(A),HERE=HERE,G=G,HELD_ROOT=A.HERE,FACTORY_SHA=pin(factory_manifest)['sha256'],template_binding=template_binding,swap=swap)
    exec(compile(adapted,'<finite original1001 admission DATA adapter>','exec'),scope)
    data=scope['inputs'](root,factory,factory_sha,runtime,runtime_sha,extras,extras_sha)
    provenance=dict(schema=1,held_main='ab6b6e1887c8d7609ba387c9401dc9f970bb3a13',held_function=pin(original.encode()),adapted_function=pin(adapted.encode()),
                    finite_replacements=[dict(before=a,after=b)for a,b in changes],complete_input_composer_inverse=True,source=G.SOURCE,parent=G.PARENT,profile_sha256=G.PROFILE,
                    old_roles_replayed=False,old_sealed_code_modified=False,worker_roles_entered=0)
    data['templates']['composition-provenance.json']=B.encoded(provenance)
    for name,row in json.loads(read(HERE/'held-inputs.json'))['files'].items():data['external'][str(A.HERE.parent/name)]=row
    return data


def render(A,data,output):
    raw=read(A.HERE/'prepare.py');text=definition(raw,'render')
    text=rewrite(text,[
      ("'PR437'","'CONTEXT'"),
      ("'d6b86264d2fb6243e0ccde4a95e2a7f50804420e'","'@ROOT_REVIEWED_FACTORY@'"),
      ("'208bd08d7f14c76468ff4c8fb18c357f37120070'","'ab6b6e1887c8d7609ba387c9401dc9f970bb3a13'"),
      ("    scope=dict(vars(B),HERE=HERE,G=G)","    definition=definition.replace(\"'@ROOT_REVIEWED_FACTORY@'\",\"(data['binding']['reviewed_factory'] if data['binding'] is not None else None)\")\n    scope=dict(vars(B),HERE=HERE,G=G)")])
    scope=dict(vars(A),HERE=HERE,G=G);exec(compile(text,'<finite context packet renderer>','exec'),scope)
    files=scope['render'](data,output)
    return files


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--held-admission-root',type=Path,required=True)
    p.add_argument('--source-root',type=Path,required=True);p.add_argument('--output',type=Path)
    for name in('factory-binding','runtime54-profile','x86-extras'):
        p.add_argument('--'+name,type=Path);p.add_argument('--'+name+'-sha256')
    a=p.parse_args();A,_=held(a.held_admission_root)
    data=inputs(A,a.source_root,a.factory_binding,a.factory_binding_sha256,a.runtime54_profile,a.runtime54_profile_sha256,a.x86_extras,a.x86_extras_sha256)
    files=render(A,data,a.output or Path('/UNWRITTEN/context-admission-DATA'))
    if a.output:A.base().publish(files,a.output)
    print(json.dumps(dict(status='CONTEXT3937_ADMISSION_DATA_ONLY',source=G.SOURCE,source_files=200,source_bytes=data['source_bytes'],
        factory_binding_pending=data['binding']is None,runtime54_pending=data['runtime54_profile']is None,packet_written=a.output is not None,
        resource_authority=None,actual_run=None,actual_job=None,Native_POSTs=0,Original_GETs=0,Reader_calls=0,roles_entered=0,acceptance=False),sort_keys=True))


if __name__=='__main__':main()

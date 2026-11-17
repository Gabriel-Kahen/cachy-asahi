# SPDX-License-Identifier: MIT
"""Pinned single-llhttp tuple joins; never a two-provider Rust admission."""
import ast
import hashlib
import importlib.util
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent
NAME='cachy-asahi-llhttp-reference'
EXPECTED349={'bytes':6800,'sha256':'579981195b654d8cdf142e4101dfc2bfffbc3576eed50f23796a06e90cf57453'}

def need(value,why):
    if not value:raise ValueError('consumer bridge: '+why)

def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())

def read(path,cap=8*1024**2):
    spec=importlib.util.spec_from_file_location('libgit2_bridge_contract',HERE/'base/contract.py' if (HERE/'base/contract.py').exists() else HERE/'contract.py')
    C=importlib.util.module_from_spec(spec);spec.loader.exec_module(C)
    return C.read(path,cap)

def interface(root):
    root=Path(root);need(root.is_absolute() and root==root.resolve(),'explicit ordinary immutable consumer root')
    proof=json.loads(read(HERE/'consumer-interface-pin.json'))
    need(proof['commit']=='14ddf20677652e1d4057798ddf04734924668ae9','frozen consumer interface revision')
    for name,wanted in proof['files'].items():need(pin(read(root/name))==wanted,'whole immutable consumer helper: '+name)
    path=root/(proof['family']+'admission.py')
    spec=importlib.util.spec_from_file_location('libgit2_frozen_consumer',path);A=importlib.util.module_from_spec(spec);spec.loader.exec_module(A)
    return A,proof

def row_policy(A,row,trust):
    """Reuse every row predicate; project ONLY exact two-package cardinality.

    This cannot call Rust admit/prepare_context, nor qualify its parent image.
    """
    text=read(A.HERE/'admission.py').decode();node,=[n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef) and n.name=='validate_policy']
    original=ast.get_source_segment(text,node)
    changes=(('len(rows) == 2','len(rows) == 1'),("{r.get('name') for r in rows} == set(SPECS)","{r.get('name') for r in rows} == {'cachy-asahi-llhttp-reference'}"))
    projected=original
    for before,after in changes:
        need(projected.count(before)==1,'finite single-row cardinality projection');projected=projected.replace(before,after)
    inverse=projected
    for before,after in reversed(changes):inverse=inverse.replace(after,before)
    need(inverse==original,'whole unchanged consumer row-policy inverse')
    scope=dict(A.__dict__);exec(compile(projected,'<single llhttp cardinality only>','exec'),scope)
    policy=dict(schema=1,kind='PROJECT_TEST_NATIVE_BUILD_DEPENDENCIES_V1',predecessor=A.PREDECESSOR,parent350=A.D.PARENT350,trust=trust,packages=[row],qualification=A.QUALIFICATION,actual=A.ACTUAL)
    return scope['validate_policy'](policy)

def evidence_files(A,root,row):
    """Exact finite original source/build receipt closure, without extraction."""
    names=set(row['license_provenance']['recipe_files'])|set(row['license_provenance']['license_files'])|set(row['license_provenance']['sources'])
    for pair in row['native']['builds']:
        names.update(pair[k]['path'] for k in ('provenance','validation'))
        folder=Path(pair['provenance']['path']).parent
        record=A.decode(read(root/pair['provenance']['path'],1024**2))
        names.update(str(folder/n) for n in record['files'])
        prefix=Path(row['license_provenance']['pkgbuild']['path']).parent
        names.update(str(folder/'inputs'/Path(n).relative_to(prefix)) for n in row['license_provenance']['recipe_files'])
    names.add(row['native']['comparison']['path']);need(0<len(names)<=512,'finite full receipt closure')
    result={};total=0
    for name in sorted(names):
        A.D.relative(name);raw=read(root/name);total+=len(raw);need(total<=32*1024**2,'bounded full receipt bytes');result[name]=pin(raw)
    return result

def validate(paths,expected,consumer_root,native,package_metadata):
    A,proof=interface(consumer_root);root=Path(paths['native_receipt']).parent
    selected=native.get('consumer');need(type(selected) is dict and set(selected)=={'row','files'},'complete shared consumer row and evidence closure required')
    row=selected['row'];need(row.get('name')==NAME,'llhttp alone is this producer dependency')
    trust=dict(scope='PROJECT_TEST_ONLY',public_key=dict(path='public-test.gpg',**expected['pins']['public_key']),primary_fingerprint=expected['fingerprint'],signing_fingerprint=expected.get('signing_fingerprint'),ALARM_authentication=False)
    row_policy(A,row,trust)
    original=proof['original_llhttp_recipe'];prefix='dependency-provenance/'+NAME+'/'
    wanted={prefix+n:v for n,v in original['files'].items()}
    wanted[prefix+original['archive']['filename']]={k:original['archive'][k] for k in ('bytes','sha256')}
    need(row['license_provenance']['recipe_files']==wanted,'all unchanged original7e4 recipe/source bytes also match consumer fed5 snapshot')
    need(row['archive']==expected['pins']['package'] and row['signature']==expected['pins']['signature'],'identical shared package/signature bytes')
    need(all(row['metadata'][key]==package_metadata.get(key,[]) for key in row['metadata']),'identical observed eight-field package metadata')
    A.public_key(read(paths['public_key'],A.S.MAX_PUBLIC),trust)
    packets=A.S.packets(read(paths['signature'],16384));need(len(packets)==1 and packets[0][0]==2,'same binary detached signature framing')
    files=evidence_files(A,root,row);need(files==selected['files'],'every selected source/native receipt byte pinned')
    source=A.audit_source(root,row);N=A.module(A.HERE/'native.py');native_result=N.validate(root,row)
    need(native_result['inventory']==EXPECTED349,'genuine llhttp producer signed349 inventory, separate from Rust parent350')
    archive=A.module(A.HERE/'archive.py').audit(Path(paths['package']),row,A.D)
    need(evidence_files(A,root,row)==files,'complete source/native custody after validation')
    return dict(kind='LLHTTP_SHARED_CONSUMER_TUPLE_DATA_V1',interface_commit=proof['commit'],row=pin(A.encode(row)),files=files,source=source,native=native_result,archive=archive,providers=row['providers'],signing_fingerprint=trust['signing_fingerprint'],primary_fingerprint=trust['primary_fingerprint'],signature_mathematics_verified=False,native_acceptance=False,Root_acceptance=None,Rust_two_provider_admission='NOT RUN; both providers and separate Rust policy required')

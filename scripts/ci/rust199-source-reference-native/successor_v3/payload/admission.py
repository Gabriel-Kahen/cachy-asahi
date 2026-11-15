# SPDX-License-Identifier: MIT
"""Exact LLVM v2 input rejoin over frozen Rust qualification gates; DATA only."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re

HERE=Path(__file__).resolve().parent
BASE_SHA='a548f56b0759ae2ecd90ee79fed8c1e254a032dbaa0726f15e673e139b946c30'
path=HERE/'frozen/rust199-admission-v1.py';raw=path.read_bytes()
if hashlib.sha256(raw).hexdigest()!=BASE_SHA:raise ValueError('whole frozen Rust admission gate differs')
spec=importlib.util.spec_from_file_location('rust199_held_admission_v1',path);BASE=importlib.util.module_from_spec(spec)
exec(compile(raw,str(path),'exec'),BASE.__dict__)
def same(value,expected):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)==json.dumps(expected,sort_keys=True,separators=(',',':'),allow_nan=False)


OLD_LLVM_SOURCE='4ceaa1c6958349451197b19acdb084a2a5be216b'
LLVM_SOURCE='6d0243dc8f5cf4ee5b9316b8c804f14a3236ecb0'
if BASE.LLVM_SOURCE!=OLD_LLVM_SOURCE:raise ValueError('exact v1-to-v2 Source literal derivation required')
BASE.LLVM_SOURCE=LLVM_SOURCE
for name in ('MIB','GIB','TARGET','CANDIDATE','INPUTS_SHA','LLVM_PACKAGE','LLVM_ARCHIVE','BASELINE_SHA','PROPOSAL','CLAIMS','MATERIALS',
             'need','sha','keys','path','selector','descriptor','read_file','decode','read_json','material_rows','original_join','candidate_qualification','readonly_subpath'):
    globals()[name]=getattr(BASE,name)

IDENTITY=dict(sha=LLVM_SOURCE,ref='refs/heads/codex/llvm23-source-reference-native-v2-20261115',
    tree='87f5aa3537474c2dd33a02c50e869ea5fb25e7b4',map_sha256='809f57839dfd574b7abf0c65535321aeac08c58608d4f9597f936a7af78fb3a2',
    files=251,bytes=40807998,profile_sha256='587145a6935726e7efe898963f126da1fe399dbde157930f83a1826e5e513e4b',operation='llvm23-source-reference-native-v2')
POLICY_PIN=dict(bytes=1114,sha256='e69b47708f171a63b7fcdcc413d6b53070f047e7240723f06115c02049c8b544')
READER_PROGRAM=dict(path='hosted/reader.py',bytes=15764,sha256='b939343e3607b985e79c70c8f420e1a26dadf8433242d17df11b8b5be21eacb1')
METADATA=decode((HERE/'llvm-v2/source.json').read_bytes())
keys(METADATA,{'schema','identity','policy','policy_pin','reader_program','contract_pin','candidate_map_pin','actual'},'exact pinned LLVM v2 Source metadata')
need(type(METADATA['schema'])is int and METADATA['schema']==1 and same(METADATA['identity'],IDENTITY) and
     same(METADATA['policy_pin'],POLICY_PIN) and same(METADATA['reader_program'],READER_PROGRAM) and
     METADATA['actual']==dict.fromkeys(('run','job','original','package','reader','root_acceptance')),'published Source is not an actual accepted build')
for filename,expected in (('policy.json',POLICY_PIN),('reader.py',READER_PROGRAM),('contract.json',METADATA['contract_pin']),('candidate-map.json',METADATA['candidate_map_pin'])):
    body=(HERE/'llvm-v2'/filename).read_bytes()
    need(dict(bytes=len(body),sha256=hashlib.sha256(body).hexdigest())=={k:expected[k] for k in ('bytes','sha256')},'retained LLVM v2 DATA leaf differs: '+filename)
POLICY=dict(**POLICY_PIN,resources=decode((HERE/'llvm-v2/policy.json').read_bytes()))
need(same(POLICY['resources'],METADATA['policy']),'exact retained policy value differs')
EXTRA={'source_identity','policy','reader'}
LLVM_KEYS={'source','archive','signature','public_test_key','verification_proof','root_decision','artifact','original'}
BINDING_KEYS={'source','ref','run','job','source_map_sha256','approval','export_sha256','image','operation','scope'}
READER_HOLDS='original4/source108/native16K/M2/performance/release remain held'
READER_SCOPE='Authenticated Root role observations and complete package DATA parity, not independent machine attestation or release admission'


def projection(a):
    need(type(a)is dict and type(a.get('llvm'))is dict,'complete Root admission and LLVM material required')
    keys(a['llvm'],LLVM_KEYS|EXTRA,'exact LLVM v2 material, policy and Reader rejoin required')
    result=copy.deepcopy(a)
    for name in EXTRA:del result['llvm'][name]
    return result


def llvm_declaration(llvm):
    keys(llvm,LLVM_KEYS|EXTRA,'exact LLVM v2 material, policy and Reader rejoin required')
    need(same(llvm['source_identity'],IDENTITY) and same(llvm['policy'],POLICY) and
         type(llvm['source'])is dict and llvm['source'].get('ref')==IDENTITY['ref'],'exact v2 Source/ref/tree/map/profile and policy required')
    BASE.llvm_declaration({k:v for k,v in llvm.items() if k not in EXTRA})
    llvm_package_bound(llvm['archive']['bytes'])
    reader=llvm['reader'];keys(reader,{'program','binding','result'},'actual v2 Reader program/binding/result required')
    need(same(reader['program'],READER_PROGRAM),'Reader must be the exact program from published v2 Source')
    descriptor(reader['binding'],fixed_path='/inputs/llvm-v2-reader-binding.json')
    descriptor(reader['result'],fixed_path='/inputs/llvm-v2-reader.json')


def llvm_package_bound(size):
    need(type(size)is int and 0<size<=POLICY['resources']['package_bytes'],'LLVM package must fit the exact accepted v2 package policy')


def reader_binding(value,llvm):
    need(type(value)is dict and BINDING_KEYS<=set(value),'complete actual Reader binding required')
    expected=dict(source=llvm['source']['sha'],ref=llvm['source']['ref'],run=llvm['source']['run'],job=llvm['source']['job'],
        source_map_sha256=IDENTITY['map_sha256'],operation=IDENTITY['operation'],scope='ROOT_AUTHENTICATED_LLVM23_DATA_READER_ONLY')
    need(all(value.get(k)==v for k,v in expected.items()) and sha(value['approval']) and sha(value['export_sha256']) and
         type(value['image'])is str and re.fullmatch('sha256:[0-9a-f]{64}',value['image']) and
         ('schema' not in value or type(value['schema'])is int and value['schema']==1),'Reader binding must join exact v2 Source/run/job/map/operation')
    return {k:value[k] for k in BINDING_KEYS}


def reader_result(value,binding,llvm):
    keys(value,{'schema','status','source','run','job','image','package','payload_entries','native_acceptance','holds','scope'},'whole actual v2 Reader result required')
    need(type(value['schema'])is int and value['schema']==1 and value['status']=='PASS_LLVM23_NATIVE_BUILD_DATA_PARITY_ONLY' and
         all(value[k]==binding[k] for k in ('source','run','job','image')) and
         same(value['package'],{k:llvm['archive'][k] for k in ('bytes','sha256')}) and
         type(value['payload_entries'])is int and 0<value['payload_entries']<=400000 and value['native_acceptance']is False and
         value['holds']==READER_HOLDS and value['scope']==READER_SCOPE,'Reader result must join package DATA and preserve all acceptance holds')


def decision_rejoin(decision,binding,llvm):
    need(type(decision)is dict and type(decision.get('llvm_v2'))is dict,'Root decision must explicitly accept the v2 rejoin')
    expected=dict(source_identity=IDENTITY,policy=POLICY,reader_program_sha256=READER_PROGRAM['sha256'],
        reader_binding_sha256=llvm['reader']['binding']['sha256'],reader_result_sha256=llvm['reader']['result']['sha256'],reader_binding=binding)
    need(same(decision['llvm_v2'],expected),'Root v2 decision must bind exact policy, Reader bytes, actual binding and result')


def _json(row):
    read_file(row['local_path'],4*MIB,row)
    return read_json(row['local_path'],row['sha256'])


def external_proofs(a):
    """Both host and actor repeat v2 body joins; no package execution or acquisition."""
    llvm_declaration(a['llvm']);legacy=projection(a)
    llvm=a['llvm'];binding=reader_binding(_json(llvm['reader']['binding']),llvm)
    reader_result(_json(llvm['reader']['result']),binding,llvm)
    decision_rejoin(_json(llvm['root_decision']),binding,llvm)
    BASE.external_proofs(legacy)


def validate(a,check_files=True):
    need(type(check_files)is bool,'explicit file-check mode required')
    legacy=projection(a);BASE.validate(legacy,check_files=False);llvm_declaration(a['llvm'])
    material_rows(a['materials'],check_files)
    if check_files:
        external_proofs(a)
        for key,cap in (('archive',8*GIB),('signature',MIB),('public_test_key',8*MIB)):
            row=a['llvm'][key];read_file(row['local_path'],cap,row)
        for row in a['materials']:read_file(row['local_path'],row['bytes'],row)
    return copy.deepcopy(a)

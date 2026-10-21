# SPDX-License-Identifier: MIT
"""Closed source roles and finite native606/Boot input authority; NULL refuses."""
import contextlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import accepted_inputs as A
HERE=Path(__file__).resolve().parent
ROOT=HERE.parent
LANE='boot607'
MANIFEST='boot607/source-manifest.json'
WORKFLOWS={'.github/workflows/native-arm-build.yml','.github/workflows/native-arm-current606-boot607.yml'}
CARRIER='4decb87f5b15f8828cea31e75cbf9e4381feaeaa'
CARRIER_REF='codex/boot-report-current606-native-inputs-v1'
PRIOR_SOURCE='3660e6cb87b4cb5591b1d295c62c8b02cca4b7e6'
PRIOR_AUTH_SHA256='55c36b4acf844f0fc068e153c5e703101d148cabd32640dc5673a9777b7d5000'

@contextlib.contextmanager
def aliases(values):
    missing=object();saved={k:sys.modules.get(k,missing) for k in values}
    try:
        sys.modules.update(values);yield
    finally:
        for k,v in saved.items():
            if v is missing:sys.modules.pop(k,None)
            else:sys.modules[k]=v

def module(name,path,values=None):
    with aliases(values or {}):
        spec=importlib.util.spec_from_file_location(name,path)
        value=importlib.util.module_from_spec(spec);sys.modules[name]=value;spec.loader.exec_module(value);return value

def original_context():
    owner=ROOT/'scripts/ci/current606-apps7-closed-owner'
    S=module('_boot607_whole_original606_selection',owner/'selection.py')
    O=module('_boot607_whole_apps350_source_contract',owner/'contract.py',{'selection':S})
    with aliases({'selection':S}):O.roles(ROOT)
    root=ROOT/'held606'
    P=module('_boot607_whole_native606_contract',root/'scripts/ci/current606-native/contract.py')
    old=module('_boot607_whole_native606_adapter',root/'scripts/ci/current606-native/adapter.py',{'contract':P})
    builds=module('_boot607_whole_native606_build_pairs',root/'scripts/ci/current606-native/build_pairs.py',{'contract':P})
    bridge=module('_boot607_whole_native606_bridge',root/'scripts/ci/current606-native/bridge606.py',{'contract':P,'adapter':old,'build_pairs':builds})
    C=module('_boot607_whole_native604_contract',root/'held604'/P.OLD/'contract.py')
    return O,S,P,old,bridge,C

def verify():
    A.need(not sys.flags.optimize,'optimized source guards refused')
    manifest=A.decode(A.read(ROOT/MANIFEST,4*1024**2))
    A.need(manifest['schema_version']==1 and manifest['status']=='SOURCE_ONLY_NATIVE606_BOOT607_NOT_ACCEPTED' and
           all(manifest[k] is None for k in ('actual_source','actual_ref','actual_run')), 'source-only complete manifest')
    files=manifest['files']
    actual=set()
    for p in ROOT.rglob('*'):
        if p.relative_to(ROOT).parts[0]=='.git':continue
        A.need(not p.is_symlink(),'whole source directory/leaf alias')
        if p.is_file():actual.add(p.relative_to(ROOT).as_posix())
    A.need(actual==set(files)|WORKFLOWS|{MANIFEST},'complete closed native Boot source closure')
    for name,expected in files.items():
        A.relative(name);A.need(A.pin(A.read(ROOT/name))==expected,'whole native Boot source drift: '+name)
    prior=A.read(HERE/'prior348-authorization.json',1024**2)
    A.need(A.pin(prior)['sha256']==PRIOR_AUTH_SHA256,'genuine complete348 predecessor source authorization')
    authorization=A.decode(prior)
    A.need(len(authorization)==348,'whole predecessor348 source role')
    for name,expected in authorization.items():
        # The main registered workflow is the sole predecessor leaf changed.
        path=HERE/'prior-native-arm-build.yml' if name=='.github/workflows/native-arm-build.yml' else ROOT/name
        A.need(A.pin(A.read(path))==expected,'complete348 source inverse before pin: '+name)
    boot_auth=A.read(HERE/'boot79-authorization.json',1024**2)
    A.need(A.pin(boot_auth)['sha256']=='c771dd294a6bf92d7b37c7854f8c9a0cdb38025e2921f7edf88c161df485eae8','whole original accepted79 authorization')
    boot_files=A.decode(boot_auth);staged=A.decode(A.read(HERE/'boot79-staged-source.json',1024**2))
    A.need(len(boot_files)==79 and set(staged)=={n for n in files if n.startswith('boot607/accepted-boot79/')},'exact complete staged original fixture/product subset')
    for name,row in staged.items():
        A.need(set(row)=={'original','bytes','sha256'} and boot_files[row['original']]=={k:row[k] for k in ('bytes','sha256')} and
               A.pin(A.read(ROOT/name))==boot_files[row['original']],'original accepted fixture/product bytes held')
    import workflow
    expected=workflow.derive((HERE/'prior-native-arm-build.yml').read_bytes(),A.pin(A.read(HERE/'run.py')),A.pin(A.read(ROOT/MANIFEST)))
    A.need(all(A.read(ROOT/name)==expected for name in WORKFLOWS),'entire workflow finite inverse/stamps')
    O,S,P,old,bridge,C=original_context();P.verify(bound=False)
    import owner_adapter,transaction_adapter
    owner_adapter.owner(old.owner(ROOT/'held606'))
    owner_adapter.consumer((P.HERE/'tools606.py').read_text())
    transaction_adapter.derive((ROOT/transaction_adapter.ORIGINAL).read_text())
    import transport_scope
    transport_scope.verify(ROOT)
    return dict(status=manifest['status'],files=len(actual),prior_source=PRIOR_SOURCE,held_native606_files=263,actual_source=None,actual_ref=None,actual_run=None)

def authorize():
    policy=A.decode(A.read(HERE/'input-policy.json',1024**2))
    A.need(policy['schema_version']==1 and policy['purpose']=='CURRENT606_NATIVE_ACCEPTED_BOOT_SYNTHETIC_COMPONENT' and
           all(policy[k] is None for k in ('actual_source','actual_ref','actual_run')), 'finite prospective Boot policy')
    A.need(policy['status']=='ROOT_BOUND_ACCEPTED606_AND_BOOT79','native Boot authority NULL/UNBOUND; refuse before actors')
    O,S,P,old,bridge,C=original_context()
    decision=S.decision(policy['current606'])
    A.need(policy['source_manifest606']==decision['source_manifest'] and policy['expected606_sha256']==S.LOCK and
           policy['current606']['source']=='f3a30f2049f57d9f3cb2433fbd59af51d4cc5720' and policy['current606']['run']==39106953257 and
           policy['boot_carrier']==dict(source=CARRIER,ref=CARRIER_REF,index=A.INDEX), 'original genuine606 and accepted Boot input roles')
    P.verify()
    return policy

def public_checkout(packet):
    authorize();packet=Path(packet).absolute()
    result=subprocess.run(['git','-C',str(packet),'rev-parse','HEAD'],capture_output=True,text=True,check=True,timeout=15)
    A.need(result.stdout.strip()==CARRIER,'exact genuine published Boot carrier checkout')
    checks=module('_boot607_native_input_package_inspector',ROOT/'held606/held-tools/scripts/checks/package_checks.py')
    return A.inspect(packet/'payload',checks)

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Overlay the pinned namespace composer for fresh runtime54 DATA packets only."""
import argparse
import ast
import importlib.util
import json
from pathlib import Path
import sys

HERE=Path(__file__).resolve().parent
sys.dont_write_bytecode=True
sys.path.insert(0,str(HERE))
import runtime54 as R

RUNTIME_FUNCTION=b'''
def runtime54_adapter():
 raw=(T/'input-seal.json').read_bytes();need(pin(raw)['sha256']==INPUT_SEAL,'fixed runtime54 input closure')
 path=T/'runtime54.py';adapter=load('_Root_bound_existing_runtime54',path,json.loads(raw)[str(path)]['sha256'])
 adapter.binding(T/'runtime54-binding.json',json.loads(raw)[str(T/'runtime54-binding.json')]);return adapter

'''
BOOT_OLD=b" U,S,L=C.modules();return C,U,S,L"
BOOT_NEW=b" C.runtime_lock_identity=runtime54_adapter().factory(T/'runtime54-binding.json',json.loads(raw)[str(T/'runtime54-binding.json')])\n U,S,L=C.modules();return C,U,S,L"
VERIFY_OLD=b" need(type(binding)is dict and binding.get('status')=='ROOT_BOUND_NAMESPACE_FACTORY_CI_MAIN' and binding.get('approved')is True,'PR433 factory CI/Main binding pending; HOLD before bootstrap or role output')"
VERIFY_NEW=VERIFY_OLD+b'\n runtime54_adapter()'
REVIEW_OLD=b'original9d_same_inode55_59258250_sameFD_PIDFD_starttime_independent_NB_CLOSE_ONLY'
REVIEW_NEW=b'original9d_same_inode54_59258250_sameFD_PIDFD_starttime_independent_NB_CLOSE_ONLY'


def encoded(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def composer():
    manifest=R.obj(R.read(HERE/'composer-inputs.json'));root=Path(manifest['root'])
    R.need(manifest['commit']=='5e23a55670d84162f03f7e0586917411bdb6cf06','exact reviewed composer commit')
    # Verify every committed composer operand before importing only its DATA composer.
    for name,row in manifest['files'].items():
        raw=(root/name).read_bytes()
        R.need(R.pin(raw)==row and root/name==(root/name).resolve() and not any(p.is_symlink() for p in (root/name,*(root/name).parents)),'whole committed composer operand '+name)
    path=root/'scripts/ci/native-build-namespace-admission-preparation/prepare.py'
    spec=importlib.util.spec_from_file_location('_held_namespace_DATA_composer',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    for name,row in manifest['files'].items():R.need(R.pin(module.read(root/name))==row,'stable ordinary committed composer operand '+name)
    return module,manifest


def replace_once(raw,old,new):
    R.need(raw.count(old)==1,'one exact reviewed operator seam')
    return raw.replace(old,new,1)


def overlay(P,data,output,root_profile=None,root_profile_sha256=None,manifest=None):
    files=P.render(data,output);output=Path(output)
    old_input=R.pin(files['input-seal.json'])['sha256'].encode()
    old_native=R.pin(files['ROOT-NATIVE-ONCE.py'])['sha256'].encode()
    reference=dict(path=None,bytes=None,sha256=None)
    if root_profile is not None:
        R.need(root_profile!=R.LOCK,'shared lock is never a profile operand')
        raw=P.read(root_profile,65536);R.need(R.pin(raw)['sha256']==root_profile_sha256,'external Root runtime54 whole profile pin')
        R.profile(R.obj(raw));reference=dict(path=str(root_profile),**R.pin(raw))
    else:R.need(root_profile_sha256 is None,'no runtime54 pin without external Root profile')
    files['runtime54-binding.json']=encoded(reference)
    files['runtime54.py']=P.read(HERE/'runtime54.py')
    files['Root-runtime54-profile.TEMPLATE.json']=P.read(HERE/'Root-runtime54-profile.TEMPLATE.json')
    files['Root-authority.TEMPLATE.json']=replace_once(files['Root-authority.TEMPLATE.json'],REVIEW_OLD,REVIEW_NEW)
    facts=P.obj(files['facts.json']);facts['runtime_lock']=dict(status='UNISSUED_ROOT_RUNTIME54_PROFILE' if root_profile is None else 'EXTERNAL_ROOT_RUNTIME54_IDENTITY_ONLY',binding=reference,resource_authority=False,original9d_sha256='9d014a2c5405f2ba5a478143545629cd5499eda2218a7306ca20cd4f24d5f94f')
    files['facts.json']=encoded(facts)
    native=replace_once(files['ROOT-NATIVE-ONCE.py'],BOOT_OLD,BOOT_NEW)
    native=replace_once(native,VERIFY_OLD,VERIFY_NEW)
    native=replace_once(native,b'def bootstrap():',RUNTIME_FUNCTION+b'def bootstrap():')
    index=dict(data['external'])
    if manifest is not None:
        index.update({str(Path(manifest['root'])/n):r for n,r in manifest['files'].items()})
    if root_profile is not None:index[str(root_profile)]=R.pin(raw)
    omitted={'ROOT-NATIVE-ONCE.py','ROOT-INDEPENDENT-PREFLIGHT.py','input-seal.json','seal.json','root-commands.json'}
    for name,body in files.items():
        if name not in omitted:index[str(output/name)]=R.pin(body)
    R.need(len(index)<=256,'finite existing closure plus exact runtime54 inputs')
    files['input-seal.json']=encoded(index)
    native=replace_once(native,old_input,R.pin(files['input-seal.json'])['sha256'].encode());files['ROOT-NATIVE-ONCE.py']=native
    files['ROOT-INDEPENDENT-PREFLIGHT.py']=replace_once(files['ROOT-INDEPENDENT-PREFLIGHT.py'],old_native,R.pin(native)['sha256'].encode())
    for name,body in files.items():
        if name.endswith('.py'):ast.parse(body,filename=name)
    seal=P.obj(files['seal.json']);seal['status']='SEALED_FRESH_NAMESPACE_RUNTIME54_UNISSUED_ROOT_PROFILE' if root_profile is None else 'SEALED_FRESH_NAMESPACE_RUNTIME54_ROOT_IDENTITY_BOUND_NOT_RESOURCE_AUTHORITY'
    seal['files']={n:R.pin(b) for n,b in files.items() if n not in {'seal.json','root-commands.json'}};files['seal.json']=encoded(seal)
    command=P.obj(files['root-commands.json']);command['packet_seal']=R.pin(files['seal.json']);command['runtime54_profile_pending']=root_profile is None
    for key in ('preflight','native'):
        argv=command[key]['argv'];argv[argv.index('--seal')+1]=command['packet_seal']['sha256']
    files['root-commands.json']=encoded(command)
    return files


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--factory-binding',type=Path);parser.add_argument('--factory-binding-sha256')
    parser.add_argument('--root-runtime-profile',type=Path);parser.add_argument('--root-runtime-profile-sha256')
    parser.add_argument('--output',type=Path)
    args=parser.parse_args();P,manifest=composer()
    data=P.inputs(P.SOURCE_ROOT,args.factory_binding,args.factory_binding_sha256)
    # Validate even when no output was requested; rendering itself is pure DATA.
    output=args.output or Path('/UNWRITTEN/fresh-runtime54-DATA')
    files=overlay(P,data,output,args.root_runtime_profile,args.root_runtime_profile_sha256,manifest)
    if args.output is not None:P.publish(files,args.output)
    print(json.dumps(dict(status='VALIDATED_RUNTIME54_OVERLAY_DATA_ONLY',runtime_profile_issued=args.root_runtime_profile is not None,
        factory_binding_pending=data['binding']is None,packet_written=args.output is not None,files=len(files),
        Native_POSTs=0,Original_GETs=0,Reader_calls=0,lease_acquisitions=0,resource_authority_issued=False,acceptance=False),sort_keys=True))


if __name__=='__main__':main()

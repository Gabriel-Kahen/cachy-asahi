#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Copy only exact indexed public inputs into fresh Git-metadata-free packets."""
import argparse
import json
from pathlib import Path
import shutil
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as C


def stage(source,setup5,modules,out):
    C.verify_source(source);source,setup5,modules,out=map(C.safe,(source,setup5,modules,out));C.need(not out.exists(),'fresh staged input root required')
    C.need(not any(out.is_relative_to(p) or p.is_relative_to(out) for p in (source,setup5,modules)),'staged packets must be separate')
    H=C.load('accepted_setup5_input_gate',source/'scripts/ci/setup5-real-modules/run.py')
    old_ref=dict(path='index.json',bytes=25005,sha256=H.INDEX_SHA);old=C.read(C.checked(setup5,old_ref));new_ref=C.policy()['module_index'];new=C.read(C.checked(modules,new_ref));refs={}
    def collect(value):
        if type(value) is dict:
            if set(value)=={'path','bytes','sha256'}:
                C.need(value['path'] not in refs or refs[value['path']]==value,'conflicting public input references');refs[value['path']]=value
            else:
                for child in value.values():collect(child)
        elif type(value) is list:
            for child in value:collect(child)
    collect(new);C.need(len(refs)==153,'closed six-module file reference count differs')
    out.mkdir(mode=0o700)
    def copy(root,target,ref):
        original=C.checked(root,ref);dest=target/ref['path'];dest.parent.mkdir(parents=True,exist_ok=True,mode=0o700);shutil.copyfile(original,dest);C.checked(target,ref)
    for role,root,index,rows in (('setup5',setup5,old_ref,[dict(path=n,**r) for n,r in old['files'].items()]),('modules',modules,new_ref,list(refs.values()))):
        target=out/role;target.mkdir(mode=0o700)
        for ref in [index,*rows]:copy(root,target,ref)
    # Setup5's accepted outer README is documentation, with an exact bounded root.
    readme=C.safe(setup5/'README.md');C.need(readme.is_file() and readme.stat().st_size==345,'accepted setup5 outer README size differs');shutil.copyfile(readme,out/'setup5/README.md')
    proof=out/'setup5-cli-check';proof.mkdir();H.accepted_cli(out/'setup5',proof)
    sys.path[:0]=[str(source/'scripts/checks'),str(source/'scripts/build')];checks=C.load('packet_package_checks',source/'scripts/checks/package_checks.py');bind=C.load('packet_build_binding',source/'scripts/build/build.py');C.module_rows(out/'modules',source,checks,bind)
    result=dict(status='PASS_PASSIVE_ROOT_BOUND_PACKET_STAGING',setup5_files=149,six_module_files=154,setup5_index_sha256=H.INDEX_SHA,module_index=new_ref,module_source_ref=C.policy()['module_source_ref'],native_runtime='NOT_RUN')
    (out/'receipt.json').write_text(json.dumps(result,indent=2)+'\n');return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('source','setup5-checkout','modules-checkout','output'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();print(json.dumps(stage(a.source.absolute(),a.setup5_checkout.absolute(),a.modules_checkout.absolute(),a.output.absolute())))

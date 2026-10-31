#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fail closed before secrets, cache mutation and native actors."""
import argparse
import os
from pathlib import Path
import shutil
import stat
import subprocess
import contract as C


def own_source(root,revision):
    C.need(C.revision(root)==revision,'implementation revision differs')
    pins=C.read(C.HERE/'source-manifest.json')
    for name,row in pins.items():C.checked(root,dict(path=name,**row))
    manifest=str((C.HERE/'source-manifest.json').relative_to(root))
    subprocess.run(['git','-C',str(root),'diff','--exit-code','HEAD','--',manifest,*pins],check=True,capture_output=True,timeout=15)


def installer(root,policy):
    C.need(C.revision(root)==policy['installer_source'],'Root-bound fresh600 producer implementation required')
    api=C.load('_root600_installer_contract',root/'scripts/ci/expanded600-installer-vm/contract.py')
    pins=api.read(api.HERE/'source-manifest.json')
    for name,row in pins.items():api.checked(root,dict(path=name,**row))
    subprocess.run(['git','-C',str(root),'diff','--exit-code','HEAD','--',str((api.HERE/'source-manifest.json').relative_to(root)),*pins],check=True,capture_output=True,timeout=15)
    value=api.policy();C.need(value['eight_pair_source']==C.EIGHT,'exact final eight-pair producer required')
    module=C.load('_root600_materializer',api.HERE/'materializer.py');module.C=api
    return api,module,value


def packet_member(checkout,name,row):
    ref=dict(path=name,**row)
    if row['bytes']!=0:return C.checked(checkout,ref)
    C.need(set(ref)=={'path','bytes','sha256'} and type(row['bytes']) is int and
         row['sha256']=='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
         'exact empty raw reference required')
    relative=Path(name);C.need(not relative.is_absolute() and relative.parts and
        all(p not in ('.','..') for p in relative.parts),'safe empty record path required')
    path=C.safe(checkout/relative);info=path.lstat()
    C.need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size==0,
         'ordinary single-link empty raw input required')
    identity=lambda value:(value.st_dev,value.st_ino,value.st_mode,value.st_nlink,value.st_uid,
        value.st_gid,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
    with path.open('rb') as stream:
        C.need(identity(os.fstat(stream.fileno()))==identity(info) and stream.read(1)==b'' and
            identity(os.fstat(stream.fileno()))==identity(info),'empty raw input changed during read')
    C.need(identity(path.lstat())==identity(info),'empty raw path changed');return path


def stage_pair(checkout,target):
    """Copy all149 accepted members, including the exact zero-byte raw log."""
    C.need(C.revision(checkout)==C.PAIR and not target.exists(),'accepted pair source and fresh data staging required')
    index=checkout/'index.json';C.need(index.stat().st_size==25005 and C.sha(index)=='b1e4208d2f32935f2e5cb1c1e3535cc49f44c7bfe08e7d64692b8ac3781d5a5d','accepted149 index required')
    value=C.read(index);C.need(len(value['files'])==147,'accepted147 indexed files required')
    # Validate the whole input before making output or copying any executable bytes.
    members={name:packet_member(checkout,name,row) for name,row in value['files'].items()}
    readme=C.safe(checkout/'README.md');info=readme.lstat()
    C.need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size==345,'ordinary accepted README required')
    target.mkdir(mode=0o700)
    for name,path in members.items():
        dest=target/name;dest.parent.mkdir(mode=0o700,parents=True,exist_ok=True);shutil.copyfile(path,dest)
    for name in ('index.json','README.md'):shutil.copyfile(C.safe(checkout/name),target/name)
    accepted=C.load('_root600_accepted_data',C.HERE/'accepted_pair.py')
    proof=target.parent/'pair-inspection';proof.mkdir(mode=0o700)
    try:accepted.accepted_cli(target,proof)
    finally:shutil.rmtree(proof)
    return target


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('implementation','installer-source','decision-source','legacy-source','seven-pairs','eight-pairs','setup5-checkout','upgrader-source'):
        p.add_argument('--'+name,type=Path)
    p.add_argument('--source',required=True);p.add_argument('--workflow-sha',required=True)
    p.add_argument('--case',choices=tuple(C.SOURCES),required=True);p.add_argument('--preflight',action='store_true');a=p.parse_args()
    value=C.policy() # Must remain first: pending evidence cannot authorize any actor.
    C.need(a.source==a.workflow_sha and len(a.source)==40,'manual workflow/source identity differs')
    own_source(C.safe(a.implementation.absolute()),a.source)
    if a.preflight:
        output=os.environ.get('GITHUB_OUTPUT')
        if output:
            with Path(output).open('a') as stream:
                for key,val in {'installer_source':value['installer_source'],'decision_source':value['decision_source'],
                                'upgrader_source':C.SOURCES[a.case]}.items():stream.write(key+'='+val+'\n')
        print('EXPANDED600_ROOT_UPGRADE_PREFLIGHT=PASS actors=NOT_RUN');return 0
    C.need(all(getattr(a,n) for n in ('installer_source','decision_source','legacy_source','seven_pairs','eight_pairs','setup5_checkout','upgrader_source')),'all immutable source checkouts required')
    C.need(C.revision(a.decision_source)==value['decision_source'],'Root decision source differs');C.prerequisites(a.decision_source,value)
    api,materializer,old=installer(a.installer_source,value);api.legacy(a.legacy_source)
    C.need(C.revision(a.seven_pairs)==api.SEVEN and C.revision(a.eight_pairs)==C.EIGHT and
         C.revision(a.setup5_checkout)==C.PAIR and C.revision(a.upgrader_source)==C.SOURCES[a.case],'held input source differs')
    api.prerequisites(a.eight_pairs,old);materializer.accepted_pairs(a.eight_pairs,a.seven_pairs,a.legacy_source,old)
    for name,row in C.read(C.HERE/'held-pins.json')[a.case]['pins'].items():C.checked(a.upgrader_source,dict(path=name,**row))
    # Full pair bytes are inspected in metadata-free staging again before producer actors.
    index=a.setup5_checkout/'index.json';C.need(C.sha(index)=='b1e4208d2f32935f2e5cb1c1e3535cc49f44c7bfe08e7d64692b8ac3781d5a5d','genuine Setup5 packet required')
    for name,row in C.read(index)['files'].items():packet_member(a.setup5_checkout,name,row)
    print('EXPANDED600_ROOT_UPGRADE_INPUTS=PASS actors=NOT_RUN');return 0


if __name__=='__main__':raise SystemExit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Manual source/accepted-input proof; requires Root's genuine original600 acceptance."""
import argparse
import hashlib
import os
import stat
from pathlib import Path
import shutil
import sys
import policy as P


def packet_source(root,ref):
    # Empty raw packet records are copied too; acceptance/archive references
    # keep the original positive-byte P.checked contract.
    if type(ref) is not dict or ref.get('bytes')!=0:return P.checked(root,ref)
    P.need(set(ref)=={'path','bytes','sha256'} and type(ref['bytes']) is int and
        type(ref['path']) is str and ref['path'] and not ref['path'].startswith('/') and
        all(part not in ('','.','..') for part in ref['path'].split('/')) and
        ref['sha256']==hashlib.sha256(b'').hexdigest(),'exact empty packet record reference required')
    path=P.safe(root/ref['path']);before=path.lstat()
    P.need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size==0,
        'ordinary single-link empty packet record required')
    identity=lambda info:(info.st_dev,info.st_ino,info.st_mode,info.st_nlink,info.st_uid,
        info.st_gid,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
    with path.open('rb') as stream:
        P.need(identity(os.fstat(stream.fileno()))==identity(before) and stream.read(1)==b'' and
            identity(os.fstat(stream.fileno()))==identity(before),'empty packet record changed during read')
    P.need(identity(path.lstat())==identity(before),'empty packet record path changed')
    return path


def stage_packet(checkout,out,probe):
    P.need(not out.exists(),'fresh metadata-free Setup5 staging required');P.safe(out)
    index=P.checked(checkout,dict(path='index.json',bytes=25005,sha256=P.INDEX));value=P.read(index)
    P.need(len(value.get('files',{}))==147,'exact accepted Setup5 packet required')
    out.mkdir(mode=0o700);target=out/'setup5';target.mkdir(mode=0o700)
    for name,row in [('index.json',P.ref(index)),*value['files'].items()]:
        source=packet_source(checkout,dict(path=name,bytes=row['bytes'],sha256=row['sha256']))
        dest=target/name;dest.parent.mkdir(parents=True,exist_ok=True,mode=0o700);shutil.copyfile(source,dest)
    readme=P.safe(checkout/'README.md');P.need(readme.is_file() and readme.stat().st_size==345,'accepted outer README shape')
    shutil.copyfile(readme,target/'README.md');proof=out/'passive-check';proof.mkdir(mode=0o700)
    H=P.load('setup5_full600_accepted_pair',probe/'scripts/ci/setup5-real-modules/run.py');H.accepted_cli(target,proof)
    return target


def verify(implementation,source,workflow_sha,baseline,probe,setup5,script_source,module_source):
    bound=P.policy();P.source(implementation)
    P.need(source==workflow_sha==P.revision(implementation),'new manual implementation/workflow identity differs')
    for root,revision in ((baseline,bound['baseline_source']),(probe,P.PROBE),(setup5,P.PAIR)):
        P.need(P.revision(root)==revision,'exact held source/accepted packet revision differs')
    folder=baseline/'scripts/ci/expanded-development-composition';sys.path.insert(0,str(folder))
    C=P.load('contract',folder/'contract.py');C.source(baseline);C.verify_self(baseline);old=C.policy()
    P.need(P.revision(script_source)==old['script_source'] and P.revision(module_source)==old['bang_source'],
        'original seven/bang2 source roots differ')
    inputs=P.load('setup5_gate_original_inputs',folder/'inputs.py');bang=P.load('setup5_gate_original_bang',folder/'bang.py')
    inputs.retained(script_source,C.read(C.checked(script_source,old['script_index'])),baseline)
    inputs.combined(module_source,old);bang.recipe(module_source,old,inputs.tools(baseline)[0])
    native=P.load('setup5_gate_real_native',probe/'scripts/ci/setup5-native-real-modules/contract.py');native.verify_source(probe)
    return bound


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('implementation','baseline','probe-source','setup5-checkout','script-source','module-source','output'):
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--source',required=True);p.add_argument('--workflow-sha',required=True);a=p.parse_args()
    roots=[P.safe(getattr(a,n).absolute()) for n in ('implementation','baseline','probe_source','setup5_checkout','script_source','module_source')]
    verify(roots[0],a.source,a.workflow_sha,*roots[1:])
    target=stage_packet(roots[3],P.safe(a.output.absolute()),roots[2])
    print(P.encoded(dict(status='PASS_PASSIVE_SETUP5_EXPANDED600_GATE',setup5_inputs=str(target),native='NOT_RUN',hardware='NOT_RUN')).decode(),end='')


if __name__=='__main__':main()

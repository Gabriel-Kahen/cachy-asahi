#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Full retained1148 package DATA, five original nonpackages, unchanged574 producer."""
import argparse
import json
import os
from pathlib import Path
import sys
import time
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
import closed as C


def prepare(root,carrier,output,proof):
    expected=json.loads(C.read(proof))['manifest_sha256'];C.verify(root,expected)
    C.need(not output.exists(),'fresh private574 output required');output.mkdir(mode=0o700)
    for n in ('context','context/deps','context/keys','home'):(output/n).mkdir(mode=0o700)
    helper_dir=root/'scripts/ci/setup6-retained-helpers';sys.path.insert(0,str(helper_dir))
    helper=C.load(helper_dir/'prepare.py','held_retained574_prepare')
    original=C.load(root/'scripts/ci/maintained_desktop574.py','unchanged_original574')
    lock=root/'scripts/ci/maintained-desktop574-inputs.json';value=json.loads(C.read(lock))
    deadline=time.monotonic()+2300
    receipt=helper.prepare(carrier,output/'context/deps','desktop574',lock,deadline,carrier/'.git')
    pairs={}
    for r in value['packages']:
        pairs[r['filename']]=dict(bytes=r['size'],sha256=r['sha256'])
        pairs[r['filename']+'.sig']=dict(bytes=r['signature_size'],sha256=r['signature_sha256'])
    cache=receipt['receipt']['cache'];identity=receipt['carrier']
    C.need(receipt['actual'] is None and receipt['source']=='ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad' and identity['files']==identity['blob_joins']==1154 and cache['before_files']=={} and cache['added']==1148 and cache['after_files']==pairs and cache['all_previous_inode_metadata_bytes_unchanged'] is True and receipt['receipt']['actual_authority'] is False,'whole retained1148 source/Git/cache DATA receipt differs')
    # Original producer has always acquired these exact five nonpackage inputs.
    # Use its held fetch() directly; existing exact files are reused automatically.
    items=original.plan(value,output/'context');other=[r for r in items if r['target'].parent.name!='deps']
    C.need(len(items)==1153 and len(other)==5,'exact1153 original inputs and five nonpackages required')
    acquired=[original.fetch(row) for row in other]
    C.need(time.monotonic()<deadline,'original2300s caller deadline exhausted')
    C.save(output/'retained-inputs.json',dict(status='PASS_RETAINED1148_AND_FIVE_ORIGINAL_NONPACKAGE_DATA',packages=receipt,nonpackages=acquired,actual=None))
    return lock


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('source','carrier','output','proof'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();root=C.safe(a.source.absolute());proof=json.loads(C.read(a.proof.absolute()))
    lock=prepare(root,C.safe(a.carrier.absolute()),C.safe(a.output.absolute()),a.proof.absolute())
    os.execv(sys.executable,[sys.executable,'-I','-B',str(root/'scripts/ci/maintained_desktop574.py'),'build','--inputs',str(lock),'--output',str(a.output.absolute()),'--job-token',proof['job_token']])

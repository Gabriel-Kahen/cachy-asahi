#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One immutable DATA fetch, exact1148 seed, five original inputs, held574 producer."""
import argparse,json,os,sys,time
from pathlib import Path
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
import closed as C


def prepare(root,carrier,output,proof,*,opener=None):
 expected=json.loads(C.read(proof))['manifest_sha256'];C.verify(root,expected)
 C.need(not output.exists(),'fresh private574 output required');output.mkdir(mode=0o700)
 for n in ('context','context/deps','context/keys','home'):(output/n).mkdir(mode=0o700)
 helper=C.load(root/C.O.LANE/'data_carrier.py','orphans03_retained_DATA')
 original=C.load(root/'scripts/ci/maintained_desktop574.py','unchanged_original574')
 lock=root/'scripts/ci/maintained-desktop574-inputs.json';value=json.loads(C.read(lock));deadline=time.monotonic()+2300
 transport=helper.acquire(root,carrier,deadline,opener=opener)
 receipt=helper.seed(root,carrier,output/'context/deps',deadline,transport)
 C.validate_packages(root,receipt)
 # Preserve the held producer's own five nonpackage operations and result schema.
 items=original.plan(value,output/'context');other=[r for r in items if r['target'].parent.name!='deps']
 C.need(len(items)==1153 and len(other)==5,'exact1153 original inputs and five nonpackages required')
 acquired=[original.fetch(row) for row in other]
 C.need(time.monotonic()<deadline,'original2300s caller deadline exhausted')
 evidence=dict(status='PASS_RETAINED1148_DATA_ARCHIVE_AND_FIVE_ORIGINAL_NONPACKAGE_DATA',packages=receipt,nonpackages=acquired,actual=None)
 C.validate_transport(root,evidence);C.save(output/'retained-inputs.json',evidence);return lock


if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('source','carrier','output','proof'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args();root=C.safe(a.source.absolute());proof=json.loads(C.read(a.proof.absolute()))
 lock=prepare(root,C.safe(a.carrier.absolute()),C.safe(a.output.absolute()),a.proof.absolute())
 os.execv(sys.executable,[sys.executable,'-I','-B',str(root/'scripts/ci/maintained_desktop574.py'),'build','--inputs',str(lock),'--output',str(a.output.absolute()),'--job-token',proof['job_token']])

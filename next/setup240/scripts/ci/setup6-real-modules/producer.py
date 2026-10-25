#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exact proven retained574 seed inside the held original2300 producer clock."""
import argparse,os,sys,time,json
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as C
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('source','carrier','output'):p.add_argument('--'+n,type=Path,required=True)
 p.add_argument('--job-token',required=True);a=p.parse_args();root=a.source.absolute();C.verify_source(root);sys.path.insert(0,str(root/'setup6-source/scripts/ci/setup6-retained-helpers'));m=C.load('_real6_retained_prepare',root/'setup6-source/scripts/ci/setup6-retained-helpers/prepare.py');deadline=time.monotonic()+2300
 v=m.prepare(a.carrier.absolute(),a.output.absolute()/'context/deps','desktop574',root/'scripts/ci/maintained-desktop574-inputs.json',deadline,a.carrier.absolute()/'.git');(a.output/'setup6-retained-inputs.json').write_text(json.dumps(v,sort_keys=True,indent=2)+'\n')
 os.execv(sys.executable,[sys.executable,'-I','-B',str(root/'scripts/ci/maintained_desktop574.py'),'build','--inputs',str(root/'scripts/ci/maintained-desktop574-inputs.json'),'--output',str(a.output.absolute()),'--job-token',a.job_token])

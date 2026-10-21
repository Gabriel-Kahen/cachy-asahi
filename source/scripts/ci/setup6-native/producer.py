# SPDX-License-Identifier: MIT
"""Seed all original574 exact inputs inside the unchanged2300 producer timeout."""
import argparse,importlib.util,json,os,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as C
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in('source','carrier','output'):p.add_argument('--'+n,type=Path,required=True)
 p.add_argument('--job-token',required=True);a=p.parse_args();root=a.source.absolute();C.verify_source(root);sys.path.insert(0,str(root/'scripts/ci/setup6-retained-helpers'))
 # This module namespace must not reuse the lane's own prepare adapter.
 spec=importlib.util.spec_from_file_location('_setup6_retained_prepare',root/'scripts/ci/setup6-retained-helpers/prepare.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);deadline=time.monotonic()+2300
 value=module.prepare(a.carrier.absolute(),a.output.absolute()/'context/deps','desktop574',root/'scripts/ci/maintained-desktop574-inputs.json',deadline,a.carrier.absolute()/'.git');(a.output/'setup6-retained-inputs.json').write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
 os.execv(sys.executable,[sys.executable,'-I','-B',str(root/'scripts/ci/maintained_desktop574.py'),'build','--inputs',str(root/'scripts/ci/maintained-desktop574-inputs.json'),'--output',str(a.output.absolute()),'--job-token',a.job_token])

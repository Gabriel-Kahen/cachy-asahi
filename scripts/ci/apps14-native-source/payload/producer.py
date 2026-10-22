# SPDX-License-Identifier: MIT
"""Seed exact full574 DATA then execute the unchanged native574 producer."""
import argparse,importlib.util,json,os,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as C

def execute(source,carrier,output,token):
 source=source.absolute();carrier=carrier.absolute();output=C.safe(output.absolute())
 C.verify_source(source)
 import job
 job.inherited(source).manifest_files(source,C.read(C.HERE/'source-manifest.json'))
 C.need(not os.path.lexists(output)and output.parent.is_dir(),'fresh owned producer output required')
 deadline=time.monotonic()+2300
 output.mkdir(mode=0o700);context=output/'context';context.mkdir(mode=0o700)
 for name in ('deps','keys'):(context/name).mkdir(mode=0o700)
 (output/'home').mkdir(mode=0o700)
 sys.path.insert(0,str(source/'scripts/ci/setup6-retained-helpers'))
 spec=importlib.util.spec_from_file_location('_apps14_retained_prepare',source/'scripts/ci/setup6-retained-helpers/prepare.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 value=module.prepare(carrier,context/'deps','desktop574',source/'scripts/ci/maintained-desktop574-inputs.json',deadline,carrier/'.git')
 (output/'apps14-retained-inputs.json').write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
 os.execv(sys.executable,[sys.executable,'-I','-B',str(source/'scripts/ci/maintained_desktop574.py'),'build','--inputs',str(source/'scripts/ci/maintained-desktop574-inputs.json'),'--output',str(output),'--job-token',token])
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('source','carrier','output'):p.add_argument('--'+name,type=Path,required=True)
 p.add_argument('--job-token',required=True);a=p.parse_args();execute(a.source,a.carrier,a.output,a.job_token)

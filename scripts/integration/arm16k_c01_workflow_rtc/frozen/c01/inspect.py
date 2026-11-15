#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify the finite C01 inputs as DATA; never prepare a raw or launch a guest."""
import argparse,importlib.util,json,subprocess,tempfile
from pathlib import Path
HERE=Path(__file__).resolve().parent


def load():
 spec=importlib.util.spec_from_file_location('c01_input_data',HERE/'inputs.py')
 module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def verify(materials,base):
 I=load();lock=json.loads((HERE/'inputs.lock.json').read_text());I.checked(base/'prepared.json',lock['base_prepared'])
 prepared=json.loads((base/'prepared.json').read_text());closure=I.closure(materials,prepared)
 statuses={}
 with tempfile.TemporaryDirectory(prefix='c01-public-verification-') as tmp:
  home=Path(tmp);key=home/'public.gpg'
  def command(argv):
   result=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
   if result.returncode or len(result.stdout)+len(result.stderr)>65536:raise ValueError('bounded public-signature verification failed')
   return result.stdout
  command(['gpg','--no-options','--batch','--homedir',tmp,'--dearmor','--output',str(key),str(materials/'TEST-public.asc')])
  for name,version in lock['added_packages'].items():
   archive=materials/(name+'-'+version+'-aarch64.pkg.tar.xz')
   raw=command(['gpgv','--homedir',tmp,'--keyring',str(key),'--status-fd','1',str(archive)+'.sig',str(archive)])
   lines=[line for line in raw.decode().splitlines() if line.startswith('[GNUPG:] VALIDSIG ')]
   if len(lines)!=1 or lines[0].split()[2]!=lock['signer']:raise ValueError('exact Root TEST signer differs')
   statuses[name]=lines[0]
 return {'status':'PASS_DATA_AND_FRESH_TEST_SIGNATURES_ONLY','operation':lock['operation'],'signer':lock['signer'],'original_project_signing':lock['original_project_signing'],'signatures':statuses,'dependency_edges':closure['dependency_edges'],'base_packages':111,'installed_packages':113,'final_packages':111,'runtime_ELFs':6,'payload_files':len(closure['project_payload']),'trust_prerequisite':'HOLD until genuine Root KSM trust/install/remove result is supplied','raw_preparation':'NOT RUN','guest_execution':'NOT RUN','performance':'NOT MEASURED','native16K':'NOT RUN','M2':'NOT RUN','release':False}


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--materials',type=Path,required=True);p.add_argument('--base',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 report=verify(a.materials.resolve(strict=True),a.base.resolve(strict=True))
 with a.output.open('x') as f:json.dump(report,f,indent=2,sort_keys=True);f.write('\n')
 print(json.dumps(report,sort_keys=True))


if __name__=='__main__':main()

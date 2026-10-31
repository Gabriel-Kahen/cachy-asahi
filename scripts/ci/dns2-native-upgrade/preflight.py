#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Source-only preflight: no invented run identity and process creation blocked."""
import argparse,hashlib,json,sys
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
import adapter as A
import selection as S

def main(source):
 with patch('subprocess.Popen',side_effect=AssertionError('source preflight cannot create processes')):
  value=S.verify_source(source,False)
  manifest=S.read(S.HERE/'source-manifest.json')
  for name,row in manifest['files'].items():S.checked(source/name,row)
  for name in('contract.py','run.py','job.py'):compile(A.text(source,name),str(A.HERE/name),'exec')
  policy=S.policy(False);value.update(source_files=len(manifest['files']),products={name:row['version']for name,row in policy['products'].items()},package_source=policy['candidate_source'],native='NOT_RUN',ALPM='NOT_RUN',hardware='NOT_RUN')
 return value

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True);a=p.parse_args();print(json.dumps(main(a.source.absolute()),sort_keys=True))

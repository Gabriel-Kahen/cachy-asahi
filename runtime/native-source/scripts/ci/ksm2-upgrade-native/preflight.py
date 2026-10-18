#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Source-only, no invented run identity or process creation."""
import argparse,json,sys
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
import adapter as A
import selection as S

def main(source):
 with patch('subprocess.Popen',side_effect=AssertionError('source-only no actors/Git/network')):
  v=S.verify_source(source,False);m=S.read(S.HERE/'source-manifest.json')
  for n,r in m['files'].items():S.checked(source/n,r)
  for n in('contract.py','run.py','job.py'):compile(A.text(source,n),str(A.HERE/n),'exec')
  p=S.policy(False);v.update(source_files=len(m['files']),versions={n:r['version']for n,r in p['products'].items()},recipe_sources=p['recipe_sources'],builders=4,consumers=6,native='NOT_RUN',ALPM='NOT_RUN',hardware='NOT_RUN')
 return v
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);a=p.parse_args();print(json.dumps(main(a.source.absolute()),sort_keys=True))

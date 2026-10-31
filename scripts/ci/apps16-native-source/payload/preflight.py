#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Source-only exact closure; never invents source/run binding or opens actor routes."""
import argparse,hashlib,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import adapter as A

def inspect(source):
 here=source/'scripts/ci/apps16-client-native'
 manifest=json.loads((here/'source-manifest.json').read_bytes());policy=json.loads((here/'input-policy.json').read_bytes())
 assert manifest['schema_version']==1 and 0<len(manifest['files'])<=128
 for name,row in manifest['files'].items():
  p=source/name;assert not any(x.is_symlink()for x in(p,*p.parents))and p.stat().st_nlink==1 and dict(bytes=p.stat().st_size,sha256=hashlib.sha256(p.read_bytes()).hexdigest())==row,name
 assert policy['purpose']=='APPS16_AND_OPT_IN_CLIENT_V2_NATIVE'and policy['dependency']is policy['dependency_source']is None
 assert {k:r['version']for k,r in policy['products'].items()}=={'runtime':'0.1.0-1','apps':'0.1.0-16','client':'0.1.0-1'}
 if policy['status']=='UNBOUND_APPS16_CLIENT_NATIVE':assert policy['candidate_source']is None and all(r['source_sha']is None for r in policy['products'].values())
 elif policy['status']=='ROOT_BOUND_FINAL_PRODUCT_SOURCES':
  import contract as C
  C.verify_source(source)
  for name in C.NAMES:C.recipe(source,name)
 else:raise ValueError('finite source calibration status')
 for name in ('contract.py','run.py','job.py','lifecycle.py'):compile(A.text(source,name),name,'exec')
 A.builder(source)
 return dict(status='PASS_SOURCE_ONLY_CLOSED_NATIVE_TRIAL',files=len(manifest['files']),versions={k:r['version']for k,r in policy['products'].items()},bound=policy['candidate_source']is not None,run_id=None,native='NOT_RUN',hardware='NOT_RUN')

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);a=p.parse_args();print(json.dumps(inspect(a.source.absolute()),sort_keys=True))

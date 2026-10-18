#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Source proof, inert component custody and one finite hosted execution entry."""
import argparse,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import hosted as O

def preflight(root):
 files=O.files(root);sys.path.insert(0,str(root/'runtime'));P=O.load('_ksm_hosted_source_preflight',root/'runtime/preflight.py');runtime=P.check(root/'runtime');v=O.policy(root)
 try:O.selected(v)
 except ValueError as e:O.need('UNBOUND'in str(e),'explicit NULL refusal')
 else:pass
 return dict(status='PASS_DEFAULT_SOURCE_ONLY_NO_ACTORS',files=len(files),runtime=runtime,bounds=O.BOUNDS,native_carrier=None,kernel_carrier=None,actual_run=None)

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('mode',choices=['source','proof','select','inputs','run']);p.add_argument('--source',type=Path,required=True)
 for n in('native','kernel','seed','inputs','work','archive-cache'):p.add_argument('--'+n,type=Path)
 a=p.parse_args();root=a.source.absolute()
 if a.mode=='source':return preflight(root)
 import os
 proof=O.prove(root,os.environ)
 if a.mode=='proof':return proof
 v=O.selected(O.policy(root)) # Before component reads or actor-related output.
 if a.mode=='select':
  for k in('native_carrier','kernel_carrier'):
   with open(os.environ['GITHUB_OUTPUT'],'a',encoding='utf-8')as f:f.write(k+'='+v[k]+'\n')
  return dict(status='BOUND_COMPONENT_SELECTION_NOT_ACCEPTANCE',source=proof)
 if a.mode=='inputs':return O.components(root,v,proof,a.native,a.kernel,None)[1]
 O.need(all(getattr(a,n)is not None for n in('native','kernel','seed','inputs','work','archive_cache')),'explicit owned execution paths');M=O.load('_ksm_hosted_owner',root/O.LANE/'owner.py');return M.run(a)
if __name__=='__main__':print(json.dumps(main(),sort_keys=True))

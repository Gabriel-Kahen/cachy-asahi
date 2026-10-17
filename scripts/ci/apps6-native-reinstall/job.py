#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Distinct source proof; original ordered consumers/dependency-image/producer cleanup."""
import argparse,json,os,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import adapter as A
import contract as C

def inherited(source):return A.module(source,'job.py')
def prove(source,environment):C.policy();return inherited(source).prove(source,environment)
def cleanup(source,proof,base,runtime,output,command=None):return inherited(source).cleanup(source,proof,base,runtime,output,command)
def retain(source,base,runtime,proof,cleanup_path,output):return inherited(source).retain(source,base,runtime,proof,cleanup_path,output)
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('phase',choices=('proof','cleanup','retain'))
 for name in ('source','proof','base','runtime','cleanup','output'):p.add_argument('--'+name,type=Path)
 a=p.parse_args()
 if a.phase=='proof':
  value=prove(a.source,os.environ);a.proof.write_bytes(C.encoded(value))
  with open(os.environ['GITHUB_OUTPUT'],'a') as f:f.write('job_token='+value['job_token']+'\nconsumer_token='+value['consumer_token']+'\n')
 elif a.phase=='cleanup':value=cleanup(a.source,C.read(a.proof),a.base,a.runtime,a.output)
 else:value=retain(a.source,a.base,a.runtime,a.proof,a.cleanup,a.output)
 print(json.dumps(value,sort_keys=True));raise SystemExit(int(value['status'] not in ('SOURCE_PROOF_PASS','PASS_ORDERED_CONSUMERS_DEPENDENCY_IMAGES_PRODUCER_AND_AUTHORITY','PASS_NATIVE_APPS6_PAIR_AND_SIGNED_REPAIR_CANDIDATE')))

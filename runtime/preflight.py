#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Passive source-only preflight; default NULL never admits native/kernel/VM work."""
import argparse,ast,json,subprocess,sys
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent));import contract as C
import media_adapter as M

def check(root=C.HERE):
 root=Path(root);files=C.source_check(root);borrowed=C.support(root);policy=C.decode(C.read(root/'input-policy.json'))
 for name in('native_source','native_run','native_decision','native_inputs','kernel_build','kernel_source','kernel_run','kernel_authority','kernel_transport','producer_report','media','VM_source','VM_ref','VM_run'):C.need(policy[name]is None,'default actual authority must remain NULL: '+name)
 for name in('native','kernel'):C.need(C.decode(C.read(root/(name+'-decision-contract.json')))['actual_acceptance']is None,'declared future contract is not an acceptance')
 inputs=C.decode(C.read(root/'borrowed/maintained574-inputs.json',4*1024**2));base={p['name']:p['version']for p in inputs['packages']};C.need(len(base)==574 and C.decode(C.read(root/'borrowed/base574.json'))==base,'exact whole original574 inventory derivation')
 ast.parse(M.derived_disk(root));KP=C.load('_ksm_preflight_profile',root/'profile/ksm_profile.py')
 for n in KP.PINS:KP.held(root/'kernel-source',n)
 with patch.object(C,'read',side_effect=AssertionError('NULL gate must precede operand IO')),patch.object(subprocess,'Popen',side_effect=AssertionError('source-only no actor')):
  try:C.gate(policy,'/unsupplied')
  except ValueError as e:C.need('UNBOUND'in str(e),'specific NULL refusal')
  else:raise ValueError('default actual gate unexpectedly admitted')
 return dict(status='PASS_SOURCE_ONLY_NO_ACTORS_OR_ACCEPTANCE',source_files=len(files)+1,whole_support_files=len(borrowed),profile=KP.PROFILE,actual_source=None,actual_run=None,native_qualification=None,kernel_qualification=None,VM_seconds=3000,preparation_seconds=1900,original_copy_context_seconds=900,readback_seconds=600,product_checked_seconds=5,actual_boot='NOT_RUN',actual_sysfs='NOT_RUN')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,default=C.HERE);a=p.parse_args();print(json.dumps(check(a.source),sort_keys=True))

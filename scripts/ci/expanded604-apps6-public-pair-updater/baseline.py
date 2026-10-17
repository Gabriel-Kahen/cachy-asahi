# SPDX-License-Identifier: MIT
"""Held Apps5 signed604 baseline and exact accepted Apps6 data-only pair staging."""
import json,shutil
from pathlib import Path
from types import SimpleNamespace
BASELINE='ed776a706fc711c5bcc4d933f38e88e7791bc9f6'
DECISIONS='1c953fb9b1f9442f40895f886b659534424345ce'
def load(C,args,policy):
 C.need(C.revision(args.baseline_source)==policy['baseline_source']==BASELINE and C.revision(args.baseline_decisions_source)==policy['baseline_decisions_source']==DECISIONS,'exact accepted Apps5 fresh source and native decision carrier')
 api=C.load('apps6_held_apps5_fresh',args.baseline_source/'scripts/ci/expanded604-current-management-installer/contract.py');api.verify_source(args.baseline_source);bound=api.policy();composition=api.COMPOSITION.policy()
 selected=SimpleNamespace(**vars(args));selected.code=args.baseline_source;selected.native604_decisions=args.baseline_decisions_source
 value,summary,prior=api.inputs(selected,bound)
 C.need(api.TARGET_SHA==C.BEFORE and prior['native604']['expected604_sha256']==C.BEFORE and prior['native604']['source_sha']=='61a75ac08c735871aac85db5db40e9acac989ddc','actual predecessor604 evidence only, no Apps6 credit')
 materializer=api.scoped_load('apps6_held_apps5_materializer',api.HERE.parent/'expanded604-current-management/materializer.py',{'contract':api.COMPOSITION})
 return api,materializer,value

def stage(C,root,target,binding,authority,implementation):
 helper=C.load('public_pairs_exact_selected_inputs',C.HERE/'selected_package.py');return helper.stage(C,root,target,binding,authority,implementation)

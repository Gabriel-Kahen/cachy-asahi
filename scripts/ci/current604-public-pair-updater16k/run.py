#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Dispatch one exact original Apps5→6 case through a separate16K VM."""
import argparse,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as C
import adapter,vm,producer_diagnostic as PDIAG

def main(argv=None):
 args=sys.argv[1:] if argv is None else argv
 # Parse only prerequisite selectors before importing the original owner.
 p=argparse.ArgumentParser(description=__doc__,epilog='Forward all original expanded604-apps6-public-pair-updater/run.py operands plus --kernel-work, --kernel-receipt, --updater-decisions; see README.md.');p.add_argument('--implementation',type=Path,required=True);p.add_argument('--case',choices=C.CASES,required=True)
 a,_=p.parse_known_args(args);C.gate(a.implementation,a.case)
 old=C.load('held',a.implementation/C.OLD/'contract.py')
 selected=old.scoped('selected',a.implementation/C.OLD/'adapter.py',{'contract':old})
 class Adapter:
  @staticmethod
  def prepare(source,target,case):
   return adapter.prepare_selected(selected,source,target,case)
 gate=old.scoped('gate',a.implementation/C.OLD/'gate.py',{'contract':old})
 cache=old.scoped('before_cache',a.implementation/C.OLD/'before_cache.py',{'contract':old})
 raw=C.read(a.implementation/C.OLD/'run.py');text=PDIAG.route_owner(adapter.owner(raw))
 namespace=dict(__name__='_updater16k_generated_owner',__file__=str(a.implementation/C.OLD/'run.py'))
 namespace['PDIAG']=PDIAG
 prior={k:sys.modules.get(k) for k in ('contract','adapter','gate','before_cache')}
 try:
  sys.modules.update(contract=old,adapter=Adapter,gate=gate,before_cache=cache)
  exec(compile(text,str(a.implementation/C.OLD/'run.py'),'exec'),namespace);namespace['vm']=vm
 finally:
  for k,v in prior.items():
   if v is None:sys.modules.pop(k,None)
   else:sys.modules[k]=v
 return namespace['main'](args)
if __name__=='__main__':raise SystemExit(main())

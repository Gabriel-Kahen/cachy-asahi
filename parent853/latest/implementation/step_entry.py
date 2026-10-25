#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One isolated signed tool transaction; full original primitive and clock bound."""
import json,sys,time,types
from pathlib import Path
HERE=Path(__file__).resolve().parent
sys.path[:0]=[str(HERE),'/runner/boot607','/runner/boot607/copyworker/held-copy/scripts/update','/runner/boot607/copyworker/scripts/ci/current606-apps7-copy']
import native_contract as C
import latest_transaction_adapter as T
import latest_restoration as R

def main():
 C.need(len(sys.argv)==2,'one exact native latest-tool step plan');path=Path(sys.argv[1]);C.need(path.parent==Path('/out')and path.name.startswith('latest607-step-')and path.suffix=='.json','owned native latest-tool step plan path')
 value=C.decode(C.ordinary(path,1024**2));C.need(type(value)is dict and set(value)=={'role','root','before','after','archive','keys','log'},'closed exact latest-tool transaction plan');role=value.pop('role');T.plan.product(role);C.native_scope(value['root'],value['keys'],value['log'])
 raw=C.ordinary(HERE/'held/alpm_step.py',128*1024);text,_=T.derive(raw,role);module=types.ModuleType('_latest607_native_signed_step');module.__file__=str(HERE/'held/alpm_step.py');previous=sys.modules.get('contract');sys.modules['contract']=C
 started=time.monotonic();start=int(time.time())
 try:exec(compile(text,module.__file__,'exec'),vars(module));result=module.apply(**value)
 finally:
  if previous is None:sys.modules.pop('contract',None)
  else:sys.modules['contract']=previous
 elapsed=time.monotonic()-started;end=int(time.time());clock=dict(authority='SOURCE_OWNED_TRANSACTION_WALLCLOCK_NOT_ROOT_OBSERVATION',start_seconds=start,end_seconds=end,monotonic_seconds=elapsed);R.interval(clock)
 result['transaction_clock']=clock;result['role']=role
 print(json.dumps(result,sort_keys=True))
if __name__=='__main__':main()

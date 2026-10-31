#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One full signed Setup primitive under the original90-second transaction cap."""
import json,sys,time,types
from pathlib import Path
HERE=Path(__file__).resolve().parent
sys.path[:0]=[str(HERE),'/runner/copyworker/held-copy/scripts/update','/runner/copyworker/scripts/ci/current606-doctor2-copy']
from native_api import C
import transaction_adapter as T
import latest_restoration as R

def main():
 if sys.argv[1:]==['--help']:print('Native-only one exact Setup signed transaction plan');return
 C.need(len(sys.argv)==2,'one exact transaction plan');path=Path(sys.argv[1]);C.need(path.parent==Path('/out')and path.name.startswith('setup6-step-')and path.suffix=='.json','finite native transaction plan path')
 value=C.decode(C.ordinary(path,1024**2));C.need(set(value)=={'root','before','after','archive','keys','log'},'whole exact transaction operands');C.native_scope(value['root'],value['keys'],value['log'])
 profile=C.decode(C.ordinary(HERE/'runtime-pins.json'));raw=C.ordinary(HERE/'held/alpm_step.py',128*1024);text=T.derive(raw,profile['held/alpm_step.py']);module=types.ModuleType('_whole_signed_native_setup_step');module.__file__=str(HERE/'held/alpm_step.py');saved=sys.modules.get('contract');sys.modules['contract']=C
 started=time.monotonic();start=int(time.time())
 try:exec(compile(text,module.__file__,'exec'),vars(module));result=module.apply(**value)
 finally:
  if saved is None:sys.modules.pop('contract',None)
  else:sys.modules['contract']=saved
 clock=dict(authority='SOURCE_OWNED_TRANSACTION_WALLCLOCK_NOT_ROOT_OBSERVATION',start_seconds=start,end_seconds=int(time.time()),monotonic_seconds=time.monotonic()-started);R.interval(clock);result['transaction_clock']=clock;print(json.dumps(result,sort_keys=True))
if __name__=='__main__':main()

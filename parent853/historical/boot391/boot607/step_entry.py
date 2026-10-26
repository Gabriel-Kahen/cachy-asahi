#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One isolated native Boot ALPM step; irreversible no-exec stays child-only."""
import json
from pathlib import Path
import sys
import types
HERE=Path(__file__).resolve().parent
sys.path[:0]=[str(HERE),str(HERE/'copyworker/held-copy/scripts/update'),str(HERE/'copyworker/scripts/ci/current606-apps7-copy')]
import native_contract as C
import transaction_adapter as T

def main():
    C.need(len(sys.argv)==2,'one exact native Boot step plan')
    path=Path(sys.argv[1])
    C.need(path.parent==Path('/out') and path.name.startswith('boot607-step-') and path.suffix=='.json','owned native step plan path')
    value=C.decode(C.ordinary(path,1024**2))
    C.need(set(value)=={'root','before','after','archive','keys','log'},'complete exact native step input')
    C.native_scope(value['root'],value['keys'],value['log'])
    raw=C.ordinary(HERE/'held-alpm-step.py',128*1024).decode()
    module=types.ModuleType('_boot607_native_alpm_step')
    module.__file__=str(HERE/'held-alpm-step.py')
    previous=sys.modules.get('contract')
    sys.modules['contract']=C
    try:
        exec(compile(T.derive(raw),module.__file__,'exec'),module.__dict__)
        result=module.apply(**value)
    finally:
        if previous is None:sys.modules.pop('contract',None)
        else:sys.modules['contract']=previous
    print(json.dumps(result,sort_keys=True))

if __name__=='__main__':main()

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Source-pinned old604 owner with an explicit separate606 bridge."""
import sys,types
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as P,adapter as A,bridge606 as X

def main(argv=None):
 P.verify();C=P.load('606_held604_contract',P.ROOT/'held604'/P.OLD/'contract.py');previous=sys.modules.get('contract');sys.modules['contract']=C
 try:
  m=types.ModuleType('606_exact_owner');m.__file__=str(P.ROOT/'held604'/P.OLD/'run.py');m.X=X;exec(compile(A.owner(P.ROOT),m.__file__,'exec'),m.__dict__);return m.main(argv)
 finally:
  if previous is None:sys.modules.pop('contract',None)
  else:sys.modules['contract']=previous
if __name__=='__main__':raise SystemExit(main())

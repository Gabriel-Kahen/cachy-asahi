#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as P

def main(argv=None):
 P.verify();C=P.load('606_preflight604_contract',P.ROOT/'held604'/P.OLD/'contract.py');previous=sys.modules.get('contract');sys.modules['contract']=C
 try:return P.load('606_held604_gate',P.ROOT/'held604'/P.OLD/'gate.py').main(argv)
 finally:
  if previous is None:sys.modules.pop('contract',None)
  else:sys.modules['contract']=previous
if __name__=='__main__':raise SystemExit(main())

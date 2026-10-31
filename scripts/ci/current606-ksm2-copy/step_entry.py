#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import json,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
sys.path[:0]=[str(HERE),str(ROOT/'held-copy/scripts/update')]
import contract as C,worker,alpm_step

def main():
 C.need(len(sys.argv)==2,'one finite selected transaction plan');path=Path(sys.argv[1]);C.need(path.parent==Path('/work/transaction-plans'),'owned transaction plan directory')
 value=C.decode(C.ordinary(path,1024**2));C.need(set(value)=={'root','before','after','archive','keys','log'},'closed selected transaction fields')
 C.capability_profile(worker.process_status());result=alpm_step.apply(**value);print(json.dumps(result,sort_keys=True))
if __name__=='__main__':main()

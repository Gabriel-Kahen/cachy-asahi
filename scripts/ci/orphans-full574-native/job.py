#!/usr/bin/python3 -I
import argparse,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import contract as C
H=C.load('original_apps_owner',C.HERE.parent/'apps-full574-native/job.py')
M=C.load('independent_orphan_modes',C.HERE/'modes.py')
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('mode',choices=('proof','check','run','cleanup','retain'));p.add_argument('--trial',choices=M.TRIALS,required=True)
 for n in ('source','packet','proof','base','output','receipt','public'):p.add_argument('--'+n,type=Path)
 a=p.parse_args();C.policy();v=M.execute(H,a.trial,a);print(C.encoded(dict(status=v['status'],trial=a.trial)).decode(),end='')
 raise SystemExit(0 if v['status'] in ('SOURCE_PROOF_PASS','EXACT_NATIVE_INPUTS_CHECKED_NOT_EXECUTED','PASS_ACTUAL_TRANSACTIONS_PENDING_ORDERED_CLEANUP','PASS_ORDERED_CONSUMERS_COPIES_KEYS_SOURCE_THEN_PRODUCER',C.STATUS) else 1)

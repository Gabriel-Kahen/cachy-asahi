#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Dispatch only the two whole-held signed one-package ALPM primitives."""
import json,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2];sys.path[:0]=[str(HERE),str(ROOT/'held-copy/scripts/update')]
import contract as C,worker,roles

def main():
 C.need(len(sys.argv)==2,'one owned selected transaction spec');p=Path(sys.argv[1]);C.need(p.parent==Path('/work/transaction-plans'),'fixed private transaction plan')
 v=C.decode(C.ordinary(p,1024**2));C.need(set(v)=={'selected','root','before','after','archive','keys','log'}and v['selected']in('apps','welcome'),'exact selected role and original transaction fields')
 C.capability_profile(worker.process_status());selected=v.pop('selected');api=roles.load(selected);result=api['alpm_step'].apply(**v);print(json.dumps(dict(selected=selected,**result),sort_keys=True))
if __name__=='__main__':main()

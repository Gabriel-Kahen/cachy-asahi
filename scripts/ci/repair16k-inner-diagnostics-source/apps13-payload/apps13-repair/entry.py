#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Apps13 repair source gate; selection is mandatory before any old owner/actor."""
import argparse,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import selection as S

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source-only',action='store_true');p.add_argument('--require-selection',action='store_true');p.add_argument('--carrier',type=Path);a=p.parse_args()
 if a.require_selection or a.carrier:S.authority()
 value=S.source_only()
 if a.carrier:
  M=S.load(S.ROOT/'apps13-repair/carrier.py','_apps13_repair_checked_entry');value['carrier']=M.inspect(a.carrier)['proof']
 print(json.dumps(value,sort_keys=True))
if __name__=='__main__':main()

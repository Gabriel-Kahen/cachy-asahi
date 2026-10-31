#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Source emission only; selected Apps11 requires future Root pair and carrier."""
import argparse,importlib.util,json,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
import source,packet
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source-only',action='store_true');p.add_argument('--require-selection',action='store_true');p.add_argument('--carrier',type=Path);p.add_argument('--output',type=Path);a=p.parse_args()
 if a.require_selection or a.carrier:packet.policy()
 result=source.emit(a.output)if a.output else source.verify()
 if a.carrier:result['carrier']=packet.inspect(a.carrier)['proof']
 print(json.dumps(result,sort_keys=True))
if __name__=='__main__':main()

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Source-only CLI and explicit whole accepted Apps8 carrier gate; never installs."""
import argparse,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import source,packet

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--carrier',type=Path);p.add_argument('--source-only',action='store_true');p.add_argument('--output',type=Path);p.add_argument('--inverse-parent',action='store_true');a=p.parse_args()
 result=source.emit(a.output,parent=a.inverse_parent)if a.output else source.verify()
 if a.carrier:result['carrier']=packet.inspect(a.carrier)['proof']
 print(json.dumps(result,sort_keys=True))
if __name__=='__main__':main()

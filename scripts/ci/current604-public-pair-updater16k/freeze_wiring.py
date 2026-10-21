#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Same explicit two-role emitter; no policy binding or Git operations."""
import argparse,sys,json
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from prepare import emit
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('source','updater','output'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args();print(json.dumps(emit(a.source.absolute(),a.updater.absolute(),a.output.absolute()),sort_keys=True))

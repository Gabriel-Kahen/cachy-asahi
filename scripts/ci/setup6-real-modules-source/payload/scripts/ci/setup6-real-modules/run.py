#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Manual native only: accepted pairs, two owned consumers, no package rebuilds."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as C
import adapter


if __name__=='__main__':
    if sys.argv[1:]==['--help']:
        print('Native Setup6 real modules: --source --base-dir --output --consumer-token --setup4-inputs --setup5-inputs --modules-inputs --setup6-inputs');raise SystemExit(0)
    C.need('--source' in sys.argv,'explicit source required');source=C.safe(Path(sys.argv[sys.argv.index('--source')+1]).absolute());C.verify_source(source)
    roots={}
    for name in ('setup5','modules','setup4','setup6'):
        flag='--'+name+'-inputs';C.need(sys.argv.count(flag)==1,'explicit unique immutable packet root required');i=sys.argv.index(flag);roots[name]=C.safe(Path(sys.argv[i+1]).absolute());del sys.argv[i:i+2]
    C.ROOTS=roots;C.BORROWED=C.borrowed_snapshot()
    out=C.safe(Path(sys.argv[sys.argv.index('--output')+1]).absolute());C.need(all(not (out.is_relative_to(p) or p.is_relative_to(out)) for p in roots.values()),'runtime and borrowed input roots must be separate')
    raise SystemExit(adapter.namespace(source)['main']())

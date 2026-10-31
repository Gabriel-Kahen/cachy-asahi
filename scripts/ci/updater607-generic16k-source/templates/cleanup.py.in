#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Complete original owned HOME/config retirement with current VM custody."""
import os,sys,types
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import entry
held=Path(os.environ['LATEST607_HELD_SOURCE']);module,proxy=entry.parent(held)
raw=entry.Q.read(entry.C.ROOT/'parent4k/cleanup.py')
text,_=entry.selected.derive(raw,[("result['source']==C.HELD","result['source']==proof['source'] and result['held_library_source']==C.HELD")])
scope=types.ModuleType('__main__');scope.__file__=str(entry.C.ROOT/'parent4k/cleanup.py');prior=sys.modules.get('case');sys.modules['case']=proxy
try:exec(compile(text,scope.__file__,'exec'),vars(scope))
finally:
 if prior is None:sys.modules.pop('case',None)
 else:sys.modules['case']=prior

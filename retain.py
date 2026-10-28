#!/usr/bin/env python3
"""Whole source guard before the existing private route."""
import importlib.util,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('_lifecycle_top_guard',ROOT/'entry.py');guard=importlib.util.module_from_spec(s);s.loader.exec_module(guard);guard.verify();private=guard.private()
prior=sys.modules.get('entry');sys.modules['entry']=private
scope={'__name__':'__main__','__file__':str(ROOT/'lifecycle/retain.py')}
try:exec(compile((ROOT/'lifecycle/retain.py').read_bytes(),scope['__file__'],'exec'),scope)
finally:
 if prior is None:sys.modules.pop('entry',None)
 else:sys.modules['entry']=prior

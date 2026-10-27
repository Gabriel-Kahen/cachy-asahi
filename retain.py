#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Original bounded DATA retention plus two actual VM summary roles."""
import os,sys,types
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import entry
held=Path(os.environ['LATEST607_HELD_SOURCE']);module,proxy=entry.parent(held)
raw=entry.Q.read(entry.C.ROOT/'parent4k/retain.py')
edits=[("'native4k-wrapper.json','wiring-owner.json')","'native4k-wrapper.json','wiring-owner.json','public/updater16k-result.json','public/updater16k-cleanup.json')"),('SOURCE_BOUND_NATIVE_ARM4K_UPDATER604_PUBLIC_DATA_NOT_ACCEPTANCE','SOURCE_BOUND_CURRENT607_GENERIC16K_PUBLIC_DATA_NOT_ACCEPTANCE'),('ORIGINAL_NATIVE_DOCKER_COPY_CRYPTO_TRANSACTION_PRESERVATION_AND_CLEANUP_NO16K_OR_HARDWARE_CREDIT','CURRENT607_GENERIC16K_VM_COPY_CRYPTO_TRANSACTION_PRESERVATION_CLEANUP_NOT_HARDWARE')]
text,_=entry.selected.derive(raw,edits)
scope=types.ModuleType('__main__');scope.__file__=str(entry.C.ROOT/'parent4k/retain.py');prior=sys.modules.get('case');sys.modules['case']=proxy
try:exec(compile(text,scope.__file__,'exec'),vars(scope))
finally:
 if prior is None:sys.modules.pop('case',None)
 else:sys.modules['case']=prior

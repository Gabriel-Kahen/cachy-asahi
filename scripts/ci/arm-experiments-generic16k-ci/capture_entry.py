#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Seed ARM guest's extra stdlib extension root before unchanged native capture."""
import ast,runpy,sys
from pathlib import Path
LANE='scripts/ci/arm-experiments-generic16k'
IMPORTS={'base64','ctypes','hashlib','importlib.util','json','os','re','sys','time','runtime'}

def import_extensions(root):
 path=root/LANE/'guest.py'
 if not path.is_file() or any(p.is_symlink() for p in (path,*path.parents)) or path.stat().st_size>65536:
  raise ValueError('ordinary bounded exact source ARM guest required')
 tree=ast.parse(path.read_bytes());names={a.name for n in tree.body if isinstance(n,ast.Import) for a in n.names}
 froms=[(n.module,tuple(a.name for a in n.names)) for n in tree.body if isinstance(n,ast.ImportFrom)]
 if names!=IMPORTS or froms!=[('pathlib',('Path',))]:raise ValueError('fixed ARM guest import closure changed')
 # Other roots are already imported by original capture/tools guest. Do not load
 # ARM runtime.py or alter sys.path/generic helper names in capture's interpreter.
 import ctypes
 if '_ctypes' not in sys.modules:raise ValueError('native ctypes extension import required')
 return ctypes

def main():
 import_extensions(Path('/repo'))
 # Original guard, source checks, capture(), ELF/DT_NEEDED and archive bodies stay unchanged.
 runpy.run_path('/source/capture.py',run_name='__main__')

if __name__=='__main__':main()

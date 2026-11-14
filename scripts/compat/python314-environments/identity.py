# SPDX-License-Identifier: MIT
"""Read-only identity check, run by the candidate rather than orchestration Python."""
import sys

if sys.version_info[:3] != (3, 14, 8):
    raise RuntimeError('wrong interpreter version')

import importlib.util
import json
from pathlib import Path
import sysconfig

prefix, base, executable = map(Path, sys.argv[1:4])
if Path(sys.prefix) != prefix or Path(sys.base_prefix) != base:
    raise RuntimeError('wrong interpreter/base prefix')
if Path(sys.executable) != executable:
    raise RuntimeError('wrong interpreter executable')
if not Path(sysconfig.__file__).is_relative_to(base):
    raise RuntimeError('foreign sysconfig')
if not all(Path(p).resolve().is_relative_to(base) or Path(p).resolve().is_relative_to(prefix)
           for p in sys.path):
    raise RuntimeError('foreign module search path')
mapped = sorted({line.split()[-1] for line in Path('/proc/self/maps').read_text().splitlines()
                 if 'libpython' in line})
if mapped != [str(base / 'lib/libpython3.14.so.1.0')]:
    raise RuntimeError('foreign mapped library')
purelib = Path(sysconfig.get_path('purelib'))
if purelib != prefix / 'lib/python3.14/site-packages':
    raise RuntimeError('wrong installation destination')
pip = importlib.util.find_spec('pip')
pip_version = None
if pip:
    if not Path(pip.origin).is_relative_to(prefix):
        raise RuntimeError('foreign pip installation')
    import importlib.metadata
    pip_version = importlib.metadata.version('pip')
print(json.dumps({'version': sys.version, 'prefix': sys.prefix, 'base_prefix': sys.base_prefix,
                  'executable': sys.executable, 'sys_path': sys.path, 'purelib': str(purelib),
                  'mapped_library': mapped, 'pip_origin': pip.origin if pip else None,
                  'pip_version': pip_version}, sort_keys=True))

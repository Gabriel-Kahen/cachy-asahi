# SPDX-License-Identifier: MIT
"""Runs only inside the selected interpreter/embedding executable."""
import importlib
import json
from pathlib import Path
import sys
import sysconfig


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


prefix, modules = map(Path, sys.argv[2:4] if getattr(sys, '_consumer_embedding', False)
                      else sys.argv[1:3])
require(sys.version_info[:3] == (3, 14, 8), 'wrong interpreter version')
require(Path(sys.prefix).resolve() == prefix.resolve(), 'wrong interpreter prefix')
require(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
        'isolation flags required')
require(all(not p or Path(p).resolve().is_relative_to(prefix.resolve())
            for p in sys.path), 'foreign initial module search path')
require(Path(sysconfig.__file__).resolve().is_relative_to(prefix), 'foreign sysconfig')
mapped = sorted({line.split()[-1] for line in Path('/proc/self/maps').read_text().splitlines()
                 if 'libpython' in line})
require(mapped == [str(prefix / 'lib/libpython3.14.so.1.0')], 'foreign mapped libpython')
sys.path.insert(0, str(modules))
results = {}
for name in ('consumer_full', 'consumer_stable'):
    module = importlib.import_module(name)
    require(Path(module.__file__).resolve().is_relative_to(modules), 'foreign extension')
    require(module.total([2, 5, -3]) == 4 and module.total([]) == 0, 'arithmetic failed')
    for bad, exception in [([object()], TypeError), ([1001], ValueError)]:
        try:
            module.total(bad)
        except exception:
            pass
        else:
            raise RuntimeError('extension exception propagation failed')
    compiled, runtime = module.versions()
    require(compiled == '3.14.8' and runtime == sys.version, 'extension version mismatch')
    results[name] = {'file': module.__file__, 'compiled': compiled, 'runtime': runtime,
                     'arithmetic_and_exceptions': 'PASS'}
print(json.dumps({'version': sys.version, 'prefix': sys.prefix, 'mapped_libpython': mapped,
                  'mode': 'embedding' if getattr(sys, '_consumer_embedding', False) else 'interpreter',
                  'extensions': results}, sort_keys=True))

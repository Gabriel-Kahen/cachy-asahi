#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Authenticated source-string entry point. Isolated Python never imports PYC."""
import sys
if __name__ == '__main__' and (not sys.flags.isolated or not sys.flags.dont_write_bytecode):
    raise SystemExit('Launch requires python -I -B')
import hashlib
import json
import os
from pathlib import Path
import stat
import types


def main():
    args = sys.argv[1:]
    if len(args) < 4 or args[:1] != ['--source-map-sha256'] or args[2:3] != ['--module'] or args[3] != 'base':
        raise ValueError('reviewed entry contract required')
    root = Path(__file__).parent
    # This entry's source bytes were authenticated by the outer owner before launch.
    raw = (root / '.source-map.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != args[1]:
        raise ValueError('external source map pin differs')
    pins = json.loads(raw)
    sources = {}
    for name, row in pins.items():
        if name not in {'common.py', 'base.py', 'worker.py'}:
            raise ValueError('unreviewed worker closure')
        path = root / name
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 1024**2:
                raise ValueError('unsafe worker source')
            data = stream.read()
            if hashlib.sha256(data).hexdigest() != row['sha256'] or stat.S_IMODE(info.st_mode) != row['mode']:
                raise ValueError('worker source bytes/mode differ')
            sources[name] = data
    if set(sources) != {'common.py', 'base.py', 'worker.py'}:
        raise ValueError('incomplete worker closure')
    for name in ('common', 'base'):
        module = types.ModuleType(name)
        module.__file__ = str(root / (name + '.py'))
        sys.modules[name] = module
        exec(compile(sources[name + '.py'], module.__file__, 'exec'), module.__dict__)
    sys.argv = [str(root / 'base.py'), *args[4:]]
    return sys.modules['base'].main()


if __name__ == '__main__':
    sys.exit(main())

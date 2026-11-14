#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Review only an explicitly supplied private DESTDIR tree; never install."""
import argparse
import hashlib
import json
from pathlib import Path
import stat

LICENSE_SHA = 'b0e25a78cffb43f4d92de8b61ccfa1f1f98ecbc22330b54b5251e7b6ba010231'


def check(root):
    root = root.resolve(strict=True)
    assert root != Path('/') and (root / 'usr/lib/python3.14').is_dir(), 'private Python DESTDIR required'
    required = ('usr/bin/python3.14', 'usr/include/python3.14/Python.h',
                'usr/lib/libpython3.14.so.1.0', 'usr/lib/pkgconfig/python-3.14.pc',
                'usr/lib/pkgconfig/python-3.14-embed.pc', 'usr/lib/python3.14/EXTERNALLY-MANAGED')
    for rel in required:
        assert (root / rel).is_file(), rel
    for rel, target in {'usr/bin/python': 'python3', 'usr/bin/python-config': 'python3-config',
                        'usr/bin/idle': 'idle3', 'usr/bin/pydoc': 'pydoc3'}.items():
        path = root / rel
        assert path.is_symlink() and path.readlink() == Path(target), rel
    license_path = root / 'usr/share/licenses/python/CPython-LICENSE'
    assert hashlib.sha256(license_path.read_bytes()).hexdigest() == LICENSE_SHA
    marker = (root / 'usr/lib/python3.14/EXTERNALLY-MANAGED').read_text()
    assert marker.startswith('[externally-managed]\nError=')
    assert not (root / 'usr/lib/python3.14/test').exists(), 'upstream regression fixtures belong outside runtime payload'
    paths = []
    for path in sorted(root.rglob('*')):
        rel = path.relative_to(root).as_posix(); mode = path.lstat().st_mode
        assert rel == 'usr' or rel.startswith(('usr/bin/', 'usr/include/', 'usr/lib/', 'usr/share/')) or rel in ('usr/bin', 'usr/include', 'usr/lib', 'usr/share'), rel
        assert not stat.S_IMODE(mode) & 0o6000, rel
        assert path.is_symlink() or path.is_dir() or path.is_file(), rel
        if path.is_symlink():
            assert not path.readlink().is_absolute() and path.resolve().is_relative_to(root), rel
        assert not rel.startswith(('usr/share/libalpm/hooks/', 'usr/lib/systemd/', 'usr/bin/pip')), rel
        paths.append(rel)
    return {'path_count': len(paths), 'ownership': 'package-owned /usr Python/headers/stdlib/docs/notices only',
            'system_mutation': False, 'hardware': 'NOT RUN'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('root', type=Path)
    print(json.dumps(check(parser.parse_args().root), sort_keys=True))

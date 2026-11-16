#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Read the retained host archive as bounded DATA; never extract or execute it."""
import argparse
import importlib.util
import json
from pathlib import Path
import sys
import time

HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module; spec.loader.exec_module(module)
    return module


host = load('python_tk_host', HERE / 'run.py')


def validate_rows(rows, pins):
    required = ('usr/bin/python3.14', 'usr/include/python3.14/Python.h',
                'usr/lib/libpython3.14.so.1.0', 'usr/lib/python3.14/EXTERNALLY-MANAGED',
                'usr/lib/python3.14/lib-dynload/_tkinter.cpython-314-x86_64-linux-gnu.so',
                'usr/lib/pkgconfig/python-3.14.pc', 'usr/lib/pkgconfig/python-3.14-embed.pc')
    for name in required:
        if rows.get(name, {}).get('type') != 'file':
            raise ValueError('required archive file missing: ' + name)
    for name, source in {'usr/share/licenses/python/CPython-LICENSE': 'CPython-LICENSE',
                         'usr/share/licenses/python/packaging-MIT': 'LICENSE',
                         'usr/share/doc/python/source-provenance.json': 'source-provenance.json',
                         'usr/lib/python3.14/EXTERNALLY-MANAGED': 'EXTERNALLY-MANAGED'}.items():
        if rows.get(name, {}).get('sha256') != pins['files'][source]['sha256']:
            raise ValueError('archive material checksum mismatch: ' + name)
    for name, target in {'python': 'python3', 'python-config': 'python3-config',
                         'idle': 'idle3', 'pydoc': 'pydoc3'}.items():
        row = rows.get('usr/bin/' + name, {})
        if row.get('type') != 'symlink' or row.get('target') != target:
            raise ValueError('archive frontend link mismatch')
    for name, row in rows.items():
        if name != 'usr' and not name.startswith('usr/'):
            raise ValueError('archive outside /usr')
        if row['mode'] & 0o6000:
            raise ValueError('privileged archive mode')
        if name.startswith(('usr/share/libalpm/hooks/', 'usr/lib/systemd/', 'usr/bin/pip',
                            'usr/lib/python3.14/test/', 'usr/lib/python3.14/idlelib/idle_test/')):
            raise ValueError('unexpected archive runtime payload')
    return {'payload_nodes': len(rows), 'ordinary_files': sum(r['type'] == 'file' for r in rows.values()),
            'ordinary_bytes': sum(r.get('bytes', 0) for r in rows.values()),
            'Tk_extension': required[4], 'status': 'PASS bounded x86_64 archive layout/material checks only'}


def read_rows(path):
    reader_path = host.ROOT / 'scripts/update/archive_stream.py'
    if host.identity(reader_path)['sha256'] != '7454682feb4b9c93b8b043b801388ce202e4a4a31c1f396d92c54b8de85a0ad0':
        raise ValueError('bounded archive reader changed')
    reader = load('python_tk_archive_stream', reader_path)
    limits = reader.Limits(compressed_bytes=128 * 1024**2, total_compressed_bytes=128 * 1024**2,
        decoded_bytes=512 * 1024**2, members=20000, file_bytes=128 * 1024**2,
        window_bytes=128 * 1024**2, deadline=time.monotonic() + 90)
    return reader.archive_payload(path, limits)


def inspect(path):
    rows = read_rows(path)
    result = validate_rows(rows, json.loads((HERE / 'inputs.json').read_text()))
    return {**result, 'archive': host.identity(path), 'holds': host.HOLDS}


def main():
    if not sys.flags.isolated:
        raise ValueError('run with python3 -I')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    args = parser.parse_args()
    print(json.dumps(inspect(args.archive), indent=2, sort_keys=True))


if __name__ == '__main__':
    main()

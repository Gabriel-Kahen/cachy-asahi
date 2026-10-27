#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Default no-actor suite; forbid reads from ignored evidence outside checkout."""
import ast, copy, ctypes, hashlib, io, json, lzma, math, os, signal, stat, sys, tarfile
import time, types, unittest, zlib
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def audit(event, args):
    if event=='ctypes.dlopen' and args[0] is not None:
        raise AssertionError('pure-suite-native-library-forbidden')
    if event.startswith('socket.') or event in {'subprocess.Popen', 'os.system', 'os.exec', 'os.fork', 'os.posix_spawn'}:
        raise AssertionError('pure-suite-actor-forbidden')
    if event == 'open' and type(args[0]) in (str, bytes):
        name = os.fsdecode(args[0])
        relative = name[len(str(ROOT)) + 1:] if name.startswith(str(ROOT) + '/') else name
        if relative.startswith('artifacts/') or '/artifacts/' in relative:
            raise AssertionError('pure-suite-ignored-input-forbidden')
        if name.endswith('.pyc') and name.startswith(str(ROOT) + '/'):
            raise AssertionError('pure-suite-project-PYC-forbidden')


if __name__ == '__main__':
    sys.addaudithook(audit)
    suite = unittest.TestSuite()
    for path in sorted((ROOT / 'tests/platform').glob('test_*.py')):
        module = types.ModuleType(path.stem)
        module.__file__ = str(path)
        exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
        suite.addTests(unittest.defaultTestLoader.loadTestsFromModule(module))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)

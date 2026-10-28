#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Tracked-only source-portability tests. No packages/libarchive/native tools."""
import ctypes, hashlib, io, json, os, sys, types, unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]

def audit(event,args):
    if event.startswith('socket.') or event in {'subprocess.Popen','os.system','os.exec','os.fork','os.posix_spawn'}:
        raise AssertionError('source-pure-actor-forbidden')
    if event=='ctypes.dlopen' and args[0] is not None:raise AssertionError('source-pure-native-library-forbidden')
    if event=='open' and type(args[0])in(str,bytes):
        name=os.fsdecode(args[0]);relative=name[len(str(ROOT))+1:] if name.startswith(str(ROOT)+'/') else name
        if relative.startswith('artifacts/') or '/artifacts/'in relative:raise AssertionError('source-pure-ignored-evidence-forbidden')
        if name.endswith('.pyc') and name.startswith(str(ROOT)+'/'):raise AssertionError('source-pure-project-pyc-forbidden')

if __name__=='__main__':
    sys.addaudithook(audit)
    path=ROOT/'tests/platform/test_metadata_encoder_portable.py'
    module=types.ModuleType('_source_portability_tests');module.__file__=str(path)
    exec(compile(path.read_bytes(),str(path),'exec'),module.__dict__)
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromModule(module))
    raise SystemExit(0 if result.wasSuccessful() else 1)

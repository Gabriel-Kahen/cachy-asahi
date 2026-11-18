#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise this interpreter; host-core probe remains an explicitly held profile."""
import argparse
import bz2
import ctypes
import dbm.gnu
import decimal
import gzip
import hashlib
import importlib
import json
import lzma
from pathlib import Path
import sqlite3
import ssl
import sys
import sysconfig
import tempfile
import zoneinfo
import zlib
from compression import zstd


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--profile', choices=('candidate', 'host-core-probe'), default='candidate')
    parser.add_argument('--prefix', type=Path)
    args = parser.parse_args()
    assert sys.version_info[:3] == (3, 14, 8), sys.version
    assert sysconfig.get_config_var('Py_ENABLE_SHARED') == 1
    assert sysconfig.get_config_var('SOABI').startswith('cpython-314-')
    if args.prefix:
        assert Path(sys.base_prefix).resolve() == args.prefix.resolve(), sys.base_prefix
        assert Path(ssl.__file__).resolve().is_relative_to(args.prefix.resolve())
    raw = b'cachy-asahi Python candidate\x00' * 64
    for module in (bz2, gzip, lzma, zlib, zstd):
        assert module.decompress(module.compress(raw)) == raw
    assert hashlib.sha256(b'abc').hexdigest() == 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    assert decimal.Decimal('1.25') * 4 == 5
    assert ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).minimum_version >= ssl.TLSVersion.TLSv1_2
    connection = sqlite3.connect(':memory:')
    try:
        assert connection.execute('select 6 * 7').fetchone() == (42,)
    finally:
        connection.close()
    assert zoneinfo.ZoneInfo('UTC').utcoffset(None).total_seconds() == 0
    assert ctypes.CDLL(None)
    for name in ('_decimal', '_ctypes', '_uuid', '_curses', 'readline', 'pyexpat', '_ssl'):
        importlib.import_module(name)
    with tempfile.TemporaryDirectory(prefix='python-candidate-runtime-') as scratch:
        with dbm.gnu.open(str(Path(scratch) / 'data'), 'c') as database:
            database[b'key'] = raw
            assert database[b'key'] == raw
    holds = []
    try:
        importlib.import_module('_tkinter')
    except ImportError:
        if args.profile == 'candidate':
            raise AssertionError('full candidate requires built _tkinter and its build dependency tk')
        holds.append('Tk-dependent candidate profile NOT QUALIFIED')
    print(json.dumps({'profile': args.profile, 'version': sys.version.split()[0],
                      'SOABI': sysconfig.get_config_var('SOABI'), 'checks': 'PASS core runtime',
                      'status': 'HOLD' if args.profile != 'candidate' else 'PASS software checks only',
                      'holds': holds, 'native_ARM': 'NOT ESTABLISHED', 'hardware': 'NOT RUN'}))
    return 2 if args.profile != 'candidate' else 0


if __name__ == '__main__':
    raise SystemExit(main())

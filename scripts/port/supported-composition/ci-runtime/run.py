#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run only the two composition suites in an explicit unprivileged CI runtime."""
import ctypes
import ctypes.util
import json
import os
from pathlib import Path
import subprocess
import sys


def main():
    if os.geteuid() == 0:
        raise ValueError('ordinary-user test runtime required')
    library = ctypes.util.find_library('alpm')
    if not library:
        raise ValueError('preinstalled reviewed libalpm required')
    alpm = ctypes.CDLL(library)
    alpm.alpm_version.restype = ctypes.c_char_p
    version = alpm.alpm_version().decode('ascii')
    if version != '16.0.1':
        raise ValueError('unreviewed libalpm ABI: ' + version)
    print(json.dumps({'scope': 'host-x86_64-DATA-resolver-tests', 'libalpm': version,
                      'python': sys.version.split()[0], 'uid': os.geteuid(),
                      'native_ARM': 'NOT RUN', 'hardware': 'NOT RUN'}), flush=True)
    here = Path(__file__).resolve().parent.parent
    for name in ('test_compose.py', 'test_maintenance.py'):
        result = subprocess.run([sys.executable, '-I', '-B', '-Werror::ResourceWarning',
                                 str(here / name), '-v'], timeout=120)
        if result.returncode:
            return result.returncode
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

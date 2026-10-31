#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only real libalpm/vercmp preflight for the offline transition tests."""
import argparse
import ctypes
import ctypes.util
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

# Independent expected signs include epoch, pkgrel, prerelease and numeric ordering.
CASES = (('1', '1', 0), ('2', '11', -1), ('11', '2', 1),
         ('2:1-1', '1:99-9', 1), ('1:99-9', '2:1-1', -1),
         ('7.1.13.asahi3-2', '7.1.13.asahi3-3', -1),
         ('1.5-1', '1.5', 0), ('1.5-1', '1.5-2', -1),
         ('1.0rc1', '1.0', -1), ('3.14.7-1', '3.14.8-1', -1))


def sign(value):
    return (value > 0) - (value < 0)


def run(expected_alpm_version=None):
    soname = ctypes.util.find_library('alpm')
    if not soname:
        raise ValueError('real preinstalled libalpm required; no fallback or skip')
    library = ctypes.CDLL(soname)
    compare = library.alpm_pkg_vercmp
    compare.argtypes, compare.restype = (ctypes.c_char_p, ctypes.c_char_p), ctypes.c_int
    version = library.alpm_version
    version.argtypes, version.restype = (), ctypes.c_char_p
    actual = version().decode('ascii')
    if expected_alpm_version is not None and actual != expected_alpm_version:
        raise ValueError('unexpected loaded libalpm version: ' + actual)
    binary = shutil.which('vercmp')
    if not binary:
        raise ValueError('real preinstalled vercmp required; no fallback or skip')
    observations = []
    for left, right, expected in CASES:
        result = subprocess.run([binary, left, right], capture_output=True, text=True, check=False, timeout=5)
        if result.returncode or result.stderr or len(result.stdout) > 32:
            raise ValueError('vercmp command refused')
        cli, api = sign(int(result.stdout.strip())), sign(compare(left.encode(), right.encode()))
        if (cli, api) != (expected, expected):
            raise ValueError('real version semantics disagree: ' + repr((left, right, cli, api, expected)))
        observations.append({'before': left, 'after': right, 'expected_sign': expected, 'cli_sign': cli, 'api_sign': api})
    return {'status': 'PASS-real-version-prerequisites', 'libalpm_soname': soname,
            'libalpm_version': actual, 'vercmp': str(Path(binary).resolve()),
            'vercmp_sha256': hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
            'observations': observations, 'package_installation_performed': False,
            'hardware_accepted': False, 'dependency_transaction_accepted': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-alpm-version')
    args = parser.parse_args()
    try:
        print(json.dumps(run(args.expected_alpm_version), indent=2, sort_keys=True))
    except (ValueError, OSError, AttributeError, UnicodeError, subprocess.TimeoutExpired) as error:
        parser.exit(1, 'transition prerequisites refused: ' + str(error) + '\n')


if __name__ == '__main__':
    main()

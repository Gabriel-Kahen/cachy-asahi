#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded hosted source checks only. No Qt builds, downloads or uploads."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import stat
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
LOCK_SHA256 = 'b985cd021f7d77094212301b8fe87f580484622a6c95b75388b49c88446c7c10'
PYTHONS = ((3, 12, 13), (3, 14, 6))
FAMILIES = {
    'serial': ('69a02851b87ca29daf2e197101b66bf75ff61889', 'packages/port/qt612-source-reference'),
    'transport': ('75cee7ea27e1c9f3d10959e824b261764b9b1c3d', 'scripts/ci/qt612-reference-artifact-transport'),
    'gui': ('b05267833d497ef034576741bf31968019a526c3', 'packages/port/qt612-gui-source-reference')}
spec = importlib.util.spec_from_file_location('qt612_source_pins', HERE / 'pins.py')
P = importlib.util.module_from_spec(spec); spec.loader.exec_module(P)


def lock():
    path = HERE / 'sources.lock.json'; info = path.lstat()
    P.need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o644
           and info.st_uid in (0, os.geteuid()) and info.st_size <= 128 * 1024, 'finite ordinary source lock')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        P.need(P.identity(os.fstat(fd)) == P.identity(info), 'source lock replaced before read')
        raw = bytearray()
        while block := os.read(fd, min(65536, info.st_size + 1 - len(raw))):
            raw.extend(block); P.need(len(raw) <= info.st_size, 'source lock grew')
        P.need(len(raw) == info.st_size and P.identity(info) == P.identity(os.fstat(fd)) == P.identity(path.lstat()),
               'source lock changed during read')
    finally: os.close(fd)
    P.need(hashlib.sha256(raw).hexdigest() == LOCK_SHA256, 'exact source lock pin required')
    value = json.loads(raw)
    P.need(set(value) == {'schema', 'kind', 'families'} and type(value['schema']) is int
           and value['schema'] == 1 and value['kind'] == 'QT612_FROZEN_SOURCE_CONTROLS_LOCK_V1'
           and set(value['families']) == set(FAMILIES), 'exact three frozen families required')
    for name, (commit, path) in FAMILIES.items():
        row = value['families'][name]
        P.need(set(row) == {'commit', 'path', 'files', 'tests'} and row['commit'] == commit and row['path'] == path,
               'frozen family selection differs')
    return value


def verify(workspace, value):
    return {name: P.verify_family(workspace / row['path'], row['files'])
            for name, row in value['families'].items()}


def run(workspace):
    P.need(sys.version_info[:3] in PYTHONS and sys.platform == 'linux' and os.geteuid() != 0,
           'explicit supported Python and unprivileged Linux required')
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024**2, 512 * 1024**2))
    resource.setrlimit(resource.RLIMIT_CPU, (120, 120))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    workspace = P.ordinary(workspace); value = lock(); before = verify(workspace, value)
    suites = [('pin-adversarial', HERE / 'test_pins.py', 20)]
    for name, row in value['families'].items():
        suites.extend((name + '/' + test, workspace / row['path'] / test, count)
                      for test, count in sorted(row['tests'].items()))
    results = []
    with tempfile.TemporaryDirectory(prefix='qt612-ci-source-MODEL-') as temporary:
        scratch = Path(temporary)
        for index, (name, test, expected) in enumerate(suites):
            owned = scratch / str(index); owned.mkdir()
            env = {'PATH': '/usr/bin:/bin', 'HOME': str(owned), 'TMPDIR': str(owned), 'LANG': 'C.UTF-8', 'TZ': 'UTC'}
            command = [sys.executable, '-I', '-B', '-Werror::ResourceWarning', str(HERE / 'runner.py'),
                       '--test', str(test), '--expected', str(expected)]
            completed = subprocess.run(command, env=env, cwd=workspace, capture_output=True, text=True,
                                       timeout=40, check=False)
            P.need(len(completed.stdout) <= 4096 and len(completed.stderr) <= 128 * 1024, 'bounded suite output required')
            if completed.returncode:
                print(completed.stderr[-8192:], file=sys.stderr)
                raise ValueError('source suite failed: ' + name)
            observed = json.loads(completed.stdout)
            P.need(observed == {'status': 'PASS_SOURCE_CONTROLS_ONLY', 'tests': expected, 'expected': expected,
                               'skips': 0, 'failures': 0, 'errors': 0,
                               'python': '.'.join(map(str, sys.version_info[:3])), 'native_acceptance': False},
                   'complete zero-skip suite receipt required')
            results.append(dict(observed, suite=name))
    P.need(before == verify(workspace, value), 'frozen source changed during controls')
    return {'status': 'PASS_QT612_SOURCE_CONTROLS_ONLY', 'python': '.'.join(map(str, sys.version_info[:3])),
            'lock_sha256': LOCK_SHA256, 'families': before, 'suites': results,
            'tests': sum(row['tests'] for row in results), 'skips': 0,
            'address_space_bytes': 512 * 1024**2, 'native_compilation': 'NOT RUN',
            'external_uploads': 'NOT RUN', 'native_acceptance': False, 'Root_acceptance': None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', required=True, type=Path)
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    try:
        report = P.ordinary(args.report); workspace = P.ordinary(args.workspace)
        P.need(not report.exists() and report.parent.is_dir() and not report.is_relative_to(workspace),
               'fresh report outside frozen workspace required')
        result = run(workspace)
        with report.open('x') as stream: json.dump(result, stream, indent=2, sort_keys=True); stream.write('\n')
        print(json.dumps({'status': result['status'], 'python': result['python'], 'tests': result['tests'],
                          'skips': 0, 'native_acceptance': False}, sort_keys=True)); return 0
    except (OSError, ValueError, KeyError, TypeError, MemoryError, subprocess.SubprocessError) as error:
        print(json.dumps({'status': 'FAIL_QT612_SOURCE_CONTROLS', 'reason': str(error),
                          'native_acceptance': False}, sort_keys=True)); return 1


if __name__ == '__main__': sys.exit(main())

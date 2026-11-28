#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Successor source CI, retaining the frozen 140-control route exactly once."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import stat
import subprocess
import sys
import tempfile
import types

HERE = Path(__file__).resolve().parent
LOCK_SHA256 = 'dc35d873e3a29c07a12c119a6c836948698a17470d9357694f7798b9d4d309c7'
PINS_SHA256 = 'd7a926b22338ab56ed246fbf17a0023b973ba741887d4ebe9dd956d0672d4afe'
PYTHONS = ((3, 12, 13), (3, 14, 6))


def need(value, reason):
    if not value: raise ValueError(reason)


def identity(s):
    return tuple(getattr(s, k) for k in ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid',
                                       'st_gid', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def read(path, expected=None, digest=None):
    need(path.is_absolute() and all(not p.is_symlink() for p in (path, *path.parents)), 'ordinary public operand required')
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o644
         and info.st_uid in (0, os.geteuid()) and info.st_size <= 2 * 1024**2, 'bounded ordinary source file')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        need(identity(info) == identity(os.fstat(fd)), 'source replaced before read')
        raw = bytearray()
        while block := os.read(fd, min(65536, info.st_size + 1 - len(raw))):
            raw.extend(block); need(len(raw) <= info.st_size, 'source grew')
        need(len(raw) == info.st_size and identity(info) == identity(os.fstat(fd)) == identity(path.lstat()), 'source changed')
    finally: os.close(fd)
    actual = hashlib.sha256(raw).hexdigest()
    need(digest is None or actual == digest, 'whole source SHA256 mismatch')
    need(expected is None or expected == {'kind': 'file', 'bytes': len(raw), 'sha256': actual, 'mode': 0o644},
         'whole source descriptor differs')
    return bytes(raw)


def load(name, path, digest=None):
    module = types.ModuleType(name); module.__file__ = str(path)
    exec(compile(read(path, digest=digest), str(path), 'exec'), module.__dict__)
    return module


def verify(workspace, selected, pins, support_sources):
    results = {name: pins.verify_family(workspace / row['path'], row['files'])
               for name, row in selected['families'].items()}
    for name, row in {**selected['support_files'], **selected['local_files']}.items():
        pins.member(name)
        read(workspace / pins.member(support_sources.get(name, name)), expected=row)
    return results


def project_sources(workspace, destination, files, support_sources):
    for name, row in files.items():
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if row['kind'] == 'symlink':
            # The frozen family check already verified this exact passive license link.
            target.symlink_to(row['target'])
        else:
            raw = read(workspace / support_sources.get(name, name), expected=row)
            with target.open('xb') as stream:
                stream.write(raw)
            target.chmod(row['mode'])


def aliases(selected, baseline_lock, catalog):
    producer = selected['families']['producer']['files']
    original = baseline_lock['families']['transport']['files']
    copied = {name.removeprefix('transport_basis/'): row for name, row in producer.items() if name.startswith('transport_basis/')}
    need(copied == original and len(copied) == 6, 'all six frozen transport alias bodies and modes must match')
    alias = catalog['coverage_alias']
    need(alias['tests'] == 28 and alias['baseline_test_path'] == 'scripts/ci/qt612-reference-artifact-transport/test_transport.py'
         and alias['producer_test_path'] == 'scripts/ci/qt612-reference-native-source/transport_basis/test_transport.py',
         'exact baseline coverage alias required')
    return {'files': 6, 'controls': 28, 'execution': 'REUSED_FROM_ONCE_EXECUTED_BASELINE', 'skipped': False}


def call(command, env, cwd, timeout):
    result = subprocess.run(command, env=env, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False)
    need(len(result.stdout) <= 65536 and len(result.stderr) <= 131072, 'bounded control output required')
    if result.returncode:
        print(result.stderr[-12000:], file=sys.stderr)
        raise ValueError('source control subprocess failed: ' + result.stdout[-1024:])
    return json.loads(result.stdout)


def run(workspace):
    need(sys.version_info[:3] in PYTHONS and sys.platform == 'linux' and os.geteuid() != 0,
         'explicit supported Python and unprivileged Linux required')
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024**2, 512 * 1024**2))
    resource.setrlimit(resource.RLIMIT_CPU, (120, 120)); resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    pins = load('frozen_qt612_pins', HERE.with_name('qt612-source-controls') / 'pins.py', PINS_SHA256)
    workspace = pins.ordinary(workspace)
    selected = json.loads(read(HERE / 'inputs.lock.json', digest=LOCK_SHA256))
    catalog = json.loads(read(HERE / 'suite_catalog.json', digest=selected['catalog_sha256']))
    support_sources = {name: row['source'] for name, row in selected['historical_support'].items()}
    need(support_sources.keys() <= selected['support_files'].keys(), 'historical routes must name pinned support files')
    before = verify(workspace, selected, pins, support_sources)
    baseline = load('frozen_qt612_ci', workspace / 'scripts/ci/qt612-source-controls/ci.py')
    baseline_lock = baseline.lock(); baseline_before = baseline.verify(workspace, baseline_lock)
    alias = aliases(selected, baseline_lock, catalog)
    source_files = selected['support_files'] | selected['local_files']
    for row in [*selected['families'].values(), *baseline_lock['families'].values()]:
        source_files.update({row['path'] + '/' + name: descriptor for name, descriptor in row['files'].items()})
    suites, baseline_result = [], None
    with tempfile.TemporaryDirectory(prefix='qt612-ci-v2-MODEL-') as temporary:
        scratch = Path(temporary); owned = scratch / 'baseline'; owned.mkdir()
        env = {'PATH': '/usr/bin:/bin', 'HOME': str(owned), 'TMPDIR': str(owned), 'LANG': 'C.UTF-8', 'TZ': 'UTC'}
        baseline_report = owned / 'report.json'
        observed = call([sys.executable, '-I', '-B', '-Werror::ResourceWarning', str(workspace / 'scripts/ci/qt612-source-controls/ci.py'),
                         '--workspace', str(workspace), '--report', str(baseline_report)], env, workspace, 90)
        baseline_result = json.loads(baseline_report.read_bytes())
        need(observed['tests'] == 140 and observed['skips'] == 0 and baseline_result['tests'] == 140
             and baseline_result['status'] == 'PASS_QT612_SOURCE_CONTROLS_ONLY', 'frozen baseline140 must pass exactly once')
        projected = pins.ordinary(scratch / 'source')
        project_sources(workspace, projected, source_files, support_sources)
        runner = projected / 'scripts/ci/qt612-source-controls-v2/runner.py'
        for index, row in enumerate(catalog['suites']):
            if row['path'] == catalog['coverage_alias']['producer_test_path']: continue
            owned = scratch / str(index); owned.mkdir()
            policy = owned / 'policy.json'
            policy.write_text(json.dumps({'workspace': str(projected), 'scratch': str(owned), 'allowed_files': sorted(source_files)}))
            env = {'PATH': '/usr/bin:/bin', 'HOME': str(owned), 'TMPDIR': str(owned), 'LANG': 'C.UTF-8', 'TZ': 'UTC'}
            result = call([sys.executable, '-I', '-B', '-Werror::ResourceWarning', str(runner),
                           '--test', str(projected / row['path']), '--expected', str(row['tests']), '--fence', row['fence'],
                           '--policy', str(policy)], env, owned, 40)
            need(result['status'] == 'PASS_ACTOR_FENCED_DATA_ONLY' and result['tests'] == row['tests']
                 and result['expected'] == row['tests'] and result['skips'] == result['failures'] == result['errors'] == 0
                 and result['native_acceptance'] is False and set(result['workspace_reads']) <= source_files.keys(),
                 'complete zero-skip DATA suite receipt required')
            suites.append(dict(result, family=row['family'], path=row['path']))
        need(before == verify(projected, selected, pins, {}) and baseline_before == baseline.verify(projected, baseline_lock),
             'projected source changed during successor controls')
    need(before == verify(workspace, selected, pins, support_sources) and baseline_before == baseline.verify(workspace, baseline_lock),
         'frozen source changed during successor controls')
    totals = {name: sum(s['tests'] for s in suites if s['family'] == name) for name in ('gui-adapter', 'producer')}
    need(totals == {'gui-adapter': 118, 'producer': 86}, 'exact selected suite coverage required')
    return {'status': 'PASS_QT612_SOURCE_CONTROLS_V2_ONLY', 'python': '.'.join(map(str, sys.version_info[:3])),
            'baseline': baseline_result, 'families': before, 'alias': alias, 'suites': suites,
            'tests': 140 + sum(row['tests'] for row in suites), 'skips': 0,
            'isolation_boundary_tests': 1, 'isolation_boundary_subcases': 10,
            'producer_logical_coverage': 114, 'lock_sha256': LOCK_SHA256, 'historical_support': selected['historical_support'],
            'private_material_readback': 'DENIED', 'native_compilation': 'NOT RUN', 'external_uploads': 'NOT RUN',
            'native_acceptance': False, 'Root_acceptance': None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', required=True, type=Path); parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    try:
        need(args.report.is_absolute() and str(args.report) == os.path.normpath(str(args.report))
             and all(not p.is_symlink() for p in (args.report, *args.report.parents))
             and not args.report.exists()
             and args.report.parent.is_dir() and not args.report.is_relative_to(args.workspace), 'fresh external report required')
        result = run(args.workspace)
        with args.report.open('x') as stream: json.dump(result, stream, indent=2, sort_keys=True); stream.write('\n')
        print(json.dumps({k: result[k] for k in ('status', 'python', 'tests', 'skips', 'native_acceptance')}, sort_keys=True)); return 0
    except (OSError, ValueError, KeyError, TypeError, MemoryError, subprocess.SubprocessError) as error:
        print(json.dumps({'status': 'FAIL_QT612_SOURCE_CONTROLS_V2', 'reason': str(error), 'native_acceptance': False}, sort_keys=True)); return 1


if __name__ == '__main__': sys.exit(main())

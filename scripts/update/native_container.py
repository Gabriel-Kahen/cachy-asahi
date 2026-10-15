#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run the existing 39 tiny checks directly in the owned native ARM container."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import unittest


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def guard():
    need(os.getuid() == os.geteuid() == 0 and os.uname().machine == 'aarch64'
         and Path('/.dockerenv').is_file(), 'native root container required')
    need(re.fullmatch('[0-9a-f]{32}', os.environ.get('CACHY_ASAHI_BOUND_UPDATE', '')),
         'explicit owned container marker required')
    need(os.environ.get('PATH') == '/usr/bin:/bin' and os.environ.get('HOME') == '/tmp/home'
         and os.environ.get('TMPDIR') == '/tmp', 'private container environment required')
    interfaces = {line.split(':', 1)[0].strip() for line in Path('/proc/net/dev').read_text().splitlines() if ':' in line}
    need(interfaces == {'lo'}, 'network-none container required')
    mounts = {row.split()[4]: row.split()[5].split(',') for row in Path('/proc/self/mountinfo').read_text().splitlines()}
    need('ro' in mounts.get('/source', []) and 'rw' in mounts.get('/workspace', [])
         and 'ro' in mounts.get('/', []) and '/tmp' in mounts, 'isolated source/workspace mounts required')
    Path('/tmp/home').mkdir(mode=0o700, exist_ok=True)


def load(name):
    path = Path('/source/scripts/update') / (name + '.py')
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


SCALE_DRIFT_TEST = 'test_scale_update.ScaleTransactions.test_scale_input_drift_after_prepare_refused'
SCALE_DRIFT_STAGES = {'invoke','child-exit','child-output-size','child-json','trust-stable',
    'package-lock-absent','workspace-clean','refusal-status','commit-not-started','checkpoint-unchanged',
    'fixture-unchanged','checkpoint-empty','scale-error-match','complete'}
SCALE_DRIFT_PHASES = {'configuration','checkpoint-lock','package-manager-lock','observe-before','prepare',
    'commit','observe-after','checkpoint','completed','scale-reporting','scale-configuration','worker'}
SCALE_DRIFT_ERRORS = {'ValueError','Invalid','OSError','TimeoutError','RuntimeError','AssertionError','Error','KeyboardInterrupt'}
SCALE_DRIFT_REASONS = {'scale configuration changed':'SCALE_DRIFT',
    'root observation deadline':'ROOT_DEADLINE','archive deadline exhausted':'ARCHIVE_DEADLINE',
    'insufficient or unknown filesystem free inode count':'CAPACITY_INODES',
    'insufficient future transaction bytes/inodes':'CAPACITY_FUTURE'}


def scale_drift_diagnostic(test):
    """Project only this fixture's fixed labels/facts; never its raw result/error."""
    if test.id() != SCALE_DRIFT_TEST:return None
    raw=getattr(test,'_scale_drift_diagnostic',None)
    raw=raw if type(raw) is dict else {}
    row=raw.get('row');row=row if type(row) is dict else {}
    def label(value,allowed):
        return value if type(value) is str and value in allowed else 'OTHER' if value is not None else 'UNAVAILABLE'
    def fact(value):
        return value if type(value) is bool or type(value) is str and value == 'UNKNOWN' else 'UNAVAILABLE'
    error=row.get('error')
    return dict(stage=label(raw.get('stage'),SCALE_DRIFT_STAGES),
        status=label(row.get('status'),{'PASS','FAIL'}),phase=label(row.get('phase'),SCALE_DRIFT_PHASES),
        error_type=label(row.get('error_type'),SCALE_DRIFT_ERRORS),
        error_category=SCALE_DRIFT_REASONS.get(error,'OTHER') if type(error) is str else 'UNAVAILABLE',
        commit_started=fact(row.get('commit_started')),packages_committed=fact(row.get('packages_committed')),
        checkpoint_changed=fact(row.get('checkpoint_changed')),callback_reached=fact(row.get('test_scale_precommit_reached')))


class Results(unittest.TestResult):
    def __init__(self):
        super().__init__()
        self.lines = []

    def addSuccess(self, test):
        super().addSuccess(test)
        self.lines.append(test.id() + ' PASS')

    def addFailure(self, test, error):
        super().addFailure(test, error)
        line=test.id() + ' FAIL ' + error[0].__name__
        diagnostic=scale_drift_diagnostic(test)
        if diagnostic is not None:line += ' ' + json.dumps(diagnostic,sort_keys=True,separators=(',',':'))
        self.lines.append(line)

    def addError(self, test, error):
        super().addError(test, error)
        self.lines.append(test.id() + ' ERROR ' + error[0].__name__)

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.lines.append(test.id() + ' SKIP')


def main():
    record = dict(status='FAIL', architecture=os.uname().machine, tests=0, failures=0, errors=0, skips=0,
                  production='NOT ESTABLISHED', full587='NOT RUN', hardware='NOT RUN', fixture_architecture='any')
    result = Results()
    authorized = False
    try:
        guard()
        authorized = True
        need(sys.argv[1:] in ([], ['--scale-fixtures']), 'unknown fixture selection')
        scaled = sys.argv[1:] == ['--scale-fixtures']
        selected = [('test_snapshot', 10), ('test_platform_policy', 10), ('test_bound_update', 19)]
        if scaled:
            selected += [('test_archive_stream', 20), ('test_full_root', 12), ('test_capacity', 4),
                         ('test_supervision', 6), ('test_measure_copy', 5), ('test_generic_policy', 6),
                         ('test_scale_update', 14)]
        expected = sum(count for _, count in selected)
        record['fixture_suite'] = 'synthetic-scale-and-tiny' if scaled else 'tiny'
        sys.path.insert(0, '/source/scripts/update')
        library = Path('/usr/lib/libalpm.so.16.0.1')
        record['libalpm_sha256'] = hashlib.sha256(library.read_bytes()).hexdigest()
        worker = load('bound_update')
        need(record['libalpm_sha256'] == worker.install.NATIVE_LIBRARY_SHA, 'native libalpm pin differs')
        suite = unittest.TestSuite()
        for name, count in selected:
            tests = unittest.defaultTestLoader.loadTestsFromModule(load(name))
            need(tests.countTestCases() == count, 'existing suite case count differs')
            suite.addTests(tests)
        suite.run(result)
        record.update(tests=result.testsRun, failures=len(result.failures), errors=len(result.errors), skips=len(result.skipped))
        need(result.wasSuccessful() and result.testsRun == expected and not result.skipped, 'native fixture suite failed')
        record['status'] = 'PASS'
    except BaseException as error:
        record['error_type'] = type(error).__name__
    # Only fixed, bounded schemas and test identifiers leave the container; no traceback/key material.
    if not authorized:
        return 1
    output = Path('/workspace')
    lines = '\n'.join(result.lines) + '\n'
    need(len(lines.encode()) <= 32768, 'sanitized test log bound')
    (output / 'tests.log').write_text(lines)
    (output / 'result.json').write_text(json.dumps(record, sort_keys=True) + '\n')
    return int(record['status'] != 'PASS')


if __name__ == '__main__':
    raise SystemExit(main())

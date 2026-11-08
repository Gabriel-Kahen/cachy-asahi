#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run 62 original and 103 new recovery controls; never emit or execute Source."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest

HERE = Path(__file__).resolve().parent
EXPECTED = {'original62': 62, 'new80': 80, 'data23': 23}


def encoded(value):
    return json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n'


def raw_pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def pin(path):
    return raw_pin(path.read_bytes())


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


class Recorded(unittest.TextTestResult):
    def startTest(self, test):
        super().startTest(test)
        self.ids.append(test.id())

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ids = []


def host_boundary(event, args):
    # Only the benign Python fixture children are allowed in this worker.
    if event in {'subprocess.Popen', 'os.posix_spawn'} and os.path.realpath(args[0]) != os.path.realpath(sys.executable):
        raise RuntimeError('non-Python actor forbidden in recovery controls')
    if event in {'os.system', 'socket.connect', 'socket.getaddrinfo'}:
        raise RuntimeError('external actor/network forbidden in recovery controls')
    if event == 'socket.__new__' and args[1] != 1:  # AF_UNIX only (owned socketpairs).
        raise RuntimeError('network socket forbidden in recovery controls')


def worker(group, parent, output):
    started = time.monotonic()
    if group == 'data23':
        factory = module('factory_controls', HERE / 'test_factory_recovery_new.py')
        factory.FactoryData.factory, factory.FactoryData.parent_source = HERE, parent
        factory.SOURCE_ROOTS.update((parent, HERE / 'overlay'))
        sys.addaudithook(factory.audit)
        wiring = module('wiring_controls', HERE / 'controls/test_recovery_wiring_new.py')
        wiring.configure(factory.maintained(HERE).render(parent)[1])
        suite = unittest.TestSuite([
            unittest.defaultTestLoader.loadTestsFromTestCase(factory.FactoryData),
            unittest.defaultTestLoader.loadTestsFromTestCase(wiring.WiringData)])
    else:
        sys.addaudithook(host_boundary)
        folder = HERE / ('controls/tests_original62' if group == 'original62' else 'tests')
        suite = unittest.defaultTestLoader.discover(str(folder), pattern='test_*.py')
    result = unittest.TextTestRunner(verbosity=2, resultclass=Recorded).run(suite)
    denied = factory.DENIED if group == 'data23' else []
    modules = {}
    for identity in result.ids:
        name = identity.split('.')[0]
        modules[name] = modules.get(name, 0) + 1
    original_counts = (group != 'original62' or modules == {
        'test_recovery_state': 30, 'test_recovery_fs': 22, 'test_recovery_sequence': 10})
    passed = (original_counts and result.wasSuccessful() and result.testsRun == EXPECTED[group]
              and len(set(result.ids)) == result.testsRun and not result.skipped
              and not result.expectedFailures and not result.unexpectedSuccesses and not denied)
    report = dict(group=group, status='PASS' if passed else 'FAIL', tests=result.testsRun,
        expected_tests=EXPECTED[group], failures=len(result.failures), errors=len(result.errors),
        skipped=len(result.skipped), expected_failures=len(result.expectedFailures),
        unexpected_successes=len(result.unexpectedSuccesses), test_ids=result.ids, modules=modules,
        denied_actor_events=denied, elapsed_seconds=round(time.monotonic()-started, 3),
        scope='AUDIT_DENIED_FACTORY_RENDER_AND_AST_DATA' if group == 'data23' else
            'DISPOSABLE_FILES_FAKE_ADAPTERS_AND_BENIGN_HOST_PYTHON_ONLY')
    with output.open('x') as stream:
        stream.write(encoded(report))
    return 0 if passed else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent-source', type=Path, required=True)
    parser.add_argument('--results', type=Path, required=True)
    parser.add_argument('--worker', choices=EXPECTED, help=argparse.SUPPRESS)
    args = parser.parse_args()
    parent = args.parent_source.resolve()
    if not parent.is_dir():
        parser.error('--parent-source must be the immutable Source850 checkout')
    if args.worker:
        return worker(args.worker, parent, args.results)
    if args.results.exists():
        parser.error('--results must be a fresh path')
    started = time.monotonic()
    groups = []
    owner = module('security_interruption_owner', HERE / 'overlay/native/security_interruption_owner.py')
    environment = dict(PATH=os.defpath, LANG='C', LC_ALL='C')
    with tempfile.TemporaryDirectory(prefix='recovery-controls-') as temporary:
        home = Path(temporary) / 'owned'; home.mkdir(mode=0o700)
        runner = owner.OwnedProcessRunner(home)
        for group in EXPECTED:
            output = Path(temporary) / (group + '.json')
            command = [sys.executable, '-I', '-B', '-Werror::ResourceWarning', str(Path(__file__).resolve()),
                '--parent-source', str(parent), '--results', str(output), '--worker', group]
            value, error = None, None
            try:
                value = runner.run(command, env=environment, cwd=str(HERE), seconds=180,
                                   output_cap=4*1024**2)
            except Exception as failure:
                error = type(failure).__name__ + ': ' + str(failure)
                value = getattr(failure, 'result', None)
            row = dict(group=group, status='FAIL', tests=0)
            if output.is_file():
                try:
                    row = json.loads(output.read_bytes())
                except (ValueError, OSError) as failure:
                    error = error or 'invalid worker result: ' + str(failure)
            else:
                error = error or 'worker produced no fresh result'
            if value is not None:
                for stream, raw in ((sys.stdout, value['stdout']), (sys.stderr, value['stderr'])):
                    stream.write(raw.decode('utf-8', errors='replace')); stream.flush()
                receipt = value['retirement']
                natural = (receipt.get('exit') == 0 and receipt.get('error') is None
                    and all(receipt.get(k) is True for k in ('passed', 'natural_exit', 'reaped',
                        'group_absent', 'descendants_absent', 'pid_reserved_until_retirement'))
                    and all(receipt.get(k) is False for k in ('timeout', 'forced_retirement', 'forced_cleanup')))
                row.update(retirement=receipt, stdout=raw_pin(value['stdout']), stderr=raw_pin(value['stderr']))
                if not natural:
                    error = error or 'worker did not naturally retire with group and descendants absent'
            else:
                error = error or 'worker has no owned retirement receipt'
            if error is not None:
                row.update(status='FAIL', error=error)
            groups.append(row)
    paths = sorted(p for p in HERE.rglob('*') if p.is_file() and '__pycache__' not in p.parts
        and (p.relative_to(HERE).parts[0] in {'overlay', 'tests', 'controls'}
             or p.name in {'prepare.py', 'profile.json', 'parent-commit.raw',
                           'test_factory_recovery_new.py', 'run_controls.py'}))
    pins = {p.relative_to(HERE).as_posix(): pin(p) for p in paths}
    total = sum(row['tests'] for row in groups)
    passed = total == 165 and all(row['status'] == 'PASS' and row.get('retirement', {}).get('exit') == 0 for row in groups)
    report = dict(schema=1, status='PASS' if passed else 'FAIL', tests=total, expected_tests=165,
        original_controls=62, new_controls=103, groups=groups,
        original62_replayed=True, cached_results_counted=False, python=sys.version.split()[0],
        elapsed_seconds=round(time.monotonic()-started, 3), input_pins=pins,
        parent_source='850368889d6dcabdc8afbe87f64f05650c44f90a',
        parent_map=pin(parent / 'native/source-map.json'),
        native_GPG_pacman_compiler_GET_capsuleReader_Source_emitter_calls=0,
        native_validation='NOT_RUN', hardware_validation='NOT_RUN')
    with args.results.open('x') as stream:
        stream.write(encoded(report))
    print(encoded(dict(status=report['status'], tests=total,
        groups={row['group']: row['tests'] for row in groups})), end='')
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())

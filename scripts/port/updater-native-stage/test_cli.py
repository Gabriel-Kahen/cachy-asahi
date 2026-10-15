"""Actual CLI control flow with inert actors in disposable Python children."""
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

STAGE = Path(os.environ.get('UPDATER_CLI_TEST_STAGE', Path(__file__).with_name('stage.py')))
HARNESS = r'''import argparse, ast, json, signal, sys
from pathlib import Path
source, mode, behavior = sys.argv[1:]
tree = ast.parse(Path(source).read_bytes(), filename=source)
entry = tree.body[-1]
assert isinstance(entry, ast.If) and ast.unparse(entry.test) == "__name__ == '__main__'"
class RuntimeCancelled(BaseException): pass
def actor(*args):
    if behavior == 'error': raise RuntimeError('inert failure')
    if behavior == 'exit-zero': raise SystemExit(0)
    if behavior == 'exit-nonzero': raise SystemExit(17)
    if behavior == 'keyboard': raise KeyboardInterrupt()
    if behavior == 'generator': raise GeneratorExit()
    if behavior == 'missing-status': return {}
    if behavior == 'malformed-result': return None
    if behavior == 'sigint': signal.raise_signal(signal.SIGINT)
    if behavior == 'sigterm':
        def cancel(*args): raise RuntimeCancelled()
        signal.signal(signal.SIGTERM, cancel)
        signal.raise_signal(signal.SIGTERM)
    return 'a' * 64 if mode == 'freeze' else {'status': behavior}
namespace = dict(__name__='__main__', __doc__='Inert CLI fixture', argparse=argparse,
    Path=Path, ROOT=Path('/fixture'), READY_SHA='b' * 64, json=json, sys=sys,
    freeze=actor, pipeline=actor, recover=actor, public_summary=lambda result: result)
sys.argv = [source, mode, '--output', '/fixture-output']
exec(compile(ast.Module(body=[entry], type_ignores=[]), source, 'exec'), namespace)
'''


class CLITests(unittest.TestCase):
    def invoke(self, mode, behavior):
        child = subprocess.run([sys.executable, '-I', '-B', '-c', HARNESS,
            str(STAGE), mode, behavior], capture_output=True, text=True, timeout=5)
        self.assertEqual(child.stderr, '')
        return child.returncode, [json.loads(line) for line in child.stdout.splitlines()]

    def test_freeze_pass_exits_zero_with_one_success_record(self):
        code, records = self.invoke('freeze', 'PASS')
        self.assertEqual(code, 0)
        self.assertEqual(records, [{'source_freeze': 'PASS', 'controller_sha256': 'a' * 64,
            'native_compilation': 'NOT RUN'}])

    def test_run_and_cleanup_pass_exit_zero_without_synthetic_systemexit_failure(self):
        for mode in ('run', 'cleanup'):
            with self.subTest(mode=mode):
                self.assertEqual(self.invoke(mode, 'PASS'), (0, [{'status': 'PASS'}]))

    def test_run_and_cleanup_nonpass_remain_failure(self):
        for mode in ('run', 'cleanup'):
            for status in ('FAIL', 'CANCELLED'):
                with self.subTest(mode=mode, status=status):
                    self.assertEqual(self.invoke(mode, status), (1, [{'status': status}]))

    def test_missing_status_and_malformed_actor_result_remain_closed_failures(self):
        for mode in ('run', 'cleanup'):
            for behavior, kind in (('missing-status', 'KeyError'), ('malformed-result', 'TypeError')):
                with self.subTest(mode=mode, behavior=behavior):
                    result = {} if behavior == 'missing-status' else None
                    self.assertEqual(self.invoke(mode, behavior),
                        (1, [result, {'status': 'FAIL', 'failure_class': kind}]))

    def test_all_actor_exceptions_and_control_signals_remain_closed_failures(self):
        cases = {'error': 'RuntimeError', 'exit-zero': 'SystemExit', 'exit-nonzero': 'SystemExit',
            'keyboard': 'KeyboardInterrupt', 'generator': 'GeneratorExit',
            'sigint': 'KeyboardInterrupt', 'sigterm': 'RuntimeCancelled'}
        for mode in ('freeze', 'run', 'cleanup'):
            for behavior, kind in cases.items():
                with self.subTest(mode=mode, behavior=behavior):
                    self.assertEqual(self.invoke(mode, behavior),
                        (1, [{'status': 'FAIL', 'failure_class': kind}]))


if __name__ == '__main__':
    unittest.main()

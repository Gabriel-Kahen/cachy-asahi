#!/usr/bin/env python3
"""Isolated publisher import/help smoke; child audits forbid execution actors."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

PUBLISHER = Path(__file__).resolve().with_name('publish.py')
CHILD = r'''
import argparse, ctypes, hashlib, importlib.util, json, os, pathlib, re, runpy, stat, sys, tempfile
publisher = pathlib.Path(sys.argv[1]).resolve()
mode = sys.argv[2]
denied = []
def audit(event, args):
    actors = event.startswith(('subprocess.', 'socket.', 'ctypes.', 'signal.')) or event in {
        'os.system', 'os.fork', 'os.forkpty', 'os.exec', 'os.posix_spawn', 'os.kill', 'os.killpg',
        'os.mkdir', 'os.rmdir', 'os.remove', 'os.rename', 'os.link', 'os.symlink', 'os.chmod', 'os.chown'}
    write = event == 'open' and (isinstance(args[1], str) and any(x in args[1] for x in 'wax+')
        or type(args[2]) is int and args[2] & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
    if actors or write:
        denied.append(event)
        raise AssertionError('isolated CLI smoke forbids actor/write: ' + event)
sys.addaudithook(audit)
if mode == 'import':
    namespace = runpy.run_path(str(publisher), run_name='_isolated_publisher_import')
    helper = namespace['P']
    assert pathlib.Path(helper.__file__).resolve() == publisher.with_name('prepare.py')
    assert helper.HERE == publisher.parent
else:
    sys.argv = [str(publisher), '--help']
    try:
        runpy.run_path(str(publisher), run_name='__main__')
    except SystemExit as error:
        assert error.code == 0
    else:
        raise AssertionError('--help must exit before any Source role')
assert not denied
print('ISOLATED_SMOKE_OK ' + json.dumps(dict(mode=mode, actor_calls=0, writes=0)))
'''


class IsolatedCLI(unittest.TestCase):
    def run_child(self, args):
        with tempfile.TemporaryDirectory(prefix='publisher-import-smoke-') as temporary:
            root = Path(temporary)
            (root / 'prepare.py').write_text("raise AssertionError('ambient prepare must never be loaded')\n")
            env = dict(os.environ, PYTHONPATH=str(root))
            return subprocess.run([sys.executable, '-I', '-B', *args], cwd=root, env=env,
                                  capture_output=True, text=True, timeout=15)

    def test_actual_isolated_help_ignores_cwd_and_pythonpath(self):
        result = self.run_child([str(PUBLISHER), '--help'])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('--root-source-publish-authorized', result.stdout)
        self.assertIn('--authority-file', result.stdout)
        self.assertEqual(result.stderr, '')

    def test_isolated_import_and_help_deny_actors(self):
        for mode in ('import', 'help'):
            with self.subTest(mode=mode):
                result = self.run_child(['-c', CHILD, str(PUBLISHER), mode])
                self.assertEqual(result.returncode, 0, result.stderr)
                marker = next(line for line in result.stdout.splitlines() if line.startswith('ISOLATED_SMOKE_OK '))
                self.assertEqual(json.loads(marker.removeprefix('ISOLATED_SMOKE_OK ')),
                                 dict(mode=mode, actor_calls=0, writes=0))
                self.assertEqual(result.stderr, '')


if __name__ == '__main__':
    unittest.main(verbosity=2)

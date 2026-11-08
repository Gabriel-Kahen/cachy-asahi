#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Isolated Python launch regression using newly authored inert sentinel modules."""
import sys

ACTIVE_TEST_ARGV = None
TEST_LAUNCH_EVENTS = []


def deny(event, args):
    if event in ('subprocess.Popen', 'os.posix_spawn') and ACTIVE_TEST_ARGV is not None:
        if args[0] == sys.executable and tuple(args[1]) == ACTIVE_TEST_ARGV:
            TEST_LAUNCH_EVENTS.append(event)
            return
    if event.startswith(('socket.', 'subprocess.', 'ctypes.', 'pty.')) or event in (
            'os.system', 'os.fork', 'os.forkpty', 'os.exec', 'os.posix_spawn'):
        raise RuntimeError('actor forbidden: ' + event)


sys.addaudithook(deny)

import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

F = Path(__file__).resolve().parents[1]
SUBJECT = F / 'payload/native/platform_namespace_policy_v1.py'
CHILD_GUARD = '''import sys
def deny(event,args):
 if event.startswith(('socket.','subprocess.','ctypes.','pty.')) or event in ('os.system','os.fork','os.forkpty','os.exec','os.posix_spawn'):
  raise RuntimeError('sentinel actor forbidden: '+event)
sys.addaudithook(deny)
'''


def launch(argv, force_spawn=False):
    global ACTIVE_TEST_ARGV
    ACTIVE_TEST_ARGV = (sys.executable, '-I', '-B', *argv)
    first = len(TEST_LAUNCH_EVENTS)
    try:
        result = subprocess.run(list(ACTIVE_TEST_ARGV), close_fds=not force_spawn,
                                capture_output=True, timeout=5, check=False)
    finally:
        ACTIVE_TEST_ARGV = None
    if len(result.stdout) + len(result.stderr) > 4096:
        raise ValueError('bounded sentinel output')
    result.test_launch_events = TEST_LAUNCH_EVENTS[first:]
    return result


class GuestStartupData(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Current maintained planner only; no guest, owner, reader or native actor.
        spec = importlib.util.spec_from_file_location('maintained_matrix_planner', SUBJECT)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def test_isolated_direct_script_counterexample_and_source_owned_bootstrap(self):
        with tempfile.TemporaryDirectory(prefix='namespace-isolated-sentinel-') as directory:
            root = Path(directory)
            (root / 'common.py').write_text("MARKER='NEW_INERT_IMPORT_SENTINEL'\n")
            script = root / 'platform_namespace_policy_v1.py'
            script.write_text(CHILD_GUARD + '''from common import MARKER
import json
def guest_cli_v2():
 print(json.dumps(dict(marker=MARKER,args=sys.argv[1:],isolated=sys.flags.isolated,bytecode=sys.dont_write_bytecode)))
 return 0
''')
            arguments = ['--guest', '--source', 'synthetic-new-DATA-only']
            for force_spawn in (False, True):
                with self.subTest(force_spawn=force_spawn):
                    old = launch([str(script), *arguments], force_spawn)
                    self.assertEqual(old.returncode, 1)
                    self.assertIn(b"ModuleNotFoundError: No module named 'common'", old.stderr)
                    fixed = launch(['-c', CHILD_GUARD + self.module.MATRIX_GUEST_BOOTSTRAP,
                                    str(root), *arguments], force_spawn)
                    self.assertEqual(fixed.returncode, 0, fixed.stderr.decode())
                    self.assertEqual(json.loads(fixed.stdout), dict(marker='NEW_INERT_IMPORT_SENTINEL',
                                     args=arguments, isolated=1, bytecode=True))
                    for result in (old, fixed):
                        self.assertEqual(result.test_launch_events[0], 'subprocess.Popen')
                        if force_spawn:
                            self.assertIn('os.posix_spawn', result.test_launch_events)
            self.assertEqual({p.name for p in root.iterdir()}, {'common.py', script.name})

    def test_test_actor_allowance_matches_one_exact_active_command(self):
        global ACTIVE_TEST_ARGV
        argv = [sys.executable, '-I', '-B', '-c', CHILD_GUARD + 'pass']
        ACTIVE_TEST_ARGV = tuple(argv)
        try:
            for event in ('subprocess.Popen', 'os.posix_spawn'):
                deny(event, (sys.executable, argv))  # Audit DATA only, no process.
                for executable, command in (('/bin/sh', argv),
                        (sys.executable, argv + ['unreviewed']),
                        (sys.executable, [sys.executable, '-c', 'pass'])):
                    with self.assertRaises(RuntimeError):
                        deny(event, (executable, command))
            for event in ('socket.connect', 'os.exec', 'os.fork', 'ctypes.dlopen'):
                with self.assertRaises(RuntimeError):
                    deny(event, ())
        finally:
            ACTIVE_TEST_ARGV = None
        for event in ('subprocess.Popen', 'os.posix_spawn'):
            with self.assertRaises(RuntimeError):
                deny(event, (sys.executable, argv))

    def test_only_launcher_changes_in_all_four_exact_plans(self):
        m = self.module
        own = dict(source='a' * 40, ref='refs/heads/codex/synthetic-new-DATA', run='123', attempt=1)
        own['token'] = hashlib.sha256((own['source'] + ':' + own['ref'] + ':' + own['run']).encode()).hexdigest()[:24]
        image = 'sha256:' + 'b' * 64
        contract = json.loads((F / 'payload/native/platform-namespace-policy-v1.json').read_bytes())
        operands = (image, own, 'c' * 64, 'd' * 64, 'e' * 64, contract)
        old, fixed = m._frozen_create_plan(*operands), m.create_plan(*operands)
        self.assertEqual([r['id'] for r in fixed['cases']], list(m.CASES))
        for before, after in zip(old['cases'], fixed['cases']):
            at = before['create'].index(image) + 1
            self.assertEqual(after['create'][at:at + 5], ['-I', '-B', '-c',
                             m.MATRIX_GUEST_BOOTSTRAP, '/opt/native-platform-tools-alpm-v1/source/native'])
            inverse = dict(after, create=after['create'][:at] + before['create'][at:at + 3]
                           + after['create'][at + 5:])
            self.assertEqual(inverse, before)
        self.assertEqual({k: v for k, v in fixed.items() if k != 'cases'},
                         {k: v for k, v in old.items() if k != 'cases'})

    def test_frozen_core_contract_and_strict_host_config_guard_stay_exact(self):
        profile = json.loads((F / 'parent-profile.json').read_bytes())
        raw = SUBJECT.read_bytes()
        self.assertEqual(hashlib.sha256(raw[:profile['matrix_core']['bytes']]).hexdigest(),
                         profile['matrix_core']['sha256'])
        self.assertIn(b"host==after['HostConfig']", raw[:profile['matrix_core']['bytes']])
        contract = (F / 'payload/native/platform-namespace-policy-v1.json').read_bytes()
        self.assertEqual(hashlib.sha256(contract).hexdigest(), profile['matrix_contract']['sha256'])


if __name__ == '__main__':
    unittest.main()

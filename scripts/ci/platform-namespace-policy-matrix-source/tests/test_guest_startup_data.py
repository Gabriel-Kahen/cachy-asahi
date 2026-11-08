#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Isolated Python launch regression using newly authored inert sentinel modules."""
import sys

ALLOW_TEST_PYTHON = False


def deny(event, args):
    if event == 'subprocess.Popen' and ALLOW_TEST_PYTHON:
        if args[0] == sys.executable and args[1][1:3] == ['-I', '-B']:
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


def launch(argv):
    global ALLOW_TEST_PYTHON
    ALLOW_TEST_PYTHON = True
    try:
        result = subprocess.run([sys.executable, '-I', '-B', *argv],
                                capture_output=True, timeout=5, check=False)
    finally:
        ALLOW_TEST_PYTHON = False
    if len(result.stdout) + len(result.stderr) > 4096:
        raise ValueError('bounded sentinel output')
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
print(json.dumps(dict(marker=MARKER,args=sys.argv[1:],isolated=sys.flags.isolated,bytecode=sys.dont_write_bytecode)))
''')
            arguments = ['--guest', '--source', 'synthetic-new-DATA-only']
            old = launch([str(script), *arguments])
            self.assertEqual(old.returncode, 1)
            self.assertIn(b"ModuleNotFoundError: No module named 'common'", old.stderr)
            fixed = launch(['-c', CHILD_GUARD + self.module.MATRIX_GUEST_BOOTSTRAP,
                            str(root), *arguments])
            self.assertEqual(fixed.returncode, 0, fixed.stderr.decode())
            self.assertEqual(json.loads(fixed.stdout), dict(marker='NEW_INERT_IMPORT_SENTINEL',
                             args=arguments, isolated=1, bytecode=True))
            self.assertEqual({p.name for p in root.iterdir()}, {'common.py', script.name})

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

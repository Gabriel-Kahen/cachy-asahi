#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real offline signature/archive lifecycle checks; no stable or M2 acceptance."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('rehearse', HERE / 'rehearse_lifecycle.py')
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)


class Lifecycle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        missing = [name for name in ('gpg', 'gpgconf', 'repo-add', 'bsdtar', 'vercmp') if not shutil.which(name)]
        if missing:
            raise unittest.SkipTest('required installed tools unavailable: ' + ', '.join(missing))

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='lifecycle-controls-')
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)

    def test_complete_cli_and_receipts_with_public_only_reverification(self):
        output = self.base / 'result'
        result = subprocess.run([sys.executable, '-I', '-B', HERE / 'rehearse_lifecycle.py', '--output', output],
                                capture_output=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        report = H.R.load(output / 'report.json')
        self.assertEqual(report['status'], 'PASS_SYNTHETIC_REHEARSAL')
        self.assertGreaterEqual(len(report['checks']), 18)
        self.assertTrue(all(row['result'] == 'PASS' for row in report['checks']))
        self.assertEqual(report['stable_promotion'], 'NOT_ACCEPTED')
        for name in ('package_installation', 'trust_bootstrap', 'native_arm', 'generic_arm_16k', 'm2_air_13', 'm2_air_15'):
            self.assertEqual(report[name], 'NOT_RUN')
        self.assertTrue(report['private_test_home_removed'])
        self.assertFalse((output / 'repository/stable').exists())
        self.assertEqual((output / 'rehearsal-selection/current').resolve(), output / 'repository/staging/fixture-1')
        self.assertTrue((output / 'repository/staging/fixture-2').is_dir())
        self.assertTrue((output / 'repository/staging/fixture-partial').is_dir())
        self.assertFalse(any(p.name in ('private-keys-v1.d', 'secring.gpg') for p in output.rglob('*')))
        with tempfile.TemporaryDirectory(prefix='rehearsal-public-verifier-') as temporary:
            home = Path(temporary)
            env = dict(PATH='/usr/bin:/bin', GNUPGHOME=str(home), HOME=str(home), LANG='C')
            subprocess.run(['gpg', '--no-options', '--batch', '--import', output / 'TEST-public.asc'],
                           env=env, capture_output=True, check=True, timeout=15)
            try:
                H.R.verify_release(output / 'repository/staging/fixture-1', report['test_signer'], env)
                for path in (output / 'recovery.json', output / 'repository/withdrawals/fixture-2.json'):
                    H.R.verify_signature(path, report['test_signer'], env)
                receipt = H.R.load(output / 'recovery.json')
                self.assertFalse(receipt['stable_accepted'])
                self.assertFalse(receipt['installed_system_restored'])
                self.assertEqual(receipt['withdrawal_sha256'], H.R.sha(output / 'repository/withdrawals/fixture-2.json'))
                self.assertEqual(H.snapshot(output / 'repository/staging/fixture-1'),
                                 {name: tuple(value) for name, value in report['retained_predecessor_files'].items()})
            finally:
                subprocess.run(['gpgconf', '--homedir', home, '--kill', 'all'],
                               capture_output=True, check=True, timeout=10)
        before = H.snapshot(output)
        again = subprocess.run([sys.executable, '-I', '-B', HERE / 'rehearse_lifecycle.py', '--output', output],
                               capture_output=True, timeout=15)
        self.assertNotEqual(again.returncode, 0)
        self.assertEqual(H.snapshot(output), before)

    def test_fixture_bytes_repeat_and_successor_really_changes_version(self):
        first = H.fixture(self.base / 'one', 'one', '1.0-1')
        second = H.fixture(self.base / 'two', 'two', '1.0-1')
        changed = H.fixture(self.base / 'three', 'three', '1.1-1')
        archives = [next(path.parent.glob('*.pkg.tar.gz')) for path in (first, second, changed)]
        self.assertEqual(archives[0].read_bytes(), archives[1].read_bytes())
        self.assertNotEqual(archives[0].read_bytes(), archives[2].read_bytes())
        self.assertEqual(H.R.pkginfo(archives[2])['version'], '1.1-1')
        self.assertEqual(H.R.load(changed.parent / 'base.json'), H.R.load(first.parent / 'base.json'))

    def test_existing_symlink_and_relative_destinations_refused_before_writes(self):
        existing = self.base / 'existing'
        existing.mkdir()
        (existing / 'keep').write_bytes(b'user owned')
        alias = self.base / 'alias'
        alias.symlink_to(existing, target_is_directory=True)
        for path in (existing, alias, alias / 'new', Path('relative-output')):
            with self.subTest(path=path), self.assertRaises((H.R.Error, OSError)):
                H.rehearse(path)
        self.assertEqual(H.snapshot(existing), {'keep': ('file', H.R.sha(existing / 'keep'))})
        self.assertEqual(list(existing.iterdir()), [existing / 'keep'])

    def test_missing_dependency_refused_before_output_creation(self):
        with mock.patch.object(H.shutil, 'which', return_value=None):
            with self.assertRaisesRegex(H.R.Error, 'required installed tools unavailable'):
                H.rehearse(self.base / 'no-tools')
        self.assertFalse((self.base / 'no-tools').exists())

    def test_failure_retains_report_and_cleans_test_home(self):
        actual = H.test_identity
        observed = []
        import contextlib
        @contextlib.contextmanager
        def identity():
            with actual() as value:
                observed.append(value[0])
                yield value
        with mock.patch.object(H, 'test_identity', identity), mock.patch.object(
                H.T, 'inspect_key', side_effect=H.T.Error('injected certificate inspection refusal')):
            with self.assertRaisesRegex(H.T.Error, 'injected certificate inspection refusal'):
                H.rehearse(self.base / 'failed')
        self.assertEqual(H.R.load(self.base / 'failed/report.json')['status'], 'FAIL')
        self.assertTrue(observed)
        self.assertFalse(observed[0].exists())

    def test_stale_selection_stops_before_verification_or_replace(self):
        root, selection = self.base / 'repo', self.base / 'selection'
        root.mkdir()
        selection.mkdir()
        (selection / 'current').symlink_to('foreign-selection')
        with mock.patch.object(H.R, 'verify_release') as verify, mock.patch.object(H.E, 'select') as replace:
            with self.assertRaisesRegex(H.R.Error, 'rehearsal selection changed'):
                H.select_fixture(root, selection, 'fixture-1', 'A' * 40, {}, 'expected-old')
        verify.assert_not_called()
        replace.assert_not_called()
        self.assertEqual(os.readlink(selection / 'current'), 'foreign-selection')

    def test_mid_stage_failure_never_publishes_partial_successor(self):
        import argparse
        root = self.base / 'repo'
        root.mkdir()
        first = H.fixture(self.base / 'initial', 'initial', '1.0-1')
        second = H.fixture(self.base / 'successor', 'successor', '1.1-1')
        with H.test_identity() as (_, key, _, env):
            H.R.stage(argparse.Namespace(spec=str(first)), root, key, env)
            retained = H.snapshot(root / 'staging/initial')
            with mock.patch.object(H.R, 'add_database', side_effect=H.R.Error('injected database creation failure')):
                with self.assertRaisesRegex(H.R.Error, 'injected database creation failure'):
                    H.R.stage(argparse.Namespace(spec=str(second)), root, key, env)
            self.assertFalse((root / 'staging/successor').exists())
            self.assertEqual(list(root.glob('.staging-*')), [])
            self.assertEqual(H.snapshot(root / 'staging/initial'), retained)
            H.R.verify_release(root / 'staging/initial', key, env)
            H.R.stage(argparse.Namespace(spec=str(second)), root, key, env)
            H.R.verify_release(root / 'staging/successor', key, env)

    def test_command_timeout_reaps_owned_child(self):
        marker = self.base / 'child-pid'
        program = 'import os,time;from pathlib import Path;Path(' + repr(str(marker)) + ').write_text(str(os.getpid()));time.sleep(20)'
        with self.assertRaises(subprocess.TimeoutExpired):
            H.bounded([sys.executable, '-I', '-c', program], dict(PATH='/usr/bin:/bin'), 0.3)
        with self.assertRaises(ProcessLookupError):
            os.kill(int(marker.read_text()), 0)

    def test_sigterm_cleans_test_home_and_owned_running_command(self):
        marker = self.base / 'state.json'
        program = '''import importlib.util,json,os,signal,sys
from pathlib import Path
s=importlib.util.spec_from_file_location('h',sys.argv[1]);h=importlib.util.module_from_spec(s);s.loader.exec_module(h)
signal.signal(signal.SIGTERM,lambda *_: (_ for _ in ()).throw(h.R.Error('test SIGTERM')))
try:
 with h.test_identity() as (home,key,public,env):
  child='import os,time,json;from pathlib import Path;Path('+repr(sys.argv[2])+').write_text(json.dumps({"home":'+repr(str(home))+',"pid":os.getpid()}));time.sleep(20)'
  h.bounded([sys.executable,'-I','-c',child],env,30)
except h.R.Error:sys.exit(7)
'''
        child = subprocess.Popen([sys.executable, '-I', '-B', '-c', program,
                                  HERE / 'rehearse_lifecycle.py', marker], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 15
            while not marker.exists() and child.poll() is None and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertTrue(marker.exists())
            state = json.loads(marker.read_text())
            child.send_signal(signal.SIGTERM)
            stdout, stderr = child.communicate(timeout=15)
            self.assertEqual(child.returncode, 7, stderr.decode())
            self.assertFalse(Path(state['home']).exists())
            with self.assertRaises(ProcessLookupError):
                os.kill(state['pid'], 0)
        finally:
            if child.poll() is None:
                child.kill()
                child.communicate(timeout=5)


if __name__ == '__main__':
    unittest.main(verbosity=2)

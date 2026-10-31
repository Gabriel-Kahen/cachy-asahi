#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Private synthetic producer/real CLI controls; no native or target evidence."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve()
ROOT = next(p for p in HERE.parents if (p / 'scripts/hardware/session_probe.py').is_file())
PROPOSED = next(p for p in HERE.parents if (p / 'scripts/support/collect_support.py').is_file())


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


C = module('collector', PROPOSED / 'scripts/support/collect_support.py')
F = module('bundle_fixtures', ROOT / 'tests/support/test_support_bundle.py')
B = F.B


class Collection(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='support-collection-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        # Copy current APIs, then replace only collection with original finite
        # fixtures. No user-facing option accepts a producer executable/path.
        for relative in ('scripts/support/support_bundle.py', 'scripts/hardware/session_probe.py',
                         'packages/tools/cachy-asahi-doctor2/cachy-asahi-doctor'):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, path)
        shutil.copyfile(PROPOSED / 'scripts/support/collect_support.py', self.root / 'scripts/support/collect_support.py')
        self.replace_collect('packages/tools/cachy-asahi-doctor2/cachy-asahi-doctor', F.doctor_fixture())
        self.replace_collect('scripts/hardware/session_probe.py', F.session_fixture())
        self.output = self.root / 'case'

    def replace_collect(self, relative, report=None, code=None):
        path = self.root / relative
        body = code or 'return ' + repr(report)
        with path.open('a') as stream:
            stream.write('\ndef collect(*a, **kw):\n    ' + body + '\n')

    def cli(self, *extra, output=None):
        return subprocess.run([sys.executable, '-B', str(self.root / 'scripts/support/collect_support.py'),
            '--release-id', F.IDENTITY['release_id'], '--release-sha256', F.IDENTITY['release_sha256'],
            '--source-commit', F.IDENTITY['source_commit'], '--output-dir', str(output or self.output), *extra],
            env=dict(PATH='/usr/bin:/bin', LC_ALL='C'), capture_output=True, timeout=10)

    def test_actual_cli_private_originals_sanitized_archive_and_failed_states(self):
        result = self.cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads((self.output / 'collection.json').read_bytes())
        self.assertEqual(receipt['status'], 'CREATED')
        self.assertIn(F.PRIVATE.encode(), (self.output / 'doctor.private.json').read_bytes())
        archive = self.output / 'share/support-bundle.tar'
        B.verify(SimpleNamespace(archive=archive, sha256=receipt['archive']['sha256'], extract_to=None))
        with tarfile.open(archive) as tar:
            content = b''.join(tar.extractfile(row).read() for row in tar)
        self.assertNotIn(F.PRIVATE.encode(), content)
        self.assertIn(b'failed', content)
        self.assertIn(b'unknown', content)
        self.assertIn(b'NOT RUN', content)
        self.assertEqual(set(receipt['inputs']), {'doctor', 'session'})
        for path in (self.output, self.output / 'share'):
            self.assertEqual(path.stat().st_mode & 0o777, 0o700)
        for path in self.output.rglob('*'):
            if path.is_file():
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(F.PRIVATE.encode(), result.stdout + result.stderr)

    def test_existing_output_refused_unchanged(self):
        self.output.mkdir()
        (self.output / 'keep').write_text('keep')
        result = self.cli()
        self.assertEqual(result.returncode, 2)
        self.assertEqual([p.name for p in self.output.iterdir()], ['keep'])

    def test_failed_second_producer_retains_first_and_durable_failure(self):
        self.replace_collect('scripts/hardware/session_probe.py', code='raise ValueError("PRIVATE-SECRET")')
        result = self.cli()
        self.assertEqual(result.returncode, 2)
        self.assertTrue((self.output / 'doctor.private.json').is_file())
        receipt = json.loads((self.output / 'collection.json').read_bytes())
        self.assertEqual((receipt['status'], receipt['failed_stage']), ('FAILED', 'session'))
        self.assertFalse((self.output / 'share').exists())
        self.assertNotIn(b'PRIVATE-SECRET', result.stdout + result.stderr)

    def test_interrupt_durable_receipt(self):
        self.replace_collect('scripts/hardware/session_probe.py', code='raise KeyboardInterrupt()')
        result = self.cli()
        self.assertEqual(result.returncode, 130)
        self.assertEqual(json.loads((self.output / 'collection.json').read_bytes())['status'], 'INTERRUPTED')

    def test_health_explicit_digest_and_binding(self):
        path = self.root / 'health.json'
        raw = B.encoded(F.health_fixture())
        path.write_bytes(raw)
        result = self.cli('--reviewed-health', str(path), '0' * 64)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.output.exists())
        result = self.cli('--reviewed-health', str(path), B.digest(raw))
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads((self.output / 'collection.json').read_bytes())
        self.assertEqual(receipt['inputs']['health'], B.pin(raw))
        with tarfile.open(self.output / 'share/support-bundle.tar') as tar:
            self.assertIn('reports/health.json', tar.getnames())

    def test_wrong_health_binding_refuses_before_collection(self):
        value = F.health_fixture()
        value['binding']['release_id'] = 'different-release'
        raw = B.encoded(value)
        path = self.root / 'health.json'
        path.write_bytes(raw)
        self.assertEqual(self.cli('--reviewed-health', str(path), B.digest(raw)).returncode, 2)
        self.assertFalse(self.output.exists())

    def test_changed_health_refuses_after_collection(self):
        path = self.root / 'health.json'
        raw = B.encoded(F.health_fixture())
        path.write_bytes(raw)
        self.replace_collect('scripts/hardware/session_probe.py', code='Path(' + repr(str(path)) + ').write_text("changed"); return ' + repr(F.session_fixture()))
        self.assertEqual(self.cli('--reviewed-health', str(path), B.digest(raw)).returncode, 2)
        self.assertFalse((self.output / 'share').exists())

    def test_unexpected_producer_exception_does_not_echo_secret(self):
        self.replace_collect('scripts/hardware/session_probe.py', code='raise RuntimeError("PRIVATE-SECRET")')
        result = self.cli()
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(b'PRIVATE-SECRET', result.stdout + result.stderr)

    def test_malformed_producer_refuses_archive(self):
        self.replace_collect('scripts/hardware/session_probe.py', {})
        self.assertEqual(self.cli().returncode, 2)
        self.assertFalse((self.output / 'share').exists())

    def test_source_drift_refused_before_archive(self):
        self.replace_collect('scripts/hardware/session_probe.py', code="Path(__file__).write_text(Path(__file__).read_text() + '\\n# changed\\n'); return " + repr(F.session_fixture()))
        self.assertEqual(self.cli().returncode, 2)
        self.assertFalse((self.output / 'share').exists())

    def test_output_symlink_ancestor_refused(self):
        alias = self.root / 'alias'
        alias.symlink_to(self.root, target_is_directory=True)
        self.assertEqual(self.cli(output=alias / 'case').returncode, 2)
        self.assertFalse(self.output.exists())


class Runner(unittest.TestCase):
    def test_transport_outcomes_preserve_known_package_absence_and_unknowns(self):
        for reason, code, expected in (('observed', 0, 'checked'), ('query-failed', 1, 'checked'),
                ('query-warning', 0, 'checked'), ('query-denied', None, 'unknown'),
                ('timeout', -9, 'unknown'), ('child-reservation-lost', None, 'unknown'),
                ('command-absent', None, 'unavailable')):
            session = SimpleNamespace(query=lambda *args: (reason, code, b'', b''))
            self.assertEqual(C.doctor_runner(session)(['/usr/bin/pacman'], 2)[0], expected)

    def test_output_bound_and_restricted_environment(self):
        def query(argv, seconds, env):
            self.assertEqual(argv, ['/usr/bin/wpctl', 'get-volume', '@DEFAULT_AUDIO_SINK@'])
            self.assertEqual(env['PIPEWIRE_REMOTE'], 'pipewire-0')
            self.assertNotIn('LD_PRELOAD', env)
            return 'observed', 0, b'x' * 65537, b''
        with patch.dict(os.environ, LD_PRELOAD='private-secret'):
            result = C.doctor_runner(SimpleNamespace(query=query))(
                ['/usr/bin/wpctl', 'get-volume', '@DEFAULT_AUDIO_SINK@'], 2, audio='/run/user/1000')
        self.assertEqual(result[0], 'unknown')

    def test_real_doctor_parser_preserves_known_absence(self):
        reason = ('query-failed', 1, b'', b"error: package 'm1n1' was not found\n")
        result = C.doctor_runner(SimpleNamespace(query=lambda *a: reason))(['/usr/bin/pacman'], 2)
        row = next(row for row in F.D.package_rows(result) if row['check'] == 'package/m1n1')
        self.assertEqual((row['state'], row['value']['presence']), ('checked', 'absent'))

    def test_real_owned_runner_timeout_output_and_ignored_sigchld(self):
        S = F.S
        result = S.query([sys.executable, '-c', 'import time; time.sleep(5)'], .05, {'PATH': '/usr/bin:/bin'})
        self.assertEqual(result[0], 'timeout')
        result = S.query([sys.executable, '-c', 'import sys; sys.stdout.write("x"*600000)'], 2, {'PATH': '/usr/bin:/bin'})
        self.assertEqual(result[0], 'output-limit')
        old = signal.signal(signal.SIGCHLD, signal.SIG_IGN)
        try:
            result = S.query(['/not-executed'], 1, {})
            self.assertEqual(result[0], 'reaping-policy-incompatible')
        finally:
            signal.signal(signal.SIGCHLD, old)


if __name__ == '__main__':
    unittest.main(verbosity=2)

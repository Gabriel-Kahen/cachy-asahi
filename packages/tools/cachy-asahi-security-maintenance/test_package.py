#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Successor-only staged CLI controls; no public request or installation."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

RECIPE = Path(__file__).resolve().parent
PRIVATE = 'usr/lib/cachy-asahi/security-maintenance-v2'
COMMAND = 'usr/bin/cachy-asahi-security-maintenance'
URL = 'https://security.archlinux.org/issues/all.json'
OFFLINE_RUNNER = r'''
import io, json, runpy, sys
from pathlib import Path
launcher, mock_body, *args = sys.argv[1:]
def deny(event, args):
    if event.startswith(('socket.', 'http.client.', 'urllib.Request')):
        print('NETWORK_ATTEMPT_REFUSED:' + event, file=sys.stderr)
        raise AssertionError('network forbidden in this installed CLI control')
sys.addaudithook(deny)
if mock_body:
    import email.message, urllib.request
    body = Path(mock_body).read_bytes()
    class Response(io.BytesIO):
        status = 200
        url = 'https://security.archlinux.org/issues/all.json'
        headers = email.message.Message()
    Response.headers['Content-Type'] = 'application/json'
    Response.headers['Content-Length'] = str(len(body))
    def mocked_open(self, request, timeout=None):
        assert request.full_url == Response.url and request.get_method() == 'GET'
        return Response(body)
    urllib.request.OpenerDirector.open = mocked_open
sys.argv = [launcher] + args
runpy.run_path(launcher, run_name='__main__')
'''


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


def encoded(v): return (json.dumps(v, sort_keys=True, indent=2) + '\n').encode()
def pin(raw): return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


class Successor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='advisory-package-'); cls.addClassCleanup(cls.temp.cleanup)
        cls.work = Path(cls.temp.name)
        load('successor_source', RECIPE / 'check_source.py').check(RECIPE)
        initial = cls.work / 'initial-prefix'
        env = dict(os.environ, srcdir=str(RECIPE), pkgdir=str(initial), startdir=str(RECIPE))
        result = subprocess.run(['bash', '-eu', '-c', 'source "$startdir/PKGBUILD"; package'],
                                env=env, cwd=cls.work, capture_output=True, timeout=30)
        if result.returncode: raise AssertionError(result.stderr)
        cls.prefix = cls.work / 'relocated-prefix'; initial.rename(cls.prefix)
        cls.launcher = cls.prefix / COMMAND
        cls.runtime = cls.prefix / PRIVATE

    def setUp(self):
        self.case = self.work / self._testMethodName; self.case.mkdir()

    def cli(self, args, expected=0, mock_body=None, launcher=None):
        result = subprocess.run([sys.executable, '-I', '-B', '-c', OFFLINE_RUNNER,
                                str(launcher or self.launcher), str(mock_body or ''), *args],
                                cwd=self.case, capture_output=True, timeout=45)
        self.assertEqual(result.returncode, expected, result.stderr)
        self.assertNotIn(b'NETWORK_ATTEMPT_REFUSED', result.stderr)
        self.assertNotIn(b'Traceback', result.stderr)
        return result

    def body(self):
        path = self.case / 'synthetic-body.json'
        path.write_bytes(encoded([dict(name='AVG-1', packages=['seed'], status='Fixed', severity='High',
            type='ORIGINAL PACKAGE TEST DATA', affected='1-1', fixed='1-2',
            issues=['CVE-2026-12345'], advisories=['ASA-202610-1'])]))
        return path

    def test_01_exact_successor_payload_and_unchanged_source_pins(self):
        pins = json.loads((RECIPE / 'payload-pins.json').read_bytes())
        self.assertEqual(len(pins), 22)
        self.assertIn('scripts/virtual/owned_process.py', pins)
        mapping = {PRIVATE + '/' + key: Path(key).name for key in pins}
        mapping[PRIVATE + '/payload-pins.json'] = 'payload-pins.json'
        mapping[COMMAND] = 'cachy-asahi-security-maintenance'
        for key in ('README.md', 'source-provenance.json', 'installed-files.txt'):
            mapping['usr/share/doc/cachy-asahi-security-maintenance/' + key] = key
        for key in ('NOTICE', 'LICENSE'):
            mapping['usr/share/licenses/cachy-asahi-security-maintenance/' + key] = key
        files = {str(p.relative_to(self.prefix)):p for p in self.prefix.rglob('*') if p.is_file()}
        self.assertEqual(set(files), set(mapping)); self.assertEqual(len(files), 29)
        for path, source in mapping.items():
            self.assertEqual(files[path].read_bytes(), (RECIPE / source).read_bytes())
            self.assertEqual(files[path].stat().st_mode & 0o777, 0o755 if path == COMMAND else 0o644)

    def test_02_new_help_and_direct_launcher_environment_isolation(self):
        help_text = self.cli(['--help']).stdout
        for command in (b'acquire-advisories', b'verify-advisories', b'prepare', b'status', b'plan-builds', b'batch'):
            self.assertIn(command, help_text)
        self.assertIn(b'--url', self.cli(['acquire-advisories', '--help']).stdout)
        self.assertIn(b'--snapshot-sha256', self.cli(['verify-advisories', '--help']).stdout)
        env = dict(os.environ, PYTHONPATH=str(self.case), PYTHONHOME=str(self.case))
        (self.case / 'json.py').write_text('raise RuntimeError("POISON")\n')
        result = subprocess.run([str(self.launcher), '--version'], env=env, cwd=self.case,
                                capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), b'cachy-asahi-security-maintenance 0.1.0-2')

    def test_03_explicit_acquire_dispatch_mocked_http_then_installed_verify(self):
        output = self.case / 'snapshot'
        acquired = json.loads(self.cli(['acquire-advisories', '--url', URL, '--output', str(output)],
                                      mock_body=self.body()).stdout)
        self.assertEqual(acquired['arm_security_status'], 'UNKNOWN')
        self.assertEqual(output.stat().st_mode & 0o777, 0o700)
        for name in ('advisories.json', 'provenance.json', 'snapshot.json'):
            self.assertEqual((output / name).stat().st_mode & 0o777, 0o600)
        metadata = json.loads((output / 'provenance.json').read_bytes())
        self.assertEqual(metadata['transport']['request_count'], 1)
        self.assertEqual(metadata['transport']['redirects'], 0)
        self.assertEqual(set(metadata['implementation']), {'scripts/maintenance/advisory_cache.py',
            'scripts/maintenance/security_advisories.py', 'scripts/maintenance/source_cache.py',
            'scripts/release/source_delivery.py', 'scripts/virtual/owned_process.py'})
        checked = json.loads(self.cli(['verify-advisories', '--snapshot', str(output),
                                      '--snapshot-sha256', acquired['snapshot_sha256']]).stdout)
        self.assertEqual(checked['status'], 'VERIFIED_RETAINED_DATA_OFFLINE')
        self.assertEqual(checked['arm_security_status'], 'UNKNOWN')

    def test_04_acquire_requires_exact_url_fresh_output_and_valid_limits(self):
        output = self.case / 'snapshot'; output.mkdir(mode=0o700)
        sentinel = output / 'keep'; sentinel.write_bytes(b'unchanged')
        self.cli(['acquire-advisories', '--url', URL, '--output', str(output)], expected=2)
        for args in ([ '--url', 'http://example.invalid/feed'], ['--url', URL, '--timeout', '0']):
            self.cli(['acquire-advisories', '--output', str(self.case / 'new'), *args], expected=2)
        self.assertFalse((self.case / 'new').exists()); self.assertEqual(sentinel.read_bytes(), b'unchanged')

    def test_05_offline_stale_and_tampered_snapshot_do_not_refresh(self):
        output = self.case / 'snapshot'; output.mkdir(mode=0o700)
        raw = self.body().read_bytes()
        meta = encoded(dict(url=URL, retrieved_at='2026-10-28T01:41:18Z', **pin(raw)))
        receipt = encoded(dict(schema_version=1, purpose='official-advisory-snapshot',
            files={'advisories.json':pin(raw), 'provenance.json':pin(meta)}, tracker_groups=1, arm_security_status='UNKNOWN'))
        for key, value in (('advisories.json', raw), ('provenance.json', meta), ('snapshot.json', receipt)):
            (output / key).write_bytes(value); (output / key).chmod(0o600)
        args = ['verify-advisories', '--snapshot', str(output), '--snapshot-sha256', pin(receipt)['sha256'],
                '--as-of', '2026-10-30T01:41:18Z']
        value = json.loads(self.cli(args).stdout)
        self.assertTrue(value['cache']['cache_stale']); self.assertEqual(value['arm_security_status'], 'UNKNOWN')
        (output / 'advisories.json').write_bytes(raw + b'\n')
        self.cli(args, expected=2)
        self.assertEqual((output / 'advisories.json').read_bytes(), raw + b'\n')

    def test_06_new_owned_supervisor_tamper_refused_before_acquire(self):
        prefix = self.case / 'tampered'; shutil.copytree(self.prefix, prefix)
        target = prefix / PRIVATE / 'scripts/virtual/owned_process.py'
        target.write_bytes(target.read_bytes() + b'\n# drift\n')
        output = self.case / 'never-created'
        result = self.cli(['acquire-advisories', '--url', URL, '--output', str(output)], expected=2,
                          launcher=prefix / COMMAND)
        self.assertIn(b'runtime source differs', result.stderr); self.assertFalse(output.exists())

    def test_07_existing_commands_dispatch_into_successor_runtime(self):
        fixture = load('successor_existing_data', RECIPE / 'fixture_security.py'); fixture.bind(self.runtime)
        f = fixture.Fixture(self.case)
        def call(action, selection=None):
            args = [action, '--operation', str(f.store.path)]
            if selection: args += ['--selection', str(selection), '--selection-sha256', fixture.m.c.digest(selection)]
            return json.loads(self.cli(args).stdout)
        prepared = call('prepare', f.selected)
        self.assertEqual(prepared['required_packages'], ['app', 'middle', 'seed'])
        self.assertEqual(call('status')['security_status'], 'UNKNOWN_PLANNING_IS_NOT_REMEDIATION')
        batches = call('plan-builds', f.batch_selected)['commands']['batches']
        self.assertEqual(len(batches), 2)
        self.assertTrue(all(str(self.runtime) in row['plan_command'][2] for row in batches))
        self.assertIn(b'--builder-interface', self.cli(['batch', '--help']).stdout)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=False); parser.add_argument('--recipe-root', type=Path)
    args, remaining = parser.parse_known_args()
    if args.recipe_root: RECIPE = args.recipe_root.resolve()
    unittest.main(argv=[sys.argv[0]] + remaining)

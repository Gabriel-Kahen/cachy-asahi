#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Private package() layout and moved, offline launcher controls; no installation."""
import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

sys.dont_write_bytecode = True
parser = argparse.ArgumentParser()
parser.add_argument('--recipe-root', type=Path, required=True)
args, remaining = parser.parse_known_args()
RECIPE = args.recipe_root.absolute()


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


C = module('platform_package_check', Path(__file__).with_name('check_package.py'))


class PackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        C.audit(RECIPE)
        cls.temp = tempfile.TemporaryDirectory(prefix='platform-package-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root = Path(cls.temp.name)
        cls.source = cls.root / 'source'
        cls.source.mkdir()
        # Only finite recipe files, never makepkg log pipes or workspace content.
        for name in ('cachy-asahi-platform-tools', 'runtime-map.json', 'source-provenance.json',
                     'README.md', 'private-platform-transition-prepare.md', 'NOTICE', 'LICENSE'):
            shutil.copyfile(RECIPE / name, cls.source / name)
        with tarfile.open(RECIPE / 'private-source.tar.gz', 'r:gz') as archive:
            for member in archive:
                path = cls.source / member.name
                path.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(member) as stream:
                    path.write_bytes(stream.read())
                path.chmod(member.mode)
        cls.original = cls.root / 'original'
        command = ['bash', '-c', 'source "$1"; srcdir=$2; pkgdir=$3; package',
                   'package-fixture', str(RECIPE / 'PKGBUILD'), str(cls.source), str(cls.original)]
        child = subprocess.run(command, capture_output=True, text=True, timeout=15)
        if child.returncode:
            raise RuntimeError(child.stderr)
        cls.prefix = cls.root / 'moved-prefix'
        cls.original.rename(cls.prefix)
        cls.launcher = cls.prefix / 'usr/bin/cachy-asahi-platform-tools'
        cls.fixture_module = module('platform_fixture', cls.source / 'private/scripts/platform/test_platform_transition.py')
        cls.preparation = module('private_prepare_fixture', cls.source / 'private/scripts/platform/prepare_transition.py')
        cls.runtime = cls.prefix / 'usr/lib/cachy-asahi/platform-tools'

    def setUp(self):
        self.fixture = self.fixture_module.TransitionTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def invoke(self, *arguments):
        # The checkout and all home configuration are unavailable; no network or host DB.
        command = ['bwrap', '--die-with-parent', '--ro-bind', '/', '/', '--unshare-net',
                   '--dev', '/dev', '--tmpfs', '/home', '--bind', str(self.root), str(self.root),
                   '--bind', str(self.fixture.root), str(self.fixture.root), '--chdir', '/tmp']
        if Path('/var/lib/pacman').is_dir():
            command += ['--tmpfs', '/var/lib/pacman']
        command += [str(self.launcher), *map(str, arguments)]
        env = dict(os.environ, PATH='/usr/bin:/bin', LC_ALL='C', TMPDIR=str(self.fixture.root))
        env.pop('PYTHONPYCACHEPREFIX', None)
        return subprocess.run(command, capture_output=True, text=True, timeout=45, env=env)

    def plan(self):
        self.fixture.row(self.fixture.after, 'mesa')['VERSION'] = ['2-1']
        ref = self.fixture.save('transition.json', self.fixture.contract())
        output = self.fixture.root / 'plan.json'
        child = self.invoke('plan', '--contract', ref['path'], '--contract-sha256', ref['sha256'], '--output', output)
        self.assertEqual(child.returncode, 0, child.stderr)
        return ref, output, json.loads(output.read_bytes())

    def test_01_exact_payload_modes_and_moved_help(self):
        expected = json.loads((RECIPE / 'payload-map.json').read_bytes())['files']
        actual = {p.relative_to(self.prefix).as_posix(): {'sha256': C.sha(p.read_bytes()), 'mode': p.stat().st_mode & 0o777}
                  for p in self.prefix.rglob('*') if p.is_file()}
        self.assertEqual(actual, expected)
        self.assertFalse(self.original.exists())
        for name in ((), ('plan',), ('prepare',), ('check',)):
            child = self.invoke(*name, '--help')
            self.assertEqual(child.returncode, 0, child.stderr)
            self.assertIn('usage:', child.stdout)

    def test_02_moved_runtime_real_tools_and_sources(self):
        child = self.invoke('check')
        self.assertEqual(child.returncode, 0, child.stderr)
        report = json.loads(child.stdout)
        self.assertEqual(report['capabilities']['plan']['status'], 'READY')
        self.assertEqual(report['capabilities']['prepare']['libalpm_version'], '16.0.1')
        self.assertEqual(report['capabilities']['prepare']['transaction'], 'NOT RUN')
        output = self.fixture.root / 'runtime.json'
        child = self.invoke('sources', '--output', output)
        self.assertEqual(child.returncode, 0, child.stderr)
        ref = {'path': str(output), 'size': output.stat().st_size, 'sha256': C.sha(output.read_bytes())}
        staged = module('staged_prepare', self.runtime / 'scripts/platform/prepare_transition.py')
        self.assertEqual(staged.runtime_sources(ref), report['runtime_sources']['files'])

    def test_03_complete_moved_plan_and_exact_recheck(self):
        ref, output, report = self.plan()
        self.assertEqual(report['status'], 'PASS-offline-data-plan')
        self.assertEqual(report['input_references'], json.loads(Path(ref['path']).read_bytes()))
        self.assertEqual(report['contract_sha256'], ref['sha256'])
        for field in ('system_mutation', 'transaction_prepared', 'fresh_signature_verification', 'hardware_accepted', 'recovery_accepted'):
            self.assertFalse(report[field])
        self.assertTrue(any(row['change'] == 'upgraded' for row in report['changes']))
        child = self.invoke('check', '--contract', ref['path'], '--contract-sha256', ref['sha256'],
                            '--report', output, '--report-sha256', C.sha(output.read_bytes()))
        self.assertEqual(child.returncode, 0, child.stderr)
        self.assertTrue(json.loads(child.stdout)['retained_plan']['exact_fresh_match'])
        report['hardware_accepted'] = True
        output.write_text(json.dumps(report))
        child = self.invoke('check', '--contract', ref['path'], '--contract-sha256', ref['sha256'],
                            '--report', output, '--report-sha256', C.sha(output.read_bytes()))
        self.assertEqual(child.returncode, 1)
        self.assertIn('differs from fresh', child.stderr)

    def test_04_blocked_plan_retained(self):
        self.fixture.row(self.fixture.after, 'consumer')['DEPENDS'] = ['mesa>=9']
        ref = self.fixture.save('transition.json', self.fixture.contract())
        output = self.fixture.root / 'blocked.json'
        child = self.invoke('plan', '--contract', ref['path'], '--contract-sha256', ref['sha256'], '--output', output)
        self.assertEqual(child.returncode, 2, child.stderr)
        report = json.loads(output.read_bytes())
        self.assertTrue(any(row['code'] == 'dependency-unsatisfied' for row in report['conditions']))
        self.assertFalse(report['software_data_bound'])

    def test_05_bound_input_and_existing_output_refusal(self):
        ref, output, report = self.plan()
        before = output.read_bytes()
        child = self.invoke('plan', '--contract', ref['path'], '--contract-sha256', ref['sha256'], '--output', output)
        self.assertEqual(child.returncode, 1)
        self.assertEqual(output.read_bytes(), before)
        child = self.invoke('plan', '--contract', ref['path'], '--contract-sha256', '0'*64,
                            '--output', self.fixture.root / 'absent.json')
        self.assertEqual(child.returncode, 1)
        self.assertFalse((self.fixture.root / 'absent.json').exists())

    def test_06_strict_prepare_unverified_certificate_refuses(self):
        ref, plan, report = self.plan()
        sources = self.fixture.root / 'runtime.json'
        self.assertEqual(self.invoke('sources', '--output', sources).returncode, 0)
        source_ref = {'path': str(sources), 'size': sources.stat().st_size, 'sha256': C.sha(sources.read_bytes())}
        request = {'schema_version': 1, 'transition_contract': ref,
                   'transition_report': {'path': str(plan), 'size': plan.stat().st_size, 'sha256': C.sha(plan.read_bytes())},
                   'runtime_sources': source_ref, 'certificates': {'alarm': self.fixture.save('unverified.gpg', b'inert unverified certificate')}}
        strict = self.fixture.save('strict.json', request)
        output = self.fixture.root / 'must-not-exist.json'
        child = self.invoke('prepare', '--contract', strict['path'], '--contract-sha256', strict['sha256'], '--output', output)
        self.assertEqual(child.returncode, 1, child.stdout)
        self.assertIn('certificate pin refused', child.stderr)
        self.assertFalse(output.exists())
        self.assertEqual(list(self.fixture.root.glob('private-platform-*')), [])

    def test_07_relocated_real_ALPM_worker_without_commit(self):
        staged = module('moved_worker_prepare', self.runtime / 'scripts/platform/prepare_transition.py')
        record = lambda name, version: {'NAME': [name], 'VERSION': [version], 'ARCH': ['aarch64'], 'LICENSE': ['MIT'],
                                      'FILENAME': [f'{name}-{version}-aarch64.pkg.tar.xz'], 'CSIZE': ['1'], 'ISIZE': ['1']}
        before = {'mesa': record('mesa', '1-1')}
        after = {'mesa': record('mesa', '2-1')}
        with tempfile.TemporaryDirectory(prefix='private-platform-prepare-', dir=self.fixture.root) as work:
            report = staged.worker(Path(work), before, after, ['mesa'])
            self.assertEqual(report['status'], 'PASS-private-metadata-prepare')
            for field in ('commit_called', 'hooks_run', 'host_database_used', 'package_authentication_performed', 'production_admitted', 'hardware_accepted'):
                self.assertFalse(report[field])
            self.assertEqual(list((Path(work) / 'root').iterdir()), [])
        after['consumer'] = record('consumer', '1-1')
        after['consumer']['DEPENDS'] = ['mesa>=3']
        with tempfile.TemporaryDirectory(prefix='private-platform-prepare-', dir=self.fixture.root) as work:
            report = staged.worker(Path(work), before, after, ['mesa', 'consumer'])
            self.assertEqual(report['status'], 'FAIL-private-metadata-prepare')
            self.assertEqual(report['prepare_errno'], 45)

    def test_08_removal_inverse_preserves_caller_reports(self):
        target = self.root / 'removal-copy'
        shutil.copytree(self.prefix, target)
        sentinel = target / 'usr/share/doc/caller-owned-report.json'
        sentinel.parent.mkdir(parents=True, exist_ok=True)
        sentinel.write_text('caller bytes')
        for name in json.loads((RECIPE / 'payload-map.json').read_bytes())['files']:
            (target / name).unlink()
        self.assertEqual([p.relative_to(target).as_posix() for p in target.rglob('*') if p.is_file()],
                         ['usr/share/doc/caller-owned-report.json'])
        self.assertEqual(sentinel.read_text(), 'caller bytes')

    def test_09_runtime_tamper_refuses_before_import(self):
        path = self.runtime / 'scripts/platform/tuple_audit.py'
        before = path.read_bytes()
        try:
            path.write_bytes(before + b'\nraise RuntimeError("MUST NOT EXECUTE")\n')
            child = self.invoke('check')
            self.assertEqual(child.returncode, 1)
            self.assertIn('runtime source checksum mismatch', child.stderr)
            self.assertNotIn('RuntimeError:', child.stderr)
        finally:
            path.write_bytes(before)


if __name__ == '__main__':
    unittest.main(argv=[sys.argv[0], *remaining])

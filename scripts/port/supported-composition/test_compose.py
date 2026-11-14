#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Actual private libalpm over synthetic metadata; no package payloads/install."""
import copy
import gzip
import hashlib
import importlib.util
import io
import json
import os
import resource
import subprocess
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('supported_composition', Path(__file__).with_name('compose.py'))
c = importlib.util.module_from_spec(spec); spec.loader.exec_module(c)


def package(name, version='1-1', depends=(), provides=(), conflicts=()):
    return {'NAME': [name], 'VERSION': [version], 'ARCH': ['aarch64'], 'LICENSE': ['MIT'],
            'DEPENDS': list(depends), 'PROVIDES': list(provides), 'CONFLICTS': list(conflicts), 'REPLACES': [],
            'FILENAME': [name + '-' + version + '-aarch64.pkg.tar.gz']}


def database(rows):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode='w:') as archive:
        for row in rows:
            body = ''.join('%' + key + '%\n' + '\n'.join(value) + '\n\n' for key, value in row.items()).encode()
            info = tarfile.TarInfo(row['NAME'][0] + '-' + row['VERSION'][0] + '/desc'); info.size = len(body)
            archive.addfile(info, io.BytesIO(body))
    return gzip.compress(raw.getvalue())


class CompositionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='supported-composition-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.before = [package(name) for name in c.t.tuple_audit.BOOT] + [package('python', '3.14.7-1'), package('shared-lib')]
        self.catalogs = {'asahi-alarm': [], 'core': [package('python', '3.14.8-1'), package('shared-lib', '2-1')], 'extra': []}
        self.counter = 0

    def ref(self, name, raw):
        if isinstance(raw, dict): raw = json.dumps(raw).encode()
        path = self.root / name; path.write_bytes(raw)
        return {'path': str(path), 'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}

    def contract(self, depends=('python>=3.11',)):
        image = self.ref('image.json', {'kind': 'observed-image-local-package-metadata', 'packages': [{'metadata': row} for row in self.before]})
        protected = self.ref('tuple.json', {'kind': 'offline-platform-metadata-witnesses', 'input_sha256': {'image': image['sha256']},
            'proposed_installed_dependency_graph': [{'name': row['NAME'][0], 'version': row['VERSION'][0]} for row in self.before if row['NAME'] != ['shared-lib']]})
        data = b'pkgbase = candidate\npkgver = 1\npkgrel = 1\narch = any\nlicense = MIT\n'
        data += ''.join('depends = ' + dep + '\n' for dep in depends).encode() + b'pkgname = candidate\n'
        candidate = self.ref('candidate.SRCINFO', data)
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode='w:gz') as output:
            body = b'pkgname = candidate\npkgver = 1-1\narch = any\nlicense = MIT\n'
            body += ''.join('depend = ' + dep + '\n' for dep in depends).encode()
            info = tarfile.TarInfo('.PKGINFO'); info.size = len(body)
            output.addfile(info, io.BytesIO(body))
        candidate_archive = self.ref('candidate-1-1-any.pkg.tar.gz', archive.getvalue())
        return {'schema_version': 1, 'kind': 'supported-Asahi-composition-inputs-v1', 'workflow': 'project-extension',
                'image_inventory': image, 'protected_tuple': protected,
                'catalogs': [self.ref(name + '.db', database(rows)) | {'name': name} for name, rows in self.catalogs.items()],
                'candidate_srcinfo': [{'srcinfo': candidate, 'archive': candidate_archive, 'archive_scope': 'synthetic-test-only'}],
                'roots': [{'name': 'candidate', 'version': '1-1', 'repo': 'project'}],
                'providers': [], 'allowed_base_changes': []}

    def execute(self, contract):
        self.counter += 1
        result = c.compose(contract, self.root / ('out-' + str(self.counter)))
        self.assertTrue(result['private_database_removed'])
        self.assertFalse(result['transaction_accepted']); self.assertFalse(result['system_mutation'])
        return result

    def test_data_read_can_advance_atime_without_content_or_identity_drift(self):
        # The host's /tmp may be mounted noatime. Linux shared-memory tmpfs
        # provides a real read-induced atime change without faking stat fields.
        with tempfile.TemporaryDirectory(prefix='composition-atime-', dir='/dev/shm') as scratch:
            path = Path(scratch) / 'data'; raw = b'exact pinned bytes'; path.write_bytes(raw)
            ref = {'path': str(path), 'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
            os.utime(path, ns=(0, path.stat().st_mtime_ns))
            self.assertEqual(c.Reader().read(ref), raw)
            self.assertNotEqual(path.stat().st_atime_ns, 0)

    def test_data_reader_still_refuses_content_and_inode_change_during_read(self):
        original = c.t.bound
        for change in ('content', 'identity'):
            with self.subTest(change=change):
                ref = self.ref('drifting-' + change, b'exact pinned bytes')
                path = Path(ref['path'])
                replacement = self.root / ('replacement-' + change)
                replacement.write_bytes(b'exact pinned bytes')
                def drift(value):
                    raw = original(value)
                    if change == 'content':
                        path.write_bytes(b'changed contents')
                    else:
                        replacement.replace(path)
                    return raw
                with mock.patch.object(c.t, 'bound', side_effect=drift):
                    with self.assertRaisesRegex(ValueError, 'DATA changed during read'):
                        c.Reader().read(ref)

    def test_current_source_metadata_joins_without_fabricating_archive_identity(self):
        result = self.execute(self.contract())
        self.assertEqual(result['metadata_prepare_status'], 'PASS', result['blockers'])
        self.assertEqual(result['status'], 'HOLD')
        row = next(row for row in result['proposed_final_inventory'] if row['name'] == 'candidate')
        self.assertEqual(row['provenance']['kind'], 'source-declared-candidate-with-real-archive-PKGINFO')
        self.assertEqual(row['metadata']['SHA256SUM'], [row['provenance']['archive_reference']['sha256']])
        self.assertNotIn('PGPSIG', row['metadata'])
        self.assertTrue(all(row['preserved'] for row in result['protected']))
        self.assertEqual(result['base_changes'], [])

    def test_protected_python_update_cannot_be_authorized_by_base_policy(self):
        contract = self.contract()
        contract['roots'].append({'name': 'python', 'version': '3.14.8-1', 'repo': 'core'})
        contract['allowed_base_changes'] = [{'name': 'python', 'before': '3.14.7-1', 'after': '3.14.8-1', 'repo': 'core'}]
        result = self.execute(contract)
        self.assertEqual(result['metadata_prepare_status'], 'FAIL')
        self.assertTrue(any(row.get('kind') == 'protected-root-version-rejected' for row in result['prepare']['errors']))
        self.assertTrue(all(row['preserved'] for row in result['protected']))

    def test_unprotected_base_change_requires_exact_explicit_policy(self):
        contract = self.contract(('shared-lib>=2',))
        result = self.execute(contract)
        self.assertEqual(result['metadata_prepare_status'], 'FAIL')
        self.assertEqual(result['base_changes'][0], {'name': 'shared-lib', 'before': '1-1', 'after': '2-1', 'repo': 'core', 'explicit_policy_matches': False})
        contract['allowed_base_changes'] = [{'name': 'shared-lib', 'before': '1-1', 'after': '2-1', 'repo': 'core'}]
        result = self.execute(contract)
        self.assertEqual(result['metadata_prepare_status'], 'PASS', result['blockers'])
        self.assertEqual(result['status'], 'HOLD')

    def test_provider_ambiguity_is_not_an_approved_default(self):
        self.catalogs['extra'] = [package('backend-a', provides=('backend',)), package('backend-b', provides=('backend',))]
        contract = self.contract(('backend',))
        result = self.execute(contract)
        self.assertEqual(result['metadata_prepare_status'], 'FAIL')
        self.assertTrue(any(row['code'] == 'unapproved-provider-choice' for row in result['blockers']))
        contract['providers'] = [{'requirement': 'backend', 'name': 'backend-b', 'version': '1-1', 'repo': 'extra'}]
        result = self.execute(contract)
        self.assertEqual(result['metadata_prepare_status'], 'PASS', result['blockers'])
        self.assertTrue(result['provider_bindings'][0]['final_witness_matches'])

    def test_missing_root_or_invalid_provider_never_becomes_prepared(self):
        contract = self.contract()
        contract['roots'].append({'name': 'absent', 'version': '1-1', 'repo': 'extra'})
        result = self.execute(contract)
        self.assertEqual(result['metadata_prepare_status'], 'FAIL')
        self.assertTrue(any(row['code'] == 'explicit-root-unsatisfied' for row in result['blockers']))

    def test_srcinfo_source_strings_are_inert_and_split_or_wrong_arch_refuse(self):
        contract = self.contract()
        data = Path(contract['candidate_srcinfo'][0]['srcinfo']['path']).read_bytes()
        destination = self.root / 'MUST-NOT-EXIST'
        metadata, _ = c.srcinfo(data + ('source = $(touch ' + str(destination) + ')\n').encode())
        self.assertEqual(metadata['NAME'], ['candidate']); self.assertFalse(destination.exists())
        for bad in (data + b'pkgname = second\n', data.replace(b'arch = any', b'arch = x86_64')):
            with self.assertRaises(ValueError): c.srcinfo(bad)

    def test_reference_drift_and_tuple_mismatch_fail_closed_with_reports(self):
        contract = self.contract()
        Path(contract['candidate_srcinfo'][0]['srcinfo']['path']).write_bytes(b'changed\n')
        output = self.root / 'drift'
        with self.assertRaises(ValueError): c.compose(contract, output)
        report = json.loads((output / 'composition.json').read_text())
        self.assertEqual(report['status'], 'FAIL'); self.assertTrue(report['private_database_removed'])

    def test_full_system_does_not_credit_a_minimal_project_extension(self):
        contract = self.contract(); contract['workflow'] = 'full-desktop'
        result = self.execute(contract)
        self.assertEqual(result['metadata_prepare_status'], 'FAIL')
        self.assertTrue(any(row['code'] == 'required-platform-member-missing' for row in result['blockers']))

    def test_missing_candidate_archive_is_a_named_hold_without_a_db_row(self):
        contract = self.contract(); contract['candidate_srcinfo'][0]['archive'] = None
        result = self.execute(contract)
        self.assertEqual(result['metadata_prepare_status'], 'FAIL')
        self.assertEqual(result['current_candidates'][0]['status'], 'HOLD-missing-exact-candidate-archive')
        self.assertFalse(any(row['name'] == 'candidate' for row in result['proposed_final_inventory']))

    def test_actual_archive_metadata_must_correspond_to_pinned_srcinfo(self):
        contract = self.contract()
        item = contract['candidate_srcinfo'][0]
        changed = Path(item['srcinfo']['path']).read_bytes().replace(b'depends = python>=3.11', b'depends = different-runtime')
        item['srcinfo'] = self.ref('mismatched.SRCINFO', changed)
        with self.assertRaises(ValueError): c.compose(contract, self.root / 'mismatch')
        report = json.loads((self.root / 'mismatch/composition.json').read_text())
        self.assertIn('SRCINFO/archive relations differ', report['error'])

    def test_excluded_catalog_root_is_named_and_never_silently_satisfied(self):
        malformed = package('filtered-root'); malformed.pop('FILENAME')
        self.catalogs['extra'] = [malformed]
        contract = self.contract(); contract['roots'].append({'name': 'filtered-root', 'version': '1-1', 'repo': 'extra'})
        result = self.execute(contract)
        self.assertEqual(result['metadata_prepare_status'], 'FAIL')
        self.assertTrue(any('filtered-root' in row.get('entry', '') for row in result['holds']))
        self.assertTrue(any(row['code'] == 'exact-target-pin-unavailable' for row in result['blockers']))

    def test_worker_failure_keeps_inputs_and_failed_report_without_killing_adapter(self):
        contract = self.contract()
        original = c.subprocess.run
        def interrupted(argv, **kwargs):
            if any(str(value).endswith('prepare_worker.py') for value in argv):
                return subprocess.CompletedProcess(argv, -11, b'', b'simulated bounded C-worker failure\n')
            return original(argv, **kwargs)
        output = self.root / 'worker-failure'
        with mock.patch.object(c.subprocess, 'run', side_effect=interrupted), self.assertRaises(ValueError):
            c.compose(contract, output)
        report = json.loads((output / 'composition.json').read_text())
        self.assertEqual(report['status'], 'FAIL'); self.assertTrue(report['private_database_removed'])
        self.assertTrue((output / 'preparation-inputs.json').is_file())
        self.assertIn(b'C-worker failure', (output / 'prepare.stderr').read_bytes())

    def test_worker_exception_is_visible_after_private_test_cleanup(self):
        contract = self.contract()
        original = c.subprocess.run
        stderr = b'SUPPORTED_COMPOSITION_ERROR {"category":"ValueError","message":"unreviewed libalpm ABI: 13.0.2"}\n'
        def refused(argv, **kwargs):
            if any(str(value).endswith('prepare_worker.py') for value in argv):
                return subprocess.CompletedProcess(argv, 1, b'', stderr)
            return original(argv, **kwargs)
        with mock.patch.object(c.subprocess, 'run', side_effect=refused):
            with self.assertRaisesRegex(ValueError, 'ValueError.*unreviewed libalpm ABI: 13.0.2'):
                c.compose(contract, self.root / 'abi-refusal')

    def test_real_worker_reports_bounded_safe_exception_and_parent_escapes_fallback(self):
        process = subprocess.run([c.sys.executable, '-I', '-B', str(Path(c.__file__).with_name('prepare_worker.py')),
                                  str(self.root / 'wrong-name.json')], capture_output=True, timeout=10)
        self.assertEqual(process.returncode, 1)
        diagnostic = json.loads(c.worker_diagnostic(process.stderr))
        self.assertEqual(diagnostic['category'], 'ValueError')
        self.assertEqual(diagnostic['message'], 'private engine input path refused')
        fallback = c.worker_diagnostic(b'x' * 10000 + b'\n\x1b[31m::error::unsafe\xff\n')
        self.assertLess(len(fallback), 3200)
        self.assertNotIn('\n', fallback); self.assertNotIn('\x1b', fallback)
        self.assertEqual(json.loads(fallback)['stderr_tail'][-20:], '[31m::error::unsafe\\xff\n'[-20:])


if __name__ == '__main__':
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    unittest.main(verbosity=2)

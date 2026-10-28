#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 cachy-asahi contributors
"""Synthetic receipt integrity checks; no Docker, compilation or installation."""
import sys
sys.dont_write_bytecode = True

import copy
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import subprocess
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
spec = importlib.util.spec_from_file_location('fdk_evidence_fixture', HERE / 'evidence.py')
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)
INPUT_BYTES = (ROOT / 'scripts/ci/inputs.lock.json').read_bytes()
INPUTS = json.loads(INPUT_BYTES)
PACKAGES = {row['name'][0]: row['version'][0] for row in INPUTS['rootfs_packages']}
PACKAGES.update({row['name']: row['version'] for row in INPUTS['packages']})
LOCK_BYTES = ''.join(f'{name} {version}\n' for name, version in sorted(PACKAGES.items())).encode()
ARCHES = {row['name'][0]: row['arch'][0] for row in INPUTS['rootfs_packages']}
ARCHES.update({row['name']: row['arch'] for row in INPUTS['packages']})
IMAGE = 'sha256:' + '2' * 64
COMMIT = 'a' * 40
SCRIPT_SHA = '1' * 64
NAME = 'cachy-asahi-' + '3' * 16
FILENAME = 'cachy-asahi-fdk-aac-3.0.0-1-aarch64.pkg.tar.xz'
REVIEWED = {'PKGBUILD': evidence.sha(b'original synthetic recipe'),
            '.SRCINFO': evidence.sha(b'original synthetic metadata')}
REQUIRED = {'build.log', 'validation.json', 'expected-packages.lock',
            'artifacts/packages.lock', 'artifacts/generated.SRCINFO',
            'artifacts/environment.txt', 'artifacts/config.sha256',
            'artifacts/makepkg.conf', 'artifacts/pacman.conf',
            'artifacts/fdk-build-commands.json'}


def base_records():
    bootstrap = {'status': 'image-provisioned', 'image_id': IMAGE,
                 'packages_lock_sha256': evidence.INVENTORY_SHA,
                 'inputs_sha256': evidence.INPUTS_SHA}
    result = {'native_build': 'PASS', 'status': 'failed',
              'reviewed_inputs_sha256': evidence.INPUTS_SHA,
              'reviewed_recipes_sha256': evidence.ORIGINALS_SHA,
              'bootstrap_script_sha256': SCRIPT_SHA}
    return bootstrap, result


def receipt():
    return {'status': 'built-package-static-pass', 'mode': 'native',
            'network': 'none', 'image': IMAGE, 'image_id': IMAGE,
            'builder_host_arch': 'aarch64', 'source_date_epoch': evidence.EPOCH,
            'exit_code': 0, 'entry_script_sha256': evidence.ENTRY_SHA, 'recipe_inputs': dict(REVIEWED),
            'expected_packages_sha256': evidence.INVENTORY_SHA,
            'clean_environment_id': NAME, 'artifacts': {FILENAME: '4' * 64},
            'files': {name: '5' * 64 for name in REQUIRED},
            'command': ['docker', 'run', '--rm', '--name', NAME, '--pull=never',
                        '--platform', 'linux/arm64', '--user', '1001:1001',
                        '--cap-drop=ALL', '--security-opt=no-new-privileges', '--read-only',
                        '--pids-limit', '512', '--memory', '4g', '--cpus', '4',
                        '--network', 'none', '--tmpfs', '/tmp:rw,nosuid,nodev,exec,size=4g',
                        '--env', 'CACHY_ASAHI_CONTAINER=1',
                        '--env', f'SOURCE_DATE_EPOCH={evidence.EPOCH}',
                        '--mount', 'type=bind,src=/tmp/fixture/inputs,dst=/inputs,readonly',
                        '--mount', 'type=bind,src=/tmp/fixture/artifacts,dst=/out',
                        '--mount', 'type=bind,src=/fixture/container-entry.sh,dst=/builder-entry.sh,readonly',
                        '--mount', 'type=bind,src=/tmp/fixture/expected-packages.lock,dst=/expected-packages.lock,readonly',
                        '--entrypoint', '/bin/bash', IMAGE, '/builder-entry.sh']}


class BaseTests(unittest.TestCase):
    def setUp(self):
        self.bootstrap, self.result = base_records()

    def accept(self, lock=LOCK_BYTES, inputs=INPUT_BYTES, image=IMAGE, commit=COMMIT):
        return evidence.accepted_base(self.bootstrap, lock, inputs, self.result,
                                      image, commit, SCRIPT_SHA)

    def test_exact_refreshed_341_inventory_binds_source_without_lifecycle_claim(self):
        self.assertEqual(evidence.sha(LOCK_BYTES), evidence.INVENTORY_SHA)
        self.assertEqual(evidence.sha(INPUT_BYTES), evidence.INPUTS_SHA)
        result = self.accept()
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(result['package_count'], 341)
        self.assertEqual(result['source_commit'], COMMIT)
        self.assertEqual(result['original_lifecycle_acceptance'], 'NOT INFERRED')

    def test_shared_kernel_functions_unchanged_and_standalone_without_worker_helper(self):
        pins = {'read': 'c176ad34b718a2025c285959c37e383e0d88bc702e28b7d28817baaf4421bf50',
            'inventory': '77efbfa3348e158bc8bb90fd4cc2e641697172c77d51808c3c54d06e150ff0e1',
            'accepted_base': '2bd338ec702083bb1c3ef83966c428ee2c7ac0a296c6d32f581da7e57d32c7c7'}
        for node in ast.parse(Path(evidence.__file__).read_bytes()).body:
            if isinstance(node, ast.FunctionDef) and node.name in pins:
                self.assertEqual(hashlib.sha256(ast.dump(node, include_attributes=False).encode()).hexdigest(), pins[node.name])
        code = '''import importlib.util,json,sys
spec=importlib.util.spec_from_file_location('standalone_kernel_helper',sys.argv[1])
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
p=json.loads(sys.stdin.read())
r=m.accepted_base(p['bootstrap'],p['lock'].encode(),p['inputs'].encode(),p['result'],p['image'],p['commit'],p['script'])
assert r['status']=='PASS' and 'worker_evidence' not in sys.modules
'''
        payload = {'bootstrap': self.bootstrap, 'lock': LOCK_BYTES.decode(), 'inputs': INPUT_BYTES.decode(),
                   'result': self.result, 'image': IMAGE, 'commit': COMMIT, 'script': SCRIPT_SHA}
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([sys.executable, '-I', '-B', '-c', code, evidence.__file__],
                input=json.dumps(payload).encode(), capture_output=True, timeout=5, cwd=directory)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(evidence.inventory(LOCK_BYTES), PACKAGES)

    def test_inventory_byte_changes_old_snapshot_and_missing_lf_fail(self):
        for data in (LOCK_BYTES[:-1], LOCK_BYTES.replace(b'\n', b'\r\n'),
                     LOCK_BYTES.replace(b'perl 5.42.3-1', b'perl 5.42.2-1'),
                     LOCK_BYTES + b'new-package 1-1\n'):
            with self.subTest(digest=evidence.sha(data)):
                with self.assertRaises(ValueError):
                    self.accept(lock=data)

    def test_inventory_format_checks_still_reject_re_pinned_fixture(self):
        rows = LOCK_BYTES.splitlines(keepends=True)
        for data in (b''.join(reversed(rows)), b''.join([rows[1]] + rows[1:]),
                     b''.join(rows[:-1]), LOCK_BYTES.replace(b' ', b'  ', 1)):
            with self.subTest(length=len(data)):
                with mock.patch.object(evidence, 'INVENTORY_SHA', evidence.sha(data)):
                    with self.assertRaises(ValueError):
                        evidence.inventory(data)

    def test_input_sidecar_and_immutable_image_commit_are_required(self):
        with self.assertRaises(ValueError):
            self.accept(inputs=INPUT_BYTES + b' ')
        for image in ('latest', 'sha256:' + '2' * 63, 'sha256:' + 'G' * 64, IMAGE + '\n'):
            with self.subTest(image=image):
                with self.assertRaises(ValueError):
                    self.accept(image=image)
        for commit in ('main', 'a' * 39, 'A' * 40, COMMIT + '\n'):
            with self.subTest(commit=commit):
                with self.assertRaises(ValueError):
                    self.accept(commit=commit)

    def test_bootstrap_identity_and_accepted_original_build_fields_are_bound(self):
        original = copy.deepcopy((self.bootstrap, self.result))
        for key, value in (('status', 'failed'), ('image_id', 'sha256:' + '9' * 64),
                           ('packages_lock_sha256', '0' * 64), ('inputs_sha256', '0' * 64)):
            self.bootstrap, self.result = copy.deepcopy(original)
            self.bootstrap[key] = value
            with self.subTest(bootstrap=key), self.assertRaises(ValueError):
                self.accept()
        for key in ('native_build', 'reviewed_inputs_sha256', 'reviewed_recipes_sha256',
                    'bootstrap_script_sha256'):
            self.bootstrap, self.result = copy.deepcopy(original)
            self.result[key] = 'incorrect'
            with self.subTest(result=key), self.assertRaises(ValueError):
                self.accept()


class ReceiptTests(unittest.TestCase):
    def test_valid_receipt_returns_only_bound_artifact_and_owned_name(self):
        record = receipt()
        before = copy.deepcopy(record)
        self.assertEqual(evidence.validate_receipt(record, REVIEWED, IMAGE),
                         {'filename': FILENAME, 'sha256': '4' * 64, 'container_name': NAME})
        self.assertEqual(record, before)

    def test_changed_identity_epoch_inventory_and_reviewed_sources_fail(self):
        for key, value in (('status', 'failed'), ('mode', 'emulated'), ('network', 'bridge'),
                           ('image', 'sha256:' + '9' * 64), ('image_id', 'sha256:' + '9' * 64),
                           ('source_date_epoch', evidence.EPOCH + 1),
                           ('expected_packages_sha256', '0' * 64), ('recipe_inputs', {})):
            record = receipt()
            record[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                evidence.validate_receipt(record, REVIEWED, IMAGE)

    def test_missing_evidence_wrong_artifact_identity_and_unowned_names_fail(self):
        for missing in REQUIRED:
            record = receipt()
            del record['files'][missing]
            with self.subTest(missing=missing), self.assertRaises(ValueError):
                evidence.validate_receipt(record, REVIEWED, IMAGE)
        for artifacts in ({}, {FILENAME: 'invalid'}, {'../' + FILENAME: '4' * 64},
                          {'other-3.0.0-1-aarch64.pkg.tar.xz': '4' * 64},
                          {FILENAME: '4' * 64, 'extra.pkg.tar.xz': '6' * 64}):
            record = receipt()
            record['artifacts'] = artifacts
            with self.subTest(artifacts=artifacts), self.assertRaises(ValueError):
                evidence.validate_receipt(record, REVIEWED, IMAGE)
        for name in ('shared-container', NAME + '\n', 'cachy-asahi-' + 'A' * 16):
            record = receipt()
            record['clean_environment_id'] = name
            with self.subTest(name=name), self.assertRaises(ValueError):
                evidence.validate_receipt(record, REVIEWED, IMAGE)

    def test_nonzero_exit_or_non_native_builder_cannot_satisfy_native_receipt(self):
        for key, value in (('exit_code', 1), ('exit_code', False),
                           ('builder_host_arch', 'x86_64'), ('entry_script_sha256', '0' * 64)):
            record = receipt()
            record[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                evidence.validate_receipt(record, REVIEWED, IMAGE)

    def test_command_name_image_network_resources_and_environment_are_bound(self):
        for original, replacement in ((NAME, 'cachy-asahi-' + '8' * 16),
                                       (IMAGE, 'sha256:' + '8' * 64),
                                       ('none', 'bridge'), ('512', '1024'), ('4g', '8g'),
                                       ('CACHY_ASAHI_CONTAINER=1', 'CACHY_ASAHI_CONTAINER=0'),
                                       (f'SOURCE_DATE_EPOCH={evidence.EPOCH}', 'SOURCE_DATE_EPOCH=0')):
            record = receipt()
            record['command'][record['command'].index(original)] = replacement
            with self.subTest(original=original), self.assertRaises(ValueError):
                evidence.validate_receipt(record, REVIEWED, IMAGE)
        record = receipt()
        record['command'].remove('--read-only')
        with self.assertRaises(ValueError):
            evidence.validate_receipt(record, REVIEWED, IMAGE)


class AttemptTests(unittest.TestCase):
    """Fake inspector callbacks test binding, never actual package acceptance."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / 'attempt'
        self.directory.mkdir()
        for folder in ('inputs', 'artifacts'):
            (self.directory / folder).mkdir()
        for name, data in (('PKGBUILD', b'original synthetic recipe'),
                           ('.SRCINFO', b'original synthetic metadata')):
            (self.directory / 'inputs' / name).write_bytes(data)
        archive = self.directory / 'artifacts' / FILENAME
        archive.write_bytes(b'original synthetic invalid archive; fake-inspector unit fixture only')
        checksum = evidence.digest(archive)
        self.package = {'artifact': FILENAME, 'sha256': checksum, 'errors': [], 'review': [],
                        'status': 'artifact-static-pass', 'members': {},
                        'elf': {name: {'machine': 183, 'load_segments': 1, 'errors': [],
                                       'hardware_status': 'NOT RUN'} for name in
                                ('usr/lib/libfdk-aac.so.2.0.4', 'usr/lib/libfdk-xhe-aac.so.0.0.0')},
                        'metadata': {'.BUILDINFO': {'format': ['2'],
                            'pkgname': ['cachy-asahi-fdk-aac'], 'pkgbase': ['cachy-asahi-fdk-aac'],
                            'pkgver': ['3.0.0-1'], 'pkgarch': ['aarch64'],
                            'builddate': [str(evidence.EPOCH)],
                            'pkgbuild_sha256sum': [REVIEWED['PKGBUILD']],
                            'installed': sorted(n + '-' + v + '-' + ARCHES[n]
                                                for n, v in PACKAGES.items())},
                            '.PKGINFO': {'pkgname': ['cachy-asahi-fdk-aac'],
                                'pkgbase': ['cachy-asahi-fdk-aac'], 'pkgver': ['3.0.0-1'],
                                'arch': ['aarch64'], 'builddate': [str(evidence.EPOCH)],
                                'license': ['LicenseRef-Fraunhofer', 'LicenseRef-Fraunhofer-xHE-AAC', 'MIT'],
                                'depend': ['glibc'], 'provides': ['libfdk-aac=3.0.0',
                                    'libfdk-aac.so=2-64', 'libfdk-xhe-aac.so=0-64'],
                                'conflict': ['libfdk-aac']}}}
        abi = {'status': 'native-ELF-ABI-pass', 'libraries': {
            name: {'soname': soname, 'exports': count, 'elf_16k_geometry': 'PASS',
                   'needed': ['libc.so.6', 'libm.so.6']} for name, soname, count in
            [('libfdk-aac', 'libfdk-aac.so.2', 18), ('libfdk-xhe-aac', 'libfdk-xhe-aac.so.0', 63)]}}
        self.log = (json.dumps(abi) + '\n' +
            'PASS: classic AAC-LC ADTS roundtrip; 32 decoded mono frames at 48000 Hz\n' +
            'PASS: xHE API 1.0AOSP configuration lifecycle; encoding/roundtrip NOT RUN\n').encode()
        self.record = receipt()
        self.record['artifacts'][FILENAME] = checksum
        self.record['recipe_metadata'] = {'pkgname': ['cachy-asahi-fdk-aac'],
            'pkgbase': ['cachy-asahi-fdk-aac'], 'pkgver': ['3.0.0'], 'pkgrel': ['1'],
            'arch': ['aarch64'], 'depends': ['glibc'],
            'license': ['LicenseRef-Fraunhofer', 'LicenseRef-Fraunhofer-xHE-AAC', 'MIT'],
            'provides': ['libfdk-aac=3.0.0', 'libfdk-aac.so=2-64', 'libfdk-xhe-aac.so=0-64'],
            'conflicts': ['libfdk-aac']}
        self.metadata = copy.deepcopy(self.record['recipe_metadata'])
        self.record['entry_script_sha256'] = evidence.ENTRY_SHA
        self.record['command'] = [value.replace('/tmp/fixture', str(self.directory))
                                  for value in self.record['command']]
        self.contents = {name: b'original synthetic environment fixture' for name in REQUIRED}
        self.contents.update({'build.log': self.log, 'expected-packages.lock': LOCK_BYTES,
                              'artifacts/packages.lock': LOCK_BYTES,
                              'artifacts/' + FILENAME: archive.read_bytes()})
        self.write_fixture()

    def write_fixture(self):
        self.contents['validation.json'] = json.dumps({'artifacts': [self.package], 'errors': []}).encode()
        for name, data in self.contents.items():
            (self.directory / name).write_bytes(data)
        self.record['files'] = {name: evidence.sha(data) for name, data in self.contents.items()}
        (self.directory / 'provenance.json').write_text(json.dumps(self.record))

    def verify(self, inspector=None, recipe_inspector=None, binder=None, **captured):
        if inspector is None:
            inspector = lambda path: copy.deepcopy(self.package)
        if recipe_inspector is None:
            recipe_inspector = lambda path: {'errors': [], 'input_sha256': dict(REVIEWED),
                                             'metadata': copy.deepcopy(self.metadata)}
        if binder is None:
            binder = lambda metadata, package, checksum: []
        return evidence.verify_attempt(self.directory, REVIEWED, IMAGE, inspector,
                                       recipe_inspector, binder, **captured)

    def test_captured_provenance_and_log_are_reused_without_mutable_reread(self):
        record, log = copy.deepcopy(self.record), bytes(self.log)
        (self.directory / 'provenance.json').write_text('{"raw":"private poison"}')
        (self.directory / 'build.log').write_bytes(b'private poisoned log')
        original_load, original_read, original_digest = evidence.load, evidence.read, evidence.digest
        def guarded(operation):
            def call(path, *args, **kwargs):
                self.assertNotIn(Path(path).name, ('provenance.json', 'build.log'))
                return operation(path, *args, **kwargs)
            return call
        with mock.patch.object(evidence, 'load', guarded(original_load)), \
             mock.patch.object(evidence, 'read', guarded(original_read)), \
             mock.patch.object(evidence, 'digest', guarded(original_digest)):
            self.assertEqual(self.verify(record=record, log_bytes=log)['classic_decoded_frames'], 32)
        with self.assertRaises(ValueError): self.verify(record=record, log_bytes=log + b'poison')

    def test_synthetic_inspector_binds_hashes_inventory_abi_and_smoke_scope(self):
        called = []
        def fake_inspector(path):
            called.append(Path(path))
            return copy.deepcopy(self.package)
        result = self.verify(fake_inspector)
        self.assertEqual(called, [self.directory / 'artifacts' / FILENAME])
        self.assertEqual(result['classic_decoded_frames'], 32)
        self.assertEqual(result['xhe_scope'], 'configuration-only')
        self.assertEqual(result['hardware'], 'NOT RUN')

    def test_recorded_validation_cannot_replace_actual_archive_inspection(self):
        def reject_invalid_archive(path):
            raise ValueError('synthetic invalid package archive')
        with self.assertRaises(ValueError):
            self.verify(reject_invalid_archive)
        parsed = copy.deepcopy(self.package)
        parsed['metadata']['.PKGINFO']['pkgver'] = ['unexpected-version']
        with self.assertRaises(ValueError):
            self.verify(lambda path: parsed)

    def test_recorded_recipe_metadata_requires_fresh_recipe_and_artifact_binding(self):
        for field, value in (('errors', ['synthetic recipe failure']),
                             ('input_sha256', {}), ('metadata', {})):
            report = {'errors': [], 'input_sha256': dict(REVIEWED),
                      'metadata': copy.deepcopy(self.metadata)}
            report[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.verify(recipe_inspector=lambda path: report)
        self.record['recipe_metadata']['conflicts'] = []
        self.write_fixture()
        with self.assertRaises(ValueError):
            self.verify()
        self.record['recipe_metadata'] = copy.deepcopy(self.metadata)
        self.write_fixture()
        with self.assertRaises(ValueError):
            self.verify(binder=lambda metadata, package, checksum: ['synthetic relation mismatch'])

    def test_changed_file_hashes_recipe_snapshot_and_extra_archive_are_rejected(self):
        log = self.directory / 'build.log'
        log.write_bytes(self.log + b'changed')
        with self.assertRaises(ValueError):
            self.verify()
        log.write_bytes(self.log)
        recipe = self.directory / 'inputs' / 'PKGBUILD'
        recipe.write_bytes(b'changed recipe')
        with self.assertRaises(ValueError):
            self.verify()
        recipe.write_bytes(b'original synthetic recipe')
        extra = self.directory / 'artifacts' / 'extra.pkg.tar.xz'
        extra.write_bytes(b'extra archive')
        with self.assertRaises(ValueError):
            self.verify()

    def test_buildinfo_installed_set_is_bijective_with_version_and_supported_architecture(self):
        original = list(self.package['metadata']['.BUILDINFO']['installed'])
        for installed in (original[:-1], original + [original[0]],
                          [row.removesuffix('-aarch64').removesuffix('-any') for row in original],
                          [original[0].rsplit('-', 1)[0] + '-x86_64'] + original[1:]):
            self.package['metadata']['.BUILDINFO']['installed'] = installed
            self.write_fixture()
            with self.subTest(length=len(installed)), self.assertRaises(ValueError):
                self.verify()

    def test_changed_or_missing_classic_and_xhe_smoke_markers_are_rejected(self):
        for log in (self.log.replace(b'32 decoded', b'2 decoded'),
                    self.log.replace(b'encoding/roundtrip NOT RUN', b'encoding/roundtrip PASS'),
                    self.log + self.log,
                    self.log.replace(b'native-ELF-ABI-pass', b'unverified-ELF-ABI-pass')):
            self.contents['build.log'] = log
            self.write_fixture()
            with self.subTest(length=len(log)), self.assertRaises(ValueError):
                self.verify()

    def test_escaping_evidence_record_is_rejected_before_reading_outside_attempt(self):
        self.record['files']['../outside'] = '0' * 64
        (self.directory / 'provenance.json').write_text(json.dumps(self.record))
        with self.assertRaises(ValueError):
            self.verify()


class ComparisonTests(unittest.TestCase):
    def setUp(self):
        self.record = {'status': 'contents-reproduced', 'errors': [],
                       'packages': {FILENAME: {key: True for key in
                           ('bytes_equal', 'installed_contents_equal', 'pkginfo_equal', 'buildinfo_equal')}}}
        self.names = [NAME, 'cachy-asahi-' + '6' * 16]

    def test_all_four_equalities_and_distinct_containers_are_required(self):
        self.assertEqual(evidence.compare_result(self.record, FILENAME, self.names)['status'], 'PASS')
        for field in self.record['packages'][FILENAME]:
            for value in (False, None, 1, 'true'):
                record = copy.deepcopy(self.record)
                record['packages'][FILENAME][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    evidence.compare_result(record, FILENAME, self.names)
        with self.assertRaises(ValueError):
            evidence.compare_result(self.record, FILENAME, [NAME, NAME])

    def test_false_pass_extra_artifact_and_recorded_error_are_rejected(self):
        for key, value in (('status', 'PASS'), ('errors', ['fixture mismatch']), ('packages', {})):
            record = copy.deepcopy(self.record)
            record[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                evidence.compare_result(record, FILENAME, self.names)
        self.record['packages']['extra.pkg.tar.xz'] = dict(self.record['packages'][FILENAME])
        with self.assertRaises(ValueError):
            evidence.compare_result(self.record, FILENAME, self.names)


class PublicStatusTests(unittest.TestCase):
    def setUp(self):
        from test_worker import passing_workers
        self.report = {'status': 'PASS', 'cancelled': False, 'phase': 'complete',
                       'worker_diagnostics': passing_workers(),
                       'cleanup': {'status': 'PASS', 'absence_verified': True},
                       'comparison': {'status': 'PASS'},
                       'accepted_base': {'status': 'PASS'}, 'live_base': {'status': 'PASS'},
                       'source': {'status': 'PASS'},
                       'build-1': {'status': 'PASS', 'cleanup': {'status': 'PASS', 'absence_verified': True}},
                       'build-2': {'status': 'PASS', 'cleanup': {'status': 'PASS', 'absence_verified': True}},
                       'error': 'SECRET fixture path /private/username',
                       'logs': ['SECRET fixture command stdout'], 'environment': {'SECRET': 'fixture'}}

    def test_public_pass_requires_cleanup_comparison_and_no_cancellation(self):
        self.assertEqual(evidence.finalstatus_public(self.report)['status'], 'PASS')
        for change in ({'cancelled': True}, {'cancelled': None}, {'status': 'failed'},
                       {'cleanup': {'status': 'PASS', 'absence_verified': False}},
                       {'cleanup': {'status': 'unknown', 'absence_verified': True}},
                       {'comparison': {'status': 'FAIL'}}, {'phase': 'build-1'}):
            with self.subTest(change=change):
                report = {**self.report, **change}
                result = evidence.finalstatus_public(report)
                self.assertEqual(result['status'], 'FAIL')
                self.assertEqual(result['native_build'], 'NOT ACCEPTED')

    def test_schema2_has_no_fallback_legacy_pair_acceptance_or_unknown_diagnostics(self):
        row = evidence.finalstatus_public(self.report)
        self.assertEqual((row['schema_version'], len(row)), (2, 13))
        legacy = copy.deepcopy(self.report); legacy.pop('worker_diagnostics')
        self.assertEqual(evidence.finalstatus_public(legacy)['status'], 'FAIL')
        for action in ('build-1', 'build-2', 'compare'):
            changed = copy.deepcopy(self.report)
            changed['worker_diagnostics'][action]['exit']['code'] = 1
            changed['worker_diagnostics'][action]['exit']['kind'] = 'EXIT_NONZERO'
            self.assertEqual(evidence.finalstatus_public(changed)['status'], 'FAIL')
        changed = copy.deepcopy(self.report); changed['worker_diagnostics']['build-1']['observation']['raw'] = 'SECRET'
        with self.assertRaises(ValueError): evidence.finalstatus_public(changed)

    def test_distinct_attempt_bindings_and_projection_snapshot_are_required(self):
        original = evidence.finalstatus_public(self.report)
        self.report['worker_diagnostics']['build-1']['observation']['builder']['reason'] = 'SECRET'
        self.assertNotIn('SECRET', json.dumps(original))
        changed = copy.deepcopy(self.report)
        changed['worker_diagnostics']['build-1']['observation']['builder']['reason'] = 'NONE'
        changed['worker_diagnostics']['build-2']['observation']['binding_sha256'] = \
            changed['worker_diagnostics']['build-1']['observation']['binding_sha256']
        with self.assertRaisesRegex(ValueError, 'worker-public-distinct-bindings'):
            evidence.finalstatus_public(changed)

    def test_public_pass_requires_every_stage_and_both_worker_cleanups(self):
        for stage in ('accepted_base', 'live_base', 'source', 'build-1', 'build-2'):
            report = copy.deepcopy(self.report)
            del report[stage]
            with self.subTest(missing=stage):
                self.assertEqual(evidence.finalstatus_public(report)['status'], 'FAIL')
            report = copy.deepcopy(self.report)
            report[stage]['status'] = 'FAIL'
            with self.subTest(failed=stage):
                self.assertEqual(evidence.finalstatus_public(report)['status'], 'FAIL')
        for stage in ('build-1', 'build-2'):
            report = copy.deepcopy(self.report)
            report[stage]['cleanup']['absence_verified'] = False
            with self.subTest(cleanup=stage):
                self.assertEqual(evidence.finalstatus_public(report)['status'], 'FAIL')

    def test_modern_pass_refuses_each_missing_inner_group(self):
        for action in ('build-1', 'build-2', 'compare'):
            report = copy.deepcopy(self.report)
            report['worker_diagnostics'][action]['observation'].pop('inner')
            with self.subTest(action=action), self.assertRaisesRegex(ValueError, 'worker-public-incomplete'):
                evidence.finalstatus_public(report)

    def test_historical_failure_retains_valid_legacy_observation(self):
        report = copy.deepcopy(self.report)
        report['status'] = 'FAIL'
        for row in report['worker_diagnostics'].values():
            row['observation'].pop('inner')
        result = evidence.finalstatus_public(report)
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['native_build'], 'NOT ACCEPTED')
        self.assertTrue(all('inner' not in row['observation']
                            for row in result['worker_diagnostics'].values()))

    def test_public_result_never_exports_raw_error_logs_environment_or_extra_fields(self):
        for report in (self.report, {**self.report, 'status': 'failed', 'phase': 'SECRET fixture'}):
            result = evidence.finalstatus_public(report)
            self.assertNotIn('SECRET', json.dumps(result))
            self.assertNotIn('error', result)
            self.assertEqual(result['hardware'], 'NOT RUN')
            self.assertEqual(result['installation'], 'NOT RUN')
            self.assertFalse(result['selected_for_release'])
            self.assertEqual(result['binary_publication'], 'NOT RUN')


class FileBoundaryTests(unittest.TestCase):
    def test_regular_read_rejects_links_fifo_oversize_and_parent_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            file = root / 'input'
            file.write_bytes(b'original fixture')
            self.assertEqual(evidence.read(file), b'original fixture')
            with self.assertRaises(ValueError):
                evidence.read(file, 2)
            for name, creator in (('symlink', lambda path: path.symlink_to(file)),
                                  ('hardlink', lambda path: os.link(file, path)),
                                  ('fifo', os.mkfifo)):
                path = root / name
                creator(path)
                with self.subTest(name=name), self.assertRaises(ValueError):
                    evidence.read(path)
                path.unlink()
            real = root / 'real'
            real.mkdir()
            (real / 'input').write_bytes(b'fixture')
            link = root / 'parent-link'
            link.symlink_to(real, target_is_directory=True)
            with self.assertRaises(ValueError):
                evidence.read(link / 'input')

    def test_json_duplicates_nonfinite_values_and_nonobjects_are_rejected(self):
        for data in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}', b'[]', b'null'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                evidence.decode(data)

    def test_evidence_relative_paths_are_canonical(self):
        for name in ('../file', '/absolute', './file', 'a//file', 'a/../file',
                     'a\\file', 'line\nfile', ''):
            with self.subTest(name=name), self.assertRaises(ValueError):
                evidence.safe_relative(name)
        self.assertEqual(evidence.safe_relative('artifacts/packages.lock'), Path('artifacts/packages.lock'))


class InnerProjectionTests(unittest.TestCase):
    """Pure finite-schema/gate controls; no native actors or invocation claims."""
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(HERE))
        import worker_evidence
        cls.public = worker_evidence
        spec = importlib.util.spec_from_file_location('inner_schema_fixture',
            ROOT / 'packages/libraries/cachy-asahi-fdk-aac/inner_observation.py')
        cls.helper = importlib.util.module_from_spec(spec); spec.loader.exec_module(cls.helper)

    def private_inner(self, sampled=True):
        attempt = {'kind':'COMPILE', 'index':0, 'natural':False, 'returncode':None}
        return {'schema_version':1, 'bindings':{key:'a'*64 for key in self.helper.BINDINGS},
            'phase':'BUILD', 'first_failure':None, 'cancelled':False, 'write_failed':False,
            'compiler_attempted':sampled, 'compiler_attempt_count':int(sampled),
            'compiler_natural_count':int(sampled), 'first_compiler_attempt':attempt if sampled else None,
            'first_compiler_natural':attempt | {'natural':True,'returncode':0} if sampled else None,
            'publication':'NOT ACCEPTED'}

    def projected_inner(self, value=None):
        value = copy.deepcopy(value if value is not None else self.private_inner())
        value.pop('bindings'); value['binding_sha256'] = 'b'*64
        return value

    def bound_group(self, value=None):
        return {'availability':'BOUND','reason':'OBSERVED','raw_sha256':'c'*64,
                'observation':self.projected_inner(value)}

    def outer(self, action='build-1', inner=True):
        config = {'source_commit':COMMIT,'stage_lock_sha256':'d'*64,'run_id':'1',
                  'run_attempt':'2','action':action,'nonce':'e'*32}
        row = self.public.initial(config, 'f'*64)
        if not inner: row.pop('inner')
        row['current_predicate'] = 'COMPLETE'
        if action != 'compare':
            row['builder'].update(exit=self.public.exit_record(0),status='STATIC_PASS',
                provenance={'bytes':1,'sha256':'1'*64},log={'bytes':1,'sha256':'2'*64})
            row['commands'] = {name:self.public.exit_record(0) for name in ('create','attach','container')}
            row['cleanup'] = {'status':'PASS','absence':'PASS','reason':'NONE'}
            if inner: row['inner'] = self.bound_group()
        return row

    def vector(self, inner=True):
        return {action:{'availability':'VERIFIED','exit':self.public.exit_record(0),
            'observation':self.public.project(self.outer(action, inner))} for action in self.public.ACTIONS}

    def test_legacy_shape_is_historical_only_and_new_initial_is_unknown(self):
        row = self.outer(inner=False)
        self.assertNotIn('inner', self.public.project(row))
        self.public.validate_workers(self.vector(False))
        with self.assertRaisesRegex(ValueError, 'worker-public-incomplete'):
            self.public.validate_workers(self.vector(False), require_complete=True)
        row = self.outer(); row['current_predicate'] = 'CONFIG'
        row['inner'] = self.public.initial_inner()
        self.assertEqual(self.public.project(row)['inner'],
            {'availability':'UNKNOWN','reason':'NOT_OBSERVED','raw_sha256':None,'observation':None})
        self.assertNotIn('compiler', json.dumps(row['inner']))

    def test_public_and_private_schema_concordance_and_nonzero_implication(self):
        for name in ('PHASES','PREDICATES','REASONS','LIMIT'):
            self.assertEqual(getattr(self.public, 'INNER_'+name), getattr(self.helper,name))
        self.assertEqual(self.public.INNER_FIELDS,
            self.helper.FIELDS - {'bindings'} | {'binding_sha256'})
        original = self.private_inner()
        mutations = [
            lambda value:value.update(schema_version=True),
            lambda value:value.update(phase='PASS'),
            lambda value:value.update(compiler_attempt_count=398),
            lambda value:value.update(compiler_natural_count=2),
            lambda value:value.update(compiler_attempted=False),
            lambda value:value.update(first_compiler_attempt=None),
            lambda value:value.update(first_compiler_natural=None),
            lambda value:value['first_compiler_attempt'].update(natural=True,returncode=0),
            lambda value:value['first_compiler_natural'].update(index=1),
            lambda value:value['first_compiler_natural'].update(returncode=7),
            lambda value:value['first_compiler_natural'].update(returncode=True),
            lambda value:value['first_compiler_natural'].update(kind='LINK',index=2),
            lambda value:value.update(first_failure={'phase':'BUILD','predicate':'UNKNOWN',
                'reason':'CANCELLED','command':None}),
            lambda value:value.update(first_failure={'phase':'BUILD','predicate':'UNKNOWN',
                'reason':'NONZERO','command':None}),
            lambda value:value.update(first_failure={'phase':'BUILD','predicate':'COMPILER_NONZERO',
                'reason':'NONZERO','command':value['first_compiler_natural']}),
        ]
        self.assertEqual(self.helper.validate(original), original)
        self.assertEqual(self.public.validate_inner_observation(self.projected_inner(original)), self.projected_inner(original))
        for index, mutate in enumerate(mutations):
            value = copy.deepcopy(original); mutate(value)
            for validator, candidate in ((self.helper.validate,value),
                    (self.public.validate_inner_observation,self.projected_inner(value))):
                with self.subTest(index=index,validator=validator), self.assertRaises(ValueError): validator(candidate)

    def test_common_event_count_and_failure_checks_match_helper_source(self):
        helper_tree = ast.parse(Path(self.helper.__file__).read_bytes())
        public_tree = ast.parse(Path(self.public.__file__).read_bytes())
        def function(tree,name):
            return next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name == name)
        class PublicNames(ast.NodeTransformer):
            def visit_Name(self,node):
                names = {'need':'inner_need','event':'inner_event','PHASES':'INNER_PHASES',
                         'PREDICATES':'INNER_PREDICATES','REASONS':'INNER_REASONS','cmd':'command'}
                return ast.copy_location(ast.Name(id=names.get(node.id,node.id),ctx=node.ctx),node)
        # Only the explicit private-bindings/public-digest shapes and byte encoders differ.
        private = ast.Module(body=function(helper_tree,'validate').body[4:-2],type_ignores=[])
        public = ast.Module(body=function(public_tree,'validate_inner_observation').body[2:-2],type_ignores=[])
        self.assertEqual(ast.dump(PublicNames().visit(private),include_attributes=False),
                         ast.dump(public,include_attributes=False))
        private_event = ast.Module(body=function(helper_tree,'event').body,type_ignores=[])
        public_event = ast.Module(body=function(public_tree,'inner_event').body,type_ignores=[])
        self.assertEqual(ast.dump(PublicNames().visit(private_event),include_attributes=False),
                         ast.dump(public_event,include_attributes=False))

    def test_first_command_count_and_identity_coherence_is_not_a_plan(self):
        value = self.private_inner(); value['first_compiler_natural']['returncode'] = 7
        value['first_failure'] = {'phase':'BUILD','predicate':'COMPILER_NONZERO','reason':'NONZERO',
            'command':copy.deepcopy(value['first_compiler_natural'])}
        self.assertEqual(self.helper.validate(value), value)
        self.public.validate_inner_observation(self.projected_inner(value))
        for mutate in (lambda value:value['first_failure']['command'].update(index=1),
                       lambda value:value.update(compiler_attempt_count=0,compiler_attempted=False,first_compiler_attempt=None),
                       lambda value:value['first_failure']['command'].update(returncode=8)):
            changed = copy.deepcopy(value); mutate(changed)
            for validator, candidate in ((self.helper.validate,changed),
                    (self.public.validate_inner_observation,self.projected_inner(changed))):
                with self.assertRaises(ValueError): validator(candidate)

    def test_group_exact_fields_status_reasons_hash_and_private_payload_refusal(self):
        group = self.bound_group()
        self.assertEqual(self.public.validate_inner_group(group), group)
        for key in group:
            changed = copy.deepcopy(group); changed.pop(key)
            with self.subTest(missing=key), self.assertRaises(ValueError): self.public.validate_inner_group(changed)
        for changes in ({'availability':'PASS'}, {'availability':True}, {'reason':'UNKNOWN'},
                        {'raw_sha256':None}, {'raw_sha256':True}, {'raw_sha256':'raw prose'},
                        {'extra':'private'}):
            with self.subTest(changes=changes), self.assertRaises(ValueError): self.public.validate_inner_group(group | changes)
        for key in ('bindings','nonce','raw_error','argv','path'):
            changed = copy.deepcopy(group); changed['observation'][key] = 'private'
            with self.subTest(private=key), self.assertRaises(ValueError): self.public.validate_inner_group(changed)
        for reason in ('NOT_OBSERVED','MISSING','UNAVAILABLE','SOURCE_INVALID','INVALID','UNBOUND'):
            unknown = self.public.initial_inner() | {'reason':reason}
            self.assertEqual(self.public.validate_inner_group(unknown), unknown)
            with self.assertRaises(ValueError): self.public.validate_inner_group(unknown | {'observation':group['observation']})

    def test_duplicate_nonfinite_and_bounds_are_refused_by_source_decoder_and_parser(self):
        for raw in (b'{"inner":null,"inner":null}',b'{"inner":NaN}',b'{"inner":Infinity}'):
            with self.assertRaises(ValueError): evidence.decode(raw)
        for poison in (float('nan'),float('inf'),float('-inf'),1e999):
            value = self.private_inner(); value['compiler_attempt_count'] = poison
            with self.assertRaises(ValueError): self.public.validate_inner_observation(self.projected_inner(value))
        group = self.bound_group(); group['observation']['phase'] = 'x'*4097
        with self.assertRaises(ValueError): self.public.validate_inner_group(group)

    def test_modern_completion_uses_sample_without_replacing_original_gates(self):
        vector = self.vector()
        self.assertEqual(self.public.validate_workers(vector,require_complete=True),vector)
        for mutate in (lambda row:row.update(inner=self.public.initial_inner()),
                lambda row:row.update(inner=self.bound_group(self.private_inner(False))),
                lambda row:row['inner']['observation'].update(write_failed=True),
                lambda row:row['inner']['observation'].update(cancelled=True),
                lambda row:row['commands'].update(attach=self.public.exit_record(4)),
                lambda row:row['cleanup'].update(status='FAIL',absence='UNVERIFIED',reason='IO')):
            row = self.outer(); mutate(row)
            with self.assertRaises(ValueError): self.public.project(row)
        row = self.outer(); inner = row['inner']['observation']
        inner['first_compiler_natural']['returncode'] = 7
        inner['first_failure'] = {'phase':'BUILD','predicate':'COMPILER_NONZERO','reason':'NONZERO',
            'command':copy.deepcopy(inner['first_compiler_natural'])}
        with self.assertRaises(ValueError): self.public.project(row)

    def test_bound_inner_failure_can_be_public_but_cannot_complete(self):
        row = self.outer(); row['current_predicate'] = 'FINALIZATION'
        self.public.failure(row,'COMMAND_NONZERO','CONTAINER_ATTACH')
        inner = row['inner']['observation']
        inner['first_compiler_natural']['returncode'] = 7
        inner['first_failure'] = {'phase':'BUILD','predicate':'COMPILER_NONZERO','reason':'NONZERO',
            'command':copy.deepcopy(inner['first_compiler_natural'])}
        inner['cancelled'] = True  # Later cancellation retains the first nonzero fact.
        public = self.public.project(row)
        self.assertEqual(public['inner']['observation']['first_failure']['command']['returncode'],7)
        self.public.validate_public(public,'build-1')
        row['current_predicate'] = 'COMPLETE'
        with self.assertRaises(ValueError): self.public.project(row)

    def test_compare_observation_is_explicitly_unknown_and_never_invented_bound(self):
        row = self.outer('compare')
        self.assertEqual(self.public.project(row)['inner'], self.public.initial_inner())
        row['inner'] = self.bound_group()
        with self.assertRaises(ValueError): self.public.project(row)
        row['inner'] = self.public.initial_inner() | {'reason':'MISSING'}
        with self.assertRaises(ValueError): self.public.project(row)

    def receiver_fixture(self, directory):
        import inner_evidence
        reviewed = {'PKGBUILD':'1'*64,'inner_observation.py':'2'*64,
            'fdk-aac-3.0.0-selected-source.tar':'3'*64,'build-layout.json':'4'*64}
        config = {'source_commit':COMMIT,'stage_lock_sha256':'5'*64,'run_id':'1','run_attempt':'2',
            'action':'build-1','nonce':'6'*32,'image':IMAGE,'private':str(directory),'snapshot':str(ROOT)}
        config_sha = '7'*64
        state = {'container_id':'8'*64,'container_name':NAME,'image':IMAGE,'nonce':config['nonce'],
            'status':'exited','running':False,'exit_code':4,'inspect_sha256':'9'*64}
        context = inner_evidence.binding_context(config,config_sha,reviewed,state)
        row = self.public.initial(config,config_sha)
        row['current_predicate'] = 'CONTAINER_ATTACH'; self.public.failure(row,'COMMAND_NONZERO')
        row['current_predicate'] = 'FINALIZATION'
        row['commands'] = {'create':self.public.exit_record(0),'attach':self.public.exit_record(4),
                          'container':self.public.exit_record(4)}
        row['builder'].update(exit=self.public.exit_record(1),status='FAILED',reason='CONTAINER_EXIT',
            provenance={'sha256':'a'*64,'bytes':1},log={'sha256':'b'*64,'bytes':1})
        row['cleanup'] = {'status':'PASS','absence':'PASS','reason':'NONE'}
        row['inner'] = self.bound_group()
        row['inner']['observation']['binding_sha256'] = evidence.sha(inner_evidence.canonical(context))
        receipt = {'status':'FAIL','action':'build-1','hardware':'NOT RUN','cancelled':False,
            'diagnostics':row,'cleanup':{'status':'PASS','absence_verified':True,'cancelled':False},
            'inner_context':context}
        provenance = {'clean_environment_id':NAME,'image':IMAGE,'image_id':IMAGE,
            'entry_script_sha256':evidence.ENTRY_SHA,'recipe_inputs':reviewed}
        return config,config_sha,reviewed,receipt,provenance

    def receive_fixture(self, directory, config, config_sha, reviewed, receipt, provenance):
        import inner_evidence
        path = directory / 'build-1-receipt.json'; path.write_text(json.dumps(receipt)); path.chmod(0o600)
        result = self.public.worker_row('UNAVAILABLE'); result['exit'] = self.public.exit_record(1)
        with mock.patch.object(self.public,'load',return_value=reviewed), \
             mock.patch.object(self.public,'observe_builder',return_value=(provenance,b'private fixture')), \
             mock.patch.object(inner_evidence,'capture_inner',side_effect=AssertionError('no child recapture')), \
             mock.patch.object(inner_evidence,'capture_file',side_effect=AssertionError('no child reread')):
            returned = self.public.receive(config,config_sha,result)
        return returned,result

    def test_receiver_uses_bound_context_and_original_capture_without_child_reread(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            config,checksum,reviewed,receipt,provenance = self.receiver_fixture(directory)
            returned,result = self.receive_fixture(directory,config,checksum,reviewed,receipt,provenance)
            self.assertEqual(returned,receipt)
            self.assertEqual(result['availability'],'VERIFIED')
            self.assertNotIn('inner_context',json.dumps(result))
            receipt['diagnostics']['inner'] = self.public.initial_inner() | {'reason':'MISSING'}
            receipt['inner_context'] = None
            returned,result = self.receive_fixture(directory,config,checksum,reviewed,receipt,provenance)
            self.assertEqual(result['observation']['inner']['availability'],'UNKNOWN')

    def test_receiver_refuses_missing_or_source_state_provenance_mismatched_context(self):
        import inner_evidence
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            config,checksum,reviewed,receipt,provenance = self.receiver_fixture(directory)
            mutations = [
                lambda value:value.update(inner_context=None),
                lambda value:value['inner_context']['source_bindings'].update(observer_sha256='0'*64),
                lambda value:value['inner_context'].update(nonce='0'*32),
                lambda value:value['inner_context']['worker_binding'].update(source_commit='0'*40),
                lambda value:value['inner_context'].update(exit_code=5),
                lambda value:value['inner_context'].update(running=True),
                lambda value:value['inner_context'].update(extra='private'),
            ]
            for index, mutate in enumerate(mutations):
                changed = copy.deepcopy(receipt); mutate(changed)
                if changed['inner_context'] is not None:
                    changed['diagnostics']['inner']['observation']['binding_sha256'] = \
                        evidence.sha(inner_evidence.canonical(changed['inner_context']))
                returned,result = self.receive_fixture(directory,config,checksum,reviewed,changed,provenance)
                with self.subTest(index=index):
                    self.assertIsNone(returned); self.assertEqual(result['availability'],'UNVERIFIED')
            returned,result = self.receive_fixture(directory,config,checksum,reviewed,receipt,
                provenance | {'entry_script_sha256':'0'*64})
            self.assertIsNone(returned); self.assertEqual(result['availability'],'UNVERIFIED')


if __name__ == '__main__':
    unittest.main()

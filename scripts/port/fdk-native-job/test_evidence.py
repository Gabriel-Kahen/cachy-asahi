#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 cachy-asahi contributors
"""Synthetic producer receipts only; no native commands or binaries published."""
import sys
sys.dont_write_bytecode = True

import copy
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
spec = importlib.util.spec_from_file_location('job_evidence_fixture', HERE / 'evidence.py')
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)
INPUT_BYTES = (ROOT / 'scripts/ci/inputs.lock.json').read_bytes()
RECIPES = ROOT / 'scripts/ci/recipes.lock.json'
INPUTS = json.loads(INPUT_BYTES)
REVIEWS = json.loads(RECIPES.read_bytes())
IMAGE = 'sha256:' + '2' * 64
SECRET = 'PRIVATE-SECRET-FIXTURE'


def save(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def metadata(path):
    result = {}
    for line in path.read_text().splitlines():
        if line.strip() and not line.lstrip().startswith('#'):
            key, value = line.strip().split(' = ', 1)
            result.setdefault(key, []).append(value)
    return result


def job_report():
    return {'status': 'PASS', 'phase': 'complete', 'cancelled': False,
            'cleanup': {'status': 'PASS', 'owned_image_absence': True},
            'producer': {'status': 'PASS'}, 'fdk': {'status': 'PASS'},
            'source': {'status': 'PASS', 'source_commit': 'a' * 40, 'packet_sha256': 'b' * 64},
            'error': SECRET, 'stdout': SECRET, 'environment': {'TOKEN': SECRET}}


class ProducerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.producer = self.root / 'producer'
        self.producer.mkdir()
        self.public = self.root / 'public'
        self.items = evidence.input_items(INPUTS)
        (self.producer / 'inputs.lock.json').write_bytes(INPUT_BYTES)
        save(self.producer / 'acquisition.json', {'schema_version': 1, 'acquisition': 'PASS',
            'signature_authentication': 'NOT RUN',
            'counts': {'total': 501, 'pass': 501, 'fail': 0, 'pending': 0},
            'inputs': {n: {**v, 'status': 'PASS'} for n, v in self.items.items()}})
        signer = INPUTS['signer_fingerprint']
        status = f'[GNUPG:] VALIDSIG {signer} 2026-10-12 1791748800 0 4 0 1 10 00 {signer}\n'
        save(self.producer / 'signatures.json', {r['filename']: {'exit_code': 0,
            'status': status, 'command': [SECRET], 'diagnostic': SECRET}
            for r in [INPUTS['rootfs']] + INPUTS['packages']})
        save(self.producer / 'cache-checksums.json', {n: v['expected_sha256'] for n, v in self.items.items()})
        save(self.producer / 'rootfs-inventory.json', INPUTS['rootfs_packages'])
        audit = {}
        for item in INPUTS['packages']:
            row = {}
            for target, source in [('pkgname', 'name'), ('pkgver', 'version'), ('arch', 'arch'),
                                   ('license', 'license'), ('depend', 'depends'), ('provides', 'provides'),
                                   ('conflict', 'conflicts'), ('replaces', 'replaces')]:
                value = item[source]
                row[target] = value if type(value) is list else [value]
            audit[item['filename']] = {'metadata': row, 'hooks': {'private-hook': SECRET},
                                      'installed_paths': [SECRET], 'buildinfo': {}}
        save(self.producer / 'package-audit.json', audit)
        versions = {r['name'][0]: r['version'][0] for r in INPUTS['rootfs_packages']}
        versions.update({r['name']: r['version'] for r in INPUTS['packages']})
        self.lock = ''.join(f'{n} {v}\n' for n, v in sorted(versions.items())).encode()
        (self.producer / 'packages.lock').write_bytes(self.lock)
        (self.producer / 'image-id').write_text(IMAGE + '\n')
        save(self.producer / 'bootstrap.json', {'status': 'image-provisioned', 'image_id': IMAGE,
            'inputs_sha256': evidence.INPUTS_SHA, 'packages_lock_sha256': evidence.INVENTORY_SHA,
            'command': [SECRET], 'dockerfile_sha256': '3' * 64})
        save(self.producer / 'result.json', {'native_build': 'PASS', 'verified_signed_packages': 248,
            'status': 'native-builds-and-byte-comparison-pass', 'mode': 'build',
            'reviewed_inputs_sha256': evidence.INPUTS_SHA, 'reviewed_recipes_sha256': evidence.RECIPES_SHA,
            'bootstrap_script_sha256': evidence.NATIVE_SCRIPT_SHA, 'error': SECRET})
        self.builds = []
        for number, (path, reviewed) in enumerate(sorted(REVIEWS.items())):
            name = Path(path).name
            save(self.producer / (name + '-review.json'), reviewed)
            original = ROOT / path
            src = metadata(original / '.SRCINFO')
            version = src['pkgver'][0] + '-' + src['pkgrel'][0]
            filename = name + '-' + version + '-any.pkg.tar.xz'
            payload = ('original synthetic receipt-only package fixture: ' + name).encode()
            pkg = {'pkgname': src['pkgname'], 'pkgbase': src.get('pkgbase', src['pkgname']),
                   'pkgver': [version], 'arch': src['arch'], 'license': src['license']}
            for field, target in [('depends', 'depend'), ('makedepends', 'makedepend'),
                                  ('checkdepends', 'checkdepend'), ('optdepends', 'optdepend'),
                                  ('provides', 'provides'), ('conflicts', 'conflict'),
                                  ('replaces', 'replaces'), ('backup', 'backup')]:
                pkg[target] = src.get(field, []) + src.get(field + '_aarch64', [])
            for attempt in (1, 2):
                directory = self.producer / (name + '-' + str(attempt))
                (directory / 'inputs').mkdir(parents=True)
                (directory / 'artifacts').mkdir()
                for relative in reviewed:
                    target = directory / 'inputs' / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(original / relative, target)
                artifact = directory / 'artifacts' / filename
                artifact.write_bytes(payload)
                checksum = evidence.sha(payload)
                validation = {'errors': [], 'artifacts': [{'artifact': filename,
                    'status': 'artifact-static-pass', 'sha256': checksum, 'errors': [],
                    'metadata': {'.PKGINFO': pkg, '.BUILDINFO': {
                        'pkgbuild_sha256sum': [reviewed['PKGBUILD']]}}, 'members': {}, 'elf': {}}]}
                save(directory / 'validation.json', validation)
                files = {'build.log': SECRET.encode(), 'expected-packages.lock': self.lock,
                         'artifacts/packages.lock': self.lock,
                         'artifacts/generated.SRCINFO': (original / '.SRCINFO').read_bytes(),
                         'artifacts/environment.txt': SECRET.encode(), 'artifacts/config.sha256': b'fixture',
                         'artifacts/makepkg.conf': b'fixture', 'artifacts/pacman.conf': b'fixture'}
                for relative, data in files.items():
                    (directory / relative).write_bytes(data)
                files['validation.json'] = (directory / 'validation.json').read_bytes()
                files['artifacts/' + filename] = payload
                save(directory / 'provenance.json', {'status': 'built-package-static-pass',
                    'mode': 'native', 'network': 'none', 'image': IMAGE, 'image_id': IMAGE,
                    'builder_host_arch': 'aarch64', 'source_date_epoch': evidence.EPOCH,
                    'exit_code': 0, 'recipe_inputs': reviewed, 'recipe_metadata': src,
                    'expected_packages_sha256': evidence.INVENTORY_SHA,
                    'clean_environment_id': 'cachy-asahi-' + f'{number * 2 + attempt:016x}',
                    'artifacts': {filename: checksum}, 'files': {n: evidence.sha(b) for n, b in files.items()}})
                self.builds.append(directory)
            save(self.producer / (name + '-compare.json'), {'status': 'contents-reproduced', 'errors': [],
                'packages': {filename: {'bytes_equal': True, 'installed_contents_equal': True,
                    'pkginfo_equal': True, 'buildinfo_equal': False}}, 'error': SECRET})

    def validate(self):
        return evidence.validate_producer(self.producer, IMAGE, evidence.NATIVE_SCRIPT_SHA, RECIPES)

    def publish(self, report=None):
        return evidence.publish(self.producer, self.public, IMAGE, evidence.NATIVE_SCRIPT_SHA,
                                RECIPES, job_report() if report is None else report)

    def mutate(self, relative, change):
        path = self.producer / relative
        value = json.loads(path.read_bytes())
        change(value)
        save(path, value)

    def test_complete_receipt_set_binds_all_originals_without_extra_buildinfo_gate(self):
        report = self.validate()
        self.assertEqual(report['status'], 'PASS')
        self.assertEqual((report['acquired_inputs'], report['authenticated_payloads'],
                          report['signed_packages'], report['builder_packages']), (501, 249, 248, 341))
        self.assertEqual(set(report['originals']), evidence.NAMES)
        self.assertTrue(all(not r['buildinfo_equal_recorded'] for r in report['originals'].values()))
        self.assertNotIn(SECRET, json.dumps(report))

    def test_result_source_recipe_image_and_inventory_drift_reject_acceptance(self):
        original = (self.producer / 'result.json').read_bytes()
        for field, value in (('native_build', 'NOT RUN'), ('status', 'failed'),
                             ('reviewed_inputs_sha256', '0' * 64), ('reviewed_recipes_sha256', '0' * 64),
                             ('bootstrap_script_sha256', '0' * 64), ('verified_signed_packages', 247), ('mode', 'integration')):
            self.mutate('result.json', lambda row: row.update({field: value}))
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate()
            (self.producer / 'result.json').write_bytes(original)
        (self.producer / 'packages.lock').write_bytes(self.lock[:-1])
        with self.assertRaises(ValueError):
            self.validate()

    def test_acquisition_missing_partial_failure_and_wrong_pins_reject_acceptance(self):
        path = self.producer / 'acquisition.json'
        original = path.read_bytes()
        name = next(iter(self.items))
        for state in ('FAIL', 'PENDING'):
            record = json.loads(original)
            record['inputs'][name]['status'] = state
            record['counts'] = {'total': 501, 'pass': 500, 'fail': int(state == 'FAIL'), 'pending': int(state == 'PENDING')}
            record['acquisition'] = 'FAIL' if state == 'FAIL' else 'IN_PROGRESS'
            save(path, record)
            with self.subTest(state=state), self.assertRaises(ValueError):
                self.validate()
        record = json.loads(original)
        del record['inputs'][name]
        save(path, record)
        with self.assertRaises(ValueError):
            self.validate()
        record = json.loads(original)
        record['inputs'][name]['expected_sha256'] = '0' * 64
        save(path, record)
        with self.assertRaises(ValueError):
            self.validate()

    def test_signature_bad_expired_wrong_primary_and_missing_payload_reject(self):
        path = self.producer / 'signatures.json'
        original = path.read_bytes()
        name = INPUTS['rootfs']['filename']
        for suffix in ('[GNUPG:] BADSIG fixture\n', '[GNUPG:] EXPKEYSIG fixture\n'):
            row = json.loads(original)
            row[name]['status'] += suffix
            save(path, row)
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                self.validate()
        row = json.loads(original)
        row[name]['status'] = row[name]['status'].replace(INPUTS['signer_fingerprint'], 'A' * 40)
        save(path, row)
        with self.assertRaises(ValueError):
            self.validate()
        row = json.loads(original)
        del row[name]
        save(path, row)
        with self.assertRaises(ValueError):
            self.validate()

    def test_audit_rootfs_and_cache_receipts_match_exact_reviewed_inputs(self):
        path = self.producer / 'rootfs-inventory.json'
        original = path.read_bytes()
        rows = json.loads(original)
        rows[0]['version'] = ['unexpected']
        save(path, rows)
        with self.assertRaises(ValueError):
            self.validate()
        path.write_bytes(original)
        self.mutate('package-audit.json', lambda rows: rows[INPUTS['packages'][0]['filename']]['metadata'].update(pkgver=['unexpected']))
        with self.assertRaises(ValueError):
            self.validate()
        self.mutate('cache-checksums.json', lambda rows: rows.update({next(iter(rows)): '0' * 64}))
        with self.assertRaises(ValueError):
            self.validate()

    def test_original_recipe_snapshot_partial_build_and_false_comparison_reject(self):
        directory = self.builds[0]
        source = directory / 'inputs' / 'PKGBUILD'
        before = source.read_bytes()
        source.write_bytes(before + b'changed')
        with self.assertRaises(ValueError):
            self.validate()
        source.write_bytes(before)
        original = (directory / 'provenance.json').read_bytes()
        self.mutate(str(directory.relative_to(self.producer) / 'provenance.json'), lambda row: row.update(status='building'))
        with self.assertRaises(ValueError):
            self.validate()
        (directory / 'provenance.json').write_bytes(original)
        comparison = next(self.producer.glob('*-compare.json'))
        row = json.loads(comparison.read_bytes())
        next(iter(row['packages'].values()))['pkginfo_equal'] = False
        save(comparison, row)
        with self.assertRaises(ValueError):
            self.validate()

    def test_exact_source_locks_and_allowlist_only_are_published(self):
        (self.producer / 'raw-secret.log').write_text(SECRET)
        (self.producer / 'cache').mkdir()
        (self.producer / 'cache' / 'invalid-codec.pkg.tar.xz').write_text(SECRET)
        result = self.publish()
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual({p.name for p in self.public.iterdir()}, evidence.PUBLIC_FILES)
        self.assertEqual((self.public / 'inputs.lock.json').read_bytes(), INPUT_BYTES)
        self.assertEqual((self.public / 'recipes.lock.json').read_bytes(), RECIPES.read_bytes())
        self.assertNotIn(SECRET, '\n'.join(p.read_text() for p in self.public.iterdir()))
        self.assertFalse(any('.pkg.tar.' in name for name in result['files']))
        for name, pin in result['files'].items():
            self.assertEqual(evidence.sha((self.public / name).read_bytes()), pin)

    def test_failed_acquisition_publishes_safe_known_filename_pin_and_http_code(self):
        name = next(iter(self.items))
        self.mutate('acquisition.json', lambda row: (
            row['inputs'][name].update(status='FAIL', http_status=404, error=SECRET, error_type=SECRET),
            row.update(acquisition='FAIL', counts={'total': 501, 'pass': 500, 'fail': 1, 'pending': 0})))
        report = job_report()
        report.update(status='FAIL', producer={'status': 'FAIL'})
        result = self.publish(report)
        self.assertEqual(result['status'], 'FAIL')
        exported = json.loads((self.public / 'acquisition.json').read_bytes())
        self.assertEqual(exported['inputs'][name]['http_status'], 404)
        self.assertEqual(exported['inputs'][name]['expected_sha256'], self.items[name]['expected_sha256'])
        self.assertNotIn(SECRET, '\n'.join(p.read_text() for p in self.public.iterdir()))
        self.assertFalse((self.public / 'signatures.json').exists())

    def test_cancelled_or_uncertain_cleanup_never_publishes_accepted_native_pass(self):
        for change in ({'cancelled': True}, {'cleanup': {'status': 'FAIL', 'owned_image_absence': False}},
                       {'phase': 'producer'}):
            self.public = self.root / ('public-' + str(len(list(self.root.glob('public-*')))))
            result = self.publish({**job_report(), **change})
            self.assertEqual(result['status'], 'FAIL')
            summary = json.loads((self.public / 'producer-summary.json').read_bytes())
            self.assertEqual(summary['native_build'], 'NOT ACCEPTED')
            self.assertEqual(summary['recorded_native_build'], 'PASS')
            self.assertEqual(summary['authoritative_job_status'], 'FAIL')

    def test_unsafe_malformed_receipt_exports_fixed_failure_only(self):
        path = self.producer / 'acquisition.json'
        path.write_bytes(b'{"inputs": "' + SECRET.encode() + b'"}')
        result = self.publish()
        self.assertEqual(result['status'], 'FAIL')
        summary = json.loads((self.public / 'producer-summary.json').read_bytes())
        self.assertEqual(summary['authoritative_job_status'], 'FAIL')
        self.assertEqual({p.name for p in self.public.iterdir()}, {'producer-summary.json', 'export-manifest.json'})
        self.assertNotIn(SECRET, '\n'.join(p.read_text() for p in self.public.iterdir()))

    def test_symlink_acquisition_receipt_exports_no_target_bytes(self):
        path = self.producer / 'acquisition.json'
        path.unlink()
        target = self.root / 'private-target'
        target.write_text(SECRET)
        path.symlink_to(target)
        result = self.publish()
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual({p.name for p in self.public.iterdir()},
                         {'producer-summary.json', 'export-manifest.json'})
        self.assertEqual(target.read_text(), SECRET)
        self.assertNotIn(SECRET, '\n'.join(p.read_text() for p in self.public.iterdir()))

    def test_symlink_public_output_and_nonempty_existing_directory_are_refused(self):
        real = self.root / 'real'
        real.mkdir()
        self.public.symlink_to(real, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.publish()
        self.assertEqual(list(real.iterdir()), [])
        self.public.unlink()
        self.public.mkdir()
        (self.public / 'keep').write_text('keep')
        with self.assertRaises(ValueError):
            self.publish()
        self.assertEqual((self.public / 'keep').read_text(), 'keep')


class PublicStatusTests(unittest.TestCase):
    def test_fixed_producer_diagnostics_only_choose_finite_failure_codes(self):
        failed = {**job_report(), 'status': 'FAIL', 'work_phase': 'producer', 'producer': {'status': 'FAIL'}}
        points = {'not-run': 'before', 'started': 'during', 'pass': 'after'}
        for phase in evidence.PRODUCER_PHASES:
            for outcome in evidence.PRODUCER_OUTCOMES:
                with self.subTest(phase=phase, outcome=outcome):
                    diagnostic = {'phase': phase, 'outcome': outcome}
                    record = evidence.public_status({**failed, 'producer_diagnostic': diagnostic})
                    code = ('producer-' + points[outcome] + '-' + phase + '-failed' if outcome in points
                            else 'producer-' + phase + '-' + outcome)
                    self.assertEqual(record['error_code'], code)
                    self.assertIn(code, evidence.PRODUCER_FAILURE_CODES)
                    self.assertNotIn('producer_diagnostic', record)
                    self.assertEqual(record['status'], 'FAIL')
        for diagnostic in (None, SECRET, {'phase': SECRET, 'outcome': 'runner-failed'},
                           {'phase': 'gpg-verify', 'outcome': SECRET},
                           {'phase': 'gpg-verify', 'outcome': 'runner-failed', 'raw_private_response': SECRET},
                           {'phase': ['gpg-verify'], 'outcome': 'runner-failed'}):
            result = evidence.public_status({**failed, 'producer_diagnostic': diagnostic})
            self.assertEqual(result['error_code'], 'fdk-native-job-failed')
            self.assertNotIn(SECRET, json.dumps(result))
        diagnostic = {'phase': 'gpg-verify', 'outcome': 'runner-failed'}
        self.assertIsNone(evidence.public_status({**job_report(), 'producer_diagnostic': diagnostic})['error_code'])
        self.assertEqual(evidence.public_status({**failed, 'work_phase': 'fdk', 'producer_diagnostic': diagnostic})['error_code'],
                         'fdk-native-job-failed')

    def test_closed_probe_substeps_and_refusals_project_without_raw_fields(self):
        failed = {**job_report(), 'status': 'FAIL', 'work_phase': 'producer', 'producer': {'status': 'FAIL'}}
        for call in evidence.BASE_PROBE_CALLS:
            for refusal in evidence.BASE_PROBE_REFUSALS:
                diagnostic = {'phase': 'base-probe', 'outcome': 'runner-failed', 'call': call, 'refusal_code': refusal}
                public = evidence.public_status({**failed, 'producer_diagnostic': diagnostic})
                self.assertEqual(public['error_code'], 'producer-base-probe-' + call + '-' + refusal)
                self.assertIn(public['error_code'], evidence.PRODUCER_FAILURE_CODES)
                self.assertNotIn('producer_diagnostic', public)
        for outcome, point in (('not-run', 'before'), ('started', 'during'), ('pass', 'after')):
            diagnostic = {'phase': 'base-probe', 'outcome': outcome, 'call': 'image-inspect', 'refusal_code': 'none'}
            self.assertEqual(evidence.public_status({**failed, 'producer_diagnostic': diagnostic})['error_code'],
                             'producer-' + point + '-base-probe-image-inspect-failed')
        good = {'phase': 'base-probe', 'outcome': 'runner-failed', 'call': 'image-inspect',
                'refusal_code': 'docker-image-drift'}
        bad = [{**good, 'call': SECRET}, {**good, 'refusal_code': SECRET}, {**good, 'phase': 'gpg-verify'},
               {**good, 'outcome': 'pass'}, {**good, 'call': []}, {**good, 'refusal_code': {}},
               {**good, 'raw_private_response': SECRET}, {k: v for k, v in good.items() if k != 'call'},
               {k: v for k, v in good.items() if k != 'refusal_code'}]
        for diagnostic in bad:
            result = evidence.public_status({**failed, 'producer_diagnostic': diagnostic})
            self.assertEqual(result['error_code'], 'fdk-native-job-failed')
            self.assertNotIn(SECRET, json.dumps(result))

    def test_pass_requires_complete_both_stages_no_cancellation_and_image_absence(self):
        self.assertEqual(evidence.public_status(job_report())['status'], 'PASS')
        for change in ({'status': 'FAIL'}, {'phase': 'cleanup'}, {'cancelled': True}, {'source': {}}, {'source': {'status': 'FAIL'}},
                       {'producer': {'status': 'FAIL'}}, {'fdk': {'status': 'FAIL'}},
                       {'cleanup': {'status': 'PASS', 'owned_image_absence': False}}):
            with self.subTest(change=change):
                result = evidence.public_status({**job_report(), **change})
                self.assertEqual(result['status'], 'FAIL')
                if 'phase' in change or 'cancelled' in change or 'cleanup' in change:
                    self.assertEqual(result['producer_status'], 'NOT ACCEPTED')
                    self.assertEqual(result['fdk_status'], 'NOT ACCEPTED')
                self.assertNotIn(SECRET, json.dumps(result))
        self.assertEqual(evidence.public_status(None)['status'], 'FAIL')
        self.assertEqual(evidence.public_status({'cleanup': None})['status'], 'FAIL')
        result = evidence.public_status(job_report())
        self.assertEqual((result['source_commit'], result['source_packet_sha256']), ('a' * 40, 'b' * 64))
        result = evidence.public_status({**job_report(), 'source': {'status': 'FAIL', 'source_commit': {SECRET: 1}, 'packet_sha256': SECRET}})
        self.assertIsNone(result['source_commit'])
        self.assertIsNone(result['source_packet_sha256'])
        self.assertNotIn(SECRET, json.dumps(result))


if __name__ == '__main__':
    unittest.main()

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""MODELED native receipts; authenticated collector and GPG/repo-add are real."""
import copy
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

import dependencies
import phases
from test_fixture import PhaseFixture, ROOT, digest, encoded, real_template


class PhaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = tempfile.TemporaryDirectory(prefix='MODELED-native-real-GPG-phase-keys-')
        cls.modules = dependencies.load_collector(ROOT)
        cls.template = real_template(Path(cls.keys.name), cls.modules)
        cls.seed_root = tempfile.TemporaryDirectory(prefix='MODELED-native-phase-seed-')
        cls.seed = PhaseFixture(Path(cls.seed_root.name), cls.template)

    @classmethod
    def tearDownClass(cls):
        cls.seed.close(); cls.seed_root.cleanup(); cls.template.close(); cls.keys.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='MODELED-native-phase-case-'); self.addCleanup(self.temp.cleanup)
        self.fixture = self.seed.clone(Path(self.temp.name))
        self.addCleanup(self.fixture.close)

    def arguments(self):
        fixture = self.fixture
        roles = {role: {key: row[key] for key in ('fingerprint', 'certificate')} for role, row in fixture.request['signers'].items()}
        public = json.loads(fixture.data[fixture.refs['public_manifest']])['files']
        objects = [dict(row, status='VALID') for row in fixture.request['signed_objects']]
        repository = json.loads(fixture.data[fixture.refs['repository']])
        return fixture.authority, fixture.authority['files'], fixture.data, roles, 'public/', public, objects, repository

    def validate(self, arguments=None):
        return phases.validate(*(arguments or self.arguments()), repo_root=ROOT)

    def rebind_receipt(self, change):
        receipt = copy.deepcopy(self.fixture.receipt); change(receipt)
        row = self.fixture.authority['crypto']['receipt']; raw = encoded(receipt)
        self.fixture.put(row['path'], raw); row.update(sha256=digest(raw), bytes=len(raw)); self.fixture.refresh()

    def test_actual_independent_gpg_recheck_of_modeled_native_packet(self):
        result = self.validate()
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(result['verification'], 'independent-real-gpg-phase-recheck')
        self.assertEqual(result['current_A_authorization'], 'REVOKED')
        self.assertEqual(len(result['lineage']), 15)
        self.assertEqual([row['terminal_authorization'] for row in result['lineage']].count('REVOKED'), 7)
        self.assertEqual([row['terminal_authorization'] for row in result['lineage']].count('VALID_AT_OBSERVATION'), 8)
        self.assertTrue(all(row['snapshot_authorization'] == 'SNAPSHOT_ONLY' and 'status' not in row for row in result['lineage']))
        self.assertEqual(result['private_recheck_cleanup'], 'PASS')
        self.assertEqual(result['hardware_validation'], 'NOT RUN')
        self.assertEqual(result['phase_receipt_sha256'], self.fixture.authority['crypto']['receipt']['sha256'])

    def test_flat_v1_authority_refused_before_authenticated_load(self):
        self.fixture.authority['crypto'] = {'status': 'PASS', 'signed_objects': []}
        with mock.patch.object(dependencies, 'load_collector', side_effect=AssertionError('must not load')):
            with self.assertRaisesRegex(ValueError, 'v1-refused'):
                self.validate()

    def test_rebound_A_terminal_valid_refused_before_rerun(self):
        self.rebind_receipt(lambda receipt: receipt['terminal_authorization'][0].update(authorization='VALID_AT_OBSERVATION'))
        with mock.patch.object(self.modules['crypto'], 'attest', side_effect=AssertionError('must not rerun')):
            with self.assertRaisesRegex(ValueError, 'authorization-differs'):
                self.validate()

    def test_rebound_raw_machine_status_hash_refused(self):
        self.rebind_receipt(lambda receipt: receipt['snapshot_integrity'][0].update(machine_status='[GNUPG:] BADSIG UNTRUSTED\n'))
        with self.assertRaisesRegex(ValueError, 'raw-status-command-binding'):
            self.validate()

    def test_rebound_positive_bad_status_with_coherent_command_hash_refused(self):
        def change(receipt):
            row = receipt['snapshot_integrity'][0]
            raw = (row['machine_status'] + '[GNUPG:] EXPKEYSIG\n').encode()
            row.update(machine_status=raw.decode(), status_sha256=digest(raw), status_bytes=len(raw))
            command = next(command for command in receipt['commands'] if '--verify' in command['argv'])
            command.update(stdout_sha256=digest(raw), stdout_bytes=len(raw))
        self.rebind_receipt(change)
        with self.assertRaisesRegex(ValueError, 'forbidden-signature-status'):
            self.validate()

    def test_rebound_current_expiry_and_future_observation_refused(self):
        for change in (lambda receipt: receipt.update(completed_at=2**40),
                       lambda receipt: receipt['certificate_expiry'].update({'signer-B': 1})):
            with self.subTest(change=change):
                self.rebind_receipt(change)
                with self.assertRaisesRegex(ValueError, 'current-expiry-required'):
                    self.validate()

    def test_native_basename_match_in_wrong_repository_refused(self):
        arguments = list(self.arguments()); repository = arguments[-1]
        observed = self.fixture.request['native_verifications'][0]
        command = repository['commands'][observed['command_index']]
        command['argv'][-1] = command['argv'][-1].replace('/baseline-A/', '/updated-B/')
        with self.assertRaisesRegex(ValueError, 'native-command-exact-binding'):
            self.validate(arguments)

    def test_native_signer_home_and_label_substitution_refused(self):
        arguments = list(self.arguments()); repository = arguments[-1]
        observed = self.fixture.request['native_verifications'][0]
        command = repository['commands'][observed['command_index']]
        command['argv'][4] = '/test-home/verifier'
        with self.assertRaisesRegex(ValueError, 'native-command-exact-binding'):
            self.validate(arguments)

    def test_native_same_key_other_packet_status_refused(self):
        observed = [row for row in self.fixture.request['native_verifications'] if row['native_phase'] == 'pre-A-revocation']
        left, right = observed[0], observed[1]
        self.fixture.put(left['status_log'], self.fixture.data[right['status_log']])
        arguments = list(self.arguments()); repository = arguments[-1]
        row = repository['commands'][left['command_index']]
        row['sha256'] = digest(self.fixture.data[left['status_log']])
        repository['evidence_sha256'][row['log']] = row['sha256']
        self.fixture.request['files'][left['status_log']] = {'sha256': row['sha256'], 'bytes': len(self.fixture.data[left['status_log']])}
        self.fixture.refresh()
        # To reach packet matching, coherently bind the request and retained-observation receipt.
        request = self.fixture.authority['crypto']['request']; raw = encoded(self.fixture.request)
        self.fixture.put(request['path'], raw); request.update(sha256=digest(raw), bytes=len(raw))
        self.rebind_receipt(lambda receipt: receipt.update(request_sha256=digest(raw),
            artifact_map_sha256=self.modules['common'].digest(self.modules['common'].encoded(self.fixture.request['files']))))
        arguments[1] = self.fixture.authority['files']
        with self.assertRaisesRegex(ValueError, 'native-signature-packet-status'):
            self.validate(arguments)

    def test_faked_time_option_in_stored_commands_refused(self):
        self.rebind_receipt(lambda receipt: receipt['commands'][0]['argv'].append('--faked-system-time=1'))
        with self.assertRaisesRegex(ValueError, 'fake-clock'):
            self.validate()

    def test_malformed_phase_rows_refused_as_valueerror(self):
        self.rebind_receipt(lambda receipt: receipt['snapshot_integrity'].__setitem__(0, None))
        with self.assertRaisesRegex(ValueError, 'row-required'):
            self.validate()

    def test_source_pin_refused(self):
        self.rebind_receipt(lambda receipt: receipt['source_sha256'].update({'crypto.py': '0' * 64}))
        with self.assertRaisesRegex(ValueError, 'authenticated-source'):
            self.validate()

    def test_real_recheck_rejects_coherently_forged_alias_signature_receipt(self):
        fixture, common = self.fixture, self.modules['common']
        request, receipt = copy.deepcopy(fixture.request), copy.deepcopy(fixture.receipt)
        alias = 'public/TEST-repository-aliases.json'
        borrowed = next(row for row in request['signed_objects'] if row['signer'] == 'signer-B' and '.pkg.' in row['path'])
        fixture.put(alias + '.sig', fixture.data[borrowed['signature']])
        public = json.loads(fixture.data[fixture.refs['public_manifest']])
        new_signature = {'sha256': digest(fixture.data[alias + '.sig']), 'bytes': len(fixture.data[alias + '.sig'])}
        public['files']['TEST-repository-aliases.json.sig'] = new_signature
        fixture.put(fixture.refs['public_manifest'], encoded(public))
        request['files'][alias + '.sig'] = new_signature
        # Forge internally coherent retained records; actual recheck still uses GPG.
        verification_commands = [row for row in receipt['commands'] if '--verify' in row['argv']]
        for field, offset in (('snapshot_integrity', 0), ('terminal_authorization', 29)):
            left = next(index for index, row in enumerate(receipt[field]) if row['path'] == alias)
            right = next(row for row in receipt[field] if row['path'] == borrowed['path'])
            row = receipt[field][left]; row['signature_sha256'] = new_signature['sha256']
            for key in ('machine_status', 'status_sha256', 'status_bytes', 'stderr_sha256', 'stderr_bytes'):
                row[key] = right[key]
            verification_commands[offset + left].update(stdout_sha256=row['status_sha256'], stdout_bytes=row['status_bytes'],
                stderr_sha256=row['stderr_sha256'], stderr_bytes=row['stderr_bytes'])
        native_alias = next(row for row in request['native_verifications'] if row['path'] == alias)
        native_borrowed = next(row for row in request['native_verifications'] if row['path'] == borrowed['path'])
        fixture.put(native_alias['status_log'], fixture.data[native_borrowed['status_log']])
        pin = {'sha256': digest(fixture.data[native_alias['status_log']]), 'bytes': len(fixture.data[native_alias['status_log']])}
        request['files'][native_alias['status_log']] = pin
        repository = json.loads(fixture.data[fixture.refs['repository']])
        command = repository['commands'][native_alias['command_index']]
        command['sha256'] = pin['sha256']; repository['evidence_sha256'][command['log']] = pin['sha256']
        fixture.put(fixture.refs['repository'], encoded(repository))
        raw = encoded(request)
        reference = fixture.authority['crypto']['request']; fixture.put(reference['path'], raw)
        reference.update(sha256=digest(raw), bytes=len(raw))
        receipt.update(request_sha256=digest(raw), artifact_map_sha256=common.digest(common.encoded(request['files'])),
                       public_artifact_map_sha256=common.digest(common.encoded(public['files'])))
        reference = fixture.authority['crypto']['receipt']; raw = encoded(receipt); fixture.put(reference['path'], raw)
        reference.update(sha256=digest(raw), bytes=len(raw)); fixture.refresh()
        with self.assertRaisesRegex(ValueError, 'independent-real-gpg-phase-recheck-refused'):
            self.validate()

    def test_real_duplicate_positive_negative_old_keyerror_new_finite_refusal(self):
        """Unmocked GPG: omit a tamper proof through coherent positive duplication."""
        def poison(receipt):
            rows = receipt['negative_verifications']
            victim = next(index for index, row in enumerate(rows) if row['phase'] == 'expected-tamper')
            borrowed = next(index for index, row in enumerate(rows) if row['phase'] == 'positive')
            rows[victim] = copy.deepcopy(rows[borrowed])
            commands = [row for row in receipt['commands'] if '--verify' in row['argv']]
            commands[15 + victim].clear()
            commands[15 + victim].update(copy.deepcopy(commands[15 + borrowed]))
        self.rebind_receipt(poison)
        # Reconstruct exactly the pinned predecessor from this sole source delta,
        # authenticate its bytes, then compile a temporary source string. No PYC,
        # fake time, substituted attester result or cryptographic bypass is used.
        applied = """                need(isinstance(stored, dict) and isinstance(current, dict)
                     and set(stored) == (NEGATIVE_KEYS if stored.get('phase') == 'expected-tamper' else PHASE_KEYS)
                     and set(current) == (NEGATIVE_KEYS if current.get('phase') == 'expected-tamper' else PHASE_KEYS)
                     and set(stored) == set(current), 'independent-object-phase-proof-differs')
"""
        source = Path(phases.__file__).read_bytes()
        self.assertEqual(source.count(applied.encode()), 1)
        legacy_raw = source.replace(applied.encode(), b'', 1)
        self.assertEqual(digest(legacy_raw), '8afe8cd2c1fffce4d2c8e97e4b6ef5545fb145fead2248b2cd937ac27374870f')
        with tempfile.TemporaryDirectory(prefix='TEST-pinned-old-phase-refusal-') as name:
            path = Path(name) / 'phases.py'
            path.write_bytes(legacy_raw)
            legacy = types.ModuleType('pinned_predecessor_phase_refusal')
            legacy.__file__ = str(path)
            exec(compile(path.read_bytes(), str(path), 'exec'), legacy.__dict__)
            with self.assertRaises(KeyError) as old:
                legacy.validate(*self.arguments(), repo_root=ROOT)
            self.assertIn(old.exception.args[0], {'fingerprint', 'digest_algorithm'})
        with self.assertRaisesRegex(ValueError, '^independent-object-phase-proof-differs$'):
            self.validate()
        with self.assertRaises(self.fixture.gate.Refused) as external:
            self.fixture.accept()
        self.assertEqual(str(external.exception), 'phase or authenticated dependency refusal')

    def test_exact_subset_copy_avoids_unrelated_authority_files(self):
        self.fixture.put('unrelated/authority-only.txt', b'MODELED authority-only data, not crypto input\n')
        self.fixture.refresh()
        result = self.validate()
        self.assertEqual(result['status'], 'PASS')


if __name__ == '__main__':
    unittest.main()

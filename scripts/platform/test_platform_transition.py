# SPDX-License-Identifier: MIT
"""Host-only synthetic archive and policy controls; no crypto/hardware result."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('tested_transition', Path(__file__).with_name('platform_transition.py'))
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


class TransitionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.before = [{'NAME': [n], 'VERSION': ['1-1'], 'ARCH': ['aarch64'], 'BASE': [n], 'LICENSE': ['MIT']}
                       for n in sorted(p.preflight.PLATFORM | {'consumer'})]
        self.row(self.before, 'consumer')['DEPENDS'] = ['mesa>=1']
        self.after = copy.deepcopy(self.before)
        self.cache = {}

    def row(self, rows, name):
        return next(r for r in rows if r['NAME'] == [name])

    def save(self, name, value):
        data = value if isinstance(value, bytes) else json.dumps(value, sort_keys=True).encode()
        path = self.root / name
        path.write_bytes(data)
        return {'path': str(path), 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}

    def archives(self, label, rows):
        provenance, index = [], []
        for metadata in rows:
            name, version, arch = p.identity(metadata)
            key = p.digest(metadata)
            if key not in self.cache:
                stream = io.BytesIO()
                with tarfile.open(fileobj=stream, mode='w:xz') as archive:
                    fields = [('pkgname', 'NAME'), ('pkgver', 'VERSION'), ('arch', 'ARCH'), ('pkgbase', 'BASE'),
                              ('depend', 'DEPENDS'), ('provides', 'PROVIDES'), ('conflict', 'CONFLICTS'),
                              ('replaces', 'REPLACES'), ('license', 'LICENSE')]
                    data = ''.join(f'{field} = {v}\n' for field, k in fields for v in metadata.get(k, [])).encode()
                    member = tarfile.TarInfo('.PKGINFO');member.size = len(data)
                    archive.addfile(member, io.BytesIO(data))
                ref = self.save(f'{name}-{version}-{key[:8]}.pkg.tar.xz', stream.getvalue())
                sig = self.save(Path(ref['path']).name + '.sig', b'SYNTHETIC-signature-NOT-crypto')
                self.cache[key] = ref, sig
            ref, sig = self.cache[key]
            provenance.append({'metadata': metadata, 'archive': ref, 'signature': sig,
                               'verification': {'status': 'cryptographic-signature-valid',
                                                'primary_fingerprint': p.recovery.auth.KEYS['alarm'][0], 'synthetic': True}})
            index.append({'name': name, 'archive': ref, 'signature': sig})
        source = self.save(label + '-provenance.json', {'packages': provenance, 'synthetic': True})
        for i, row in enumerate(index):
            row['provenance'] = {'document': source, 'row': i}
        return self.save(label + '-archives.json', {'schema_version': 1, 'kind': 'platform-archive-reference-index', 'packages': index})

    def contract(self):
        states = []
        for label, rows in (('before', self.before), ('candidate', self.after)):
            states.append({'id': label, 'inventory': self.save(label + '.json', {'packages': [{'metadata': r} for r in rows]}),
                           'archive_index': self.archives(label, rows)})
        left, right = states
        graph = [{'name': r['NAME'][0], 'version': r['VERSION'][0]} for r in self.before]
        tuple_ref = self.save('tuple.json', {'input_sha256': {'image': left['inventory']['sha256']},
                                             'proposed_installed_dependency_graph': graph})
        names = sorted({r['NAME'][0] for r in self.before + self.after})
        maps = [{r['NAME'][0]: r['VERSION'][0] for r in rows} for rows in (self.before, self.after)]
        group = {'name': 'synthetic-tuple', 'before': {n: maps[0].get(n) for n in names},
                 'candidate': {n: maps[1].get(n) for n in names}, 'allow_changes': names,
                 'allow_downgrades': [], 'allow_removals': []}
        policy = self.save('policy.json', {'schema_version': 1, 'kind': 'coordinated-platform-version-policy',
                                          'before_release': left, 'candidate_release': right, 'coordinated_sets': [group]})
        assets = self.save('assets.json', {'schema_version': 1, 'for_inventory': left['inventory'],
                                          'assets': [{'role': role, 'artifact': self.save(role, b'synthetic baseline asset')}
                                                     for role in sorted(p.preflight.BOOT_ROLES | p.preflight.CONFIG_ROLES)]})
        return {'schema_version': 1, 'before_release': left, 'candidate_release': right,
                'protected_tuple': tuple_ref, 'coordinated_policy': policy, 'retained_recovery_assets': assets}

    def rewrite(self, contract, key, callback):
        doc = p.document(contract[key]);callback(doc)
        contract[key] = self.save(Path(contract[key]['path']).name, doc)

    def codes(self, report):
        return {row['code'] for row in report['conditions']}

    def test_complete_data_plan_has_no_acceptance(self):
        report = p.run(self.contract())
        self.assertTrue(report['software_data_bound'])
        self.assertEqual(report['changes'], [])
        for key in ('hardware_accepted', 'recovery_accepted', 'installation_accepted', 'fresh_signature_verification', 'transaction_prepared'):
            self.assertFalse(report[key])
        self.assertEqual([r['result'] for r in report['physical_checks']], ['NOT RUN', 'NOT RUN'])

    def test_coordinated_mesa_change_reports_consumer(self):
        self.row(self.after, 'mesa')['VERSION'] = ['2-1']
        report = p.run(self.contract())
        self.assertTrue(report['software_data_bound'])
        self.assertEqual([(r['name'], r['change']) for r in report['changes']], [('mesa', 'upgraded')])
        self.assertIn('consumer', [r['name'] for r in report['dependency_impact']['unchanged_dependents']])

    def test_incompatible_dependency(self):
        self.row(self.after, 'consumer')['DEPENDS'] = ['mesa>=3']
        self.assertIn('dependency-unsatisfied', self.codes(p.run(self.contract())))

    def test_uncoordinated_change(self):
        self.row(self.after, 'mesa')['VERSION'] = ['2-1']
        contract = self.contract()
        self.rewrite(contract, 'coordinated_policy', lambda d: d['coordinated_sets'][0].update(allow_changes=[]))
        self.assertIn('change-not-coordinated', self.codes(p.run(contract)))

    def test_downgrade_requires_allowance(self):
        self.row(self.after, 'mesa')['VERSION'] = ['1-0']
        contract = self.contract()
        self.assertIn('downgrade-not-explicit', self.codes(p.run(contract)))
        self.rewrite(contract, 'coordinated_policy', lambda d: d['coordinated_sets'][0].update(allow_downgrades=['mesa']))
        self.assertTrue(p.run(contract)['software_data_bound'])

    def test_platform_removal_still_blocks(self):
        self.after = [r for r in self.after if r['NAME'] != ['speakersafetyd']]
        contract = self.contract()
        self.rewrite(contract, 'coordinated_policy', lambda d: d['coordinated_sets'][0].update(allow_removals=['speakersafetyd']))
        self.assertIn('required-platform-package-missing', self.codes(p.run(contract)))

    def test_same_version_metadata_change(self):
        self.row(self.after, 'mesa')['DEPENDS'] = ['linux-asahi']
        self.assertIn('mesa', [r['name'] for r in p.run(self.contract())['changes']])

    def test_added_only_dependency_assessment(self):
        self.after.append({'NAME': ['new-app'], 'VERSION': ['1-1'], 'ARCH': ['any'], 'BASE': ['new-app'],
                           'LICENSE': ['MIT'], 'DEPENDS': ['mesa']})
        self.assertEqual(p.run(self.contract())['added_package_dependencies'][0]['package'], 'new-app')

    def test_candidate_conflict(self):
        self.row(self.after, 'consumer')['CONFLICTS'] = ['mesa']
        self.assertIn('candidate-package-conflict', self.codes(p.run(self.contract())))

    def test_missing_recovery_assets(self):
        contract = self.contract()
        self.rewrite(contract, 'retained_recovery_assets', lambda d: d.update(assets=[]))
        self.assertEqual(sum(r['code'] == 'retained-recovery-asset-missing' for r in p.run(contract)['conditions']), 6)

    def test_missing_archive_is_not_byte_change(self):
        contract = self.contract();old = contract['before_release']['archive_index']
        doc = p.document(old);doc['packages'] = [r for r in doc['packages'] if r['name'] != 'mesa']
        contract['before_release']['archive_index'] = self.save('before-archives.json', doc)
        self.rewrite(contract, 'coordinated_policy', lambda d: d.update(before_release=contract['before_release']))
        report = p.run(contract)
        self.assertIn('exact-archive-missing', self.codes(report))
        self.assertEqual(report['changes'], [])
        self.assertEqual(report['dependency_impact']['changed_packages'], [])

    def test_policy_replay_refused(self):
        contract = self.contract();contract['candidate_release']['id'] = 'other'
        with self.assertRaisesRegex(ValueError, 'policy/release'):
            p.run(contract)

    def test_wrong_policy_version_refused(self):
        contract = self.contract()
        self.rewrite(contract, 'coordinated_policy', lambda d: d['coordinated_sets'][0]['candidate'].update(mesa='wrong'))
        with self.assertRaisesRegex(ValueError, 'exact version'):
            p.run(contract)

    def test_archive_provenance_mismatch(self):
        contract = self.contract();ref = contract['before_release']['archive_index']
        doc = p.document(ref);doc['packages'][0]['archive']['sha256'] = '0' * 64
        contract['before_release']['archive_index'] = self.save('before-archives.json', doc)
        with self.assertRaisesRegex(ValueError, 'provenance digest'):
            p.run(contract)

    def test_tampered_archive(self):
        contract = self.contract();entry = p.document(contract['before_release']['archive_index'])['packages'][0]
        Path(entry['archive']['path']).write_bytes(b'corrupt')
        with self.assertRaisesRegex(ValueError, 'binary input'):
            p.run(contract)

    def test_duplicate_json(self):
        contract = self.contract();contract['protected_tuple'] = self.save('tuple.json', b'{"x":1,"x":2}')
        with self.assertRaisesRegex(ValueError, 'duplicate JSON'):
            p.run(contract)

    def test_candidate_signature_claim_missing_is_gap(self):
        contract = self.contract()
        ref = contract['candidate_release']['archive_index'];index = p.document(ref)
        origin = index['packages'][0]['provenance'];doc = p.document(origin['document'])
        doc['packages'][origin['row']]['verification'] = {}
        changed = self.save('candidate-provenance.json', doc)
        for row in index['packages']:
            row['provenance']['document'] = changed
        contract['candidate_release']['archive_index'] = self.save('candidate-archives.json', index)
        self.rewrite(contract, 'coordinated_policy', lambda d: d.update(candidate_release=contract['candidate_release']))
        self.assertIn('retained-signature-evidence-missing', self.codes(p.run(contract)))

    def test_archive_symlink_refused(self):
        contract = self.contract();entry = p.document(contract['before_release']['archive_index'])['packages'][0]
        path = Path(entry['archive']['path']);other = path.with_name('held-archive')
        path.rename(other);path.symlink_to(other)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            p.run(contract)

    def test_protected_baseline_pin_refused(self):
        contract = self.contract()
        self.rewrite(contract, 'protected_tuple', lambda d: d['input_sha256'].update(image='0' * 64))
        with self.assertRaisesRegex(ValueError, 'tuple/before'):
            p.run(contract)

    def test_overlapping_policy_refused(self):
        contract = self.contract()
        def overlap(doc):
            group = copy.deepcopy(doc['coordinated_sets'][0]);group['name'] = 'overlap'
            doc['coordinated_sets'].append(group)
        self.rewrite(contract, 'coordinated_policy', overlap)
        with self.assertRaisesRegex(ValueError, 'overlapping'):
            p.run(contract)

    def test_same_version_bytes_change_is_explicit(self):
        contract = self.contract();ref = contract['candidate_release']['archive_index'];index = p.document(ref)
        entry = next(r for r in index['packages'] if r['name'] == 'mesa')
        original = Path(entry['archive']['path']).read_bytes()
        # Valid second xz stream changes retained bytes without changing first PKGINFO.
        import lzma
        replacement = self.save('mesa-repacked.pkg.tar.xz', original + lzma.compress(b'fixture padding'))
        entry['archive'] = replacement
        origin = entry['provenance'];doc = p.document(origin['document'])
        doc['packages'][origin['row']]['archive'] = replacement
        changed = self.save('candidate-provenance.json', doc)
        for row in index['packages']:
            row['provenance']['document'] = changed
        contract['candidate_release']['archive_index'] = self.save('candidate-archives.json', index)
        self.rewrite(contract, 'coordinated_policy', lambda d: d.update(candidate_release=contract['candidate_release']))
        report = p.run(contract)
        self.assertEqual([r['name'] for r in report['changes']], ['mesa'])
        self.assertNotEqual(report['changes'][0]['before']['archive_sha256'], report['changes'][0]['candidate']['archive_sha256'])

    def test_nested_provider_work_refused_before_archive_inspection(self):
        contract = self.contract()
        rows = [{'metadata': {'NAME': ['pkg' + str(i)], 'VERSION': ['1-1'], 'ARCH': ['aarch64'],
                              'DEPENDS': ['provider'] * 200, 'PROVIDES': ['provider'] * 200}}
                for i in range(100)]
        contract['before_release']['inventory'] = self.save('large.json', {'packages': rows})
        with self.assertRaisesRegex(ValueError, 'work bound'):
            p.run(contract)

    def test_consumer_impact_timeout_is_controlled(self):
        with patch.object(p.subprocess, 'run', side_effect=subprocess.TimeoutExpired('fixture', 0.01)):
            with self.assertRaisesRegex(ValueError, 'impact deadline'):
                p.consumer_impact([], [], 1)

    def test_archive_pkginfo_identity_mismatch_refused(self):
        contract = self.contract()
        entry = p.document(contract['before_release']['archive_index'])['packages'][0]
        metadata = copy.deepcopy(self.row(self.before, entry['name']));metadata['VERSION'] = ['wrong-1']
        with self.assertRaisesRegex(ValueError, 'metadata inspection refused'):
            p.inspect(entry['archive'], metadata, 20)

    def test_cli_complete_blocked_and_no_overwrite(self):
        contract = self.contract();ref = self.save('contract.json', contract);output = self.root / 'output.json'
        command = [sys.executable, '-B', p.__file__, '--contract', ref['path'], '--contract-sha256', ref['sha256'], '--output', str(output)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        again = subprocess.run(command, capture_output=True, text=True, timeout=30)
        self.assertEqual(again.returncode, 1)
        self.rewrite(contract, 'retained_recovery_assets', lambda d: d.update(assets=[]))
        ref = self.save('contract.json', contract)
        command[command.index('--contract-sha256')+1] = ref['sha256'];command[-1] = str(self.root / 'blocked.json')
        self.assertEqual(subprocess.run(command, capture_output=True, timeout=30).returncode, 2)


if __name__ == '__main__':
    unittest.main()

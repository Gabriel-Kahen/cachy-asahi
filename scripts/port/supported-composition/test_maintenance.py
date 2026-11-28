#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real private libalpm for an explicitly synthetic three-change DATA proposal."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('composition_fixtures', Path(__file__).with_name('test_compose.py'))
T = importlib.util.module_from_spec(spec); spec.loader.exec_module(T)
c = T.c


class MaintenanceTests(unittest.TestCase):
    ref = T.CompositionTests.ref
    contract = T.CompositionTests.contract
    execute = T.CompositionTests.execute

    def setUp(self):
        T.CompositionTests.setUp(self)
        existing = {row['NAME'][0] for row in self.before}
        self.before += [T.package(name) for name in sorted(c.PLATFORM - existing)]
        self.before += [T.package('networkmanager', '1.58.1-1'), T.package('perl', '5.42.2-2')]
        self.catalogs['core'].append(T.package('perl', '5.42.3-1'))
        self.catalogs['extra'].append(T.package('networkmanager', '1.58.1-2'))

    def full(self, depends=('python>=3.11',)):
        contract = self.contract(depends); contract['workflow'] = 'full-desktop'
        contract['protected_tuple'] = self.ref('maintenance-tuple.json', {'kind': 'offline-platform-metadata-witnesses',
            'input_sha256': {'image': contract['image_inventory']['sha256']}, 'proposed_installed_dependency_graph':
                [{'name': row['NAME'][0], 'version': row['VERSION'][0]} for row in self.before
                 if row['NAME'][0] not in ('shared-lib', 'networkmanager', 'perl')]})
        contract['roots'] += [{'name': name, 'version': after, 'repo': repo}
                             for name, (_, after, repo) in c.maintenance.EXACT.items()]
        return contract

    def proposal(self, contract):
        original = self.ref('original-composition.json', contract)
        proposal = {'schema_version': 1, 'kind': 'unapproved-Asahi-three-package-maintenance-v1',
            'approval_status': 'UNAPPROVED', 'composition_contract': copy.deepcopy(original),
            **{key: copy.deepcopy(contract[key]) for key in ('image_inventory', 'protected_tuple', 'catalogs')},
            'changes': [{'name': name, 'before': before, 'after': after, 'repo': repo,
                         'reason': 'Synthetic exact maintenance compatibility proposal; no acceptance.'}
                        for name, (before, after, repo) in c.maintenance.EXACT.items()]}
        return original, proposal

    def proposed(self, contract, modify=None):
        original, proposal = self.proposal(contract)
        if modify: modify(proposal)
        proposal_ref = self.ref('proposal.json', proposal)
        self.counter += 1
        return c.compose(contract, self.root / ('maintenance-out-' + str(self.counter)),
                         maintenance_ref=proposal_ref, contract_ref=original)

    def test_exact_proposal_prepares_separately_and_retains_original_failure(self):
        report = self.proposed(self.full())
        self.assertEqual(report['original_policy']['status'], 'FAIL')
        self.assertEqual(report['metadata_prepare_status'], 'FAIL')
        self.assertTrue(report['original_policy_failure_retained'])
        proposed = report['proposed_maintenance']
        self.assertEqual(proposed['metadata_prepare_status'], 'PASS', proposed['blockers'])
        self.assertEqual(report['status'], 'HOLD'); self.assertEqual(report['approval_status'], 'UNAPPROVED')
        self.assertEqual({row['name'] for row in proposed['base_changes']}, set(c.maintenance.EXACT))
        self.assertTrue(all(row['exact_proposal_matches'] for row in proposed['base_changes']))
        self.assertEqual(proposed['original_protected_unchanged'], proposed['original_protected_count'] - 1)
        self.assertEqual(proposed['proposed_protected_preserved'], proposed['original_protected_count'])
        self.assertFalse(proposed['transaction_accepted']); self.assertFalse(proposed['selection_changed'])
        inventory = json.loads(Path(proposed['final_inventory']['path']).read_text())
        self.assertFalse(inventory['dependency_transaction_accepted'])
        self.assertEqual(next(row['version'] for row in inventory['proposed_final_inventory'] if row['name'] == 'python'), '3.14.8-1')
        self.assertTrue(report['private_database_removed'])

    def test_default_original_profile_still_fails_without_optional_proposal(self):
        report = self.execute(self.full())
        self.assertEqual(report['status'], 'FAIL'); self.assertNotIn('proposed_maintenance', report)
        self.assertTrue(any(row['expected'] == '3.14.7-1' and row['preserved'] for row in report['protected'] if row['name'] == 'python'))

    def test_same_version_provider_pin_rejects_different_catalog_metadata(self):
        self.before.append(T.package('backend', provides=('audio-backend',)))
        self.catalogs['extra'].append(T.package('backend', provides=('audio-backend', 'other-backend')))
        contract = self.full(('audio-backend',))
        contract['providers'].append({'name': 'backend', 'version': '1-1', 'repo': 'extra',
                                      'requirement': 'audio-backend'})
        proposed = self.proposed(contract)['proposed_maintenance']
        self.assertEqual(proposed['metadata_prepare_status'], 'FAIL')
        root = next(row for row in proposed['roots'] if row['name'] == 'backend')
        self.assertFalse(root['satisfied'])
        self.assertEqual(root['differing_metadata_fields'], ['PROVIDES'])
        self.assertFalse(proposed['provider_bindings'][0]['final_witness_matches'])

    def test_same_version_project_root_requires_reinstall_in_both_profiles(self):
        installed = T.package('candidate', depends=('python>=3.11',))
        installed['ARCH'] = ['any']
        self.before.append(installed)
        report = self.proposed(self.full())
        for result in (report, report['proposed_maintenance']):
            self.assertEqual(result['metadata_prepare_status'], 'FAIL')
            self.assertIn({
                'code': 'same-version-project-root-needs-explicit-reinstall-plan',
                'target': {'name': 'candidate', 'version': '1-1', 'repo': 'project'},
            }, result['blockers'])
            self.assertNotIn('candidate', {row['name'] for row in result['prepare']['add']})

    def test_wrong_after_missing_before_extra_package_and_reason_are_refused(self):
        alterations = [lambda p: p['changes'][0].update(after='3.14.9-1'),
                       lambda p: p['changes'][0].update(before='3.14.6-1'),
                       lambda p: p['changes'].append({'name': 'mesa', 'before': '1-1', 'after': '2-1', 'repo': 'extra', 'reason': 'forbidden'}),
                       lambda p: p['changes'][0].update(reason='')]
        for change in alterations:
            with self.subTest(change=change), self.assertRaises(ValueError): self.proposed(self.full(), change)

    def test_original_image_protected_catalog_and_composition_bindings_cannot_change(self):
        for key in ('image_inventory', 'protected_tuple', 'composition_contract'):
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.proposed(self.full(), lambda p: p[key].update(sha256='a' * 64))
        with self.assertRaises(ValueError):
            self.proposed(self.full(), lambda p: p['catalogs'][0].update(sha256='a' * 64))

    def test_extra_kernel_mesa_audio_target_changes_refuse_the_narrow_proposal(self):
        for name in ('linux-asahi', 'mesa', 'asahi-audio'):
            contract = self.full()
            contract['roots'].append({'name': name, 'version': '2-1', 'repo': 'asahi-alarm'})
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'extra original protected'):
                self.proposed(contract)

    def test_missing_retained_before_identity_refuses_the_proposal(self):
        contract = self.full()
        image = json.loads(Path(contract['image_inventory']['path']).read_text())
        image['packages'] = [row for row in image['packages'] if row['metadata']['NAME'] != ['networkmanager']]
        contract['image_inventory'] = self.ref('missing-networkmanager-image.json', image)
        protected = json.loads(Path(contract['protected_tuple']['path']).read_text())
        protected['input_sha256']['image'] = contract['image_inventory']['sha256']
        contract['protected_tuple'] = self.ref('missing-networkmanager-tuple.json', protected)
        with self.assertRaisesRegex(ValueError, 'retained before identity'):
            self.proposed(contract)

    def test_extra_implicit_unprotected_change_is_not_granted(self):
        report = self.proposed(self.full(('shared-lib>=2',)))
        self.assertEqual(report['proposed_maintenance']['metadata_prepare_status'], 'FAIL')
        self.assertTrue(any(row['code'] == 'unlisted-or-wrong-base-change' for row in report['proposed_maintenance']['blockers']))
        self.assertEqual(report['approval_status'], 'UNAPPROVED')

    def test_proposal_cannot_add_roots_or_flip_to_approved(self):
        contract = self.full(); contract['roots'] = [row for row in contract['roots'] if row['name'] != 'python']
        with self.assertRaisesRegex(ValueError, 'add or retarget'): self.proposed(contract)
        with self.assertRaises(ValueError): self.proposed(self.full(), lambda p: p.update(approval_status='APPROVED'))


if __name__ == '__main__':
    unittest.main(verbosity=2)

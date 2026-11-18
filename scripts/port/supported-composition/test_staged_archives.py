#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Actor-free regressions for the held archive projection."""

import base64
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('tested_staged_archives', Path(__file__).with_name('staged_archives.py'))
S = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(S)

SHA = 'a' * 64
SIGNATURE = b'fixture-signature-bytes'


def candidate(name, version='1-1', repo='core'):
    return {'name': name, 'version': version, 'repo': repo, 'metadata': {
        'NAME': [name], 'VERSION': [version], 'ARCH': ['aarch64'],
        'FILENAME': [f'{name}-{version}-aarch64.pkg.tar.xz'], 'CSIZE': ['32'], 'SHA256SUM': [SHA],
        'PGPSIG': [base64.b64encode(SIGNATURE).decode()],
    }}


def staged(row, scope='historical-ALARM-package'):
    return {'version': row['version'], 'arch': 'aarch64', 'filename': row['metadata']['FILENAME'][0],
            'archive': {'bytes': 32, 'sha256': SHA}, 'signature': S.T.pin(SIGNATURE), 'signature_scope': scope,
            'staged_repository': 'development-fixture'}


class StagedArchives(unittest.TestCase):
    def test_exact_historical_archive_supplies_bytes_without_origin_change(self):
        row = candidate('gtk4', repo='extra')
        result = S.mapping([row], 1, {}, {'gtk4': staged(row)})
        match = result['packages'][0]
        self.assertEqual(match['repo'], 'extra')
        self.assertEqual(match['archive_relation'], 'exact-staged-archive')
        self.assertEqual(match['signature_relation'], 'exact-candidate-catalog-signature')
        self.assertTrue(match['may_supply_candidate_archive_bytes'])
        self.assertEqual(result['eligible_archive_count'], 1)

    def test_protected_and_test_signed_archive_matches_cannot_supply(self):
        python, overlay = candidate('python', '3.14.8-1'), candidate('overlay', repo='project')
        result = S.mapping([python, overlay], 2, {'python': '3.14.7-1', 'linux-asahi': '1-1'}, {
            'python': staged(python), 'overlay': staged(overlay, 'project-TEST-overlay'),
        })
        self.assertEqual(result['archive_relations'], {'exact-staged-archive': 2})
        self.assertEqual(result['eligible_archive_count'], 0)
        self.assertEqual(result['protected_conflicts'], [
            {'name': 'linux-asahi', 'expected': '1-1', 'candidate': None},
            {'name': 'python', 'expected': '3.14.7-1', 'candidate': '3.14.8-1'},
        ])

    def test_compared_archive_fields_and_missing_pin(self):
        for field, value in (('SHA256SUM', ['b' * 64]), ('ARCH', ['any']),
                             ('CSIZE', ['33']), ('FILENAME', ['different.pkg.tar.xz'])):
            with self.subTest(field=field):
                row = candidate('extra')
                record = staged(row)
                row['metadata'][field] = value
                result = S.mapping([row], 1, {}, {'extra': record})
                self.assertEqual(result['archive_relations'], {'different-archive-identity': 1})
                self.assertEqual(result['eligible_archive_count'], 0)
        row = candidate('glib2', '2.88.3-1')
        record = staged(row)
        del row['metadata']['SHA256SUM']
        held = S.mapping([row], 1, {'glib2': '2.88.3-1'}, {'glib2': record})
        self.assertEqual(held['archive_relations'], {'candidate-archive-pin-missing': 1})
        newer = S.mapping([row], 1, {}, {'glib2': staged(candidate('glib2', '2.90.1-1'))})
        self.assertEqual(newer['archive_relations'], {'different-staged-version': 1})

    def test_contradictory_identity_and_duplicate_refused(self):
        row = candidate('extra')
        with self.assertRaisesRegex(ValueError, 'candidate identity'):
            S.mapping([row, row], 2, {}, {})
        with self.assertRaisesRegex(ValueError, 'candidate identity'):
            S.mapping([dict(row, version='2-1')], 1, {}, {})
        with self.assertRaisesRegex(ValueError, 'inventory count'):
            S.mapping([row], 2, {}, {})

    def test_catalog_signature_must_join_exact_staged_detached_signature(self):
        row = candidate('gtk4')
        record = {'gtk4': staged(row)}
        row['metadata']['PGPSIG'] = [base64.b64encode(b'other-signature').decode()]
        result = S.mapping([row], 1, {}, record)['packages'][0]
        self.assertEqual(result['signature_relation'], 'different-candidate-catalog-signature')
        self.assertFalse(result['may_supply_candidate_archive_bytes'])
        del row['metadata']['PGPSIG']
        missing = S.mapping([row], 1, {}, record)['packages'][0]
        self.assertEqual(missing['signature_relation'], 'candidate-catalog-signature-missing')
        self.assertFalse(missing['may_supply_candidate_archive_bytes'])

    def test_missing_catalog_operands_use_existing_intake_shape(self):
        alarm, asahi = candidate('gtk4', repo='extra'), candidate('asahi-audio', repo='asahi-alarm')
        del asahi['metadata']['PGPSIG']
        project = candidate('first-login', repo='project')
        baseline = candidate('linux-asahi', repo='observed-Asahi-base')
        python = candidate('python', '3.14.8-1')
        result = S.mapping([alarm, asahi, project, baseline, python], 5, {'python': '3.14.7-1'}, {})
        operands = result['missing_catalog_intake_operands']
        self.assertEqual(operands, [S.INTAKE.archive_spec(row['metadata'], row['repo'],
            'missing-exact-tentative-candidate') for row in (alarm, asahi)])
        self.assertEqual([(item['key'], item['signature_pin'] is not None) for item in operands],
                         [('alarm', True), ('community', False)])
        self.assertEqual(result['intake_counts_by_repository']['core'], {'protected-version-conflict': 1})
        self.assertEqual(result['intake_counts_by_repository']['observed-Asahi-base'],
                         {'observed-base-needs-exact-archive-binding': 1})
        self.assertEqual(result['intake_counts_by_repository']['project'],
                         {'project-candidate-needs-separate-archive-source': 1})
        alarm['metadata']['FILENAME'] = ['wrong.tar.zst']
        rejected = S.mapping([alarm], 1, {}, {})
        self.assertEqual(rejected['packages'][0]['intake_category'], 'catalog-operand-refused-by-existing-intake')
        self.assertEqual(rejected['missing_catalog_intake_operands'], [])

    def test_omitted_original_tuple_refuses_before_staging(self):
        images, tuple_ref, contract_ref, report_ref = ('image', 'tuple', 'contract', 'report')
        contract = {'schema_version': 1, 'kind': 'supported-Asahi-composition-inputs-v1', 'workflow': 'full-desktop',
                    'image_inventory': images, 'protected_tuple': tuple_ref}
        report = {'schema_version': 1, 'kind': 'supported-Asahi-composition-DATA-proposal', 'workflow': 'full-desktop',
                  'transaction_accepted': False, 'full_supported_system_accepted': False,
                  'input_references': [contract_ref, images, tuple_ref], 'protected': [],
                  'original_protected_count': 1}
        documents = {contract_ref: contract, report_ref: report}
        with patch.object(S.C.Reader, 'document', side_effect=documents.__getitem__), \
             patch.object(S.C, 'base_policy', return_value=({}, 1, {'python': '3.14.7-1'})), \
             patch.object(S, 'staged_records', side_effect=AssertionError('staging accessed after tuple omission')):
            with self.assertRaisesRegex(ValueError, 'original protected tuple'):
                S.evaluate(contract_ref, report_ref, Path('/unused'), None)


if __name__ == '__main__':
    unittest.main()

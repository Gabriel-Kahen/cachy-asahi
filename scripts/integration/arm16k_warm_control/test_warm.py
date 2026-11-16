# SPDX-License-Identifier: MIT
"""Finite joined-public-DATA controls; images and actor entry are never opened."""
import copy
import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent

def module(name):
    spec = importlib.util.spec_from_file_location('warm_test_'+name, HERE/(name+'.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class WarmControls(unittest.TestCase):
    def setUp(self):
        self.fixture = module('test_prepare')
        self.K = self.fixture.K
        self.packet, self.source, *_ = self.fixture.modeled()

    def test_complete_finite_provenance_and_observation_limits(self):
        self.K.inputs(self.packet, self.source, 1000000)
        selected = module('plan').WARM_SELECTION
        self.assertEqual(self.packet['baseline']['provenance'], selected)
        self.assertEqual(selected['packages']['count'], 111)
        self.assertEqual(selected['control']['scope'], 'ACCEPT_FINITE_OBSERVATION_AND_CLEANUP_ONLY')
        self.assertEqual(selected['control']['next_boot_stability'], 'NOT_RUN')
        self.assertFalse(selected['control']['package_transaction'])
        self.assertTrue(all(value is None for value in module('plan').plan()['decisions'].values()))

    def test_actual_selected_descriptor_tamper_refuses(self):
        for field in ('raw', 'prepared', 'certificate'):
            packet = copy.deepcopy(self.packet)
            packet['baseline'][field] = self.fixture.pin('SUBSTITUTED_'+field)
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.K.inputs(packet, self.source)

    def test_every_selected_provenance_field_and_absence_refuse(self):
        selected = self.packet['baseline']['provenance']
        for field in selected:
            packet = copy.deepcopy(self.packet)
            del packet['baseline']['provenance'][field]
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.K.inputs(packet, self.source)
        for field in ('original_baseline', 'control', 'conversion', 'packages'):
            packet = copy.deepcopy(self.packet)
            packet['baseline']['provenance'][field] = {}
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.K.inputs(packet, self.source)

    def test_boolean_integer_provenance_substitution_refuses(self):
        self.packet['baseline']['provenance']['control']['normal_PAM_logout'] = 1
        with self.assertRaises(ValueError):
            self.K.inputs(self.packet, self.source)

    def test_same_kernel_tools_and_original_nonce_are_required(self):
        cases = [('baseline_nonce', 'f'*32), ('kernel', {}),
            ('tool_image', 'sha256:'+'f'*64), ('actor_tools', {})]
        for field, value in cases:
            packet = copy.deepcopy(self.packet)
            packet[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.K.inputs(packet, self.source)

    def test_templates_do_not_issue_review_grants_or_run(self):
        template = self.K.input_template()
        for field in ('nonce', 'baseline_nonce', 'source_lock', 'tool_image', 'idle_seconds'):
            self.assertIsNone(template[field])
        self.assertIsNone(template['baseline']['accepted'])
        self.assertIsNone(self.K.authority_template()['accepted'])
        self.assertIsNone(self.K.admission_template()['accepted'])
        self.assertTrue(all(value is None for value in template['resources'].values()))


if __name__ == '__main__':
    unittest.main(verbosity=2)

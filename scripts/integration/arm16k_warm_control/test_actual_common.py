# SPDX-License-Identifier: MIT
"""Actual fixed common joins and negative DATA controls; no new image or VM."""
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('warm_actual_common', HERE/'construct_source.py')
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)
K = C.K


def completed_MODEL():
    """Only missing warm descriptors are synthetic; never actual qualification."""
    value = copy.deepcopy(C.incomplete_actual_selection())
    warm = dict(raw=dict(bytes=C.P.BASELINE['raw']['bytes'], sha256='a'*64),
        prepared=K.bytes_pin(b'PUBLIC_MODEL_PREPARED'),
        certificate=K.bytes_pin(b'PUBLIC_MODEL_CERTIFICATE_NOT_MINTED'))
    value['warmed_baseline'] = warm
    value['conversion'] = dict(report=K.bytes_pin(b'PUBLIC_MODEL_CONVERSION'),
        raw=warm['raw'], prepared=warm['prepared'], opaque_only=True, original_unchanged=True)
    value['packages']['warmed_inventory'] = copy.deepcopy(C.IDENTITY_PIN)
    return value


class ActualCommonControls(unittest.TestCase):
    def test_exact_actual_common_and_complete111_identity(self):
        common = C.fixed_common()
        self.assertEqual(K.json_pin(common), C.COMMON_PIN)
        self.assertEqual(common['original_baseline'], C.P.BASELINE)
        self.assertEqual(common['source23'], C.FIXED_CONTROL['source_lock'])
        self.assertEqual(common['dependency65'], C.P.SOURCE65['lock'])
        joins = {'packet': 'packet/control-packet.json', 'observations': 'control-output/observations.json',
            'report': 'control-output/report.json', 'terminal_closure': 'Root-terminal-closure.ACTUAL.json',
            'outer_result': 'outer-output/Root-outer-result.json'}
        for role, name in joins.items():
            self.assertEqual(C.FIXED_CONTROL[role], {n: common['control'][name][n] for n in ('bytes', 'sha256')})
        self.assertEqual(C.FIXED_CONTROL['overlay'], {n: common['overlay'][n] for n in ('bytes', 'sha256')})
        self.assertEqual(C.IDENTITY_PIN, {n: common['fixed_package_identity'][n] for n in ('bytes', 'sha256')})

    def test_concrete_actual_selection_is_incomplete_and_creates_no_source(self):
        value = K.load(HERE/'selection.ACTUAL.INCOMPLETE.DATA.json')
        self.assertEqual(value, C.incomplete_actual_selection())
        self.assertIsNone(value['conversion'])
        self.assertTrue(all(pin is None for pin in value['warmed_baseline'].values()))
        self.assertIsNone(value['packages']['warmed_inventory'])
        for field in ('Root_warm_baseline_acceptance', 'next_boot_stability'):
            self.assertIsNone(value[field])
        with tempfile.TemporaryDirectory(prefix='actual-common-public-DATA-') as directory:
            out = Path(directory)/'must-not-exist'
            with self.assertRaises(ValueError):
                C.construct(HERE/'selection.ACTUAL.INCOMPLETE.DATA.json', K.json_pin(value)['sha256'], out)
            self.assertFalse(out.exists())

    def test_actual_nonce_kernel_image_and_all_six_tool_substitutions_refuse(self):
        for field in ('baseline_nonce', 'kernel', 'tool_image', 'actor_tools'):
            value = completed_MODEL()
            value[field] = 'f'*32 if field == 'baseline_nonce' else ('sha256:'+'f'*64 if field == 'tool_image' else {})
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'same actual original nonce kernel image and six tools'):
                C.selection(value)
        for tool in K.TOOLS:
            value = completed_MODEL()
            value['actor_tools'][tool] = K.bytes_pin(b'SUBSTITUTED_TOOL')
            with self.subTest(tool=tool), self.assertRaisesRegex(ValueError, 'same actual original nonce kernel image and six tools'):
                C.selection(value)

    def test_whole_actual111_identity_cannot_be_replaced_by_count_or_another_pin(self):
        for replacement in (dict(count=111), K.bytes_pin(b'OTHER111')):
            value = completed_MODEL()
            value['packages']['original_inventory'] = replacement
            value['packages']['warmed_inventory'] = replacement
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                C.selection(value)

    def test_actual_control_packet_or_common_pin_tamper_refuses(self):
        value = completed_MODEL()
        value['control']['packet'] = K.bytes_pin(b'SUBSTITUTED_PACKET')
        with self.assertRaisesRegex(ValueError, 'complete exact original baseline control and cleanup provenance'):
            C.selection(value)
        value = completed_MODEL()
        value['common_inputs'] = K.bytes_pin(b'SUBSTITUTED_COMMON')
        with self.assertRaisesRegex(ValueError, 'exact common facts'):
            C.selection(value)

    def test_source_choices_never_premark_acceptance_or_next_boot_stability(self):
        C.selection(completed_MODEL())
        for field in ('Root_warm_baseline_acceptance', 'next_boot_stability'):
            for status in (True, 'PASS', 'STABLE'):
                value = completed_MODEL()
                value[field] = status
                with self.subTest(field=field, status=status), self.assertRaisesRegex(ValueError, 'unissued warm acceptance and stability'):
                    C.selection(value)


if __name__ == '__main__':
    unittest.main(verbosity=2)

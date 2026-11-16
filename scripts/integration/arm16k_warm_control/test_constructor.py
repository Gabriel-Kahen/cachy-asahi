# SPDX-License-Identifier: MIT
"""Public MODEL source construction; no actual warm descriptors or image reads."""
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('finite_warm_constructor', HERE/'construct_source.py')
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)
K = C.K


def model():
    pin = lambda label: K.bytes_pin(('PUBLIC_MODEL_'+label).encode())
    warm = dict(raw=dict(bytes=C.P.BASELINE['raw']['bytes'], sha256='a'*64),
        prepared=pin('warm_prepared'), certificate=pin('Root_SELECTED_CERTIFICATE_MODEL'))
    return dict(kind='ROOT_SELECTED_ONE_WARM_PAM_BASELINE_DATA_V1',
        original_baseline=copy.deepcopy(C.P.BASELINE), comparison_source65=copy.deepcopy(C.P.SOURCE65['lock']),
        control=copy.deepcopy(C.FIXED_CONTROL), warmed_baseline=warm,
        conversion=dict(report=pin('opaque_conversion_report'), raw=warm['raw'], prepared=warm['prepared'],
            opaque_only=True, original_unchanged=True),
        packages=dict(count=111, original_inventory=copy.deepcopy(C.IDENTITY_PIN), warmed_inventory=copy.deepcopy(C.IDENTITY_PIN)),
        baseline_nonce=C.COMMON['original_baseline_nonce'],
        kernel={n: copy.deepcopy(C.COMMON['kernel'][n]) for n in ('Image', 'config')},
        tool_image=C.COMMON['tool_image'], actor_tools=copy.deepcopy(C.COMMON['actor_tools']),
        common_inputs=copy.deepcopy(C.COMMON_PIN), Root_warm_baseline_acceptance=None, next_boot_stability=None)


class ConstructorControls(unittest.TestCase):
    def test_predecessor_complete_inverse_and_scope(self):
        inverse = C.V.verify()
        self.assertTrue(inverse['dependency65_unchanged'])
        self.assertTrue(inverse['actor_controller_reader_constructor_unchanged'])
        self.assertIsNone(inverse['actual_VM'])

    def test_unknown_empty_directory_cannot_disappear_from_inverse(self):
        with tempfile.TemporaryDirectory(prefix='finite-warm-inverse-MODEL-') as directory:
            root = Path(directory)
            (root/'public.py').write_bytes(b'# PUBLIC MODEL\n')
            (root/'unexpected').mkdir()
            with self.assertRaisesRegex(ValueError, 'exact source directory membership'):
                C.V.rows(root)

    def test_incomplete_new_root_choices_refuse(self):
        for field in ('raw', 'prepared', 'certificate'):
            selected = model()
            selected['warmed_baseline'][field] = None
            with self.subTest(field=field), self.assertRaises(ValueError):
                C.selection(selected)

    def test_missing_or_substituted_actual_control_cleanup_and_old_baseline_refuse(self):
        for field in ('original_baseline', 'comparison_source65', 'control'):
            selected = model()
            selected[field] = {}
            with self.subTest(field=field), self.assertRaises(ValueError):
                C.selection(selected)
        for field in C.FIXED_CONTROL:
            selected = model()
            del selected['control'][field]
            with self.subTest(control=field), self.assertRaises(ValueError):
                C.selection(selected)

    def test_integer_boolean_coercion_cannot_alter_actual_provenance(self):
        for group, field, value in (('control', 'normal_PAM_logout', 1),
                ('control', 'package_transaction', 0), ('conversion', 'opaque_only', 1),
                ('conversion', 'original_unchanged', 1), ('packages', 'count', True)):
            selected = model()
            selected[group][field] = value
            with self.subTest(group=group, field=field), self.assertRaises(ValueError):
                C.selection(selected)

    def test_package_change_and_partial_conversion_substitution_refuse(self):
        for field in ('raw', 'prepared'):
            selected = model()
            selected['warmed_baseline'][field] = K.bytes_pin(b'SUBSTITUTE')
            with self.subTest(field=field), self.assertRaises(ValueError):
                C.selection(selected)
        selected = model()
        selected['packages']['warmed_inventory'] = K.bytes_pin(b'SUBSTITUTED111')
        with self.assertRaises(ValueError):
            C.selection(selected)

    def test_real_public_source_snapshot_and_external_pin_tamper(self):
        with tempfile.TemporaryDirectory(prefix='finite-warm-public-MODEL-') as directory:
            root = Path(directory)
            inputs = root/'selection.json'
            value = model()
            inputs.write_bytes(K.canonical(value))
            expected = K.pin(inputs)['sha256']
            out = root/'source'
            report = C.construct(inputs, expected, out)
            self.assertIsNone(report['actual_source'])
            self.assertIsNone(report['actual_VM'])
            family = out/'arm16k_no_package_control'
            support = C.module('support', family)
            self.assertEqual(support.source(report['source_lock']), report['source_lock'])
            actor = family/'actor.py'
            original_actor = actor.read_bytes()
            actor.write_bytes(original_actor+b'\n')
            with self.assertRaisesRegex(ValueError, 'Source bytes/mode mismatch'):
                support.source(report['source_lock'])
            actor.write_bytes(original_actor)
            actor.chmod(0o755)
            with self.assertRaisesRegex(ValueError, 'ordinary Git0644 Source required'):
                support.source(report['source_lock'])
            actor.chmod(0o644)
            contracts = C.module('contracts', family)
            with self.assertRaises((ValueError, TypeError)):
                contracts.inputs(contracts.input_template(), report['source_lock'])
            before = C.V.rows(C.HERE/'predecessor'/'arm16k_no_package_control')
            after = C.V.rows(family)
            changed = {name for name in set(before)|set(after) if before.get(name) != after.get(name)}
            self.assertEqual(changed, {'plan.py', 'contracts.py', 'test_prepare.py', 'test_warm.py',
                'operator-inputs.TEMPLATE.json', 'source.lock.json'})
            self.assertEqual(C.V.rows(C.HERE/'predecessor'/'arm16k_perl5423_vm'),
                C.V.rows(out/'arm16k_perl5423_vm'))
            value['warmed_baseline']['certificate'] = K.bytes_pin(b'SUBSTITUTED_CERTIFICATE')
            inputs.write_bytes(K.canonical(value))
            with self.assertRaisesRegex(ValueError, 'exact external one-warm selection pin'):
                C.construct(inputs, expected, root/'must-not-exist')
            self.assertFalse((root/'must-not-exist').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)

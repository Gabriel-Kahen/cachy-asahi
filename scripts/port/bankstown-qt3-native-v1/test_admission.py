#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Finite synthetic DATA controls; these do not issue a Root decision."""
import copy
import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('bankstown_admission_test', HERE / 'admission.py')
A = importlib.util.module_from_spec(spec)
spec.loader.exec_module(A)


def model():
    """Unissued synthetic declaration, usable only within these tests."""
    tiny = A.pin(b'MODEL')
    return dict(schema=1, kind='ROOT_REVIEWED_BANKSTOWN_QT3_PRIVATE_TEST_V1', issuer='Root',
                approved=True, purpose='PRIVATE_TEST_NATIVE_BUILD_ONLY', issued_at=100, expires_at=200,
                source={'commit': 'a' * 40, 'ref': 'refs/heads/codex/MODEL'},
                materials={**{p: tiny for p in A.REQUIRED_MATERIALS},
                           'model/catalog.json': A.pin(b'MODEL_CATALOG'),
                           'model/inventory.lock': A.pin(b'MODEL_INVENTORY')},
                catalog=A.pin(b'MODEL_CATALOG'), image={'id': 'sha256:' + 'b' * 64,
                'inventory': A.pin(b'MODEL_INVENTORY')}, recipe={'path': A.RECIPE, 'version': '1.1.0-5'},
                resources={'wall_seconds': 600, 'command_seconds': 300, 'cpus': 1,
                           'memory_bytes': 1024**3, 'pids': 64, 'max_output_bytes': 1024**2},
                selected_files={**{p: tiny for p in A.TOOLS.values()}, '/usr/lib/Scrt1.o': tiny},
                tool_paths=A.TOOLS.copy(),
                closure={'status': 'ROOT_REVIEWED_COMPLETE_TOOL_SUPPORT_CLOSURE',
                         'non_elf_support': ['/usr/lib/Scrt1.o']},
                owned_executor={'code_pin': tiny, 'docker_endpoint': 'unix:///run/user/1000/docker.sock',
                                'engine_id': 'MODEL_ENGINE'},
                legal='HELD', key_freshness='HELD', **A.FINAL)


def check(value, now=150):
    raw = A.encoded(value)
    return A.validate_trial(raw, A.pin(raw)['sha256'], now=now)


class Admission(unittest.TestCase):
    def test_typed_finite_model_roundtrip_no_acceptance(self):
        d = check(model())
        self.assertEqual(d['tool_paths'], A.TOOLS)
        self.assertIsNone(d['Root_acceptance'])
        self.assertFalse(d['native_component_acceptance'])

    def test_unissued_or_forged_authority_refused(self):
        for key, value in (('approved', None), ('approved', 1), ('issuer', 'Worker'),
                           ('kind', 'MODEL'), ('schema', True), ('Root_acceptance', True),
                           ('native_component_acceptance', 0), ('legal', 'ACCEPTED')):
            d = model(); d[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                check(d)

    def test_whole_pin_and_duplicate_json_refused(self):
        raw = A.encoded(model())
        with self.assertRaisesRegex(ValueError, 'PIN_DIFFERS'):
            A.validate_trial(raw, '0' * 64, now=150)
        raw = raw.replace(b'"schema": 1', b'"schema": 1, "schema": 1')
        with self.assertRaisesRegex(ValueError, 'DUPLICATE'):
            A.validate_trial(raw, A.pin(raw)['sha256'], now=150)

    def test_freshness_strict_types_and_duration(self):
        for now in (99, 200, float('nan'), True):
            with self.subTest(now=now), self.assertRaises(ValueError):
                check(model(), now)
        d = model(); d['expires_at'] = 100000
        with self.assertRaises(ValueError): check(d)

    def test_materials_source_and_catalog_refs_required(self):
        for mutate in (lambda d: d['materials'].pop(A.PREFIX + 'profile.py'),
                       lambda d: d['source'].update(commit=None),
                       lambda d: d['materials'].update({'../escape': A.pin(b'x')}),
                       lambda d: d['materials'].update({'alias': d['catalog']}),
                       lambda d: d['image'].update(id='mutable:latest')):
            d = model(); mutate(d)
            with self.assertRaises(ValueError): check(d)

    def test_finite_resources_and_executor_exact(self):
        for key, value in (('wall_seconds', 601), ('cpus', 1.0), ('pids', True), ('memory_bytes', 0)):
            d = model(); d['resources'][key] = value
            with self.assertRaises(ValueError): check(d)
        for value in (None, {}, {'code_pin': A.pin(b'x'), 'docker_endpoint': 'tcp://host:2375', 'engine_id': 'x'}):
            d = model(); d['owned_executor'] = value
            with self.assertRaises(ValueError): check(d)

    def test_selected_namespace_counts_bytes_and_roles(self):
        for mutate in (lambda d: d['selected_files'].update({'/usr/../escape': A.pin(b'x')}),
                       lambda d: d['tool_paths'].update(rustc='/host/rustc'),
                       lambda d: d['closure'].update(non_elf_support=[]),
                       lambda d: d['selected_files'].update({'/oversized': {'bytes': 256*1024**2+1, 'sha256': 'a'*64}}),
                       lambda d: d['selected_files'].update({f'/many/{i}': A.pin(b'x') for i in range(4097)})):
            d = model(); mutate(d)
            with self.assertRaises(ValueError): check(d)


if __name__ == '__main__':
    unittest.main()

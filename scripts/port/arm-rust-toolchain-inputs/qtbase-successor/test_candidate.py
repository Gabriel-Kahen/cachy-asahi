#!/usr/bin/env python3
import copy
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('candidate', HERE / 'candidate.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def versioned_elf():
    data = bytearray(4096)
    data[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<H', data, 18, 183)
    struct.pack_into('<Q', data, 32, 64)
    struct.pack_into('<HH', data, 54, 56, 2)
    struct.pack_into('<IIQQQQQQ', data, 64, 1, 4, 0, 0x1000, 0, 4096, 4096, 4096)
    tags = [(5, 0x1300), (10, 32), (0x6ffffffe, 0x1400), (0x6fffffff, 1),
            (0x6ffffffc, 0x1500), (0x6ffffffd, 1), (0, 0)]
    struct.pack_into('<IIQQQQQQ', data, 120, 2, 4, 0x200, 0x1200, 0, len(tags) * 16, len(tags) * 16, 8)
    for i, pair in enumerate(tags):
        struct.pack_into('<qQ', data, 0x200 + i * 16, *pair)
    strings = b'\0libsample.so.1\0ABI_1\0'
    data[0x300:0x320] = strings.ljust(32, b'\0')
    name = strings.index(b'ABI_1')
    struct.pack_into('<HHIII', data, 0x400, 1, 1, 1, 16, 0)
    struct.pack_into('<IHHII', data, 0x410, 0, 0, 2, name, 0)
    struct.pack_into('<HHHHIII', data, 0x500, 1, 0, 2, 1, 0, 20, 0)
    struct.pack_into('<II', data, 0x514, name, 0)
    return data


class CandidateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.c, cls.lock, cls.combined = m.load()
        cls.baseline = json.loads((m.PARENT / 'inputs.lock.json').read_text())

    def test_explicit_successor_preserves275_and_original_hold(self):
        self.assertEqual(self.baseline['packages']['qt6-base']['version'], '6.12.0-2')
        self.assertEqual(self.combined['packages']['qt6-base']['version'], '6.12.0-3')
        for name, record in self.baseline['packages'].items():
            if name != 'qt6-base':
                self.assertEqual(record, self.combined['packages'][name])
        self.assertEqual(m.package_contracts(self.c, self.combined)[1], [])

    def test_protected_replacement_refused(self):
        changed = copy.deepcopy(self.lock)
        changed['new_packages']['icu'] = self.baseline['packages']['icu']
        with self.assertRaisesRegex(ValueError, 'protected package replacement'):
            m.combine(self.c, changed, self.baseline)

    def test_100_package_limit_refused(self):
        changed = copy.deepcopy(self.lock)
        changed['new_packages'].update({f'extra-{n}': {} for n in range(101)})
        with self.assertRaisesRegex(ValueError, 'exceeds100'):
            m.combine(self.c, changed, self.baseline)

    def test_wrong_candidate_version_refused(self):
        changed = copy.deepcopy(self.lock)
        changed['new_packages']['qt6-base']['version'] = '6.12.0-2'
        with self.assertRaisesRegex(ValueError, 'wrong explicit Qt'):
            m.combine(self.c, changed, self.baseline)

    def test_missing_declared_provider_is_retained(self):
        changed = copy.deepcopy(self.combined)
        del changed['packages']['json-glib']
        changed['dependency_joins'] = [r for r in changed['dependency_joins'] if r['package'] != 'json-glib']
        missing = m.package_contracts(self.c, changed)[1]
        self.assertTrue(any(r['provider'] == 'json-glib' for r in missing))

    def test_missing_inputs_refuse_preparation_before_output(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / 'prefix'
            args = SimpleNamespace(cache=[], output=output, prepare=True)
            with patch.object(self.c, 'find_input', return_value=None), self.assertRaisesRegex(ValueError, 'refusing preparation'):
                m.verify(self.c, self.lock, self.combined, args)
            self.assertFalse(output.exists())

    def test_version_need_and_definition(self):
        self.assertEqual(m.elf_versions.parse(versioned_elf()),
                         {'needs': {'libsample.so.1': ['ABI_1']}, 'defines': ['ABI_1']})

    def test_malformed_version_records_refused(self):
        for offset, value in [(0x40c, 16), (0x41c, 16), (0x408, 0xfffffff0)]:
            data = versioned_elf()
            struct.pack_into('<I', data, offset, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                m.elf_versions.parse(data)

    def test_GNU_version_mismatch_is_not_a_soname_pass(self):
        entries = {'/consumer': {'gnu_versions': {'needs': {'libsample.so.1': ['ABI_1']}}},
                   '/provider': {'gnu_versions': {'defines': ['ABI_2']}}}
        joins = [{'consumer': '/consumer', 'needed': 'libsample.so.1', 'provider': '/provider'}]
        self.assertEqual(m.elf_versions.join(entries, joins)[0], [])
        self.assertEqual(m.elf_versions.join(entries, joins)[1][0]['version'], 'ABI_1')

    def test_tmp_only(self):
        with self.assertRaisesRegex(ValueError, 'below /tmp'):
            m.below_tmp(Path('/home/not-a-cache'))


if __name__ == '__main__':
    unittest.main()

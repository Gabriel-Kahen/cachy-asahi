"""Synthetic controls: no archives, payload execution, linker or network."""
import importlib.util
from pathlib import Path
import resource
import struct
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('large_elf', Path(__file__).with_name('large_elf.py'))
L = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(L)


def image(alignment=16384, machine=183):
    data = L.ELFBuffer(4096)
    ident = b'\x7fELF\x02\x01\x01' + b'\0' * 9
    struct.pack_into('<16sHHIQQQIHHHHHH', data, 0, ident, 3, machine, 1,
                     0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
    struct.pack_into('<IIQQQQQQ', data, 64, 1, 5, 0, 0, 0, len(data), len(data), alignment)
    strings = b'\0libc.so.6\0GLIBC_2.17\0libdemo.so.1\0DEMO_1.0\0'
    data[0x300:0x300 + len(strings)] = strings
    tags = [(1, strings.index(b'libc')), (5, 0x300), (10, len(strings)),
            (14, strings.index(b'libdemo')), (0x6ffffffe, 0x380), (0x6fffffff, 1),
            (0x6ffffffc, 0x3b0), (0x6ffffffd, 1), (0, 0)]
    struct.pack_into('<IIQQQQQQ', data, 120, 2, 4, 0x200, 0x200, 0x200,
                     len(tags) * 16, len(tags) * 16, 8)
    for i, (tag, value) in enumerate(tags):
        struct.pack_into('<qQ', data, 0x200 + i * 16, tag, value)
    struct.pack_into('<HHIII', data, 0x380, 1, 1, strings.index(b'libc'), 16, 0)
    struct.pack_into('<IHHII', data, 0x390, 0, 0, 2, strings.index(b'GLIBC'), 0)
    struct.pack_into('<HHHHIII', data, 0x3b0, 1, 0, 2, 1, 0, 20, 0)
    struct.pack_into('<II', data, 0x3c4, strings.index(b'DEMO'), 0)
    return data


class LargeELFTests(unittest.TestCase):
    def test_16k_and_actual_version_contracts(self):
        result = L.inspect(image())
        self.assertEqual(result['classification'], 'AARCH64_STRUCTURAL_16K_OBSERVED')
        self.assertEqual(result['elf']['needed'], ['libc.so.6'])
        self.assertEqual(result['elf']['soname'], 'libdemo.so.1')
        self.assertEqual(result['gnu_versions'], {'needs': {'libc.so.6': ['GLIBC_2.17']},
                                                 'defines': ['DEMO_1.0']})
        self.assertFalse(result['runtime_load_verified'])

    def test_4k_is_not_promoted_by_16k_congruence(self):
        result = L.inspect(image(alignment=4096))
        self.assertTrue(result['elf']['PT_LOAD'][0]['offset_vaddr_congruent_mod_16384'])
        self.assertTrue(result['elf']['insufficient_declared_16K_alignment'])
        self.assertEqual(result['classification'], 'AARCH64_STRUCTURAL_16K_REFUSED')
        self.assertTrue(result['geometry']['errors'])

    def test_wrong_arch_is_static_data(self):
        result = L.inspect(image(machine=62))
        self.assertEqual(result['classification'], 'WRONG_ARCHITECTURE_OR_RUNTIME_SCOPE_UNRESOLVED')
        self.assertTrue(result['geometry']['errors'])

    def test_object_cap_before_allocation_and_before_inspection(self):
        with self.assertRaisesRegex(ValueError, 'object byte cap'):
            L.ELFBuffer(L.MAX_OBJECT_BYTES + 1)
        with self.assertRaisesRegex(ValueError, 'object byte cap'):
            L.inspect(image(), object_cap=4095)
        with self.assertRaisesRegex(ValueError, 'cap policy'):
            L.inspect(image(), object_cap=L.MAX_OBJECT_BYTES + 1)

    def test_streamed_prefix_extend_retains_c_buffer(self):
        original = image()
        data = L.ELFBuffer(b'\x7fELF')
        data.extend(memoryview(original)[4:])
        self.assertEqual(struct.unpack_from('<H', data, 18)[0], 183)
        self.assertEqual(L.inspect(data)['gnu_versions']['defines'], ['DEMO_1.0'])
        with patch.object(L, 'MAX_OBJECT_BYTES', 8):
            small = L.ELFBuffer(b'1234')
            with self.assertRaisesRegex(ValueError, 'object byte cap'):
                small.extend(b'56789')

    def test_slices_share_storage_and_cannot_copy_large_suffixes(self):
        data = L.ELFBuffer(2 * L.MIB)
        data[100:104] = b'name'
        table = data[64:]
        self.assertIs(table.owner, data)
        self.assertEqual(table.index(b'name'), 36)
        data[100] = ord('N')
        self.assertEqual(table[36:40].decode(), 'Name')
        self.assertIn(b'Name', table[36:])
        with self.assertRaisesRegex(ValueError, 'string copy bound'):
            bytes(table)

    def test_malformed_version_chain_refused(self):
        data = image()
        struct.pack_into('<I', data, 0x390 + 12, 16)
        with self.assertRaisesRegex(ValueError, 'auxiliary chain'):
            L.inspect(data)

    def test_operation_and_deadline_bounds(self):
        with patch.object(L, 'MAX_OPERATIONS', 1):
            with self.assertRaisesRegex(ValueError, 'operation/time bound'):
                L.inspect(image())
        with patch.object(L, 'MAX_PARSE_SECONDS', -1):
            with self.assertRaisesRegex(ValueError, 'operation/time bound'):
                L.inspect(image())

    def test_large_prebuilt_input_requires_streaming(self):
        with self.assertRaisesRegex(ValueError, 'must stream'):
            L.ELFBuffer(b'x' * (L.MIB + 1))
        with self.assertRaisesRegex(ValueError, 'must stream'):
            L.inspect(b'x' * (L.MIB + 1))

    def test_process_limit_does_not_exceed_contract(self):
        L.limit_process()
        soft, hard = resource.getrlimit(resource.RLIMIT_AS)
        self.assertLessEqual(soft, L.PROCESS_LIMIT_BYTES)
        self.assertLessEqual(hard, L.PROCESS_LIMIT_BYTES)


if __name__ == '__main__':
    unittest.main()

"""Static ELF segment invariants, without executing synthetic fixtures."""
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts/checks'))
import package_checks as checks


def elf(file_offset=0, address=0, alignment=16384):
    data = bytearray(120)
    data[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HH', data, 16, 2, 183)
    struct.pack_into('<Q', data, 32, 64)
    struct.pack_into('<HHH', data, 52, 64, 56, 1)
    struct.pack_into('<IIQQQQQQ', data, 64, 1, 5, file_offset, address, 0, 0, 0, alignment)
    return data


class ELFAlignmentTests(unittest.TestCase):
    def test_declared_alignment_rejects_page_congruent_mismatches(self):
        for offset, address, alignment in ((0, 16384, 65536), (8, 16392, 65536),
                                            (16, 65552, 131072)):
            with self.subTest(offset=offset, address=address, alignment=alignment):
                errors = checks.elf_check(elf(offset, address, alignment))['errors']
                self.assertTrue(any('p_align' in error for error in errors), errors)

    def test_equal_nonzero_residues_are_valid(self):
        for offset, address, alignment in ((0, 16384, 16384), (0, 65536, 65536),
                                            (8, 65544, 65536), (16, 131088, 65536),
                                            (8, 131080, 131072)):
            with self.subTest(offset=offset, address=address, alignment=alignment):
                result = checks.elf_check(elf(offset, address, alignment))
                self.assertEqual(result['errors'], [])
                self.assertEqual(result['hardware_status'], 'NOT RUN')

    def test_invalid_alignments_refuse_without_division_errors(self):
        for alignment in (0, 1, 4096, 24576):
            with self.subTest(alignment=alignment):
                self.assertTrue(checks.elf_check(elf(alignment=alignment))['errors'])


if __name__ == '__main__':
    unittest.main()

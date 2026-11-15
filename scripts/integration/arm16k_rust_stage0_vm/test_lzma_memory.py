# SPDX-License-Identifier: MIT
"""Finite decoder policy and header DATA controls; no archive or actor entry."""
import importlib.util
import io
import json
import lzma
from pathlib import Path
import unittest
from unittest.mock import Mock,patch
import zlib

HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('fenced_lzma_stage0',HERE/'stage0.py');S=importlib.util.module_from_spec(s);s.loader.exec_module(S)


class LzmaMemoryControls(unittest.TestCase):
    def test_selected_finite_cap_is_passed_to_decoder(self):
        self.assertEqual(S.MAX_DECODER_MEMORY,160*1024**2)
        with patch.object(S.lzma,'LZMADecompressor',return_value=Mock()) as factory:
            S._XZStream(io.BytesIO(b''),dict(bytes=0,sha256='0'*64))
        factory.assert_called_once_with(format=lzma.FORMAT_XZ,memlimit=160*1024**2)
        self.assertEqual((S.CHUNK,S.MAX_ARCHIVE,S.MAX_LOGICAL,S.MAX_FILE),(65536,128*1024**2,1024**3,256*1024**2))

    def test_recorded_real_headers_and_one_byte_probe_join_exact_archives(self):
        data=json.loads((HERE/'data/lzma-memory-profile.json').read_bytes());spec=json.loads((HERE/'data/stage0.json').read_bytes())
        self.assertEqual(data['selected_memlimit_bytes'],S.MAX_DECODER_MEMORY)
        self.assertEqual(data['max_output_per_probe'],1);self.assertFalse(data['full_archive_extraction']);self.assertFalse(data['owner_bounds_changed'])
        for name,row in data['archives'].items():
            self.assertEqual(row['archive_expected_pin'],{k:spec['archives'][name][k] for k in ('bytes','sha256')})
            f=row['filters'][0];decoded=lzma._decode_filter_properties(f['id'],bytes.fromhex(f['properties_hex']))
            self.assertEqual(decoded,f['decoded']);self.assertLess(decoded['dict_size'],S.MAX_DECODER_MEMORY)
            selected=next(p for p in row['probes'] if p['memlimit']==S.MAX_DECODER_MEMORY)
            self.assertEqual((selected['status'],selected['output_bytes']),('PASS_FIRST_BYTE_ONLY',1))
        self.assertGreater(data['measured_first_byte_minimum']['smallest_accepted_bytes'],128*1024**2)

    def test_larger_dictionary_header_is_still_refused_before_output(self):
        data=json.loads((HERE/'data/lzma-memory-profile.json').read_bytes());row=data['archives']['rustc-1.98.0-aarch64-unknown-linux-gnu.tar.xz']
        block=bytearray.fromhex(row['block_header_hex']);block[4]=0x20  # 256MiB dictionary.
        block[-4:]=zlib.crc32(block[:-4]).to_bytes(4,'little')
        decoder=lzma.LZMADecompressor(format=lzma.FORMAT_XZ,memlimit=S.MAX_DECODER_MEMORY)
        with self.assertRaisesRegex(lzma.LZMAError,'Memory usage limit exceeded'):
            decoder.decompress(bytes.fromhex(row['xz_header_hex'])+block,max_length=1)


if __name__=='__main__':unittest.main()

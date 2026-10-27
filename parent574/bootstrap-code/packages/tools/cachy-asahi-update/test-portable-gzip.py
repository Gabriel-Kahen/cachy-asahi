#!/usr/bin/env python3
"""Finite offline fixtures for portable gzip; no generator/pin modifications."""
import binascii
import gzip
import importlib.util
import io
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('portable_gzip', Path(__file__).with_name('portable-gzip.py'))
portable = importlib.util.module_from_spec(spec)
spec.loader.exec_module(portable)


def encode(data, chunks=None, flush=False):
    output = io.BytesIO()
    with portable.GzipFile(filename='', fileobj=output, mode='wb', mtime=0) as writer:
        if chunks is None:
            chunks = [len(data)]
        offset = 0
        for size in chunks:
            writer.write(data[offset:offset + size])
            offset += size
            if flush:
                writer.flush()
        writer.write(data[offset:])
    return output.getvalue()


class PortableTests(unittest.TestCase):
    def test_exact_empty_encoding(self):
        expected = portable.HEADER + b'\x01\x00\x00\xff\xff' + b'\x00' * 8
        self.assertEqual(encode(b''), expected)
        self.assertEqual(gzip.decompress(expected), b'')

    def test_known_single_block_and_trailer(self):
        data = b'123456789'
        expected = portable.HEADER + struct.pack('<BHH', 1, 9, 9 ^ 0xffff) + data
        expected += struct.pack('<II', 0xcbf43926, 9)
        self.assertEqual(encode(data), expected)

    def test_compression_levels_and_engine_do_not_affect_encoding(self):
        outputs = []
        with patch.object(gzip.zlib, 'compressobj', side_effect=AssertionError('compression engine called')):
            for level in (0, 1, 9):
                output = io.BytesIO()
                with portable.GzipFile(fileobj=output, mode='wb', compresslevel=level, mtime=0) as writer:
                    writer.write(b'fixture' * 20000)
                outputs.append(output.getvalue())
        self.assertEqual(outputs[0], outputs[1])
        self.assertEqual(outputs[0], outputs[2])

    def test_chunk_and_flush_invariance_across_boundary_sizes(self):
        for size in (0, 1, 65534, 65535, 65536, 131070, 131071, 1024 * 1024 + 13):
            data = (bytes(range(256)) * ((size + 255) // 256))[:size]
            expected = encode(data)
            for chunks in ([1, 1, 65533, 1, 65535], [32767] * 40, [65535] * 20):
                with self.subTest(size=size, chunks=chunks[:3]):
                    actual = encode(data, chunks, flush=True)
                    self.assertEqual(actual, expected)
                    self.assertEqual(gzip.decompress(actual), data)

    def test_fixed_stored_blocks_and_final_bit(self):
        data = b'x' * (65535 * 2 + 7)
        encoded = encode(data)
        offset = len(portable.HEADER)
        lengths = []
        while True:
            final, size, inverse = struct.unpack_from('<BHH', encoded, offset)
            self.assertIn(final, (0, 1))
            self.assertEqual(size ^ inverse, 0xffff)
            self.assertEqual(encoded[offset + 5:offset + 5 + size], b'x' * size)
            lengths.append(size)
            offset += 5 + size
            if final:
                break
        self.assertEqual(lengths, [65535, 65535, 7])
        self.assertEqual(len(encoded) - offset, 8)

    def test_exact_multiple_has_no_extra_empty_block(self):
        self.assertEqual(len(encode(b'x' * 65535)), 10 + 5 + 65535 + 8)

    def test_input_limits_reject_before_accepting_excess_and_no_valid_finalization(self):
        output = io.BytesIO()
        writer = portable.GzipFile(filename='', fileobj=output, mode='wb', mtime=0, max_bytes=3)
        writer.write(b'abc')
        with self.assertRaises(ValueError):writer.write(b'd')
        with self.assertRaises(OSError):writer.write(b'')
        writer.close()
        self.assertTrue(writer.closed)
        with self.assertRaises((EOFError, gzip.BadGzipFile)):gzip.decompress(output.getvalue())
        for invalid in (-1, True, portable.MAX_INPUT_BYTES + 1):
            with self.assertRaises(ValueError):
                portable.GzipFile(fileobj=io.BytesIO(), mode='wb', max_bytes=invalid)

    def test_close_idempotent_external_sink_preserved_and_closed_operations_refused(self):
        output = io.BytesIO()
        writer = portable.GzipFile(fileobj=output, mode='wb', mtime=0)
        self.assertTrue(writer.writable());self.assertFalse(writer.readable());self.assertFalse(writer.seekable())
        self.assertEqual(writer.write(memoryview(b'abc')), 3)
        self.assertEqual(writer.tell(), 3)
        writer.close();first = output.getvalue();writer.close()
        self.assertEqual(first, output.getvalue());self.assertFalse(output.closed)
        for action in (lambda: writer.write(b'd'), writer.flush, writer.tell):
            with self.assertRaises(ValueError):action()

    def test_owned_file_closed_and_body_exception_still_propagated(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'out.gz'
            with self.assertRaisesRegex(RuntimeError, 'fixture'):
                with portable.GzipFile(filename=path, mode='wb', mtime=0) as writer:
                    writer.write(b'partial input')
                    raise RuntimeError('fixture')
            self.assertTrue(writer.closed)
            self.assertTrue(writer._output.closed)
            self.assertEqual(gzip.decompress(path.read_bytes()), b'partial input')

    def test_read_delegate_survives_temporary_global_factory_patch(self):
        data = encode(b'read fixture')
        original = gzip.GzipFile
        with patch.object(gzip, 'GzipFile', portable.GzipFile):
            with gzip.GzipFile(fileobj=io.BytesIO(data), mode='rb') as reader:
                self.assertIsInstance(reader, original)
                self.assertEqual(reader.read(), b'read fixture')

    def test_corrupt_crc_size_and_truncated_data_rejected_by_standard_reader(self):
        data = encode(b'fixture')
        for modified in (data[:-8] + b'\x00' * 8, data[:-1], data[:12]):
            with self.subTest(data=modified), self.assertRaises((gzip.BadGzipFile, EOFError)):
                gzip.decompress(modified)

    def test_short_writes_and_sink_failure_close_lifecycle(self):
        class Short(io.BytesIO):
            def write(self, data):return super().write(data[:3])
        output = Short()
        with portable.GzipFile(fileobj=output, mode='wb') as writer:writer.write(b'fixture' * 20000)
        self.assertEqual(gzip.decompress(output.getvalue()), b'fixture' * 20000)
        class Fails(io.BytesIO):
            fail = False
            def write(self, data):
                if self.fail:raise OSError('fixture sink failed')
                return super().write(data)
        output = Fails();writer = portable.GzipFile(fileobj=output, mode='wb');writer.write(b'fixture');output.fail = True
        with self.assertRaises(OSError):writer.close()
        self.assertTrue(writer.closed);writer.close();self.assertFalse(output.closed)

    def test_blocked_sink_and_flush_failure_are_terminal(self):
        class Blocked(io.BytesIO):
            def write(self, data):return 0
        output = Blocked()
        with self.assertRaises(OSError):portable.GzipFile(fileobj=output, mode='wb')
        self.assertFalse(output.closed)
        class FailsFlush(io.BytesIO):
            def flush(self):raise OSError('flush fixture')
        output = FailsFlush();writer = portable.GzipFile(fileobj=output, mode='wb');writer.write(b'fixture')
        with self.assertRaises(OSError):writer.flush()
        writer.close()
        self.assertTrue(writer.closed)
        with self.assertRaises((gzip.BadGzipFile, EOFError)):gzip.decompress(output.getvalue())

    def test_bad_input_and_unsupported_modes_do_not_change_stream(self):
        output = io.BytesIO();writer = portable.GzipFile(fileobj=output, mode='wb')
        for data in ('text', memoryview(b'abcdef')[::2]):
            with self.assertRaises(TypeError):writer.write(data)
        self.assertEqual(writer.tell(), 0);writer.write(b'ok');writer.close()
        self.assertEqual(gzip.decompress(output.getvalue()), b'ok')
        for args in ({'mode': 'ab'}, {'mode': 'wt'}, {'mode': 'wb', 'mtime': 1}, {'mode': 'wb', 'compresslevel': 10}):
            with self.assertRaises(ValueError):portable.GzipFile(fileobj=io.BytesIO(), **args)

    def test_tarfile_stream_and_seekable_writer_use(self):
        outputs = []
        for mode in ('w', 'w|'):
            output = io.BytesIO()
            with portable.GzipFile(fileobj=output, mode='wb', filename='', mtime=0) as encoded:
                with tarfile.open(fileobj=encoded, mode=mode, format=tarfile.PAX_FORMAT) as archive:
                    info = tarfile.TarInfo('fixture');info.size = 7;info.mtime = 0
                    archive.addfile(info, io.BytesIO(b'fixture'))
            outputs.append(output.getvalue())
            with tarfile.open(fileobj=io.BytesIO(outputs[-1]), mode='r:gz') as archive:
                self.assertEqual(archive.extractfile('fixture').read(), b'fixture')
        self.assertEqual(*outputs)

    def test_finite_large_fixture_crc_and_size(self):
        data = bytes(range(256)) * (4 * 1024 * 1024 // 256)
        encoded = encode(data, [65535] * 64)
        crc, size = struct.unpack('<II', encoded[-8:])
        self.assertEqual(crc, binascii.crc32(data) & 0xffffffff)
        self.assertEqual(size, len(data))
        self.assertEqual(gzip.decompress(encoded), data)
        self.assertEqual(len(encoded), 18 + len(data) + 5 * ((len(data) + 65534) // 65535))


if __name__ == '__main__':
    unittest.main()

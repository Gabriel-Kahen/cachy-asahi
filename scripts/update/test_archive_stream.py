#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Actual compressed data inspection only; no extraction or system actors."""
import argparse
from dataclasses import replace
import gzip
import hashlib
import importlib.util
import io
import lzma
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import time
import tracemalloc
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('archive_stream', Path(__file__).with_name('archive_stream.py'))
reader = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = reader
spec.loader.exec_module(reader)
WORKSPACE = None
FORMATS = ('gzip', 'xz', 'zstd')


def tar_bytes(entries=None, tar_format=tarfile.PAX_FORMAT):
    if entries is None:
        entries = [('.PKGINFO', b'fixture metadata\n'), ('usr/share/demo/data', b'payload\n')]
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=tar_format) as archive:
        for item, data in entries:
            if isinstance(item, str):
                info = tarfile.TarInfo(item)
                info.size = len(data)
                info.mode = 0o644
            else:
                info = item
            archive.addfile(info, io.BytesIO(data) if info.isfile() else None)
    return output.getvalue()


def compress(data, kind):
    if kind == 'gzip':
        return gzip.compress(data, mtime=0)
    if kind == 'xz':
        return lzma.compress(data)
    if reader.zstd is None:
        raise unittest.SkipTest('Python compression.zstd is required for zstd cases')
    return reader.zstd.compress(data)


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='stream-archive-', dir=WORKSPACE)
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'archive'
        self.limits = reader.Limits(compressed_bytes=8 * 1024**2, total_compressed_bytes=16 * 1024**2,
            decoded_bytes=32 * 1024**2, members=100, file_bytes=20 * 1024**2,
            window_bytes=64 * 1024**2, deadline=time.monotonic() + 30)

    def parse(self, raw=None, kind='gzip', limits=None, accounting=None):
        self.path.write_bytes(compress(tar_bytes() if raw is None else raw, kind))
        return reader.archive_payload(self.path, limits or self.limits, accounting)

    def test_all_three_real_formats_and_exact_success_accounting(self):
        for kind in FORMATS:
            with self.subTest(kind=kind):
                accounting = {'bytes': 0, 'nodes': 0}
                raw = tar_bytes()
                rows = self.parse(raw, kind, accounting=accounting)
                self.assertEqual(rows, {'usr/share/demo/data': dict(type='file', mode=0o644, uid=0, gid=0,
                    sha256=hashlib.sha256(b'payload\n').hexdigest(), bytes=8)})
                self.assertEqual(accounting, {'bytes': len(raw), 'nodes': 2,
                                             'compressed_bytes': self.path.stat().st_size})

    def test_regular_directory_relative_link_and_long_pax_path(self):
        directory = tarfile.TarInfo('usr/share/demo')
        directory.type, directory.mode = tarfile.DIRTYPE, 0o755
        link = tarfile.TarInfo('usr/share/demo/alias')
        link.type, link.linkname = tarfile.SYMTYPE, 'data'
        long = 'usr/share/' + 'x' * 140
        rows = self.parse(tar_bytes([(directory, b''), ('usr/share/demo/data', b'x'),
                                     (link, b''), (long, b'y')]), 'zstd')
        self.assertEqual(rows[directory.name]['type'], 'directory')
        self.assertEqual(rows[link.name]['target'], 'data')
        self.assertIn(long, rows)

    def test_compressed_per_archive_and_aggregate_limits(self):
        self.parse()
        size = self.path.stat().st_size
        for limits, accounting in ((replace(self.limits, compressed_bytes=size - 1), None),
                (replace(self.limits, total_compressed_bytes=size), {'compressed_bytes': 1})):
            with self.subTest(limits=limits), self.assertRaises(reader.Invalid):
                reader.archive_payload(self.path, limits, accounting)

    def test_python_tarfile_zstd_writer_compatibility(self):
        if reader.zstd is None:
            self.skipTest('Python compression.zstd is unavailable')
        with tarfile.open(self.path, 'w:zst') as archive:
            item = tarfile.TarInfo('payload')
            item.size = 4
            archive.addfile(item, io.BytesIO(b'data'))
        rows = reader.archive_payload(self.path, self.limits)
        self.assertEqual(rows['payload']['sha256'], hashlib.sha256(b'data').hexdigest())

    def test_gnu_long_name_extension_is_streamed_and_counted(self):
        name = 'usr/share/' + 'x' * 140
        accounting = {'bytes': 0, 'nodes': 0}
        rows = self.parse(tar_bytes([(name, b'x')], tarfile.GNU_FORMAT), 'xz', accounting=accounting)
        self.assertIn(name, rows)
        self.assertEqual(accounting['nodes'], 2)

    def test_decoded_bombs_bounded_for_every_format(self):
        raw = tar_bytes([('payload', b'x' * 2 * 1024**2)])
        for kind in FORMATS:
            with self.subTest(kind=kind), self.assertRaisesRegex(reader.Invalid, 'decoded byte limit'):
                self.parse(raw, kind, replace(self.limits, decoded_bytes=65536))

    def test_shared_decoded_and_member_counters_cannot_reset_per_archive(self):
        accounting = {'bytes': 0, 'nodes': 0}
        limits = replace(self.limits, decoded_bytes=len(tar_bytes()), members=2)
        self.parse(limits=limits, accounting=accounting)
        before = dict(accounting)
        with self.assertRaises(reader.Invalid):
            reader.archive_payload(self.path, limits, accounting)
        self.assertEqual(accounting, before)

    def test_file_and_control_member_limits(self):
        for name in ('payload', '.PKGINFO'):
            with self.subTest(name=name), self.assertRaisesRegex(reader.Invalid, 'file byte limit'):
                self.parse(tar_bytes([(name, b'12345')]), limits=replace(self.limits, file_bytes=4))

    def test_zero_sized_member_flood_and_metadata_headers_count(self):
        for raw in (tar_bytes([('a', b''), ('b', b'')]), tar_bytes([('a' * 140, b'')])):
            with self.subTest(raw_size=len(raw)), self.assertRaisesRegex(reader.Invalid, 'member limit'):
                self.parse(raw, limits=replace(self.limits, members=1))

    def test_oversized_pax_header_is_bounded_before_tarfile_allocation(self):
        info = tarfile.TarInfo('payload')
        info.pax_headers = {'comment': 'x' * (reader.CHUNK + 1)}
        with self.assertRaisesRegex(reader.Invalid, 'extended header byte limit'):
            self.parse(tar_bytes([(info, b'')]))

    def test_xz_and_zstd_decoder_window_limits(self):
        raw = tar_bytes([('payload', b'x' * 1024**2)])
        with self.assertRaises(reader.Invalid):
            self.parse(raw, 'xz', replace(self.limits, window_bytes=32768))
        if reader.zstd is not None:
            z = reader.zstd
            codec = z.ZstdCompressor(options={z.CompressionParameter.window_log: 20,
                                            z.CompressionParameter.content_size_flag: 0})
            self.path.write_bytes(codec.compress(raw) + codec.flush())
            with self.assertRaises(reader.Invalid):
                reader.archive_payload(self.path, replace(self.limits, window_bytes=32768))

    def test_truncation_trailing_and_concatenated_compressed_frames(self):
        for kind in FORMATS:
            encoded = compress(tar_bytes(), kind)
            for bad in (encoded[:-1], encoded[:len(encoded) // 2], encoded + b'junk', encoded + encoded):
                with self.subTest(kind=kind, size=len(bad)), self.assertRaises(reader.Invalid):
                    self.path.write_bytes(bad)
                    reader.archive_payload(self.path, self.limits)

    def test_uncompressed_tar_trailing_archive_and_incomplete_zero_ending(self):
        raw = tar_bytes()
        for bad in (raw + tar_bytes([('other', b'x')]), raw + b'junk', raw[:1536], raw[:-1]):
            with self.subTest(size=len(bad)), self.assertRaises(reader.Invalid):
                self.parse(bad)

    def test_bad_paths_uids_duplicate_members_and_control_names(self):
        for name in ('/outside', '../outside', 'x/../../outside', 'x//y', '.foreign'):
            with self.subTest(name=name), self.assertRaises(reader.Invalid):
                self.parse(tar_bytes([(name, b'x')]))
        for field in ('uid', 'gid'):
            info = tarfile.TarInfo('payload')
            setattr(info, field, 1)
            with self.subTest(field=field), self.assertRaises(reader.Invalid):
                self.parse(tar_bytes([(info, b'')]))
        with self.assertRaises(reader.Invalid):
            self.parse(tar_bytes([('payload', b'a'), ('payload', b'b')]))

    def test_hardlinks_devices_fifo_and_sparse_are_refused(self):
        for kind in (tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE, tarfile.GNUTYPE_SPARSE):
            info = tarfile.TarInfo('payload')
            info.type, info.linkname = kind, 'other'
            with self.subTest(kind=kind), self.assertRaises(reader.Invalid):
                self.parse(tar_bytes([(info, b'')]))
        info = tarfile.TarInfo('payload')
        info.pax_headers = {'GNU.sparse.map': '0,0'}
        with self.assertRaisesRegex(reader.Invalid, 'sparse'):
            self.parse(tar_bytes([(info, b'')]))

    def test_symlink_escape_cycles_and_ldconfig_direct_or_alias(self):
        for target in ('/outside', '../../outside', 'payload'):
            info = tarfile.TarInfo('payload')
            info.type, info.linkname = tarfile.SYMTYPE, target
            with self.subTest(target=target), self.assertRaises(reader.Invalid):
                self.parse(tar_bytes([(info, b'')]))
        for name in reader.AUXILIARIES:
            with self.subTest(name=name), self.assertRaisesRegex(reader.Invalid, 'ldconfig'):
                self.parse(tar_bytes([(name, b'never executed')]))
        info = tarfile.TarInfo('alias')
        info.type, info.linkname = tarfile.SYMTYPE, 'usr/bin/ldconfig'
        with self.assertRaisesRegex(reader.Invalid, 'ldconfig alias'):
            self.parse(tar_bytes([(info, b'')]))

    def test_expired_and_mid_stream_deadlines_preserve_counters(self):
        with self.assertRaisesRegex(reader.Invalid, 'deadline'):
            self.parse(limits=replace(self.limits, deadline=time.monotonic() - 1))
        accounting, calls = {'bytes': 0, 'nodes': 0}, 0
        self.path.write_bytes(compress(tar_bytes(), 'gzip'))

        def clock():
            nonlocal calls
            calls += 1
            return 0 if calls < 8 else 101

        with mock.patch.object(reader.time, 'monotonic', clock), self.assertRaisesRegex(reader.Invalid, 'deadline'):
            reader.archive_payload(self.path, replace(self.limits, deadline=100), accounting)
        self.assertEqual(accounting, {'bytes': 0, 'nodes': 0})

    def test_regular_input_identity_and_hardlink_symlink_refusal(self):
        self.parse()
        link = self.path.with_name('hardlink')
        link.hardlink_to(self.path)
        with self.assertRaises(reader.Invalid):
            reader.archive_payload(self.path, self.limits)
        link.unlink()
        link.symlink_to(self.path)
        with self.assertRaises(OSError):
            reader.archive_payload(link, self.limits)

    def test_peak_python_memory_does_not_grow_with_decoded_payload(self):
        raw = tar_bytes([('payload', b'x' * 12 * 1024**2)])
        self.path.write_bytes(compress(raw, 'gzip'))
        del raw
        tracemalloc.start()
        try:
            rows = reader.archive_payload(self.path, self.limits)
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertEqual(rows['payload']['bytes'], 12 * 1024**2)
        self.assertLess(peak, 2 * 1024**2)

    def test_invalid_limits_and_aggregate_values_are_refused(self):
        for name in ('compressed_bytes', 'total_compressed_bytes', 'decoded_bytes', 'members', 'file_bytes', 'window_bytes'):
            with self.subTest(name=name), self.assertRaises(reader.Invalid):
                replace(self.limits, **{name: True})
        for deadline in (float('inf'), float('nan'), True):
            with self.subTest(deadline=deadline), self.assertRaises(reader.Invalid):
                replace(self.limits, deadline=deadline)
        self.parse()
        with self.assertRaises(reader.Invalid):
            reader.archive_payload(self.path, self.limits, {'bytes': -1})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, required=True)
    args, remaining = parser.parse_known_args()
    args.workspace.mkdir(mode=0o700, parents=True, exist_ok=True)
    WORKSPACE = str(args.workspace.resolve(strict=True))
    unittest.main(argv=[__file__, *remaining])

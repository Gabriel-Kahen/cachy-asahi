# SPDX-License-Identifier: MIT
import io
from pathlib import Path
import struct
import tarfile
import tempfile
import time
import unittest
import build_kernel as build


class BuildControls(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_configuration_rejects_other_granule_modules_and_missing_builtin(self):
        fragment = (build.HERE / 'kernel.fragment').read_text()
        path = self.root / '.config'
        path.write_text(fragment)
        self.assertEqual(build.config_check(path)['page_size'], 16384)
        for wrong in (fragment.replace('CONFIG_ARM64_16K_PAGES=y', 'CONFIG_ARM64_16K_PAGES=n'),
                      fragment.replace('CONFIG_MODULES=n', 'CONFIG_MODULES=y'),
                      fragment.replace('CONFIG_SERIAL_AMBA_PL011=y', 'CONFIG_SERIAL_AMBA_PL011=m'),
                      fragment + 'CONFIG_ARM64_4K_PAGES=y\n'):
            path.write_text(wrong)
            with self.assertRaises(ValueError):
                build.config_check(path)

    def test_image_header_rejects_4k_64k_big_endian_and_truncation(self):
        path = self.root / 'Image'
        for flags, good in ((4, True), (2, False), (6, False), (5, False)):
            data = bytearray(64)
            data[56:60] = b'ARM\x64'
            struct.pack_into('<Q', data, 24, flags)
            path.write_bytes(data)
            if good:
                self.assertEqual(build.image_check(path)['boot'], 'NOT RUN')
            else:
                with self.assertRaises(ValueError):
                    build.image_check(path)
        path.write_bytes(b'ARM\x64')
        with self.assertRaises(ValueError):
            build.image_check(path)

    def test_source_rejects_traversal_escape_link_and_device(self):
        for kind in ('traversal', 'link', 'device'):
            archive = self.root / (kind + '.tar.gz')
            with tarfile.open(archive, 'w:gz') as output:
                name = build.ARCHIVE_ROOT + ('/../escape' if kind == 'traversal' else '/entry')
                member = tarfile.TarInfo(name)
                if kind == 'link':
                    member.type = tarfile.SYMTYPE
                    member.linkname = '../../escape'
                elif kind == 'device':
                    member.type = tarfile.CHRTYPE
                output.addfile(member, io.BytesIO())
            destination = self.root / kind
            destination.mkdir()
            with self.assertRaises((ValueError, tarfile.FilterError)):
                build.extract(archive, destination)
        self.assertFalse((self.root / 'escape').exists())

    def test_failed_command_is_retained_with_exact_log(self):
        records = []
        with self.assertRaises(ValueError):
            build.run(['/usr/bin/false'], self.root / 'command.log', {'PATH': '/usr/bin:/bin'},
                      self.root, time.monotonic() + 5, records)
        self.assertEqual(records[0]['returncode'], 1)
        self.assertEqual(records[0]['log_sha256'], build.sha(self.root / 'command.log'))

    def test_deadline_retires_owned_process(self):
        records = []
        start = time.monotonic()
        with self.assertRaises(ValueError):
            build.run(['/usr/bin/sleep', '30'], self.root / 'timeout.log', {'PATH': '/usr/bin:/bin'},
                      self.root, time.monotonic() - 1, records)
        self.assertLess(time.monotonic() - start, 7)
        self.assertIsNotNone(records[0]['returncode'])


if __name__ == '__main__':
    unittest.main()

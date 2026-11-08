"""Hardlink target types and ordering in inert package archives."""
import io
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts/checks'))
import package_checks as checks


class PackageHardlinkTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.archive = Path(temporary.name) / 'links.pkg.tar'

    def inspect(self, target_type=tarfile.REGTYPE, *, link_first=False,
                link_target='usr/share/target', omit_target=False):
        metadata = {
            '.PKGINFO': b'pkgname = links\npkgver = 1-1\narch = any\nlicense = MIT\n',
            '.BUILDINFO': ('format = 2\npkgname = links\npkgver = 1-1\npkgarch = any\n'
                           'pkgbuild_sha256sum = ' + 'a' * 64 + '\n').encode(),
            '.MTREE': b'inert metadata fixture',
            'usr/share/real': b'payload',
        }
        with tarfile.open(self.archive, 'w') as archive:
            for name, content in metadata.items():
                member = tarfile.TarInfo(name)
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content))
            target = tarfile.TarInfo('usr/share/target')
            target.type = target_type
            if target.isfile():
                target.size = 7
            elif target.issym() or target.islnk():
                target.linkname = 'usr/share/real' if target.islnk() else 'real'
            link = tarfile.TarInfo('usr/share/copy')
            link.type = tarfile.LNKTYPE
            link.linkname = link_target
            for member in ([link, target] if link_first else [target, link]):
                if member is target and omit_target:
                    continue
                archive.addfile(member, io.BytesIO(b'payload') if member.isfile() else None)
        return checks.package(self.archive)

    def test_supported_regular_target_types_work_in_both_archive_orders(self):
        for kind in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.CONTTYPE):
            for link_first in (False, True):
                with self.subTest(kind=kind, link_first=link_first):
                    result = self.inspect(kind, link_first=link_first)
                    self.assertEqual(result['errors'], [])
                    self.assertEqual(result['status'], 'artifact-static-pass')
                    self.assertEqual(result['members']['usr/share/target']['type'], kind.decode('ascii'))

    def test_nonregular_and_missing_targets_still_fail(self):
        for kind in (tarfile.DIRTYPE, tarfile.SYMTYPE, tarfile.LNKTYPE):
            with self.subTest(kind=kind):
                result = self.inspect(kind)
                self.assertTrue(any('hardlink target' in error for error in result['errors']))
        self.assertTrue(any('hardlink target' in error
                            for error in self.inspect(omit_target=True)['errors']))

    def test_unsafe_link_targets_are_rejected(self):
        for target in ('../../outside', '/usr/share/target'):
            with self.subTest(target=target), self.assertRaises(ValueError):
                self.inspect(link_target=target)


if __name__ == '__main__':
    unittest.main()

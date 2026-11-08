"""Required package metadata must be regular files; fixtures are not MTREE audits."""
import io
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts/checks'))
import package_checks as checks


class RequiredMetadataTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.archive = Path(temporary.name) / 'fixture.pkg.tar'

    def inspect(self, changed=None, kind=tarfile.REGTYPE, omitted=None):
        contents = {
            '.PKGINFO': b'pkgname = fixture\npkgver = 1-1\narch = any\nlicense = MIT\n',
            '.BUILDINFO': ('format = 2\npkgname = fixture\npkgver = 1-1\npkgarch = any\n'
                           'pkgbuild_sha256sum = ' + 'a' * 64 + '\n').encode(),
            '.MTREE': b'inert metadata fixture',
            'usr/share/fixture/data': b'payload',
        }
        with tarfile.open(self.archive, 'w') as archive:
            for name, content in contents.items():
                if name == omitted:
                    continue
                member = tarfile.TarInfo(name)
                member.type = kind if name == changed else tarfile.REGTYPE
                if member.isfile():
                    member.size = len(content)
                    archive.addfile(member, io.BytesIO(content))
                else:
                    if member.islnk() or member.issym():
                        member.linkname = 'usr/share/fixture/data'
                    archive.addfile(member)
        return checks.package(self.archive)

    def test_required_metadata_cannot_be_a_directory_or_link(self):
        for name in ('.PKGINFO', '.BUILDINFO', '.MTREE'):
            for kind in (tarfile.DIRTYPE, tarfile.SYMTYPE, tarfile.LNKTYPE):
                with self.subTest(name=name, kind=kind):
                    result = self.inspect(name, kind)
                    self.assertEqual(result['status'], 'fail')
                    self.assertTrue(any(name in error and 'regular' in error
                                        for error in result['errors']), result['errors'])

    def test_supported_regular_tar_types_remain_allowed(self):
        for name in ('.PKGINFO', '.BUILDINFO', '.MTREE'):
            for kind in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.CONTTYPE):
                with self.subTest(name=name, kind=kind):
                    result = self.inspect(name, kind)
                    self.assertEqual(result['errors'], [])
                    self.assertEqual(result['status'], 'artifact-static-pass')

    def test_missing_metadata_still_fails(self):
        result = self.inspect(omitted='.MTREE')
        self.assertEqual(result['status'], 'fail')
        self.assertTrue(any('.MTREE' in error for error in result['errors']))


if __name__ == '__main__':
    unittest.main()

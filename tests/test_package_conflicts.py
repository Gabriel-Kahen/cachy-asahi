"""Installed-path collision checks over reports and inert package archives."""
import copy
import io
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts/checks'))
import package_checks as checks


def report(artifact, path, kind):
    return dict(artifact=artifact, members={path: dict(type=kind)})


class PackageConflictTests(unittest.TestCase):
    def test_file_directory_collisions_are_reported_in_both_orders(self):
        path = 'usr/share/collision'
        for kind in ('0', '1', '2'):
            file_report = report('file.pkg.tar', path, kind)
            directory_report = report('directory.pkg.tar', path, '5')
            for reports in ([file_report, directory_report], [directory_report, file_report]):
                with self.subTest(kind=kind, order=[r['artifact'] for r in reports]):
                    before = copy.deepcopy(reports)
                    findings = checks.conflicts(reports)
                    self.assertEqual(len(findings), 1)
                    for text in (path, 'file.pkg.tar', 'directory.pkg.tar'):
                        self.assertIn(text, findings[0])
                    self.assertEqual(reports, before)

    def test_shared_directories_and_unrelated_paths_remain_allowed(self):
        reports = [report('a', 'usr/share/shared', '5'),
                   report('b', 'usr/share/shared', '5'),
                   report('c', 'usr/share/other', '0')]
        self.assertEqual(checks.conflicts(reports), [])
        self.assertEqual(checks.conflicts([]), [])

    def test_existing_file_file_collisions_remain_reported(self):
        findings = checks.conflicts([report('a', 'usr/bin/tool', '0'),
                                     report('b', 'usr/bin/tool', '0')])
        self.assertEqual(len(findings), 1)
        self.assertIn('usr/bin/tool', findings[0])

    def test_archive_metadata_is_not_an_installed_path_conflict(self):
        for path in checks.PACKAGE_METADATA:
            with self.subTest(path=path):
                self.assertEqual(checks.conflicts([report('a', path, '0'),
                                                   report('b', path, '5')]), [])

    def test_real_archive_reports_retain_the_collision(self):
        with tempfile.TemporaryDirectory() as temporary:
            reports = []
            for name, kind in (('alpha', tarfile.REGTYPE), ('beta', tarfile.DIRTYPE)):
                path = Path(temporary) / (name + '.pkg.tar')
                metadata = {
                    '.PKGINFO': f'pkgname = {name}\npkgver = 1-1\narch = any\nlicense = MIT\n'.encode(),
                    '.BUILDINFO': (f'format = 2\npkgname = {name}\npkgver = 1-1\n'
                                   'pkgarch = any\npkgbuild_sha256sum = ' + 'a' * 64 + '\n').encode(),
                    '.MTREE': b'inert fixture',
                }
                with tarfile.open(path, 'w') as archive:
                    for key, content in metadata.items():
                        member = tarfile.TarInfo(key)
                        member.size = len(content)
                        archive.addfile(member, io.BytesIO(content))
                    member = tarfile.TarInfo('usr/share/collision')
                    member.type = kind
                    archive.addfile(member)
                result = checks.package(path)
                self.assertEqual(result['errors'], [])
                reports.append(result)
            self.assertTrue(checks.conflicts(reports))
            self.assertTrue(checks.conflicts(list(reversed(reports))))


if __name__ == '__main__':
    unittest.main()

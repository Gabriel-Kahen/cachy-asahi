# SPDX-License-Identifier: MIT
"""Inert archive/receipt checks. No Docker, pacman, or network."""
import gzip
import io
from pathlib import Path, PurePosixPath
import runpy
import tarfile
import tempfile
import unittest

verify = runpy.run_path(str(Path(__file__).with_name('verify.py')))
SETUP = verify['SETUP']
FIRST = verify['FIRST']
RECIPES = verify['RECIPES']
IMAGE = 'sha256:' + '1' * 64
EPOCH = '1795837388'


class PairTests(unittest.TestCase):
    def setUp(self):
        temp = self.enterContext(tempfile.TemporaryDirectory(prefix='first-login-native-pair-'))
        self.root = Path(temp)
        self.source = self.root / 'source'
        self.public = self.root / 'public'
        self.source.mkdir()
        self.public.mkdir()
        self.write(self.source / 'source-date-epoch', EPOCH + '\n')
        self.write(self.public / 'build-image.txt', IMAGE + '\n')
        self.base = 'bash 5.3-1\npython 3.14-1\n'
        self.with_setup = 'bash 5.3-1\ncachy-asahi-setup 0.3.1-2\npython 3.14-1\n'
        self.write(self.public / 'base-packages.txt', self.base)
        self.archives = {package: self.make_archive(package) for package in RECIPES}
        for name, container in (('lane-1', '2' * 64), ('lane-2', '3' * 64)):
            self.write_lane(name, container)

    @staticmethod
    def write(path, text):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.encode() if isinstance(text, str) else text)

    def make_archive(self, package, archive_mtime=0, change_path=None):
        version, dirname, _, _, _ = RECIPES[package]
        recipe = self.source / 'packages/tools' / dirname
        files = verify['payload'](package)
        contents = {name: (filename + '\n').encode() for name, filename in files.items()}
        pins = {}
        for name, filename in files.items():
            if filename.startswith('@'):
                pins[filename[1:]] = verify['sha'](contents[name])
            else:
                self.write(recipe / filename, contents[name])
        if package == FIRST:
            self.write(recipe / 'setup8-fixture.py', b'@setup.py\n')
        pkgbuild = b''.join(f'{digest}  {filename}\n'.encode() for filename, digest in pins.items())
        self.write(recipe / 'PKGBUILD', pkgbuild)
        dep = 'python>=3.11' if package == SETUP else 'cachy-asahi-setup>=0.3.1-2'
        self.write(recipe / '.SRCINFO', f'\tdepends = {dep}\n')
        dirs = {str(parent) for name in files for parent in PurePosixPath(name).parents} - {'.'}
        contents['.PKGINFO'] = (
            f'pkgname = {package}\npkgver = {version}\narch = any\nbuilddate = {EPOCH}\ndepend = {dep}\n'
        ).encode()
        inventory = self.base if package == SETUP else self.with_setup
        contents['.BUILDINFO'] = (
            f'pkgbuild_sha256sum = {verify["sha"](pkgbuild)}\nbuilddate = {EPOCH}\nbuildenv = check\nbuildenv = !sign\n'
            + ''.join(f'installed = {item.replace(" ", "-", 1)}-aarch64\n' for item in inventory.splitlines())
        ).encode()
        contents['.MTREE'] = gzip.compress(''.join(
            f'./{name} type=file sha256digest={verify["sha"](contents[name])}\n' for name in files
        ).encode(), mtime=0)
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w:xz', preset=0) as archive:
            for name in sorted(dirs | contents.keys()):
                row = tarfile.TarInfo(name)
                row.mtime = archive_mtime
                row.mode = 0o755 if name in dirs or name.startswith('usr/bin/') else 0o644
                if name == change_path:
                    row.type = tarfile.SYMTYPE
                    row.linkname = '/tmp/other'
                    archive.addfile(row)
                elif name in dirs:
                    row.type = tarfile.DIRTYPE
                    archive.addfile(row)
                else:
                    row.size = len(contents[name])
                    archive.addfile(row, io.BytesIO(contents[name]))
        return output.getvalue()

    def write_lane(self, name, container):
        lane = self.public / name
        self.write(lane / 'container.txt', f'{container} {IMAGE} none false\n')
        self.write(lane / 'before-setup.txt', self.base)
        self.write(lane / 'before-first-login.txt', self.with_setup)
        self.write(lane / 'runtime.txt', f'architecture=aarch64\npage_size=4096\nbuilder_uid=2000\nsource_date_epoch={EPOCH}\n')
        setup_archive = verify['archive_name'](SETUP)
        self.write(lane / 'installed-build-dependency.sha256',
                   f'{verify["sha"](self.archives[SETUP])}  /work/result/packages/{setup_archive}\n')
        self.write(lane / 'install-build-dependency.log', 'installing Setup from this lane\n')
        for package, (_, _, prefix, counts, sources) in RECIPES.items():
            self.write(lane / 'packages' / verify['archive_name'](package), self.archives[package])
            self.write(lane / f'{prefix}-source.log', '... Passed\n' * sources)
            self.write(lane / f'{prefix}-build.log', 'Checking runtime dependencies\nChecking buildtime dependencies\n'
                       + ''.join(f'Ran {count} tests in 1s\n\nOK\n' for count in counts))

    def check(self):
        return verify['check_pair'](self.public, self.source)

    def test_clean_pair(self):
        result = self.check()
        self.assertEqual(result['native_build_pair'], 'PASS')
        self.assertEqual(result['signed_installation'], 'NOT RUN')
        self.assertEqual(result['packages'][FIRST]['dependencies'], ['cachy-asahi-setup>=0.3.1-2'])

    def test_equal_payload_but_different_archive_bytes_refused(self):
        path = self.public / 'lane-2/packages' / verify['archive_name'](FIRST)
        self.write(path, self.make_archive(FIRST, archive_mtime=1))
        with self.assertRaisesRegex(ValueError, 'archive bytes differ'):
            self.check()

    def test_archive_symlink_refused(self):
        path = self.public / 'lane-1/packages' / verify['archive_name'](FIRST)
        self.write(path, self.make_archive(FIRST, change_path=f'usr/bin/{FIRST}'))
        with self.assertRaisesRegex(ValueError, 'type, owner or mode'):
            self.check()

    def test_first_login_inventory_must_contain_only_new_setup(self):
        self.write(self.public / 'lane-1/before-first-login.txt', self.base)
        with self.assertRaisesRegex(ValueError, 'Setup dependency inventory'):
            self.check()

    def test_install_receipt_must_name_same_lane_archive(self):
        self.write(self.public / 'lane-1/installed-build-dependency.sha256', '0' * 64 + '\n')
        with self.assertRaisesRegex(ValueError, 'installed Setup archive hash'):
            self.check()

    def test_dependency_bypass_refused_even_if_tests_pass(self):
        log = self.public / 'lane-1/first-login-build.log'
        self.write(log, log.read_text() + 'Skipping dependency checks\n')
        with self.assertRaisesRegex(ValueError, 'first-login checks'):
            self.check()

    def test_same_container_refused(self):
        self.write(self.public / 'lane-2/container.txt', (self.public / 'lane-1/container.txt').read_text())
        with self.assertRaisesRegex(ValueError, 'container isolation'):
            self.check()

    def test_non_4k_runtime_refused(self):
        runtime = self.public / 'lane-1/runtime.txt'
        self.write(runtime, runtime.read_text().replace('4096', '16384'))
        with self.assertRaisesRegex(ValueError, 'native runtime'):
            self.check()


if __name__ == '__main__':
    unittest.main()

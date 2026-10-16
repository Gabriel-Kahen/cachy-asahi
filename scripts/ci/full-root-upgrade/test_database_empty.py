"""Empty ALPM ownership is data; missing, changed or malformed data still refuses."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('empty_ownership_driver', HERE / 'root_upgrade.py')
driver = importlib.util.module_from_spec(spec); spec.loader.exec_module(driver)


class EmptyOwnership(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.root = Path(temp.name); self.local = self.root / driver.DB
        self.local.mkdir(parents=True); (self.local / 'ALPM_DB_VERSION').write_bytes(b'9\n')
        self.package = self.local / 'base-3-3'; self.package.mkdir()
        (self.package / 'desc').write_bytes(b'%NAME%\nbase\n\n%VERSION%\n3-3\n\n%ARCH%\nany\n\n%DEPENDS%\nglibc\n\n')
        self.files = self.package / 'files'; self.files.write_bytes(b'')

    def observation(self):
        nodes = {}
        for path in self.local.rglob('*'):
            if path.is_file():
                info = path.stat(); raw = path.read_bytes()
                nodes[path.relative_to(self.root).as_posix()] = dict(type='file', mode=info.st_mode & 0o7777,
                    uid=info.st_uid, gid=info.st_gid, bytes=len(raw), sha256=driver.sha(raw))
        return nodes

    def test_zero_byte_ownership_retains_package_and_dependencies(self):
        rows = driver.database(self.root, observed=self.observation())
        self.assertEqual(rows, [dict(name='base', version='3-3', arch='any', depend=['glibc'],
                                     provides=[], conflict=[], files=[])])

    def test_nonempty_missing_files_field_still_refuses(self):
        for raw in (b'\n', b'%BACKUP%\netc/example\tdeadbeef\n\n', b'%UNKNOWN%\nvalue\n\n'):
            with self.subTest(raw=raw):
                self.files.write_bytes(raw)
                with self.assertRaisesRegex(ValueError, 'installed ownership missing'):
                    driver.database(self.root, observed=self.observation())

    def test_missing_or_symlink_ownership_is_never_synthesized(self):
        self.files.unlink()
        with self.assertRaises(FileNotFoundError): driver.database(self.root)
        other = self.package / 'other'; other.write_bytes(b'')
        self.files.symlink_to('other')
        with self.assertRaises(OSError): driver.database(self.root)

    def test_empty_record_still_requires_exact_observation_hash_and_size(self):
        nodes = self.observation(); name = self.files.relative_to(self.root).as_posix()
        for changes in ({'sha256': '0'*64}, {'bytes': 1}):
            with self.subTest(changes=changes):
                bad = {k: dict(v) for k,v in nodes.items()}; bad[name].update(changes)
                with self.assertRaisesRegex(ValueError, 'differs from root observation'):
                    driver.database(self.root, observed=bad)

    def test_empty_and_nonempty_packages_are_both_retained_and_paths_validated(self):
        second = self.local / 'payload-fixture-1-1'; second.mkdir()
        (second / 'desc').write_bytes(b'%NAME%\npayload-fixture\n\n%VERSION%\n1-1\n\n%ARCH%\nany\n\n')
        (second / 'files').write_bytes(b'%FILES%\nusr/\nusr/share/inert\n\n')
        rows = driver.database(self.root, observed=self.observation())
        self.assertEqual([(r['name'], r['files']) for r in rows], [('base', []), ('payload-fixture', ['usr/share/inert'])])
        (second / 'files').write_bytes(b'%FILES%\n../escape\n\n')
        with self.assertRaises(ValueError): driver.database(self.root, observed=self.observation())


if __name__ == '__main__': unittest.main()

# SPDX-License-Identifier: MIT
import copy
import importlib.util
import json
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('archive_review', HERE / 'inspect_archive.py')
review = importlib.util.module_from_spec(spec); spec.loader.exec_module(review)


class ArchiveControls(unittest.TestCase):
    def setUp(self):
        self.pins = json.loads((HERE / 'inputs.json').read_text())
        self.rows = {name: {'type': 'file', 'mode': 0o644, 'bytes': 123} for name in (
            'usr/bin/python3.14', 'usr/include/python3.14/Python.h', 'usr/lib/libpython3.14.so.1.0',
            'usr/lib/python3.14/EXTERNALLY-MANAGED',
            'usr/lib/python3.14/lib-dynload/_tkinter.cpython-314-x86_64-linux-gnu.so',
            'usr/lib/pkgconfig/python-3.14.pc', 'usr/lib/pkgconfig/python-3.14-embed.pc')}
        for name, source in {'usr/share/licenses/python/CPython-LICENSE': 'CPython-LICENSE',
                'usr/share/licenses/python/packaging-MIT': 'LICENSE',
                'usr/share/doc/python/source-provenance.json': 'source-provenance.json',
                'usr/lib/python3.14/EXTERNALLY-MANAGED': 'EXTERNALLY-MANAGED'}.items():
            self.rows[name] = {'type': 'file', 'mode': 0o644, 'bytes': 123,
                               'sha256': self.pins['files'][source]['sha256']}
        for name, target in {'python': 'python3', 'python-config': 'python3-config',
                             'idle': 'idle3', 'pydoc': 'pydoc3'}.items():
            self.rows['usr/bin/' + name] = {'type': 'symlink', 'target': target, 'mode': 0o777}

    def test_matching_layout(self):
        self.assertEqual(review.validate_rows(self.rows, self.pins)['ordinary_files'], 10)

    def test_omitted_tk(self):
        del self.rows['usr/lib/python3.14/lib-dynload/_tkinter.cpython-314-x86_64-linux-gnu.so']
        with self.assertRaisesRegex(ValueError, 'missing'): review.validate_rows(self.rows, self.pins)

    def test_changed_notice(self):
        self.rows['usr/share/licenses/python/CPython-LICENSE']['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'checksum'): review.validate_rows(self.rows, self.pins)

    def test_wrong_frontend(self):
        self.rows['usr/bin/python']['target'] = '/usr/bin/python3'
        with self.assertRaisesRegex(ValueError, 'frontend'): review.validate_rows(self.rows, self.pins)

    def test_privileged_file(self):
        self.rows['usr/bin/python3.14']['mode'] = 0o4755
        with self.assertRaisesRegex(ValueError, 'privileged'): review.validate_rows(self.rows, self.pins)

    def test_hooks_services_pip_and_fixtures(self):
        for path in ('usr/share/libalpm/hooks/a.hook', 'usr/lib/systemd/system/a.service',
                     'usr/bin/pip3', 'usr/lib/python3.14/test/test_tk.py',
                     'usr/lib/python3.14/idlelib/idle_test/test.py'):
            rows = copy.deepcopy(self.rows); rows[path] = {'type': 'file', 'mode': 0o644}
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, 'unexpected'):
                review.validate_rows(rows, self.pins)

    def test_outside_usr(self):
        self.rows['etc/unbound'] = {'type': 'file', 'mode': 0o644}
        with self.assertRaisesRegex(ValueError, 'outside'): review.validate_rows(self.rows, self.pins)


if __name__ == '__main__':
    unittest.main()

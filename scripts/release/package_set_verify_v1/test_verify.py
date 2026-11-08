# SPDX-License-Identifier: MIT
"""Focused selection/snapshot/set integration controls; archives are synthetic."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tarfile
import unittest
from unittest.mock import patch

import verify as v


class VerifyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='package-set-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.selected = self.root / 'release.json'
        self.rows = []

    def archive(self, name='demo', payload=None):
        filename = name + '-1-1-any.pkg.tar'
        metadata = (f'pkgname = {name}\npkgver = 1-1\narch = any\nlicense = MIT\n').encode()
        build = (f'format = 2\npkgname = {name}\npkgver = 1-1\npkgarch = any\n'
                 f'pkgbuild_sha256sum = {"0" * 64}\n').encode()
        path = self.root / filename
        with tarfile.open(path, 'w') as archive:
            for key, body in {'.PKGINFO': metadata, '.BUILDINFO': build, '.MTREE': b'fixture',
                              **(payload if payload is not None else {'usr/bin/' + name: b'demo'})}.items():
                member = tarfile.TarInfo(key)
                member.mode = 0o755 if body is None else 0o644
                member.type = tarfile.DIRTYPE if body is None else tarfile.REGTYPE
                member.size = 0 if body is None else len(body)
                archive.addfile(member, None if body is None else io.BytesIO(body))
        row = dict(name=name, version='1-1', arch='any', filename=filename,
                   sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        self.rows.append(row)
        return path

    def select(self):
        self.selected.write_text(json.dumps(dict(schema_version=1, release_id='synthetic-test', packages=self.rows)))
        return hashlib.sha256(self.selected.read_bytes()).hexdigest()

    def run_cli(self, pin=None):
        pin = self.select() if pin is None else pin
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = v.main(['--selection', str(self.selected), '--selection-sha256', pin,
                           '--archive-root', str(self.root)])
        return code, out.getvalue(), err.getvalue()

    def test_selected_set_and_current_validator_identity(self):
        self.archive('second'); self.archive('first')
        code, out, err = self.run_cli()
        report = json.loads(out)
        self.assertEqual((code, err, report['status']), (0, '', 'STATIC_PASS'))
        self.assertEqual([p['name'] for p in report['packages']], ['first', 'second'])
        self.assertEqual(report['validator_sha256'], hashlib.sha256(v.VALIDATOR.read_bytes()).hexdigest())
        self.assertIn('NOT_ESTABLISHED', report['limit'])

    def test_selection_pin_before_inspection(self):
        self.archive(); self.select()
        code, out, err = self.run_cli('0' * 64)
        self.assertEqual((code, out), (2, ''))
        self.assertIn('selection SHA-256 mismatch', err)

    def test_archive_pin_refuses_without_partial_report(self):
        path = self.archive(); path.write_bytes(b'substituted')
        code, out, err = self.run_cli()
        self.assertEqual((code, out), (2, ''))
        self.assertIn('archive SHA-256 mismatch', err)

    def test_each_selected_identity_field_is_checked(self):
        self.archive()
        for field, wrong in (('name', 'other'), ('version', '2-1'), ('arch', 'aarch64')):
            original = self.rows[0][field]; self.rows[0][field] = wrong
            code, out, err = self.run_cli()
            self.assertEqual((code, err), (1, ''))
            self.assertIn('selected package ' + field, str(json.loads(out)['packages'][0]['errors']))
            self.rows[0][field] = original

    def test_set_conflicts_include_ancestor_file(self):
        self.archive('parent', {'usr/share/demo': b'file'})
        self.archive('child', {'usr/share/demo/child': b'file'})
        code, out, err = self.run_cli()
        self.assertEqual((code, err), (1, ''))
        self.assertIn('is a child of', str(json.loads(out)['errors']))

    def test_shared_directories_and_unselected_files(self):
        self.archive('one', {'usr/share/demo': None, 'usr/share/demo/one': b'one'})
        self.archive('two', {'usr/share/demo': None, 'usr/share/demo/two': b'two'})
        (self.root / 'unselected.pkg.tar').write_bytes(b'not selected')
        self.assertEqual(self.run_cli()[0], 0)

    def test_review_is_not_success(self):
        self.archive(payload={'etc/demo.conf': b'config'})
        code, out, err = self.run_cli()
        self.assertEqual((code, err, json.loads(out)['status']), (1, '', 'REVIEW_REQUIRED'))
        self.assertTrue(json.loads(out)['packages'][0]['review'])

    def test_inspector_errors_are_not_success(self):
        self.archive(payload={'boot/forbidden': b'platform'})
        code, out, err = self.run_cli()
        self.assertEqual((code, err, json.loads(out)['status']), (1, '', 'FAIL'))
        self.assertIn('protected platform path', str(json.loads(out)['packages'][0]['errors']))

    def test_invalid_selection_namespace(self):
        self.archive()
        for filename in ('../demo.pkg.tar', '/demo.pkg.tar', 'nested/demo.pkg.tar'):
            self.rows[0]['filename'] = filename
            code, out, err = self.run_cli()
            self.assertEqual((code, out), (2, ''))
            self.assertIn('basename', err)

    def test_duplicate_selection_and_missing_archive(self):
        path = self.archive(); self.rows.append(dict(self.rows[0]))
        self.assertIn('duplicate package', self.run_cli()[2])
        self.rows.pop(); path.unlink()
        self.assertEqual(self.run_cli()[:2], (2, ''))

    def test_symlink_and_fifo_refuse(self):
        import os
        path = self.archive(); path.rename(self.root / 'real')
        path.symlink_to('real')
        self.assertIn('symlink', self.run_cli()[2])
        path.unlink(); os.mkfifo(path)
        self.assertIn('regular input', self.run_cli()[2])

    def test_snapshot_prevents_second_path_read(self):
        path = self.archive(); pin = self.select()
        original = v.copy_input

        def substitute(source, output, maximum):
            result = original(source, output, maximum)
            if source == path:
                path.write_bytes(b'replaced after snapshot')
            return result

        with patch.object(v, 'copy_input', side_effect=substitute):
            self.assertEqual(v.verify(self.selected, pin, self.root)['status'], 'STATIC_PASS')
        self.assertEqual(path.read_bytes(), b'replaced after snapshot')

    def test_input_bounds_and_duplicate_json_keys(self):
        self.archive()
        with patch.object(v, 'MAX_ARCHIVE', 1):
            self.assertIn('byte limit', self.run_cli()[2])
        with patch.object(v, 'MAX_SET', 1):
            self.assertIn('byte limit', self.run_cli()[2])
        self.selected.write_bytes(b'{"schema_version":1,"schema_version":1}')
        pin = hashlib.sha256(self.selected.read_bytes()).hexdigest()
        self.assertIn('duplicate JSON key', self.run_cli(pin)[2])

    def test_compressed_archive_formats(self):
        import gzip
        import lzma
        path = self.archive()
        raw = path.read_bytes()
        for suffix, compress in (('.gz', gzip.compress), ('.xz', lzma.compress)):
            compressed = path.with_name(path.name + suffix)
            compressed.write_bytes(compress(raw))
            self.rows[0].update(filename=compressed.name,
                                sha256=hashlib.sha256(compressed.read_bytes()).hexdigest())
            self.assertEqual(self.run_cli()[0], 0)

    @unittest.skipUnless(shutil.which('zstd'), 'existing validator zstd dependency unavailable')
    def test_zstd_from_separate_cli_process(self):
        path = self.archive()
        raw = subprocess.run(['zstd', '-q', '-c'], input=path.read_bytes(),
                             capture_output=True, check=True).stdout
        compressed = path.with_name(path.name + '.zst'); compressed.write_bytes(raw)
        self.rows[0].update(filename=compressed.name, sha256=hashlib.sha256(raw).hexdigest())
        pin = self.select()
        result = subprocess.run([sys.executable, '-B', str(Path(v.__file__).resolve()),
                                 '--selection', str(self.selected), '--selection-sha256', pin,
                                 '--archive-root', str(self.root)], cwd='/',
                                capture_output=True, text=True, timeout=15)
        self.assertEqual((result.returncode, result.stderr), (0, ''))
        self.assertEqual(json.loads(result.stdout)['status'], 'STATIC_PASS')

    def test_pinned_malformed_archive_refuses(self):
        path = self.archive(); path.write_bytes(b'not an archive')
        self.rows[0]['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        code, out, err = self.run_cli()
        self.assertEqual((code, out, json.loads(err)['status']), (2, '', 'REFUSED'))

    def test_excessive_json_nesting_refuses(self):
        self.selected.write_text('[' * 2000 + '0' + ']' * 2000)
        pin = hashlib.sha256(self.selected.read_bytes()).hexdigest()
        code, out, err = self.run_cli(pin)
        self.assertEqual((code, out, json.loads(err)['status']), (2, '', 'REFUSED'))


if __name__ == '__main__':
    unittest.main()

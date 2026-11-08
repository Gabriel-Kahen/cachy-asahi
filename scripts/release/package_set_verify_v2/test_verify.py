# SPDX-License-Identifier: MIT
"""Bounded full-set controls; every generated package archive is synthetic."""
import contextlib
import gzip
import hashlib
import importlib.util
import io
import json
import lzma
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import weakref


HERE = Path(__file__).resolve().parent
DATA = HERE / 'testdata'


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


v = module('package_set_verify_v2_controls', HERE / 'verify.py')
v1 = module('package_set_verify_v1_reference', HERE.parent / 'package_set_verify_v1/verify.py')
checks = module('package_set_current_api_reference', v.VALIDATOR)


class InspectedReport(dict):
    """Weak references expose accidentally retained per-archive report objects."""


class VerifyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='package-set-v2-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.selected = self.root / 'release.json'
        self.rows = []

    def archive(self, name='demo', version='1-1', arch='any', payload=None, compress=None):
        filename = f'p{len(self.rows):04d}.pkg.tar'
        metadata = f'pkgname = {name}\npkgver = {version}\narch = {arch}\nlicense = MIT\n'.encode()
        build = (f'format = 2\npkgname = {name}\npkgver = {version}\npkgarch = {arch}\n'
                 f'pkgbuild_sha256sum = {"0" * 64}\n').encode()
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w') as archive:
            for key, body in {'.PKGINFO': metadata, '.BUILDINFO': build, '.MTREE': b'fixture',
                              **({'usr/share/fixture/' + name: b'inert'} if payload is None else payload)}.items():
                member = tarfile.TarInfo(key)
                member.mode = 0o755 if body is None else 0o644
                member.type = tarfile.DIRTYPE if body is None else tarfile.REGTYPE
                member.size = 0 if body is None else len(body)
                archive.addfile(member, None if body is None else io.BytesIO(body))
        raw = stream.getvalue()
        if compress == 'gz':
            filename += '.gz'; raw = gzip.compress(raw, mtime=0)
        elif compress == 'xz':
            filename += '.xz'; raw = lzma.compress(raw)
        path = self.root / filename
        path.write_bytes(raw)
        self.rows.append(dict(name=name, version=version, arch=arch, filename=filename,
                              sha256=hashlib.sha256(raw).hexdigest()))
        return path

    def select(self):
        raw = json.dumps(dict(schema_version=1, release_id='synthetic-v2-controls',
                              packages=self.rows)).encode()
        self.selected.write_bytes(raw)
        return hashlib.sha256(raw).hexdigest()

    def run_cli(self, *options, pin=None):
        pin = self.select() if pin is None else pin
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = v.main(['--selection', str(self.selected), '--selection-sha256', pin,
                           '--archive-root', str(self.root), *map(str, options)])
        return code, out.getvalue(), err.getvalue()

    def refused(self, *options, pin=None):
        code, out, err = self.run_cli(*options, pin=pin)
        self.assertEqual((code, out), (2, ''))
        self.assertEqual(json.loads(err)['status'], 'REFUSED')
        return err

    def track_inspections(self):
        original = v.inspect_snapshot
        snapshots, reports = [], []

        def inspect(snapshot, pin, **kwargs):
            snapshot = Path(snapshot)
            self.assertTrue(snapshot.is_file())
            self.assertTrue(all(reference() is None for reference in reports),
                            'previous per-archive report retained into the next inspection')
            self.assertTrue(all(not p.exists() for p in snapshots if p != snapshot),
                            'previous archive snapshot survived into the next inspection')
            self.assertEqual(list(snapshot.parent.glob('*.pkg.tar*')), [snapshot],
                             'more than one archive snapshot retained')
            snapshots.append(snapshot)
            report = InspectedReport(original(snapshot, pin, **kwargs))
            reports.append(weakref.ref(report))
            return report

        return inspect, snapshots, reports

    def test_full_actual607_identities_real_workers_late_collisions_and_cleanup(self):
        raw = (DATA / 'current607.lock').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),
                         'be35402204ba5c03d78279722afa83047c9575d2da70fb5c4064f46ed15954c5')
        identities = [line.split() for line in raw.decode().splitlines()]
        self.assertEqual(len(identities), 607)
        self.assertEqual(len({name for name, _ in identities}), 607)
        for i, (name, version) in enumerate(identities):
            payload = {'usr/share/fixture/' + name: b'inert'}
            if i in (0, 606):
                payload['usr/share/full607/same-path'] = b'conflict'
            if i == 1:
                payload['usr/share/full607/ancestor'] = b'file'
            if i == 605:
                payload['usr/share/full607/ancestor/child'] = b'child'
            if i in (2, 604):
                payload.update({'usr/share/full607/shared': None,
                                'usr/share/full607/shared/' + name: b'owned'})
            self.archive(name, version, 'any', payload)
        tracked, snapshots, reports = self.track_inspections()
        with patch.object(v, 'inspect_snapshot', side_effect=tracked):
            code, out, err = self.run_cli()
        result = json.loads(out)
        self.assertEqual((code, err, result['status']), (1, '', 'FAIL'))
        self.assertEqual(len(result['packages']), 607)
        self.assertEqual([(r['name'], r['version']) for r in result['packages']],
                         [tuple(row) for row in identities])
        self.assertTrue(all(row['arch'] == 'any' for row in result['packages']))
        failures = {r['name'] for r in result['packages'] if r['errors']}
        self.assertEqual(failures, {'mesa', 'asahi-audio', 'speakersafetyd', 'alsa-ucm-conf-asahi'})
        for row in result['packages']:
            if row['name'] in failures:
                self.assertIn('protected platform package name: ' + row['name'], row['errors'])
        self.assertTrue(any('usr/share/full607/same-path:' in e and 'conflicts with' in e
                            for e in result['errors']))
        self.assertTrue(any('is a child of usr/share/full607/ancestor' in e for e in result['errors']))
        self.assertFalse(any('usr/share/full607/shared:' in e for e in result['errors']))
        self.assertEqual(len(snapshots), 607)
        self.assertTrue(all(not p.exists() for p in snapshots))
        self.assertTrue(all(reference() is None for reference in reports))
        self.assertEqual(result['usage']['archive_bytes'], sum(p.stat().st_size for p in
                         (self.root / row['filename'] for row in self.rows)))
        self.assertEqual(result['usage']['peak_snapshot_bytes'], max(
                         (self.root / row['filename']).stat().st_size for row in self.rows))
        self.assertEqual(result['validator_sha256'], hashlib.sha256(v.VALIDATOR.read_bytes()).hexdigest())

    def test_shared_directories_are_static_pass(self):
        self.archive('one', payload={'usr/share/shared': None, 'usr/share/shared/one': b'one'})
        self.archive('two', payload={'usr/share/shared': None, 'usr/share/shared/two': b'two'})
        code, out, err = self.run_cli()
        self.assertEqual((code, err, json.loads(out)['status']), (0, '', 'STATIC_PASS'))
        self.assertEqual(json.loads(out)['errors'], [])

    def test_observed_platform_metadata_remains_separate_and_protected(self):
        fixture = json.loads((DATA / 'platform-identities.json').read_bytes())
        self.assertEqual(fixture['source_records'], 261)
        self.assertFalse(fixture['dependency_transaction_accepted'])
        self.assertFalse(fixture['hardware_accepted'])
        for row in fixture['packages']:
            self.archive(row['name'], row['version'], row['arch'],
                         {'boot/synthetic/' + row['name']: b'inert'})
        code, out, err = self.run_cli()
        result = json.loads(out)
        self.assertEqual((code, err, result['status']), (1, '', 'FAIL'))
        self.assertEqual(len(result['packages']), 6)
        for row in result['packages']:
            self.assertTrue(any('protected platform path' in e for e in row['errors']))
        alias = next(row for row in result['packages'] if row['name'] == 'uboot-asahi')
        self.assertFalse(any('protected platform package name' in e for e in alias['errors']))

    def test_current_api_errors_review_and_limit_match_v1(self):
        self.archive('review', payload={'etc/demo.conf': b'config'})
        self.archive('protected', payload={'boot/synthetic': b'inert'})
        pin = self.select()
        old, new = v1.verify(self.selected, pin, self.root), v.verify(self.selected, pin, self.root)
        self.assertEqual(new['status'], old['status'])
        self.assertEqual(new['limit'], old['limit'])
        self.assertEqual(new['errors'], old['errors'])
        self.assertEqual([(p['name'], p['errors'], p['review']) for p in new['packages']],
                         [(p['name'], p['errors'], p['review']) for p in old['packages']])

    def test_review_required_stays_exit1(self):
        self.archive(payload={'etc/demo.conf': b'config'})
        code, out, err = self.run_cli()
        self.assertEqual((code, err, json.loads(out)['status']), (1, '', 'REVIEW_REQUIRED'))

    def test_aggregate_compressed_bytes_refuse_without_partial_stdout(self):
        a = self.archive('one', compress='gz'); b = self.archive('two', compress='xz')
        tracked, snapshots, _ = self.track_inspections()
        with patch.object(v, 'inspect_snapshot', side_effect=tracked):
            self.assertIn('byte', self.refused('--max-total-bytes', a.stat().st_size + b.stat().st_size - 1))
        self.assertEqual(len(snapshots), 1)
        self.assertFalse(snapshots[0].exists())

    def test_aggregate_members_refuse_and_cleanup(self):
        self.archive('one'); self.archive('two')
        tracked, snapshots, _ = self.track_inspections()
        with patch.object(v, 'inspect_snapshot', side_effect=tracked):
            self.assertIn('member budget', self.refused('--max-members', 7))
        self.assertEqual(len(snapshots), 2)
        self.assertTrue(all(not p.exists() for p in snapshots))

    def test_spool_budget_refuses_and_cleanup(self):
        self.archive()
        tracked, snapshots, _ = self.track_inspections()
        with patch.object(v, 'inspect_snapshot', side_effect=tracked):
            self.assertIn('spool byte budget', self.refused('--max-spool-bytes', 1))
        self.assertEqual(len(snapshots), 1)
        self.assertFalse(snapshots[0].exists())

    def test_worker_report_output_bound_refuses(self):
        self.archive()
        with patch.object(v, 'MAX_WORKER_OUTPUT', 1):
            self.assertIn('worker report byte budget', self.refused())

    def test_aggregate_summary_bound_refuses_without_large_fixture(self):
        self.archive()

        def current_projected(snapshot, pin, **kwargs):
            self.assertEqual(pin, hashlib.sha256(v.VALIDATOR.read_bytes()).hexdigest())
            report = checks.package(snapshot)
            report['members'] = {name: {'type': row['type']} for name, row in report['members'].items()}
            return report

        with patch.object(v, 'inspect_snapshot', side_effect=current_projected), \
             patch.object(v, 'MAX_WORKER_OUTPUT', 1):
            self.assertIn('summary byte budget', self.refused())

    def test_compact_and_pretty_final_report_bounds_refuse(self):
        self.archive(); pin = self.select()
        baseline = v.verify(self.selected, pin, self.root)
        compact = len(v.encoded(baseline))
        pretty = len(json.dumps(baseline, sort_keys=True, indent=2).encode())
        self.assertGreater(pretty, compact)
        for maximum in (compact - 1, (compact + pretty) // 2):
            with self.subTest(maximum=maximum), patch.object(v, 'MAX_REPORT', maximum):
                self.assertIn('final report byte budget', self.refused(pin=pin))

    def test_budgets_are_lower_only(self):
        self.archive(); pin = self.select()
        for key, maximum in [('max_total_bytes', v.MAX_SET), ('max_members', v.MAX_MEMBERS),
                             ('max_spool_bytes', v.MAX_SPOOL)]:
            for invalid in (0, -1, True, maximum + 1):
                with self.subTest(key=key, invalid=invalid), \
                     patch.object(v, 'inspect_snapshot', side_effect=AssertionError('inspection before budget validation')):
                    with self.assertRaisesRegex(ValueError, 'lower-only'):
                        v.verify(self.selected, pin, self.root, **{key: invalid})

    def test_cap1024_refuses1025_before_inspection(self):
        self.rows = [dict(name='synthetic-' + str(i), version='1-1', arch='any',
                          filename=f'p{i:04d}.pkg.tar', sha256='0' * 64) for i in range(1025)]
        with patch.object(v, 'inspect_snapshot', side_effect=AssertionError('inspection before selection validation')):
            self.assertIn('1024', self.refused())

    def test_selection_pin_and_archive_pin_precede_workers(self):
        path = self.archive(); self.select()
        with patch.object(v, 'inspect_snapshot', side_effect=AssertionError('worker before selection pin')):
            self.assertIn('selection SHA-256 mismatch', self.refused(pin='0' * 64))
        path.write_bytes(b'substituted')
        with patch.object(v, 'inspect_snapshot', side_effect=AssertionError('worker before archive pin')):
            self.assertIn('archive SHA-256 mismatch', self.refused())

    def test_identity_namespace_duplicate_and_missing_refusals(self):
        path = self.archive()
        for field, wrong in [('name', 'other'), ('version', '2-1'), ('arch', 'aarch64')]:
            original = self.rows[0][field]; self.rows[0][field] = wrong
            code, out, err = self.run_cli()
            self.assertEqual((code, err), (1, ''))
            self.assertIn('selected package ' + field, str(json.loads(out)['packages'][0]['errors']))
            self.rows[0][field] = original
        original = self.rows[0]['filename']
        for bad in ('../a.pkg.tar', '/a.pkg.tar', 'nested/a.pkg.tar'):
            self.rows[0]['filename'] = bad
            self.assertIn('basename', self.refused())
        self.rows[0]['filename'] = original
        self.rows.append(dict(self.rows[0])); self.assertIn('duplicate package', self.refused())
        self.rows.pop(); path.unlink(); self.refused()

    def test_symlink_and_fifo_refuse_without_blocking(self):
        path = self.archive(); path.rename(self.root / 'real')
        path.symlink_to('real'); self.assertIn('symlink', self.refused())
        path.unlink(); os.mkfifo(path); self.assertIn('regular input', self.refused())

    def test_snapshot_is_inspected_after_original_path_replacement(self):
        path = self.archive(); pin = self.select(); original = v.copy_input

        def substitute(source, output, maximum):
            result = original(source, output, maximum)
            if source == path:
                path.write_bytes(b'replaced after snapshot')
            return result

        with patch.object(v, 'copy_input', side_effect=substitute):
            self.assertEqual(v.verify(self.selected, pin, self.root)['status'], 'STATIC_PASS')
        self.assertEqual(path.read_bytes(), b'replaced after snapshot')

    def test_worker_failure_timeout_and_malformed_archive_cleanup(self):
        path = self.archive()
        for error in (ValueError('bounded inspect worker refused'),
                      subprocess.TimeoutExpired(['worker'], 90)):
            seen = []

            def fail(snapshot, pin, **kwargs):
                seen.append(Path(snapshot)); raise error

            with self.subTest(error=type(error).__name__), patch.object(v, 'inspect_snapshot', side_effect=fail):
                self.refused()
            self.assertEqual(len(seen), 1)
            self.assertFalse(seen[0].exists())
        path.write_bytes(b'not an archive')
        self.rows[0]['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        self.assertIn('worker refused', self.refused())

    def test_worker_rejects_wrong_validator_pin(self):
        path = self.archive()
        with self.assertRaisesRegex(ValueError, 'validator SHA-256 changed'):
            v.inspect_snapshot(path, '0' * 64)

    def test_selection_size_and_duplicate_json_key_bounds(self):
        self.archive()
        with patch.object(v, 'MAX_SELECTION', 1):
            self.assertIn('byte limit', self.refused())
        self.selected.write_bytes(b'{"schema_version":1,"schema_version":1}')
        self.assertIn('duplicate JSON key', self.refused(pin=hashlib.sha256(self.selected.read_bytes()).hexdigest()))

    def test_gzip_xz_archives_and_unselected_inputs(self):
        self.archive('gzip-fixture', compress='gz'); self.archive('xz-fixture', compress='xz')
        (self.root / 'unselected.pkg.tar').write_bytes(b'not selected')
        self.assertEqual(self.run_cli()[0], 0)

    @unittest.skipUnless(shutil.which('zstd'), 'existing validator zstd dependency unavailable')
    def test_zstd_via_separate_cli_process(self):
        path = self.archive()
        raw = subprocess.run(['zstd', '-q', '-c'], input=path.read_bytes(), capture_output=True, check=True).stdout
        compressed = path.with_name(path.name + '.zst'); compressed.write_bytes(raw)
        self.rows[0].update(filename=compressed.name, sha256=hashlib.sha256(raw).hexdigest())
        pin = self.select()
        result = subprocess.run([sys.executable, '-I', '-B', str(HERE / 'verify.py'),
                                 '--selection', str(self.selected), '--selection-sha256', pin,
                                 '--archive-root', str(self.root)], cwd='/', capture_output=True,
                                text=True, timeout=20)
        self.assertEqual((result.returncode, result.stderr), (0, ''))
        self.assertEqual(json.loads(result.stdout)['status'], 'STATIC_PASS')


if __name__ == '__main__':
    unittest.main()

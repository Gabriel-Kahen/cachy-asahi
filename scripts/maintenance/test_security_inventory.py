# SPDX-License-Identifier: MIT
import copy
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import security_inventory as M

HERE = Path(__file__).resolve().parent


def package(name='demo', version='1:2.0-3', arch='aarch64'):
    return dict(name=name, version=version, arch=arch, provides=['demo-abi=2', 'Demo'],
                depend=[], conflict=[], files=['usr/bin/' + name])


def envelope(*rows):
    return dict(schema_version=1, kind='complete-installed-inventory', target_arch='aarch64',
                snapshot_id='operator-retained-snapshot', packages=list(rows or [package()]))


def observed():
    value = envelope()
    inputs = {'local/ALPM_DB_VERSION': M.a.pin(b'9\n'),
              'local/demo-1:2.0-3/desc': M.a.pin(b'retained desc DATA'),
              'local/demo-1:2.0-3/files': M.a.pin(b'retained files DATA')}
    digest = M.v.digest(M.v.encoded(inputs))
    value['snapshot_id'] = 'alpm-local-db-' + digest
    value['observation'] = dict(qualification=M.v.QUALIFICATION, dbpath='/retained/example/pacman',
        format='ALPM_LOCAL_DB_9', inputs=inputs, database_sha256=digest,
        packages_metadata_sha256=M.v.digest(M.v.encoded(value['packages'])),
        payload_verified=False, hardware_verified=False,
        consistency='TWO_MATCHING_READS_NO_LOCK_NO_DETECTED_DRIFT')
    return value


class Controls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ('collect', 'publish', 'scan', '_collect_encoded'):
            guard = patch.object(M.v, name, side_effect=AssertionError('no database observation'))
            guard.start(); self.addCleanup(guard.stop)
        guard = patch.object(socket, 'socket', side_effect=AssertionError('no network'))
        guard.start(); self.addCleanup(guard.stop)

    def save(self, value):
        raw = M.encoded(value); path = self.root / 'retained.json'; path.write_bytes(raw)
        return path, raw

    def convert(self, value):
        path, raw = self.save(value); out = self.root / 'converted'
        result = M.run(path, M.a.pin(raw)['sha256'], out)
        return path, raw, out, result

    def test_declared_identity_sorted_exact_and_private_source_immutable(self):
        value = envelope(package('zeta'), package('alpha', '7.1-2', 'any'))
        value['packages'][0].update(pkgbase='different-source', origin='retained operator label')
        path, raw, out, result = self.convert(value)
        self.assertEqual(path.read_bytes(), raw); self.assertEqual((out/'source.json').read_bytes(), raw)
        rows = json.loads((out/'inventory.json').read_bytes()); M.a.inventory(rows)
        expected = [{k: row[k] for k in ('name', 'version', 'arch', 'provides', 'pkgbase', 'origin') if k in row}
                    for row in sorted(value['packages'], key=lambda row: row['name'])]
        self.assertEqual(rows, expected)
        receipt = json.loads((out/'receipt.json').read_bytes())
        self.assertEqual(receipt['source'], dict(file='source.json', **M.a.pin(raw)))
        self.assertEqual(receipt['source_qualification'], M.DECLARED)
        self.assertEqual(receipt['observation_check'], 'NOT_OBSERVED')
        self.assertEqual(result['freshness'], 'NOT_REOBSERVED_SOURCE_MAY_BE_STALE')
        self.assertEqual(result['arm_security_status'], 'UNKNOWN')
        self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o700)
        self.assertTrue(all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in out.iterdir()))

    def test_observed_qualifier_and_internal_provenance_preserved_not_reobserved(self):
        value = observed(); _, _, out, result = self.convert(value)
        receipt = json.loads((out/'receipt.json').read_bytes())
        self.assertEqual(result['source_qualification'], M.v.QUALIFICATION)
        self.assertEqual(receipt['observation'], value['observation'])
        self.assertEqual(receipt['snapshot_id'], value['snapshot_id'])
        self.assertEqual(receipt['observation_check'], 'INTERNAL_HASH_CONSISTENCY_ONLY')
        self.assertIs(receipt['payload_verified'], False); self.assertIs(receipt['hardware_verified'], False)

    def test_wrong_pin_schema_arch_duplicate_missing_identity_refuse_before_output(self):
        path, raw = self.save(envelope())
        with self.assertRaisesRegex(ValueError, 'checksum'): M.run(path, '0'*64, self.root/'no-output')
        self.assertFalse((self.root/'no-output').exists())
        invalid = [dict(envelope(), schema_version=True), dict(envelope(), schema_version=2),
                   dict(envelope(), target_arch='x86_64'), dict(envelope(), extra=True),
                   envelope(package(), package()), envelope(package(version='2.0')),
                   envelope(package(arch='x86_64')), dict(envelope(), snapshot_id='')]
        missing = envelope(); del missing['packages'][0]['provides']; invalid.append(missing)
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError): M.project(value)

    def test_observation_hash_and_record_drift_are_not_accepted(self):
        original = observed()
        def missing_record(value):
            observation = value['observation']
            del observation['inputs']['local/demo-1:2.0-3/desc']
            observation['inputs']['local/demo-1:2.0-3/install'] = M.a.pin(b'retained install DATA')
            observation['database_sha256'] = M.v.digest(M.v.encoded(observation['inputs']))
            value['snapshot_id'] = 'alpm-local-db-' + observation['database_sha256']
        for mutate in (lambda v: v['packages'][0].update(version='1:2.0-4'),
                       lambda v: v['observation'].update(database_sha256='0'*64),
                       missing_record):
            value = copy.deepcopy(original); mutate(value)
            with self.assertRaises(ValueError): M.project(value)

    def test_duplicate_nonfinite_and_size_count_bounds(self):
        for raw in (b'{"schema_version":1,"schema_version":1}', b'{"x":NaN}', b'{"x":Infinity}', b'{"x":1.2}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError): M.decode(raw)
        with patch.object(M, 'INPUT_CAP', 8), self.assertRaises(ValueError): M.decode(b' ' * 9)
        with patch.object(M.a, 'CAP', 8), self.assertRaises(ValueError): M.project(envelope())
        for rows in ([], [package()] * 4097):
            with self.assertRaises(ValueError): M.project(dict(envelope(), packages=rows))

    def test_fresh_output_nonsymlink_input_and_partial_output_has_no_receipt(self):
        path, raw = self.save(envelope()); checksum = M.a.pin(raw)['sha256']; out = self.root/'output'
        out.mkdir()
        with self.assertRaises(ValueError): M.run(path, checksum, out)
        alias = self.root/'alias'; alias.symlink_to(path)
        with self.assertRaises(ValueError): M.run(alias, checksum, self.root/'new')
        alias.unlink(); os.link(path, alias)
        with self.assertRaises(ValueError): M.run(path, checksum, self.root/'new')
        alias.unlink(); original_write = M.write_at
        def fail(directory, name, data):
            if name == 'inventory.json': raise OSError('simulated interrupted write')
            return original_write(directory, name, data)
        with patch.object(M, 'write_at', side_effect=fail), self.assertRaises(OSError):
            M.run(path, checksum, self.root/'partial')
        self.assertFalse((self.root/'partial/receipt.json').exists())
        self.assertEqual(path.read_bytes(), raw)
        with self.assertRaises(ValueError): M.run(path, checksum, self.root/'partial')

    def test_actual_converter_to_monitor_cli_no_fixed_version_or_actor(self):
        path, raw = self.save(envelope()); out = self.root/'converted'
        env = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'PYTHONDONTWRITEBYTECODE': '1'}
        first = subprocess.run([sys.executable, '-B', str(HERE/'security_inventory.py'), '--input', str(path),
            '--input-sha256', M.a.pin(raw)['sha256'], '--output', str(out)], env=env, capture_output=True, text=True, timeout=10)
        self.assertEqual(first.returncode, 0, first.stderr)
        group = dict(name='AVG-1', packages=['demo'], status='Unknown', severity='High', type='test advisory',
                     affected=None, fixed=None, issues=['CVE-2026-12345'], advisories=['ASA-202611-1'])
        cache = M.encoded([group]); (self.root/'advisories.json').write_bytes(cache)
        provenance = dict(url=M.a.URL, retrieved_at='2026-11-08T12:00:00Z', **M.a.pin(cache))
        (self.root/'provenance.json').write_bytes(M.encoded(provenance))
        second = subprocess.run([sys.executable, '-B', str(HERE/'security_advisories.py'), '--inventory', str(out/'inventory.json'),
            '--advisories', str(self.root/'advisories.json'), '--provenance', str(self.root/'provenance.json'),
            '--output', str(self.root/'report'), '--as-of', '2026-11-08T13:00:00Z'], env=env, capture_output=True, text=True, timeout=10)
        self.assertEqual(second.returncode, 0, second.stderr)
        report = json.loads((self.root/'report/report.json').read_bytes()); row = report['packages'][0]
        self.assertEqual(row['version'], '1:2.0-3'); self.assertEqual(row['arm_security_status'], 'UNKNOWN')
        self.assertEqual(row['findings'][0]['version_relation'], 'UNKNOWN_NO_ARCH_FIXED_VERSION')
        self.assertEqual(report['inputs']['inventory.json'], M.a.pin((out/'inventory.json').read_bytes()))
        self.assertEqual(path.read_bytes(), raw)


if __name__ == '__main__': unittest.main()

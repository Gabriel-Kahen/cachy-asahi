# SPDX-License-Identifier: MIT
"""Explicitly modeled admission; actual authenticated bootstrap/held imports."""
import copy
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import common
import orchestrator

HERE = Path(__file__).parent


class Interface(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='rcn-interface-tests-')
        self.root = Path(self.temp.name); self.inputs = self.root / 'inputs'; self.inputs.mkdir()
        identity = {'source_commit': '1' * 40, 'run_id': '123', 'nonce': '2' * 32, 'image_id': 'sha256:' + '3' * 64}
        summary = {'schema_version': 1, 'purpose': 'frozen-development-only-native-integration', 'status': 'PASS',
                   'cancelled': False, 'source_commit': identity['source_commit'], 'base_image': identity['image_id'],
                   'owned_image_cleanup': {'status': 'PASS', 'absence_verified': True, 'cleanup_uncertain': False},
                   'stages': {name: {'status': 'PASS'} for name in ('fixtures', 'signer', 'lifecycle', 'repository', 'onboarding', 'desktop', 'source-suites')}}
        public = {**identity, 'purpose': 'accepted-repository-public-artifacts', 'status': 'PASS'}
        cleanup = {'status': 'PASS', 'container': 'cachy-asahi-repository-' + identity['nonce'], 'container_id': '4' * 64,
                   'absence_verified': True, 'name_absence_verified': True, 'id_absence_verified': True}
        self.authority = {**identity, 'purpose': 'accepted-repository-client-inputs', 'status': 'PASS', 'refs': {}, 'files': {},
                          'crypto': {'purpose': 'external-repository-cryptographic-acceptance', 'signed_objects': []}}
        for name, record in (('aggregate', summary), ('public_acceptance', public), ('cleanup', cleanup)):
            filename = name + '.json'; raw = common.encoded(record); (self.inputs / filename).write_bytes(raw)
            self.authority['refs'][name] = filename
            self.authority['files'][filename] = {'sha256': common.digest(raw), 'bytes': len(raw)}
        self.crypto = {**identity, 'schema_version': 2, 'purpose': 'repository-cryptographic-phases', 'status': 'PASS',
                       'original_local_certification': 'native-receipts-only', 'current_A_authorization': 'REVOKED',
                       'private_work_cleanup': 'PASS', 'snapshot_integrity': [], 'terminal_authorization': []}
        for n in range(15):
            path = f'artifact-{n:02}'; signature = path + '.sig'; role = 'signer-A' if n < 7 else 'signer-B'
            for filename in (path, signature):
                raw = b'MODELED observation'; (self.inputs / filename).write_bytes(raw)
                self.authority['files'][filename] = {'sha256': common.digest(raw), 'bytes': len(raw)}
            original = {'path': path, 'signature': signature, 'signer': role, 'status': 'VALID'}
            self.authority['crypto']['signed_objects'].append(original)
            row = {key: original[key] for key in ('path', 'signature', 'signer')}
            row.update(integrity='VALID', data_sha256=common.digest(raw), signature_sha256=common.digest(raw))
            self.crypto['snapshot_integrity'].append({**row, 'authorization': 'SNAPSHOT_ONLY'})
            self.crypto['terminal_authorization'].append({**row, 'authorization': 'REVOKED' if n < 7 else 'VALID_AT_OBSERVATION'})

    def tearDown(self): self.temp.cleanup()

    def run_interface(self):
        authority, crypto = common.encoded(self.authority), common.encoded(self.crypto)
        metadata = common.encoded({'acceptance_sha256': common.digest(authority)})
        return orchestrator.post_terminal(self.inputs, authority, common.digest(authority), crypto, common.digest(crypto), metadata, common.digest(metadata))

    def test_modeled_terminal_refuses_incompatible_v1_without_signing(self):
        result = self.run_interface()
        self.assertEqual(result['status'], 'NOT RUN')
        self.assertFalse(result['signer_generated'])
        self.assertIn('successor', result['blockers'][0])

    def test_false_current_A_valid_refused_even_rebound(self):
        self.crypto['terminal_authorization'][0]['authorization'] = 'VALID_AT_OBSERVATION'
        with self.assertRaises(common.Refused): self.run_interface()

    def test_terminal_failure_precedes_source_import(self):
        raw = common.encoded({'status': 'FAIL'}); filename = self.authority['refs']['aggregate']
        (self.inputs / filename).write_bytes(raw)
        self.authority['files'][filename] = {'sha256': common.digest(raw), 'bytes': len(raw)}
        with self.assertRaisesRegex(common.Refused, 'terminal'): self.run_interface()

    def test_name_only_cleanup_refused(self):
        filename = self.authority['refs']['cleanup']; value = common.decode((self.inputs / filename).read_bytes())
        value.pop('id_absence_verified'); raw = common.encoded(value); (self.inputs / filename).write_bytes(raw)
        self.authority['files'][filename] = {'sha256': common.digest(raw), 'bytes': len(raw)}
        with self.assertRaisesRegex(common.Refused, 'CID'): self.run_interface()

    def test_frozen_dependency_drift_refused_before_import(self):
        fake = self.root / 'repo'; path = fake / 'scripts/release'; path.mkdir(parents=True)
        (path / 'release.py').write_bytes(b'raise RuntimeError("must not execute")')
        with self.assertRaisesRegex(common.Refused, 'dependency'):
            orchestrator.held_modules(fake, self.root)

    def source_cli(self):
        source = self.root / 'source'; source.mkdir()
        names = ('common.py', 'base.py', 'provenance.py', 'crypto.py', 'orchestrator.py', 'entry.py', 'worker.py')
        pins = {}
        for name in names:
            raw = (HERE / name).read_bytes(); (source / name).write_bytes(raw)
            pins[name] = {'sha256': common.digest(raw), 'mode': 0o644}
        raw = common.encoded(pins); manifest = self.root / 'source-map.json'; manifest.write_bytes(raw)
        return source, manifest, common.digest(raw)

    def test_real_cli_authenticates_all_sources_before_import(self):
        source, manifest, pin = self.source_cli()
        (source / 'crypto.py').write_bytes(b'raise RuntimeError("must not import drift")')
        proc = subprocess.run(['/usr/bin/python3', '-I', '-B', source / 'entry.py', '--source-map', manifest,
                               '--source-map-sha256', pin, 'attest', '--inputs', self.inputs, '--request', '/absent',
                               '--request-sha256', '0' * 64, '--output', self.root / 'output'], capture_output=True, timeout=10)
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(common.decode(proc.stdout)['error_type'], 'ValueError')
        self.assertNotIn(b'RuntimeError', proc.stdout + proc.stderr)
        self.assertFalse((self.root / 'output').exists())

    def test_real_cli_ignores_pyc_and_refuses_missing_request(self):
        source, manifest, pin = self.source_cli()
        cache = source / '__pycache__'; cache.mkdir(); (cache / 'crypto.pyc').write_bytes(b'hostile')
        proc = subprocess.run(['/usr/bin/python3', '-I', '-B', source / 'entry.py', '--source-map', manifest,
                               '--source-map-sha256', pin, 'attest', '--inputs', self.inputs, '--request', '/absent',
                               '--request-sha256', '0' * 64, '--output', self.root / 'output'], capture_output=True, timeout=10)
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(common.decode(proc.stdout)['error_type'], 'FileNotFoundError')
        self.assertEqual(list(cache.iterdir()), [cache / 'crypto.pyc'])

    def test_real_cli_bootstrap_rejects_oversize_and_fifo_before_import(self):
        source, manifest, pin = self.source_cli()
        for special in ('oversize', 'fifo'):
            with self.subTest(special=special):
                path = self.root / special
                if special == 'fifo': os.mkfifo(path)
                else: path.write_bytes(b'x' * (1024**2 + 1))
                proc = subprocess.run(['/usr/bin/python3', '-I', '-B', source / 'entry.py', '--source-map', path,
                    '--source-map-sha256', pin, 'attest', '--inputs', self.inputs, '--request', '/absent',
                    '--request-sha256', '0' * 64, '--output', self.root / 'output'], capture_output=True, timeout=3)
                self.assertEqual(proc.returncode, 1)
                self.assertEqual(common.decode(proc.stdout)['error_type'], 'ValueError')

    def test_plain_python_refused_before_adjacent_stdlib_poison(self):
        source, manifest, pin = self.source_cli()
        marker = self.root / 'executed-poison'
        (source / 'json.py').write_text('from pathlib import Path; Path(' + repr(str(marker)) + ').touch()\n')
        proc = subprocess.run(['/usr/bin/python3', source / 'entry.py'], capture_output=True, timeout=3)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn(b'-I -B', proc.stderr)
        self.assertFalse(marker.exists())

    def test_real_authenticated_cli_crypto_synthetic_complete(self):
        from test_crypto import RealFixture
        fixture_root = self.root / 'crypto-fixture'; fixture_root.mkdir()
        fixture = RealFixture(fixture_root)
        try:
            source, manifest, pin = self.source_cli()
            raw = common.encoded(fixture.request); request = self.root / 'crypto-request.json'; request.write_bytes(raw)
            output = self.root / 'crypto-output'
            proc = subprocess.run(['/usr/bin/python3', '-I', '-B', source / 'entry.py', '--source-map', manifest,
                '--source-map-sha256', pin, 'attest', '--inputs', fixture.inputs, '--request', request,
                '--request-sha256', common.digest(raw), '--output', output], capture_output=True, timeout=30)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            result = common.decode(proc.stdout)
            self.assertEqual(result['current_A_authorization'], 'REVOKED')
            self.assertEqual(common.decode((output / 'result.json').read_bytes())['status'], 'PASS')
            self.assertFalse(list(self.root.glob('repository-crypto-*')))
        finally:
            fixture.close()


if __name__ == '__main__': unittest.main()

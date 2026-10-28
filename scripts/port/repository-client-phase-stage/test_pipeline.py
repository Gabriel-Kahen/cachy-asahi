#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Modeled native/base/provenance, real original phases and fresh TEST clients.

No gate or cryptographic verdict is stubbed. This is local fixture execution,
never accepted native, installation or hardware evidence.
"""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import dependencies
import entry
from test_fixture import PhaseFixture, digest, encoded, modules, real_template

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent


class RealPhasePipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key_temp = tempfile.TemporaryDirectory(prefix='phase-pipeline-real-TEST-keys-')
        cls.collector = modules()[1]
        cls.template = real_template(Path(cls.key_temp.name), cls.collector)

    @classmethod
    def tearDownClass(cls):
        try: cls.template.close()
        finally: cls.key_temp.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='MODELED-native-real-phase-pipeline-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.inputs = self.root / 'inputs'; self.inputs.mkdir()
        self.fixture = PhaseFixture(self.inputs, template=self.template)
        self.addCleanup(self.fixture.close)
        self.raw = encoded(self.fixture.authority); self.pin = digest(self.raw)
        self.authority_path = self.root / 'authority.json'; self.authority_path.write_bytes(self.raw)
        self.metadata = encoded(self.fixture.metadata())
        self.metadata_path = self.root / 'metadata.json'; self.metadata_path.write_bytes(self.metadata)
        self.repo = self.root / 'repo'
        self.source = self.repo / 'scripts/port/repository-client-phase-stage'
        self.source.mkdir(parents=True)
        for name in entry.SOURCES:
            shutil.copyfile(HERE / name, self.source / name)
            (self.source / name).chmod(0o644)
        for name in dependencies.COLLECTOR:
            target = self.repo / 'scripts/port/repository-client-native' / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / 'scripts/port/repository-client-native' / name, target)
        for name in dependencies.PREDECESSORS:
            target = self.repo / name; target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target); target.chmod(dependencies.PREDECESSOR_MODES[name])
        self.map = self.root / 'test-controlled-source-map.json'
        self.map.write_bytes(encoded({name: {'sha256': digest((self.source / name).read_bytes()), 'mode': 0o644}
                                      for name in entry.SOURCES}))
        self.map_pin = digest(self.map.read_bytes())
        self.loaded = entry.authenticated(self.map, self.map_pin, source_root=self.source, repo_root=self.repo)

    def cli(self, action, extra=()):
        return subprocess.run([sys.executable, '-I', '-B', str(self.source / 'entry.py'),
            '--source-map', str(self.map), '--source-map-sha256', self.map_pin, action,
            '--inputs', str(self.inputs), '--authority', str(self.authority_path), '--authority-sha256', self.pin,
            *map(str, extra)], capture_output=True, timeout=60)

    def assert_lineage(self, result, output):
        self.assertEqual(result['status'], 'PASS', result.get('blockers'))
        self.assertEqual(result['current_A_authorization'], 'REVOKED')
        self.assertEqual(result['original_crypto_verification'], 'independent-public-key-phase-verification')
        self.assertEqual(result['phase_receipt_sha256'], self.fixture.authority['crypto']['receipt']['sha256'])
        self.assertEqual(result['phase_request_sha256'], self.fixture.authority['crypto']['request']['sha256'])
        self.assertFalse(result['original_B_continuity'])
        self.assertEqual(len(result['client_cases']), 7)
        self.assertTrue(all(row['result'] == 'PASS' for row in result['client_cases']))
        self.assertEqual(result['cleanup'], {'status': 'PASS', 'private_state_absent': True, 'signer_agent_stop': 'PASS'})
        lineage = json.loads((output / 'bundle/evidence/lineage.json').read_bytes())
        self.assertEqual(lineage, result['lineage'])
        rows = lineage['input_lineage']; self.assertEqual(len(rows), 15)
        self.assertEqual(sum(row['terminal_authorization'] == 'REVOKED' for row in rows), 7)
        self.assertEqual(sum(row['terminal_authorization'] == 'VALID_AT_OBSERVATION' for row in rows), 8)
        self.assertTrue(all(row['snapshot_authorization'] == 'SNAPSHOT_ONLY' for row in rows))
        self.assertNotIn(result['signer'], {row['fingerprint'] for row in lineage['original_signer_roles'].values()})
        for row in self.fixture.authority['archives']:
            self.assertEqual((output / 'bundle/repo' / Path(row['path']).name).read_bytes(), self.fixture.data[row['path']])
        self.assertEqual(len(list((output / 'bundle/repo').glob('*.pkg.tar.*'))), 8)  # four archives + signatures
        self.assertFalse(any('repository-test-fixture' in path.name for path in (output / 'bundle/repo').iterdir()))

    def test_copied_packet_real_phases_and_real_restaging_propagate_both_roots(self):
        adapter, gate = self.loaded['adapter'], self.loaded['gate']
        output = self.root / 'api-output'
        original = gate.accept
        with mock.patch.dict(original.__kwdefaults__, {'repo_root': self.root / 'poisoned-default-root'}), \
             mock.patch.object(gate, 'accept', wraps=original) as observed:
            result = adapter.execute(self.inputs, self.raw, self.pin, self.metadata, digest(self.metadata), output,
                                     repo_root=self.repo)
        self.assertEqual(observed.call_count, 2)
        self.assertTrue(all(call.kwargs['repo_root'] == self.repo for call in observed.call_args_list))
        self.assert_lineage(result, output)

    def test_isolated_authenticated_cli_accepts_real_phase_fixture(self):
        process = self.cli('accept')
        self.assertEqual(process.returncode, 0, process.stderr.decode() + process.stdout.decode())
        accepted = json.loads(process.stdout)
        self.assertEqual(accepted['status'], 'PASS-input-acceptance')
        self.assertEqual(accepted['current_A_authorization'], 'REVOKED')
        self.assertEqual(len(accepted['lineage']), 15)
        self.assertEqual(accepted['crypto_verification'], 'independent-public-key-phase-verification')

    def test_isolated_authenticated_cli_restages_real_phase_fixture(self):
        output = self.root / 'cli-output'
        process = self.cli('restage', ['--metadata', self.metadata_path, '--metadata-sha256', digest(self.metadata),
                                     '--output', output])
        self.assertEqual(process.returncode, 0, process.stderr.decode() + process.stdout.decode())
        self.assert_lineage(json.loads(process.stdout), output)

    def test_missing_metadata_stops_after_real_phase_acceptance(self):
        output = self.root / 'missing-metadata'
        adapter = self.loaded['adapter']
        with mock.patch.object(adapter, 'restage', side_effect=AssertionError('signer/client must not run')):
            result = adapter.execute(self.inputs, self.raw, self.pin, None, None, output, repo_root=self.repo)
        self.assertEqual(result['status'], 'NOT RUN', result['blockers'])
        self.assertEqual(result['repository_input_acceptance'], 'PASS')
        self.assertEqual(len(result['blockers']), 3)
        self.assertFalse(output.exists())

    def test_v1_authority_fails_cold_before_fresh_signer(self):
        authority = dict(self.fixture.authority); authority['schema_version'] = 1
        raw = encoded(authority); output = self.root / 'refused-v1'
        adapter = self.loaded['adapter']
        with mock.patch.object(adapter, 'restage', side_effect=AssertionError('signer/client must not run')):
            result = adapter.execute(self.inputs, raw, digest(raw), self.metadata, digest(self.metadata), output,
                                     repo_root=self.repo)
        self.assertEqual(result['status'], 'FAIL')
        self.assertNotIn('repository_input_acceptance', result)
        self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()

"""Complete MODELED authority admission followed by real TEST client execution.

The native/crypto/base observations here are fabricated, explicitly synthetic
test data. No gate is mocked; new TEST signing/release/client commands are real.
"""
import io
import json
import os
from pathlib import Path
import signal
import tarfile
import tempfile
import unittest
from unittest import mock

import adapter
import gate
from test_gate import Fixture, encode


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='SYNTHETIC-restage-full-pipeline-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.inputs = self.root / 'inputs'; self.inputs.mkdir()
        self.fixture = Fixture(self.inputs)
        for phase, rows in self.fixture.rows.items():
            for row in rows:
                archive = io.BytesIO()
                name = row['name']
                info = (f"pkgname = {name}\npkgver = {row['version']}\narch = any\nlicense = MIT\n").encode()
                with tarfile.open(fileobj=archive, mode='w:xz') as target:
                    for path, data in (('.PKGINFO', info), ('usr/share/' + name + '/fixture.txt',
                                                               ('SYNTHETIC payload ' + phase + name).encode())):
                        item = tarfile.TarInfo(path); item.size, item.mode = len(data), 0o644
                        target.addfile(item, io.BytesIO(data))
                data = archive.getvalue(); row['sha256'] = gate.digest(data)
                for label in gate.LABELS:
                    if (label == 'baseline-A') != (phase == 'baseline'):
                        continue
                    self.fixture.put('public/TEST-repositories/' + label + '/' + Path(row['archive']).name, data)
        contract = json.loads(self.fixture.data[self.fixture.refs['repository_contract']])
        contract.update(self.fixture.rows)
        self.fixture.put(self.fixture.refs['repository_contract'], encode(contract))
        manifest_path = self.fixture.refs['public_manifest']
        public = {name.removeprefix('public/'): {'sha256': gate.digest(data), 'bytes': len(data)}
                  for name, data in self.fixture.data.items() if name.startswith('public/') and name != manifest_path}
        manifest = json.loads(self.fixture.data[manifest_path]); manifest['files'] = public
        self.fixture.put(manifest_path, encode(manifest))
        acceptance_path = self.fixture.refs['public_acceptance']
        acceptance = json.loads(self.fixture.data[acceptance_path]); acceptance['manifest_sha256'] = gate.digest(self.fixture.data[manifest_path])
        self.fixture.put(acceptance_path, encode(acceptance))
        self.fixture.authority['crypto']['artifact_map_sha256'] = gate.digest(gate.canonical(public))
        for row in self.fixture.authority['archives']:
            row.update(sha256=gate.digest(self.fixture.data[row['path']]), bytes=len(self.fixture.data[row['path']]))
        self.fixture.change('repository', lambda value: value.update(original_inputs={
            phase: {row['name']: {key: row[key] for key in ('sha256', 'version')} for row in rows}
            for phase, rows in self.fixture.rows.items()}))
        self.fixture.bind_native()
        self.fixture.project()
        self.fixture.refresh()
        self.authority = encode(self.fixture.authority)
        self.pin = gate.digest(self.authority)

    def metadata(self):
        snapshot = 'SYNTHETIC-complete-generic-base'
        license_text = 'SYNTHETIC test license text; no distribution acceptance.\n'
        protected = next(iter(sorted(self.fixture.base)))
        return {'schema_version': 1, 'purpose': 'reviewed-generic-restage-metadata',
                'development_only': True, 'platform_scope': 'generic-builder-only',
                'acceptance_sha256': self.pin, 'source_commit': self.fixture.recipe_commit,
                'base': {'schema_version': 1, 'snapshot_id': snapshot, 'target_arch': 'aarch64',
                         'kind': 'complete-target-transaction', 'fixture_scope': 'FABRICATED-METADATA-NOT-NATIVE',
                         'packages': [{'name': name, 'version': version, 'arch': 'aarch64', 'depend': [],
                                       'provides': [], 'conflict': [], 'files': ['SYNTHETIC/base/' + name]}
                                      for name, version in sorted(self.fixture.base.items())]},
                'policy': {'selected_packages': sorted(gate.ORIGINALS), 'supported_models': [],
                           'protected_packages': [protected], 'coordinated_sets': [{'name': 'SYNTHETIC-base',
                                'versions': {protected: self.fixture.base[protected]}}]},
                'project_license': {'spdx': 'MIT', 'text': license_text, 'sha256': gate.digest(license_text.encode())},
                'provenance': {row['name']: {'schema_version': 1, 'artifact_sha256': row['sha256'],
                    'source_commit': self.fixture.recipe_commit, 'recipe_sha256': 'b' * 64,
                    'package': {'name': row['name'], 'version': row['version'], 'arch': 'any'},
                    'licenses': ['MIT'], 'sources': [{'url': 'fixture://SYNTHETIC', 'sha256': 'c' * 64}],
                    'build': {'execution': 'synthetic', 'architecture': 'aarch64',
                              'environment': 'SYNTHETIC-fixture-not-native', 'snapshot_id': snapshot}}
                    for row in self.fixture.authority['archives']}}

    def test_complete_unmocked_gate_and_real_test_restaging(self):
        metadata = encode(self.metadata())
        output = self.root / 'output'
        result = adapter.execute(self.inputs, self.authority, self.pin, metadata, gate.digest(metadata), output)
        self.assertEqual(result['status'], 'PASS', result['blockers'])
        self.assertEqual(result['lineage']['original_crypto_verification'], 'external-attestation-only')
        self.assertFalse(result['original_B_continuity'])
        self.assertEqual(len(result['client_cases']), 7)
        self.assertTrue(all(row['result'] == 'PASS' for row in result['client_cases']))
        for row in result['lineage']['input_lineage']:
            self.assertEqual(row['data_sha256'], gate.digest(self.fixture.data[row['path']]))
            self.assertEqual(row['signature_sha256'], gate.digest(self.fixture.data[row['signature']]))
        self.assertNotIn(result['signer'], {row['fingerprint'] for row in result['lineage']['original_signer_roles'].values()})
        for row in self.fixture.authority['archives']:
            self.assertEqual((output / 'bundle/repo' / Path(row['path']).name).read_bytes(),
                             self.fixture.data[row['path']])

    def test_accepted_gate_without_metadata_does_not_execute(self):
        with mock.patch.object(adapter.subprocess, 'Popen', side_effect=AssertionError('must not execute')):
            result = adapter.execute(self.inputs, self.authority, self.pin, None, None, self.root / 'output')
        self.assertEqual(result['status'], 'NOT RUN')
        self.assertEqual(len(result['blockers']), 3)
        self.assertFalse((self.root / 'output').exists())

    def test_private_key_material_is_not_a_license(self):
        value = self.metadata()
        text = '-----BEGIN PGP PRIVATE KEY BLOCK-----\nSYNTHETIC-TEST\n'
        value['project_license'].update(text=text, sha256=gate.digest(text.encode()))
        metadata = encode(value)
        with mock.patch.object(adapter.subprocess, 'Popen', side_effect=AssertionError('must not execute')):
            result = adapter.execute(self.inputs, self.authority, self.pin, metadata, gate.digest(metadata), self.root / 'output')
        self.assertEqual(result['status'], 'FAIL')
        self.assertIn('private material', result['blockers'][0])
        self.assertFalse((self.root / 'output').exists())

    def test_terminal_close_cancellation_invalidates_pass_after_real_client_work(self):
        metadata = encode(self.metadata())
        original = adapter.Publication.close
        for timing, sig in (('before', signal.SIGTERM), ('after', signal.SIGINT)):
            output = self.root / ('terminal-close-' + timing)
            injected, closed = [], []
            def close(publication):
                target = publication.created and not injected
                if target and timing == 'before':
                    injected.append(True); os.kill(os.getpid(), sig)
                result = original(publication)
                if target:
                    closed.append(not publication.fds and publication.root is None)
                if target and timing == 'after':
                    injected.append(True); os.kill(os.getpid(), sig)
                return result
            with self.subTest(timing=timing, signal=sig), adapter.cancellation_handlers(), \
                 mock.patch.object(adapter.Publication, 'close', side_effect=close, autospec=True):
                result = adapter.execute(self.inputs, self.authority, self.pin, metadata, gate.digest(metadata), output)
            self.assertEqual(result['status'], 'FAIL', result['blockers'])
            self.assertEqual(injected, [True])
            self.assertEqual(closed, [True])
            self.assertEqual(result['cleanup']['status'], 'PASS')
            self.assertEqual(len(result['client_cases']), 7)
            self.assertTrue(all(row['result'] == 'PASS' for row in result['client_cases']))
            self.assertFalse((output / 'result.json').exists(), 'terminal cancellation preserved PASS')
            for row in self.fixture.authority['archives']:
                self.assertEqual((self.inputs / row['path']).read_bytes(), self.fixture.data[row['path']])

    def test_signer_stop_spawn_cancellation_finishes_real_private_teardown(self):
        metadata = encode(self.metadata())
        output = self.root / 'signer-stop-cancel'
        original = adapter.subprocess.Popen
        children = []
        def spawn(argv, *args, **kwargs):
            child = original(argv, *args, **kwargs)
            if Path(argv[0]).name == 'gpgconf' and '--kill' in argv:
                children.append(child)
                os.kill(os.getpid(), signal.SIGTERM)
            return child
        with adapter.cancellation_handlers(), mock.patch.object(adapter.subprocess, 'Popen', side_effect=spawn):
            result = adapter.execute(self.inputs, self.authority, self.pin, metadata, gate.digest(metadata), output)
        self.assertEqual(result['status'], 'FAIL', result['blockers'])
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].poll())
        self.assertTrue(children[0].stdout.closed and children[0].stderr.closed)
        self.assertEqual(result['cleanup'], {'status': 'PASS', 'private_state_absent': True, 'signer_agent_stop': 'PASS'})
        self.assertEqual(len(result['client_cases']), 7)
        self.assertFalse(output.exists())
        self.assertEqual(adapter.DEFERRED_CANCELLATION, [])


if __name__ == '__main__':
    unittest.main()

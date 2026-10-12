#!/usr/bin/env python3
"""Synthetic acceptance fixtures; real TEST GPG/repo-add/frozen client execution.

The upstream acceptance gate is mocked only for modeled local inputs. These
tests provide no native repository, Asahi, production trust or hardware evidence.
"""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
import types
import os
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
NAMES = ('cachy-asahi-hyprland-settings', 'cachy-asahi-fish-config',
         'cachy-asahi-zsh-config', 'cachy-asahi-setup')
COMMIT = 'a' * 40
SNAPSHOT = 'SYNTHETIC-generic-restage-fixture'


def encoded(value):
    return (json.dumps(value, sort_keys=True) + '\n').encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


class AdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        missing = [name for name in ('gpg', 'gpgconf', 'gpg-connect-agent', 'repo-add', 'bsdtar', 'vercmp')
                   if not shutil.which(name)]
        if missing:
            raise RuntimeError('required real fixture tools missing: ' + ', '.join(missing))
        spec = importlib.util.spec_from_file_location('repository_client_adapter',
                                                     Path(__file__).with_name('adapter.py'))
        cls.adapter = importlib.util.module_from_spec(spec)
        # The gate and dependency controls are modeled only; no native input or
        # original phase attestation is accepted by these adapter unit tests.
        fixture_gate = types.ModuleType('phase_gate_fixture')
        fixture_gate.accept = lambda *args: (_ for _ in ()).throw(ValueError('MODELED gate requires explicit test fixture'))
        def fixture_tree(root, expected):
            paths = list(root.rglob('*'))
            cls.adapter.need(len(paths) <= 1024 and not any(path.is_symlink() for path in paths), 'MODELED finite tree')
            cls.adapter.need({path.relative_to(root).as_posix() for path in paths if path.is_file()} == set(expected),
                             'MODELED exact tree')
        fixture_gate.tree = fixture_tree
        fixture_dependencies = types.ModuleType('phase_dependencies_fixture')
        common_path = ROOT / 'scripts/port/repository-client-native/common.py'
        common = types.ModuleType('MODELED_authenticated_signal_runtime_test_only')
        common.__file__ = str(common_path)
        # Explicit stdlib-only source compile for local control tests, never PYC.
        exec(compile(common_path.read_bytes(), common.__file__, 'exec'), common.__dict__)
        fixture_dependencies.load_collector = lambda root: {'common': common}
        with mock.patch.dict(sys.modules, {'gate': fixture_gate, 'dependencies': fixture_dependencies}):
            spec.loader.exec_module(cls.adapter)
        cls.adapter.bind_common(ROOT)


    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='SYNTHETIC-restage-regression-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.inputs = self.root / 'inputs'
        self.inputs.mkdir()
        self.output = self.root / 'public'
        self.authority = encoded({'synthetic_fixture': True,
                                  'purpose': 'MODELED-acceptance-only-NOT-native-evidence'})
        self.archives = []
        self.provenance = {}
        for name in NAMES:
            path = self.inputs / (name + '-1.0-1-any.pkg.tar.gz')
            metadata = ('pkgname = ' + name + '\npkgver = 1.0-1\narch = any\n'
                        'license = MIT\ndepend = generic-runtime>=1\n').encode()
            with tarfile.open(path, 'w:gz') as archive:
                for filename, data in (('.PKGINFO', metadata),
                                       ('usr/share/' + name + '/fixture', b'SYNTHETIC TEST ONLY\n')):
                    entry = tarfile.TarInfo(filename)
                    entry.size, entry.mode, entry.uid, entry.gid = len(data), 0o644, 0, 0
                    archive.addfile(entry, io.BytesIO(data))
            data = path.read_bytes()
            self.archives.append({'name': name, 'path': path, 'version': '1.0-1',
                                  'sha256': sha(data), 'bytes': len(data)})
            self.provenance[name] = {
                'schema_version': 1, 'artifact_sha256': sha(data),
                'package': {'name': name, 'version': '1.0-1', 'arch': 'any'},
                'source_commit': COMMIT, 'recipe_sha256': 'b' * 64, 'licenses': ['MIT'],
                'sources': [{'url': 'fixture://SYNTHETIC-not-retrievable/' + name,
                             'sha256': 'c' * 64}],
                'build': {'execution': 'synthetic', 'architecture': 'aarch64',
                          'environment': 'SYNTHETIC-fixture-not-native', 'snapshot_id': SNAPSHOT}}
        self.accepted = {
            'source_commit': COMMIT, 'workflow': 'MODELED-not-a-workflow',
            'run_id': 'SYNTHETIC-not-a-native-run', 'archives': self.archives,
            'base_versions': [{'name': 'generic-runtime', 'version': '1'}],
            'archive_role': 'updated', 'crypto_verification': 'independent-public-key-phase-verification',
            'phase_receipt_sha256': 'd' * 64, 'phase_request_sha256': 'e' * 64, 'current_A_authorization': 'REVOKED',
            'lineage': [{'path': 'SYNTHETIC-baseline-A/data', 'signature': 'SYNTHETIC-baseline-A/data.sig',
                'signer': 'A' * 40, 'integrity': 'VALID', 'authorization': 'REVOKED',
                'data_sha256': 'a' * 64, 'signature_sha256': 'b' * 64, 'certificate_sha256': 'c' * 64,
                'fixture_scope': 'MODELED-PHASE-ATTESTATION-NOT-NATIVE'}]}
        license_text = 'SYNTHETIC license fixture, not project or upstream license evidence.\n'
        self.metadata = {
            'schema_version': 1, 'purpose': 'reviewed-generic-restage-metadata',
            'development_only': True, 'platform_scope': 'generic-builder-only',
            'acceptance_sha256': sha(self.authority), 'source_commit': COMMIT,
            'base': {'schema_version': 1, 'snapshot_id': SNAPSHOT, 'target_arch': 'aarch64',
                     'kind': 'complete-target-transaction', 'packages': [
                         {'name': 'generic-runtime', 'version': '1', 'arch': 'aarch64',
                          'depend': [], 'provides': [], 'conflict': [],
                          'files': ['usr/share/generic-runtime/fixture']}]},
            'policy': {'selected_packages': list(NAMES), 'protected_packages': ['generic-runtime'],
                       'coordinated_sets': [{'name': 'SYNTHETIC-runtime',
                                             'versions': {'generic-runtime': '1'}}],
                       'supported_models': []},
            'provenance': self.provenance,
            'project_license': {'spdx': 'MIT', 'text': license_text,
                                'sha256': sha(license_text.encode())}}

    def execute(self, metadata=None):
        data = encoded(self.metadata if metadata is None else metadata)
        with mock.patch.object(self.adapter.gate, 'accept', return_value=self.accepted), \
             self.adapter.cancellation_handlers():
            return self.adapter.execute(self.inputs, self.authority, sha(self.authority),
                                        data, sha(data), self.output, repo_root=ROOT)

    def test_missing_metadata_does_not_start_a_signer_or_client(self):
        with mock.patch.object(self.adapter.gate, 'accept', return_value=self.accepted), \
             mock.patch('subprocess.Popen', side_effect=AssertionError('unexpected execution')):
            result = self.adapter.execute(self.inputs, self.authority, sha(self.authority),
                                          None, None, self.output, repo_root=ROOT)
        self.assertEqual(result['status'], 'NOT RUN')
        self.assertTrue(result['blockers'])

    def test_external_acceptance_refusal_precedes_output_or_execution(self):
        with mock.patch.object(self.adapter.gate, 'accept', side_effect=ValueError('SYNTHETIC gate refusal')), \
             mock.patch('subprocess.Popen', side_effect=AssertionError('unexpected execution')):
            result = self.adapter.execute(self.inputs, self.authority, sha(self.authority),
                                          None, None, self.output, repo_root=ROOT)
        self.assertEqual(result['status'], 'FAIL')
        self.assertTrue(result['blockers'])
        self.assertFalse(self.output.exists())

    def test_v1_external_attestation_and_current_A_validity_claim_refused(self):
        for changes in ({'crypto_verification': 'external-attestation-only'}, {'current_A_authorization': 'VALID'},
                        {'phase_receipt_sha256': None}, {'lineage': {}}):
            accepted = {**self.accepted, **changes}
            with self.subTest(changes=changes), mock.patch.object(self.adapter.gate, 'accept', return_value=accepted), \
                 mock.patch('subprocess.Popen', side_effect=AssertionError('unexpected command')) as command:
                result = self.adapter.execute(self.inputs, self.authority, sha(self.authority),
                                              None, None, self.output, repo_root=ROOT)
            self.assertEqual(result['status'], 'FAIL')
            self.assertFalse(self.output.exists())
            command.assert_not_called()

    def test_authenticated_collector_drift_precedes_gate_and_commands(self):
        with mock.patch.object(self.adapter.dependencies, 'load_collector', side_effect=ValueError('MODELED pinned collector drift')), \
             mock.patch.object(self.adapter.gate, 'accept', side_effect=AssertionError('unexpected gate')) as accept, \
             mock.patch('subprocess.Popen', side_effect=AssertionError('unexpected command')) as command:
            result = self.adapter.execute(self.inputs, self.authority, sha(self.authority),
                                          None, None, self.output, repo_root=ROOT)
        self.assertEqual(result['status'], 'FAIL')
        self.assertFalse(self.output.exists())
        accept.assert_not_called()
        command.assert_not_called()

    def test_real_term_after_popen_before_assignment_reaps_child_and_pipes(self):
        work = self.root / 'command-spawn-control'
        work.mkdir(mode=0o700)
        commands = self.adapter.Commands(work)
        actual, children = subprocess.Popen, []
        def interrupted_spawn(*args, **kwargs):
            process = actual(*args, **kwargs)
            children.append(process)
            os.kill(os.getpid(), signal.SIGTERM)
            return process
        with self.adapter.cancellation_handlers(), mock.patch('subprocess.Popen', side_effect=interrupted_spawn):
            with self.assertRaises(KeyboardInterrupt):
                commands.run(['python3', '-I', '-c', 'import time;time.sleep(60)'])
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].returncode)
        self.assertTrue(children[0].stdout.closed and children[0].stderr.closed)
        with self.assertRaises(ProcessLookupError):
            os.kill(children[0].pid, 0)
        self.assertEqual(commands.records, [])
        self.assertEqual(self.adapter.common_runtime().PENDING, [])

    def test_phase_attestation_change_after_real_client_cases_refused(self):
        data = encoded(self.metadata)
        changed = {**self.accepted, 'phase_receipt_sha256': 'f' * 64}
        with mock.patch.object(self.adapter.gate, 'accept', side_effect=[self.accepted, changed]):
            result = self.adapter.execute(self.inputs, self.authority, sha(self.authority),
                                          data, sha(data), self.output, repo_root=ROOT)
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(len(result['client_cases']), 7)
        self.assertEqual(result['cleanup']['status'], 'PASS')
        self.assertFalse((self.output / 'result.json').exists())

    def test_real_term_during_first_cleanup_guard_installation_stops_agent_and_removes_state(self):
        actual_restage, actual_signal = self.adapter.restage, signal.signal
        armed, fired = [], []
        def restage(*args, **kwargs):
            result = actual_restage(*args, **kwargs)
            armed.append(True)
            return result
        def install(number, handler):
            result = actual_signal(number, handler)
            if armed and not fired and getattr(handler, '__name__', None) == 'remember':
                fired.append(number)
                os.kill(os.getpid(), signal.SIGTERM)
            return result
        with mock.patch.object(self.adapter, 'restage', side_effect=restage), mock.patch.object(signal, 'signal', side_effect=install):
            result = self.execute()
        self.assertEqual(len(fired), 1)
        self.assertEqual(len(result['client_cases']), 7)
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['cleanup'], {'status': 'PASS', 'private_state_absent': True, 'signer_agent_stop': 'PASS'})
        self.assertFalse((self.output / 'result.json').exists())
        self.assertEqual(self.adapter.common_runtime().PENDING, [])

    def test_incomplete_base_metadata_refused(self):
        for field in ('depend', 'provides', 'conflict', 'files'):
            metadata = copy.deepcopy(self.metadata)
            del metadata['base']['packages'][0][field]
            self.output = self.root / ('public-' + field)
            with self.subTest(field=field):
                self.assertEqual(self.execute(metadata)['status'], 'FAIL')

    def test_unsatisfied_dependency_and_coordinated_version_refused(self):
        for value in ('0', 'missing-runtime'):
            metadata = copy.deepcopy(self.metadata)
            self.output = self.root / ('public-' + value)
            if value == '0':
                metadata['base']['packages'][0]['version'] = '0'
            else:
                metadata['policy']['coordinated_sets'][0]['versions'] = {value: '1'}
            with self.subTest(value=value):
                self.assertEqual(self.execute(metadata)['status'], 'FAIL')

    def test_modeled_complete_base_missing_extra_or_version_drift_refused(self):
        for change in ('missing', 'extra', 'version'):
            metadata = copy.deepcopy(self.metadata)
            self.output = self.root / ('public-base-' + change)
            if change == 'missing':
                metadata['base']['packages'] = []
            elif change == 'extra':
                package = copy.deepcopy(metadata['base']['packages'][0])
                package['name'], package['files'] = 'extra-runtime', []
                metadata['base']['packages'].append(package)
            else:
                metadata['base']['packages'][0]['version'] = '2'
            with self.subTest(change=change), \
                 mock.patch('subprocess.Popen', side_effect=AssertionError('unexpected execution')) as run:
                self.assertEqual(self.execute(metadata)['status'], 'FAIL')
                run.assert_not_called()

    def test_asahi_model_claim_refused_for_generic_restaging(self):
        metadata = copy.deepcopy(self.metadata)
        metadata['policy']['supported_models'] = ['m2-air-13']
        self.assertEqual(self.execute(metadata)['status'], 'FAIL')

    def test_accepted_archive_drift_refused(self):
        self.archives[0]['path'].write_bytes(b'SYNTHETIC changed after modeled acceptance\n')
        self.assertEqual(self.execute()['status'], 'FAIL')

    def test_metadata_authority_binding_and_provenance_cannot_be_substituted(self):
        for field in ('acceptance_sha256', 'artifact_sha256', 'source_commit'):
            metadata = copy.deepcopy(self.metadata)
            self.output = self.root / ('public-' + field)
            if field == 'acceptance_sha256':
                metadata[field] = '0' * 64
            else:
                metadata['provenance'][NAMES[0]][field] = '0' * (40 if field == 'source_commit' else 64)
            with self.subTest(field=field):
                self.assertEqual(self.execute(metadata)['status'], 'FAIL')

    def test_generated_upgrades_cannot_be_relabelled_native_builds(self):
        metadata = copy.deepcopy(self.metadata)
        metadata['provenance'][NAMES[0]]['build']['execution'] = 'native'
        self.assertEqual(self.execute(metadata)['status'], 'FAIL')

    def test_archive_symlink_replacement_refused_without_following_it(self):
        path = self.archives[0]['path']
        retained = self.root / 'retained-package'
        path.rename(retained)
        path.symlink_to(retained)
        self.assertEqual(self.execute()['status'], 'FAIL')
        self.assertEqual(sha(retained.read_bytes()), self.archives[0]['sha256'])

    def test_existing_output_and_symlink_are_never_overwritten(self):
        for linked in (False, True):
            sentinel = self.root / ('sentinel-' + str(linked))
            sentinel.mkdir()
            (sentinel / 'keep').write_bytes(b'USER OWNED\n')
            self.output = self.root / ('public-existing-' + str(linked))
            if linked:
                self.output.symlink_to(sentinel, target_is_directory=True)
            else:
                self.output = sentinel
            with self.subTest(linked=linked):
                self.assertEqual(self.execute()['status'], 'FAIL')
                self.assertEqual((sentinel / 'keep').read_bytes(), b'USER OWNED\n')
                self.assertEqual(sorted(p.name for p in sentinel.iterdir()), ['keep'])

    def test_real_restaging_checks_all_archives_and_seven_client_cases(self):
        original = {row['name']: row['path'].read_bytes() for row in self.archives}
        result = self.execute()
        self.assertEqual(result['status'], 'PASS', result.get('blockers'))
        self.assertTrue(result['development_only'])
        self.assertFalse(result['selected_for_release'])
        self.assertFalse(result['lineage']['original_B_continuity'])
        self.assertEqual(result['lineage']['archive_role'], 'updated')
        self.assertEqual(result['lineage']['original_crypto_verification'], 'independent-public-key-phase-verification')
        self.assertEqual(result['lineage']['input_lineage'], self.accepted['lineage'])
        self.assertEqual(result['lineage']['phase_receipt_sha256'], 'd' * 64)
        self.assertEqual(result['lineage']['phase_request_sha256'], 'e' * 64)
        self.assertEqual(result['lineage']['current_A_authorization'], 'REVOKED')
        self.assertEqual(result['schema_version'], 2)
        self.assertEqual(result['purpose'], 'phase-aware-separate-test-restage')
        self.assertEqual(result['release_semantics'], 'PASS')
        self.assertEqual(result['cleanup'], {'status': 'PASS', 'private_state_absent': True,
                                             'signer_agent_stop': 'PASS'})
        self.assertEqual([row['name'] for row in result['client_cases']], [
            'cold-readonly', 'apply-1', 'repeat-readonly', 'apply-2',
            'signed-rollback-rejected', 'signed-same-sequence-change-rejected',
            'wrong-namespace-rejected'])
        self.assertTrue(all(row['result'] == 'PASS' for row in result['client_cases']))
        cases = {row['name']: row for row in result['client_cases']}
        self.assertIsNone(cases['cold-readonly']['checkpoint_before'])
        self.assertIsNone(cases['cold-readonly']['checkpoint_after'])
        self.assertNotEqual(cases['apply-1']['checkpoint_before'], cases['apply-1']['checkpoint_after'])
        self.assertNotEqual(cases['apply-2']['checkpoint_before'], cases['apply-2']['checkpoint_after'])
        for name in ('repeat-readonly', 'signed-rollback-rejected',
                     'signed-same-sequence-change-rejected', 'wrong-namespace-rejected'):
            self.assertEqual(cases[name]['checkpoint_before'], cases[name]['checkpoint_after'])
        manifest = json.loads((self.output / 'bundle/release.json').read_bytes())
        self.assertEqual({p['name'] for p in manifest['packages']}, set(NAMES))
        self.assertEqual(manifest['signer'], result['signer'])
        spec = json.loads((self.output / 'bundle/spec.json').read_bytes())
        self.assertIs(spec['synthetic'], True)
        self.assertEqual(spec['policy']['supported_models'], [])
        for row in self.archives:
            self.assertEqual((self.output / 'bundle/repo' / row['path'].name).read_bytes(), original[row['name']])
            self.assertEqual(row['path'].read_bytes(), original[row['name']])
        files = {p.relative_to(self.output).as_posix(): p for p in self.output.rglob('*') if p.is_file()}
        self.assertEqual(set(files), set(result['public_files']) | {'result.json'})
        for name, reference in result['public_files'].items():
            self.assertEqual(reference, {'sha256': sha(files[name].read_bytes()),
                                         'bytes': files[name].stat().st_size})
        for row in result['commands']:
            self.assertEqual(sha(files[row['stdout']].read_bytes()), row['stdout_sha256'])
            self.assertEqual(sha(files[row['stderr']].read_bytes()), row['stderr_sha256'])
        self.assertTrue(any(Path(row['argv'][0]).name.startswith('gpg') for row in result['commands']))
        self.assertTrue(any(Path(row['argv'][0]).name == 'repo-add' for row in result['commands']))
        self.assertTrue(any('verify' in row['argv'] and any(p.endswith('/client.py') for p in row['argv'])
                            for row in result['commands']))
        for path in self.output.rglob('*'):
            self.assertFalse(path.is_symlink())
            self.assertFalse(stat.S_ISSOCK(path.lstat().st_mode))
            self.assertNotIn(path.name, {'signing-home', 'state', 'private-keys-v1.d', 'trustdb.gpg'})
            if path.is_file():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertNotIn(b'-----BEGIN PGP PRIVATE KEY BLOCK-----', path.read_bytes())
                self.assertNotIn(b'(protected-private-key', path.read_bytes())

    def test_cleanup_failure_cannot_publish_success(self):
        cleanup = self.adapter.cleanup_signer
        def fail_after_stopping(commands, work):
            cleanup(commands, work)
            raise OSError('SYNTHETIC cleanup acknowledgement failure')
        with mock.patch.object(self.adapter, 'cleanup_signer', side_effect=fail_after_stopping):
            result = self.execute()
        self.assertEqual(result['status'], 'FAIL')
        self.assertNotEqual(result['cleanup']['status'], 'PASS')
        self.assertFalse((self.output / 'result.json').exists())

    def test_late_public_receipt_cancellation_cannot_leave_pass(self):
        put = self.adapter.put
        interrupted = False
        def cancel_after_write(path, data, **options):
            nonlocal interrupted
            put(path, data, **options)
            if Path(path).name == 'result.json' and options.get('dir_fd') is not None:
                interrupted = True
                raise KeyboardInterrupt('SYNTHETIC late receipt cancellation')
        with mock.patch.object(self.adapter, 'put', side_effect=cancel_after_write):
            result = self.execute()
        self.assertTrue(interrupted)
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['cleanup']['status'], 'PASS')
        self.assertFalse((self.output / 'result.json').exists())

    def test_first_signer_command_cancellation_is_cleanup_safe(self):
        original = subprocess.Popen
        interrupted = False
        def cancel_once(argv, *args, **kwargs):
            nonlocal interrupted
            if '--quick-generate-key' in map(str, argv) and not interrupted:
                interrupted = True
                raise KeyboardInterrupt('SYNTHETIC signer startup cancellation')
            return original(argv, *args, **kwargs)
        with mock.patch('subprocess.Popen', side_effect=cancel_once):
            result = self.execute()
        self.assertTrue(interrupted)
        self.assertEqual(result['status'], 'FAIL')
        self.assertFalse((self.output / 'result.json').exists())

    def test_acceptance_drift_after_client_cases_blocks_publication(self):
        data = encoded(self.metadata)
        with mock.patch.object(self.adapter.gate, 'accept', side_effect=[
                self.accepted, ValueError('SYNTHETIC authority drift during execution')]):
            result = self.adapter.execute(self.inputs, self.authority, sha(self.authority),
                                          data, sha(data), self.output, repo_root=ROOT)
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(len(result['client_cases']), 7)
        self.assertFalse((self.output / 'result.json').exists())

    def test_expired_stage_budget_still_stops_real_private_signer(self):
        restage = self.adapter.restage
        def expire_after_client_cases(accepted, metadata, authority_pin, metadata_pin, sources, work, commands):
            result = restage(accepted, metadata, authority_pin, metadata_pin, sources, work, commands)
            commands.started = time.monotonic() - self.adapter.TOTAL_SECONDS - 1
            return result
        with mock.patch.object(self.adapter, 'restage', side_effect=expire_after_client_cases):
            result = self.execute()
        self.assertEqual(result['status'], 'PASS', result.get('blockers'))
        self.assertEqual(result['cleanup'], {'status': 'PASS', 'private_state_absent': True,
                                             'signer_agent_stop': 'PASS'})
        self.assertTrue(any('--kill' in row['argv'] for row in result['commands']))

    def test_cleanup_term_is_deferred_until_real_agent_is_stopped(self):
        run = self.adapter.Commands.run
        interrupted = False
        agent_pid = None
        def interrupt_after_stop(commands, argv, **options):
            nonlocal interrupted, agent_pid
            result = run(commands, argv, **options)
            if 'GETINFO pid' in map(str, argv):
                agent_pid = int(re.search(rb'^D ([0-9]+)$', result[0], re.M)[1])
            if '--kill' in map(str, argv) and not interrupted:
                interrupted = True
                signal.raise_signal(signal.SIGTERM)
            return result
        with mock.patch.object(self.adapter.Commands, 'run', new=interrupt_after_stop):
            result = self.execute()
        self.assertTrue(interrupted)
        self.assertIsNotNone(agent_pid)
        self.assertEqual(result['status'], 'FAIL')
        self.assertTrue(result['cleanup']['private_state_absent'])
        state = Path(f'/proc/{agent_pid}/stat')
        if state.exists():
            self.assertEqual(state.read_bytes().rsplit(b')', 1)[1].split()[0], b'Z')
        self.assertFalse((self.output / 'result.json').exists())

    def test_output_parent_replacement_cannot_redirect_public_writes(self):
        parent = self.root / 'publish-parent'
        parent.mkdir(mode=0o700)
        self.output = parent / 'public'
        external = self.root / 'external'
        external.mkdir(mode=0o700)
        (external / 'keep').write_bytes(b'USER OWNED\n')
        retained = self.root / 'retained-parent'
        restage = self.adapter.restage
        def replace_after_real_restaging(*args, **options):
            result = restage(*args, **options)
            parent.rename(retained)
            parent.symlink_to(external, target_is_directory=True)
            return result
        with mock.patch.object(self.adapter, 'restage', side_effect=replace_after_real_restaging):
            result = self.execute()
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual((external / 'keep').read_bytes(), b'USER OWNED\n')
        self.assertEqual(sorted(p.name for p in external.iterdir()), ['keep'])
        self.assertFalse((self.output / 'result.json').exists())

    def test_term_during_private_directory_removal_finishes_cleanup(self):
        cleanup = tempfile.TemporaryDirectory.cleanup
        interrupted = False
        private = None
        def interrupt_then_remove(directory):
            nonlocal interrupted, private
            if Path(directory.name).name.startswith('repository-client-restage-') and not interrupted:
                interrupted = True
                private = Path(directory.name)
                signal.raise_signal(signal.SIGTERM)
            cleanup(directory)
        with mock.patch.object(tempfile.TemporaryDirectory, 'cleanup', new=interrupt_then_remove):
            result = self.execute()
        self.assertTrue(interrupted)
        self.assertIsNotNone(private)
        self.assertFalse(private.exists())
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['cleanup'], {'status': 'PASS', 'private_state_absent': True,
                                             'signer_agent_stop': 'PASS'})
        self.assertFalse((self.output / 'result.json').exists())

    def test_secondary_term_during_failed_receipt_invalidation_removes_pass(self):
        put = self.adapter.put
        remove = self.adapter.Publication.remove_receipt
        wrote_pass = False
        secondary_signal = False
        first_removal_completed = False
        original = {row['path']: row['path'].read_bytes() for row in self.archives}
        def cancel_after_pass(path, data, **options):
            nonlocal wrote_pass
            put(path, data, **options)
            if Path(path).name == 'result.json' and options.get('dir_fd') is not None:
                self.assertEqual(json.loads(data)['status'], 'PASS')
                wrote_pass = True
                raise KeyboardInterrupt('SYNTHETIC late publication cancellation')
        def interrupt_before_invalidation(publication):
            nonlocal secondary_signal, first_removal_completed
            first = not secondary_signal
            if first:
                secondary_signal = True
                self.assertTrue((self.output / 'result.json').exists())
                signal.raise_signal(signal.SIGTERM)
            remove(publication)
            if first:
                first_removal_completed = True
        with mock.patch.object(self.adapter, 'put', side_effect=cancel_after_pass), \
             mock.patch.object(self.adapter.Publication, 'remove_receipt', new=interrupt_before_invalidation):
            try:
                result = self.execute()
            except KeyboardInterrupt:
                result = None
        if result is not None:
            self.assertEqual(result['status'], 'FAIL')
        self.assertTrue(wrote_pass)
        self.assertTrue(secondary_signal)
        self.assertTrue(first_removal_completed)
        self.assertFalse((self.output / 'result.json').exists())
        self.assertEqual(sorted(p.name for p in self.inputs.iterdir()),
                         sorted(path.name for path in original))
        for path, data in original.items():
            self.assertEqual(path.read_bytes(), data)


if __name__ == '__main__':
    unittest.main(verbosity=2)

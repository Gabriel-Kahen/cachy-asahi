"""Inert binding and commit-truth controls; no native driver or helper executes."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / 'scripts/update/aux_copy.py').is_file())
spec = importlib.util.spec_from_file_location('caller_upgrade_hook_test', HERE / 'upgrade_hook.py')
h = importlib.util.module_from_spec(spec); spec.loader.exec_module(h)


class DriverBinding(unittest.TestCase):
    def test_direct_worker_binds_exact_aux_copy_initializer_and_linked_runtime(self):
        with tempfile.TemporaryDirectory() as temporary:
            control = Path(temporary)
            (control / 'scale.json').write_text('{}')
            config = dict(copy_seconds=600, driver_seconds=1800,
                code_pins={'scripts/update/linked_runtime.py': 'a'*64,
                           'scripts/update/aux_initialize.py': 'b'*64},
                release=dict(supported_models=['m2-air-13', 'm2-air-15'], sequence=1))
            argv = h.driver_command(config, control, Path('/stage'), 'A'*40)
        self.assertIn('--worker', argv); self.assertIn('--auxiliary-runtime', argv)
        self.assertEqual(argv[argv.index('--runtime') + 1], '/upgrade-code/scripts/update/linked_runtime.py')
        self.assertEqual(argv[argv.index('--initializer') + 1], '/upgrade-code/scripts/update/aux_initialize.py')
        self.assertEqual(argv[argv.index('--runtime-sha256') + 1], 'a'*64)
        self.assertEqual(argv[argv.index('--source') + 1], '/stage')
        self.assertEqual(argv[argv.index('--source-root') + 1], '/upgrade-code')
        self.assertEqual(argv[argv.index('--gpg-home') + 1], '/upgrade-signing')
        self.assertNotIn('setup_trial', ' '.join(argv))
        driver = ROOT / 'scripts/ci/full-root-upgrade/root_upgrade.py'
        self.assertIn("root / 'scripts/update/aux_copy.py'", driver.read_text())

    def test_worker_failure_keeps_unknown_without_fabricating_commit_or_retry(self):
        for change in ({'termination': 'timeout'}, {'returncode': -9}, {'stdout': b'not json'},
                       {'direct_child_reaped': False}, {'stdout': b'{"status":"PASS"}'},
                       {'stdout': b'{"status":"PASS","commit_started":true,"packages_committed":true,"checkpoint_changed":true}', 'returncode': 1}):
            row = dict(termination=None, returncode=0, direct_child_reaped=True, stdout=b'{}') | change
            with self.subTest(change=change):
                result = h.driver_result(row)
                self.assertEqual(result['status'], 'FAIL')
                self.assertEqual(result['commit_started'], 'UNKNOWN')

    def test_known_postcommit_failure_survives_projection(self):
        result = dict(status='FAIL', commit_started=True, packages_committed=True, checkpoint_changed=True,
                      committed_transactions=1, copy_cleanup='FAIL-owned-workspace-retained-or-partial')
        row = dict(termination=None, returncode=1, direct_child_reaped=True, stdout=json.dumps(result).encode())
        self.assertEqual(h.driver_result(row), result)

    def test_empty_source_link_selection_refuses(self):
        empty = SimpleNamespace(CHAIN_PATHS=(), LINK_NODES={})
        with patch.object(h, 'load', return_value=empty):
            with self.assertRaisesRegex(ValueError, 'actual87'): h.selected_links(ROOT)


class ConfigurationPins(unittest.TestCase):
    def test_changed_code_or_external_source_refuses_without_import(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary); code = base / 'code'; code.mkdir()
            names = [h.DRIVER, 'scripts/ci/full-root-upgrade/construct_repository.py'] + [
                'scripts/update/' + n + '.py' for n in (
                    'aux_copy', 'aux_initialize', 'linked_runtime', 'root_link_selection', 'supervision')]
            pins = {}
            for name in names:
                path = code / name; path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('inert source bytes\n'); pins[name] = h.digest(path)
            external = {}
            for name in ('/setup4.py', '/footprint.py', '/persistent_scope.py'):
                path = base / Path(name).name; path.write_text('inert external bytes\n'); external[name] = path
            value = dict(schema_version=1, purpose='actual587-persistent-root-setup4-test', code_pins=pins,
                external_pins={k:h.digest(v) for k,v in external.items()}, stage_seconds=900,
                verify_seconds=600, copy_seconds=600, driver_seconds=1800,
                scale=dict(before_lock_sha256=h.BEFORE, after_lock_sha256=h.AFTER, platform_mode='generic-development'),
                release=dict(release_id='test', repo_name='test', namespace='test', sequence=1,
                    issued_utc='2026-10-16T00:00:00Z', expires_utc='2026-10-18T00:00:00Z',
                    supported_models=['m2-air-13','m2-air-15']))
            config = base / 'config.json'; config.write_text(json.dumps(value))
            ordinary = h.ordinary
            with patch.object(h, 'ordinary', side_effect=lambda p: ordinary(external.get(str(p), p))), \
                 patch.object(h, 'load') as loader:
                self.assertEqual(h.configuration(config, code), value)
                (code / h.DRIVER).write_text('changed\n')
                with self.assertRaisesRegex(ValueError, 'code bytes changed'): h.configuration(config, code)
                (code / h.DRIVER).write_text('inert source bytes\n')
                external['/setup4.py'].write_text('changed\n')
                with self.assertRaisesRegex(ValueError, 'external helper bytes changed'): h.configuration(config, code)
                loader.assert_not_called()


class HookOrdering(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.volume = Path(temp.name); self.signing = self.volume / 'external-signing'; self.signing.mkdir()
        self.expected = dict(line.split() for line in (ROOT / 'scripts/ci/full-development-composition/expected-updater-v2.lock').read_text().splitlines())
        self.composition = SimpleNamespace(guard=Mock(), inventory=Mock(return_value=self.expected))
        self.config = dict(stage_seconds=900, verify_seconds=600, driver_seconds=1800,
                           scale={'limits':dict(root_nodes=500000, root_bytes=8*1024**3,
                               file_bytes=1024**3, package_files=500000)})
        self.driver = dict(status='PASS', commit_started=True, packages_committed=True,
            checkpoint_changed=True, committed_transactions=1, copy_cleanup='PASS-owned-workspace-removed')
        self.row = dict(termination=None, returncode=0, direct_child_reaped=True,
                       group_kill_sent=False, stdout=json.dumps(self.driver).encode())
        self.scope = SimpleNamespace(materialize=Mock(return_value={'status':'PASS','source_manifest_sha256':'a'*64}),
                                     verify=Mock(return_value={'status':'PASS','source_manifest_sha256':'a'*64}))
        self.supervision = SimpleNamespace(run=Mock(return_value=self.row))
        self.roots = SimpleNamespace(Limits=lambda **kwargs: SimpleNamespace(**kwargs))
        self.scale = SimpleNamespace(configuration=Mock())

    def execute(self, link_error=None):
        def module(name, path):
            return {'caller_stage_roots':self.roots, 'caller_upgrade_supervision':self.supervision,
                    'caller_persistent_scope':self.scope, 'caller_scale_validation':self.scale}[name]
        with patch.object(h, 'VOLUME', self.volume), patch.object(h, 'SIGNING', self.signing), \
             patch.object(h, 'configuration', return_value=self.config), patch.object(h, 'selected_links', side_effect=link_error), \
             patch.object(h, 'load', side_effect=module), patch.object(h, 'quiesce', return_value={'status':'PASS'}), \
             patch.object(h, 'driver_command', return_value=['INERT DRIVER']), \
             patch.dict(h.os.environ, CACHY_ASAHI_BOUND_UPDATE='a'*32):
            return h.run([], {'full_root_upgrade':True, 'test_signer_fingerprint':'A'*40}, self.expected,
                         Path('/inputs'), Path('/tmp/work'), self.composition)

    def test_missing_literal_selection_refuses_before_materialization_or_worker(self):
        result = self.execute(ValueError('actual87 missing'))
        self.assertEqual(result['status'], 'FAIL'); self.assertFalse(result['commit_started'])
        self.scope.materialize.assert_not_called(); self.supervision.run.assert_not_called()

    def test_complete_persistent_source_and_postcheck_are_required(self):
        result = self.execute()
        self.assertEqual(result['status'], 'PASS'); self.assertEqual(result['committed_transactions'], 1)
        self.assertFalse(result['whole_container_root'])
        self.scope.materialize.assert_called_once(); self.scope.verify.assert_called_once()
        self.supervision.run.assert_called_once()
        self.assertEqual(self.supervision.run.call_args.kwargs['output_limit'], 1024**2)
        self.assertGreater(self.scope.verify.call_args.args[-1].deadline,
                           self.scope.materialize.call_args.args[-1].deadline - 301)

    def test_source_and_stage_both_changed_cannot_receive_preservation_credit(self):
        self.scope.verify.return_value = {'status':'PASS', 'source_manifest_sha256':'b'*64}
        result = self.execute()
        self.assertEqual(result['status'], 'FAIL')
        self.assertTrue(result['commit_started']); self.assertTrue(result['packages_committed'])
        self.assertEqual(result['committed_transactions'], 1)
        self.assertNotIn('persistent_source_preserved', result)

    def test_worker_timeout_is_unknown_and_never_retried(self):
        self.row.update(termination='timeout', returncode=-9, stdout=b'')
        result = self.execute()
        self.assertEqual(result['status'], 'FAIL'); self.assertEqual(result['commit_started'], 'UNKNOWN')
        self.supervision.run.assert_called_once()

    def test_scoped_source_refusal_prevents_driver(self):
        self.scope.materialize.return_value = {'status':'FAIL'}
        result = self.execute()
        self.assertEqual(result['status'], 'FAIL'); self.supervision.run.assert_not_called()


if __name__ == '__main__': unittest.main()

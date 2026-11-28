"""Source-only controls for the Root-selected v3 launcher."""

from contextlib import nullcontext
import json
from pathlib import Path
import runpy
import sys
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


FILES = Path(__file__).resolve().parent
LAUNCHER = runpy.run_path(str(FILES / 'development-launcher-v3.py'))
SOURCE, DATA = 'a' * 40, 'b' * 40
GIT = b'SOURCE-ONLY GIT'
PACKET = b'SOURCE-ONLY PACKET'


def plan():
    return {
        'composition': 'repository-svg',
        'data_commit': DATA,
        'development_sha256': LAUNCHER['digest'](PACKET),
        'git_sha256': LAUNCHER['digest'](GIT),
        'bootstrap_v3_sha256': '3' * 64,
        'root_pins': {**dict.fromkeys(LAUNCHER['PIN_KEYS'], 'c' * 64), 'source_commit': SOURCE},
    }


def environment():
    return {'GITHUB_REPOSITORY': LAUNCHER['REPOSITORY'], 'GITHUB_SHA': SOURCE, 'GITHUB_WORKFLOW_SHA': SOURCE}


class RootPlanTests(unittest.TestCase):
    def test_missing_or_wrong_material_refuses_before_delivery(self):
        changes = (
            ('bootstrap-pin', lambda value, env: value.pop('bootstrap_v3_sha256'), 'Root-launch-plan'),
            ('original-bundle', lambda value, env: value['root_pins'].pop('original_source_sha256'), 'Root-launch-pins'),
            ('aliased-data-commit', lambda value, env: value.update(data_commit=SOURCE), 'Root-launch-pins'),
            ('legacy-composition', lambda value, env: value.update(composition='installer-preflight'), 'Root-launch-plan'),
            ('workflow-commit', lambda value, env: env.update(GITHUB_WORKFLOW_SHA=DATA), 'workflow-source'),
        )
        for name, change, reason in changes:
            with self.subTest(name=name):
                value, env = plan(), environment()
                change(value, env)
                delivery, runner = Mock(), Mock()
                with self.assertRaisesRegex(LAUNCHER['Refused'], reason):
                    LAUNCHER['launch_composed'](value, env, delivery=delivery, runner=runner)
                delivery.assert_not_called()
                runner.assert_not_called()

    def test_legacy_dependency_pin_refuses_before_later_delivery(self):
        delivery, runner = Mock(return_value=b'wrong launcher'), Mock()
        with self.assertRaisesRegex(LAUNCHER['Refused'], 'delivery-pin'):
            LAUNCHER['launch_composed'](plan(), environment(), delivery=delivery, runner=runner)
        self.assertEqual(delivery.call_count, 1)
        self.assertEqual(delivery.call_args.args[:3],
                         (SOURCE, LAUNCHER['CODE_PATHS']['launcher'], LAUNCHER['LEGACY_LAUNCHER_SHA']))
        runner.assert_not_called()

    def test_exact_legacy_dependencies_then_stale_v3_bootstrap_refuse(self):
        fetched = []

        def deliver(commit, path, expected, limit, end):
            fetched.append((commit, path))
            if path == LAUNCHER['CODE_PATHS']['bootstrap']:
                return b'stale v3 bootstrap'
            return (FILES / Path(path).name).read_bytes()

        runner = Mock()
        with self.assertRaisesRegex(LAUNCHER['Refused'], 'delivery-pin'):
            LAUNCHER['launch_composed'](plan(), environment(), delivery=deliver, runner=runner)
        self.assertEqual(fetched, [(SOURCE, LAUNCHER['CODE_PATHS'][key])
                                   for key in ('launcher', 'legacy_bootstrap', 'bootstrap')])
        runner.assert_not_called()

    def test_selection_must_bind_packet_before_workspace_or_actor(self):
        value = plan()
        selection = json.dumps({'source_files': dict.fromkeys(range(LAUNCHER['LIVE_ROWS'])),
                                'packet_sha256': '9' * 64}).encode()
        data = {name: selection if name == 'selection_sha256' else name.encode()
                for name in LAUNCHER['DATA_PATHS']}
        for name, raw in data.items():
            value['root_pins'][name] = LAUNCHER['digest'](raw)
        code = b'FIXTURE = "source only"'
        value['bootstrap_v3_sha256'] = LAUNCHER['digest'](code)
        sources = {path: data[name] for name, path in LAUNCHER['DATA_PATHS'].items()}
        sources.update({LAUNCHER['CODE_PATHS']['bootstrap']: code,
                        LAUNCHER['CODE_PATHS']['legacy_bootstrap']: (FILES / 'development-bootstrap.py').read_bytes(),
                        LAUNCHER['CODE_PATHS']['issuer']: (FILES / 'development-clock-issuer.py').read_bytes()})
        legacy = runpy.run_path(str(FILES / 'development-launcher.py'))
        legacy.update(controls=lambda end: nullcontext(), run=Mock(), select_workspace=Mock())
        legacy = SimpleNamespace(**legacy)
        globals_ = LAUNCHER['launch_composed'].__globals__
        with patch.dict(globals_, {'load_legacy': lambda *args: legacy}):
            with self.assertRaisesRegex(LAUNCHER['Refused'], 'selection-packet-binding'):
                LAUNCHER['launch_composed'](value, environment(), delivery=lambda _, path, *args: sources[path])
        legacy.select_workspace.assert_not_called()
        legacy.run.assert_not_called()


class WireTests(unittest.TestCase):
    def setUp(self):
        self.plan = plan()
        self.end = time.monotonic() + 60
        self.layout = {name: Path('/MODELED') / name for name in ('workspace', 'bootstrap', 'cache', 'output')}
        self.layout['original'] = self.layout['bootstrap'] / 'historical-source'
        self.owner = SimpleNamespace(path=self.layout['workspace'], verify=Mock())
        self.bindings = {
            'DEVELOPMENT_' + prefix + suffix: '/MODELED/' + prefix if suffix == '_PATH' else 'd' * 64
            for prefix in ('CLOCK', 'EXECUTION_GRANT', 'RUNTIME_CONTRACT') for suffix in ('_PATH', '_SHA256')
        }
        self.verified = {
            'selected_rows_verified': LAUNCHER['LIVE_ROWS'], 'packet_sha256': self.plan['development_sha256'],
            'metadata_pins': {path: digit * 64 for path, digit in zip(LAUNCHER['METADATA'].values(), '123')},
        }

    def test_controller_argv_uses_v3_packet_and_historical_metadata(self):
        entry = time.monotonic()
        argv = LAUNCHER['controller_argv'](self.plan, self.layout, self.verified, self.bindings, entry)
        self.assertEqual(argv[:5], [sys.executable, '-E', '-s', '-B', str(
            self.layout['workspace'] / 'scripts/ci/development/controller.py')])
        flags = dict(zip(argv[5::2], argv[6::2]))
        self.assertEqual(len(flags), len(argv[5::2]))
        self.assertEqual(flags['--packet'], str(self.layout['workspace'] / LAUNCHER['PACKET_PATH']))
        self.assertEqual(flags['--original-source-root'], str(self.layout['original']))
        self.assertEqual(flags['--controller-entry-monotonic'], repr(entry))
        self.assertEqual(flags['--composition'], 'repository-svg')
        for flag, path in LAUNCHER['METADATA'].items():
            self.assertEqual(flags['--' + flag + '-sha256'], self.verified['metadata_pins'][path])
        self.assertNotIn('--check-only', flags)

    def test_refused_candidate_cannot_form_controller_argv(self):
        changes = (
            ({'original': self.layout['workspace'] / 'old'}, {}, 'original-source-path'),
            ({'original': Path('/MODELED')}, {}, 'original-source-path'),
            ({}, {'packet_sha256': '9' * 64}, 'development-packet-binding'),
            ({}, {'selected_rows_verified': 258}, 'development-packet-binding'),
            ({}, {'metadata_pins': {}}, 'development-packet-binding'),
        )
        for path_changes, result_changes, reason in changes:
            with self.subTest(path_changes=path_changes, result_changes=result_changes):
                with self.assertRaisesRegex(LAUNCHER['Refused'], reason):
                    LAUNCHER['controller_argv'](self.plan, {**self.layout, **path_changes},
                        {**self.verified, **result_changes}, self.bindings, time.monotonic())

    def test_checkout_accepts_only_the_exact_three_data_paths(self):
        legacy = SimpleNamespace(read_bootstrap=Mock(return_value=(GIT, object(), None)),
                                 git_environment=lambda prepared: {'SOURCE_ONLY': '1'})
        prepared = {'paths': self.layout, 'workspace_owner': self.owner}
        paths = list(LAUNCHER['DATA_PATHS'].values())
        data_diff = lambda names: ('\n'.join(names) + '\n').encode()
        runner = Mock(side_effect=[(0, b'')] * 3 + [(0, data_diff(paths))] + [(0, b''), (0, SOURCE.encode())])
        LAUNCHER['checkout'](legacy, None, prepared, self.plan, self.end, runner)
        self.assertEqual(runner.call_count, 6)
        self.owner.verify.assert_any_call(self.end, empty=True)
        for names in (paths[:-1], paths + ['scripts/changed.py'], paths[:-1] + [paths[0]]):
            runner = Mock(side_effect=[(0, b'')] * 3 + [(0, data_diff(names))])
            with self.subTest(names=names), self.assertRaisesRegex(LAUNCHER['Refused'], 'data-only-tree-required'):
                LAUNCHER['checkout'](legacy, None, prepared, self.plan, self.end, runner)
            self.assertEqual(runner.call_count, 4)

    def test_even_rebound_packet_requires_v3_selection_and_original_pins(self):
        hashes = self.verified['metadata_pins']
        binding = {'source_files': {'sample.py': 'live'}, 'metadata_pins': {'sample.py': 'live'},
                   'original_source': {'integration_lock_sha256': hashes[LAUNCHER['METADATA']['integration']]}}
        selected = json.dumps(binding).encode()
        rows = {key: {'sha256': value} for key, value in hashes.items()}
        packet = {'schema_version': 3, 'composition': 'repository-svg', 'initial_source_files': rows, **binding}
        decoder = SimpleNamespace(decode=json.loads)

        def verify(value, verified=self.verified):
            raw = json.dumps(value).encode()
            active = dict(self.plan, development_sha256=LAUNCHER['digest'](raw))
            LAUNCHER['bind_packet'](decoder, raw, selected, verified, active)

        verify(packet)
        for wrong in ({'schema_version': 2}, {'composition': 'installer-preflight'},
                      {'metadata_pins': {}}, {'original_source': {}}):
            with self.subTest(wrong=wrong), self.assertRaisesRegex(LAUNCHER['Refused'], 'development-packet-selection'):
                verify({**packet, **wrong})
        with self.assertRaisesRegex(LAUNCHER['Refused'], 'development-packet-invocation'):
            verify(packet, {**self.verified, 'metadata_pins': {}})

    def test_prepared_source_refusal_retires_before_controller_spawn(self):
        owned = SimpleNamespace(verify=Mock())
        prepared = {'paths': self.layout, 'owned': owned,
                    'execution_grant': ('/MODELED/grant', '5' * 64),
                    'runtime_contract': ('/MODELED/runtime', '6' * 64)}
        bootstrap = SimpleNamespace(prepare=Mock(return_value=prepared), verify_checkout=Mock(return_value=self.verified))
        legacy = SimpleNamespace(defer_controls=nullcontext, clock=Mock(return_value=(self.end, self.end + 20)),
                                 read_bootstrap=Mock(return_value=(b'wrong packet', None, None)), retire=Mock(return_value=[]))
        issuer = SimpleNamespace(issue=Mock(return_value=self.bindings))
        runner, checkout = Mock(), Mock()
        globals_ = LAUNCHER['_launch'].__globals__
        with patch.dict(globals_, {'checkout': checkout}), patch.object(globals_['signal'], 'setitimer'):
            with self.assertRaisesRegex(LAUNCHER['Refused'], 'development-packet-pin'):
                LAUNCHER['_launch'](legacy, (None, bootstrap, issuer), (b'one', b'two', b'three'),
                                    self.plan, environment(), self.end, runner, self.owner)
        runner.assert_not_called()
        checkout.assert_called_once()
        legacy.retire.assert_called_once_with(owned)

    def test_modeled_dispatch_keeps_bootstrap_custody_and_original_cutoff(self):
        hashes = self.verified['metadata_pins']
        binding = {'source_files': {'sample.py': 'live'}, 'metadata_pins': {'sample.py': 'live'},
                   'original_source': {'integration_lock_sha256': hashes[LAUNCHER['METADATA']['integration']]}}
        selected = json.dumps(binding).encode()
        rows = {key: {'sha256': value} for key, value in hashes.items()}
        packet = {'schema_version': 3, 'composition': 'repository-svg', 'initial_source_files': rows, **binding}
        raw = json.dumps(packet).encode()
        packet_pin = LAUNCHER['digest'](raw)
        value = {**self.plan, 'development_sha256': packet_pin}
        verified = {**self.verified, 'packet_sha256': packet_pin}
        owned = SimpleNamespace(verify=Mock())
        prepared = {'paths': self.layout, 'owned': owned,
                    'execution_grant': ('/MODELED/grant', '5' * 64),
                    'runtime_contract': ('/MODELED/runtime', '6' * 64)}
        bootstrap = SimpleNamespace(prepare=Mock(return_value=prepared), verify_checkout=Mock(return_value=verified))
        legacy = SimpleNamespace(defer_controls=nullcontext, clock=Mock(return_value=(self.end, self.end + 20)),
                                 read_bootstrap=Mock(return_value=(raw, None, None)), retire=Mock(return_value=[]))
        fixture_issuer = SimpleNamespace(issue=Mock(return_value=self.bindings))
        runner, checkout = Mock(return_value=(3, b'')), Mock()
        decoder = SimpleNamespace(decode=json.loads)
        globals_ = LAUNCHER['_launch'].__globals__
        with patch.dict(globals_, {'checkout': checkout}), patch.object(globals_['signal'], 'setitimer'):
            result = LAUNCHER['_launch'](legacy, (decoder, bootstrap, fixture_issuer), (selected, b'peer', b'history'),
                                         value, environment(), self.end, runner, self.owner)
        self.assertEqual((result['controller_exit_code'], result['retained_cutoff']), (3, self.end))
        argv, child, cwd, workflow_end = runner.call_args.args
        flags = dict(zip(argv[5::2], argv[6::2]))
        self.assertEqual(flags['--original-source-root'], str(self.layout['original']))
        self.assertEqual(flags['--packet'], str(self.layout['workspace'] / LAUNCHER['PACKET_PATH']))
        self.assertEqual(child['DEVELOPMENT_CLOCK_PATH'], self.bindings['DEVELOPMENT_CLOCK_PATH'])
        self.assertEqual(cwd, str(self.owner.path))
        self.assertEqual(workflow_end, self.end + 20)
        self.assertEqual(runner.call_args.kwargs, {'spawn_deadline': self.end, 'workspace_owner': self.owner})
        legacy.retire.assert_called_once_with(owned)


if __name__ == '__main__':
    unittest.main()

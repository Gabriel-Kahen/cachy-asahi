#!/usr/bin/env python3
"""Inert caller routing controls; no retained native fixture or Docker required."""
import ast
import importlib.util
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


outer = load('upgrade_outer_route', HERE / 'run.py')
inner = load('upgrade_inner_route', HERE / 'container.py')


class UpgradeRoute(unittest.TestCase):
    def setUp(self):
        self.expected = {'initial': '1'}
        self.plan = {'full_root_upgrade': True, 'setup4': {'package': {}}}
        self.hook = SimpleNamespace(run=Mock(return_value={'status': 'PASS'}))

    def invoke(self):
        return inner.upgrade(['pacman'], self.plan, self.expected, Path('/inputs'), Path('/work'))

    def test_hook_exact_binding_and_preserved_source(self):
        with patch.object(inner, 'load', return_value=self.hook) as loader, patch.object(inner, 'inventory', return_value=self.expected):
            self.assertEqual(self.invoke(), {'status': 'PASS'})
        loader.assert_called_once_with('composition_full_root_upgrade', Path('/upgrade-hook.py'))
        self.hook.run.assert_called_once_with(['pacman'], self.plan, self.expected, Path('/inputs'), Path('/work'), inner)

    def test_failed_hook_refuses(self):
        self.hook.run.return_value = {'status': 'FAIL'}
        with patch.object(inner, 'load', return_value=self.hook), patch.object(inner, 'inventory') as inventory:
            with self.assertRaisesRegex(inner.UpgradeFailure, 'did not pass') as caught: self.invoke()
            self.assertEqual(caught.exception.evidence, {'status': 'FAIL'})
            inventory.assert_not_called()

    def test_postcommit_failure_retains_full_hook_truth(self):
        self.hook.run.return_value = {'status': 'FAIL', 'commit_started': True, 'packages_committed': True,
                                     'committed_transactions': 1, 'copy_cleanup': 'UNKNOWN'}
        with patch.object(inner, 'load', return_value=self.hook), patch.object(inner, 'inventory'):
            with self.assertRaises(inner.UpgradeFailure) as caught: self.invoke()
        self.assertEqual(caught.exception.evidence, self.hook.run.return_value)

    def test_source_drift_refuses(self):
        with patch.object(inner, 'load', return_value=self.hook), patch.object(inner, 'inventory', return_value={'changed': '2'}):
            with self.assertRaisesRegex(ValueError, 'source inventory changed'): self.invoke()

    def test_legacy_modes_refuse_before_hook(self):
        for key in ('measurement_only', 'footprint', 'lifecycle', 'updater_v2'):
            with self.subTest(key=key), patch.object(inner, 'load') as loader:
                self.plan[key] = True
                with self.assertRaisesRegex(ValueError, 'dedicated'): self.invoke()
                loader.assert_not_called()
                del self.plan[key]
        for key in ('setup4', 'full_root_upgrade'):
            plan = self.plan.copy(); del plan[key]
            with patch.object(inner, 'load') as loader:
                with self.assertRaises(ValueError): inner.upgrade([], plan, {}, None, None)
                loader.assert_not_called()

    def test_initial_install_precedes_hook_and_ownership(self):
        tree = ast.parse((HERE / 'container.py').read_text())
        main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
        calls = {name: [n.lineno for n in ast.walk(main) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == name]
                 for name in ('install', 'upgrade')}
        self.assertEqual(len(calls['install']), 1)
        self.assertEqual(len(calls['upgrade']), 1)
        source = (HERE / 'container.py').read_text()
        self.assertLess(calls['install'][0], calls['upgrade'][0])
        self.assertLess(calls['upgrade'][0], source[:source.index("result['phase'] = 'installed-dependencies-and-ownership'")].count('\n') + 1)
        self.assertNotIn('setup4.run(', source)
        self.assertNotIn('measure_only(', source)


class OuterRoute(unittest.TestCase):
    def test_mounts_budgets_environment_and_no_legacy_route(self):
        args = SimpleNamespace(upgrade_code=Path('/freeze'), upgrade_config=Path('/config.json'), setup4_pair=Path('/pair'))
        argv = outer.container_args(args, Path('/in'), Path('/public'), Path('/private'), 'container', 'volume')
        mounts = [argv[i + 1] for i, value in enumerate(argv) if value == '--mount']
        bytarget = {next(v[4:] for v in row.split(',') if v.startswith('dst=')): row for row in mounts}
        self.assertEqual(len(bytarget), len(mounts))
        for target in ('/inputs', '/runner.py', '/upgrade-code', '/upgrade-config.json', '/upgrade-pair', '/upgrade-hook.py', '/persistent_scope.py', '/setup4.py', '/footprint.py', '/measurement-source'):
            self.assertTrue(bytarget[target].endswith(',readonly'), target)
        self.assertEqual(bytarget['/upgrade-signing'], 'type=bind,src=/private/test-signing,dst=/upgrade-signing')
        self.assertEqual(bytarget['/measurement'], 'type=volume,src=volume,dst=/measurement,volume-nocopy')
        self.assertEqual(bytarget['/out'], 'type=bind,src=/public,dst=/out')
        self.assertIn('--network=none', argv)
        self.assertIn('--cap-drop=ALL', argv)
        for cap in ('SYS_CHROOT', 'FSETID', 'KILL'): self.assertIn('--cap-add=' + cap, argv)
        self.assertIn('--env=PATH=/usr/bin:/bin', argv)
        self.assertEqual(sum(v.startswith('--env=CACHY_ASAHI_BOUND_UPDATE=') for v in argv), 1)
        self.assertFalse(any('setup_trial' in v or '/lifecycle.py' in v for v in argv))

    def test_absolute_input_bounds(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); ordinary = root / 'file'; ordinary.write_text('{}')
            self.assertEqual(outer.absolute_input(ordinary), ordinary)
            self.assertEqual(outer.absolute_input(root, directory=True), root)
            link = root / 'link'; link.symlink_to(ordinary)
            for path in (Path('relative'), link, root):
                with self.subTest(path=path), self.assertRaises(AssertionError): outer.absolute_input(path)
            unsafe = root / 'comma,file'; unsafe.write_text('{}')
            with self.assertRaises(AssertionError): outer.absolute_input(unsafe)

    def test_preparation_binding_and_config_before_actors(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prep = root / 'prep'; (prep / 'scripts/ci/full-development-composition').mkdir(parents=True)
            caller = root / 'caller'; caller.mkdir()
            for name in ('container.py', 'upgrade_hook.py', 'persistent_scope.py'): (caller / name).write_text('')
            config = root / 'config.json'; config.write_text('{}')
            args = SimpleNamespace(preparation_source=prep, upgrade_code=root, upgrade_config=config, setup4_pair=root)
            with patch.object(outer, 'CALLER', caller), patch.object(outer, 'HERE'), patch.object(outer.subprocess, 'check_output', return_value=outer.PREPARATION_SOURCE + '\n') as query:
                outer.configure_inputs(args)
                self.assertEqual(outer.HERE, prep / 'scripts/ci/full-development-composition')
                query.assert_called_once()
                config.write_text('[]')
                with self.assertRaises(AssertionError): outer.configure_inputs(args)
                config.write_text('x' * (1024**2 + 1))
                with self.assertRaisesRegex(AssertionError, 'bounded'): outer.configure_inputs(args)
            with patch.object(outer.subprocess, 'check_output', return_value='0' * 40):
                with self.assertRaises(AssertionError): outer.configure_inputs(args)

    def test_retirement_refuses_volume_until_container_absent(self):
        with tempfile.TemporaryDirectory() as directory:
            owned = Path(directory) / 'owned.json'
            owned.write_text('{"container":"owned-container","footprint_volume":"owned-volume"}')
            cleaner = SimpleNamespace(remove_volume=Mock())
            result = {}
            with patch.object(outer.subprocess, 'run'), patch.object(outer.subprocess, 'check_output', return_value=b'container-still-present'), patch.object(outer, 'module', return_value=cleaner):
                failures = outer.retire_outer(owned, result)
            self.assertIn('container-absence', failures)
            self.assertIn('owned-footprint-volume', failures)
            cleaner.remove_volume.assert_not_called()
            with patch.object(outer.subprocess, 'run'), patch.object(outer.subprocess, 'check_output', return_value=b''), patch.object(outer, 'module', return_value=cleaner):
                self.assertEqual(outer.retire_outer(owned, result), [])
            cleaner.remove_volume.assert_called_once_with('owned-volume')
            self.assertEqual(result['upgrade_volume_cleanup'], 'PASS-absence-verified')
            cleaner.remove_volume.side_effect = ValueError('absence unverified')
            with patch.object(outer.subprocess, 'run'), patch.object(outer.subprocess, 'check_output', return_value=b''), patch.object(outer, 'module', return_value=cleaner):
                self.assertEqual(outer.retire_outer(owned, {}), ['owned-footprint-volume'])

    def test_workflow_fixed_preparation_and_retained_seed(self):
        text = (HERE / 'workflow.yml').read_text()
        for pin in (outer.PREPARATION_SOURCE, '04a4a74e16e1e1bc939ea74791bf1f1bf7b46bbd',
                    'a7857658af224984065e575f6ffed8308ea85027d46eace8bda146d9033e93b3',
                    'a388c8c8ba8e06cb92fd2be598b86e433c4e403b6e71a0f15b1eaec381bb7300'):
            self.assertIn(pin, text)
        for arg in ('--preparation-source', '--upgrade-code', '--upgrade-config', '--setup4-pair', '--updater-v2-source'):
            self.assertIn(arg, text)
        self.assertNotIn('--measure-footprint', text)
        self.assertIn('ref: ${{ inputs.source }}', text)
        self.assertIn('composition-preparation/scripts/ci/full-development-composition/retained/setup4-pair.tar.xz', text)


if __name__ == '__main__': unittest.main()

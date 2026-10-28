# SPDX-License-Identifier: MIT
import hashlib
import ast
import builtins
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import time
import unittest
from unittest.mock import patch

import entry as e


def signal_graph_probe(poison=False, fail=False):
    """Owned isolated child only: actual graph setup, never runtime actors."""
    import _signal
    import importlib.util
    import signal
    numbers = (signal.SIGINT, signal.SIGTERM, signal.SIGALRM)
    getter, setter = _signal.getsignal, _signal.signal
    originals = {number: getter(number) for number in numbers}
    original_module = sys.modules['_signal']
    original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
    original_pending = signal.sigpending()
    original_timer = signal.getitimer(signal.ITIMER_REAL)
    assert original_timer == (0.0, 0.0)
    assert original_module is _signal is signal._signal
    assert _signal.__spec__.origin == 'built-in'
    assert getter.__self__ is _signal and e.machinery.BuiltinImporter.find_spec('_signal').origin == 'built-in'
    root = Path(e.__file__).resolve().parents[3]
    path = root/'scripts/ci/development/test_repository_handoff.py'
    spec = importlib.util.spec_from_file_location('owned_signal_graph_fixture', path)
    fixture = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = fixture
    spec.loader.exec_module(fixture)
    graph = DependencyGraphTests()
    graph.setUp()
    callbacks, result, calls = [], {}, []
    def interrupt(number, frame):
        callbacks.append(number)
        raise KeyboardInterrupt()
    def observed():
        return [getter(number) is interrupt and signal.getsignal(number) is interrupt for number in numbers]
    fake = types.ModuleType('_signal')
    fake.__spec__ = types.SimpleNamespace(origin='built-in')
    def forbidden(*args):
        calls.append('foreign builtin callback')
        raise AssertionError('foreign _signal executed')
    fake.getsignal = fake.signal = forbidden
    cleanup_done = False
    try:
        # Existing Sources.module checks still refuse an unlabelled pre-entry
        # fake. A forged pre-entry bootstrap is outside its trust precondition.
        unlabelled = types.ModuleType('_signal')
        source = fixture.adapter.Sources.__new__(fixture.adapter.Sources)
        source.root = root
        rel = 'scripts/port/repository-native-handoff/entry.py'
        source.raw = {rel: (root/rel).read_bytes()}
        sys.modules['_signal'] = unlabelled
        try:
            source.module('unlabelled_signal_entry', rel)
            result['unlabelled_preentry_refused'] = False
        except fixture.adapter.Refused:
            result['unlabelled_preentry_refused'] = True
        finally:sys.modules['_signal'] = original_module
        loaded = source.module('trusted_signal_entry', rel)
        result['entry_keeps_genuine_builtin'] = loaded.BOOTSTRAP.get('_signal') is _signal
        runtime, _ = e.authenticated(root/'scripts/port/repository-native-handoff/source-map.json',
            hashlib.sha256((root/'scripts/port/repository-native-handoff/source-map.json').read_bytes()).hexdigest(),
            source_root=root/'scripts/port/repository-native-handoff', deadline=time.monotonic()+20)
        for number in numbers:setter(number, interrupt)
        result['before_graph'] = observed()
        if poison:sys.modules['_signal'] = fake
        graph.load('collector', module=loaded);graph.load('phase', module=loaded)
        result['after_graph'] = observed()
        result['postentry_cache_slot_restored'] = sys.modules['_signal'] is (fake if poison else original_module)
        target = graph.root/e.COLLECTOR_ROOT/'common.py';held = target.read_bytes()
        target.write_bytes(held + b'\n# unrelated ungranted fixture change\n')
        try:
            graph.load('phase', module=loaded)
            result['unrelated_source_drift_refused'] = False
        except ValueError as error:
            result['unrelated_source_drift_error'] = str(error)
            result['unrelated_source_drift_refused'] = str(error) == 'source-bytes-mode'
        finally:target.write_bytes(held)
        if fail:raise RuntimeError('owned-probe-failure')
        try:
            with runtime['supervisor'].handlers(lambda *_: None):pass
            result['supervisor_error'] = None
        except BaseException as error:
            result['supervisor_error'] = type(error).__name__
        result['after_supervisor'] = observed()
        result['fixture_cleanup_errors'] = 0 if graph.doCleanups() else 1
        cleanup_done = True
        result['after_cleanup'] = observed()
        result['mask_pending_timer_held'] = (
            signal.pthread_sigmask(signal.SIG_BLOCK, set()) == original_mask and
            signal.sigpending() == original_pending and signal.getitimer(signal.ITIMER_REAL) == original_timer)
    except RuntimeError as error:
        if not fail or str(error) != 'owned-probe-failure':raise
        result['deliberate_failure_observed'] = 'RuntimeError'
    finally:
        try:
            if not cleanup_done:result['fixture_cleanup_errors'] = 0 if graph.doCleanups() else 1
        finally:
            result['foreign_callbacks'] = calls
            result['signals_observed'] = callbacks
            result['mask_pending_timer_held'] = (
                signal.pthread_sigmask(signal.SIG_BLOCK, set()) == original_mask and
                signal.sigpending() == original_pending and signal.getitimer(signal.ITIMER_REAL) == original_timer)
            sys.modules['_signal'] = original_module
            for number, original in originals.items():setter(number, original)
            signal.setitimer(signal.ITIMER_REAL, *original_timer)
            signal.pthread_sigmask(signal.SIG_SETMASK, original_mask)
            result['original_handlers_restored'] = all(getter(n) is old for n, old in originals.items())
            result['original_mask_pending_timer_restored'] = (
                signal.pthread_sigmask(signal.SIG_BLOCK, set()) == original_mask and
                signal.sigpending() == original_pending and signal.getitimer(signal.ITIMER_REAL) == original_timer)
            assert result['original_handlers_restored'] and result['original_mask_pending_timer_restored']
            sys.modules.pop(spec.name, None)
    return result


class SignalLoaderTests(unittest.TestCase):
    def test_actual_graph_retains_custom_callbacks_and_quarantines_postentry_builtin_poison(self):
        script = '''import importlib.util,json,sys
from pathlib import Path
path=Path(sys.argv[1]);sys.path.insert(0,str(path.parent))
spec=importlib.util.spec_from_file_location('owned_signal_entry_tests',path)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
print(json.dumps(module.signal_graph_probe(sys.argv[2]=='poison',sys.argv[2]=='failure'),sort_keys=True))
'''
        with tempfile.TemporaryDirectory(prefix='signal-loader-') as temporary:
            env = dict(PATH='/usr/bin:/bin', HOME=temporary, TMPDIR=temporary, LC_ALL='C')
            for mode in ('ordinary', 'poison', 'failure'):
                with self.subTest(mode=mode):
                    completed = subprocess.run([sys.executable, '-I', '-B', '-S', '-c', script,
                        str(Path(__file__).resolve()), mode], cwd=temporary, env=env,
                        capture_output=True, timeout=90)
                    self.assertEqual(completed.returncode, 0, completed.stderr.decode(errors='replace'))
                    self.assertLess(len(completed.stdout) + len(completed.stderr), 1024**2)
                    result = json.loads(completed.stdout)
                    keys = ('before_graph', 'after_graph') if mode == 'failure' else ('before_graph', 'after_graph', 'after_supervisor', 'after_cleanup')
                    for key in keys:
                        self.assertEqual(result[key], [True, True, True], result)
                    for key in ('entry_keeps_genuine_builtin', 'unlabelled_preentry_refused',
                                'postentry_cache_slot_restored', 'mask_pending_timer_held',
                                'original_handlers_restored', 'original_mask_pending_timer_restored',
                                'unrelated_source_drift_refused'):
                        self.assertIs(result[key], True, result)
                    if mode == 'failure':self.assertEqual(result['deliberate_failure_observed'], 'RuntimeError')
                    else:self.assertIsNone(result['supervisor_error'])
                    self.assertEqual(result['fixture_cleanup_errors'], 0)
                    self.assertEqual(result['foreign_callbacks'], [])
                    self.assertEqual(result['signals_observed'], [])


class EntryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.rows = {}
        for name in e.SOURCES:
            raw = (Path(e.__file__).parent / name).read_bytes()
            (self.root / name).write_bytes(raw); (self.root / name).chmod(0o644)
            self.rows[name] = {'sha256': hashlib.sha256(raw).hexdigest(), 'mode': 0o644}
        self.map = self.root / 'source-map.json'
        self.raw = (json.dumps(self.rows, sort_keys=True, indent=2) + '\n').encode()
        self.map.write_bytes(self.raw)
        self.pin = hashlib.sha256(self.raw).hexdigest()
    def test_exact_seven_source_preflight_and_no_pyc(self):
        modules, rows = e.authenticated(self.map, self.pin, source_root=self.root, deadline=time.monotonic() + 20)
        self.assertEqual(set(modules), set(e.MODULES)); self.assertEqual(rows, self.rows)
        self.assertEqual(list(self.root.rglob('*.pyc')), [])
        self.assertEqual(len(rows), 7)
    def test_predecessor_five_source_map_refuses_before_compile(self):
        old = {name: row for name, row in self.rows.items() if name not in ('transport.py', 'supervisor.py')}
        raw = (json.dumps(old, sort_keys=True) + '\n').encode(); self.map.write_bytes(raw)
        with patch.object(e, 'compile_modules') as compiled, self.assertRaises(ValueError):
            e.authenticated(self.map, hashlib.sha256(raw).hexdigest(), source_root=self.root, deadline=time.monotonic() + 20)
        compiled.assert_not_called()
    def test_services_are_inert_and_added_supervision_cannot_renew(self):
        modules, rows = e.authenticated(self.map, self.pin, source_root=self.root, deadline=time.monotonic() + 20)
        end = time.monotonic() + 40
        with patch.object(modules['transport'], 'DockerTransport') as transport, \
             patch.object(modules['supervisor'], 'RoleSupervisor') as supervisor:
            services = e.services(modules, rows, source_root=self.root, private_root=self.root / 'private',
                job_deadline=end, cli_sha256='a' * 64, endpoint_identity=[0] * 6, env={})
            transport.assert_called_once(); supervisor.assert_not_called()
            first = services['supervise_factory'](end - 1)
            self.assertIs(first, supervisor.return_value)
            with self.assertRaises(ValueError): services['supervise_factory'](end)
            supervisor.assert_called_once()
            guard = supervisor.call_args.kwargs['source_guard']
            target = self.root / 'producer.py'; target.chmod(0o755)
            with self.assertRaises(ValueError): guard()
    def original_fixture(self):
        original = self.root / 'original'; rows = {}
        names = [*e.ORIGINAL.values(), *(f'inert/{index}.py' for index in range(159-len(e.ORIGINAL)))]
        for name in names:
            path = original / name; path.parent.mkdir(parents=True, exist_ok=True)
            raw = b'# inert original source fixture; no actors\n'
            path.write_bytes(raw); path.chmod(0o644)
            rows[name] = {'sha256': hashlib.sha256(raw).hexdigest(), 'mode': 0o644}
        lock = original / 'lock.json'; raw = json.dumps({'source_files': rows}, sort_keys=True).encode()
        lock.write_bytes(raw)
        return original, lock, hashlib.sha256(raw).hexdigest(), original / names[0]
    def test_real_supervisor_factory_guard_refuses_changed_closure_before_fork(self):
        modules, rows = e.authenticated(self.map, self.pin, source_root=self.root, deadline=time.monotonic()+20)
        end = time.monotonic()+120
        with patch.object(modules['transport'], 'DockerTransport'):
            services = e.services(modules, rows, source_root=self.root, private_root=self.root/'private',
                job_deadline=end, cli_sha256='a'*64, endpoint_identity=[0]*6, env={})
            actor = services['supervise_factory'](end-1)
        self.assertEqual(actor.receipts, [])
        (self.root/'producer.py').chmod(0o755)
        with patch.object(modules['supervisor'].os, 'fork') as forked, self.assertRaises(ValueError):
            # This real captured broker function is never invoked: the changed
            # closure must refuse before the supervisor creates a child.
            actor('bind-metadata', modules['broker'].identity, deadline=time.monotonic()+90)
        forked.assert_not_called()
    def test_original_postexecution_mode_and_inode_changes_refuse_and_restore(self):
        original, lock, pin, target = self.original_fixture()
        saved = {name: sys.modules.get(name) for name in e.ORIGINAL}
        with self.assertRaisesRegex(ValueError, 'original-source-drift'):
            with e.original_modules(original, lock, pin, deadline=time.monotonic()+10,
                                    verification_deadline=time.monotonic()+10):
                target.chmod(0o755)
        self.assertEqual({name: sys.modules.get(name) for name in e.ORIGINAL}, saved)
        target.chmod(0o644)
        with self.assertRaisesRegex(ValueError, 'original-source-drift'):
            with e.original_modules(original, lock, pin, deadline=time.monotonic()+10,
                                    verification_deadline=time.monotonic()+10):
                before = target.stat().st_ino
                alternate = target.with_name('replacement.py'); alternate.write_bytes(target.read_bytes()); alternate.chmod(0o644)
                os.replace(alternate, target)
                self.assertNotEqual(before, target.stat().st_ino)
        self.assertEqual({name: sys.modules.get(name) for name in e.ORIGINAL}, saved)
    def test_original_postexecution_boundary_on_failed_actor_and_expired_cutoff(self):
        original, lock, pin, target = self.original_fixture()
        with self.assertRaisesRegex(ValueError, 'original-source-drift'):
            with e.original_modules(original, lock, pin, deadline=time.monotonic()+10,
                                    verification_deadline=time.monotonic()+10):
                target.chmod(0o755)
                raise RuntimeError('MODELED actor failed')
        target.chmod(0o644)
        with self.assertRaisesRegex(ValueError, 'source-deadline'):
            with e.original_modules(original, lock, pin, deadline=time.monotonic()+10, verification_deadline=-1):
                pass
    def test_original_unchanged159_and_initial_mode_drift(self):
        original, lock, pin, target = self.original_fixture()
        with e.original_modules(original, lock, pin, deadline=time.monotonic()+10,
                                verification_deadline=time.monotonic()+10) as modules:
            self.assertEqual(set(modules), set(e.ORIGINAL))
        target.chmod(0o755)
        with self.assertRaisesRegex(ValueError, 'source-bytes-mode'):
            with e.original_modules(original, lock, pin, deadline=time.monotonic()+10,
                                    verification_deadline=time.monotonic()+10):
                self.fail('initial mutation must refuse before actor boundary')
    def test_original_postexecution_bytes_and_links_refuse(self):
        original, lock, pin, target = self.original_fixture()
        raw = target.read_bytes()
        with self.assertRaisesRegex(ValueError, 'original-source-drift'):
            with e.original_modules(original, lock, pin, deadline=time.monotonic()+10,
                                    verification_deadline=time.monotonic()+10):
                target.write_bytes(raw + b'# modified bytes\n')
        target.write_bytes(raw)
        for kind in ('symlink', 'hardlink'):
            alternate = target.with_name('saved.py'); alternate.write_bytes(raw); alternate.chmod(0o644)
            with self.subTest(kind=kind), self.assertRaises((ValueError, OSError)):
                with e.original_modules(original, lock, pin, deadline=time.monotonic()+10,
                                        verification_deadline=time.monotonic()+10):
                    target.unlink()
                    if kind == 'symlink': target.symlink_to(alternate)
                    else: os.link(alternate, target)
            target.unlink(); alternate.unlink(); target.write_bytes(raw); target.chmod(0o644)
    def test_source_byte_mode_and_map_drift_refuse(self):
        (self.root / 'capture.py').chmod(0o755)
        with self.assertRaises(ValueError): e.authenticated(self.map, self.pin, source_root=self.root, deadline=time.monotonic() + 20)
        (self.root / 'capture.py').chmod(0o644)
        (self.root / 'capture.py').write_bytes(b'raise AssertionError("must not execute")\n')
        with self.assertRaises(ValueError): e.authenticated(self.map, self.pin, source_root=self.root, deadline=time.monotonic() + 20)
        with self.assertRaises(ValueError): e.authenticated(self.map, '0' * 64, source_root=self.root, deadline=time.monotonic() + 20)
    def test_expired_source_cutoff_refuses_before_map_read(self):
        with patch.object(e.os, 'open') as opened, self.assertRaises(ValueError):
            e.authenticated(self.map, self.pin, source_root=self.root, deadline=-1)
        opened.assert_not_called()
    def test_symlink_and_hardlink_sources_refuse(self):
        path = self.root / 'capture.py'; saved = self.root / 'saved'; path.rename(saved); path.symlink_to(saved)
        with self.assertRaises(OSError): e.authenticated(self.map, self.pin, source_root=self.root, deadline=time.monotonic() + 20)
        path.unlink(); os.link(saved, path)
        with self.assertRaises(ValueError): e.authenticated(self.map, self.pin, source_root=self.root, deadline=time.monotonic() + 20)
    def test_poisoned_cached_project_module_cannot_execute(self):
        poisoned = types.ModuleType('capture'); poisoned.digest = lambda _: 'fake'
        with patch.dict(sys.modules, {'capture': poisoned}):
            modules, _ = e.authenticated(self.map, self.pin, source_root=self.root, deadline=time.monotonic() + 20)
        self.assertEqual(modules['capture'].digest(b'x'), hashlib.sha256(b'x').hexdigest())
    def test_poisoned_stdlib_origin_refuses(self):
        poisoned = types.ModuleType('threading')
        with patch.dict(sys.modules, {'threading': poisoned}), self.assertRaises(ValueError):
            e.authenticated(self.map, self.pin, source_root=self.root, deadline=time.monotonic() + 20)
    def test_cli_requires_isolation_and_is_actor_free(self):
        command = [sys.executable, '-I', '-B', '-S', str(self.root / 'entry.py'),
                   '--source-map', str(self.map), '--source-map-sha256', self.pin]
        result = subprocess.run(command, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(json.loads(result.stdout)['actors'], 'NOT RUN')
        result = subprocess.run([sys.executable, '-B', '-S', *command[4:]], capture_output=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)


class DependencyGraphTests(unittest.TestCase):
    """Load actual copied, pinned sources; never invoke a package/native actor."""
    PINS = {'collector': '26eeddc56574c5475df67841c1ac8120900deabe1478f6d1fa7cd290f64f63a9',
            'phase': '5718ca6cda60d7f6c02952cba7e92ff46666e20f8252ce7c1cdf722825ec2e43'}
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = Path(e.__file__).resolve().parents[3]
        self.prefixes = {'collector': e.COLLECTOR_ROOT, 'phase': e.PHASE_ROOT}
        self.manifests = {}
        self.files = []
        for role, prefix in self.prefixes.items():
            raw = (self.repo / prefix / 'source-map.json').read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), self.PINS[role])
            self.manifests[role] = json.loads(raw)
            names = [prefix + '/' + name for name in self.manifests[role]]
            self.files.extend(names)
            for name in [prefix + '/source-map.json', *names]: self.copy(name)
        for name in e.PREDECESSORS:
            self.copy(name); self.files.append(name)
        self.bind_current_fixture_predecessors()
    def bind_current_fixture_predecessors(self):
        """Synthetic fixture pins only; never rebase an accepted runtime graph."""
        self.PINS = dict(self.PINS)
        fixed = ('scripts/release/release.py', 'scripts/client/client.py')
        orchestrator = self.root/e.COLLECTOR_ROOT/'orchestrator.py'
        declarations = e.literals(orchestrator.read_bytes(), ('HELD', 'DEPENDENCIES'))
        self.assertEqual(set(declarations['DEPENDENCIES']), set(fixed))
        pairs = [(declarations['DEPENDENCIES'][name], hashlib.sha256((self.root/name).read_bytes()).hexdigest()) for name in fixed]
        historical = self.root/'scripts/port/repository-client-stage/adapter.py'
        phase_adapter = self.root/e.PHASE_ROOT/'adapter.py'
        dependency = self.root/e.PHASE_ROOT/'dependencies.py'
        def replace(path, replacements):
            raw = path.read_bytes()
            for old, new in replacements:
                self.assertEqual(raw.count(old.encode()), 1, (path.name, old))
                raw = raw.replace(old.encode(), new.encode())
            path.write_bytes(raw)
        old_adapter = declarations['HELD']['adapter.py']
        self.assertEqual(hashlib.sha256(historical.read_bytes()).hexdigest(), old_adapter)
        replace(historical, pairs);new_adapter = hashlib.sha256(historical.read_bytes()).hexdigest()
        old_orchestrator = self.manifests['collector']['orchestrator.py']['sha256']
        replace(orchestrator, [*pairs, (old_adapter, new_adapter)])
        new_orchestrator = hashlib.sha256(orchestrator.read_bytes()).hexdigest()
        self.PINS['collector'] = self.repin('collector', 'orchestrator.py')
        replace(phase_adapter, pairs)
        replace(dependency, [*pairs, (old_adapter, new_adapter), (old_orchestrator, new_orchestrator),
                             (type(self).PINS['collector'], self.PINS['collector'])])
        self.repin('phase', 'adapter.py')
        self.PINS['phase'] = self.repin('phase', 'dependencies.py')
    def copy(self, name):
        source, target = self.repo / name, self.root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes()); target.chmod(source.stat().st_mode & 0o777)
    def load(self, role, *, deadline=None, pin=None, module=e):
        prefix = self.prefixes[role]
        return module.dependency_entry(self.root, prefix + '/entry.py',
            self.manifests[role]['entry.py']['sha256'], prefix + '/source-map.json',
            pin or self.PINS[role], deadline=time.monotonic()+10 if deadline is None else deadline,
            phase=role == 'phase')
    def repin(self, role, name):
        prefix = self.prefixes[role]
        self.manifests[role][name]['sha256'] = hashlib.sha256((self.root/prefix/name).read_bytes()).hexdigest()
        raw = (json.dumps(self.manifests[role], sort_keys=True, indent=2)+'\n').encode()
        (self.root/prefix/'source-map.json').write_bytes(raw)
        return hashlib.sha256(raw).hexdigest()
    def test_actual_fresh_collector_and_phase_graphs_load_without_pyc_or_actors(self):
        collector, pins = self.load('collector')
        self.assertEqual(set(collector), set(e.COLLECTOR)); self.assertEqual(len(pins), 7)
        self.assertIs(collector['provenance'].digest, collector['common'].digest)
        phase, pins = self.load('phase')
        self.assertEqual(set(phase), set(e.PHASE)); self.assertEqual(len(pins), 5)
        self.assertIs(phase['adapter'].gate, phase['gate'])
        self.assertIs(phase['gate'].phases, phase['phases'])
        self.assertEqual(list(self.root.rglob('*.pyc')), [])
    def test_foreign_project_labels_none_slots_and_project_paths_are_not_grants(self):
        fake = types.ModuleType('common'); fake.__file__ = str(self.root/e.COLLECTOR_ROOT/'common.py')
        fake.__spec__ = types.SimpleNamespace(origin=fake.__file__)
        with patch.dict(sys.modules, {'common': fake, 'gate': None, 'dependencies': fake}), patch.object(sys, 'path', [str(self.root)]):
            paths = list(sys.path)
            collector, _ = self.load('collector'); phase, _ = self.load('phase')
            self.assertIsNot(collector['common'], fake)
            self.assertIs(phase['gate'].dependencies, phase['dependencies'])
            self.assertIs(sys.modules['common'], fake); self.assertIn('gate', sys.modules)
            self.assertIsNone(sys.modules['gate']); self.assertEqual(sys.path, paths)
            with self.assertRaises(ValueError): collector['common'].__builtins__['__import__']('unknown_project')
            with self.assertRaises(ValueError): collector['common'].__builtins__['__import__']('common', level=1)
    def test_entire_sixteen_source_graph_hashes_and_modes_refuse_before_project_compile(self):
        compiled = e.LANGUAGE['compile']
        for name in self.files:
            target = self.root/name; raw, mode = target.read_bytes(), target.stat().st_mode & 0o777
            for change in ('bytes', 'mode'):
                with self.subTest(source=name, change=change):
                    if change == 'bytes': target.write_bytes(raw+b'\n# stale source\n')
                    else: target.chmod(0o755 if mode == 0o644 else 0o644)
                    project_compiles = []
                    def observe(*args, **kwargs):
                        if not (len(args)>3 and args[3] == ast.PyCF_ONLY_AST): project_compiles.append(args[1])
                        return compiled(*args, **kwargs)
                    with patch.object(e, 'LANGUAGE', {**e.LANGUAGE, 'compile': observe}), self.assertRaises(ValueError): self.load('phase')
                    self.assertEqual(project_compiles, [])
                    target.write_bytes(raw); target.chmod(mode)
    def test_stale_maps_extra_rows_and_inconsistent_collector_declaration_refuse(self):
        for role in self.prefixes:
            with self.subTest(role=role), self.assertRaises(ValueError): self.load(role, pin='0'*64)
        target = self.root/e.PHASE_ROOT/'source-map.json'
        original = target.read_bytes(); changed = json.loads(original)
        changed['foreign.py'] = {'sha256':'a'*64, 'mode':0o644}
        raw = json.dumps(changed).encode(); target.write_bytes(raw)
        with self.assertRaisesRegex(ValueError, 'dependency-closure'): self.load('phase', pin=hashlib.sha256(raw).hexdigest())
        target.write_bytes(original)
        source = self.root/e.PHASE_ROOT/'dependencies.py'
        source.write_bytes(source.read_bytes().replace(self.manifests['collector']['common.py']['sha256'].encode(), b'a'*64))
        with self.assertRaisesRegex(ValueError, 'dependency-collector-declaration'):
            self.load('phase', pin=self.repin('phase', 'dependencies.py'))
    def test_same_byte_inode_replacement_between_capture_and_exec_refuses_and_restores(self):
        original = e.LANGUAGE['compile']; mutated = False
        before, paths = {name: sys.modules.get(name) for name in (*e.COLLECTOR, *e.PHASE)}, list(sys.path)
        def replace(*args, **kwargs):
            nonlocal mutated
            result = original(*args, **kwargs)
            if not mutated and not (len(args)>3 and args[3] == ast.PyCF_ONLY_AST):
                mutated = True; target = self.root/e.PREDECESSORS[-1]
                alternate = target.with_name('replacement'); alternate.write_bytes(target.read_bytes())
                alternate.chmod(target.stat().st_mode & 0o777); os.replace(alternate, target)
            return result
        with patch.object(e, 'LANGUAGE', {**e.LANGUAGE, 'compile': replace}), self.assertRaisesRegex(ValueError, 'dependency-source-drift'):
            self.load('phase')
        self.assertTrue(mutated); self.assertEqual(sys.path, paths)
        self.assertEqual({name:sys.modules.get(name) for name in before}, before)
    def test_private_collector_return_ignores_cache_and_checks_deferred_source_custody(self):
        phase, _ = self.load('phase'); dependency = phase['dependencies']
        first = dependency.load_collector(self.root)
        dependency.CACHE[str(self.root)] = {'common': types.ModuleType('common')}
        self.assertIs(dependency.load_collector(self.root)['common'], first['common'])
        with self.assertRaisesRegex(ValueError, 'dependency-root'): dependency.load_collector(self.root/'other')
        target = self.root/e.PREDECESSORS[-1]
        self.assertEqual(dependency.predecessor(self.root, e.PREDECESSORS[-1]), target.read_bytes())
        target.chmod(0o755)
        with self.assertRaisesRegex(ValueError, 'dependency-source-drift'): dependency.load_collector(self.root)
        with self.assertRaisesRegex(ValueError, 'dependency-source-drift'): dependency.predecessor(self.root, e.PREDECESSORS[-1])
    def test_historical_snapshot_has_its_own_gate_and_foreign_snapshot_source_refuses(self):
        collector, _ = self.load('collector')
        scratch = self.root/'scratch'; scratch.mkdir()
        held = collector['orchestrator'].held_modules(self.root, scratch)
        self.assertIs(held['adapter'].gate, held['gate'])
        self.assertIn('/scratch/held/gate.py', held['gate'].__file__)
        phase, _ = self.load('phase'); self.assertIsNot(held['gate'], phase['gate'])
        snapshot = scratch/'held'; target = snapshot/'gate.py'
        target.write_bytes(b'raise AssertionError("foreign snapshot executed")\n')
        mapped = json.loads((snapshot/'.source-map.json').read_bytes())
        mapped['gate.py']['sha256'] = hashlib.sha256(target.read_bytes()).hexdigest()
        (snapshot/'.source-map.json').write_text(json.dumps(mapped))
        with self.assertRaisesRegex(ValueError, 'dependency-snapshot-map'):
            collector['common'].load_snapshot(snapshot, ('gate', 'adapter'))
    def test_frozen_release_loads_but_foreign_bytes_or_equal_code_objects_never_execute(self):
        phase, _ = self.load('phase'); raw = (self.root/'scripts/release/release.py').read_bytes()
        release = phase['adapter'].load_release(raw, types.SimpleNamespace(run=lambda *a, **k: (_ for _ in ()).throw(AssertionError('actor'))))
        self.assertTrue(callable(release.require))
        with self.assertRaisesRegex(ValueError, 'unbound-runtime-source'):
            phase['adapter'].load_release(raw+b'\n# foreign bytes\n', None)
        foreign = compile(raw+b'\n# foreign but equal Python code\n', '<verified-frozen-release>', 'exec')
        with self.assertRaisesRegex(ValueError, 'unbound-runtime-code'):
            release.__builtins__['exec'](foreign, {})
    def fraction_fixture(self):
        source = self.root/e.COLLECTOR_ROOT/'provenance.py'
        source.write_bytes(source.read_bytes()+b'\nimport fractions\nOBSERVED_FRACTION = fractions.Fraction(2, 4)\n')
        return self.repin('collector', 'provenance.py')
    def test_forged_stdlib_cache_before_entry_initialization_and_transitive_builtins_are_ignored(self):
        pin = self.fraction_fixture(); fake = types.ModuleType('fractions')
        fake.__file__ = str(Path(e.sysconfig.get_path('stdlib'))/'fractions.py')
        fake.__spec__ = types.SimpleNamespace(origin=fake.__file__)
        loaded = types.ModuleType('copied_entry'); loaded.__file__ = e.__file__
        with patch.dict(sys.modules, {'fractions': fake}):
            e.LANGUAGE['exec'](e.LANGUAGE['compile'](Path(e.__file__).read_bytes(), e.__file__, 'exec'), loaded.__dict__)
            calls = []
            def foreign(*args, **kwargs): calls.append(args); raise AssertionError('foreign builtin executed')
            with patch.object(builtins, '__import__', foreign), patch.object(builtins, 'compile', foreign), patch.object(builtins, 'exec', foreign):
                collector, _ = self.load('collector', pin=pin, module=loaded)
                self.assertEqual(str(collector['provenance'].OBSERVED_FRACTION), '1/2')
                self.assertIs(builtins.__import__, foreign)
            self.assertEqual(calls, []); self.assertIs(sys.modules['fractions'], fake)
    def test_foreign_import_finders_hooks_and_cache_never_run_and_restore_exactly(self):
        pin = self.fraction_fixture(); calls = []
        class ForeignFinder:
            def find_spec(self, *args): calls.append(args); raise AssertionError('foreign finder executed')
        def hook(path): calls.append(path); raise AssertionError('foreign hook executed')
        with patch.object(sys, 'meta_path', [ForeignFinder()]), patch.object(sys, 'path_hooks', [hook]), \
             patch.object(sys, 'path_importer_cache', {e.sysconfig.get_path('stdlib'): ForeignFinder()}):
            meta, hooks, cache, paths = list(sys.meta_path), list(sys.path_hooks), dict(sys.path_importer_cache), list(sys.path)
            collector, _ = self.load('collector', pin=pin)
            self.assertEqual(str(collector['provenance'].OBSERVED_FRACTION), '1/2')
            self.assertEqual((sys.meta_path, sys.path_hooks, sys.path_importer_cache, sys.path), (meta, hooks, cache, paths))
        self.assertEqual(calls, [])
    def test_existing_deadline_applies_before_read_and_to_deferred_helpers(self):
        with patch.object(e, 'read') as read, self.assertRaisesRegex(ValueError, 'source-deadline'): self.load('phase', deadline=-1)
        read.assert_not_called()
        end = time.monotonic()+10; phase, _ = self.load('phase', deadline=end)
        with patch.object(e.time, 'monotonic', return_value=end), self.assertRaisesRegex(ValueError, 'source-deadline'):
            phase['dependencies'].load_collector(self.root)

    def test_stdlib_finder_bindings_cannot_be_replaced_after_entry_initialization(self):
        pin = self.fraction_fixture()
        foreign = types.SimpleNamespace(path_hook=lambda *a: (_ for _ in ()).throw(AssertionError('foreign finder')))
        with patch.multiple(e.machinery, BuiltinImporter=foreign, FrozenImporter=foreign,
                            PathFinder=foreign, FileFinder=foreign, SourceFileLoader=foreign,
                            ExtensionFileLoader=foreign):
            collector, _ = self.load('collector', pin=pin)
            self.assertEqual(str(collector['provenance'].OBSERVED_FRACTION), '1/2')


if __name__ == '__main__': unittest.main()

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Actor-fenced explicit Source read-only binding DATA; no mount qualification."""
import argparse
import ast
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parent
PREFIX = 'scripts/ci/fish-config02-native-source/successor_v2/'
NONCE = 'a' * 32
TEMP_ROOT = Path(os.environ.get('TMPDIR', '/dev/shm'))
if TEMP_ROOT not in (Path('/dev/shm'), Path('/tmp')):
    raise SystemExit('DATA TMPDIR must be /dev/shm or /tmp')
TEMP_PREFIX = str(TEMP_ROOT / 'FISH-V8-DATA.')
ACTORS = []


def fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.', 'fcntl.')) or event in {
        'resource.setrlimit', 'os.system', 'os.fork', 'os.forkpty', 'os.exec', 'os.posix_spawn',
        'os.kill', 'os.killpg', 'os.pidfd_open',
    }:
        ACTORS.append(event)
        raise AssertionError('FENCED no process/resource/network/custody actor: ' + event)
    if event == 'open' and isinstance(args[0], (str, bytes, os.PathLike)):
        if (args[2] or 0) & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
            if not str(Path(os.fsdecode(args[0])).absolute()).startswith(TEMP_PREFIX):
                raise AssertionError('FENCED writes only to disposable DATA fixture')


sys.addaudithook(fence)


def module(path):
    value = ModuleType('fenced_fish_v8_' + path.stem)
    value.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), 'exec'), value.__dict__)
    return value


C = module(HERE / 'prepare.py')


def function(raw, name):
    return next(node for node in ast.walk(ast.parse(raw))
                if isinstance(node, ast.FunctionDef) and node.name == name)


def shape(node):
    return ast.dump(node, include_attributes=False)


class BeforeActor(Exception):
    pass


class Controls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='FISH-V8-DATA.', dir=TEMP_ROOT)
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(self.assertEqual, ACTORS, [], 'actual actors must remain zero')
        self.pidfd = patch.object(os, 'pidfd_open', create=True,
                                  side_effect=AssertionError('NO actual PIDFD open'))
        self.pidfd.start()
        self.addCleanup(self.pidfd.stop)
        self.source = self.root / 'source'
        self.volume = self.root / 'operation' / 'volume'
        self.source.mkdir()
        self.volume.mkdir(parents=True)

    def args(self, kind='owner', source=None, volume=None):
        limits = POLICY[kind]
        command = ['/usr/bin/python3', '-I', '-B', '/declared/payload.py'] if kind == 'owner' else ['/usr/bin/dockerd']
        volume = self.volume if volume is None else volume
        return D.service_args(NONCE, kind, limits, command, volume / (kind + '.log'),
                              1000 if kind == 'owner' else None, 1000 if kind == 'owner' else None,
                              source_root=self.source if source is None else source)

    def test_actual_owner_and_daemon_vectors_add_only_exact_source_readonly_bind(self):
        for kind in ('owner', 'daemon'):
            with self.subTest(kind=kind):
                actual = self.args(kind)
                command = ['/usr/bin/python3', '-I', '-B', '/declared/payload.py'] if kind == 'owner' else ['/usr/bin/dockerd']
                expected = OLD.service_args(NONCE, kind, POLICY[kind], command, self.volume / (kind + '.log'),
                                            1000 if kind == 'owner' else None, 1000 if kind == 'owner' else None)
                bindings = [item for item in actual if item.startswith('--property=BindReadOnlyPaths=')]
                self.assertEqual(bindings, ['--property=BindReadOnlyPaths=' + str(self.source)])
                self.assertEqual([item for item in actual if item not in bindings], expected)
                self.assertIn('--property=ProtectSystem=strict', actual)
                self.assertIn('--property=ReadOnlyPaths=/tmp /var/tmp /sys/fs/cgroup', actual)
                writable = [item for item in actual if item.startswith('--property=ReadWritePaths=')]
                self.assertEqual(writable, [item for item in expected if item.startswith('--property=ReadWritePaths=')])
                self.assertNotIn(':' + str(self.source), bindings[0])
                self.assertFalse(bindings[0].split('=', 2)[2].startswith('-'))

    def test_required_source_operand_and_unsafe_property_tokens_refuse(self):
        with self.assertRaises(TypeError):
            D.service_args(NONCE, 'owner', POLICY['owner'], ['/usr/bin/python3'], self.volume / 'owner.log', 1000, 1000)
        invalid = (None, Path('relative-source'), Path('/'), self.source / '..',
                   self.root / 'space source', self.root / 'colon:source', self.root / '%h',
                   self.root / 'newline\nsource', self.root / 'back\\slash')
        for source in invalid:
            with self.subTest(source=repr(source)), self.assertRaises((ValueError, TypeError)):
                D.service_args(NONCE, 'owner', POLICY['owner'], ['/usr/bin/python3'], self.volume / 'owner.log',
                               1000, 1000, source_root=source)

    def test_alias_and_whole_volume_overlap_refuse_for_both_domains(self):
        source_alias = self.root / 'source-alias'
        source_alias.symlink_to(self.source, target_is_directory=True)
        volume_alias = self.root / 'volume-alias'
        volume_alias.symlink_to(self.volume, target_is_directory=True)
        nested = self.volume / 'source'
        nested.mkdir()
        source_child = self.source / 'volume'
        source_child.mkdir()
        for kind in ('owner', 'daemon'):
            for source, volume in ((source_alias, self.volume), (self.source, volume_alias),
                                   (self.volume, self.volume), (nested, self.volume),
                                   (self.root, self.volume), (self.source, source_child)):
                with self.subTest(kind=kind, source=source, volume=volume), self.assertRaises(ValueError):
                    self.args(kind, source=source, volume=volume)
        # Siblings can share a covering host mount; only the Source gets the new read-only binding.
        self.assertIn('--property=BindReadOnlyPaths=' + str(self.source), self.args())

    def test_missing_or_nondirectory_source_and_volume_never_become_optional(self):
        source_file = self.root / 'source-file'
        source_file.write_bytes(b'MODEL ordinary file, not a Source directory')
        volume_file = self.root / 'volume-file'
        volume_file.write_bytes(b'MODEL ordinary file, not a quota directory')
        for kind in ('owner', 'daemon'):
            for source, volume in ((self.root / 'missing-source', self.volume),
                                   (source_file, self.volume),
                                   (self.source, self.root / 'missing-volume'),
                                   (self.source, volume_file)):
                with self.subTest(kind=kind, source=source, volume=volume), self.assertRaises((ValueError, OSError)):
                    self.args(kind, source=source, volume=volume)

    def test_actual_start_passes_exact_declared_source_before_first_actor(self):
        start = function(OWNER, 'start')
        calls = [node for node in ast.walk(start) if isinstance(node, ast.Call) and
                 isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and
                 node.func.value.id == 'D' and node.func.attr == 'service_args']
        self.assertEqual(len(calls), 1)
        self.assertEqual([shape(item.value) for item in calls[0].keywords if item.arg == 'source_root'],
                         [shape(ast.parse('self.root', mode='eval').body)])
        scope = dict(D=D, H=SimpleNamespace(checked=Mock()), Path=Path)
        exec(compile(ast.Module(body=[start], type_ignores=[]), '<actual-Fish-v8-start-DATA>', 'exec'), scope)
        out = self.volume.parent
        run = Mock(side_effect=BeforeActor('MODEL stop before transport'))
        model = SimpleNamespace(root=self.source, out=out, policy=POLICY, nonce=NONCE, units={},
                                tools={'python3': {'path': '/usr/bin/python3'}},
                                show=Mock(return_value={'LoadState': 'not-found'}),
                                tool=lambda _: '/usr/bin/systemd-run', run=run)
        with patch.object(D, 'service_args', wraps=D.service_args) as service, self.assertRaises(BeforeActor):
            scope['start'](model, 'owner', ['/usr/bin/python3', '-I', '-B', '/declared/payload.py'], 1000, 1000)
        self.assertEqual(service.call_args.kwargs, {'source_root': self.source})
        run.assert_called_once()
        self.assertIn('--property=BindReadOnlyPaths=' + str(self.source), run.call_args.args[0])
        self.assertEqual(model.units, {'owner': dict(submitted=True, cgroup=None)})
        model.root = self.volume
        model.units = {}
        run.reset_mock()
        with self.assertRaises(ValueError):
            scope['start'](model, 'owner', ['/usr/bin/python3'], 1000, 1000)
        run.assert_not_called()
        self.assertEqual(model.units, {})

    def test_previous_payload_guard_remains_exact_and_writable_source_refuses(self):
        self.assertEqual(BODIES[PREFIX + 'payload.py'], ORIGINAL[PREFIX + 'payload.py'])
        guard = next(node for node in function(BODIES[PREFIX + 'payload.py'], 'main').body if
                     isinstance(node, ast.Expr) and isinstance(node.value, ast.Call) and
                     any(isinstance(arg, ast.Constant) and arg.value ==
                         'actual owner writable filesystem restricted to quota work domain'
                         for arg in node.value.args))
        code = compile(ast.Module(body=[guard], type_ignores=[]), '<exact-Fish-filesystem-guard-DATA>', 'exec')
        source = Path('/MODEL_SOURCE')
        for writable in (None, '/tmp', '/var/tmp', str(source)):
            with self.subTest(writable=writable), patch.object(os, 'access', side_effect=lambda path, mode: str(path) == writable):
                scope = dict(D=D, os=os, root=source)
                if writable is None: exec(code, scope)
                else:
                    with self.assertRaisesRegex(ValueError, 'actual owner writable filesystem restricted to quota work domain'):
                        exec(code, scope)

    def test_previous_actor_acceptance_and_package_bodies_remain_exact(self):
        old_owner = ORIGINAL[PREFIX + 'hosted_owner.py']
        for name in ('main', 'run', 'stop', 'cleanup', 'setup', 'preflight', 'show', 'docker', 'loop_identity'):
            with self.subTest(method=name): self.assertEqual(shape(function(old_owner, name)), shape(function(OWNER, name)))
        projected, seams = C.projections(ORIGINAL)
        for name, raw in projected.items():
            restored = raw.decode()
            for seam in reversed(seams[name]):
                self.assertEqual(restored.count(seam['after']), 1)
                restored = restored.replace(seam['after'], seam['before'])
            self.assertEqual(restored.encode(), ORIGINAL[name])
        for name, raw in ORIGINAL.items():
            if name.startswith(('held-source32/', '.github/')) or name.endswith(
                    ('/go_cli_va.py', '/failed_retirement.py', '/payload_diagnostic.py', '/filesystem_diagnostic.py')):
                with self.subTest(unchanged=name): self.assertEqual(BODIES[name], raw)
        self.assertNotIn('reset-failed', OWNER.decode())
        self.assertIn("'ordinary payload natural success required'", OWNER.decode())

    def test_complete_constructor62_and_predecessor60_57_53_50_48_inverses(self):
        output = self.root / 'Source62'
        receipt = C.construct(BASE, output)
        self.assertEqual(receipt['files'], 62)
        for key in ('actual_source', 'actual_run', 'actual_runtime', 'Root_authority', 'role_label'):
            self.assertIsNone(receipt[key])
        bodies = {path.relative_to(output).as_posix(): path.read_bytes() for path in output.rglob('*') if path.is_file()}
        validator = module(output / PREFIX / 'data.py')
        validator.source(output, receipt['source_map']['sha256'])
        restored60 = validator.inverse_source60(bodies)
        self.assertEqual(restored60, ORIGINAL)
        restored57 = validator.inverse_source57(restored60)
        self.assertEqual(len(restored57), 57)
        restored53 = validator.inverse_source53(restored57)
        self.assertEqual(len(restored53), 53)
        restored50 = validator.inverse_source50(restored53)
        self.assertEqual(len(restored50), 50)
        self.assertEqual(validator.inverse_source48(None, restored50)['files'], 48)
        policy = json.loads(bodies[PREFIX + 'policy.json'])
        declaration = policy.pop('source_readonly_binding')
        self.assertEqual(declaration, C.DECLARATION)
        self.assertEqual(declaration['unit_property'], 'BindReadOnlyPaths')
        self.assertEqual(declaration['domains'], ['owner', 'daemon'])
        self.assertIs(declaration['whole_quota_volume_disjoint'], True)
        self.assertEqual(policy, json.loads(ORIGINAL[PREFIX + 'policy.json']))
        binding = json.loads(bodies[PREFIX + 'source-ro-binding.json'])
        for key in ('actual_source', 'actual_run', 'actual_runtime', 'Root_authority', 'role_label'):
            self.assertIsNone(binding[key])
        self.assertEqual(C.construct(BASE, self.root / 'second-Source62'), receipt)
        self.assertEqual(C.frozen(BASE)[0], ORIGINAL)
        self.assertTrue(all(path.stat().st_mode & 0o777 == 0o644 for path in output.rglob('*') if path.is_file()))
        self.assertTrue(all(value is None for value in json.loads(bodies['source-map.json'])['actual'].values()))

    def test_source_and_inverse_drift_refuse(self):
        output = self.root / 'wrong-source'
        with self.assertRaises(ValueError): C.construct(PREVIEW, output)
        self.assertFalse(output.exists())
        original_read = C.read
        def changed_source(path):
            raw = original_read(path)
            return raw + b'MODEL source drift' if Path(path) == BASE / 'LICENSE' else raw
        with patch.object(C, 'read', side_effect=changed_source), self.assertRaises(ValueError):
            C.construct(BASE, output)
        self.assertFalse(output.exists())
        inverse = PREFIX + 'source60-inverse.json'
        proof = json.loads(BODIES[inverse])
        for mode in ('before', 'after', 'added'):
            value = copy.deepcopy(proof)
            if mode == 'before': value['before_utf8'].pop(PREFIX + 'policy.json')
            elif mode == 'after': value['after'][PREFIX + 'hosted_owner.py']['sha256'] = '0' * 64
            else: value['added'].remove(PREFIX + 'source-ro-binding.json')
            changed = dict(BODIES, **{inverse: C.encode(value)})
            with self.subTest(mode=mode), self.assertRaises(ValueError): D.inverse_source60(changed)


if __name__ == '__main__':
    if not sys.flags.isolated or not sys.flags.dont_write_bytecode or not __debug__:
        raise SystemExit('run unoptimized DATA controls with Python -I -B')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, required=True, help='explicit complete frozen Source60 DATA root')
    options, rest = parser.parse_known_args()
    BASE = options.base
    ORIGINAL, unused_manifest, OLD = C.frozen(BASE)
    with tempfile.TemporaryDirectory(prefix='FISH-V8-DATA.', dir=TEMP_ROOT) as temporary:
        PREVIEW = Path(temporary) / 'constructed-preview'
        C.construct(BASE, PREVIEW)
        D = module(PREVIEW / PREFIX / 'data.py')
        BODIES = {path.relative_to(PREVIEW).as_posix(): path.read_bytes() for path in PREVIEW.rglob('*') if path.is_file()}
        OWNER = BODIES[PREFIX + 'hosted_owner.py']
        POLICY = json.loads(BODIES[PREFIX + 'policy.json'])
        unittest.main(argv=[sys.argv[0], *rest], verbosity=2)

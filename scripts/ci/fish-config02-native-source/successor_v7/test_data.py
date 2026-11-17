#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Actor-fenced fixed-path diagnostic controls; no native confinement credit."""
import argparse
import ast
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
PREFIX = 'scripts/ci/fish-config02-native-source/successor_v2/'
TEMP_ROOT = Path(os.environ.get('TMPDIR', '/dev/shm'))
if TEMP_ROOT not in (Path('/dev/shm'), Path('/tmp')):
    raise SystemExit('DATA TMPDIR must be /dev/shm or /tmp')
TEMP_PREFIX = str(TEMP_ROOT / 'FISH-V7-DATA.')
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
    value = ModuleType('fenced_fish_v7_' + path.stem)
    value.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), 'exec'), value.__dict__)
    return value


C = module(HERE / 'prepare.py')
Y = module(HERE / 'filesystem_diagnostic.py')


def function(raw, name):
    return next(node for node in ast.walk(ast.parse(raw))
                if isinstance(node, ast.FunctionDef) and node.name == name)


def shape(node):
    return ast.dump(node, include_attributes=False)


def decode(text):
    return json.loads(text.removeprefix(Y.PREFIX))


class Controls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='FISH-V7-DATA.', dir=TEMP_ROOT)
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(self.assertEqual, ACTORS, [], 'actual actors must remain zero')
        self.pidfd = patch.object(os, 'pidfd_open', create=True,
                                  side_effect=AssertionError('NO actual PIDFD open'))
        self.pidfd.start()
        self.addCleanup(self.pidfd.stop)

    def test_actual_probe_permission_mount_classes_and_entry_classes_over_models(self):
        target = Path('/PRIVATE_SOURCE_SENTINEL')
        for mode, entry in ((stat.S_IFDIR | 0o750, 'DIRECTORY'), (stat.S_IFREG | 0o440, 'FILE'),
                            (stat.S_IFLNK | 0o777, 'SYMLINK'), (stat.S_IFSOCK | 0o660, 'OTHER')):
            for writable in (False, True):
                for flags, mount in ((0, 'READ_WRITE'), (os.ST_RDONLY, 'READ_ONLY')):
                    with self.subTest(entry=entry, writable=writable, mount=mount), \
                         patch.object(Path, 'lstat', return_value=SimpleNamespace(st_mode=mode)), \
                         patch.object(os, 'access', return_value=writable) as access, \
                         patch.object(os, 'statvfs', return_value=SimpleNamespace(f_flag=flags)) as vfs:
                        row = Y.probe(target)
                        self.assertEqual(row, dict(entry_class=entry, mode_bits=stat.S_IMODE(mode),
                                                   write_access=writable, mount_class=mount, errors={}))
                        access.assert_called_once_with(target, os.W_OK)
                        vfs.assert_called_once_with(target)
        # A read-write mount does not imply permission; contradictions stay observations.
        self.assertIs(Y.DECLARATION['observation_only'], True)
        self.assertIs(Y.DECLARATION['acceptance_override'], False)

    def test_probe_errors_unknown_values_and_private_text_are_not_read_only(self):
        private = 'PRIVATE_TOKEN=/private/unpublished/path\n\x1b[31m'
        unknown = type('PRIVATE_EXCEPTION_SENTINEL', (Exception,), {})
        with patch.object(Path, 'lstat', side_effect=PermissionError(private)), \
             patch.object(os, 'access', side_effect=unknown(private)), \
             patch.object(os, 'statvfs', side_effect=FileNotFoundError(private)):
            row = Y.probe(Path('/PRIVATE_PATH_SENTINEL'))
            text = Y.record('/PRIVATE_SOURCE_SENTINEL', '/PRIVATE_QUOTA_SENTINEL')
        self.assertEqual(row, dict(entry_class='UNKNOWN', mode_bits=None, write_access=None,
                                   mount_class='UNKNOWN', errors=dict(entry='PermissionError', access='OTHER', mount='FileNotFoundError')))
        value = decode(text)
        self.assertEqual(value['status'], 'PARTIAL')
        for secret in (private, 'PRIVATE_EXCEPTION_SENTINEL', '/PRIVATE_SOURCE_SENTINEL', '/PRIVATE_QUOTA_SENTINEL'):
            self.assertNotIn(secret, text)
        self.assertTrue(all(item['mount_class'] == 'UNKNOWN' and item['write_access'] is None for item in value['paths']))
        for invalid_mode in (None, True, -1, 'directory'):
            with self.subTest(mode=invalid_mode), patch.object(Path, 'lstat', return_value=SimpleNamespace(st_mode=invalid_mode)), \
                 patch.object(os, 'access', return_value='PRIVATE_ACCESS_SENTINEL'), \
                 patch.object(os, 'statvfs', return_value=SimpleNamespace(f_flag=-1)):
                result = Y.probe('/PRIVATE_PATH_SENTINEL')
                self.assertEqual(result['entry_class'], 'UNKNOWN')
                self.assertIsNone(result['write_access'])
                self.assertEqual(result['mount_class'], 'UNKNOWN')

    def test_only_four_fixed_target_roles_are_sampled_without_path_output(self):
        source, work = Path('/PRIVATE_SOURCE_SENTINEL'), Path('/PRIVATE_QUOTA_SENTINEL')
        cases = ((True, os.ST_RDONLY), (False, 0))
        for writable, flags in cases:
            with self.subTest(writable=writable, flags=flags), \
                 patch.object(Path, 'lstat', return_value=SimpleNamespace(st_mode=stat.S_IFDIR | 0o700)), \
                 patch.object(os, 'access', return_value=writable) as access, \
                 patch.object(os, 'statvfs', return_value=SimpleNamespace(f_flag=flags)) as vfs:
                text = Y.record(source, work)
            expected = [Path('/tmp'), Path('/var/tmp'), source, work]
            self.assertEqual([call.args[0] for call in access.call_args_list], expected)
            self.assertEqual([call.args[0] for call in vfs.call_args_list], expected)
            value = decode(text)
            self.assertEqual(value['kind'], Y.DECLARATION['kind'])
            self.assertEqual(set(value), {'kind', 'status', 'paths'})
            self.assertEqual(value['status'], 'OBSERVED')
            self.assertEqual([row['label'] for row in value['paths']], ['tmp', 'var_tmp', 'source', 'quota_work'])
            self.assertLessEqual(len((text + '\n').encode()), 2048)
            self.assertNotIn(str(source), text)
            self.assertNotIn(str(work), text)
            self.assertNotIn('/tmp', text)
            self.assertNotIn('/var/tmp', text)
            self.assertTrue(all(row['write_access'] == writable for row in value['paths']))
            self.assertFalse(any(key in value for key in ('accepted', 'confinement_pass', 'payload_success')))
        calls = [node for node in ast.walk(ast.parse((HERE / 'filesystem_diagnostic.py').read_bytes())) if isinstance(node, ast.Call)]
        forbidden = {'walk', 'scandir', 'listdir', 'glob', 'rglob', 'open', 'write_bytes', 'write_text', 'Popen', 'run'}
        self.assertFalse(any(isinstance(node.func, ast.Attribute) and node.func.attr in forbidden for node in calls))

    def test_emitter_fallback_is_bounded_unknown_and_does_not_raise(self):
        private = 'PRIVATE_TOKEN=/unpublished/fallback\n\x1b[31m'
        stream = io.StringIO()
        with patch.object(Y, 'record', side_effect=RuntimeError(private)), contextlib.redirect_stderr(stream):
            self.assertIsNone(Y.emit('/PRIVATE_SOURCE_SENTINEL', '/PRIVATE_QUOTA_SENTINEL'))
        text = stream.getvalue()
        self.assertEqual(decode(text), dict(kind=Y.DECLARATION['kind'], status='UNKNOWN'))
        self.assertNotIn(private, text)
        self.assertLessEqual(len(text.encode()), 2048)
        with patch.object(Y, 'record', return_value=Y.FALLBACK), patch('builtins.print', side_effect=OSError(private)):
            self.assertIsNone(Y.emit('/PRIVATE_SOURCE_SENTINEL', '/PRIVATE_QUOTA_SENTINEL'))
        oversized = dict(entry_class='DIRECTORY', mode_bits=0o700, write_access=False,
                         mount_class='READ_ONLY', errors={'entry': 'x' * 2048})
        with patch.object(Y, 'probe', return_value=oversized), self.assertRaises(ValueError):
            Y.record('/PRIVATE_SOURCE_SENTINEL', '/PRIVATE_QUOTA_SENTINEL')

    def guard_sequence(self):
        main = function(PAYLOAD, 'main')
        selected = []
        for node in main.body:
            if not isinstance(node, ast.Expr) or not isinstance(node.value, ast.Call): continue
            call = node.value
            if not isinstance(call.func, ast.Attribute) or not isinstance(call.func.value, ast.Name): continue
            alias, method = call.func.value.id, call.func.attr
            if alias == 'X' and method == 'phase' and call.args and isinstance(call.args[0], ast.Constant) and call.args[0].value == 'readonly-filesystem':
                selected.append(node)
            elif alias == 'Y' and method == 'emit': selected.append(node)
            elif alias == 'D' and method == 'need' and call.args and any(
                    isinstance(value, ast.Constant) and value.value == 'actual owner writable filesystem restricted to quota work domain'
                    for value in call.args): selected.append(node)
        self.assertEqual(len(selected), 3)
        self.assertEqual([ast.unparse(node.value.func) for node in selected], ['X.phase', 'Y.emit', 'D.need'])
        return ast.Module(body=selected, type_ignores=[])

    def test_actual_diagnostic_precedes_exact_guard_and_unknown_cannot_waive(self):
        code = compile(self.guard_sequence(), '<actual-Fish-v7-filesystem-gate-DATA>', 'exec')
        root = Path('/PRIVATE_SOURCE_SENTINEL')
        scope = dict(X=X, Y=Y, D=D, Path=Path, root=root, config={'output': '/PRIVATE_QUOTA_SENTINEL/fish-native'}, os=os)
        for writable in (None, '/tmp', '/var/tmp', str(root)):
            stream, events = io.StringIO(), []
            def access(path, mode):
                events.append(('guard', str(path)))
                self.assertEqual(mode, os.W_OK)
                return str(path) == writable
            def failed_record(source, work):
                events.append(('diagnostic', source, work))
                raise PermissionError('PRIVATE_ERROR_SENTINEL')
            with self.subTest(writable=writable), patch.object(os, 'access', side_effect=access), \
                 patch.object(Y, 'record', side_effect=failed_record), contextlib.redirect_stderr(stream):
                if writable is None: exec(code, scope)
                else:
                    with self.assertRaisesRegex(ValueError, 'actual owner writable filesystem restricted to quota work domain'):
                        exec(code, scope)
            self.assertEqual(events[0], ('diagnostic', root, Path('/PRIVATE_QUOTA_SENTINEL')))
            self.assertTrue(all(event[0] == 'guard' for event in events[1:]))
            self.assertEqual(X.CURRENT, 'readonly-filesystem')
            self.assertEqual(decode(stream.getvalue())['status'], 'UNKNOWN')
            self.assertNotIn('PRIVATE_ERROR_SENTINEL', stream.getvalue())

    def test_all_existing_contracts_guards_and_actor_bodies_remain_exact(self):
        projected, seams = C.projections(ORIGINAL)
        for name, raw in projected.items():
            restored = raw.decode()
            for seam in reversed(seams[name]):
                self.assertEqual(restored.count(seam['after']), 1)
                restored = restored.replace(seam['after'], seam['before'])
            self.assertEqual(restored.encode(), ORIGINAL[name])
        owner = PREFIX + 'hosted_owner.py'
        self.assertEqual(BODIES[owner], ORIGINAL[owner])
        self.assertEqual(shape(function(ORIGINAL[PREFIX + 'data.py'], 'service_args')),
                         shape(function(BODIES[PREFIX + 'data.py'], 'service_args')))
        args = D.service_args('a' * 32, 'owner', json.loads(ORIGINAL[PREFIX + 'policy.json'])['owner'],
                              ['/usr/bin/python3', '-I', '-B', '/PRIVATE_SOURCE/payload.py'],
                              Path('/PRIVATE_VOLUME/owner.log'), 1000, 1000)
        self.assertIn('--property=ProtectSystem=strict', args)
        self.assertIn('--property=ReadOnlyPaths=/tmp /var/tmp /sys/fs/cgroup', args)
        self.assertEqual([item for item in args if item.startswith('--property=ReadWritePaths=')],
                         ['--property=ReadWritePaths=/PRIVATE_VOLUME/work'])
        old_payload = ORIGINAL[PREFIX + 'payload.py']
        original_main, current_main = function(old_payload, 'main'), copy.deepcopy(function(PAYLOAD, 'main'))
        current_main.body = [node for node in current_main.body if not (
            isinstance(node, ast.Expr) and isinstance(node.value, ast.Call) and
            isinstance(node.value.func, ast.Attribute) and isinstance(node.value.func.value, ast.Name) and
            node.value.func.value.id == 'Y' and node.value.func.attr == 'emit')]
        self.assertEqual(shape(original_main), shape(current_main))
        guards = lambda raw: [shape(node) for node in ast.walk(ast.parse(raw)) if isinstance(node, ast.Call) and
                             isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and
                             node.func.value.id == 'D' and node.func.attr == 'need']
        self.assertEqual(guards(old_payload), guards(PAYLOAD))
        old_handlers = [shape(node) for node in ast.walk(ast.parse(old_payload)) if isinstance(node, ast.ExceptHandler)]
        new_handlers = [shape(node) for node in ast.walk(ast.parse(PAYLOAD)) if isinstance(node, ast.ExceptHandler)]
        self.assertEqual(old_handlers, new_handlers)
        for name, body in ORIGINAL.items():
            if name.startswith(('held-source32/', '.github/')) or name.endswith(('/go_cli_va.py', '/failed_retirement.py', '/payload_diagnostic.py')):
                with self.subTest(unchanged=name): self.assertEqual(BODIES[name], body)

    def test_exact_constructor60_and_complete57_53_50_48_inverses(self):
        output = self.root / 'Source60'
        result = C.construct(BASE, output)
        self.assertEqual(result['files'], 60)
        for key in ('actual_source', 'actual_run', 'Root_authority', 'role_label'):
            self.assertIsNone(result[key])
        validator = module(output / PREFIX / 'data.py')
        bodies = {path.relative_to(output).as_posix(): path.read_bytes() for path in output.rglob('*') if path.is_file()}
        validator.source(output, C.pin(bodies['source-map.json'])['sha256'])
        restored57 = validator.inverse_source57(bodies)
        self.assertEqual(restored57, ORIGINAL)
        restored53 = validator.inverse_source53(restored57)
        self.assertEqual(len(restored53), 53)
        restored50 = validator.inverse_source50(restored53)
        self.assertEqual(len(restored50), 50)
        self.assertEqual(validator.inverse_source48(None, restored50)['files'], 48)
        policy = json.loads(bodies[PREFIX + 'policy.json'])
        self.assertEqual(policy.pop('filesystem_diagnostics'), Y.DECLARATION)
        self.assertEqual(policy, json.loads(ORIGINAL[PREFIX + 'policy.json']))
        self.assertEqual(bodies[PREFIX + 'filesystem_diagnostic.py'], (HERE / 'filesystem_diagnostic.py').read_bytes())
        self.assertEqual(C.construct(BASE, self.root / 'second-Source60'), result)
        self.assertEqual(C.frozen(BASE)[0], ORIGINAL)
        self.assertTrue(all(path.stat().st_mode & 0o777 == 0o644 for path in output.rglob('*') if path.is_file()))
        self.assertTrue(all(value is None for value in json.loads(bodies['source-map.json'])['actual'].values()))

    def test_source_helper_and_inverse_drift_refuse_before_output(self):
        output = self.root / 'wrong-source'
        with self.assertRaises(ValueError): C.construct(PREVIEW, output)
        self.assertFalse(output.exists())
        original_read = C.read
        for path in (BASE / 'LICENSE', HERE / 'filesystem_diagnostic.py'):
            def changed_operand(candidate):
                raw = original_read(candidate)
                return raw + b'\nMODEL drift\n' if Path(candidate) == path else raw
            with self.subTest(path=path.name), patch.object(C, 'read', side_effect=changed_operand), \
                 patch.object(C, 'load_bytes', wraps=C.load_bytes) as imports:
                with self.assertRaises(ValueError): C.construct(BASE, output)
                self.assertFalse(any(len(call.args) >= 3 and Path(call.args[2]) == HERE / 'filesystem_diagnostic.py'
                                     for call in imports.call_args_list))
            self.assertFalse(output.exists())
        inverse = PREFIX + 'source57-inverse.json'
        proof = json.loads(BODIES[inverse])
        for mode in ('before', 'after', 'added'):
            value = copy.deepcopy(proof)
            if mode == 'before': value['before_utf8'].pop(PREFIX + 'policy.json')
            elif mode == 'after': value['after'][PREFIX + 'filesystem_diagnostic.py']['sha256'] = '0' * 64
            else: value['added'].remove(PREFIX + 'filesystem_diagnostic.py')
            changed = dict(BODIES, **{inverse: C.encode(value)})
            with self.subTest(mode=mode), self.assertRaises(ValueError): D.inverse_source57(changed)

    def test_null_and_foreign_helper_pins_refuse_before_import_or_output(self):
        for pin in (None, dict(bytes=3065, sha256='0' * 64), dict(bytes=3066, sha256=C.HELPER_PIN['sha256'])):
            output = self.root / 'invalid-helper-pin'
            with self.subTest(pin=pin), patch.object(C, 'HELPER_PIN', pin), \
                 patch.object(C, 'load_bytes', wraps=C.load_bytes) as imports:
                with self.assertRaises(ValueError): C.construct(BASE, output)
                self.assertFalse(any(len(call.args) >= 3 and Path(call.args[2]) == HERE / 'filesystem_diagnostic.py'
                                     for call in imports.call_args_list))
            self.assertFalse(output.exists())


if __name__ == '__main__':
    if not sys.flags.isolated or not sys.flags.dont_write_bytecode or not __debug__:
        raise SystemExit('run unoptimized DATA controls with Python -I -B')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, required=True, help='explicit complete frozen Source57 DATA root')
    options, rest = parser.parse_known_args()
    BASE = options.base
    ORIGINAL, unused_manifest, unused_validator = C.frozen(BASE)
    with tempfile.TemporaryDirectory(prefix='FISH-V7-DATA.', dir=TEMP_ROOT) as temporary:
        PREVIEW = Path(temporary) / 'constructed-preview'
        C.construct(BASE, PREVIEW)
        D = module(PREVIEW / PREFIX / 'data.py')
        X = module(PREVIEW / PREFIX / 'payload_diagnostic.py')
        BODIES = {path.relative_to(PREVIEW).as_posix(): path.read_bytes() for path in PREVIEW.rglob('*') if path.is_file()}
        PAYLOAD = BODIES[PREFIX + 'payload.py']
        unittest.main(argv=[sys.argv[0], *rest], verbosity=2)

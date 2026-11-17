#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Actor-fenced Fish diagnostics/retirement DATA, never native qualification.

Runs actual generated functions and immutable helper predicates over modeled
PIDFD/systemd/cgroup observations. Filesystem fixtures are disposable DATA.
"""
import argparse
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import select
import stat
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parent
PREFIX = 'scripts/ci/fish-config02-native-source/successor_v2/'
NONCE = 'a' * 32
UNIT = 'cachy-fish02-' + NONCE + '-owner.service'
GROUP = '/system.slice/' + UNIT
TEMP_ROOT = Path(os.environ.get('TMPDIR', '/dev/shm'))
if TEMP_ROOT not in (Path('/dev/shm'), Path('/tmp')):
    raise SystemExit('DATA TMPDIR must be /dev/shm or /tmp')
TEMP_PREFIX = str(TEMP_ROOT / 'FISH-V6-DATA.')
ACTORS = []


def fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.', 'fcntl.')) or event in {
        'resource.setrlimit', 'os.system', 'os.fork', 'os.forkpty', 'os.exec', 'os.posix_spawn',
        'os.kill', 'os.killpg', 'os.pidfd_open',
    }:
        ACTORS.append(event)
        raise AssertionError('FENCED no actual resource/process/network/custody actor: ' + event)
    if event == 'open' and isinstance(args[0], (str, bytes, os.PathLike)):
        if (args[2] or 0) & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
            if not str(Path(os.fsdecode(args[0])).absolute()).startswith(TEMP_PREFIX):
                raise AssertionError('FENCED writes only to disposable DATA fixture')


sys.addaudithook(fence)


def module(path):
    value = ModuleType('fenced_fish_v6_' + path.stem)
    value.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), 'exec'), value.__dict__)
    return value


C = module(HERE / 'prepare.py')
F = module(HERE / 'failed_retirement.py')
X = module(HERE / 'payload_diagnostic.py')


def fixture():
    owned = dict(submitted=True, pid=123, starttime=456, cgroup=GROUP, original_pidfd=7,
                 original_pidfd_identity=dict(dev=11, inode=22))
    row = dict(Description='cachy-fish02-owned-' + NONCE + '-owner', LoadState='loaded',
               ActiveState='failed', SubState='failed', MainPID='0', ControlGroup='',
               Result='exit-code', ExecMainCode='1', ExecMainStatus='2')
    censuses = [dict(cgroup=GROUP, path_present=False, events_empty=True,
                     procs_empty=True, pidfd_exited=True) for _ in range(2)]
    return owned, row, censuses


def function(raw, name):
    return next(node for node in ast.walk(ast.parse(raw))
                if isinstance(node, ast.FunctionDef) and node.name == name)


def shape(node):
    return ast.dump(node, include_attributes=False)


def modeled_pidfd(rows=None, identity=None):
    """Actual helper poll/identity code; no real descriptor is opened/read."""
    poll = Mock()
    poll.poll.return_value = [(7, select.POLLIN)] if rows is None else rows
    return (
        patch.object(os, 'readlink', return_value='anon_inode:[pidfd]'),
        patch.object(os, 'fstat', return_value=SimpleNamespace(st_dev=11, st_ino=22) if identity is None else identity),
        patch.object(select, 'poll', return_value=poll),
    )


class Controls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='FISH-V6-DATA.', dir=TEMP_ROOT)
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(self.assertEqual, ACTORS, [], 'actual actors must remain zero')
        self.pidfd = patch.object(os, 'pidfd_open', create=True,
                                  side_effect=AssertionError('NO actual PIDFD open'))
        self.pidfd.start()
        self.addCleanup(self.pidfd.stop)

    def test_hash_only_payload_diagnostics_all_literal_phases(self):
        private = 'PRIVATE_TOKEN=/private/unpublished/value\nsecond line\x1b[31m'
        for phase in X.PHASES:
            with self.subTest(phase=phase):
                X.phase(phase)
                text = X.record(ValueError(private))
                self.assertLessEqual(len((text + '\n').encode()), 512)
                self.assertNotIn(private, text)
                row = json.loads(text.removeprefix('HOLD_PAYLOAD: '))
                self.assertEqual(row['phase'], phase)
                self.assertEqual(row['exception'], 'ValueError')
                self.assertEqual(row['message_bytes'], len(private.encode()))
                self.assertEqual(row['message_prefix_sha256'], hashlib.sha256(private.encode()).hexdigest())
                self.assertFalse(row['truncated'])
                self.assertEqual(set(row), {'kind', 'phase', 'exception', 'message_bytes',
                                           'message_prefix_bytes', 'message_prefix_sha256', 'truncated'})
        X.phase('entry')
        long = ('é' + private) * 1000
        row = json.loads(X.record(ValueError(long)).removeprefix('HOLD_PAYLOAD: '))
        self.assertTrue(row['truncated'])
        self.assertEqual(row['message_prefix_bytes'], 8192)
        self.assertEqual(row['message_prefix_sha256'], hashlib.sha256(long.encode()[:8192]).hexdigest())
        unknown = type('PRIVATE_CLASS_PATH', (Exception,), {})
        self.assertEqual(json.loads(X.record(unknown(private)).removeprefix('HOLD_PAYLOAD: '))['exception'], 'OTHER')
        with self.assertRaises(ValueError): X.phase(private)
        self.assertEqual(len(X.PHASES), 16)

    def test_actual_pidfd_identity_and_poll_predicates_over_models(self):
        readlink, fstat, polling = modeled_pidfd()
        with readlink, fstat, polling:
            self.assertEqual(F.pidfd_identity(7), dict(dev=11, inode=22))
            self.assertTrue(F.pidfd_exited(7, dict(dev=11, inode=22)))
            with self.assertRaises(ValueError): F.pidfd_exited(7, dict(dev=11, inode=99))
            for value in (None, True, -1, '7'):
                with self.subTest(fd=value), self.assertRaises(ValueError): F.pidfd_identity(value)
        for rows in ([], [(7, 0)], [(8, select.POLLIN)], [(7, select.POLLERR)],
                     [(7, select.POLLIN | select.POLLNVAL)], [(7, select.POLLIN | select.POLLERR)]):
            readlink, fstat, polling = modeled_pidfd(rows)
            with self.subTest(rows=rows), readlink, fstat, polling:
                self.assertFalse(F.pidfd_exited(7, dict(dev=11, inode=22)))
        for target in ('/foreign/file', 'anon_inode:[eventfd]'):
            with self.subTest(target=target), patch.object(os, 'readlink', return_value=target), self.assertRaises(ValueError):
                F.pidfd_identity(7)
        with patch.object(os, 'readlink', side_effect=FileNotFoundError('MODEL closed FD')), self.assertRaises(FileNotFoundError):
            F.pidfd_exited(7, dict(dev=11, inode=22))

    def test_failed_owner_retirement_requires_complete_unchanged_custody(self):
        owned, row, census = fixture()
        readlink, fstat, polling = modeled_pidfd()
        with readlink, fstat, polling:
            result = F.retire_failed('owner', NONCE, owned, row, row, 7, census)
        self.assertEqual(result['unit'], UNIT)
        self.assertEqual(result['retirement'], 'STOPPED_EMPTY_FAILED_OWNER')
        self.assertEqual(result['payload_exit'], 2)
        self.assertIs(result['payload_success'], False)
        self.assertIs(result['unit_reset'], False)
        modes = ('active-before', 'active-after', 'unknown-unit', 'foreign-description', 'foreign-cgroup',
                 'missing-start', 'missing-pid', 'unsubmitted', 'missing-ledger', 'foreign-ledger',
                 'missing-identity', 'missing-fd', 'zero-exit', 'signal-exit', 'timeout', 'oom',
                 'changed-exit', 'one-census', 'nonempty-events', 'nonempty-procs', 'unknown-census',
                 'wrong-census-group', 'census-live-fd', 'daemon', 'foreign-nonce')
        for mode in modes:
            owned, before, censuses = fixture()
            after = copy.deepcopy(before)
            fd, kind, nonce = 7, 'owner', NONCE
            if mode == 'active-before': before.update(ActiveState='active', SubState='running', MainPID='123', ControlGroup=GROUP)
            elif mode == 'active-after': after['ActiveState'] = 'active'
            elif mode == 'unknown-unit': after['LoadState'] = 'not-found'
            elif mode == 'foreign-description': after['Description'] = 'foreign'
            elif mode == 'foreign-cgroup': owned['cgroup'] = '/foreign'
            elif mode == 'missing-start': owned.pop('starttime')
            elif mode == 'missing-pid': owned.pop('pid')
            elif mode == 'unsubmitted': owned['submitted'] = False
            elif mode == 'missing-ledger': owned.pop('original_pidfd')
            elif mode == 'foreign-ledger': owned['original_pidfd'] = 8
            elif mode == 'missing-identity': owned.pop('original_pidfd_identity')
            elif mode == 'missing-fd': fd = None
            elif mode == 'zero-exit': after['ExecMainStatus'] = '0'
            elif mode == 'signal-exit': after['ExecMainCode'] = '2'
            elif mode == 'timeout': after['Result'] = 'timeout'
            elif mode == 'oom': after['Result'] = 'oom-kill'
            elif mode == 'changed-exit': after['ExecMainStatus'] = '3'
            elif mode == 'one-census': censuses.pop()
            elif mode == 'nonempty-events': censuses[1]['events_empty'] = False
            elif mode == 'nonempty-procs': censuses[1]['procs_empty'] = False
            elif mode == 'unknown-census': censuses[1]['events_empty'] = None
            elif mode == 'wrong-census-group': censuses[1]['cgroup'] = '/foreign'
            elif mode == 'census-live-fd': censuses[1]['pidfd_exited'] = False
            elif mode == 'daemon': kind = 'daemon'
            elif mode == 'foreign-nonce': nonce = 'b' * 32
            readlink, fstat, polling = modeled_pidfd()
            with self.subTest(mode=mode), readlink, fstat, polling, self.assertRaises(ValueError):
                F.retire_failed(kind, nonce, owned, before, after, fd, censuses)
        readlink, fstat, polling = modeled_pidfd([])
        owned, row, census = fixture()
        with readlink, fstat, polling, self.assertRaises(ValueError):
            F.retire_failed('owner', NONCE, owned, row, row, 7, census)

    def test_cgroup_census_bounded_files_and_unknown_are_never_empty(self):
        path = self.root / 'MODEL-cgroup'
        path.mkdir()
        events, procs = path / 'cgroup.events', path / 'cgroup.procs'
        events.write_bytes(b'populated 0\nfrozen 0\n')
        procs.write_bytes(b'')
        self.assertEqual(F.empty_snapshot(path), dict(path_present=True, events_empty=True, procs_empty=True))
        self.assertEqual(F.empty_snapshot(path / 'missing'), dict(path_present=False, events_empty=True, procs_empty=True))
        for body, processes in ((b'populated 1\n', b''), (b'unknown 0\n', b''),
                                (b'populated 1\npopulated 0\n', b''), (b'populated 0 extra\n', b''),
                                (b'populated 0\n', b'123\n'), (b'x' * 65537, b'')):
            events.write_bytes(body)
            procs.write_bytes(processes)
            with self.subTest(events=body[:60], procs=processes), self.assertRaises(ValueError):
                F.empty_snapshot(path)
        events.write_bytes(b'populated 0\n')
        procs.write_bytes(b'')
        link = self.root / 'MODEL-symlink'
        link.symlink_to(path, target_is_directory=True)
        with self.assertRaises(ValueError): F.empty_snapshot(link)
        events.unlink()
        events.symlink_to(procs)
        with self.assertRaises(OSError): F.empty_snapshot(path)
        with patch.object(Path, 'lstat', side_effect=PermissionError('MODEL unknown census permission')), self.assertRaises(PermissionError):
            F.empty_snapshot(path)
        before = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_dev=1, st_ino=2)
        after = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_dev=1, st_ino=3)
        with patch.object(Path, 'lstat', side_effect=[before, after]), \
             patch.object(F, 'bounded', side_effect=[b'populated 0\n', b'']), self.assertRaises(ValueError):
            F.empty_snapshot(path)

    def projected_stop(self, mode='failed'):
        scope = dict(D=D, F=F, Path=Path, time=SimpleNamespace(sleep=lambda _: None))
        exec(compile(ast.Module(body=[function(OWNER, 'stop')], type_ignores=[]), '<actual-Fish-v6-stop-DATA>', 'exec'), scope)
        owned, row, censuses = fixture()
        after = copy.deepcopy(row)
        if mode == 'active': after.update(ActiveState='active', SubState='running', MainPID='123', ControlGroup=GROUP)
        elif mode == 'foreign': row['Description'] = 'foreign'
        elif mode == 'changed-exit': after['ExecMainStatus'] = '3'
        elif mode == 'missing-custody': owned.pop('original_pidfd')
        elif mode == 'nonempty': censuses[1]['procs_empty'] = False
        elif mode == 'unknown-census': censuses[1]['events_empty'] = None
        elif mode == 'foreign-fd': owned['original_pidfd_identity']['inode'] = 99
        show = Mock(side_effect=[row, after, after])
        run = Mock()
        model = SimpleNamespace(nonce=NONCE, units={'owner': owned}, pidfds={'owner': 7},
                                show=show, tool=lambda _: '/usr/bin/systemctl', run=run)
        snapshots = [dict((key, value) for key, value in item.items() if key not in ('cgroup', 'pidfd_exited')) for item in censuses]
        readlink, fstat, polling = modeled_pidfd([] if mode == 'live-fd' else None)
        with readlink, fstat, polling, patch.object(F, 'empty_snapshot', side_effect=snapshots) as snapshot:
            if mode == 'failed':
                result = scope['stop'](model, 'owner')
                self.assertEqual(snapshot.call_count, 2)
                self.assertEqual(snapshot.call_args_list[0].args, (Path('/sys/fs/cgroup' + GROUP),))
                self.assertEqual(snapshot.call_args_list[1].args, (Path('/sys/fs/cgroup' + GROUP),))
                run.assert_called_once_with(['/usr/bin/systemctl', 'stop', UNIT], 20)
                self.assertEqual(result['retirement'], 'STOPPED_EMPTY_FAILED_OWNER')
                self.assertIs(result['payload_success'], False)
                self.assertIs(result['unit_reset'], False)
            else:
                with self.assertRaises((ValueError, OSError)): scope['stop'](model, 'owner')
                if mode == 'foreign': run.assert_not_called()

    def test_actual_projected_stop_strict_failed_owner_and_refusals(self):
        for mode in ('failed', 'active', 'foreign', 'changed-exit', 'missing-custody', 'nonempty',
                     'unknown-census', 'foreign-fd', 'live-fd'):
            with self.subTest(mode=mode): self.projected_stop(mode)
        scope = dict(D=D, F=F, Path=Path, time=SimpleNamespace(sleep=lambda _: None))
        exec(compile(ast.Module(body=[function(OWNER, 'stop')], type_ignores=[]), '<actual-Fish-v6-stop-DATA>', 'exec'), scope)
        self.assertEqual(scope['stop'](SimpleNamespace(units={}), 'owner'), dict(submitted=False))

    def test_actual_final_status_keeps_failed_payload_hold_after_retirement(self):
        passed = 'PASS_CURRENT_FISH02_NATIVE_PAIR_EXTERNAL_DOMAINS_ONLY'
        nodes = [node for node in ast.walk(function(OWNER, 'main')) if isinstance(node, ast.If) and
                 any(isinstance(statement, ast.Assign) and isinstance(statement.value, ast.Constant) and
                     statement.value.value == passed for statement in node.body)]
        self.assertEqual(len(nodes), 1, 'one actual final payload/cleanup acceptance branch')
        branch = compile(ast.Module(body=nodes, type_ignores=[]), '<actual-Fish-v6-final-status-DATA>', 'exec')
        owned, row, census = fixture()
        readlink, fstat, polling = modeled_pidfd()
        with readlink, fstat, polling:
            retired = F.retire_failed('owner', NONCE, owned, row, row, 7, census)
        self.assertIs(retired['payload_success'], False)
        for initial, errors, absent, expected in (
            ('HOLD', [], True, 'HOLD'),
            ('PAIR_PASSED_PENDING_EXTERNAL_CLEANUP', [], True, passed),
            ('PAIR_PASSED_PENDING_EXTERNAL_CLEANUP', [{'step': 'MODEL cleanup failure'}], True, 'HOLD'),
            ('PAIR_PASSED_PENDING_EXTERNAL_CLEANUP', [], False, 'HOLD'),
            ('PAIR_PASSED_PENDING_EXTERNAL_CLEANUP', [{'step': 'MODEL cleanup failure'}], False, 'HOLD'),
        ):
            report = dict(status=initial, native_pair='NOT RUN' if initial == 'HOLD' else 'MODEL_PREEXISTING_PAIR',
                          cleanup=dict(services={'owner': copy.deepcopy(retired)}, errors=errors,
                                       owned_storage_absent=absent))
            original_pair = report['native_pair']
            with self.subTest(initial=initial, errors=errors, storage_absent=absent):
                exec(branch, {'report': report})
                self.assertEqual(report['status'], expected)
                self.assertEqual(report['native_pair'], original_pair, 'retirement never creates payload evidence')
                self.assertIs(report['cleanup']['services']['owner']['payload_success'], False)

    def test_generated_owner_and_payload_keep_original_acceptance_guards(self):
        old_owner, old_payload = ORIGINAL[PREFIX + 'hosted_owner.py'], ORIGINAL[PREFIX + 'payload.py']
        projected, seams = C.projections(ORIGINAL)
        for name, raw in projected.items():
            text = raw.decode()
            for seam in reversed(seams[name]):
                self.assertEqual(text.count(seam['after']), 1)
                text = text.replace(seam['after'], seam['before'])
            self.assertEqual(text.encode(), ORIGINAL[name])
        for name in ('cleanup', 'run', 'main', 'setup', 'preflight'):
            with self.subTest(function=name): self.assertEqual(shape(function(old_owner, name)), shape(function(OWNER, name)))
        self.assertNotIn('reset-failed', OWNER.decode())
        self.assertIn("'ordinary payload natural success required'", OWNER.decode())
        original_main, current_main = function(old_payload, 'main'), copy.deepcopy(function(PAYLOAD, 'main'))
        current_main.body = [node for node in current_main.body if not (
            isinstance(node, ast.Expr) and isinstance(node.value, ast.Call) and
            isinstance(node.value.func, ast.Attribute) and isinstance(node.value.func.value, ast.Name) and
            node.value.func.value.id == 'X' and node.value.func.attr == 'phase')]
        self.assertEqual(shape(original_main), shape(current_main))
        phases = [node.value.args[0].value for node in function(PAYLOAD, 'main').body if (
            isinstance(node, ast.Expr) and isinstance(node.value, ast.Call) and
            isinstance(node.value.func, ast.Attribute) and isinstance(node.value.func.value, ast.Name) and
            node.value.func.value.id == 'X' and node.value.func.attr == 'phase')]
        self.assertEqual(phases, list(X.PHASES))
        guards = lambda raw: [shape(node) for node in ast.walk(ast.parse(raw)) if isinstance(node, ast.Call) and
                             isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and
                             node.func.value.id == 'D' and node.func.attr == 'need']
        self.assertEqual(guards(old_payload), guards(PAYLOAD))
        handler = next(node for node in ast.walk(ast.parse(PAYLOAD)) if isinstance(node, ast.ExceptHandler))
        self.assertIn('X.record(error)', ast.unparse(handler))
        self.assertIn('SystemExit(2)', ast.unparse(handler))
        start = ast.unparse(function(OWNER, 'start'))
        self.assertIn('original_pidfd=fd', start)
        self.assertIn('original_pidfd_identity=F.pidfd_identity(fd)', start)

    def test_exact_constructor57_and_complete53_50_48_inverses(self):
        output = self.root / 'Source57'
        result = C.construct(BASE, output)
        self.assertEqual(result['files'], 57)
        for key in ('actual_source', 'actual_run', 'Root_authority', 'role_label'):
            self.assertIsNone(result[key])
        bodies = {path.relative_to(output).as_posix(): path.read_bytes() for path in output.rglob('*') if path.is_file()}
        validator = module(output / PREFIX / 'data.py')
        validator.source(output, C.pin(bodies['source-map.json'])['sha256'])
        restored53 = validator.inverse_source53(bodies)
        self.assertEqual(restored53, ORIGINAL)
        restored50 = validator.inverse_source50(restored53)
        self.assertEqual(len(restored50), 50)
        self.assertEqual(validator.inverse_source48(None, restored50)['files'], 48)
        policy = json.loads(bodies[PREFIX + 'policy.json'])
        self.assertEqual(policy.pop('payload_diagnostics'), X.DECLARATION)
        self.assertEqual(policy.pop('failed_owner_retirement'), F.DECLARATION)
        self.assertEqual(policy, json.loads(ORIGINAL[PREFIX + 'policy.json']))
        for name, body in ORIGINAL.items():
            if name.startswith(('held-source32/', '.github/')) or name.endswith('/go_cli_va.py'):
                with self.subTest(unchanged=name): self.assertEqual(bodies[name], body)
        self.assertEqual(bodies[PREFIX + 'payload_diagnostic.py'], (HERE / 'payload_diagnostic.py').read_bytes())
        self.assertEqual(bodies[PREFIX + 'failed_retirement.py'], (HERE / 'failed_retirement.py').read_bytes())
        self.assertEqual(C.construct(BASE, self.root / 'second-Source57'), result)
        self.assertEqual(C.frozen(BASE)[0], ORIGINAL)
        self.assertTrue(all(path.stat().st_mode & 0o777 == 0o644 for path in output.rglob('*') if path.is_file()))
        manifest = json.loads(bodies['source-map.json'])
        self.assertTrue(all(value is None for value in manifest['actual'].values()))

    def test_pinned_source_and_inverse_byte_drift_refuse(self):
        output = self.root / 'wrong-source'
        with self.assertRaises(ValueError): C.construct(PREVIEW, output)
        self.assertFalse(output.exists())
        original_read = C.read
        def changed_base(path):
            raw = original_read(path)
            return raw + b'MODEL drift' if Path(path) == BASE / 'LICENSE' else raw
        with patch.object(C, 'read', side_effect=changed_base), self.assertRaises(ValueError):
            C.construct(BASE, output)
        self.assertFalse(output.exists())
        bodies = {path.relative_to(PREVIEW).as_posix(): path.read_bytes() for path in PREVIEW.rglob('*') if path.is_file()}
        inverse = PREFIX + 'source53-inverse.json'
        proof = json.loads(bodies[inverse])
        for mode in ('before', 'after', 'added'):
            value = copy.deepcopy(proof)
            if mode == 'before': value['before_utf8'].pop(PREFIX + 'policy.json')
            elif mode == 'after': value['after'][PREFIX + 'failed_retirement.py']['sha256'] = '0' * 64
            else: value['added'].remove(PREFIX + 'failed_retirement.py')
            changed = dict(bodies, **{inverse: C.encode(value)})
            with self.subTest(mode=mode), self.assertRaises(ValueError): D.inverse_source53(changed)

    def test_whole_helper_and_provenance_pins_refuse_before_load_or_output(self):
        original_read = C.read
        for name in ('UPSTREAM.json', 'payload_diagnostic.py', 'failed_retirement.py'):
            output = self.root / ('drift-' + name)
            def changed_operand(path):
                raw = original_read(path)
                return raw + b'\n' if Path(path) == HERE / name else raw
            with self.subTest(name=name), patch.object(C, 'read', side_effect=changed_operand), \
                 patch.object(C, 'load_bytes', wraps=C.load_bytes) as imports:
                with self.assertRaises(ValueError): C.construct(BASE, output)
                self.assertFalse(any(call.args[1] in ('pinned_diagnostic', 'pinned_retirement')
                                     for call in imports.call_args_list))
                self.assertFalse(output.exists())


if __name__ == '__main__':
    if not sys.flags.isolated or not sys.flags.dont_write_bytecode or not __debug__:
        raise SystemExit('run unoptimized DATA controls with Python -I -B')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, required=True, help='explicit complete frozen Source53 DATA root')
    options, rest = parser.parse_known_args()
    BASE = options.base
    ORIGINAL, unused_manifest, unused_validator = C.frozen(BASE)
    with tempfile.TemporaryDirectory(prefix='FISH-V6-DATA.', dir=TEMP_ROOT) as temporary:
        PREVIEW = Path(temporary) / 'constructed-preview'
        C.construct(BASE, PREVIEW)
        D = module(PREVIEW / PREFIX / 'data.py')
        OWNER = (PREVIEW / PREFIX / 'hosted_owner.py').read_bytes()
        PAYLOAD = (PREVIEW / PREFIX / 'payload.py').read_bytes()
        unittest.main(argv=[sys.argv[0], *rest], verbosity=2)

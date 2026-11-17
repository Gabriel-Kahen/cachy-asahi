#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fenced DATA tests: actual generated run/helper, modeled limits and children.

No controller construction, host executable probe, real limit change, child,
Go probe, Root grant or native actor is entered. Constructor output is temporary
synthetic DATA, never a Root role output or an authority receipt.
"""
import argparse
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import resource
import sys
import tempfile
import time
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parent
PREFIX = 'scripts/ci/fish-config02-native-source/successor_v2/'
NORMAL = 536870912
DOCKER = 2147483648
PARENT = (NORMAL, DOCKER)
HELPER_PIN = dict(bytes=1996, sha256='3b2feba315f3a0e4cfed2498160e75591d64c7b8f0e8f5c11b46321b04b5eff3')
ACTORS = []
TEMP_ROOT = Path(os.environ.get('TMPDIR', '/dev/shm'))
if TEMP_ROOT not in (Path('/dev/shm'), Path('/tmp')):
    raise SystemExit('DATA TMPDIR must be /dev/shm or /tmp')
TEMP_PREFIX = str(TEMP_ROOT / 'FISH-V5-DATA.')


def fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.', 'fcntl.')) or event in {
        'resource.setrlimit', 'os.system', 'os.fork', 'os.forkpty', 'os.exec', 'os.posix_spawn', 'os.kill', 'os.killpg',
    }:
        ACTORS.append(event)
        raise AssertionError('FENCED no actual limit/process/network/custody actor: ' + event)
    if event == 'open' and isinstance(args[0], (str, bytes, os.PathLike)):
        if (args[2] or 0) & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
            if not str(Path(os.fsdecode(args[0])).absolute()).startswith(TEMP_PREFIX):
                raise AssertionError('FENCED writes only to disposable DATA fixture')


sys.addaudithook(fence)


def load(path):
    value = ModuleType('fenced_v5_' + path.stem)
    value.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), 'exec'), value.__dict__)
    return value


C = load(HERE / 'prepare.py')
I = load(HERE / 'inverse.py')
if C.pin((HERE / 'go_cli_va.py').read_bytes()) != HELPER_PIN:
    raise SystemExit('exact immutable helper required before pure policy import')
V = load(HERE / 'go_cli_va.py')


def run_scope():
    """Load only actual run/write definitions, bypassing actor __init__/imports."""
    tree = ast.parse(OWNER_RAW)
    controller = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'Controller')
    run = next(node for node in controller.body if isinstance(node, ast.FunctionDef) and node.name == 'run')
    write = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'write')
    scope = dict(D=D, H=H, V=V, resource=resource, os=os, json=json, time=SimpleNamespace(monotonic=lambda: 1000.0))
    exec(compile(ast.Module(body=[write, run], type_ignores=[]), '<actual-generated-v5-Controller.run-DATA>', 'exec'), scope)
    return scope


def observation(path):
    return dict(candidate=path, path=path, bytes=1, sha256='a' * 64, metadata={'MODEL': True}, chain=[], target_chain=[])


def retired(**changes):
    row = dict(reaped=True, ownership='REAPED', group_census='EMPTY_TWICE', output_complete=True,
               signals=[], timeout=False, error=None, exit=0, output=b'MODELED complete finite output\n')
    row.update(changes)
    return row


class Controls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='FISH-V5-DATA.', dir=TEMP_ROOT)
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(self.assertEqual, ACTORS, [], 'actual actor and setrlimit calls must be zero')
        self.pidfd = patch.object(os, 'pidfd_open', create=True, side_effect=AssertionError('NO actual PIDFD'))
        self.pidfd.start()
        self.addCleanup(self.pidfd.stop)

    def modeled_run(self, path='/usr/bin/docker', *, tools=None, parent=PARENT, retirement=None, check=True,
                    command_count=0, end=1100.0, cleanup_end=1200.0, cleaning=False, drift=False):
        """Execute the real run and helper callback over a modeled fork boundary."""
        tools = {name: observation('/usr/bin/' + name) for name in D.HOST_NAMES} if tools is None else tools
        events, child_pairs = [], []
        state = dict(pair=parent, phase='parent')
        scope = run_scope()
        output = self.root / ('run-' + str(len(list(self.root.iterdir()))))
        output.mkdir()
        supervise = Mock(return_value=retired() if retirement is None else copy.deepcopy(retirement))
        controller = SimpleNamespace(policy=copy.deepcopy(POLICY), tools=tools, commands=[{}] * command_count,
                                     end=end, cleanup_end=cleanup_end, cleaning=cleaning, out=output,
                                     O=SimpleNamespace(supervise=supervise))
        def observed(candidate):
            events.append(('H.checked', candidate))
            value = copy.deepcopy(next(row for row in tools.values() if row['candidate'] == candidate))
            if drift: value['sha256'] = 'b' * 64
            return value
        def getlimit(kind):
            self.assertEqual(kind, resource.RLIMIT_AS)
            events.append(('getrlimit', state['phase'], state['pair']))
            return state['pair']
        def setlimit(kind, pair):
            self.assertEqual(kind, resource.RLIMIT_AS)
            self.assertEqual(state['phase'], 'child', 'parent must never apply a child limit')
            events.append(('setrlimit', 'MODELED child only', pair))
            state['pair'] = pair
        def popen(argv, **kwargs):
            self.assertTrue(any(event[0] == 'H.checked' for event in events))
            self.assertEqual(events[-1], ('getrlimit', 'parent', parent))
            self.assertEqual(kwargs['env'], dict(PATH='/usr/bin:/bin', HOME=str(output), LC_ALL='C', DOCKER_BUILDKIT='0'))
            self.assertTrue(kwargs['start_new_session'])
            self.assertEqual((kwargs['stdin'], kwargs['stdout'], kwargs['stderr']), (-3, -1, -1))
            events.append(('Popen', 'MODELED no child created', argv))
            saved = state['pair']
            state['phase'] = 'child'
            try:
                kwargs['preexec_fn']() # Actual Root helper callback, mocked resource functions.
                child_pairs.append(state['pair'])
            finally:
                state.update(pair=saved, phase='parent')
            return 'MODELED_CHILD_HANDLE'
        launch = Mock(side_effect=popen)
        scope['subprocess'] = SimpleNamespace(Popen=launch, DEVNULL=-3, PIPE=-1)
        with patch.object(H, 'inspect', side_effect=observed), patch.object(resource, 'getrlimit', side_effect=getlimit), \
             patch.object(resource, 'setrlimit', side_effect=setlimit):
            try:
                value = scope['run'](controller, [path, '--MODEL'], seconds=30, check=check)
                error = None
            except ValueError as failure:
                value, error = None, failure
        self.assertEqual(state['pair'], parent, 'modeled parent retains its original soft/hard pair')
        return SimpleNamespace(value=value, error=error, launch=launch, supervise=supervise, controller=controller,
                               events=events, child_pairs=child_pairs, output=output)

    def test_actual_generated_run_docker_only_child_limits_and_receipts(self):
        for name in D.HOST_NAMES:
            with self.subTest(name=name):
                result = self.modeled_run('/usr/bin/' + name)
                self.assertIsNone(result.error)
                expected = (DOCKER, DOCKER) if name == 'docker' else (NORMAL, NORMAL)
                self.assertEqual(result.child_pairs, [expected])
                result.launch.assert_called_once()
                result.supervise.assert_called_once_with('MODELED_CHILD_HANDLE', cap=30, retirement=.5, grace=.1, max_output=1024**2)
                receipt = json.loads((result.output / 'command-001.json').read_bytes())
                self.assertEqual((receipt['address_space']['soft_bytes'], receipt['address_space']['hard_bytes']), expected)
                body = (result.output / 'command-001.bin').read_bytes()
                self.assertEqual(receipt['output'], D.pin(body))
                self.assertEqual(result.value, (0, body))
        tools = {'docker': observation('/usr/sbin/docker')}
        self.assertEqual(self.modeled_run('/usr/sbin/docker', tools=tools).child_pairs, [(DOCKER, DOCKER)])

    def test_run_refuses_unknown_noncanonical_drift_and_wrong_parent_before_popen(self):
        for pair in ((NORMAL, NORMAL), (DOCKER, DOCKER), (-1, -1), (NORMAL, -1)):
            with self.subTest(parent=pair):
                result = self.modeled_run(parent=pair)
                self.assertIsNotNone(result.error)
                result.launch.assert_not_called()
        for path, tools, drift in (
            ('docker', {'docker': observation('/usr/bin/docker')}, False),
            ('/usr/bin/docker', {'dockerd': observation('/usr/bin/dockerd')}, False),
            ('/usr/bin/unknown', {'docker': observation('/usr/bin/docker')}, False),
            ('/tmp/docker', {'docker': observation('/tmp/docker')}, False),
            ('/usr/bin/../bin/docker', {'docker': observation('/usr/bin/../bin/docker')}, False),
            ('/usr/bin/docker', {'docker': observation('/usr/bin/docker')}, True),
        ):
            with self.subTest(path=path, drift=drift):
                result = self.modeled_run(path, tools=tools, drift=drift)
                self.assertIsNotNone(result.error)
                result.launch.assert_not_called()

    def test_root_helper_exact_plans_callbacks_and_invalid_unlimited_refusals(self):
        self.assertEqual(V.controller_limit(POLICY), PARENT)
        policy = copy.deepcopy(POLICY)
        policy['docker_cli_address_space']['docker_cli_AS_bytes'] = -1
        with self.assertRaises(ValueError): V.controller_limit(policy)
        plans = [V.child_plan(['/usr/bin/docker'], {'docker': observation('/usr/bin/docker')}, POLICY),
                 V.child_plan(['/usr/bin/dockerd'], {'dockerd': observation('/usr/bin/dockerd')}, POLICY)]
        for plan in plans:
            pair = plan['soft_bytes'], plan['hard_bytes']
            with patch.object(resource, 'setrlimit') as setter, patch.object(resource, 'getrlimit', return_value=pair) as getter:
                V.child_limits(plan)()
                setter.assert_called_once_with(resource.RLIMIT_AS, pair)
                getter.assert_called_once_with(resource.RLIMIT_AS)
            with patch.object(resource, 'setrlimit'), patch.object(resource, 'getrlimit', return_value=PARENT):
                with self.assertRaisesRegex(ValueError, 'actual child finite AS'): V.child_limits(plan)()
        with patch.object(resource, 'setrlimit') as setter:
            for plan in (dict(kind='GO_DOCKER_CLI', soft_bytes=-1, hard_bytes=-1),
                         dict(kind='GO_DOCKER_CLI', soft_bytes=DOCKER, hard_bytes=-1),
                         dict(kind='NORMAL_HOST_CHILD', soft_bytes=NORMAL, hard_bytes=DOCKER),
                         dict(kind='OTHER', soft_bytes=DOCKER, hard_bytes=DOCKER), {}, None):
                with self.subTest(plan=plan), self.assertRaises(ValueError): V.child_limits(plan)
            setter.assert_not_called()
        for argv in ([], (), 'docker', ['/usr/bin/unknown'], ['docker']):
            with self.subTest(argv=argv), self.assertRaises(ValueError):
                V.child_plan(argv, {'docker': observation('/usr/bin/docker')}, POLICY)

    def test_actual_run_preserves_finite_supervision_and_natural_retirement_guards(self):
        for field, value in (('reaped', False), ('ownership', 'UNKNOWN'), ('group_census', 'EMPTY_ONCE'),
                             ('output_complete', False), ('signals', ['SIGTERM']), ('timeout', True), ('error', 'MODEL_ERROR'),
                             ('exit', 1), ('exit', False)):
            with self.subTest(field=field, value=value):
                result = self.modeled_run(retirement=retired(**{field: value}))
                self.assertIsNotNone(result.error)
                result.supervise.assert_called_once()
        for args in (dict(command_count=512), dict(end=1001.0)):
            result = self.modeled_run(**args)
            self.assertIsNotNone(result.error)
            result.launch.assert_not_called()
        result = self.modeled_run(end=900.0, cleanup_end=1005.0, cleaning=True, retirement=retired(exit=2), check=False)
        self.assertIsNone(result.error)
        result.supervise.assert_called_once_with('MODELED_CHILD_HANDLE', cap=5, retirement=.5, grace=.1, max_output=1024**2)

    def test_exact_constructor53_policy_only_declaration_and_full50_then48_inverse(self):
        original, old_manifest, unused = C.frozen(BASE)
        self.assertEqual(len(original), 50)
        self.assertEqual(sum(map(len, original.values())), 892625)
        self.assertEqual(I.SOURCE50['tree'], 'dff997f10bd4e917709f2b76d4c32f07ed379a03')
        output = self.root / 'constructed-DATA'
        receipt = C.construct(BASE, output)
        self.assertEqual(receipt['files'], 53)
        self.assertEqual(receipt['helper'], HELPER_PIN)
        for key in ('actual_source', 'Root_authority', 'actual_run'): self.assertIsNone(receipt[key])
        bodies = {path.relative_to(output).as_posix(): path.read_bytes() for path in output.rglob('*') if path.is_file()}
        validator = C.load_bytes(bodies[PREFIX + 'data.py'], 'constructed_DATA_validator', output / PREFIX / 'data.py')
        validator.source(output, receipt['source_map']['sha256'])
        restored = validator.inverse_source50(bodies)
        self.assertEqual(restored, original)
        self.assertEqual(validator.inverse_source48(None, restored)['files'], 48)
        policy = json.loads(bodies[PREFIX + 'policy.json'])
        self.assertEqual(policy.pop('docker_cli_address_space'), V.DECLARATION)
        self.assertEqual(policy, json.loads(original[PREFIX + 'policy.json']))
        self.assertEqual(bodies[PREFIX + 'go_cli_va.py'], (HERE / 'go_cli_va.py').read_bytes())
        for name, body in original.items():
            if name.startswith(('held-source32/', '.github/')):
                self.assertEqual(bodies[name], body)
        owner = bodies[PREFIX + 'hosted_owner.py'].decode()
        for before, after in reversed(C.OWNER_EDITS):
            self.assertEqual(owner.count(after), 1)
            owner = owner.replace(after, before)
        self.assertEqual(owner.encode(), original[PREFIX + 'hosted_owner.py'])
        self.assertEqual(C.construct(BASE, self.root / 'second-DATA'), receipt)
        self.assertEqual(C.frozen(BASE)[0], original, 'frozen Source50 remains unchanged')

    def test_null_foreign_requirement_and_helper_body_drift_refuse_before_output(self):
        requirement = json.loads((HERE / 'helper.REQUIRED.json').read_bytes())
        original_read = C.read
        variations = []
        for key in ('helper', 'api', 'upstream_commit'):
            value = copy.deepcopy(requirement)
            value[key] = None
            variations.append((key + '-NULL', value))
        for field, value in (('sha256', '0' * 64), ('bytes', 1997)):
            candidate = copy.deepcopy(requirement)
            candidate['helper'][field] = value
            variations.append((field + '-foreign', candidate))
        for key, value in (('upstream_commit', 'f' * 40), ('api', ['foreign_api(policy)'])):
            candidate = copy.deepcopy(requirement)
            candidate[key] = value
            variations.append((key + '-foreign', candidate))
        for label, value in variations:
            output = self.root / label
            def modeled_read(path):
                return C.encode(value) if Path(path) == HERE / 'helper.REQUIRED.json' else original_read(path)
            with self.subTest(label=label), patch.object(C, 'read', side_effect=modeled_read), \
                 patch.object(C, 'operand', side_effect=AssertionError('invalid requirement reached helper body')) as operand:
                with self.assertRaises(ValueError): C.construct(BASE, output)
                operand.assert_not_called()
                self.assertFalse(output.exists())
        output = self.root / 'helper-drift'
        def changed_helper(path):
            raw = original_read(path)
            return raw + b'\n# MODELED byte drift\n' if Path(path) == HERE / 'go_cli_va.py' else raw
        with patch.object(C, 'read', side_effect=changed_helper), patch.object(C, 'load_bytes', wraps=C.load_bytes) as imports:
            with self.assertRaisesRegex(ValueError, 'whole pinned Root operand'): C.construct(BASE, output)
            self.assertFalse(any(call.args[1] == 'whole_pinned_Root_va_helper' for call in imports.call_args_list))
        self.assertFalse(output.exists())

    def test_frozen_source50_drift_and_preview53_refuse_before_output(self):
        output = self.root / 'wrong-base'
        with self.assertRaisesRegex(ValueError, 'exact Source50 map'): C.construct(PREVIEW, output)
        self.assertFalse(output.exists())
        original_read = C.read
        def changed_base(path):
            raw = original_read(path)
            return raw + b'MODELED base drift' if Path(path) == BASE / 'LICENSE' else raw
        with patch.object(C, 'read', side_effect=changed_base):
            with self.assertRaisesRegex(ValueError, 'whole Source50 member'): C.construct(BASE, output)
        self.assertFalse(output.exists())

    def test_generated_preview_exact_source53_and_inverse_corruption_refuse(self):
        manifest = json.loads((PREVIEW / 'source-map.json').read_bytes())
        bodies = {'source-map.json': (PREVIEW / 'source-map.json').read_bytes()}
        bodies.update({name: (PREVIEW / name).read_bytes() for name in manifest['files']})
        self.assertEqual(len(bodies), 53)
        D.source(PREVIEW, D.pin(bodies['source-map.json'])['sha256'])
        self.assertEqual(D.inverse_source50(bodies), C.frozen(BASE)[0])
        self.assertEqual(OWNER_RAW, C.projected_owner(C.frozen(BASE)[0][PREFIX + 'hosted_owner.py']))
        name = PREFIX + 'source50-inverse.json'
        proof = json.loads(bodies[name])
        for mode in ('before', 'after', 'added'):
            value = copy.deepcopy(proof)
            if mode == 'before': value['before_utf8'].pop(PREFIX + 'policy.json')
            elif mode == 'after': value['after'][PREFIX + 'go_cli_va.py']['sha256'] = '0' * 64
            else: value['added'].remove(PREFIX + 'go_cli_va.py')
            changed = dict(bodies, **{name: C.encode(value)})
            with self.subTest(mode=mode), self.assertRaises(ValueError): D.inverse_source50(changed)


if __name__ == '__main__':
    if not sys.flags.isolated or not sys.flags.dont_write_bytecode or not __debug__:
        raise SystemExit('run unoptimized DATA controls with Python -I -B')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, required=True, help='explicit exact frozen Source50 DATA root')
    options, rest = parser.parse_known_args()
    BASE = options.base
    with tempfile.TemporaryDirectory(prefix='FISH-V5-DATA.', dir=TEMP_ROOT) as fixture:
        PREVIEW = Path(fixture) / 'constructed-preview'
        C.construct(BASE, PREVIEW)
        H = load(PREVIEW / PREFIX / 'host_tools.py')
        D = load(PREVIEW / PREFIX / 'data.py')
        OWNER_RAW = (PREVIEW / PREFIX / 'hosted_owner.py').read_bytes()
        POLICY = json.loads((PREVIEW / PREFIX / 'policy.json').read_bytes())
        unittest.main(argv=[sys.argv[0], *rest], verbosity=2)

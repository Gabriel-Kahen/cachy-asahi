#!/usr/bin/env python3
"""New pure DATA controls; no actors, network, native execution or old suite."""
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import types
import unittest

sys.dont_write_bytecode = True
SOURCE = Path(os.environ.get('DESKTOP_CENSUS_SOURCE', Path(__file__).resolve().parents[1] / 'proposed-source')).resolve()
DENIED = []


def audit(event, args):
    if (event.startswith(('subprocess.', 'socket.')) or event in
            ('os.system', 'os.posix_spawn', 'os.fork', 'os.forkpty', 'os.exec', 'os.kill', 'os.killpg', 'pty.spawn')):
        DENIED.append(event)
        raise AssertionError('process/network actor denied: ' + event)


sys.addaudithook(audit)


def need(value, message):
    if not value:
        raise ValueError(message)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


ALPM = ast.parse((SOURCE / 'native/desktop_alpm_v1.py').read_bytes())
READER = ast.parse((SOURCE / 'native/desktop_reader_v1.py').read_bytes())


def functions(tree, names, extra=None):
    namespace = dict(need=need, re=re, Path=Path, pin=pin, CENSUS_CORE_SHA256='83444522f4dfede67f6965ea75de8411b9e34510c04d40571fe439c223294e8f',
                     T=types.SimpleNamespace(encoded=encoded))
    if extra:
        namespace.update(extra)
    nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    assert {node.name for node in nodes} == set(names)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), '<trusted-local-pure-functions>', 'exec'), namespace)
    return namespace


A = functions(ALPM, ['observe_group_census', 'record_group_census', 'retain_group_census'])
R = functions(READER, ['retained_group_census_diagnostics', 'retained_public_projection', 'desktop_commands'])
for node in READER.body:
    if isinstance(node, ast.Assign) and any(isinstance(n, ast.Name) and n.id == 'PRODUCERS' for n in node.targets):
        R['PRODUCERS'] = ast.literal_eval(node.value)


def command(census='PRESENT_OR_REUSED', success=False, index=0):
    return dict(step='build-a', argv=['/usr/bin/makepkg'], expected=0, success=success,
                log='%03d-build-a.log' % index, log_pin=pin(b'complete original DATA\n'),
                supervision=dict(exit=0, reaped=True, ownership='REAPED', timeout=False, signals=[],
                                 output_complete=True, group_census=census, error=None, seconds=1, passed=success))


def observation(count=1):
    return dict(kind='MATCHES', leader=41, member_count=count, truncated=count > 32,
                members=[dict(pid=i + 41, start_ticks=i + 100, state='Z') for i in range(min(count, 32))])


def diagnostic(index=0, scans=None):
    return dict(schema=1, command_index=index, source_core_sha256=A['CENSUS_CORE_SHA256'],
                scope='ORIGINAL_POST_REAP_SCAN_MATCHES_MAY_BE_REUSED', scans=scans or [observation()])


def failed(index=0):
    row = command(index=index)
    row['group_census_diagnostic'] = diagnostic(index)
    return row


class Core:
    def __init__(self, result=None, error=None):
        self.result = {(41, 100, b'Z')} if result is None else result
        self.error, self.calls = error, []

    def _members(self, pid, deadline, *, live=False):
        self.calls.append((pid, deadline, live))
        if self.error is not None:
            raise self.error
        return self.result

    def forbidden(self, *args, **kwargs):
        raise AssertionError('unexpected additional process operation')

    _stat = _rss_members = waitpid = waitid = kill = killpg = pidfd_open = forbidden


class View:
    def __init__(self, commands):
        prefix = 'journey/desktop-alpm-v1/'
        self.bodies = {'receipt.json': encoded({}), prefix + 'result.json': encoded(dict(commands=commands)),
                       prefix + 'commands.json': encoded(commands)}
        for row in commands:
            self.bodies[prefix + row['log']] = b'complete original DATA\n'
        selected = {n: dict(kind='file', mode=0o600, source_mode=0o644, **pin(b)) for n, b in self.bodies.items()}
        self.binding = dict(source='1'*40, ref='refs/heads/codex/data', run='7', attempt=1, token='test')
        self.map_sha = '2'*64
        projection = dict(schema=1, status='PASS_FINITE_DESKTOP_ALPM_PUBLIC_DATA_PROJECTION', binding=self.binding,
            source_map_sha256=self.map_sha, source_producers=R['PRODUCERS'], selected=selected,
            omitted_private_scopes=['journey/desktop-alpm-v1/home'], original_output_unchanged=True,
            omitted_private_trees_walked=False, archive_custody={},
            privacy='Ordinary DATA marker refusal; only exact source-bound package tar custody permits bound public source identifiers',
            scope='Fixed desktop-alpm-v1 result, commands and raw referenced logs only; private home trees not retained')
        self.bodies['public-projection.json'] = encoded(projection)
        self.files = {n: dict(kind='file', mode=0o600, **pin(b)) for n, b in self.bodies.items()}

    def read(self, name):
        return self.bodies[name]

    def load(self, name):
        return json.loads(self.read(name))


class RefusingScope:
    def __truediv__(self, name):
        self.name = name
        return self

    def write_bytes(self, raw):
        raise OSError('synthetic retention refused')


class CensusControls(unittest.TestCase):
    def tearDown(self):
        self.assertEqual(DENIED, [])

    def test_exact_call_and_same_return_object(self):
        core = Core()
        observations = A['observe_group_census'](types.SimpleNamespace(core=core))
        self.assertIs(core._members(41, 8.5), core.result)
        self.assertEqual(core.calls, [(41, 8.5, False)])
        self.assertEqual(observations, [observation()])

    def test_live_scan_has_no_diagnostic_or_extra_call(self):
        core = Core()
        observations = A['observe_group_census'](types.SimpleNamespace(core=core))
        self.assertIs(core._members(41, 8.5, live=True), core.result)
        self.assertEqual(core.calls, [(41, 8.5, True)])
        self.assertEqual(observations, [])

    def test_original_exception_identity_preserved(self):
        original = TimeoutError('synthetic original scan cap')
        core = Core(error=original)
        observations = A['observe_group_census'](types.SimpleNamespace(core=core))
        with self.assertRaises(TimeoutError) as caught:
            core._members(41, 8.5)
        self.assertIs(caught.exception, original)
        self.assertEqual(core.calls, [(41, 8.5, False)])
        self.assertEqual(observations, [dict(kind='REFUSED', leader=41, error_type='TimeoutError')])

    def test_last_two_original_scans_only(self):
        core = Core()
        observations = A['observe_group_census'](types.SimpleNamespace(core=core))
        for index in range(4):
            core._members(41, index)
        self.assertEqual(len(core.calls), 4)
        self.assertEqual(observations, [observation(), observation()])

    def test_max32_count_and_truncation(self):
        core = Core({(i+41, i+100, b'Z') for i in range(40)})
        observations = A['observe_group_census'](types.SimpleNamespace(core=core))
        self.assertIs(core._members(41, 8.5), core.result)
        self.assertEqual(observations, [observation(40)])
        row = command()
        commands = types.SimpleNamespace(records=[row])
        self.assertTrue(A['record_group_census'](commands, 0, observations))
        self.assertEqual(R['retained_group_census_diagnostics']([row])['commands'], 1)

    def test_capture_format_refusal_does_not_change_return(self):
        core = Core({(41, 100, b'\xff')})
        observations = A['observe_group_census'](types.SimpleNamespace(core=core))
        self.assertIs(core._members(41, 8.5), core.result)
        self.assertEqual(observations, [dict(kind='REFUSED', leader=41, error_type='UnicodeDecodeError')])

    def test_command_row_attachment_leaves_supervision_unchanged(self):
        row = command()
        state, before = row['supervision'], copy.deepcopy(row['supervision'])
        self.assertTrue(A['record_group_census'](types.SimpleNamespace(records=[row]), 0, [observation()]))
        self.assertIs(row['supervision'], state)
        self.assertEqual(state, before)
        self.assertFalse(row['success'])

    def test_no_success_or_unrecorded_row_attachment(self):
        row = command('EMPTY_TWICE', True)
        self.assertFalse(A['record_group_census'](types.SimpleNamespace(records=[row]), 0, [observation()]))
        self.assertNotIn('group_census_diagnostic', row)
        self.assertFalse(A['record_group_census'](types.SimpleNamespace(records=[]), 0, [observation()]))

    def test_primary_and_cleanup_indices_validate(self):
        commands = [failed(0), failed(1)]
        commands[1]['step'], commands[1]['log'] = 'retire-signing', '001-retire-signing.log'
        self.assertEqual(R['retained_group_census_diagnostics'](commands)['commands'], 2)

    def test_success_absence_is_optional(self):
        result = R['retained_group_census_diagnostics']([command('EMPTY_TWICE', True)])
        self.assertEqual(result, dict(status='VALIDATED_UNRESOLVED_ORIGINAL_GROUP_CENSUS_DATA_ONLY', commands=0, native='NOT_ADMITTED'))

    def test_required_missing_primary_and_cleanup_refused(self):
        for index in range(2):
            rows = [failed(0), failed(1)]
            del rows[index]['group_census_diagnostic']
            with self.subTest(index=index), self.assertRaises(ValueError):
                R['retained_group_census_diagnostics'](rows)

    def test_unknown_refusal_is_bound_unresolved_data(self):
        row = command('UNKNOWN')
        row['group_census_diagnostic'] = diagnostic(scans=[dict(kind='REFUSED', leader=41, error_type='TimeoutError')])
        self.assertEqual(R['retained_group_census_diagnostics']([row])['commands'], 1)

    def test_untyped_command_or_supervision_refused(self):
        for rows in (None, [False], [dict(supervision=['invalid'])], [dict(supervision=True)]):
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                R['retained_group_census_diagnostics'](rows)
        self.assertEqual(R['retained_group_census_diagnostics']([dict(success=False, supervision=None)])['commands'], 0)

    def test_representative_refusal_mutations(self):
        mutations = [
            lambda v: v.update(schema=True), lambda v: v.update(command_index=True),
            lambda v: v.update(command_index=1), lambda v: v.update(source_core_sha256='0'*64),
            lambda v: v.update(scope='ACCEPTED'), lambda v: v.update(scans=[]),
            lambda v: v.update(scans=[observation()]*3),
            lambda v: v['scans'][0].update(leader=True),
            lambda v: v.update(scans=[observation(), dict(observation(), leader=42)]),
            lambda v: v['scans'][0].update(member_count=True),
            lambda v: v['scans'][0].update(member_count=33),
            lambda v: v['scans'][0].update(truncated=True),
            lambda v: v['scans'][0]['members'][0].update(pid=0),
            lambda v: v['scans'][0]['members'][0].update(pid=True),
            lambda v: v['scans'][0]['members'][0].update(start_ticks=0),
            lambda v: v['scans'][0]['members'][0].update(state='ZZ'),
            lambda v: v['scans'][0].update(member_count=2, members=[dict(pid=41,start_ticks=100,state='Z')]*2),
            lambda v: v['scans'][0].update(member_count=2, members=[dict(pid=42,start_ticks=101,state='Z'), dict(pid=41,start_ticks=100,state='Z')]),
            lambda v: v.update(scans=[dict(kind='REFUSED', leader=41, error_type='TimeoutError')]),
            lambda v: v.update(extra=True),
        ]
        for index, mutate in enumerate(mutations):
            row = failed()
            mutate(row['group_census_diagnostic'])
            with self.subTest(index=index), self.assertRaises(ValueError):
                R['retained_group_census_diagnostics']([row])

    def test_failure_projection_route_enforces_diagnostic(self):
        view = View([failed()])
        result = R['retained_public_projection'](view, view.files, view.binding, view.map_sha)
        self.assertEqual(result['status'], 'VALIDATED_FINITE_DESKTOP_PUBLIC_DATA_PROJECTION_ONLY')
        view = View([command()])
        with self.assertRaisesRegex(ValueError, 'original scan diagnostic'):
            R['retained_public_projection'](view, view.files, view.binding, view.map_sha)

    def test_positive_route_keeps_empty_twice_requirement(self):
        row = command('EMPTY_TWICE', True)
        view = View([row])
        R['desktop_commands'](view, view.files, 'journey/desktop-alpm-v1/', [row])
        row = command('PRESENT_OR_REUSED', True)
        view = View([row])
        with self.assertRaisesRegex(ValueError, 'natural retirement'):
            R['desktop_commands'](view, view.files, 'journey/desktop-alpm-v1/', [row])
        row['group_census_diagnostic'] = diagnostic()
        with self.assertRaises(ValueError):
            R['retained_group_census_diagnostics']([row])

    def test_retention_failure_preserves_original_exception(self):
        primary = RuntimeError('original command failed')
        row, report = command(), {}
        try:
            try:
                raise primary
            except RuntimeError:
                A['retain_group_census'](types.SimpleNamespace(records=[row]), 0, [observation()], RefusingScope(), report)
                raise
        except RuntimeError as caught:
            self.assertIs(caught, primary)
        self.assertEqual(report['diagnostic_retention_failures'], [dict(kind='group-census', command_index=0, error_type='OSError')])

    def test_recording_exception_preserves_original_exception(self):
        namespace = functions(ALPM, ['retain_group_census'], dict(record_group_census=lambda *a: (_ for _ in ()).throw(ValueError('synthetic recording failure'))))
        primary, report = TimeoutError('original command timeout'), {}
        try:
            try:
                raise primary
            except TimeoutError:
                namespace['retain_group_census'](None, 0, [], RefusingScope(), report)
                raise
        except TimeoutError as caught:
            self.assertIs(caught, primary)
        self.assertEqual(report['diagnostic_retention_failures'][0]['error_type'], 'ValueError')

    def test_existing_core_and_workflow_are_byte_held(self):
        self.assertEqual(pin((SOURCE / 'scripts/virtual/owned_process.py').read_bytes())['sha256'], A['CENSUS_CORE_SHA256'])
        contract = json.loads((SOURCE / 'native/desktop-contract-v1.json').read_bytes())
        workflow = contract['original_workflow']
        self.assertEqual(pin((SOURCE / workflow['path']).read_bytes()), {k:workflow[k] for k in ('bytes','sha256')})

    def test_no_new_probe_wait_signal_and_both_instance_sites(self):
        forbidden = {'_stat','_rss_members','waitpid','waitid','kill','killpg','pidfd_open','stat','scandir','sleep','supervise'}
        helpers = [n for n in ALPM.body if isinstance(n,ast.FunctionDef) and n.name in ('observe_group_census','record_group_census','retain_group_census')]
        calls = [n for node in helpers for n in ast.walk(node) if isinstance(n,ast.Call)]
        called = {n.func.id if isinstance(n.func,ast.Name) else n.func.attr if isinstance(n.func,ast.Attribute) else '' for n in calls}
        self.assertFalse(called & forbidden)
        inside = next(n for n in ALPM.body if isinstance(n,ast.FunctionDef) and n.name=='inside')
        observe = [n for n in ast.walk(inside) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='observe_group_census']
        retain = [n for n in ast.walk(inside) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='retain_group_census']
        self.assertEqual(len(observe), 2)
        self.assertEqual(len(retain), 2)


if __name__ == '__main__':
    unittest.main(verbosity=2)

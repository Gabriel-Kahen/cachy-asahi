"""NEW pure AST controls: existing-scan observation, unchanged refusal, typed DATA."""
import ast
import copy
import os
from pathlib import Path
import re
import sys
from types import SimpleNamespace
import unittest

sys.dont_write_bytecode = True
SOURCE = Path(os.environ['IMAGE_TOOLS_NATIVE_SOURCE']).resolve() / 'native'


def deny(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.')) or event in (
            'os.system', 'os.fork', 'os.posix_spawn', 'os.exec', 'os.kill', 'os.killpg'):
        raise AssertionError('NEW_DATA_CONTROLS_DENY_ACTORS')


sys.addaudithook(deny)


def need(value, message):
    if not value:
        raise ValueError(message)


def selected(path, names):
    tree = ast.parse(path.read_bytes())
    nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    assert {node.name for node in nodes} == set(names)
    space = dict(need=need, re=re, CENSUS_CORE_SHA256='83444522f4dfede67f6965ea75de8411b9e34510c04d40571fe439c223294e8f')
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), 'exec'), space)
    return space


A = selected(SOURCE / 'image_alpm_v1.py', ['observe_group_census', 'record_group_census'])
R = selected(SOURCE / 'image_reader_v1.py', ['retained_group_census_diagnostics'])['retained_group_census_diagnostics']


def command(census='PRESENT_OR_REUSED', success=False):
    return dict(step='build-a', success=success, supervision=dict(exit=0, reaped=True,
        ownership='REAPED', group_census=census, output_complete=True, timeout=False,
        signals=[], error=None, passed=False))


class Diagnostic(unittest.TestCase):
    def model(self, members, census='PRESENT_OR_REUSED'):
        calls = []

        def original(pid, deadline, *, live=False):
            calls.append((pid, deadline, live))
            return members

        commands = SimpleNamespace(core=SimpleNamespace(_members=original), records=[command(census)])
        scans = A['observe_group_census'](commands)
        result = commands.core._members(123, 456.0)
        self.assertIs(result, members)
        self.assertEqual(calls, [(123, 456.0, False)])
        before = copy.deepcopy(commands.records[0])
        self.assertTrue(A['record_group_census'](commands, 0, scans))
        self.assertEqual({k: v for k, v in commands.records[0].items() if k != 'group_census_diagnostic'}, before)
        return commands, scans, calls

    def test_actual_failure_shape_stays_failed(self):
        commands, scans, calls = self.model({(124, 900, b'Z')})
        self.assertFalse(commands.records[0]['success'])
        self.assertFalse(commands.records[0]['supervision']['passed'])
        self.assertEqual(R(commands.records)['commands'], 1)

    def test_max32_sorted_rows_with_exact_total(self):
        commands, scans, calls = self.model({(n, n + 1000, b'S') for n in range(500, 540)})
        self.assertEqual(scans[0]['member_count'], 40)
        self.assertEqual(len(scans[0]['members']), 32)
        self.assertIs(scans[0]['truncated'], True)
        self.assertEqual(R(commands.records)['commands'], 1)

    def test_live_calls_are_not_additional_diagnostic_scans(self):
        members = {(124, 900, b'S')}
        calls = []
        commands = SimpleNamespace(core=SimpleNamespace(_members=lambda *a, **kw: calls.append((a, kw)) or members), records=[])
        scans = A['observe_group_census'](commands)
        self.assertIs(commands.core._members(123, 456.0, live=True), members)
        self.assertEqual(len(calls), 1)
        self.assertEqual(scans, [])

    def test_original_exception_identity_is_preserved(self):
        error = TimeoutError('existing census deadline')

        def original(*args, **kwargs):
            raise error

        commands = SimpleNamespace(core=SimpleNamespace(_members=original), records=[command('UNKNOWN')])
        scans = A['observe_group_census'](commands)
        with self.assertRaises(TimeoutError) as raised:
            commands.core._members(123, 456.0)
        self.assertIs(raised.exception, error)
        self.assertTrue(A['record_group_census'](commands, 0, scans))
        self.assertEqual(R(commands.records)['commands'], 1)

    def test_two_empty_success_scans_do_not_change_success(self):
        commands = SimpleNamespace(core=SimpleNamespace(_members=lambda *a, **kw: set()), records=[command('EMPTY_TWICE', True)])
        scans = A['observe_group_census'](commands)
        commands.core._members(123, 456.0)
        commands.core._members(123, 456.0)
        self.assertFalse(A['record_group_census'](commands, 0, scans))
        self.assertNotIn('group_census_diagnostic', commands.records[0])
        self.assertEqual(R(commands.records)['commands'], 0)

    def test_no_original_scan_is_never_fabricated(self):
        commands = SimpleNamespace(records=[command('UNKNOWN')])
        scans = A['observe_group_census'](commands)
        self.assertEqual(scans, [])
        self.assertFalse(A['record_group_census'](commands, 0, scans))
        self.assertEqual(R(commands.records)['commands'], 0)

    def test_missing_nonempty_scan_diagnostic_refuses(self):
        with self.assertRaisesRegex(ValueError, 'requires original scan'):
            R([command()])

    def test_malformed_or_positive_claims_refuse(self):
        commands, _, _ = self.model({(124, 900, b'Z')})
        original = commands.records
        mutations = [
            lambda v: v[0].update(success=True),
            lambda v: v[0]['group_census_diagnostic'].update(command_index=True),
            lambda v: v[0]['group_census_diagnostic'].update(source_core_sha256='0' * 64),
            lambda v: v[0]['group_census_diagnostic'].update(scope='OWNED_ABSENCE_PROVED'),
            lambda v: v[0]['group_census_diagnostic']['scans'][0].update(member_count=True),
            lambda v: v[0]['group_census_diagnostic']['scans'][0].update(truncated=True),
            lambda v: v[0]['group_census_diagnostic']['scans'][0]['members'][0].update(start_ticks=False),
            lambda v: v[0]['group_census_diagnostic']['scans'][0]['members'][0].update(state='live'),
            lambda v: v[0]['group_census_diagnostic']['scans'][0].update(member_count=0, members=[]),
        ]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                value = copy.deepcopy(original)
                mutate(value)
                with self.assertRaises(ValueError):
                    R(value)


if __name__ == '__main__':
    unittest.main(verbosity=2)

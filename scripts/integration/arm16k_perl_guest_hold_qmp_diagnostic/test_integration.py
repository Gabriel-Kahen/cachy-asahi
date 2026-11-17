"""Source-pinned, in-memory hook controls; never runs the controller or an actor."""
import ast
import hashlib
import json
from pathlib import Path
import re
import types
import unittest

HERE = Path(__file__).resolve().parent


def apply_proposal(original, patch):
    lines, out, position = original.splitlines(True), [], 0
    rows = patch.splitlines(True)
    index = 2
    while index < len(rows):
        header = re.match(r'@@ -(\d+)(?:,\d+)? \+\d+(?:,\d+)? @@', rows[index])
        if not header:
            raise ValueError('fixed unified patch hunk required')
        start = int(header.group(1)) - 1
        out.extend(lines[position:start])
        position, index = start, index + 1
        while index < len(rows) and not rows[index].startswith('@@'):
            row = rows[index]
            index += 1
            if row[0] in ' -':
                if lines[position] != row[1:]:
                    raise ValueError('exact original source context required')
                if row[0] == ' ':
                    out.append(lines[position])
                position += 1
            elif row[0] == '+':
                out.append(row[1:])
            else:
                raise ValueError('unsupported patch record')
    return ''.join(out + lines[position:])


class Integration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        basis = json.loads((HERE / 'integration-basis.DATA.json').read_text())
        raw = Path(basis['source']['path']).read_bytes()
        if (len(raw), hashlib.sha256(raw).hexdigest()) != (
                basis['source']['bytes'], basis['source']['sha256']):
            raise ValueError('Source339 source pin changed')
        cls.original = raw.decode()
        cls.proposed = apply_proposal(cls.original, (HERE / 'integration.UNISSUED.patch').read_text())
        cls.expected = basis['proposed_controller']

    def sampler(self):
        tree = ast.parse(self.proposed)
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef)
                        and n.name == 'diagnostic_sample')
        def need(value, message):
            if not value:
                raise ValueError(message)
        contract = types.SimpleNamespace(need=need, canonical=lambda value:
            (json.dumps(value, sort_keys=True, indent=2) + '\n').encode())
        values = {'module': lambda name: contract}
        exec(compile(ast.Module(body=[function], type_ignores=[]), '<hook-only>', 'exec'), values)
        return values['diagnostic_sample']

    def test_exact_proposed_source_compiles_without_execution(self):
        raw = self.proposed.encode()
        self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()),
                         (self.expected['bytes'], self.expected['sha256']))
        compile(self.proposed, '<unapplied-controller-proposal>', 'exec')

    def test_original_quit_call_and_retirement_requirements_preserved(self):
        def selected(source):
            tree = ast.parse(source)
            function = next(n for n in tree.body if isinstance(n, ast.FunctionDef)
                            and n.name == 'normal_hold_cleanup')
            calls = [n for n in ast.walk(function) if isinstance(n, ast.Call)]
            quit_call = next(n for n in calls if isinstance(n.func, ast.Name)
                             and n.func.id == 'quit_hold_qmp')
            requirements = [n for n in calls if isinstance(n.func, ast.Attribute)
                            and isinstance(n.func.value, ast.Name)
                            and n.func.value.id == 'K' and n.func.attr == 'need']
            return ast.dump(quit_call), [ast.dump(n) for n in requirements]
        self.assertEqual(selected(self.original), selected(self.proposed))

    def test_optional_failure_is_fixed_unavailable_without_private_error(self):
        class Failed:
            def sample(self, stage):
                raise RuntimeError('synthetic-private-error-must-not-appear')
        report = {}
        self.sampler()(Failed(), 'HOLD', report)
        self.assertTrue(report['guest_HOLD_state_diagnostic_unavailable'])
        self.assertNotIn('synthetic-private', json.dumps(report))
        self.sampler()(None, 'HOLD', None)

    def test_three_slots_and_canonical_report_component_bound(self):
        class Observer:
            def __init__(self, size=1):
                self.calls, self.size = 0, size
            def sample(self, stage):
                self.calls += 1
                return {'stage': stage, 'synthetic': 'x' * self.size}
        sample, observer, report = self.sampler(), Observer(), {}
        for stage in ('HOLD', 'BEFORE_QUIT', 'DEADLINE'):
            sample(observer, stage, report)
        sample(observer, 'DEADLINE', report)
        self.assertEqual(observer.calls, 3)
        self.assertEqual(len(report['guest_HOLD_state_observations']), 3)
        rejected = {}
        sample(Observer(65536), 'HOLD', rejected)
        self.assertEqual(rejected['guest_HOLD_state_observations'], [])
        self.assertTrue(rejected['guest_HOLD_state_diagnostic_unavailable'])


if __name__ == '__main__':
    unittest.main(verbosity=2)

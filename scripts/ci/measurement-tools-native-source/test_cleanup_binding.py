#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""New cleanup-binding DATA cases; evaluate AST slices, never import actors/readers."""
import argparse
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
READER_SHA256 = '24aae711a58e12fa41c9bd06268ce819d253964104a56466fff535e699682f6f'
CONTRACT_SHA256 = 'e1b8985635822cf02f11bddbd7afb157352c19e5f6e4945adf92c8a5e3c04913'
PASS = 'PASS_MEASUREMENT_TOOLS_NATIVE_ALPM_COMPONENT'
GUARD = 'actual same-source owner and cleanup outcomes'
ACTORS = []
PRODUCTION_IMPORTS = []


def need(value, message):
    if not value:
        raise ValueError(message)


def audit(event, args):
    if event.startswith(('subprocess.', 'socket.', 'os.exec', 'os.spawn')) or event in {
        'os.system', 'os.fork', 'os.forkpty', 'os.posix_spawn', 'os.kill', 'os.killpg', 'pty.spawn', 'ctypes.dlopen'
    }:
        ACTORS.append(event)
        raise RuntimeError('DATA-only actor denied: ' + event)
    if event == 'import' and args[0].split('.')[0] in {
        'owner', 'prepare', 'reader', 'capsule', 'common', 'measurement_reader_v1',
        'measurement_alpm_v1', 'measurement_tools_v1', 'measurement_projection_v1', 'measurement_guest_v1'
    }:
        PRODUCTION_IMPORTS.append(args[0])
        raise RuntimeError('production module import denied: ' + args[0])


def ordinary(path, cap=1024**2):
    path = Path(path).absolute()
    before = path.lstat()
    need(not any(p.is_symlink() for p in (path, *path.parents))
         and stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= cap,
         'bounded ordinary DATA input required')
    raw = path.read_bytes()
    fields = lambda row: (row.st_dev, row.st_ino, row.st_mode, row.st_nlink, row.st_size,
                          row.st_mtime_ns, row.st_ctime_ns)
    need(len(raw) == before.st_size and fields(before) == fields(path.lstat()), 'DATA changed during read')
    return raw


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def expression(node, names, methods=()):
    """Only bounded source-selected dictionary/boolean expressions may compile."""
    allowed = (ast.Expression, ast.Call, ast.Name, ast.Load, ast.Constant, ast.keyword,
               ast.Attribute, ast.List, ast.Dict, ast.BoolOp, ast.And, ast.Or, ast.Compare,
               ast.Eq, ast.NotEq, ast.UnaryOp, ast.Not, ast.Subscript)
    for child in ast.walk(node):
        need(isinstance(child, allowed), 'unexpected syntax in selected DATA expression')
        if isinstance(child, ast.Name):
            need(child.id in names, 'unexpected name in selected DATA expression')
        if isinstance(child, ast.Attribute):
            need(isinstance(child.value, ast.Name)
                 and ((child.value.id == 'args' and child.attr == 'map_sha256')
                      or (child.value.id in methods and child.attr == 'get')),
                 'unexpected attribute in selected DATA expression')
        if isinstance(child, ast.Call):
            need((isinstance(child.func, ast.Name) and child.func.id == 'dict')
                 or (isinstance(child.func, ast.Attribute) and child.func.attr == 'get'),
                 'unexpected call in selected DATA expression')
    return compile(ast.fix_missing_locations(ast.Expression(body=copy.deepcopy(node))),
                   '<cleanup-binding-DATA-expression>', 'eval')


class CleanupBinding(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.owner_raw = ordinary(OPTIONS.owner)
        cls.reader_raw = ordinary(OPTIONS.reader)
        cls.owner = ast.parse(cls.owner_raw, filename=str(OPTIONS.owner))
        cls.reader = ast.parse(cls.reader_raw, filename=str(OPTIONS.reader))
        cls.owner_run = next(n for n in cls.owner.body if isinstance(n, ast.FunctionDef) and n.name == 'run')
        cls.outer_try = next(n for n in cls.owner_run.body if isinstance(n, ast.Try))
        cls.constructors = []
        for node in ast.walk(cls.owner_run):
            if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'cleanup'
                                                  for t in node.targets):
                need(isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name)
                     and node.value.func.id == 'dict', 'cleanup assignments must be direct DATA dictionaries')
                cls.constructors.append((node, expression(node.value, {'dict', 'own', 'args', 'build_operations'})))
        cls.constructors.sort(key=lambda pair: pair[0].lineno)
        validate = next(n for n in cls.reader.body if isinstance(n, ast.FunctionDef) and n.name == 'validate')
        guards = [n for n in ast.walk(validate) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                  and n.func.id == 'need' and len(n.args) == 2 and isinstance(n.args[1], ast.Constant)
                  and n.args[1].value == GUARD]
        need(len(guards) == 1, 'one unchanged reader same-source guard required')
        cls.guard = expression(guards[0].args[0], {'receipt', 'cleanup', 'binding', 'expected'},
                               ('receipt', 'cleanup'))
        branches = [n for n in validate.body if isinstance(n, ast.If)
                    and any(isinstance(v, ast.Constant) and v.value == 'VALIDATED_NATIVE_FAILURE_DATA_ONLY'
                            for statement in n.body for v in ast.walk(statement))]
        need(len(branches) == 1, 'one original native failure DATA route required')
        cls.failure_branch = branches[0]
        cls.failure = expression(branches[0].test, {'receipt', 'cleanup', 'PASS', 'diagnostic'},
                                 ('receipt', 'cleanup'))
        cls.binding = dict(source='45090bf73532af6f4e7b6fc22c7fc190bfb3c59a',
                           ref='refs/heads/codex/measurement-cleanup-synthetic', run='41207305491', attempt=1)
        cls.binding['token'] = hashlib.sha256((':'.join(cls.binding[k] for k in ('source', 'ref', 'run'))).encode()).hexdigest()[:24]
        cls.map = 'a' * 64

    def contexts(self):
        own = copy.deepcopy(self.binding)
        args = SimpleNamespace(map_sha256=self.map)
        return [eval(code, {'__builtins__': {}}, dict(dict=dict, own=own, args=args, build_operations=[]))
                for _, code in self.constructors]

    def accepts(self, receipt, cleanup):
        return eval(self.guard, {'__builtins__': {}},
                    dict(receipt=receipt, cleanup=cleanup, binding=self.binding,
                         expected=dict(map_sha256=self.map)))

    def receipt(self):
        return dict(binding=copy.deepcopy(self.binding), source_map_sha256=self.map, status='FAIL')

    def test_01_both_producer_cleanup_contexts_are_bound(self):
        self.assertEqual(len(self.constructors), 2)
        rows = self.contexts()
        self.assertEqual([r['status'] for r in rows], ['UNKNOWN', 'UNKNOWN_NOT_ACCEPTED'])
        for row in rows:
            self.assertEqual(row['binding'], self.binding)
            self.assertEqual(row['source_map_sha256'], self.map)
            self.assertTrue(self.accepts(self.receipt(), row))

    def test_02_initial_and_finally_failure_paths_keep_context_before_save(self):
        initial, final = [node for node, _ in self.constructors]
        self.assertLess(initial.lineno, self.outer_try.lineno)
        self.assertIn(final, self.outer_try.finalbody)
        saves = [n for n in ast.walk(self.outer_try) if isinstance(n, ast.Call)
                 and isinstance(n.func, ast.Name) and n.func.id == 'save' and len(n.args) == 2
                 and isinstance(n.args[0], ast.BinOp) and isinstance(n.args[0].op, ast.Div)
                 and isinstance(n.args[0].right, ast.Constant) and n.args[0].right.value == 'cleanup.json']
        self.assertEqual(len(saves), 2)  # Initial finally persistence, then pre-projection persistence.
        final_nodes = {node for statement in self.outer_try.finalbody for node in ast.walk(statement)}
        direct_final_calls = [statement.value for statement in self.outer_try.finalbody
                              if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call)]
        for call in saves:
            self.assertIn(call, final_nodes)
            self.assertIn(call, direct_final_calls)
            self.assertEqual(ast.dump(call.args[0]),
                             "BinOp(left=Name(id='output', ctx=Load()), op=Div(), right=Constant(value='cleanup.json'))")
            self.assertEqual(ast.dump(call.args[1]), "Name(id='cleanup', ctx=Load())")
            self.assertGreater(call.lineno, final.lineno)
        stores = [node for node in ast.walk(self.owner_run) if isinstance(node, ast.Name)
                  and node.id == 'cleanup' and isinstance(node.ctx, ast.Store)]
        self.assertEqual(sorted(node.lineno for node in stores), [initial.lineno, final.lineno])
        for node in ast.walk(self.owner_run):
            if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name) and node.value.id == 'cleanup' \
                    and isinstance(node.ctx, (ast.Store, ast.Del)):
                self.assertIsInstance(node.slice, ast.Constant)
                self.assertNotIn(node.slice.value, ('binding', 'source_map_sha256'))
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                    and isinstance(node.func.value, ast.Name) and node.func.value.id == 'cleanup':
                self.assertIn(node.func.attr, ('get', 'update'))
                if node.func.attr == 'update':
                    self.assertEqual(node.args, [])
                    self.assertTrue(all(keyword.arg in ('status', 'error') for keyword in node.keywords))
        self.assertFalse(any(isinstance(n, ast.Delete) and any(isinstance(x, ast.Name) and x.id == 'cleanup'
                                                             for x in ast.walk(n)) for n in ast.walk(self.owner_run)))

    def test_03_early_and_retirement_failures_round_trip_as_bound_data(self):
        for row in self.contexts():
            for status in ('UNKNOWN', 'UNKNOWN_NOT_ACCEPTED', 'FAIL_RETIREMENT_UNKNOWN'):
                with self.subTest(status=status):
                    value = dict(row, status=status, error='synthetic retained primary failure')
                    value = json.loads(json.dumps(value, sort_keys=True))
                    self.assertTrue(self.accepts(self.receipt(), value))
                    self.assertNotEqual(value['status'], 'PASS_EXACT_OWNED_RESOURCES_RETIRED')
                    self.assertEqual(value['error'], 'synthetic retained primary failure')

    def test_04_every_wrong_binding_selector_refused(self):
        for key in ('source', 'ref', 'run', 'attempt', 'token'):
            for target in ('receipt', 'cleanup', 'both'):
                with self.subTest(selector=key, target=target):
                    receipt, cleanup = self.receipt(), copy.deepcopy(self.contexts()[1])
                    for name, row in (('receipt', receipt), ('cleanup', cleanup)):
                        if target in (name, 'both'):
                            row['binding'][key] = 2 if key == 'attempt' else 'wrong'
                    self.assertFalse(self.accepts(receipt, cleanup))

    def test_05_missing_and_null_bindings_refused(self):
        for target in ('receipt', 'cleanup'):
            for absent in (True, False):
                with self.subTest(target=target, absent=absent):
                    receipt, cleanup = self.receipt(), copy.deepcopy(self.contexts()[1])
                    row = receipt if target == 'receipt' else cleanup
                    if absent:
                        del row['binding']
                    else:
                        row['binding'] = None
                    self.assertFalse(self.accepts(receipt, cleanup))

    def test_06_missing_null_and_wrong_maps_refused(self):
        for target in ('receipt', 'cleanup', 'both'):
            for bad in (None, '', 'b' * 64, 'missing'):
                with self.subTest(target=target, value=bad):
                    receipt, cleanup = self.receipt(), copy.deepcopy(self.contexts()[1])
                    for name, row in (('receipt', receipt), ('cleanup', cleanup)):
                        if target in (name, 'both'):
                            if bad == 'missing':
                                del row['source_map_sha256']
                            else:
                                row['source_map_sha256'] = bad
                    self.assertFalse(self.accepts(receipt, cleanup))

    def test_07_bound_failure_data_cannot_select_positive_route(self):
        for row in self.contexts():
            for receipt_status, cleanup_status, candidate in (
                ('FAIL', row['status'], False), ('FAIL', 'PASS_EXACT_OWNED_RESOURCES_RETIRED', True),
                (PASS, 'UNKNOWN_NOT_ACCEPTED', True), (PASS, 'PASS_EXACT_OWNED_RESOURCES_RETIRED', False)
            ):
                with self.subTest(receipt=receipt_status, cleanup=cleanup_status, candidate=candidate):
                    receipt = dict(self.receipt(), status=receipt_status)
                    cleanup = dict(row, status=cleanup_status)
                    self.assertTrue(self.accepts(receipt, cleanup))
                    self.assertTrue(eval(self.failure, {'__builtins__': {}},
                                         dict(receipt=receipt, cleanup=cleanup, PASS=PASS,
                                              diagnostic=dict(positive_candidate=candidate))))
        returned = next(n for n in self.failure_branch.body if isinstance(n, ast.Return)).value
        fields = {keyword.arg: keyword.value for keyword in returned.keywords}
        self.assertEqual(ast.literal_eval(fields['native']), 'NOT_ADMITTED')

    def test_08_reader_and_package_contract_are_unchanged(self):
        self.assertEqual(pin(self.reader_raw)['sha256'], READER_SHA256)
        raw = ordinary(OPTIONS.reader.parent / 'measurement-contract-v1.json')
        self.assertEqual(pin(raw)['sha256'], CONTRACT_SHA256)
        contract = json.loads(raw)
        self.assertEqual(contract['recipe']['expected_test_counts'], [8])
        self.assertEqual(len(contract['recipe']['source_files']), 18)
        self.assertEqual(len(contract['recipe']['payload_files']), 14)
        text = self.owner_raw.decode()
        for literal in ("'--read-only'", "'--cap-drop=ALL'", "'--security-opt=no-new-privileges'",
                        "'--pids-limit=256'", "'--memory=4g'", "'--cpus=2'"):
            self.assertIn(literal, text)

    def test_09_factory_profile_map_and_prepare_pins_join_new_owner(self):
        profile_raw = ordinary(OPTIONS.profile)
        profile = json.loads(profile_raw)
        owner_pin = dict(pin(self.owner_raw), mode=stat.S_IMODE(OPTIONS.owner.stat().st_mode))
        reader_pin = dict(pin(self.reader_raw), mode=stat.S_IMODE(OPTIONS.reader.stat().st_mode))
        self.assertEqual(profile['after']['native/owner.py'], owner_pin)
        self.assertEqual(profile['payload']['native/owner.py'], owner_pin)
        self.assertEqual(profile['after']['native/measurement_reader_v1.py'], reader_pin)
        raw = ordinary(OPTIONS.owner.parent / 'source-map.json')
        mapping = json.loads(raw)
        self.assertEqual(len(mapping['files']), 198)
        self.assertEqual(mapping['files']['native/owner.py'], owner_pin)
        self.assertEqual(mapping['files']['native/measurement_reader_v1.py'], reader_pin)
        self.assertEqual(len(profile['after']), 199)
        self.assertEqual(mapping['files'], {name: row for name, row in profile['after'].items()
                                            if name != 'native/source-map.json'})
        self.assertEqual(profile['source_map_sha256'], pin(raw)['sha256'])
        self.assertEqual(profile['after']['native/source-map.json'], dict(pin(raw), mode=420))
        self.assertEqual(profile['payload']['native/source-map.json'], dict(pin(raw), mode=420))
        prepare = ast.parse(ordinary(OPTIONS.prepare))
        fixed = [n.value for n in prepare.body if isinstance(n, ast.Assign)
                 and any(isinstance(t, ast.Name) and t.id == 'PROFILE_SHA256' for t in n.targets)]
        self.assertEqual(len(fixed), 1)
        self.assertEqual(ast.literal_eval(fixed[0]), pin(profile_raw)['sha256'])

    def test_10_zero_actor_attempts_and_no_production_module_imports(self):
        self.assertEqual(ACTORS, [])
        self.assertEqual(PRODUCTION_IMPORTS, [])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--owner', type=Path, required=True)
    parser.add_argument('--reader', type=Path, required=True)
    parser.add_argument('--profile', type=Path, default=HERE / 'profile.json')
    parser.add_argument('--prepare', type=Path, default=HERE / 'prepare.py')
    parser.add_argument('--result', type=Path, required=True)
    OPTIONS = parser.parse_args()
    need(not OPTIONS.result.exists(), 'fresh DATA result required')
    sys.addaudithook(audit)  # Before any production AST compile/eval or input selection.
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(CleanupBinding)
    cases = [case.id().split('.')[-1] for case in suite]
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    passed = result.wasSuccessful() and result.testsRun == len(cases) == 10 and not result.skipped
    record = dict(schema=1, status='PASS_NEW_CLEANUP_BINDING_DATA_ONLY' if passed else 'FAIL',
                  tests=result.testsRun, cases=cases, failures=len(result.failures), errors=len(result.errors),
                  skips=len(result.skipped), actor_attempts=ACTORS, production_module_imports=PRODUCTION_IMPORTS,
                  source_AST_slices_only=True, original_capsule_GETs=0, reader_validate_calls=0,
                  Source_constructor_calls=0, Source_emissions=0, old_controls_replayed=0,
                  native='NOT_RUN', namespace_support='UNKNOWN', native_acceptance='NOT_ADMITTED')
    with OPTIONS.result.open('x') as stream:
        json.dump(record, stream, sort_keys=True, indent=2)
        stream.write('\n')
    raise SystemExit(0 if passed else 1)

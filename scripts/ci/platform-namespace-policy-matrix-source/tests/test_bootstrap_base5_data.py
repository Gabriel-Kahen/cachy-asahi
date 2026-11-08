#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Three new fetch-selection DATA regressions; no Source imports or actors."""
import sys


def deny(event, args):
    if event.startswith(('socket.', 'subprocess.', 'ctypes.', 'pty.')) or event in (
            'os.system', 'os.fork', 'os.forkpty', 'os.exec', 'os.posix_spawn'):
        raise RuntimeError('actor forbidden: ' + event)
    if event == 'import' and args[0].split('.')[0] in {'socket', 'subprocess', 'ctypes', 'multiprocessing'}:
        raise RuntimeError('actor import forbidden')


sys.addaudithook(deny)

import argparse
import ast
import hashlib
import json
from pathlib import Path
import unittest

F = Path(__file__).resolve().parents[1]
BASIS = None
OPERATION = 'platform-namespace-policy-matrix-v1'


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def shape(text):
    return ast.dump(ast.parse(text, mode='eval').body, include_attributes=False)


def selection_data(node, operation):
    """Interpret only the finite selector AST as DATA, never compile/eval Source."""
    if isinstance(node, ast.Attribute) and shape(ast.unparse(node)) == shape('native.fetch'):
        return 'ORIGINAL_PINNED_FETCH'
    if isinstance(node, ast.Lambda):
        if shape(ast.unparse(node)) != shape('lambda row,selected_cache:cache_file(selected_cache,row)'):
            raise ValueError('unrecognized selector DATA')
        return 'CACHE_ONLY_FETCH'
    if isinstance(node, ast.IfExp) and shape(ast.unparse(node.test)) == shape('operation==MATRIX_OPERATION'):
        return selection_data(node.body if operation == OPERATION else node.orelse, operation)
    raise ValueError('unrecognized selector DATA')


def basis_json(name):
    profile = json.loads((F / 'parent-profile.json').read_bytes())
    raw = (BASIS / name).read_bytes()
    row = profile['files'][name]
    if len(raw) != row['bytes'] or hashlib.sha256(raw).hexdigest() != row['sha256']:
        raise ValueError('exact held basis DATA required: ' + name)
    return json.loads(raw)


class BootstrapBase5Data(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = (F / 'payload/native/owner.py').read_text()
        cls.owner_run = next(n for n in ast.parse(cls.raw).body if isinstance(n, ast.FunctionDef) and n.name == 'run')
        cls.selector = [n for n in ast.walk(cls.owner_run) if isinstance(n, ast.Assign)
                        and any(isinstance(t, ast.Name) and t.id == 'parent_fetch' for t in n.targets)]
        if len(cls.selector) != 1:
            raise ValueError('one base-input selector required')

    def test_matrix_old_missing_base_counterfactual_and_restored_original_fetch(self):
        old = ast.parse('(lambda row,selected_cache:cache_file(selected_cache,row)) '
                        'if operation==MATRIX_OPERATION else native.fetch', mode='eval').body
        self.assertEqual(selection_data(old, OPERATION), 'CACHE_ONLY_FETCH')
        for operation in ('source184', 'platform-alpm-v1', OPERATION):
            with self.subTest(operation=operation):
                self.assertEqual(selection_data(self.selector[0].value, operation), 'ORIGINAL_PINNED_FETCH')
        self.assertEqual(selection_data(old, 'platform-alpm-v1'), 'ORIGINAL_PINNED_FETCH')

    def test_exact_five_base_inputs_and_512_package_inputs_remain_disjoint(self):
        original = basis_json('bootstrap/scripts/ci/inputs.lock.json')
        extras = basis_json('native/input-profile.json')['additions']['rows']
        self.assertEqual(hashlib.sha256(encoded(original)).hexdigest(),
                         '00aab63e0b388efa1f9c7145ba49ffc8333987322de1482e9b6cc6d2676c9166')
        self.assertEqual(hashlib.sha256(encoded(extras)).hexdigest(),
                         '3c43d8e9216cc26ea9734080ca4c1291c69bc51962ab2f7b004a54cfd9b1574d')
        base = original['keyring_files'] + [original['rootfs']]
        base_names = {r['filename'] for r in base} | {original['rootfs']['filename'] + '.sig'}
        package_names = {r['filename'] + suffix for r in original['packages'] + extras for suffix in ('', '.sig')}
        self.assertEqual(len(base_names), 5)
        self.assertEqual(len(package_names), 512)
        self.assertFalse(base_names & package_names)
        self.assertTrue(all(r['url'].startswith('https://') for r in base))

    def test_full201_fixture_retains_explicit_git_modes_and_checker_authorities(self):
        rows = json.loads((F / 'tests/fixtures/source-full-map.json').read_bytes())
        self.assertEqual(len(rows), 201)
        for name, row in rows.items():
            with self.subTest(path=name):
                self.assertEqual(set(row), {'bytes', 'sha256', 'mode', 'blob', 'git_mode'})
                self.assertIn(row['mode'], (420, 493))
                self.assertEqual(row['git_mode'], '100755' if row['mode'] == 493 else '100644')
        checker = ast.parse((F / 'tests/check_constructed_source.py').read_bytes())
        constants = {target.id: node.value.value for node in checker.body
                     if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant)
                     for target in node.targets if isinstance(target, ast.Name)}
        profile = json.loads((F / 'parent-profile.json').read_bytes())
        overlay = json.loads((F / 'overlay-manifest.json').read_bytes())
        self.assertEqual({name: constants[name] for name in ('PARENT', 'PTREE', 'TREE', 'MAP')},
                         dict(PARENT=profile['parent'], PTREE=profile['parent_tree'],
                              TREE=overlay['expected_tree'], MAP=overlay['expected_map_sha256']))
        for variable, relative in [('profile_raw', 'parent-profile.json'),
                                   ('catalog_raw', 'tests/fixtures/catalog.json'),
                                   ('selected', 'overlay-manifest.json')]:
            expression = shape("pin(" + variable + ")['sha256']")
            pins = [n.comparators[0].value for n in ast.walk(checker)
                    if isinstance(n, ast.Compare) and len(n.ops) == 1
                    and isinstance(n.ops[0], ast.Eq) and len(n.comparators) == 1
                    and isinstance(n.comparators[0], ast.Constant)
                    and ast.dump(n.left, include_attributes=False) == expression]
            self.assertEqual(pins, [hashlib.sha256((F / relative).read_bytes()).hexdigest()], relative)

    def test_package_callback_stays_cache_only_before_unchanged_signed248_audit(self):
        calls = [n for n in ast.walk(self.owner_run) if isinstance(n, ast.Call)
                 and isinstance(n.func, ast.Name) and n.func.id == 'bind_fetch']
        self.assertEqual(len(calls), 1)
        self.assertEqual(shape(ast.unparse(calls[0])), shape(
            "bind_fetch(original,profile['additions']['rows'],args.cache,"
            'lambda row,selected_cache:cache_file(selected_cache,row),parent_fetch)'))
        self.assertLess(self.selector[0].lineno, calls[0].lineno)
        audits = [n for n in ast.walk(self.owner_run) if isinstance(n, ast.Call)
                  and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name)
                  and n.func.value.id == 'native' and n.func.attr == 'audit']
        self.assertTrue(any(shape(ast.unparse(n)) == shape('native.audit(original,args.cache,base)')
                            and n.lineno > calls[0].lineno for n in audits))
        self.assertIn("seed.prepare(args.carrier, args.cache, 'native248'", self.raw)
        self.assertIn("native.audit(original, args.cache, base) == 248", self.raw)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--basis', required=True, type=Path)
    args, rest = parser.parse_known_args()
    BASIS = args.basis.resolve(strict=True)
    unittest.main(argv=[sys.argv[0], *rest])

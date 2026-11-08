#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""New raw-parent bridge DATA checks; never import a Source module or reader."""
import sys


def deny(event, args):
    if event.startswith(('socket.', 'subprocess.', 'ctypes.', 'pty.')) or event in (
            'os.system', 'os.fork', 'os.forkpty', 'os.exec', 'os.posix_spawn'):
        raise RuntimeError('actor forbidden: ' + event)
    if event == 'import' and args[0].split('.')[0] in {'socket', 'subprocess', 'ctypes', 'multiprocessing'}:
        raise RuntimeError('actor import forbidden')


sys.addaudithook(deny)

import ast
import hashlib
import json
from pathlib import Path
import unittest

F = Path(__file__).resolve().parents[1]
HISTORICAL = '05df8c71ea2bcb525bb1cfbc59983452062a1e97'
PHYSICAL = '639e3f9b5176bf8ebe497fc0b247182af90904e7'


def oid(kind, raw):
    return hashlib.sha1(kind.encode() + b' ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def header(raw, name):
    prefix = name.encode() + b' '
    return [line[len(prefix):].decode() for line in raw.split(b'\n\n', 1)[0].splitlines()
            if line.startswith(prefix)]


def constants(raw):
    values = {}
    for node in ast.parse(raw).body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    values[target.id] = node.value.value
    return values


class ParentBridgeData(unittest.TestCase):
    def test_raw_identities_remain_distinct_with_same199_tree(self):
        profile = json.loads((F / 'parent-profile.json').read_bytes())
        old = (F / 'parent-commit.raw').read_bytes()
        physical = (F / 'tests/fixtures/raw-parent.txt').read_bytes()
        self.assertEqual(oid('commit', old), HISTORICAL)
        self.assertEqual(oid('commit', physical), PHYSICAL)
        self.assertNotEqual(old, physical)
        self.assertEqual(profile['parent'], HISTORICAL)
        self.assertEqual(profile['physical_git_parent'], PHYSICAL)
        self.assertEqual(header(old, 'tree'), header(physical, 'tree'))
        self.assertEqual(header(physical, 'tree'), [profile['parent_tree']])
        self.assertEqual(header(physical, 'parent'), [profile['physical_parent_sole_parent']])
        self.assertEqual(len(profile['files']), 199)

    def test_synthetic_source_and_independent_fixture_authorities_join(self):
        fixture = F / 'tests/fixtures'
        raw = (fixture / 'raw-source.txt').read_bytes()
        full = json.loads((fixture / 'source-full-map.json').read_bytes())
        mapped_raw = (fixture / 'source-map.json').read_bytes()
        mapped = json.loads(mapped_raw)
        authority = constants((F / 'tests/fake_owner.py').read_bytes())
        selected = json.loads((F / 'overlay-manifest.json').read_bytes())
        self.assertEqual(oid('commit', raw), authority['SOURCE'])
        self.assertEqual(header(raw, 'parent'), [PHYSICAL])
        self.assertNotEqual(header(raw, 'parent'), [HISTORICAL])
        self.assertEqual(header(raw, 'tree'), [selected['expected_tree']])
        self.assertEqual(len(full), 201)
        self.assertEqual(len(mapped['files']), 200)
        self.assertEqual(hashlib.sha256(mapped_raw).hexdigest(), authority['MAP'])
        self.assertEqual(authority['MAP'], selected['expected_map_sha256'])
        self.assertEqual(full['native/platform_namespace_policy_v1.py']['sha256'], authority['MODULE_SHA'])
        for name, row in json.loads((fixture / 'catalog.json').read_bytes())['files'].items():
            body = (fixture / name).read_bytes()
            self.assertEqual(dict(bytes=len(body), sha256=hashlib.sha256(body).hexdigest()), row)

    def test_fixed_physical_git_gate_preserves_frozen_logical_contract(self):
        raw = (F / 'payload/native/platform_namespace_policy_v1.py').read_bytes()
        profile = json.loads((F / 'parent-profile.json').read_bytes())
        values = constants(raw)
        self.assertEqual(values['PARENT'], HISTORICAL)
        self.assertEqual(values['MATRIX_GIT_PARENT'], PHYSICAL)
        core = profile['matrix_core']
        self.assertEqual(hashlib.sha256(raw[:core['bytes']]).hexdigest(), core['sha256'])
        contract_raw = (F / 'payload/native/platform-namespace-policy-v1.json').read_bytes()
        self.assertEqual(hashlib.sha256(contract_raw).hexdigest(), profile['matrix_contract']['sha256'])
        self.assertEqual(json.loads(contract_raw)['source_parent'], HISTORICAL)
        functions = {n.name: ast.get_source_segment(raw.decode(), n) for n in ast.parse(raw).body
                     if isinstance(n, ast.FunctionDef)}
        for name in ('validate_source_proof', 'owner_matrix', 'validate_runtime_evidence'):
            with self.subTest(function=name):
                self.assertIn('MATRIX_GIT_PARENT', functions[name])
                self.assertNotIn("'cat-file','commit',PARENT]", functions[name])
                self.assertNotIn("'ls-tree','-rz','--full-tree',PARENT]", functions[name])
        self.assertIn("proof.get('historical_parent')==PARENT", functions['validate_source_proof'])
        self.assertIn("proof.get('git_parent')==MATRIX_GIT_PARENT", functions['validate_source_proof'])


if __name__ == '__main__':
    unittest.main()

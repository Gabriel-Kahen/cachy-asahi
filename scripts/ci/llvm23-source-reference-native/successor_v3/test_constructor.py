#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Finite constructor DATA controls; no Source payload or operational role runs."""
import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
PARENT = ANCESTOR = None
ALIASES = ('.github/workflows/native-arm-build.yml',
           '.github/workflows/native-arm-llvm23-source-reference-v2.yml')
COMMON = 'hosted/common.py'
SAVED_MAP = 'previous-v2/source-map.json'
META = 'successor-v3.json'
OLD_ALIAS = b'.github/workflows/native-arm-llvm23-source-reference-v1.yml'
NEW_ALIAS = b'.github/workflows/native-arm-llvm23-source-reference-v2.yml'
V2_PREPARE_SHA = 'ba41cc4e3ec0dc285be5909fa32331c7ce1eb5dc33ebb1d2538ae5240aa75784'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


P = load('llvm_v3_constructor_controls', HERE / 'prepare.py')
ancestor_prepare = HERE.parent / 'successor_v2/prepare.py'
if hashlib.sha256(ancestor_prepare.read_bytes()).hexdigest() != V2_PREPARE_SHA:
    raise ValueError('frozen v2 constructor source differs')
P2 = load('llvm_v2_constructor_controls', ancestor_prepare)


def rebind_map(rows):
    """Let inner predicates see tampering instead of only the outer map mismatch."""
    manifest = json.loads(rows['source-map.json'][0])
    manifest['files'] = {n: dict(bytes=len(b), sha256=hashlib.sha256(b).hexdigest(), mode=mode)
                         for n, (b, mode) in rows.items() if n != 'source-map.json'}
    rows['source-map.json'] = ((json.dumps(manifest, sort_keys=True, indent=2, allow_nan=False) + '\n').encode(), 0o644)
    return rows


class ConstructorControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.before = P.parent(PARENT)
        cls.after = P.render(cls.before)

    def test_exact_parent_and_closed_map(self):
        rows = self.before
        self.assertEqual((len(rows), sum(len(b) for b, _ in rows.values())), (251, 40807998))
        self.assertEqual(P.fs.tree(rows), '87f5aa3537474c2dd33a02c50e869ea5fb25e7b4')
        self.assertEqual(P.fs.pin(rows['source-map.json'][0])['sha256'],
                         '809f57839dfd574b7abf0c65535321aeac08c58608d4f9597f936a7af78fb3a2')
        manifest = json.loads(rows['source-map.json'][0])
        self.assertEqual(manifest['files'], P.fs.descriptors({n: v for n, v in rows.items() if n != 'source-map.json'}))
        self.assertTrue(all(v is None for v in manifest['actual'].values()))

    def test_only_three_operational_leaves_two_additions_and_new_map(self):
        before, after = self.before, self.after
        self.assertEqual(set(after) - set(before), {SAVED_MAP, META})
        self.assertFalse(set(before) - set(after))
        self.assertEqual({n for n in before if before[n] != after[n]},
                         {COMMON, *ALIASES, 'source-map.json'})
        self.assertEqual(len(after), 253)
        manifest = json.loads(after['source-map.json'][0])
        self.assertEqual(manifest['files'], P.fs.descriptors({n: v for n, v in after.items() if n != 'source-map.json'}))

    def test_alias_and_workflow_guards_are_exact_literal_changes(self):
        old, mode = self.before[COMMON]
        new = self.after[COMMON][0]
        self.assertEqual(old.count(OLD_ALIAS), 1)
        self.assertEqual(new, old.replace(OLD_ALIAS, NEW_ALIAS))
        self.assertEqual(self.after[COMMON][1], mode)
        old_sha, new_sha = (hashlib.sha256(v).hexdigest().encode() for v in (old, new))
        self.assertEqual(new_sha.decode(), '67bdf69692f0014ae4b81e4507a205a9c0d598c2691c7723bbc1a782bc40df5d')
        for name in ALIASES:
            with self.subTest(name=name):
                body, mode = self.before[name]
                self.assertEqual(body.count(old_sha), 1)
                self.assertEqual(self.after[name], (body.replace(old_sha, new_sha), mode))
        self.assertEqual(self.after[ALIASES[0]], self.after[ALIASES[1]])

    def test_selfcontained_inverse_restores_every_parent_byte_and_mode(self):
        self.assertEqual(self.after[SAVED_MAP], self.before['source-map.json'])
        restored = P.undo(dict(self.after))
        self.assertEqual(restored, self.before)
        self.assertEqual(len(restored), 251)
        self.assertEqual(P.fs.tree(restored), P.fs.tree(self.before))

    def test_all_actor_candidate_original_and_v2_metadata_preserved(self):
        selected = {n for n in self.before if n.startswith(('actor/', 'packages/', 'original/'))}
        selected.update({'candidate-map.json', 'successor-v2.json', 'inverse.json',
                         'hosted/entry.py', 'hosted/producer.py', 'hosted/reader.py',
                         'hosted/volume.py', 'contract.json', 'policy.json', 'root-admission.TEMPLATE.json'})
        self.assertTrue({'actor/entry.py', 'actor/runtime.py', 'actor/container_mode.py',
                         'actor/runtime-derivation.json', 'actor/entry.sh'} <= selected)
        for name in selected:
            with self.subTest(name=name):
                self.assertEqual(self.after[name], self.before[name])

    def test_bindings_remain_outer_v2_inner_v1_and_actual_null(self):
        contract = json.loads(self.after['contract.json'][0])
        self.assertEqual(contract['operation'], 'llvm23-source-reference-native-v1')
        self.assertEqual(contract['outer_delegation']['operation'], 'llvm23-source-reference-native-v2')
        self.assertIn(b"OPERATION='llvm23-source-reference-native-v2'", self.after[COMMON][0])
        for name in ['source-map.json', META, 'successor-v2.json']:
            with self.subTest(name=name):
                actual = json.loads(self.after[name][0])['actual']
                self.assertEqual(set(actual), {'source', 'ref', 'run', 'job', 'reader', 'authority', 'approval', 'artifact', 'image'})
                self.assertTrue(all(v is None for v in actual.values()))

    def test_parent_map_body_mode_and_extra_leaf_refuse(self):
        for kind in ['map', 'body', 'mode', 'extra']:
            rows = dict(self.before)
            if kind == 'map':
                rows['source-map.json'] = (rows['source-map.json'][0] + b' ', 0o644)
            elif kind == 'body':
                rows[COMMON] = (rows[COMMON][0] + b'\n', rows[COMMON][1])
            elif kind == 'mode':
                rows[COMMON] = (rows[COMMON][0], 0o755)
            else:
                rows['unrecorded.txt'] = (b'inert DATA\n', 0o644)
            with self.subTest(kind=kind), patch.object(P.fs, 'snapshot', return_value=rows), self.assertRaises(ValueError):
                P.parent(PARENT)

    def test_render_requires_the_exact_parent_mapping(self):
        for kind in ['body', 'mode', 'extra']:
            rows = dict(self.before)
            if kind == 'body':
                rows[COMMON] = (rows[COMMON][0] + b'\n', 0o644)
            elif kind == 'mode':
                rows['actor/entry.py'] = (rows['actor/entry.py'][0], 0o755)
            else:
                rows['unrecorded.txt'] = (b'inert DATA\n', 0o644)
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                P.render(rows)

    def test_undo_refuses_alias_guard_body_mode_and_extra_leaf(self):
        for kind in ['alias', 'guard', 'body', 'mode', 'extra']:
            rows = dict(self.after)
            if kind == 'alias':
                rows[COMMON] = (rows[COMMON][0].replace(NEW_ALIAS, OLD_ALIAS), 0o644)
            elif kind == 'guard':
                current = hashlib.sha256(rows[COMMON][0]).hexdigest().encode()
                rows[ALIASES[0]] = (rows[ALIASES[0]][0].replace(current, b'0' * 64), 0o644)
            elif kind == 'body':
                rows['actor/entry.py'] = (rows['actor/entry.py'][0] + b'\n', 0o644)
            elif kind == 'mode':
                rows[COMMON] = (rows[COMMON][0], 0o755)
            else:
                rows['unrecorded.txt'] = (b'inert DATA\n', 0o644)
            for rebound in [False, True]:
                candidate = rebind_map(dict(rows)) if rebound else rows
                with self.subTest(kind=kind, rebound=rebound), self.assertRaises(ValueError):
                    P.undo(candidate)

    def test_undo_refuses_missing_or_corrupt_inverse_and_saved_map(self):
        for name in [META, SAVED_MAP]:
            for kind in ['missing', 'body', 'mode']:
                rows = dict(self.after)
                if kind == 'missing':
                    del rows[name]
                elif kind == 'body':
                    rows[name] = (b'{}\n', 0o644)
                else:
                    rows[name] = (rows[name][0], 0o755)
                for rebound in [False, True]:
                    candidate = rebind_map(dict(rows)) if rebound else rows
                    with self.subTest(name=name, kind=kind, rebound=rebound), self.assertRaises((ValueError, KeyError)):
                        P.undo(candidate)
        for kind in ['parent', 'after', 'before', 'seam', 'frozen']:
            rows = dict(self.after)
            meta = json.loads(rows[META][0])
            if kind == 'parent':
                meta['parent']['tree'] = '0' * 40
            elif kind in ['after', 'before']:
                meta['changed'][COMMON][kind]['sha256'] = '0' * 64
            elif kind == 'seam':
                meta['changed'][COMMON]['inverse']['count'] = 2
            else:
                meta['frozen_python']['actor/entry.py']['sha256'] = '0' * 64
            rows[META] = ((json.dumps(meta, sort_keys=True, indent=2) + '\n').encode(), 0o644)
            with self.subTest(inverse=kind), self.assertRaises(ValueError):
                P.undo(rebind_map(rows))

    def test_actual_full_v2_inverse_chain_restores_exact_248_ancestor(self):
        restored = P.undo(dict(self.after))
        ancestor = P2.parent(ANCESTOR)
        meta = json.loads(restored['successor-v2.json'][0])
        original = P2.undo(restored, ancestor, meta)
        self.assertEqual(original, ancestor)
        self.assertEqual((len(original), sum(len(b) for b, _ in original.values())), (248, 40788233))
        self.assertEqual(P2.fs.tree(original), 'b6d4f3bcbfb7454b1760c3ff9f9910d734d8bece')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent-source', required=True, type=Path)
    parser.add_argument('--ancestor-source', required=True, type=Path)
    args = parser.parse_args()
    PARENT, ANCESTOR = args.parent_source.resolve(), args.ancestor_source.resolve()
    def denied(*args, **kwargs):
        raise AssertionError('constructor DATA controls forbid actors/network/lease')
    with contextlib.ExitStack() as stack:
        for name in ['subprocess.run', 'subprocess.Popen', 'socket.socket', 'socket.create_connection',
                     'fcntl.flock', 'os.system', 'os.fork', 'os.posix_spawn', 'os.posix_spawnp', 'os.pidfd_open']:
            stack.enter_context(patch(name, denied, create=name == 'os.pidfd_open'))
        unittest.main(argv=[__file__], verbosity=2)

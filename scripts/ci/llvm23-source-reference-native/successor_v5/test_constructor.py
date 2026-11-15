#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Fenced complete Source DATA/inverse controls; no artifact code imports."""
import argparse
import copy
import ctypes
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('llvm_stage_constructor_controls', HERE / 'prepare.py')
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)
PARENT = ANCESTOR = None


def fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.', 'os.exec', 'os.spawn', 'os.posix_spawn')) or event in (
            'os.system', 'os.fork', 'os.forkpty', 'fcntl.flock', 'fcntl.lockf', 'os.unshare', 'os.setns'):
        raise RuntimeError('constructor DATA-only fence: ' + event)


sys.addaudithook(fence)


def rebind(rows):
    m = json.loads(rows['source-map.json'][0])
    m['files'] = P.fs.descriptors({n: v for n, v in rows.items() if n != 'source-map.json'})
    rows['source-map.json'] = (P.encode(m), 0o644)
    return rows


class ConstructorControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.before = P.parent(PARENT)
        cls.after = P.render(cls.before)

    def test_exact_published_parent(self):
        self.assertEqual((len(self.before), sum(len(b) for b, _ in self.before.values())), (256, 40919517))
        self.assertEqual(P.fs.tree(self.before), P.PARENT['tree'])
        self.assertEqual(P.PARENT['source'], '365a763bc515a1b3550cc804536ddbf66353aac8')
        self.assertEqual(P.PARENT['ref'], 'refs/heads/codex/llvm23-source-reference-native-v2-20261115-r2')

    def test_one_literal_actor_delta_and_exact_four_additions(self):
        self.assertEqual(len(self.after), 260)
        self.assertEqual(set(self.after) - set(self.before), {P.SAVED_ACTOR, P.SAVED_CONTRACT, P.SAVED_MAP, P.META})
        self.assertEqual({n for n in self.before if self.before[n] != self.after[n]}, {P.ACTOR, P.CONTRACT, 'source-map.json'})
        raw, mode = self.before[P.ACTOR]
        self.assertEqual(raw.count(P.OLD.encode()), 1)
        self.assertEqual(self.after[P.ACTOR], (raw.replace(P.OLD.encode(), P.NEW.encode()), mode))
        self.assertEqual(self.after[P.ACTOR][0].replace(P.NEW.encode(), P.OLD.encode()), raw)

    def test_only_derived_contract_descriptor_and_honest_flag_change(self):
        expected = json.loads(self.before[P.CONTRACT][0])
        expected['actor_files']['container_mode.py'] = P.descriptor(self.after[P.ACTOR])
        expected['outer_delegation']['frozen_python_actor'] = False
        self.assertEqual(self.after[P.CONTRACT], (P.encode(expected), self.before[P.CONTRACT][1]))
        self.assertEqual(expected['actor_files']['container_mode.py'], P.descriptor(self.after[P.ACTOR]))

    def test_all_other_bytes_modes_and_historical_claims_frozen(self):
        for n, row in self.before.items():
            if n not in (P.ACTOR, P.CONTRACT, 'source-map.json'):
                self.assertEqual(self.after[n], row, n)
        self.assertEqual(self.after[P.SAVED_ACTOR], self.before[P.ACTOR])
        self.assertEqual(self.after[P.SAVED_CONTRACT], self.before[P.CONTRACT])
        self.assertEqual(self.after[P.SAVED_MAP], self.before['source-map.json'])

    def test_complete260_to256_and_all_historical_inverses(self):
        restored = P.undo(dict(self.after))
        self.assertEqual(restored, self.before)
        ancestor = P.P2.parent(ANCESTOR)
        self.assertEqual(P.historical_with_ancestor(restored, ancestor), ancestor)

    def test_new_selectors_null_and_operations_unchanged(self):
        for name in ('source-map.json', P.META):
            self.assertEqual(json.loads(self.after[name][0])['actual'], P.ACTUAL)
        meta = json.loads(self.after[P.META][0])
        self.assertEqual((meta['outer_operation'], meta['inner_operation']), (P.OP, P.INNER))

    def test_parent_tamper_mode_extra_or_map_refused_even_rebound(self):
        for kind in ('actor', 'contract', 'mode', 'extra', 'map'):
            rows = dict(self.before)
            if kind == 'mode': rows[P.ACTOR] = (rows[P.ACTOR][0], 0o755)
            elif kind == 'extra': rows['extra.DATA'] = (b'inert\n', 0o644)
            elif kind == 'map': rows['source-map.json'] = (rows['source-map.json'][0] + b' ', 0o644)
            else:
                n = P.ACTOR if kind == 'actor' else P.CONTRACT
                rows[n] = (rows[n][0] + b'\n', rows[n][1])
            with self.subTest(kind=kind), self.assertRaises(ValueError): P.render(rows)
            if kind != 'map':
                with self.subTest(kind=kind, rebound=True), self.assertRaises(ValueError): P.render(rebind(rows))

    def test_recomputed_map_cannot_hide_successor_tamper(self):
        for name in (P.ACTOR, P.CONTRACT, 'actor/runtime.py', 'policy.json', 'successor-v2.json'):
            rows = dict(self.after); rows[name] = (rows[name][0] + b'\n', rows[name][1])
            with self.subTest(name=name), self.assertRaises(ValueError): P.undo(rebind(rows))

    def test_complete_saved_operands_missing_body_mode_refused(self):
        for name in (P.SAVED_ACTOR, P.SAVED_CONTRACT, P.SAVED_MAP, P.META):
            for kind in ('missing', 'body', 'mode'):
                rows = dict(self.after)
                if kind == 'missing': rows.pop(name)
                elif kind == 'body': rows[name] = (b'{}\n', 0o644)
                else: rows[name] = (rows[name][0], 0o755)
                with self.subTest(name=name, kind=kind), self.assertRaises((ValueError, KeyError)):
                    P.undo(rebind(rows))

    def test_metadata_unknown_fields_numeric_alias_authority_and_seam_refused(self):
        for kind in ('extra', 'schema', 'parent', 'authority', 'seam', 'claim'):
            rows = dict(self.after); meta = json.loads(rows[P.META][0])
            if kind == 'extra': meta['extra'] = True
            elif kind == 'schema': meta['schema'] = True
            elif kind == 'parent': meta['parent']['tree'] = '0' * 40
            elif kind == 'authority': meta['actual']['authority'] = 'FORGED'
            elif kind == 'claim': meta['changed'][P.CONTRACT]['derivation']['frozen_python_actor']['after'] = True
            else: meta['changed'][P.ACTOR]['inverse']['new'] += ';UNREVIEWED'
            rows[P.META] = (P.encode(meta), 0o644)
            with self.subTest(kind=kind), self.assertRaises(ValueError): P.undo(rebind(rows))

    def test_map_scope_and_noncanonical_alias_refused(self):
        for kind in ('scope', 'whitespace'):
            rows = dict(self.after)
            if kind == 'scope':
                meta = json.loads(rows['source-map.json'][0]); meta['scope'] = 'WAIVER'
                rows['source-map.json'] = (P.encode(meta), 0o644)
            else: rows['source-map.json'] = (rows['source-map.json'][0] + b' ', 0o644)
            with self.subTest(kind=kind), self.assertRaises(ValueError): P.undo(rows)

    def test_duplicate_or_already_corrected_actor_seam_refused(self):
        with self.assertRaises(ValueError): P.corrected(self.before[P.ACTOR][0] + P.OLD.encode())
        with self.assertRaises(ValueError): P.corrected(self.after[P.ACTOR][0])

    def test_five_constructor_files_and_external_profile_join(self):
        descriptors = P.constructor_files()
        self.assertEqual(set(descriptors), {'prepare.py', 'README.md', 'test_constructor.py', 'test_stage_receipts.py', 'observed-failure.json'})
        profile = dict(parent=P.PARENT, actual=P.ACTUAL, outer_operation=P.OP, inner_operation=P.INNER,
                       constructor_files=descriptors, expected_files=260,
                       expected_bytes=sum(len(b) for b, _ in self.after.values()),
                       expected_map=P.fs.pin(self.after['source-map.json'][0]), expected_tree=P.fs.tree(self.after))
        raw = P.encode(profile); original = P.fs.read
        def read(path, *args):
            return (raw, 0o644) if path == HERE / 'constructor-profile.json' else original(path, *args)
        with patch.object(P.fs, 'read', side_effect=read):
            self.assertEqual(P.verify_profile(hashlib.sha256(raw).hexdigest()), profile)
            with self.assertRaises(ValueError): P.verify_profile('0' * 64)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent-source', type=Path, required=True)
    parser.add_argument('--ancestor-source', type=Path, required=True)
    args = parser.parse_args()
    PARENT, ANCESTOR = args.parent_source, args.ancestor_source
    unittest.main(argv=[__file__], verbosity=2)

# SPDX-License-Identifier: MIT
"""Portable exact-source and genuine archive-copy regressions; no native actors."""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('repair_inspect_factory', HERE / 'prepare.py')
F = importlib.util.module_from_spec(spec)
spec.loader.exec_module(F)
SOURCE = Path(os.environ['REPAIR_INSPECT_INPUT']).absolute()
EXPECTED = Path(os.environ['REPAIR_INSPECT_EXPECTED']).absolute()
CARRIER = Path(os.environ['REPAIR_INSPECT_CARRIER']).absolute()


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class Controls(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('REPAIR_INSPECT_WORK'))
        self.work = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def helper(self):
        values, profile = F.compose(SOURCE)
        self.assertEqual(F.tree(EXPECTED), values)
        return load(EXPECTED / F.HELPER, 'exact_public_inspect_helper')

    def test_both_real_cli_contexts_and_complete_source_entry(self):
        expected = F.tree(EXPECTED)
        for context in ('known', 'null'):
            output = self.work / context
            process = subprocess.run([
                sys.executable, '-I', '-B', '-Werror', str(HERE / 'prepare.py'),
                '--source', str(SOURCE), '--output', str(output), '--context', context],
                capture_output=True, timeout=30, check=True)
            receipt = json.loads(process.stdout)
            self.assertEqual(F.tree(output), expected)
            self.assertEqual(receipt['source'] is None, context == 'null')
            self.assertIsNone(receipt['actual'])
            self.assertFalse(receipt['native_acceptance'])
            self.assertEqual(process.stderr, b'')
        # Both contexts emit identical source. Execute this full guard once per Python.
        output = self.work / 'known'
        process = subprocess.run([
            sys.executable, '-I', '-B', '-Werror', str(output / 'apps16-repair/entry.py'),
            '--source-only', '--require-selection'], capture_output=True, timeout=300,
            check=True)
        result = json.loads(process.stdout)
        self.assertEqual(result['source_files'], 242)
        self.assertIsNone(result['actual'])
        self.assertEqual(process.stderr, b'')

    def test_entire_before_after_held_and_counted_source_inverse(self):
        values, profile = F.compose(SOURCE)
        before = F.tree(SOURCE)
        self.assertEqual(values, F.tree(EXPECTED))
        self.assertEqual(profile['counts'], dict(before=239, after=242, held=229,
                                                 changed=10, added=3))
        guard = load(EXPECTED / F.GUARD, 'exact_public_inspect_source_guard')
        p = guard.profile(EXPECTED)
        self.assertEqual(guard.bodies(EXPECTED, p), before)
        self.assertEqual(guard.transformed(before, values[F.HELPER], values[F.GUARD],
                                           values[F.PROFILE]), values)
        for name in profile['held']:
            self.assertEqual(values[name], before[name])

    def test_input_drift_missing_extra_directory_symlink_hardlink_prewrite(self):
        for variant in ('drift', 'missing', 'extra', 'empty-directory', 'symlink', 'hardlink'):
            with self.subTest(variant=variant):
                source = self.work / variant
                shutil.copytree(SOURCE, source)
                leaf = source / F.SELECT
                if variant == 'drift':
                    leaf.write_bytes(leaf.read_bytes() + b'\n')
                elif variant == 'missing':
                    leaf.unlink()
                elif variant == 'extra':
                    (source / 'foreign').write_bytes(b'foreign')
                elif variant == 'empty-directory':
                    (source / 'foreign').mkdir()
                elif variant == 'symlink':
                    leaf.unlink()
                    leaf.symlink_to(SOURCE / F.SELECT)
                else:
                    leaf.unlink()
                    os.link(source / F.JOB, leaf)
                output = self.work / (variant + '-output')
                with self.assertRaises(ValueError):
                    F.emit(source, output, 'known')
                self.assertFalse(output.exists())

    def test_canonical_disjoint_fresh_context_and_late_drift_refusals(self):
        source = self.work / 'source'
        shutil.copytree(SOURCE, source)
        alias = self.work / 'alias'
        alias.symlink_to(source, target_is_directory=True)
        for incoming, output in ((source, source), (source, source / 'nested'),
                                 (alias, self.work / 'output'), (source, Path('relative')),
                                 (source, HERE / 'nested'),
                                 (source, self.work / 'x/../out'),
                                 (source, self.work / 'future-native-actual' / 'source')):
            with self.assertRaises(ValueError):
                F.emit(incoming, output, 'known')
        with self.assertRaises(ValueError):
            F.emit(source, self.work / 'wrong-context', 'other')
        original = F.tree
        calls = []

        def changed(root):
            result = original(root)
            if root == source:
                calls.append(None)
                if len(calls) == 2:
                    result[F.SELECT] += b'late drift'
            return result

        output = self.work / 'late-output'
        with patch.object(F, 'tree', side_effect=changed), self.assertRaises(ValueError):
            F.emit(source, output, 'known')
        self.assertFalse(output.exists())

    def test_fixed_selected_role_and_original_authenticated_default_budget(self):
        helper = self.helper()
        values = dict(helper.FIXED, **{'--workspace': '/work/main',
                      '--apps-provenance-sha256': 'a' * 64,
                      '--full574-policy-sha256': 'b' * 64,
                      '--full574-lease-sha256': 'c' * 64,
                      '--ownership-sha256': 'd' * 64})
        argv = ['/usr/bin/python3', '-I', '-B', helper.PATH, 'inspect']
        args = types.SimpleNamespace(action='inspect', tcg_owned_inspect_profile=helper.PROFILE)
        for key in helper.KEYS:
            argv.extend((key, values[key]))
            setattr(args, key[2:].replace('-', '_'), values[key])
        calls = []
        budget = helper.wrap(lambda arg: calls.append(arg) or 600)
        self.assertEqual(budget(None), 600)
        self.assertEqual(budget(args), 1200)
        self.assertEqual(calls, [None, args])
        self.assertTrue(helper.role(argv, 610))
        self.assertTrue(helper.role(argv + [helper.FLAG, helper.PROFILE], 1210, selected=True))
        for wrong in (dict(action='apply'), dict(worker=True), dict(source='/seed'),
                      dict(tcg_owned_inspect_profile='foreign')):
            bad = types.SimpleNamespace(**dict(vars(args), **wrong))
            with self.assertRaises(ValueError):
                budget(bad)
        self.assertFalse(helper.role(argv, 1210, selected=True))
        self.assertFalse(helper.role(argv + [helper.FLAG, helper.PROFILE], 1211, selected=True))
        with self.assertRaises(ValueError):
            helper.wrap(lambda arg: 601)(args)

    def alias_fixture(self):
        helper = self.helper()
        source = self.work / 'source'
        (source / 'apps16-repair').mkdir(parents=True)
        raw = (EXPECTED / 'apps16-repair/carrier-profile.json').read_bytes()
        (source / 'apps16-repair/carrier-profile.json').write_bytes(raw)
        profile = json.loads(raw)
        self.assertEqual(F.tree(CARRIER).keys(), profile['files'].keys())
        self.assertEqual({n: F.pin(b) for n, b in F.tree(CARRIER).items()}, profile['files'])
        carrier = self.work / 'apps16-native-pair'
        for target in set(helper.ALIASES.values()):
            path = carrier / target
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((CARRIER / target).read_bytes())
        args = types.SimpleNamespace(source=source, packet=self.work / 'old-packet',
                                     public=self.work / 'public')
        args.public.mkdir()
        result = dict(files={})
        copies = []

        def copy(path, name, cap):
            body = helper.read(path, cap)[0]
            target = args.public / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(body)
            result['files'][name] = F.pin(body)
            copies.append(path)

        return helper, args, result, copies, copy

    def test_four_genuine_archives_use_carrier_not_stale_packet_and_other_routes_held(self):
        helper, args, result, copies, copy = self.alias_fixture()
        for name, target in helper.ALIASES.items():
            stale = args.packet / name
            stale.parent.mkdir(parents=True, exist_ok=True)
            stale.write_bytes(b'old packet is intentionally wrong')
            helper.copy_reference(copy, args, name, dict(path=name, **helper.PIN), result)
            self.assertEqual(copies[-1], args.source.parent / 'apps16-native-pair' / target)
            self.assertEqual(result['files']['native-inputs/' + name], helper.PIN)
        self.assertEqual(len(result['files']), 4)
        other = args.packet / 'ordinary'
        other.write_bytes(b'ordinary held route')
        helper.copy_reference(copy, args, 'ordinary', {}, result)
        self.assertEqual(copies[-1], other)
        selected = next(iter(helper.ALIASES.values()))
        helper.copy_reference(copy, args, 'APPS16_CARRIER/' + selected, {}, result)
        self.assertEqual(copies[-1], args.source.parent / 'apps16-native-pair' / selected)

    def test_four_alias_wrong_schema_missing_symlink_hardlink_and_mutation_refuse(self):
        helper, args, result, copies, copy = self.alias_fixture()
        name = next(iter(helper.ALIASES))
        row = dict(path=name, **helper.PIN)
        for bad in (dict(row, path='foreign'), dict(row, bytes=1),
                    dict(row, sha256='0' * 64), dict(row, extra=True)):
            with self.assertRaises(ValueError):
                helper.copy_reference(copy, args, name, bad, result)
        path = args.source.parent / 'apps16-native-pair' / helper.ALIASES[name]
        body = path.read_bytes()
        for kind in ('missing', 'symlink', 'hardlink', 'changed'):
            with self.subTest(kind=kind):
                path.unlink()
                if kind == 'symlink':
                    path.symlink_to(CARRIER / helper.ALIASES[name])
                elif kind == 'hardlink':
                    other = self.work / 'hardlinked-archive'
                    other.write_bytes(body)
                    os.link(other, path)
                elif kind == 'changed':
                    path.write_bytes(body + b'changed')
                with self.assertRaises((ValueError, OSError)):
                    helper.copy_reference(copy, args, name, row, result)
                if path.is_symlink() or path.exists():
                    path.unlink()
                path.write_bytes(body)

        def mutate(source, name, cap):
            copy(source, name, cap)
            source.write_bytes(body + b'changed after copying')

        with self.assertRaises(ValueError):
            helper.copy_reference(mutate, args, name, row, result)

    def test_factory_stable_descriptor_detects_during_read_mutation(self):
        path = self.work / 'ordinary'
        path.write_bytes(b'a' * 65536)
        original = os.read
        changed = []

        def read(fd, size):
            raw = original(fd, size)
            if not changed:
                changed.append(None)
                path.write_bytes(b'b' * 65536)
            return raw

        before = len(list(Path('/proc/self/fd').iterdir()))
        with patch.object(F.os, 'read', side_effect=read), self.assertRaises(ValueError):
            F.read(path)
        self.assertEqual(len(list(Path('/proc/self/fd').iterdir())), before)


if __name__ == '__main__':
    unittest.main(verbosity=2)

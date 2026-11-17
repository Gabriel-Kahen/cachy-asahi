#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Actor-fenced DATA controls using Source310 and two explicitly supplied immutable proposals."""
import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('observed_hold_DATA_constructor', HERE / 'constructor.py')
C = importlib.util.module_from_spec(spec); spec.loader.exec_module(C)
ARGS = None


class ConstructorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.owned = tempfile.TemporaryDirectory(prefix='perl-observed-HOLD-DATA-')
        cls.addClassCleanup(cls.owned.cleanup)
        cls.work = Path(cls.owned.name)
        cls.roots = [ARGS.predecessor, ARGS.guard, ARGS.qmp]
        cls.ownpin = C.pin((HERE / 'source.lock.json').read_bytes())
        cls.inputs = [C.snapshot(root) for root in cls.roots]
        cls.output = cls.work / 'source'
        # These patches fence every real constructor and export-verifier call.
        for target in ('subprocess.Popen', 'socket.socket', 'os.system'):
            guard = patch(target, side_effect=AssertionError('actor/process/network forbidden'))
            guard.start(); cls.addClassCleanup(guard.stop)
        cls.report = C.construct(*cls.roots, cls.output, cls.ownpin)
        cls.export = C.snapshot(cls.output)
        cls.sourcepin = cls.report['source_lock']

    def projected(self, source=None, guard=None, qmp=None):
        own = C.snapshot(HERE)
        return C.project(source if source is not None else self.inputs[0],
                         guard if guard is not None else self.inputs[1],
                         qmp if qmp is not None else self.inputs[2], own, self.roots[2])

    def test_complete310_inverse_reuses_unchanged_bytes_and_only_four_preimages(self):
        inputs = C.decode(C.snapshot(HERE)['inputs.json'][0])
        self.assertEqual(C.inverse(self.export, inputs['predecessor']), self.inputs[0])
        changed = {'controller.py', 'hold_cleanup.py', 'guest/root.sh', 'guest/initialized-state.sh', 'source.lock.json'}
        for name, row in self.inputs[0].items():
            if name not in changed: self.assertEqual(self.export[name], row)
        originals = {name[len(C.PREFIX + 'inverse/leaves/'):] for name in self.export if name.startswith(C.PREFIX + 'inverse/leaves/')}
        self.assertEqual(originals, changed - {'source.lock.json'})
        self.assertEqual(self.export['guest/root.sh'], self.inputs[1]['guest/root.sh'])
        self.assertEqual(self.export['guest/initialized-state.sh'], self.inputs[1]['guest/initialized-state.sh'])
        self.assertEqual(self.export['hold_cleanup.py'][0], self.inputs[2]['generated-hold_cleanup.py'][0])

    def test_complete_physical_export_and_cap_with_no_actual_authority(self):
        self.assertEqual(C.verify_export(self.output, self.sourcepin, self.ownpin), self.report)
        self.assertLessEqual(self.report['closed_leaf_bytes'], 4 * 1024**2)
        self.assertTrue(all(value is None for value in self.report['actual'].values()))
        manifest = C.decode(self.export[C.PREFIX + 'construction.DATA.json'][0])
        self.assertEqual(set(manifest['changes']), {'controller.py', 'hold_cleanup.py', 'guest/root.sh', 'guest/initialized-state.sh', 'qmp_observations.py'})
        self.assertTrue(all(value is None for value in manifest['actual'].values()))
        self.assertEqual(set(manifest['added_membership']), set(self.export) - set(self.inputs[0]))
        self.assertNotIn(C.PREFIX + 'predecessor/controller.py', self.export)

    def test_deterministic_second_physical_export(self):
        other = self.work / 'second-source'
        self.assertEqual(C.construct(*self.roots, other, self.ownpin), self.report)
        self.assertEqual(C.snapshot(other), self.export)

    def test_predecessor_byte_change_refused(self):
        rows = dict(self.inputs[0]); body, mode = rows['controller.py']
        rows['controller.py'] = bytes([body[0] ^ 1]) + body[1:], mode
        with self.assertRaisesRegex(ValueError, 'membership, bytes and modes'):
            self.projected(source=rows)

    def test_predecessor_missing_leaf_refused(self):
        rows = dict(self.inputs[0]); rows.pop('README.md')
        with self.assertRaises(ValueError): self.projected(source=rows)

    def test_predecessor_mode_change_refused(self):
        rows = dict(self.inputs[0]); body, mode = rows['controller.py']
        rows['controller.py'] = body, 0o755 if mode == 0o644 else 0o644
        with self.assertRaises(ValueError): self.projected(source=rows)

    def test_changed_predecessor_lock_or_authority_refused(self):
        rows = dict(self.inputs[0]); lock = C.decode(rows['source.lock.json'][0])
        lock['actual']['Root_acceptance'] = True
        rows['source.lock.json'] = C.canonical(lock), 0o644
        with self.assertRaisesRegex(ValueError, 'externally pinned'): self.projected(source=rows)

    def test_guard_proposal_change_refused_before_execution(self):
        rows = dict(self.inputs[1]); rows['proposal.py'] = b'raise AssertionError("must never execute")\n', 0o644
        with self.assertRaisesRegex(ValueError, 'complete immutable proposal'): self.projected(guard=rows)

    def test_qmp_proposal_change_refused_before_execution(self):
        rows = dict(self.inputs[2]); rows['proposal.py'] = b'raise AssertionError("must never execute")\n', 0o644
        with self.assertRaisesRegex(ValueError, 'complete immutable proposal'): self.projected(qmp=rows)

    def test_missing_nonoperational_proposal_leaf_refused(self):
        for index, key in ((1, 'README.md'), (2, 'README.md')):
            with self.subTest(proposal=index):
                rows = dict(self.inputs[index]); rows.pop(key)
                with self.assertRaises(ValueError):
                    self.projected(**({'guard': rows} if index == 1 else {'qmp': rows}))

    def test_wrong_constructor_selection_refuses_before_output(self):
        output = self.work / 'must-not-exist'
        with self.assertRaises(ValueError):
            C.construct(*self.roots, output, dict(self.ownpin, sha256='0' * 64))
        self.assertFalse(output.exists())

    def test_extra_empty_directory_and_alias_refused(self):
        root = self.work / 'bad-namespace'; root.mkdir()
        (root / 'leaf').write_bytes(b'ordinary\n'); (root / 'leaf').chmod(0o644)
        extra = root / 'empty'; extra.mkdir()
        with self.assertRaisesRegex(ValueError, 'exact namespace'): C.snapshot(root)
        extra.rmdir(); (root / 'alias').symlink_to(root / 'leaf')
        with self.assertRaisesRegex(ValueError, 'unaliased'): C.snapshot(root)

    def test_hardlink_refused(self):
        root = self.work / 'bad-hardlink'; root.mkdir()
        (root / 'leaf').write_bytes(b'ordinary\n'); os.link(root / 'leaf', root / 'second')
        with self.assertRaisesRegex(ValueError, 'single-link'): C.snapshot(root)

    def test_cap_not_enlarged(self):
        root = self.work / 'oversized'; root.mkdir()
        (root / 'leaf').write_bytes(b'x' * (C.CAP + 1)); (root / 'leaf').chmod(0o644)
        with self.assertRaisesRegex(ValueError, 'bounded ordinary'): C.snapshot(root)

    def test_existing_or_overlapping_output_refused(self):
        with self.assertRaisesRegex(ValueError, 'fresh output'):
            C.construct(*self.roots, self.output, self.ownpin)
        inside = self.roots[0] / 'forbidden-new-output'
        with self.assertRaisesRegex(ValueError, 'disjoint'):
            C.construct(*self.roots, inside, self.ownpin)
        self.assertFalse(inside.exists())

    def test_export_tamper_refused_with_unchanged_external_lock(self):
        root = self.work / 'corrupt-source'; shutil.copytree(self.output, root)
        (root / 'hold_cleanup.py').write_bytes(b'wrong\n')
        with self.assertRaisesRegex(ValueError, 'membership, bytes and modes'):
            C.verify_export(root, self.sourcepin, self.ownpin)

    def test_resealed_inverse_tamper_still_refused(self):
        root = self.work / 'resealed-source'; shutil.copytree(self.output, root)
        (root / C.PREFIX / 'inverse/leaves/controller.py').write_bytes(b'wrong\n')
        files = C.snapshot(root); lock = C.decode(files['source.lock.json'][0])
        lock['files'] = C.rows({name: row for name, row in files.items() if name != 'source.lock.json'})
        raw = C.canonical(lock); (root / 'source.lock.json').write_bytes(raw)
        with self.assertRaises(ValueError):
            C.verify_export(root, C.pin(raw), self.ownpin)

    def test_added_membership_cannot_drop_or_hide_original_leaf(self):
        rows = dict(self.export)
        path = C.PREFIX + 'construction.DATA.json'
        value = C.decode(rows[path][0]); value['added_membership'].append('README.md')
        value['added_membership'].sort(); rows[path] = C.canonical(value), 0o644
        with self.assertRaises(ValueError):
            C.inverse(rows, C.decode(C.snapshot(HERE)['inputs.json'][0])['predecessor'])

    def test_old_lock_is_exact_and_authority_cannot_be_carried_forward(self):
        rows = dict(self.export); name = C.PREFIX + 'inverse/source.lock.json'
        old = C.decode(rows[name][0]); old['actual']['Root_acceptance'] = True
        rows[name] = C.canonical(old), 0o644
        with self.assertRaises(ValueError):
            C.inverse(rows, C.decode(C.snapshot(HERE)['inputs.json'][0])['predecessor'])

    def test_original_unissued_authority_refuses_before_runtime_helper(self):
        spec = importlib.util.spec_from_file_location('observed_hold_source_controller_DATA', self.output / 'controller.py')
        controller = importlib.util.module_from_spec(spec); spec.loader.exec_module(controller)
        spec = importlib.util.spec_from_file_location('observed_hold_contracts_DATA', self.output / 'contracts.py')
        contracts = importlib.util.module_from_spec(spec); spec.loader.exec_module(contracts)
        value = json.loads((self.output / 'authority.TEMPLATE.json').read_bytes())
        with patch.object(controller, 'module', side_effect=AssertionError('runtime helper forbidden')):
            with self.assertRaisesRegex(ValueError, 'actual Root-issued accepted'):
                controller.authority(value, 'prepare', {}, self.sourcepin, self.work / 'unissued-output', contracts)
        self.assertFalse((self.work / 'unissued-output').exists())

    def test_unmodified_runtime_adapter_accepts_whole_new_source_lock(self):
        spec = importlib.util.spec_from_file_location('unmodified_successor_adapter_DATA', self.output / 'adapter.py')
        adapter = importlib.util.module_from_spec(spec); spec.loader.exec_module(adapter)
        self.assertEqual(adapter.source(self.sourcepin['sha256']), self.sourcepin)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('predecessor', 'guard', 'qmp'):
        parser.add_argument('--' + name, type=Path, required=True)
    ARGS, remaining = parser.parse_known_args()
    unittest.main(argv=[sys.argv[0], *remaining])

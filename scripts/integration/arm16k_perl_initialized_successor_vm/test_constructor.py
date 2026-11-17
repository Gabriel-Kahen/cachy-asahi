#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Actor-fenced DATA controls using three explicitly supplied immutable families."""
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
spec = importlib.util.spec_from_file_location('successor_DATA_constructor', HERE / 'constructor.py')
C = importlib.util.module_from_spec(spec); spec.loader.exec_module(C)
ARGS = None


class ConstructorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.owned = tempfile.TemporaryDirectory(prefix='perl-successor-DATA-')
        cls.addClassCleanup(cls.owned.cleanup)
        cls.work = Path(cls.owned.name)
        cls.roots = [ARGS.predecessor, ARGS.cleanup, ARGS.metadata]
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

    def projected(self, source=None, cleanup=None, metadata=None):
        own = C.snapshot(HERE)
        return C.project(source if source is not None else self.inputs[0],
                         cleanup if cleanup is not None else self.inputs[1],
                         metadata if metadata is not None else self.inputs[2], own, self.roots[1])

    def test_complete_predecessor_inverse_and_unrelated_bytes_modes(self):
        changed = {'controller.py', 'guest/installed-metadata.sh', 'source.lock.json'}
        for name, row in self.inputs[0].items():
            self.assertEqual(self.export[C.PREFIX + 'predecessor/' + name], row)
            if name not in changed:
                self.assertEqual(self.export[name], row)
        self.assertEqual(self.export['hold_cleanup.py'], self.inputs[1]['hold_cleanup.py'])
        self.assertEqual(self.export['guest/installed-metadata.sh'], self.inputs[2]['guest/installed-metadata.sh'])

    def test_complete_physical_export_and_cap_with_no_actual_authority(self):
        self.assertEqual(C.verify_export(self.output, self.sourcepin, self.ownpin), self.report)
        self.assertLessEqual(self.report['closed_leaf_bytes'], 4 * 1024**2)
        self.assertTrue(all(value is None for value in self.report['actual'].values()))
        manifest = C.decode(self.export[C.PREFIX + 'construction.DATA.json'][0])
        self.assertEqual(set(manifest['changes']), {'controller.py', 'guest/installed-metadata.sh', 'hold_cleanup.py'})
        self.assertTrue(all(value is None for value in manifest['actual'].values()))
        self.assertEqual(len(json.loads(self.inputs[2]['mapping.DATA.json'][0])['returns']), 55)
        self.assertEqual(len(json.loads(self.inputs[2]['mapping.DATA.json'][0])['stages']), 14)

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

    def test_cleanup_proposal_change_refused_before_execution(self):
        rows = dict(self.inputs[1]); rows['proposal.py'] = b'raise AssertionError("must never execute")\n', 0o644
        with self.assertRaisesRegex(ValueError, 'complete immutable proposal'): self.projected(cleanup=rows)

    def test_metadata_proposal_change_refused_before_execution(self):
        rows = dict(self.inputs[2]); rows['instrument.py'] = b'raise AssertionError("must never execute")\n', 0o644
        with self.assertRaisesRegex(ValueError, 'complete immutable proposal'): self.projected(metadata=rows)

    def test_missing_nonoperational_proposal_leaf_refused(self):
        for index, key in ((1, 'README.md'), (2, 'test_instrument.py')):
            with self.subTest(proposal=index):
                rows = dict(self.inputs[index]); rows.pop(key)
                with self.assertRaises(ValueError):
                    self.projected(**({'cleanup': rows} if index == 1 else {'metadata': rows}))

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
        (root / C.PREFIX / 'predecessor/controller.py').write_bytes(b'wrong\n')
        files = C.snapshot(root); lock = C.decode(files['source.lock.json'][0])
        lock['files'] = C.rows({name: row for name, row in files.items() if name != 'source.lock.json'})
        raw = C.canonical(lock); (root / 'source.lock.json').write_bytes(raw)
        with self.assertRaisesRegex(ValueError, 'membership, bytes and modes'):
            C.verify_export(root, C.pin(raw), self.ownpin)

    def test_unmodified_runtime_adapter_accepts_whole_new_source_lock(self):
        spec = importlib.util.spec_from_file_location('unmodified_successor_adapter_DATA', self.output / 'adapter.py')
        adapter = importlib.util.module_from_spec(spec); spec.loader.exec_module(adapter)
        self.assertEqual(adapter.source(self.sourcepin['sha256']), self.sourcepin)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('predecessor', 'cleanup', 'metadata'):
        parser.add_argument('--' + name, type=Path, required=True)
    ARGS, remaining = parser.parse_known_args()
    unittest.main(argv=[sys.argv[0], *remaining])

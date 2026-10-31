#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Focused DATA controls; no actor, Git, network or operand-code execution."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).absolute().parent
spec = importlib.util.spec_from_file_location('native_source_assembler_control', HERE / 'assemble_source.py')
A = importlib.util.module_from_spec(spec); spec.loader.exec_module(A)


def deny(event, args):
    if event.startswith(('subprocess.', 'socket.', 'os.exec', 'os.spawn')) or event in ('os.system', 'os.fork', 'os.forkpty', 'os.kill', 'os.killpg', 'os.posix_spawn'):
        raise AssertionError('DATA control actor forbidden: ' + event)


sys.addaudithook(deny)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def write_tree(root, files):
    root.mkdir(mode=0o700)
    for name, (raw, mode) in files.items():
        path = root / name; path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw); path.chmod(mode)


class AssemblerControls(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='source-tools-assembler-data-')
        self.addCleanup(self.tmp.cleanup); self.root = Path(self.tmp.name)
        self.parent = {name: (('original inert parent ' + name + '\n').encode(), 0o644) for name in A.SEAMS}
        self.parent.update({'base/x%03d.py' % n: (b'raise AssertionError("DATA must never execute")\n', 0o755 if n == 0 else 0o644) for n in range(186)})
        self.assertEqual(len(self.parent), 191)
        self.parent_tree = A.tree(self.parent)
        self.raw = ('tree ' + self.parent_tree + '\nparent ' + '1' * 40 + '\nauthor Original <test@example.invalid> 1 +0000\ncommitter Original <test@example.invalid> 1 +0000\n\nOriginal inert fixture\n').encode()
        self.parent_sha = A.oid(b'commit', self.raw).hex()
        self.parent_path = self.root / 'parent'; write_tree(self.parent_path, self.parent)
        self.raw_path = self.root / 'parent.raw'; self.raw_path.write_bytes(self.raw)
        self.overlay = {name: (('original inert overlay ' + name + '\n').encode(), 0o644) for name in A.SEAMS | A.ADDITIONS}
        self.overlay['.github/workflows/native-arm-developer-workflows.yml'] = self.overlay['.github/workflows/native-arm-build.yml']
        self.overlay['native/source-tools-contract-v1.json'] = (encoded(dict(operation=A.OPERATION, actual=dict(source=None, ref=None, run=None, job=None, artifact=None))), 0o644)
        self.refresh_final()
        write_tree(self.root / 'overlay', self.overlay)
        self.profile_path = self.root / 'profile.json'; self.refresh_profile()
        self.output = self.root / 'output'
        self.patch_parent = patch.multiple(A, GENUINE_PARENT=self.parent_sha, PARENT_TREE=self.parent_tree)
        self.patch_parent.start(); self.addCleanup(self.patch_parent.stop)

    def refresh_final(self):
        final = dict(self.parent); final.update(self.overlay)
        rows = {name: row for name, row in A.descriptors(final).items() if name != A.MAP}
        self.overlay[A.MAP] = (encoded(dict(schema=1, actual=dict(source=None, ref=None, run=None), files=rows)), 0o644)
        final.update(self.overlay); self.final = final

    def refresh_profile(self, change=None):
        value = dict(schema=1, purpose='source-tools-native-main-overlay', genuine_parent=self.parent_sha,
            parent_tree=self.parent_tree, main_base=A.MAIN_BASE, operation=A.OPERATION, actual=dict(source=None, ref=None, run=None),
            parent_files=A.descriptors(self.parent), overlay=A.descriptors(self.overlay), source_map_sha256=A.pin(self.overlay[A.MAP][0])['sha256'],
            prospective_tree=A.tree(self.final), source_files=200)
        if change:
            change(value)
        raw = encoded(value); self.profile_path.write_bytes(raw); self.profile_sha = A.pin(raw)['sha256']
        self.policy = value

    def run_assemble(self):
        return A.assemble(self.parent_path, self.raw_path, self.profile_path, self.profile_sha, self.output)

    def test_exact200_roundtrip_keeps_executable_mode_and_never_executes_source(self):
        result = self.run_assemble()
        self.assertEqual(result['status'], 'ASSEMBLED_EXACT_CLOSED_SOURCE_DATA_ONLY')
        self.assertEqual(A.snapshot(self.output), self.final)
        self.assertEqual(stat.S_IMODE((self.output / 'base/x000.py').stat().st_mode), 0o755)
        self.assertEqual(result['actual'], dict(source=None, ref=None, run=None))
        self.assertEqual(result['native'], 'NOT_RUN')
        self.assertFalse(list(self.output.rglob('__pycache__')))

    def test_stale_profile_pin_refuses_before_output(self):
        self.profile_path.write_bytes(self.profile_path.read_bytes() + b' ')
        with self.assertRaisesRegex(ValueError, 'profile checksum'):
            self.run_assemble()
        self.assertFalse(self.output.exists())

    def test_mutated_raw_genuine_parent_refuses(self):
        self.raw_path.write_bytes(self.raw + b'changed')
        with self.assertRaisesRegex(ValueError, 'raw genuine parent'):
            self.run_assemble()
        self.assertFalse(self.output.exists())

    def test_parent_bytes_mode_extra_and_empty_directory_refuse(self):
        selected = self.parent_path / 'base/x000.py'
        for fault in ('bytes', 'mode', 'extra', 'empty'):
            with self.subTest(fault=fault):
                if fault == 'bytes': selected.write_bytes(b'changed')
                elif fault == 'mode': selected.chmod(0o644)
                elif fault == 'extra': (self.parent_path / 'extra').write_bytes(b'extra')
                else: (self.parent_path / 'empty').mkdir()
                with self.assertRaises(ValueError): self.run_assemble()
                if fault == 'bytes': selected.write_bytes(self.parent['base/x000.py'][0])
                elif fault == 'mode': selected.chmod(0o755)
                elif fault == 'extra': (self.parent_path / 'extra').unlink()
                else: (self.parent_path / 'empty').rmdir()
        self.assertFalse(self.output.exists())

    def test_parent_profile_repin_cannot_change_committed_tree(self):
        selected = self.parent_path / 'base/x000.py'; selected.write_bytes(b'changed')
        self.parent['base/x000.py'] = (b'changed', 0o755); self.refresh_profile()
        with self.assertRaisesRegex(ValueError, 'genuine191'):
            self.run_assemble()
        self.assertFalse(self.output.exists())

    def test_overlay_bytes_mode_and_extra_refuse(self):
        selected = self.root / 'overlay/native/owner.py'; original = selected.read_bytes()
        for fault in ('bytes', 'mode', 'extra'):
            with self.subTest(fault=fault):
                if fault == 'bytes': selected.write_bytes(b'changed')
                elif fault == 'mode': selected.chmod(0o755)
                else: (self.root / 'overlay/extra.py').write_bytes(b'raise AssertionError("DATA")\n')
                with self.assertRaisesRegex(ValueError, 'overlay'):
                    self.run_assemble()
                if fault == 'bytes': selected.write_bytes(original)
                elif fault == 'mode': selected.chmod(0o644)
                else: (self.root / 'overlay/extra.py').unlink()
        self.assertFalse(self.output.exists())

    def test_profile_extra_path_and_nonNULL_actuals_refuse(self):
        self.refresh_profile(lambda value: value['actual'].update(source='a' * 40))
        with self.assertRaisesRegex(ValueError, 'overlay identity'):
            self.run_assemble()
        self.refresh_profile(lambda value: value['overlay'].update({'elsewhere.py': dict(bytes=1, sha256='a' * 64, mode=420)}))
        with self.assertRaisesRegex(ValueError, 'row count'):
            self.run_assemble()
        self.assertFalse(self.output.exists())

    def test_final_map_and_contract_actuals_remain_NULL(self):
        changed = dict(self.final)
        manifest = A.decode(changed[A.MAP][0]); manifest['actual']['run'] = '1'
        changed[A.MAP] = (encoded(manifest), 0o644)
        policy = copy.deepcopy(self.policy); policy['source_map_sha256'] = A.pin(changed[A.MAP][0])['sha256']
        with self.assertRaisesRegex(ValueError, 'NULL actuals'):
            A.check_final(changed, policy)
        contract = A.decode(changed['native/source-tools-contract-v1.json'][0]); contract['actual']['job'] = '1'
        changed = dict(self.final); changed['native/source-tools-contract-v1.json'] = (encoded(contract), 0o644)
        manifest = A.decode(changed[A.MAP][0]); manifest['files'] = {name: row for name, row in A.descriptors(changed).items() if name != A.MAP}
        changed[A.MAP] = (encoded(manifest), 0o644); policy['source_map_sha256'] = A.pin(changed[A.MAP][0])['sha256']
        with self.assertRaisesRegex(ValueError, 'contract actual'):
            A.check_final(changed, policy)

    def test_symlink_hardlink_fifo_and_ancestor_alias_refuse(self):
        selected = self.parent_path / 'base/x000.py'; original = selected.read_bytes()
        for fault in ('symlink', 'hardlink', 'fifo'):
            with self.subTest(fault=fault):
                selected.unlink()
                if fault == 'symlink': selected.symlink_to(self.parent_path / 'base/x001.py')
                elif fault == 'hardlink': os.link(self.parent_path / 'base/x001.py', selected)
                else: os.mkfifo(selected)
                with self.assertRaises((ValueError, OSError)): self.run_assemble()
                selected.unlink(); selected.write_bytes(original); selected.chmod(0o755)
        alias = self.root / 'alias'; alias.symlink_to(self.parent_path, target_is_directory=True)
        with self.assertRaises(OSError): A.snapshot(alias)
        self.assertFalse(self.output.exists())

    def test_existing_output_and_output_symlink_are_preserved(self):
        self.output.mkdir(); (self.output / 'keep').write_bytes(b'operator-owned')
        with self.assertRaisesRegex(ValueError, 'fresh absent output'): self.run_assemble()
        self.assertEqual((self.output / 'keep').read_bytes(), b'operator-owned')
        shutil.rmtree(self.output); self.output.symlink_to(self.parent_path, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'fresh absent output'): self.run_assemble()
        self.assertTrue(self.output.is_symlink()); self.assertTrue(self.parent_path.is_dir())

    def test_root_is_not_an_output_child(self):
        with self.assertRaisesRegex(ValueError, 'output child'):
            A.publish(self.final, Path('/'))

    def test_output_parent_writable_by_others_refuses(self):
        writable = self.root / 'writable'; writable.mkdir(mode=0o777); writable.chmod(0o777)
        with self.assertRaisesRegex(ValueError, 'output parent'):
            A.publish(self.final, writable / 'output')
        self.assertFalse((writable / 'output').exists())

    def test_later_publication_failure_cleans_only_owned_stage(self):
        class BadRename:
            def __call__(self, *args): return -1
        class Libc:
            renameat2 = BadRename()
        with patch.object(A.ctypes, 'CDLL', return_value=Libc()), patch.object(A.ctypes, 'get_errno', return_value=5):
            with self.assertRaises(OSError): self.run_assemble()
        self.assertFalse(self.output.exists()); self.assertFalse(list(self.root.glob('.source-tools-stage-*')))
        self.assertEqual(A.snapshot(self.parent_path), self.parent)

    def test_duplicate_json_boolean_types_and_unsafe_names_refuse(self):
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            A.decode(b'{"schema":1,"schema":1}')
        for name in ('../escape', '/absolute', 'x//y', 'x\\y', 'x/./y'):
            with self.subTest(name=name), self.assertRaises(ValueError): A.relative(name)
        self.refresh_profile(lambda value: value.update(source_files=True))
        with self.assertRaisesRegex(ValueError, 'overlay identity'): self.run_assemble()


if __name__ == '__main__':
    unittest.main(verbosity=2)

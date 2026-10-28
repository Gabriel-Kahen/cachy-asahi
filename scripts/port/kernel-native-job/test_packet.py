#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 cachy-asahi contributors
"""Synthetic source packet checks; never execute Git, recipes or native tools."""
import sys
sys.dont_write_bytecode = True

import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('kernel_job_packet_fixture', HERE / 'packet.py')
packet = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packet)


class PacketTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / 'repo'
        self.root.mkdir()
        self.commit = 'a' * 40
        environment = mock.patch.dict(os.environ, GITHUB_SHA=self.commit, GITHUB_WORKFLOW_SHA=self.commit)
        environment.start()
        self.addCleanup(environment.stop)
        self.commands = []
        self.contents = {}
        def write(name, data, mode=0o644):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(mode)
            self.contents[name] = data
        self.write = write
        for name, data in {'LICENSE': b'fixture license\n', 'AGENTS.md': b'fixture instructions\n',
                           'scripts/setup/setup.py': b'fixture canonical setup\n',
                           'scripts/ci/native_arm.py': b'fixture native helper\n',
                           packet.PREFIX + 'packet.py': b'fixture packet helper\n',
                           packet.PREFIX + 'runtime.py': b'fixture runtime\n',
                           packet.WORKFLOW: b'fixture workflow\n',
                           packet.DOCUMENT: b'fixture doc\n'}.items():
            write(name, data, 0o755 if name.endswith('.sh') else 0o644)
        self.recipes = {}
        for base in sorted(packet.RECIPE_BASES):
            name = Path(base).name
            directory = 'desktop' if 'hyprland' in name else 'settings' if name.endswith('setup') else 'shells'
            base = 'packages/' + directory + '/' + name
            # Deliberately shell-looking bytes: the packet only reads and copies.
            data = b'$(touch SHOULD_NEVER_EXECUTE)\n'
            write(base + '/PKGBUILD', data)
            self.recipes[base] = {'PKGBUILD': packet.sha(data)}
        native = 'scripts/ci/native_arm.py'
        self.kernel = {'schema_version': 1, 'files': {
                native: {'sha256': packet.sha(self.contents[native]), 'mode': 0o644}}}
        write(packet.KERNEL + 'stage.lock.json', self.json_bytes(self.kernel))
        write('scripts/ci/recipes.lock.json', self.json_bytes(self.recipes))
        write('scripts/ci/inputs.lock.json', self.json_bytes({
                'source_date_epoch': packet.EPOCH, 'packages': [{} for _ in range(248)]}))
        # The self-referential lock is excluded from the packet file set.
        write(packet.PREFIX + 'packet.lock.json', b'{}\n')
        self.helper_pins = {name: (packet.sha(self.contents[name]), (self.root / name).stat().st_mode & 0o777)
                            for name in ('LICENSE', 'AGENTS.md', 'scripts/setup/setup.py', 'scripts/ci/native_arm.py')}
        self.pins = {'HELPERS': self.helper_pins, 'RECIPE_COUNT': 4, 'KERNEL_COUNT': 1, 'KERNEL_SHA': packet.sha(self.contents[packet.KERNEL + 'stage.lock.json']),
                     'RECIPES_SHA': packet.sha(self.contents['scripts/ci/recipes.lock.json']),
                     'INPUTS_SHA': packet.sha(self.contents['scripts/ci/inputs.lock.json'])}
        patcher = mock.patch.multiple(packet, **self.pins)
        patcher.start()
        self.addCleanup(patcher.stop)
        names = packet.closure(self.root)[0]
        self.manifest = {'schema_version': 1, 'files': {name: {
                'sha256': packet.sha(self.contents[name]), 'bytes': len(self.contents[name]),
                'mode': (self.root / name).stat().st_mode & 0o777} for name in sorted(names)}}
        self.manifest_path = self.base / 'reviewed.json'
        self.refresh_manifest()

    @staticmethod
    def json_bytes(value):
        return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()

    def refresh_manifest(self):
        self.manifest_path.write_bytes(self.json_bytes(self.manifest))
        self.manifest_sha = packet.sha(self.manifest_path.read_bytes())

    def run_git(self, argv, **kwargs):
        self.commands.append(argv)
        self.assertEqual(argv[:7], ['/usr/bin/git', '-c', 'core.hooksPath=/dev/null', '-c',
                                  'core.fsmonitor=false', '--no-optional-locks', '-C'])
        self.assertEqual(argv[7], str(self.root))
        if argv[8] == 'rev-parse':
            self.assertEqual(argv[9:], ['--verify', 'HEAD'])
            return subprocess.CompletedProcess(argv, 0, (self.commit + '\n').encode())
        if argv[8] == 'show':
            name = argv[9].removeprefix(self.commit + ':')
            self.assertEqual(argv[9], self.commit + ':' + name)
            return subprocess.CompletedProcess(argv, 0, self.contents[name])
        self.assertEqual(argv[8:12], ['ls-tree', '--format=%(objectmode)', self.commit, '--'])
        name = argv[12]
        return subprocess.CompletedProcess(argv, 0,
                ('100' + oct(self.manifest['files'][name]['mode'])[2:] + '\n').encode())

    def verify(self, output=None, callback=None, root=None):
        runner = mock.Mock()
        runner.run.side_effect = callback or self.run_git
        return packet.verify(root or self.root, self.manifest_path, self.manifest_sha,
                self.commit, runner, output or self.base / 'packet')

    def test_complete_closure_preserves_all_bytes_modes_and_commit_bindings(self):
        before = {name: (self.root / name).read_bytes() for name in self.contents}
        result = self.verify()
        output = self.base / 'packet'
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(result['files'], len(self.manifest['files']))
        actual = {str(p.relative_to(output)) for p in output.rglob('*') if p.is_file()}
        self.assertEqual(actual, set(self.manifest['files']))
        self.assertNotIn(packet.PREFIX + 'packet.lock.json', actual)
        self.assertIn('scripts/setup/setup.py', actual)
        self.assertIn('LICENSE', actual)
        for name, row in self.manifest['files'].items():
            self.assertEqual((output / name).read_bytes(), self.contents[name])
            self.assertEqual((output / name).stat().st_mode & 0o777, row['mode'])
        self.assertEqual(len(self.commands), 1 + 2 * len(actual))
        self.assertEqual(before, {name: (self.root / name).read_bytes() for name in before})
        self.assertFalse((self.root / 'SHOULD_NEVER_EXECUTE').exists())

    def test_missing_or_extra_manifest_input_is_refused_before_output(self):
        original = copy.deepcopy(self.manifest)
        for change in ('missing', 'extra'):
            self.manifest = copy.deepcopy(original)
            if change == 'missing':
                del self.manifest['files']['scripts/setup/setup.py']
            else:
                self.manifest['files']['private-unreviewed.tar.gz'] = {
                        'sha256': '0' * 64, 'mode': 0o644, 'bytes': 0}
            self.refresh_manifest()
            output = self.base / change
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'packet-complete-set'):
                self.verify(output)
            self.assertFalse(output.exists())

    def test_original_locks_must_keep_exact_pins(self):
        for index, name in enumerate(('scripts/ci/inputs.lock.json', 'scripts/ci/recipes.lock.json',
                                     packet.KERNEL + 'stage.lock.json')):
            path = self.root / name
            path.write_bytes(self.contents[name] + b' ')
            output = self.base / ('pin-' + str(index))
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'packet-pin'):
                self.verify(output)
            self.assertFalse(output.exists())
            path.write_bytes(self.contents[name])

    def test_manifest_pin_duplicate_keys_and_nonfinite_numbers_are_refused(self):
        for data in (self.json_bytes(self.manifest) + b' ',
                     b'{"schema_version":1,"schema_version":1,"files":{}}',
                     b'{"schema_version":NaN,"files":{}}'):
            self.manifest_path.write_bytes(data)
            pin = self.manifest_sha if data.endswith(b' ') else packet.sha(data)
            runner = mock.Mock()
            with self.subTest(data=data[:30]), self.assertRaises(ValueError):
                packet.verify(self.root, self.manifest_path, pin, self.commit, runner, self.base / 'unused')
            runner.run.assert_not_called()

    def test_source_bytes_modes_symlinks_and_hardlinks_are_refused(self):
        name = packet.DOCUMENT
        path = self.root / name
        for change in ('bytes', 'mode', 'symlink', 'hardlink'):
            path.unlink()
            if change == 'symlink':
                path.symlink_to(self.root / 'LICENSE')
            else:
                path.write_bytes(b'changed' if change == 'bytes' else self.contents[name])
                path.chmod(0o755 if change == 'mode' else 0o644)
                if change == 'hardlink':
                    os.link(path, self.base / 'extra-link')
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.verify(self.base / change)

    def test_commit_blob_and_mode_or_nonzero_git_results_are_refused(self):
        for change in ('blob', 'mode', 'exit'):
            def drift(argv, **kwargs):
                result = self.run_git(argv, **kwargs)
                if change == 'blob' and argv[8] == 'show':
                    result.stdout = b'different committed source'
                elif change == 'mode' and argv[8] == 'ls-tree':
                    result.stdout = b'100777\n'
                elif change == 'exit':
                    result.returncode = 1
                return result
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'packet-(Git-binding|HEAD)'):
                self.verify(self.base / change, drift)

    def test_mid_copy_source_drift_is_refused(self):
        name = 'scripts/setup/setup.py'
        def drift(argv, **kwargs):
            result = self.run_git(argv, **kwargs)
            if argv[8] == 'ls-tree' and argv[-1] == name:
                (self.root / name).write_bytes(b'mid-copy drift')
            return result
        with self.assertRaisesRegex(ValueError, 'packet-copy-race'):
            self.verify(callback=drift)

    def test_mid_copy_destination_mode_drift_is_refused(self):
        output = self.base / 'packet'
        changed = False
        def drift(argv, **kwargs):
            nonlocal changed
            result = self.run_git(argv, **kwargs)
            target = output / 'AGENTS.md'
            if not changed and target.exists():
                target.chmod(0o755)
                changed = True
            return result
        with self.assertRaisesRegex(ValueError, 'packet-copy-race'):
            self.verify(output, drift)
        self.assertTrue(changed)

    def test_kernel_and_original_recipe_must_match_independent_frozen_maps(self):
        for change in ('kernel', 'recipe'):
            name = 'scripts/ci/native_arm.py' if change == 'kernel' else next(iter(self.recipes)) + '/PKGBUILD'
            before = self.contents[name]
            self.write(name, b'new separately pinned source\n')
            row = self.manifest['files'][name]
            row.update(sha256=packet.sha(self.contents[name]), bytes=len(self.contents[name]))
            self.refresh_manifest()
            expected = 'frozen-kernel-drift' if change == 'kernel' else 'original-recipe-drift'
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, expected):
                self.verify(self.base / change)
            self.write(name, before)
            row.update(sha256=packet.sha(before), bytes=len(before))

    def test_output_inside_repo_existing_or_symlink_is_refused(self):
        existing = self.base / 'existing'
        existing.mkdir()
        link = self.base / 'output-link'
        link.symlink_to(existing, target_is_directory=True)
        for output in (self.root / 'new', existing, link):
            with self.subTest(output=output), self.assertRaises(ValueError):
                self.verify(output)

    def test_dotdot_output_cannot_create_inside_source_root(self):
        external = self.base / 'external'
        external.mkdir()
        output = external / '..' / 'repo' / 'escaped'
        with self.assertRaises(ValueError):
            self.verify(output)
        self.assertFalse((self.root / 'escaped').exists())

    def test_symlink_output_ancestor_cannot_create_inside_source_root(self):
        alias = self.base / 'repo-alias'
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.verify(alias / 'escaped')
        self.assertFalse((self.root / 'escaped').exists())

    def test_invalid_commit_and_rows_are_refused(self):
        for commit in ('main', 'A' * 40, 'a' * 39):
            self.commit = commit
            with self.subTest(commit=commit), self.assertRaises(ValueError):
                self.verify()
        self.commit = 'a' * 40
        name = next(iter(self.manifest['files']))
        original = self.manifest['files'][name].copy()
        for index, change in enumerate(({'mode': True}, {'bytes': -1}, {'sha256': 'a' * 63}, {'extra': 1})):
            self.manifest['files'][name] = {**original, **change}
            self.refresh_manifest()
            with self.subTest(row=change), self.assertRaisesRegex(ValueError, 'packet-row'):
                self.verify(self.base / ('row-' + str(index)))

    def test_directory_walk_is_finite_before_any_git_or_copy(self):
        job = self.root / packet.PREFIX
        for name in range(1025):
            (job / (str(name) + '.py')).write_bytes(b'')
        with self.assertRaisesRegex(ValueError, 'packet-directory-bound'):
            packet.closure(self.root)
        self.assertEqual(self.commands, [])

    def test_workflow_sha_environment_and_head_must_match(self):
        for key in ('GITHUB_SHA', 'GITHUB_WORKFLOW_SHA'):
            with mock.patch.dict(os.environ, {key: 'b' * 40}), self.assertRaisesRegex(ValueError, 'packet-workflow-commit'):
                self.verify()
        def different_head(argv, **kwargs):
            result = self.run_git(argv, **kwargs)
            if argv[8] == 'rev-parse':
                result.stdout = ('b' * 40 + '\n').encode()
            return result
        with self.assertRaisesRegex(ValueError, 'packet-HEAD'):
            self.verify(callback=different_head)

    def test_manifest_authentication_and_parser_use_the_same_captured_bytes(self):
        original = packet.read
        def swap(path, *args):
            data = original(path, *args)
            if Path(path) == self.manifest_path:
                self.manifest_path.write_bytes(b'{"schema_version":1,"files":{}}')
            return data
        with mock.patch.object(packet, 'read', side_effect=swap):
            self.assertEqual(self.verify()['status'], 'PASS')

    def test_helper_frozen_pin_cannot_be_overridden_by_manifest(self):
        name = 'scripts/setup/setup.py'
        self.write(name, b'new producer helper', 0o644)
        self.manifest['files'][name] = packet.row(self.contents[name], 0o644)
        self.refresh_manifest()
        with self.assertRaisesRegex(ValueError, 'frozen-producer-drift'):
            self.verify()

    def test_total_budget_refuses_before_git_and_output(self):
        with mock.patch.object(packet, 'MAX_TOTAL', 1), self.assertRaisesRegex(ValueError, 'packet-total-bound'):
            self.verify()
        self.assertEqual(self.commands, [])
        self.assertFalse((self.base / 'packet').exists())

    def test_per_file_budget_oversized_rows_refused(self):
        self.manifest['files']['LICENSE']['bytes'] = packet.MAX_FILE + 1
        self.refresh_manifest()
        with self.assertRaisesRegex(ValueError, 'packet-row'):
            self.verify()
        self.assertEqual(self.commands, [])

    def test_recipe_extra_file_is_refused_before_git_and_output(self):
        self.write(next(iter(self.recipes)) + '/unreviewed.txt', b'new file')
        with self.assertRaisesRegex(ValueError, 'producer-recipe-set'):
            self.verify()
        self.assertEqual(self.commands, [])

    def test_job_cache_excluded_but_links_are_refused(self):
        cache = self.root / packet.PREFIX / '__pycache__'
        cache.mkdir()
        (cache / 'packet.pyc').write_bytes(b'cache')
        self.assertNotIn(packet.PREFIX + '__pycache__/packet.pyc', packet.closure(self.root)[0])
        (self.root / packet.PREFIX / 'alias.py').symlink_to(self.root / 'LICENSE')
        with self.assertRaisesRegex(ValueError, 'packet-own-file'):
            packet.closure(self.root)

    def test_private_snapshot_under_only_new_job_artifacts_is_allowed(self):
        parent = self.root / 'artifacts/kernel-native-job'
        parent.mkdir(parents=True)
        self.assertEqual(self.verify(parent / 'source')['status'], 'PASS')
        other = self.root / 'artifacts/kernel-native-stage'
        other.mkdir(parents=True)
        with self.assertRaisesRegex(ValueError, 'packet-commit-output'):
            self.verify(other / 'source')

    def test_preview_returns_complete_map_without_writing_lock(self):
        self.assertEqual(packet.preview(self.root), self.manifest)
        self.assertEqual((self.root / packet.PREFIX / 'packet.lock.json').read_bytes(), b'{}\n')

    def test_capture_detects_mutation_during_file_read(self):
        path = self.root / packet.DOCUMENT
        original = os.read
        changed = False
        def mutate(fd, size):
            nonlocal changed
            data = original(fd, size)
            if data and not changed:
                path.write_bytes(b'changed during read')
                changed = True
            return data
        with mock.patch.object(os, 'read', side_effect=mutate), self.assertRaisesRegex(ValueError, 'packet-race'):
            packet.capture(path)

    def test_capture_refuses_symlink_ancestors_and_oversized_file(self):
        alias = self.base / 'source-alias'
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'packet-file'):
            packet.capture(alias / 'LICENSE')
        with self.assertRaisesRegex(ValueError, 'packet-file'):
            packet.capture(self.root / 'LICENSE', limit=1)

    def test_private_manifest_mode_is_allowed_but_source_mode_is_fixed(self):
        self.manifest_path.chmod(0o600)
        self.assertEqual(self.verify()['status'], 'PASS')
        (self.root / packet.DOCUMENT).chmod(0o600)
        with self.assertRaisesRegex(ValueError, 'packet-source-mode'):
            packet.preview(self.root)

    def test_closure_file_count_limit_is_enforced(self):
        with mock.patch.object(packet, 'MAX_FILES', 1), self.assertRaisesRegex(ValueError, 'packet-file-count'):
            packet.closure(self.root)


if __name__ == '__main__':
    unittest.main()

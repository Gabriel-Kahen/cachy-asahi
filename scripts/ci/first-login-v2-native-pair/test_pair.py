#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Source-only regression controls for the First Login native pair adapter."""

import argparse
import importlib.util
import json
from pathlib import Path
import shutil
import stat
import tempfile
from types import ModuleType
import unittest
from unittest.mock import patch


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).resolve().with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pair = load('pair')
bootstrap = load('bootstrap')


class PairTests(unittest.TestCase):
    def test_installed_setup8_is_the_only_inventory_change(self):
        raw = (inputs / 'expected342.lock').read_bytes()
        removed = raw.replace(b'cachy-asahi-setup 0.3.0-1\n', b'', 1)
        self.assertEqual(pair.builder_lock(removed), raw)
        with self.assertRaisesRegex(ValueError, 'exact proven Fish'):
            pair.builder_lock(removed.replace(b'fish 4.9.3-1\n', b'', 1))

    def test_real_check_log_parses_and_missing_or_duplicate_named_case_refuses(self):
        raw = check_log.read_bytes()
        pair.check_log(raw)
        line = next(line for line in raw.splitlines() if pair.VERBOSE_CASE.fullmatch(line))
        for changed in (raw.replace(line, b'', 1), raw + b'\n' + line + b'\n',
                        raw.replace(b'Ran 11 tests', b'Ran 10 tests', 1)):
            with self.subTest(changed=len(changed)), self.assertRaises(ValueError):
                pair.check_log(changed)

    def test_bootstrap_wrapper_stages_only_pinned_dependency_before_actor_boundary(self):
        source = native_source.read_bytes()
        native = ModuleType('fake_native')
        native.PINNED_CONTEXT_TRANSFER = self.fail
        certificate_bytes = b'actor-fenced dummy public certificate bytes'
        test_pins = {**pair.PINS['setup8'], 'certificate': {
            'bytes': len(certificate_bytes), 'sha256': pair.digest(certificate_bytes)}}
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            cert = home / 'public.gpg'
            cert.write_bytes(certificate_bytes)
            context = home / 'context'
            context.mkdir(mode=0o700)
            with patch.dict(pair.PINS, setup8=test_pins):
                code = bootstrap.bind(native, source, inputs / 'dependency', cert, pair)
                self.assertTrue(callable(native.build))
                self.assertIn('pacman -U --noconfirm --noscriptlet /tmp/setup8/' + pair.SETUP, code)
                self.assertIn('gpgv --status-fd 1 --keyring /tmp/setup8/public.gpg', code)
                self.assertIn("expected['cachy-asahi-setup'] = '0.3.0-1'", code)
                self.assertNotIn('SigLevel = Never', code)
                self.assertEqual(code.count('PINNED_CONTEXT_TRANSFER('), 3)
                self.assertEqual(list(context.iterdir()), [])
                native._stage_exact_setup8(context)
                self.assertEqual({item.name for item in (context/'setup8').iterdir()},
                                 {pair.SETUP, pair.SETUP + '.sig', 'public.gpg'})
                self.assertEqual(stat.S_IMODE((context/'setup8'/pair.SETUP).stat().st_mode), 0o644)
                cert.write_bytes(b'changed')
                with self.assertRaisesRegex(ValueError, 'exact Setup8 certificate'):
                    native._stage_exact_setup8(context)
                with self.assertRaisesRegex(ValueError, 'exact proven signed-input'):
                    bootstrap.bind(native, source + b'\n', inputs / 'dependency', cert, pair)

    def test_recipe_is_exact_and_source_pins_refuse_modified_body(self):
        expected = pair.PINS['recipe']
        self.assertEqual({leaf.name: pair.digest(leaf.read_bytes()) for leaf in
                          (inputs / 'recipe').iterdir()}, expected)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            copy = root / 'recipe'
            shutil.copytree(inputs / 'recipe', copy)
            (copy / 'PKGBUILD').write_bytes(b'pkgname=other\n')
            output = root / 'unopened'
            with self.assertRaisesRegex(ValueError, 'exact First Login recipe'):
                pair.prepare(copy, copy / 'not-used', root / 'not-used', output, fish_tools)
            self.assertFalse(output.exists())

    def test_signed_runtime_tool_projections_change_only_exact_archive_identity(self):
        for name in pair.FISH_TOOL_PINS:
            raw = (fish_tools / name).read_bytes()
            projected = pair.project_tool(name, raw)
            self.assertEqual(projected, (inputs / 'tool-projections' / name).read_bytes())
            self.assertIn(pair.ARCHIVE.encode(), projected)
            with self.assertRaisesRegex(ValueError, 'exact proven Fish builder'):
                pair.project_tool(name, raw + b'\n')

    def test_finish_joins_both_normal_check_logs_to_distinct_exact_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            archive = b'\xfd7zXZ\0synthetic-header-only-fixture'
            log = check_log.read_bytes()
            lock = inputs / 'expected342.lock'
            lock_body = lock.read_bytes()
            image = 'sha256:' + '1' * 64
            dirs = [output / 'build-1', output / 'build-2']
            for root in dirs:
                artifacts = root / 'artifacts'
                artifacts.mkdir(parents=True)
                (artifacts / pair.ARCHIVE).write_bytes(archive)
                (artifacts / pair.CHECK_LOG).write_bytes(log)
                (artifacts / 'packages.lock').write_bytes(lock_body)
                (root / 'provenance.json').write_text(json.dumps({
                    'status': 'built-package-static-pass', 'exit_code': 0, 'mode': 'native',
                    'builder_host_arch': 'aarch64', 'image_id': image, 'recipe_inputs': pair.PINS['recipe'],
                    'expected_packages_sha256': pair.digest(lock_body), 'clean_environment_id': root.name,
                    'artifacts': {pair.ARCHIVE: pair.digest(archive)},
                    'files': {'artifacts/' + pair.CHECK_LOG: pair.digest(log)},
                }))
            result = output / 'comparison.json'
            result.write_text(json.dumps({'status': 'contents-reproduced', 'errors': [], 'packages': {
                pair.ARCHIVE: {field: True for field in ('installed_contents_equal', 'pkginfo_equal',
                                                        'buildinfo_equal', 'bytes_equal')}}}))
            self.assertEqual(len(pair.finish(*dirs, result, image, lock)['builds']), 2)
            (dirs[1] / 'artifacts' / 'packages.lock').write_bytes(lock_body.replace(b'cachy-asahi-setup 0.3.0-1\n', b''))
            with self.assertRaisesRegex(ValueError, 'actual complete 342'):
                pair.finish(*dirs, result, image, lock)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--staged', type=Path, required=True)
    parser.add_argument('--native-source', type=Path, required=True)
    parser.add_argument('--check-log', type=Path, required=True)
    parser.add_argument('--fish-tools', type=Path, required=True)
    args = parser.parse_args()
    inputs, native_source, check_log, fish_tools = args.staged, args.native_source, args.check_log, args.fish_tools
    unittest.main(argv=[__file__, '-v'])

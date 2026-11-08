#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Current 0.5 recipe custody controls; all recipe/archive contents remain DATA."""
import argparse
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent
PROFILE_SHA = 'c1f3c13aa7c75c587055de0d619f27755a987a87baac16b9c783c40d273174cd'
ADAPTER_SHA = '0d4ff5d64b000453eb66f753808f6aeeb9a0c2fe5a1244a8e178b788178da976'
NAMES = set('PKGBUILD .SRCINFO LICENSE NOTICE README.md cachy-asahi-source-tools check_package.py fixtures.tar.gz multi_package_roundtrip.py payload-map.json private-source.tar.gz source-provenance.json source_context_info.py source_mirror_catalog.py source_mirror_diff.py source_release_context.py test_cli_input_refusal.py test_package.py test_source_context_info.py test_source_mirror_catalog.py test_source_mirror_diff.py test_source_release_context.py'.split())
PRIVATE = set('build/build_v2.py build/container-entry-v2.sh build/mirror_consumer.py build/source_materials.py checks/package_checks.py maintenance/source_cache.py release/recipe_source_delivery.py release/release_sbom.py release/release_source_mirror.py release/source_delivery.py update/archive_stream.py'.split())


class CurrentDeliveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # unittest discovery imports this module without entering the CLI.
        if 'VALUE' not in globals():
            configure(argparse.Namespace(
                recipe_root=HERE.parents[1] / 'packages/tools/cachy-asahi-source-tools-v5',
                adapter=HERE / 'source_tools_source_delivery_v1.py',
                profile=HERE / 'source-tools-source-profile-v5.json'))

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='source-tools-v5-delivery-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.recipe = self.root / 'recipe'
        self.recipe.mkdir(mode=0o700)
        # Normalize only this verified COPY. The supplied recipe is never chmodded.
        for name, row in VALUE['files'].items():
            raw, _ = D.read(ARGS.recipe_root / name)
            self.assertEqual((len(raw), D.sha(raw)), (row['bytes'], row['sha256']))
            path = self.recipe / name
            path.write_bytes(raw)
            path.chmod(row['mode'])
        self.profile = self.root / 'profile-v5.json'
        self.profile.write_bytes(PROFILE_RAW)
        self.out = self.root / 'export'
        self.common = ['--profile', str(self.profile), '--profile-sha256', PROFILE_SHA]

    def cli(self, argv, expected=0):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(D.main(argv), expected, err.getvalue())
        return json.loads(out.getvalue()) if expected == 0 else err.getvalue()

    def pack(self, expected=0, output=None):
        return self.cli(['pack', '--recipe', str(self.recipe), '--output', str(output or self.out), *self.common], expected)

    def use(self, action, raw=None, expected=0, output=None, digest=None):
        path = self.out / 'source.tar'
        if raw is not None:
            path.write_bytes(raw)
        args = [action, '--bundle', str(path), '--sha256', digest or D.sha(path.read_bytes()), *self.common]
        if action == 'unpack':
            args += ['--output', str(output or self.root / 'unpacked')]
        return self.cli(args, expected)

    def assert_recipe(self, recipe):
        self.assertEqual(D.scan(recipe), NAMES)
        for name, row in VALUE['files'].items():
            raw, mode = D.read(recipe / name)
            self.assertEqual((len(raw), D.sha(raw), mode), (row['bytes'], row['sha256'], row['mode']))

    def test_exact_current_recipe_license_and_twenty_source_bindings(self):
        self.assertEqual(set(VALUE['files']), NAMES)
        self.assertEqual(VALUE['version'], '0.5.0-1')
        self.assertEqual(len(NAMES), 22)
        pkgbuild = (self.recipe / 'PKGBUILD').read_text()
        srcinfo = (self.recipe / '.SRCINFO').read_text()
        sources = re.search(r'^source=\(([^\n]*)\)$', pkgbuild, re.M).group(1).split()
        sums = re.search(r'^sha256sums=\(([^\n]*)\)$', pkgbuild, re.M).group(1).split()
        self.assertEqual(len(sources), 20)
        self.assertEqual(set(sources) | {'PKGBUILD', '.SRCINFO'}, NAMES)
        self.assertEqual(sources, re.findall(r'^\s+source = (.+)$', srcinfo, re.M))
        self.assertEqual(sums, re.findall(r'^\s+sha256sums = (.+)$', srcinfo, re.M))
        self.assertEqual(sums, [VALUE['files'][name]['sha256'] for name in sources])
        self.assertIn('pkgver=0.5.0\npkgrel=1\n', pkgbuild)
        self.assertIn('\tpkgver = 0.5.0\n\tpkgrel = 1\n', srcinfo)
        self.assertIn('license=(MIT)', pkgbuild)
        self.assertIn('\tlicense = MIT\n', srcinfo)
        self.assertIn('Permission is hereby granted', (self.recipe / 'LICENSE').read_text())
        self.assertEqual(VALUE['files']['cachy-asahi-source-tools']['mode'], 0o755)
        self.assertEqual({v['mode'] for k, v in VALUE['files'].items() if k != 'cachy-asahi-source-tools'}, {0o644})

    def test_private_eleven_provenance_and_payload_closure_data_only(self):
        provenance = json.loads((self.recipe / 'source-provenance.json').read_bytes())
        payload = json.loads((self.recipe / 'payload-map.json').read_bytes())
        self.assertEqual(provenance['license'], 'MIT')
        self.assertEqual(provenance['source_revision'], '28814717fd2dbf66b9b65c2354a36b3c2843e3be')
        self.assertEqual(set(provenance['files']), {'scripts/' + p for p in PRIVATE})
        with tarfile.open(fileobj=io.BytesIO((self.recipe / 'private-source.tar.gz').read_bytes()), mode='r:gz') as archive:
            members = archive.getmembers()
            self.assertEqual(len(members), 11)
            self.assertEqual({m.name for m in members}, {'private/scripts/' + p for p in PRIVATE})
            for member in members:
                self.assertTrue(member.isfile())
                self.assertFalse(member.pax_headers)
                row = provenance['files'][member.name.removeprefix('private/')]
                with archive.extractfile(member) as stream:
                    raw = stream.read(D.MAX_FILE + 1)
                self.assertEqual((len(raw), D.sha(raw), member.mode), (row['bytes'], row['sha256'], row['mode']))
                installed = 'usr/lib/cachy-asahi/source-tools/' + member.name.removeprefix('private/')
                self.assertEqual(payload['files'][installed], row)

    def test_export_deterministic_twenty_four_members_and_receipt(self):
        result = self.pack()
        second = self.root / 'second'
        self.pack(output=second)
        raw = (self.out / 'source.tar').read_bytes()
        self.assertEqual(raw, (second / 'source.tar').read_bytes())
        self.assertEqual(result['recipe_files'], 22)
        self.assertEqual(result['version'], '0.5.0-1')
        self.assertFalse(result['code_executed'])
        self.assertFalse(result['network'])
        self.assertFalse(result['release_accepted'])
        self.assertEqual(result['profile_sha256'], PROFILE_SHA)
        receipt = json.loads((self.out / 'receipt.json').read_bytes())
        self.assertEqual(receipt, {k: v for k, v in result.items() if k != 'status'})
        self.assertEqual(stat.S_IMODE(self.out.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.out / 'source.tar').stat().st_mode), 0o600)
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
            rows = archive.getmembers()
            self.assertEqual(len(rows), 24)
            self.assertEqual([r.name for r in rows], sorted(['recipe/' + n for n in NAMES] + ['delivery/' + D.PROFILE_NAME, 'delivery/' + D.ADAPTER_NAME]))
            for row in rows:
                self.assertTrue(row.isfile())
                self.assertEqual((row.uid, row.gid, row.mtime, row.uname, row.gname), (0, 0, 0, '', ''))
        self.use('verify')

    def test_unpack_reimport_exact_all_hashes_modes_and_transport(self):
        self.pack()
        self.use('unpack')
        unpacked = self.root / 'unpacked'
        self.assert_recipe(unpacked / 'recipe')
        self.assertEqual((unpacked / 'delivery' / D.PROFILE_NAME).read_bytes(), PROFILE_RAW)
        self.assertEqual(D.sha((unpacked / 'delivery' / D.ADAPTER_NAME).read_bytes()), ADAPTER_SHA)
        result = self.cli(['pack', '--recipe', str(unpacked / 'recipe'), '--output', str(self.root / 'reimport'), *self.common])
        self.assertEqual((self.out / 'source.tar').read_bytes(), (self.root / 'reimport/source.tar').read_bytes())
        self.assertEqual(result['recipe_files'], 22)

    def test_moved_standalone_trusted_adapter_without_original_recipe(self):
        packed = self.pack()
        moved = self.root / 'moved'
        moved.mkdir(mode=0o700)
        # This maintained, independently hash-checked copy is NEVER read from source.tar.
        trusted = moved / 'trusted-adapter.py'
        trusted.write_bytes(ADAPTER_RAW)
        profile = moved / 'externally-pinned-profile.json'
        profile.write_bytes(PROFILE_RAW)
        bundle = moved / 'source.tar'
        bundle.write_bytes((self.out / 'source.tar').read_bytes())
        shutil.rmtree(self.recipe)
        shutil.rmtree(self.out)
        self.profile.unlink()
        for action in ('verify', 'unpack'):
            args = [sys.executable, '-I', '-B', str(trusted), action, '--bundle', str(bundle), '--sha256', packed['source_sha256'], '--profile', str(profile), '--profile-sha256', PROFILE_SHA]
            if action == 'unpack':
                args += ['--output', str(moved / 'retrieved')]
            run = subprocess.run(args, cwd=moved, capture_output=True, text=True, timeout=20)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(json.loads(run.stdout)['recipe_files'], 22)
        self.assert_recipe(moved / 'retrieved/recipe')
        self.assertFalse(list(self.root.rglob('__pycache__')))

    def test_each_recipe_member_mutation_refused_before_output(self):
        for name in sorted(NAMES):
            with self.subTest(member=name):
                path = self.recipe / name
                original = path.read_bytes()
                path.write_bytes(original + b'\n')
                self.assertIn('recipe input mismatch', self.pack(1))
                self.assertFalse(self.out.exists())
                path.write_bytes(original)

    def test_missing_extra_mode_and_old_recipe_refuse(self):
        path = self.recipe / 'source_release_context.py'
        original = path.read_bytes()
        path.unlink()
        self.assertIn('file set differs', self.pack(1))
        path.write_bytes(original)
        path.chmod(0o644)
        path.chmod(0o600)
        self.assertIn('recipe input mismatch', self.pack(1))
        path.chmod(0o644)
        extra = self.recipe / 'extra'
        extra.write_bytes(b'extra')
        self.assertIn('file set differs', self.pack(1))
        extra.unlink()
        pkg = self.recipe / 'PKGBUILD'
        pkg.write_bytes(pkg.read_bytes().replace(b'pkgver=0.5.0', b'pkgver=0.1.0'))
        self.assertIn('recipe input mismatch', self.pack(1))
        self.assertFalse(self.out.exists())

    def test_wrong_profile_bundle_and_re_pinned_missing_or_changed_member_refuse(self):
        packed = self.pack()
        original = (self.out / 'source.tar').read_bytes()
        self.profile.write_bytes(PROFILE_RAW + b'\n')
        self.assertIn('profile checksum mismatch', self.use('verify', expected=1))
        self.profile.write_bytes(PROFILE_RAW)
        self.assertIn('bundle checksum mismatch', self.use('verify', raw=original + b'x', expected=1, digest=packed['source_sha256']))
        entries = D.verified(original, D.sha(original), VALUE, PROFILE_RAW, ADAPTER_RAW)
        for name in ('recipe/LICENSE', 'recipe/private-source.tar.gz', 'recipe/PKGBUILD', 'delivery/' + D.ADAPTER_NAME):
            with self.subTest(member=name):
                altered = dict(entries)
                altered.pop(name)
                self.use('unpack', raw=D.archive(altered), expected=1)
                self.assertFalse((self.root / 'unpacked').exists())
                altered = dict(entries)
                body, mode = altered[name]
                altered[name] = (bytes([body[0] ^ 1]) + body[1:], mode)
                self.use('unpack', raw=D.archive(altered), expected=1)
                self.assertFalse((self.root / 'unpacked').exists())

    def test_no_execution_import_network_or_builder_during_export_verify_unpack(self):
        imports = __import__
        def safe_import(name, *args, **kwargs):
            self.assertNotIn(name, ('check_package', 'source_release_context', 'build_v2', 'mirror_consumer', 'source_mirror_catalog'))
            return imports(name, *args, **kwargs)
        with mock.patch('subprocess.Popen', side_effect=AssertionError('subprocess prohibited')), mock.patch('socket.socket', side_effect=AssertionError('network prohibited')), mock.patch('os.system', side_effect=AssertionError('shell prohibited')), mock.patch('builtins.__import__', side_effect=safe_import):
            self.pack()
            self.use('verify')
            self.use('unpack')
        self.assertFalse(list(self.root.rglob('__pycache__')))

    def test_no_replace_and_interrupted_export_preserve_foreign_and_cleanup(self):
        self.out.mkdir()
        marker = self.out / 'foreign'
        marker.write_bytes(b'owned')
        self.pack(1)
        self.assertEqual(marker.read_bytes(), b'owned')
        shutil.rmtree(self.out)
        with mock.patch.object(D, 'write_file', side_effect=KeyboardInterrupt):
            self.assertRaises(KeyboardInterrupt, self.pack)
        self.assertFalse(self.out.exists())
        self.assertFalse(list(self.root.glob('.source-tools-source-*')))
        self.pack()
        foreign = self.root / 'unpacked'
        foreign.mkdir()
        marker = foreign / 'foreign'
        marker.write_bytes(b'owned')
        self.use('unpack', expected=1)
        self.assertEqual(marker.read_bytes(), b'owned')


def configure(args):
    global ARGS, D, PROFILE_RAW, ADAPTER_RAW, VALUE
    ARGS = args
    ARGS.recipe_root = ARGS.recipe_root.absolute()
    ARGS.adapter = ARGS.adapter.absolute()
    import hashlib
    ADAPTER_RAW = ARGS.adapter.read_bytes()
    if hashlib.sha256(ADAPTER_RAW).hexdigest() != ADAPTER_SHA:
        raise ValueError('trusted maintained v1 adapter SHA-256 differs')
    spec = importlib.util.spec_from_file_location('trusted_source_tools_delivery', ARGS.adapter)
    D = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(D)
    PROFILE_RAW, _ = D.read(ARGS.profile.absolute())
    VALUE = D.profile(PROFILE_RAW, PROFILE_SHA)
    if D.scan(ARGS.recipe_root) != NAMES:
        raise ValueError('current recipe exact 22-file input set differs')


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--recipe-root', type=Path, required=True)
    parser.add_argument('--adapter', type=Path, default=HERE / 'source_tools_source_delivery_v1.py')
    parser.add_argument('--profile', type=Path, default=HERE / 'source-tools-source-profile-v5.json')
    try:
        configure(parser.parse_args())
    except (OSError, ValueError) as error:
        parser.error(str(error))
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(CurrentDeliveryTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print(json.dumps(dict(status='PASS' if result.wasSuccessful() else 'FAIL', tests=result.testsRun,
        failures=len(result.failures), errors=len(result.errors), skipped=len(result.skipped),
        recipe_files=22, transport_members=24, private_runtime_files=11, version='0.5.0-1',
        profile_sha256=PROFILE_SHA, adapter_sha256=ADAPTER_SHA,
        native='NOT_RUN', installation='NOT_RUN', hardware='NOT_RUN', release='NOT_ADMITTED',
        code_from_recipe_or_bundle_executed=False, network=False), sort_keys=True))
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())

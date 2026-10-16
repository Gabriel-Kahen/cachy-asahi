#!/usr/bin/env python3
"""Inert controls: package-set binding, export seals, signer and actor boundary."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
spec = importlib.util.spec_from_file_location('installer587_producer', HERE / 'producer.py')
producer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(producer)
BASE = json.loads((ROOT / 'scripts/ci/maintained-desktop574-inputs.json').read_text())
LOCK = (ROOT / 'scripts/ci/full-development-composition/expected-updater-v2.lock').read_bytes()
BASE_NAMES = {r['name'] for r in BASE['packages'] if r['name'] != 'libfdk-aac'}
ADDITIONS = [{'name': name, 'version': version} for name, version in
             (line.split() for line in LOCK.decode().splitlines()) if name not in BASE_NAMES]


class Selection(unittest.TestCase):
    def test_actual_declared_set_exact_initial_checkpoint(self):
        rows = producer.selected_rows(BASE['packages'], ADDITIONS, LOCK)
        self.assertEqual(len(rows), 587)
        self.assertNotIn('libfdk-aac', {r['name'] for r in rows})
        self.assertEqual(producer.inventory(rows), LOCK)

    def test_duplicate_addition_refuses(self):
        with self.assertRaisesRegex(ValueError, 'exact14'):
            producer.selected_rows(BASE['packages'], ADDITIONS[:-1] + ADDITIONS[:1], LOCK)

    def test_wrong_checkpoint_refuses(self):
        rows = [dict(r) for r in ADDITIONS]
        next(r for r in rows if r['name'] == 'cachy-asahi-setup')['version'] = '0.1.0-4'
        with self.assertRaisesRegex(ValueError, 'initial587'):
            producer.selected_rows(BASE['packages'], rows, LOCK)

    def test_extra_base_omission_refuses(self):
        with self.assertRaisesRegex(ValueError, 'exact574'):
            producer.selected_rows(BASE['packages'][1:], ADDITIONS, LOCK)

    def test_unsorted_lock_refuses(self):
        with self.assertRaisesRegex(ValueError, 'initial587'):
            producer.selected_rows(BASE['packages'], ADDITIONS, b'\n'.join(reversed(LOCK.splitlines())) + b'\n')


class Boundaries(unittest.TestCase):
    def test_held_prefix_compiles_and_excludes_volume_actor(self):
        api = SimpleNamespace(__dict__={})
        # Real imported globals are unnecessary: compiling does not call actors.
        api = SimpleNamespace()
        function, digest = producer.preparation_prefix(api, ROOT / 'scripts/ci/full-root-upgrade-caller/run.py')
        self.assertEqual(len(digest), 64)
        self.assertNotIn('container_args', function.__code__.co_names)
        self.assertNotIn('create_volume', function.__code__.co_names)

    def test_prefix_returns_before_exact_actor_boundary(self):
        text = """def compose(args, raw, public, result):
    inputs, plan, image, checkpoint_sha = 1, 2, 3, 4
    footprint = module('composition_volume_owner', HERE / 'footprint.py')
    raise RuntimeError('actor tail reached')
"""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'run.py'; path.write_text(text)
            api = SimpleNamespace()
            function, _ = producer.preparation_prefix(api, path)
            self.assertEqual(function(None, None, None, {}), {'inputs': 1, 'plan': 2, 'image': 3, 'checkpoint_sha': 4})

    def test_missing_or_duplicate_marker_refuses(self):
        for text in ("def compose(*args):\n    return 1\n", """def compose(*args):
    footprint = module('composition_volume_owner', HERE / 'footprint.py')
    footprint = module('composition_volume_owner', HERE / 'footprint.py')
"""):
            with tempfile.TemporaryDirectory() as td:
                path = Path(td) / 'run.py'; path.write_text(text)
                with self.assertRaisesRegex(ValueError, 'boundary changed'):
                    producer.preparation_prefix(SimpleNamespace(), path)

    def test_non_native_refuses_before_any_actor_or_output(self):
        with patch.object(producer.platform, 'machine', return_value='x86_64'), patch.object(producer.subprocess, 'run') as actor:
            with self.assertRaisesRegex(ValueError, 'native aarch64'):
                producer.prepare(SimpleNamespace())
            actor.assert_not_called()


class Signatures(unittest.TestCase):
    def test_primary_and_subkey_validation(self):
        primary, subkey = 'A' * 40, 'B' * 40
        for signing in (primary, subkey):
            producer.valid_signer(f'[GNUPG:] VALIDSIG {signing} 2026-10-16 1792100000 0 4 0 22 8 00 {primary}\n', primary)

    def test_wrong_duplicate_missing_or_rejected_status_refuses(self):
        primary = 'A' * 40
        good = f'[GNUPG:] VALIDSIG {primary} 2026-10-16 1792100000 0 4 0 22 8 00 {primary}\n'
        for status in ('', good + good, good.replace(primary, 'B' * 40), good + '[GNUPG:] REVKEYSIG key name\n'):
            with self.assertRaises(ValueError):
                producer.valid_signer(status, primary)


class Export(unittest.TestCase):
    def test_all587_signatures_checked_and_only_public_cache_exported(self):
        with tempfile.TemporaryDirectory() as td:
            raw = Path(td)
            inputs = raw / 'inputs'; inputs.mkdir()
            deps = raw / 'desktop574/context/deps'; deps.mkdir(parents=True)
            base = json.loads(json.dumps(BASE))
            additions = [dict(r) for r in ADDITIONS]
            data, signature = b'inert-test-archive', b'inert-test-signature'
            for row in base['packages'] + additions:
                row.update(filename=row['name'] + '.pkg.tar.xz', sha256=hashlib.sha256(data).hexdigest(), size=len(data),
                           signature_sha256=hashlib.sha256(signature).hexdigest(), signature_size=len(signature))
                root = inputs if row in additions else deps
                (root / row['filename']).write_bytes(data)
                (root / (row['filename'] + '.sig')).write_bytes(signature)
            (inputs / 'expected-installed.lock').write_bytes(LOCK)
            (raw / 'desktop574/installed-packages.lock').write_bytes(producer.inventory(BASE['packages']))
            alarm, test = b'inert-public-upstream', b'inert-public-TEST'
            (inputs / 'archlinuxarm.gpg').write_bytes(alarm)
            (inputs / 'TEST-public.asc').write_bytes(test)
            base['keyring_files'] = [{'filename': 'archlinuxarm.gpg', 'sha256': hashlib.sha256(alarm).hexdigest(), 'size': len(alarm)}]
            project_names = [r['name'] for r in additions if r['name'].startswith('cachy-asahi-')]
            self.assertEqual(len(project_names), 10)
            projects = [{'name': name, 'payload': []} for name in project_names]
            held = {'inputs': inputs, 'checkpoint_sha': producer.EXPECTED,
                    'plan': {'packages': additions, 'projects': projects, 'signer_fingerprint': base['signer_fingerprint'],
                             'test_signer_fingerprint': 'A' * 40}}
            calls, closed = [], []
            class Verifier:
                def __init__(self, home, keys):
                    self.keys = keys
                def __call__(self, archive, sig, signer):
                    calls.append((archive.name, signer))
                def close(self):
                    closed.append(True)
            ready = producer.export_ready(raw, raw / 'ready', held, base, {'installer': 'NOT RUN'}, Verifier)
            manifest = json.loads((ready / 'manifest.json').read_text())
            self.assertEqual(manifest['status'], 'READY_SIGNED_INITIAL587')
            self.assertEqual(manifest['builder_lock']['sha256'], producer.BUILDER)
            self.assertEqual(len(calls), 587)
            self.assertEqual(sum(signer == 'A' * 40 for _, signer in calls), 10)
            self.assertEqual(closed, [True])
            self.assertEqual({p.name for p in ready.iterdir()}, {'packages', 'keys', 'manifest.json', 'expected-installed.lock', 'builder-packages.lock'})
            for row in manifest['packages']:
                self.assertEqual((ready / row['archive']).stat().st_mode & 0o777, 0o444)
            self.assertEqual((ready / 'packages').stat().st_mode & 0o777, 0o555)
            self.assertNotIn('libfdk-aac.pkg.tar.xz', {p.name for p in (ready / 'packages').iterdir()})
            (ready / 'packages').chmod(0o700); (ready / 'keys').chmod(0o700)

    def test_symlink_hash_size_and_bound_refuse_without_copy(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); source = root / 'source'; source.write_bytes(b'x')
            digest = hashlib.sha256(b'x').hexdigest()
            linked = root / 'link'; linked.symlink_to(source)
            cases = [(linked, digest, 1, 1), (source, '0' * 64, 1, 1), (source, digest, 2, 2), (source, digest, 1, 0)]
            for index, (path, pin, size, bound) in enumerate(cases):
                target = root / str(index)
                with self.assertRaises(ValueError):
                    producer.checked_copy(path, target, pin, size, bound)
                self.assertFalse(target.exists())


class Cleanup(unittest.TestCase):
    def fixture(self, td, image, preexisting=()):
        root = Path(td)
        (root / 'private/desktop574').mkdir(parents=True)
        (root / 'public').mkdir()
        (root / 'private/desktop574/image-id').write_text(image)
        producer.save(root / 'producer-owner.json', {'schema_version': 1, 'token': 'a' * 32,
            'core_image': 'sha256:' + '0' * 64, 'images_preexisting': list(preexisting)})
        return root

    def test_preexisting_image_is_preserved(self):
        image = 'sha256:' + '1' * 64
        with tempfile.TemporaryDirectory(dir='/tmp') as td:
            root = self.fixture(td, image, [image])
            with patch.object(producer.subprocess, 'run') as actor:
                result = producer.cleanup(root)
            actor.assert_not_called()
            self.assertEqual(result['status'], 'PASS')
            self.assertFalse((root / 'private').exists())

    def test_failed_absence_retains_private_data(self):
        from types import SimpleNamespace
        image = 'sha256:' + '1' * 64
        with tempfile.TemporaryDirectory(dir='/tmp') as td:
            root = self.fixture(td, image)
            with patch.object(producer.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stderr=b'')) as actor:
                with self.assertRaisesRegex(ValueError, 'cleanup failed'):
                    producer.cleanup(root)
            self.assertEqual(actor.call_count, 2)
            self.assertTrue((root / 'private').exists())
            self.assertEqual(json.loads((root / 'public/producer-cleanup.json').read_text())['status'], 'FAIL')

    def test_borrowed_core_cannot_be_removed(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as td:
            root = self.fixture(td, 'sha256:' + '0' * 64)
            with patch.object(producer.subprocess, 'run') as actor:
                with self.assertRaisesRegex(ValueError, 'cleanup failed'):
                    producer.cleanup(root)
            actor.assert_not_called()
            self.assertTrue((root / 'private').exists())


if __name__ == '__main__':
    unittest.main()

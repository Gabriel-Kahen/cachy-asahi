#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline successor mirrors over inert sources and synthetic package archives."""
import copy
from contextlib import redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).absolute().parent
spec = importlib.util.spec_from_file_location('incremental_mirror_fixtures', HERE / 'test_release_source_mirror.py')
f = importlib.util.module_from_spec(spec); spec.loader.exec_module(f)
m, ROOT, DEPS = f.m, f.ROOT, f.DEPS


def members(raw):
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        return {node.name: archive.extractfile(node).read() for node in archive}


class SuccessorFixture(f.HTTPSFixture):
    """Two remote sources: one revised by release, one identical in every release."""
    unchanged = b'Original unchanged remote source fixture; data only.\n'

    def __init__(self, root, release_id='mirror-release-one', revision=1):
        super().__init__(root)
        self.manifest['release_id'] = self.spec['release_id'] = release_id
        self.source = ('Original remote source fixture revision ' + str(revision) + '; data only.\n').encode()
        self.url = 'https://example.invalid/changed-' + str(revision) + '.tar.gz'
        self.unchanged_url = 'https://example.invalid/unchanged.tar.gz'
        version = '1.' + str(revision) + '-1'; package = self.package(self.name)
        package.update(version=version, filename=self.name + '-' + version + '-any.pkg.tar.gz')
        bodies = self.bodies[self.name]
        bodies['PKGBUILD'] = ('# Inert recipe revision ' + str(revision) + '; never sourced\n').encode()
        bodies['retained.py'] = b'raise AssertionError("retained source must remain inert")\n'
        bodies['.SRCINFO'] = f.metadata(dict(pkgname=[self.name], pkgver=['1.' + str(revision)], pkgrel=['1'],
            arch=['any'], license=['MIT'], source=[self.url, self.unchanged_url, 'LICENSE', 'retained.py'],
            sha256sums=[m.digest(self.source), m.digest(self.unchanged), m.digest(self.license), m.digest(bodies['retained.py'])]))
        provenance = self.provenance[self.name]
        provenance['package']['version'] = version
        provenance['recipe_sha256'] = m.digest(bodies['PKGBUILD'])
        provenance['sources'] = [dict(url=self.url, sha256=m.digest(self.source)),
                                  dict(url=self.unchanged_url, sha256=m.digest(self.unchanged))]
        rows = self.archive_rows[self.name]
        rows['.PKGINFO'] = (f.metadata(dict(pkgname=[self.name], pkgver=[version], arch=['any'], license=['MIT'])), 0o644)
        rows['.BUILDINFO'] = (f.metadata(dict(format=['2'], pkgname=[self.name], pkgver=[version], pkgarch=['any'],
            pkgbuild_sha256sum=[provenance['recipe_sha256']], installed=['compiler-1-1-aarch64'])), 0o644)
        rows['usr/bin/fixture'] = (b'Inert package payload for ' + m.digest(self.source).encode() + b'\n', 0o755)
        self.refresh_archive(self.name)
        self.index['packages'] = [dict(package={key:package[key] for key in ('name','version','arch','sha256')},
            recipe_key='PKGBUILD', bundle=self.material(self.name, 'source.tar', f.recipe.tar_bytes(bodies)),
            recipe=self.material(self.name, 'recipe', bodies['PKGBUILD']),
            source_map=self.material(self.name, 'map', m.encoded({key:m.digest(raw) for key,raw in bodies.items()})),
            notices=[self.material(self.name, 'license', self.license)],
            authorization=self.material(self.name, 'review', b'Existing inert fixture review; no permission decision.\n'),
            review_status='Host source mirror fixture only')]
        self.refresh()
        license_ref = self.catalog['sources'][0]['license_evidence'][0]
        self.catalog['sources'] = [dict(material=dict(id=key, path=key + '.tar.gz', sha256=m.digest(raw), bytes=len(raw)),
            url=url, revision=label, license='MIT', license_evidence=[license_ref])
            for key,url,label,raw in (('changed', self.url, 'revision-' + str(revision), self.source),
                                      ('unchanged', self.unchanged_url, 'unchanged-1', self.unchanged))]
        self.plan['sources'] = [dict(source=row['url'], id=row['material']['id'], revision=row['revision'])
                                for row in self.catalog['sources']]
        self.plan['recipe_inputs'] = {key:m.digest(raw) for key,raw in bodies.items()}
        for raw in (self.source, self.unchanged):
            target = self.cache / 'objects' / m.digest(raw); target.write_bytes(raw); target.chmod(0o600)
        self.refresh_inputs()

    def refresh_inputs(self):
        super().refresh_inputs()
        for row in self.catalog['sources']:
            receipt = self.sm.cache.encoded(dict(schema_version=1, purpose='source-cache-receipt',
                inputs_sha256=self.plan['catalog_sha256'], source=row,
                object_path='objects/' + row['material']['sha256'], legal_acceptance=False,
                source_completeness_accepted=False))
            target = self.cache / 'receipts' / (self.plan['catalog_sha256'] + '-' + row['material']['id'] + '.json')
            target.write_bytes(receipt); target.chmod(0o600)


class IncrementalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='source-mirror-incremental-'); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.first = SuccessorFixture(self.root / 'first', 'mirror-release-one', 1)
        self.second = SuccessorFixture(self.root / 'second', 'mirror-release-two', 2)
        self.previous, self.previous_index, _ = self.first.build()

    def update(self, previous=None, previous_pin=None, previous_release=None, next_fixture=None):
        previous = self.previous if previous is None else previous
        fixture = self.second if next_fixture is None else next_fixture
        return m.update(previous, m.digest(previous) if previous_pin is None else previous_pin,
            self.first.pin if previous_release is None else previous_release, fixture.root, fixture.pin, DEPS,
            inputs=fixture.inputs_path, inputs_sha256=m.digest(fixture.inputs_raw), retained_root=fixture.retained,
            directory=ROOT / 'scripts/release')

    def test_two_release_deterministic_reuse_retirement_and_recovery(self):
        raw, index, verifier = self.update()
        self.assertEqual(raw, self.update()[0])
        self.assertEqual(verifier, (HERE / 'release_source_mirror.py').read_bytes())
        second, second_index, _ = self.second.build()
        before, after = set(self.previous_index['objects']), set(second_index['objects'])
        stats = index['stats']
        self.assertEqual(stats['new_objects'], len(after - before))
        self.assertEqual(stats['reused_objects'], len(after & before))
        self.assertEqual(stats['retired_objects'], len(before - after))
        self.assertEqual(stats['retained_recovery_objects'], len(before - after))
        self.assertEqual(stats['pruned_objects'], 0)
        self.assertGreater(stats['new_objects'], 0); self.assertGreater(stats['reused_objects'], 0)
        self.assertGreater(stats['retired_objects'], 0)
        content = members(raw)
        for body in (self.first.source, self.second.source, self.first.unchanged, self.first.license):
            self.assertEqual(content['objects/' + m.digest(body)], body)
        self.assertEqual(sum(path == 'objects/' + m.digest(self.first.unchanged) for path in content), 1)
        self.assertEqual([row['release_sha256'] for row in index['releases']], [self.first.pin, self.second.pin])
        for row, original in zip(index['releases'], (self.previous, second)):
            saved = content['objects/' + row['manifest']['sha256']]
            saved_index = m.decode(saved)
            rebuilt = m.tar_bytes({'mirror.json':saved,
                'verify.py':content['objects/' + row['verifier']['sha256']],
                **{'objects/' + key:content['objects/' + key] for key in saved_index['objects']}})
            self.assertEqual(rebuilt, original)
            self.assertEqual(m.digest(rebuilt), row['mirror_sha256'])
            m.verify(rebuilt, row['mirror_sha256'], row['release_sha256'])
        for pin in (self.first.pin, self.second.pin):
            result = m.verify_any(raw, m.digest(raw), pin)
            self.assertEqual(result['release_sha256'], pin)
            self.assertEqual(result['head_release_sha256'], self.second.pin)
            self.assertEqual(set(result['retained_releases']), {self.first.pin, self.second.pin})

    def test_three_release_history_retains_first_recovery_inputs(self):
        raw, index, _ = self.update()
        third = SuccessorFixture(self.root / 'third', 'mirror-release-three', 3)
        updated, final, _ = self.update(raw, previous_release=self.second.pin, next_fixture=third)
        self.assertEqual(len(final['releases']), 3)
        self.assertEqual(final['stats']['pruned_objects'], 0)
        for pin in (self.first.pin, self.second.pin, third.pin):
            self.assertEqual(m.verify_any(updated, m.digest(updated), pin)['release_sha256'], pin)
        self.assertIn('objects/' + m.digest(self.first.source), members(updated))

    def test_offline_update_no_source_execution(self):
        with patch.object(socket, 'socket', side_effect=AssertionError('network forbidden')), \
             patch.object(socket, 'getaddrinfo', side_effect=AssertionError('DNS forbidden')), \
             patch.object(subprocess, 'Popen', side_effect=AssertionError('subprocess forbidden')):
            raw, _, _ = self.update()
            self.assertEqual(m.verify_any(raw, m.digest(raw), self.first.pin)['release_sha256'], self.first.pin)

    def test_missing_tampered_and_wrong_pin_previous_refused(self):
        old = members(self.previous); key = 'objects/' + m.digest(self.first.source)
        for kind in ('missing', 'tampered'):
            changed = dict(old)
            if kind == 'missing': changed.pop(key)
            else: changed[key] += b'changed'
            altered = m.tar_bytes(changed)
            with self.assertRaises((ValueError, KeyError)):
                self.update(altered)
        for options in ({'previous_pin':'a' * 64}, {'previous_release':'b' * 64}):
            with self.assertRaises(ValueError): self.update(**options)

    def test_previous_proof_precedes_next_input_loading(self):
        changed = members(self.previous); changed.pop('objects/' + m.digest(self.first.source))
        with patch.object(m, 'build', side_effect=AssertionError('next inputs read before previous proof')):
            with self.assertRaises(ValueError): self.update(m.tar_bytes(changed))

    def test_missing_next_source_refused(self):
        target = self.second.cache / 'objects' / m.digest(self.second.source)
        target.unlink()
        with self.assertRaisesRegex(ValueError, 'offline|missing'):
            self.update()

    def test_same_release_or_conflicting_release_id_refused(self):
        with self.assertRaises(ValueError): self.update(next_fixture=self.first)
        self.second.manifest['release_id'] = self.second.spec['release_id'] = self.first.manifest['release_id']
        self.second.refresh(); self.second.refresh_inputs()
        with self.assertRaises(ValueError): self.update()

    def test_history_missing_recovery_object_or_changed_stats_refused(self):
        raw, index, _ = self.update(); original = members(raw)
        changed = dict(original); changed.pop('objects/' + m.digest(self.first.source))
        altered = m.tar_bytes(changed)
        with self.assertRaises((ValueError, KeyError)):
            m.verify_any(altered, m.digest(altered), self.second.pin)
        changed_index = copy.deepcopy(index); changed_index['stats']['retired_objects'] += 1
        changed = dict(original, **{'history.json':m.encoded(changed_index)})
        altered = m.tar_bytes(changed)
        with self.assertRaises(ValueError): m.verify_any(altered, m.digest(altered), self.first.pin)

    def test_cumulative_object_budget_refuses_without_pruning(self):
        _, index, _ = self.update()
        unique_bytes = sum(index['objects'].values())
        with patch.object(m, 'MAX_TOTAL', unique_bytes - 1):
            with self.assertRaises(ValueError): self.update()
        self.assertEqual(m.MAX_OBJECT, 64 * 1024**2)
        self.assertEqual(m.MAX_TOTAL, 512 * 1024**2)
        self.assertEqual(m.MAX_FILES, 16384)

    def test_standalone_relocation_verifies_both_releases_without_originals(self):
        raw, _, verifier = self.update(); dest = self.root / 'relocated'; dest.mkdir()
        (dest / 'mirror.tar').write_bytes(raw); (dest / 'verify.py').write_bytes(verifier)
        for fixture in (self.first, self.second):
            shutil.rmtree(fixture.root); shutil.rmtree(fixture.retained)
        for pin in (self.first.pin, self.second.pin):
            argv = [sys.executable, '-I', '-B', str(dest / 'verify.py'), 'verify', '--bundle', str(dest / 'mirror.tar'),
                    '--sha256', m.digest(raw), '--release-sha256', pin]
            result = subprocess.run(argv, cwd=dest, env={'PATH':'/usr/bin:/bin'}, capture_output=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(json.loads(result.stdout)['release_sha256'], pin)
        with self.assertRaises(ValueError): m.verify_any(raw, m.digest(raw), 'f' * 64)

    def test_update_cli_fresh_output_and_no_overwrite_or_output_on_refusal(self):
        previous = self.root / 'previous.tar'; previous.write_bytes(self.previous)
        output = self.root / 'output'
        argv = ['update', '--previous-bundle', str(previous), '--previous-sha256', m.digest(self.previous),
            '--previous-release-sha256', self.first.pin, '--release-dir', str(self.second.root),
            '--release-sha256', self.second.pin, '--output', str(output),
            '--retained-inputs', str(self.second.inputs_path), '--inputs-sha256', m.digest(self.second.inputs_raw),
            '--retained-root', str(self.second.retained)]
        def run(arguments):
            captured = io.StringIO()
            with patch.object(m, 'dependencies', return_value=DEPS), redirect_stdout(captured):
                result = m.main(arguments)
            return result, json.loads(captured.getvalue())
        # The implementation's default directory points at the packet, while
        # trusted shared helpers intentionally remain in the checkout.
        actual_update = m.update
        def update_in_checkout(*args, **kwargs):
            kwargs['directory'] = ROOT / 'scripts/release'
            return actual_update(*args, **kwargs)
        with patch.object(m, 'update', side_effect=update_in_checkout):
            code, result = run(argv)
            self.assertEqual(code, 0, result)
            self.assertEqual(result['status'], 'UPDATED_SOURCE_MIRROR')
            before = {path.name:path.read_bytes() for path in output.iterdir()}
            code, result = run(argv)
            self.assertEqual(code, 1); self.assertEqual(result['status'], 'REFUSED')
            self.assertEqual(before, {path.name:path.read_bytes() for path in output.iterdir()})
            previous.write_bytes(self.previous + b'changed')
            refused = list(argv); refused[refused.index('--output') + 1] = str(self.root / 'must-not-exist')
            code, result = run(refused)
            self.assertEqual(code, 1); self.assertEqual(result['status'], 'REFUSED')
            self.assertFalse((self.root / 'must-not-exist').exists())


if __name__ == '__main__':
    unittest.main()

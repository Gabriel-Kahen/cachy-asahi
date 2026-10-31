#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real original recipe round trips; synthetic archive bindings grant no admission."""
import copy
import gzip
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest

HERE = Path(__file__).absolute().parent
REPO = HERE.parents[1]
SPEC = importlib.util.spec_from_file_location('recipe_delivery', HERE / 'recipe_source_delivery.py')
d = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(d)
REVISION = 'ab57e41b60d08e564bc0fe7e9a0c9a9c0706c283'
ORIGINAL_NAMES = ('cachy-asahi-maintenance', 'cachy-asahi-session-diagnostics')
LEGACY_BUNDLES = {
    ('cachy-asahi-maintenance', '0.1.0-1'): 'f84ca37ccee0f00f9fd0bbaace405e0fc71be8b8819755c8d498d19ae96dac5a',
    ('cachy-asahi-session-diagnostics', '0.1.0-2'): '0c504f7c8a479e7d99f7bc4d507adbbe9dc6718dfb7b3377929317a6dac14860',
}


class RecipeDelivery(unittest.TestCase):
    def setUp(self):
        # The original socket ancestry test correctly rejects world-writable
        # /tmp ancestors; relocate beneath this caller-owned test directory.
        self.temp = tempfile.TemporaryDirectory(prefix='original-source-roundtrip-', dir=HERE)
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)

    def recipe(self, name):
        return REPO / 'packages/tools' / name

    def pack(self, name, target='delivery', **options):
        output = self.work / target
        result = d.pack(self.recipe(name), name, REVISION, output, **options)
        return output, result

    def contents(self, name):
        return d.source_set(name, lambda key: d.s.local_read(self.recipe(name), key, d.MAX_FILE))

    def fixture_archive(self, name, *, recipe_version=None, recipe_hash=None, version=None, tamper=False, duplicate=False,
                        extra=False, metadata_link=False):
        if recipe_version is None:
            bodies, info = self.contents(name)
        else:
            _, bodies = self.legacy(name, recipe_version)
            info = d.metadata(bodies['.SRCINFO'])
        p = d.profile(name, recipe_version)
        pkg = dict(pkgname=[name], pkgbase=[name], pkgver=[version or p['version']],
                   arch=['any'], license=['MIT'], depend=info.get('depends', []),
                   optdepend=info.get('optdepends', []))
        build = dict(format=['2'], pkgname=[name], pkgver=pkg['pkgver'], pkgarch=['any'],
                     pkgbuild_sha256sum=[recipe_hash or p['recipe']])
        def metadata(row):
            return ''.join(k + ' = ' + value + '\n' for k, values in row.items() for value in values).encode()
        files = {key: (bodies[source], mode) for key, (source, mode) in d.payload(name, recipe_version).items()}
        files.update({'.PKGINFO': (metadata(pkg), 0o644), '.BUILDINFO': (metadata(build), 0o644),
                      '.MTREE': (b'original synthetic fixture; no native builder ran\n', 0o644)})
        if tamper:
            files['usr/bin/' + name] = (b'changed payload\n', 0o755)
        if extra:
            files['usr/bin/unexpected'] = (b'foreign payload\n', 0o755)
        output = self.work / ('fixture-' + str(len(list(self.work.glob('fixture-*')))) + '.pkg.tar')
        with tarfile.open(output, 'w', format=tarfile.USTAR_FORMAT) as archive:
            for key, (raw, mode) in files.items():
                member = tarfile.TarInfo(key)
                member.size, member.mode = len(raw), mode
                if key == '.MTREE' and metadata_link:
                    member.type, member.linkname, member.size = tarfile.SYMTYPE, '.PKGINFO', 0
                archive.addfile(member, io.BytesIO(raw))
            if duplicate:
                member = tarfile.TarInfo('.BUILDINFO')
                member.size = len(metadata(build))
                archive.addfile(member, io.BytesIO(metadata(build)))
        return output

    def test_real_roundtrip_original_check_and_package_functions_without_checkout(self):
        for name in ORIGINAL_NAMES:
            with self.subTest(name=name):
                delivery, result = self.pack(name, name)
                raw = (delivery / 'source.tar').read_bytes()
                saved, bodies = d.unpacked(raw, result['bundle_sha256'])
                target = self.work / (name + '-relocated')
                d.write_fresh(target, bodies)
                unrelated = self.work / (name + '-cwd')
                unrelated.mkdir()
                stage = self.work / (name + '-stage')
                command = ['bash', '--noprofile', '--norc', '-c',
                           'set -eu; umask 022; source "$1/PKGBUILD"; srcdir=$1; startdir=$1; pkgdir=$2; check; package',
                           'roundtrip', str(target), str(stage)]
                run = subprocess.run(command, cwd=unrelated,
                                     env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'PYTHONPATH': '/nonexistent'},
                                     capture_output=True, timeout=90)
                self.assertEqual(run.returncode, 0, (run.stdout + run.stderr).decode())
                checker = d.profile(name)['checker']
                run = subprocess.run(['python', '-I', '-B', str(target / checker), '--recipe-root', str(target),
                                      '--stage', str(stage)], cwd=unrelated, capture_output=True, timeout=15)
                self.assertEqual(run.returncode, 0, (run.stdout + run.stderr).decode())
                actual = {p.relative_to(stage).as_posix() for p in stage.rglob('*') if p.is_file()}
                self.assertEqual(actual, set(d.payload(name)))
                self.assertEqual(saved['archive_status'], 'UNBOUND_NO_ARCHIVE_SUPPLIED')
                self.assertIsNone(saved['archive_binding'])
                self.assertFalse((delivery / 'source-delivery.json').exists())
                self.assertFalse(list(target.rglob('__pycache__')))
                self.assertFalse(list(stage.rglob('__pycache__')))

    def test_bundle_is_byte_deterministic_and_preserves_all_declared_sources(self):
        for name in ORIGINAL_NAMES:
            with self.subTest(name=name):
                first, one = self.pack(name, name + '-one')
                second, two = self.pack(name, name + '-two')
                self.assertEqual(one, two)
                self.assertEqual({p.name: p.read_bytes() for p in first.iterdir()},
                                 {p.name: p.read_bytes() for p in second.iterdir()})
                saved, bodies = d.unpacked((first / 'source.tar').read_bytes(), one['bundle_sha256'])
                expected, _ = self.contents(name)
                self.assertEqual(bodies, expected)
                self.assertEqual(json.loads((first / 'source-map.json').read_bytes()),
                                 {k: d.s.digest(v) for k, v in expected.items()})
                self.assertEqual(saved['observed_source_revision'], REVISION)

    def test_source_and_recipe_and_srcinfo_tamper_refused(self):
        name = 'cachy-asahi-maintenance'
        source = self.work / 'recipe'
        shutil.copytree(self.recipe(name), source)
        for key in ('PKGBUILD', '.SRCINFO', 'health.py', 'LICENSE'):
            original = (source / key).read_bytes()
            (source / key).write_bytes(original + b'tamper\n')
            with self.subTest(key=key), self.assertRaises(d.s.Error):
                d.pack(source, name, REVISION, self.work / 'refused')
            self.assertFalse((self.work / 'refused').exists())
            (source / key).write_bytes(original)

    def test_symlink_hardlink_and_fifo_input_refused(self):
        name = 'cachy-asahi-session-diagnostics'
        source = self.work / 'recipe'
        shutil.copytree(self.recipe(name), source)
        leaf = source / 'session_probe.py'
        original = leaf.read_bytes()
        for kind in ('symlink', 'hardlink', 'fifo'):
            leaf.unlink()
            if kind == 'symlink':
                leaf.symlink_to(self.recipe(name) / leaf.name)
            elif kind == 'hardlink':
                other = self.work / 'hardlink-body'
                other.write_bytes(original)
                os.link(other, leaf)
            else:
                os.mkfifo(leaf)
            with self.subTest(kind=kind), self.assertRaises((d.s.Error, OSError)):
                d.pack(source, name, REVISION, self.work / 'refused')
            leaf.unlink()
            leaf.write_bytes(original)

    def test_unreviewed_package_revision_and_existing_output_refused(self):
        name = 'cachy-asahi-maintenance'
        with self.assertRaises(d.s.Error):
            d.pack(self.recipe(name), 'other', REVISION, self.work / 'absent')
        with self.assertRaises(d.s.Error):
            d.pack(self.recipe(name), name, 'short', self.work / 'absent')
        target = self.work / 'keep'
        target.mkdir()
        (target / 'sentinel').write_bytes(b'keep')
        with self.assertRaises(FileExistsError):
            self.pack(name, 'keep')
        self.assertEqual(list(target.iterdir()), [target / 'sentinel'])

    def test_bundle_checksum_manifest_payload_extra_and_trailing_bytes_refused(self):
        name = 'cachy-asahi-session-diagnostics'
        output, result = self.pack(name)
        raw = (output / 'source.tar').read_bytes()
        with self.assertRaises(d.s.Error):
            d.unpacked(raw, '0' * 64)
        saved, bodies = d.unpacked(raw, result['bundle_sha256'])
        for kind in ('manifest', 'payload', 'extra', 'trailing'):
            files = dict(bodies)
            changed = copy.deepcopy(saved)
            if kind == 'manifest':
                changed['native_build'] = 'PASS'
            elif kind == 'payload':
                files['session_probe.py'] += b'corruption\n'
            elif kind == 'extra':
                files['foreign'] = b'unlisted\n'
            files['bundle.json'] = d.encoded(changed)
            raw = d.tar_bytes(files) + (b'trailing\n' if kind == 'trailing' else b'')
            with self.subTest(kind=kind), self.assertRaises(d.s.Error):
                d.unpacked(raw, d.s.digest(raw))

    def test_bundle_escaping_symlink_duplicate_and_oversized_members_refused(self):
        for kind in ('escaping', 'symlink', 'duplicate', 'oversized'):
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode='w') as archive:
                member = tarfile.TarInfo('../escape' if kind == 'escaping' else 'leaf')
                member.size = 1
                if kind == 'symlink':
                    member.type, member.linkname, member.size = tarfile.SYMTYPE, '/tmp/escape', 0
                if kind == 'oversized':
                    member.size = d.MAX_FILE + 1
                archive.addfile(member, io.BytesIO(b'x' * member.size))
                if kind == 'duplicate':
                    archive.addfile(member, io.BytesIO(b'x'))
            raw = stream.getvalue()
            with self.subTest(kind=kind), self.assertRaises(d.s.Error):
                d.unpacked(raw, d.s.digest(raw))

    def test_exact_synthetic_archive_binding_existing_transport_export_and_reconstruct(self):
        for name in ORIGINAL_NAMES:
            with self.subTest(name=name):
                archive = self.fixture_archive(name)
                review = self.work / (name + '-review')
                review.write_bytes(b'Existing synthetic fixture review: NOT RUN native, M2 and release.\n')
                output, result = self.pack(name, name, archive=archive, review=review,
                                           review_status='NOT RUN synthetic control', synthetic=True)
                saved = json.loads((output / 'bundle.json').read_bytes())
                self.assertEqual(saved['archive_binding']['archive_sha256'], d.s.digest(archive.read_bytes()))
                self.assertEqual(saved['archive_binding']['native_execution'], 'NOT_ESTABLISHED')
                index = json.loads((output / 'source-delivery.json').read_bytes())
                record = index['packages'][0]
                # Mark the test transport as synthetic. Real input association
                # remains distinct from the actor that built an archive.
                self.assertIs(index['synthetic'], True)
                row = dict(id=name + '-index', path='source-delivery.json',
                           sha256=d.s.digest(d.encoded(index)))
                package = dict(record['package'])
                references = d.s.assemble(output, row, [package], [name], True,
                                         lambda _: {'recipe_sha256': d.profile(name)['recipe']})
                self.assertEqual(len(references), 7)
                refs = {value['id']: value for value in references}
                read = lambda eid, limit: d.s.local_read(output, refs[eid]['path'], limit)
                receipt = d.s.export_package(record, read, self.work / (name + '-export'), 'f' * 64)
                self.assertIs(receipt['legal_acceptance'], False)
                self.assertIs(receipt['source_completeness_accepted'], False)
                exported = self.work / (name + '-export') / record['bundle']['id']
                _, files = d.unpacked(exported.read_bytes(), result['bundle_sha256'])
                self.assertEqual(files, self.contents(name)[0])

    def test_actual_supplied_archive_mismatches_refused_before_output(self):
        name = 'cachy-asahi-maintenance'
        for change in ({'recipe_hash': '0' * 64}, {'version': '0.1.0-unreviewed'}, {'tamper': True},
                       {'extra': True}, {'duplicate': True}, {'metadata_link': True}):
            archive = self.fixture_archive(name, **change)
            with self.subTest(change=change), self.assertRaises((d.s.Error, ValueError)):
                self.pack(name, 'refused', archive=archive)
            self.assertFalse((self.work / 'refused').exists())

    def test_unbound_package_cannot_emit_release_association(self):
        review = self.work / 'review'
        review.write_bytes(b'Existing review, source only.\n')
        with self.assertRaises(d.s.Error):
            self.pack('cachy-asahi-maintenance', review=review, review_status='source only')
        self.assertFalse((self.work / 'delivery').exists())

    def test_cli_pack_unpack_checksum_and_symlink_output_parent_refusal(self):
        name = 'cachy-asahi-session-diagnostics'
        adapter = HERE / 'recipe_source_delivery.py'
        output = self.work / 'cli-delivery'
        command = ['python', '-I', '-B', str(adapter), 'pack', '--recipe', str(self.recipe(name)),
                   '--package', name, '--source-revision', REVISION, '--output', str(output)]
        run = subprocess.run(command, capture_output=True, timeout=10)
        self.assertEqual(run.returncode, 0, run.stderr)
        result = json.loads(run.stdout)
        extract = ['python', '-I', '-B', str(adapter), 'unpack', '--bundle', str(output / 'source.tar'),
                   '--sha256', result['bundle_sha256'], '--output', str(self.work / 'unpacked')]
        run = subprocess.run(extract, capture_output=True, timeout=10)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIs(json.loads(run.stdout)['code_executed'], False)
        self.assertEqual({p.name: p.read_bytes() for p in (self.work / 'unpacked').iterdir()},
                         self.contents(name)[0])
        extract[extract.index('--sha256') + 1] = '0' * 64
        run = subprocess.run(extract, capture_output=True, timeout=10)
        self.assertEqual(run.returncode, 2)
        self.assertIn(b'checksum', run.stderr)
        alias = self.work / 'alias'
        alias.symlink_to(self.work, target_is_directory=True)
        with self.assertRaises(OSError):
            d.write_fresh(alias / 'absent', {'leaf': b'example'})
        self.assertFalse((self.work / 'absent').exists())

    def test_malformed_manifest_and_unlisted_empty_or_missing_source_refused(self):
        name = 'cachy-asahi-session-diagnostics'
        output, result = self.pack(name)
        saved, bodies = d.unpacked((output / 'source.tar').read_bytes(), result['bundle_sha256'])
        for change in ('package_type', 'missing', 'empty', 'binding'):
            files = dict(bodies)
            value = copy.deepcopy(saved)
            if change == 'package_type':
                value['package'] = []
            elif change == 'missing':
                del files['NOTICE']
            elif change == 'empty':
                files['NOTICE'] = b''
            else:
                value['archive_binding'] = {}
            files['bundle.json'] = d.encoded(value)
            raw = d.tar_bytes(files)
            with self.subTest(change=change), self.assertRaises((d.s.Error, KeyError)):
                d.unpacked(raw, d.s.digest(raw))

    def legacy(self, name, version):
        path = HERE / 'fixtures/recipe-source-legacy' / (name + '-' + version + '.tar.gz')
        with gzip.GzipFile(fileobj=io.BytesIO(d.s.read_file(path, d.MAX_FILE))) as stream:
            raw = stream.read(d.MAX_TOTAL + 1)
        return d.unpacked(raw, LEGACY_BUNDLES[name, version])

    def test_retained_legacy_bundles_verify_relocate_and_repack_byte_identically(self):
        for (name, version), checksum in LEGACY_BUNDLES.items():
            with self.subTest(name=name, version=version):
                saved, bodies = self.legacy(name, version)
                self.assertEqual(saved['package']['version'], version)
                self.assertEqual(d.source_profile(name, bodies), d.profile(name, version))
                recipe = self.work / name
                d.write_fresh(recipe, bodies)
                result = d.pack(recipe, name, saved['observed_source_revision'], self.work / (name + '-repacked'))
                self.assertEqual(result['bundle_sha256'], checksum)
                self.assertEqual(result['package']['version'], version)
                self.assertEqual(d.payload(name, version), d.payload(name))

    def test_current_pack_unpack_selects_exact_new_recipe_and_version_without_hooks(self):
        for name in ORIGINAL_NAMES:
            p = d.profile(name)
            with self.subTest(name=name):
                output, result = self.pack(name, name)
                saved, bodies = d.unpacked((output / 'source.tar').read_bytes(), result['bundle_sha256'])
                self.assertEqual(saved['package']['version'], p['version'])
                self.assertEqual(saved['recipe_sha256'], p['recipe'])
                self.assertEqual(d.s.digest(bodies['.SRCINFO']), p['srcinfo'])
                self.assertEqual(d.source_profile(name, bodies), p)

    def test_mixed_old_new_and_unreviewed_recipe_revisions_refused(self):
        for name, version in LEGACY_BUNDLES:
            _, old = self.legacy(name, version)
            current, _ = self.contents(name)
            for key in ('PKGBUILD', '.SRCINFO'):
                mixed = dict(current, **{key: old[key]})
                with self.subTest(name=name, key=key), self.assertRaisesRegex(d.s.Error, 'recipe/SRCINFO changed'):
                    d.source_set(name, mixed.__getitem__)
            unreviewed = dict(current, PKGBUILD=current['PKGBUILD'] + b'\n# unreviewed revision\n')
            with self.assertRaisesRegex(d.s.Error, 'recipe/SRCINFO changed'):
                d.source_set(name, unreviewed.__getitem__)
            with self.assertRaisesRegex(d.s.Error, 'unreviewed recipe version'):
                d.profile(name, '0.1.0-999')

    def test_legacy_manifest_version_or_current_binding_cannot_relabel_old_sources(self):
        for name, version in LEGACY_BUNDLES:
            saved, bodies = self.legacy(name, version)
            wrong = copy.deepcopy(saved)
            wrong['package']['version'] = d.profile(name)['version']
            raw = d.tar_bytes(dict(bodies, **{'bundle.json': d.encoded(wrong)}))
            with self.assertRaisesRegex(d.s.Error, 'manifest mismatch'):
                d.unpacked(raw, d.s.digest(raw))
            binding = dict(status='ARCHIVE_METADATA_AND_PAYLOAD_BOUND', archive_sha256='a' * 64,
                           archive_bytes=1, pkgbuild_sha256=d.profile(name)['recipe'], metadata_sha256='b' * 64,
                           native_execution='NOT_ESTABLISHED')
            with self.assertRaisesRegex(d.s.Error, 'binding recipe mismatch'):
                d.manifest(name, bodies, d.metadata(bodies['.SRCINFO']), saved['observed_source_revision'], binding)

    def test_synthetic_archive_binding_retains_old_new_version_and_recipe_separation(self):
        for name, version in LEGACY_BUNDLES:
            _, old = self.legacy(name, version)
            current, info = self.contents(name)
            archive = self.fixture_archive(name)
            historical = self.fixture_archive(name, recipe_version=version)
            for bodies, metadata, matching, other in (
                (old, d.metadata(old['.SRCINFO']), historical, archive),
                (current, info, archive, historical),
            ):
                with self.subTest(name=name, recipe=d.source_profile(name, bodies)['version']):
                    bound = d.bind_archive(matching, name, bodies, metadata)
                    self.assertEqual(bound['pkgbuild_sha256'], d.s.digest(bodies['PKGBUILD']))
                    self.assertEqual(bound['native_execution'], 'NOT_ESTABLISHED')
                    with self.assertRaisesRegex(d.s.Error, 'identity/dependencies mismatch'):
                        d.bind_archive(other, name, bodies, metadata)


if __name__ == '__main__':
    unittest.main(verbosity=2)

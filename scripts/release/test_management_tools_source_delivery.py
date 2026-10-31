#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite local-source management profiles; no recipe hooks or runtime actors.

Package archives below are synthetic data, never native-build evidence.
"""
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).absolute().parent
REPO = HERE.parents[1]
SPEC = importlib.util.spec_from_file_location('management_delivery', HERE / 'recipe_source_delivery.py')
d = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(d)
REVISION = '89a423cb56f6500b4b81df47e63f0cfdb823b60b'
PROFILES = {
    'cachy-asahi-orphans': ('0.1.0-2', 8, 5),
    'cachy-asahi-cache': ('0.2.0-1', 7, 4),
    'cachy-asahi-repository-runtime': ('0.1.0-1', 11, 8),
}


class ManagementDelivery(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='management-source-', dir=HERE)
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        # Plain source tar/recipe checks must never start any external actor.
        no_actor = patch.object(subprocess, 'Popen', side_effect=AssertionError('unexpected child actor'))
        no_actor.start()
        self.addCleanup(no_actor.stop)

    def recipe(self, name):
        return REPO / 'packages/tools' / name

    def contents(self, name):
        return d.source_set(name, lambda key: d.s.local_read(self.recipe(name), key, d.MAX_FILE))

    def archive(self, name, mutate=None):
        bodies, info = self.contents(name)
        pkg = dict(pkgname=[name], pkgbase=[name], pkgver=[PROFILES[name][0]],
                   arch=['any'], license=['MIT'], depend=info.get('depends', []))
        build = dict(format=['2'], pkgname=[name], pkgver=pkg['pkgver'], pkgarch=['any'],
                     pkgbuild_sha256sum=[d.profile(name)['recipe']])
        files = {path: (bodies[source], mode) for path, (source, mode) in d.payload(name).items()}
        if mutate:
            mutate(pkg, build, files)
        metadata = lambda row: ''.join(k + ' = ' + value + '\n'
                                       for k, values in row.items() for value in values).encode()
        files.update({'.PKGINFO': (metadata(pkg), 0o644), '.BUILDINFO': (metadata(build), 0o644),
                      '.MTREE': (b'SYNTHETIC data only; native build NOT RUN\n', 0o644)})
        path = self.work / 'synthetic.pkg.tar'
        with tarfile.open(path, 'w', format=tarfile.USTAR_FORMAT) as archive:
            for key, (raw, mode) in files.items():
                member = tarfile.TarInfo(key)
                member.size, member.mode = len(raw), mode
                archive.addfile(member, io.BytesIO(raw))
        return path

    def test_real_sources_deterministic_relocation_and_static_recipe_checks(self):
        c = d.module('management_static_checks', HERE.parent / 'checks/package_checks.py')
        for name, (version, source_count, payload_count) in PROFILES.items():
            with self.subTest(name=name):
                one, two = self.work / (name + '-one'), self.work / (name + '-two')
                result = d.pack(self.recipe(name), name, REVISION, one)
                self.assertEqual(result, d.pack(self.recipe(name), name, REVISION, two))
                self.assertEqual({p.name: p.read_bytes() for p in one.iterdir()},
                                 {p.name: p.read_bytes() for p in two.iterdir()})
                saved, bodies = d.unpacked((one / 'source.tar').read_bytes(), result['bundle_sha256'])
                expected, info = self.contents(name)
                self.assertEqual(bodies, expected)
                self.assertEqual(len(bodies), source_count)
                self.assertEqual(set(bodies), {'PKGBUILD', '.SRCINFO', *info['source']})
                self.assertEqual(json.loads((one / 'source-map.json').read_bytes()),
                                 {k: d.s.digest(v) for k, v in bodies.items()})
                relocated = self.work / (name + '-relocated')
                d.write_fresh(relocated, bodies)
                report = c.recipe(relocated / 'PKGBUILD')
                self.assertEqual(report['errors'], [])
                self.assertEqual(report['status'], 'static-pass')
                self.assertEqual(saved['package'], dict(name=name, version=version, arch='any'))
                self.assertEqual(len(d.payload(name)), payload_count)
                self.assertEqual(saved['dependencies']['depends'], info['depends'])
                self.assertEqual(saved['archive_status'], 'UNBOUND_NO_ARCHIVE_SUPPLIED')
                self.assertIsNone(saved['archive_binding'])
                self.assertFalse((one / 'source-delivery.json').exists())
                self.assertEqual(saved['native_build'], 'NOT_RUN')
                self.assertEqual(saved['alpm_installation'], 'NOT_RUN')
                self.assertEqual(saved['physical_m2'], 'NOT_RUN')
                self.assertFalse(saved['legal_acceptance'])

    def test_literal_recipe_srcinfo_and_exact_host_command_policy(self):
        for name in PROFILES:
            bodies, info = self.contents(name)
            literal = {}
            for match in re.finditer(r'^([a-z][a-z0-9_]*)=(\([^)]*\)|[^\n]+)',
                                     bodies['PKGBUILD'].decode(), re.M):
                key, value = match.groups()
                self.assertNotIn('$', value)
                self.assertNotIn('`', value)
                literal[key] = shlex.split(value[1:-1] if value.startswith('(') else value, comments=True)
            self.assertEqual(info['pkgbase'], [name])
            for key in ('pkgname', 'pkgver', 'pkgrel', 'pkgdesc', 'url', 'epoch', 'arch', 'license',
                        'depends', 'makedepends', 'checkdepends', 'optdepends', 'provides', 'conflicts',
                        'replaces', 'backup', 'install', 'source', 'sha256sums'):
                self.assertEqual(info.get(key, []), literal.get(key, []), (name, key))
            saved = d.manifest(name, bodies, info, REVISION, None)
            commands = [['python', '-I', '-B', 'check_source.py', '--recipe-root', '.']] if name.endswith('runtime') else [
                ['python', '-I', '-B', name, '--help']]
            self.assertEqual(saved['host_check_commands'], commands)

    def test_cache_and_orphans_payload_match_pinned_literal_install_statements(self):
        for name in ('cachy-asahi-cache', 'cachy-asahi-orphans'):
            bodies, _ = self.contents(name)
            actual = {}
            for line in bodies['PKGBUILD'].decode().splitlines():
                if line.strip().startswith('install -Dm'):
                    _, mode, source, dest = shlex.split(line)
                    self.assertTrue(source.startswith('$srcdir/'))
                    self.assertTrue(dest.startswith('$pkgdir/'))
                    actual[dest.removeprefix('$pkgdir/').replace('$pkgname', name)] = (
                        source.removeprefix('$srcdir/'), int(mode.removeprefix('-Dm'), 8))
            self.assertEqual(actual, d.payload(name))
        self.assertEqual(d.payload('cachy-asahi-orphans')[
            'usr/share/cachy-asahi-orphans/protection-floor.json'], ('protection-floor.json', 0o644))

    def test_runtime_helper_pins_provenance_and_loop_defined_payload(self):
        name = 'cachy-asahi-repository-runtime'
        bodies, _ = self.contents(name)
        pins = json.loads(bodies['helper-pins.json'])['files']
        provenance = json.loads(bodies['source-provenance.json'])
        self.assertEqual(pins, provenance['helpers'])
        self.assertEqual(sum(row['bytes'] for row in pins.values()), 86445)
        self.assertEqual(provenance['helper_files'], 3)
        self.assertEqual(provenance['helper_bytes'], 86445)
        self.assertEqual(provenance['version'], PROFILES[name][0])
        self.assertEqual(set(pins), {'scripts/client/client.py', 'scripts/release/release.py',
                                     'scripts/release/source_delivery.py'})
        recipe = bodies['PKGBUILD'].decode()
        self.assertIn('local base="$pkgdir/usr/share/cachy-asahi/repository-runtime"', recipe)
        actual = {}
        for path, row in pins.items():
            leaf = Path(path).name
            self.assertEqual(row, dict(bytes=len(bodies[leaf]), sha256=d.s.digest(bodies[leaf])))
            self.assertEqual(provenance['original_source_paths'][leaf], path)
            self.assertIn(f'install -Dm644 "$srcdir/{leaf}" "$base/{path}" || return', recipe)
            actual['usr/share/cachy-asahi/repository-runtime/' + path] = (leaf, 0o644)
        for names, folder in (('README.md source-provenance.json helper-pins.json', 'doc'),
                              ('NOTICE LICENSE', 'licenses')):
            self.assertIn(f'for file in {names}; do', recipe)
            self.assertIn(f'install -Dm644 "$srcdir/$file" "$pkgdir/usr/share/{folder}/$pkgname/$file" || return', recipe)
            actual.update({'usr/share/' + folder + '/' + name + '/' + leaf: (leaf, 0o644)
                           for leaf in names.split()})
        self.assertEqual(actual, d.payload(name))
        self.assertFalse(any(path.startswith('usr/bin/') for path in actual))

    def test_every_recipe_source_and_metadata_tamper_refused_before_publication(self):
        for name in PROFILES:
            bodies, _ = self.contents(name)
            source = self.work / name
            d.write_fresh(source, bodies)
            for key, raw in bodies.items():
                with self.subTest(name=name, key=key):
                    (source / key).write_bytes(raw + b'changed\n')
                    with self.assertRaises(d.s.Error):
                        d.pack(source, name, REVISION, self.work / 'refused')
                    self.assertFalse((self.work / 'refused').exists())
                    (source / key).write_bytes(raw)
            with self.assertRaisesRegex(d.s.Error, 'unreviewed recipe version'):
                d.profile(name, '0.0.0-999')

    def test_unsafe_input_nodes_refused_for_all_three_profiles(self):
        for name in PROFILES:
            bodies, info = self.contents(name)
            source = self.work / name
            d.write_fresh(source, bodies)
            leaf = source / info['source'][0]
            for kind in ('symlink', 'hardlink', 'fifo'):
                leaf.unlink()
                if kind == 'symlink':
                    leaf.symlink_to(self.recipe(name) / leaf.name)
                elif kind == 'hardlink':
                    donor = self.work / (name + '-donor')
                    donor.write_bytes(bodies[leaf.name])
                    os.link(donor, leaf)
                else:
                    os.mkfifo(leaf)
                with self.subTest(name=name, kind=kind), self.assertRaises((d.s.Error, OSError)):
                    d.pack(source, name, REVISION, self.work / 'refused')
                self.assertFalse((self.work / 'refused').exists())
                leaf.unlink()
                leaf.write_bytes(bodies[leaf.name])

    def test_bundle_checksum_manifest_extra_and_trailing_tamper_refused(self):
        for name in PROFILES:
            bodies, info = self.contents(name)
            saved = d.manifest(name, bodies, info, REVISION, None)
            original = d.tar_bytes(dict(bodies, **{'bundle.json': d.encoded(saved)}))
            with self.subTest(name=name), self.assertRaises(d.s.Error):
                d.unpacked(original, '0' * 64)
            for kind in ('manifest', 'source', 'extra', 'trailing'):
                files, changed = dict(bodies), copy.deepcopy(saved)
                if kind == 'manifest':
                    changed['package']['version'] = '999.0-1'
                elif kind == 'source':
                    files[info['source'][0]] += b'tampered\n'
                elif kind == 'extra':
                    files['foreign'] = b'unlisted\n'
                files['bundle.json'] = d.encoded(changed)
                raw = d.tar_bytes(files) + (b'trailing\n' if kind == 'trailing' else b'')
                with self.subTest(name=name, kind=kind), self.assertRaises(d.s.Error):
                    d.unpacked(raw, d.s.digest(raw))

    def test_synthetic_archive_binding_and_existing_transport_roundtrip(self):
        for name in PROFILES:
            archive = self.archive(name)
            review = self.work / 'review'
            review.write_bytes(b'SYNTHETIC data; native/ALPM/M2/release NOT RUN\n')
            output = self.work / name
            result = d.pack(self.recipe(name), name, REVISION, output, archive=archive,
                            review=review, review_status='SYNTHETIC source association only', synthetic=True)
            saved, bodies = d.unpacked((output / 'source.tar').read_bytes(), result['bundle_sha256'])
            self.assertEqual(saved['archive_binding']['archive_sha256'], d.s.digest(archive.read_bytes()))
            self.assertEqual(saved['archive_binding']['native_execution'], 'NOT_ESTABLISHED')
            index = d.s.decode((output / 'source-delivery.json').read_bytes())
            self.assertIs(index['synthetic'], True)
            record = index['packages'][0]
            row = dict(id=name + '-index', path='source-delivery.json', sha256=d.s.digest(d.encoded(index)))
            refs = d.s.assemble(output, row, [record['package']], [name], True,
                                lambda _: {'recipe_sha256': d.profile(name)['recipe']})
            refs = {r['id']: r for r in refs}
            read = lambda eid, limit: d.s.local_read(output, refs[eid]['path'], limit)
            exported = self.work / (name + '-export')
            receipt = d.s.export_package(record, read, exported, 'f' * 64)
            self.assertFalse(receipt['source_completeness_accepted'])
            self.assertFalse(receipt['legal_acceptance'])
            _, actual = d.unpacked((exported / record['bundle']['id']).read_bytes(), result['bundle_sha256'])
            self.assertEqual(actual, bodies)

    def test_each_synthetic_payload_file_bytes_mode_and_coverage_mismatch_refused(self):
        for name in PROFILES:
            bodies, info = self.contents(name)
            for path in d.payload(name):
                for kind in ('bytes', 'mode', 'missing'):
                    def mutate(pkg, build, files):
                        raw, mode = files[path]
                        if kind == 'bytes':
                            files[path] = (raw + b'changed\n', mode)
                        elif kind == 'mode':
                            files[path] = (raw, 0o600)
                        else:
                            del files[path]
                    with self.subTest(name=name, path=path, kind=kind), self.assertRaises((d.s.Error, ValueError)):
                        d.bind_archive(self.archive(name, mutate), name, bodies, info)
            extra = lambda pkg, build, files: files.update({'usr/bin/unreviewed': (b'extra\n', 0o755)})
            with self.subTest(name=name, kind='extra'), self.assertRaises((d.s.Error, ValueError)):
                d.bind_archive(self.archive(name, extra), name, bodies, info)

    def test_synthetic_archive_metadata_mismatch_and_unbound_association_refused(self):
        changes = [('pkg', 'pkgname', ['other']), ('pkg', 'pkgbase', ['other']),
                   ('pkg', 'pkgver', ['0.0.0-1']), ('pkg', 'arch', ['aarch64']),
                   ('pkg', 'license', ['GPL-3.0-only']), ('pkg', 'depend', []),
                   ('pkg', 'optdepend', ['foreign: description']), ('pkg', 'conflict', ['foreign']),
                   ('build', 'pkgname', ['other']), ('build', 'pkgver', ['other']),
                   ('build', 'pkgarch', ['aarch64']), ('build', 'pkgbuild_sha256sum', ['0' * 64])]
        for name in PROFILES:
            bodies, info = self.contents(name)
            for row, key, values in changes:
                def mutate(pkg, build, files):
                    (pkg if row == 'pkg' else build)[key] = values
                with self.subTest(name=name, row=row, key=key), self.assertRaises((d.s.Error, ValueError)):
                    d.bind_archive(self.archive(name, mutate), name, bodies, info)
            review = self.work / 'review'
            review.write_bytes(b'Source only; no archive supplied\n')
            with self.assertRaises(d.s.Error):
                d.pack(self.recipe(name), name, REVISION, self.work / 'refused',
                       review=review, review_status='source only')
            self.assertFalse((self.work / 'refused').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite expanded tools, exact version selection and synthetic associations.

Never source a PKGBUILD or execute its prepare/check/package hooks on the host.
"""
import copy
import importlib.util
import io
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import unittest

HERE = Path(__file__).absolute().parent
REPO = HERE.parents[1]
SPEC = importlib.util.spec_from_file_location('expanded_delivery', HERE / 'recipe_source_delivery.py')
d = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(d)
REVISION = '49771edfc7a9def473b875c59242abd3a25d4177'
NAMES = ('cachy-asahi-setup', 'cachy-asahi-mirrors', 'cachy-asahi-doctor')


class Expansion(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='source-expansion-', dir=HERE)
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)

    def recipe(self, name, version=None):
        if name == 'cachy-asahi-setup':
            if version == '0.1.0-7':
                return REPO / 'packages/settings/cachy-asahi-setup'
            return REPO / 'packages/tools/cachy-asahi-setup8'
        return REPO / 'packages/tools' / name

    def contents(self, name, version=None):
        return d.source_set(name, lambda key: d.s.local_read(self.recipe(name, version), key, d.MAX_FILE))

    def archive(self, name, mutate=None, recipe_version=None):
        bodies, info = self.contents(name, recipe_version)
        pkg = dict(pkgname=[name], pkgbase=[name], pkgver=[d.profile(name, recipe_version)['version']],
                   arch=['any'], license=['MIT'], depend=info.get('depends', []),
                   optdepend=info.get('optdepends', []))
        build = dict(format=['2'], pkgname=[name], pkgver=pkg['pkgver'], pkgarch=['any'],
                     pkgbuild_sha256sum=[d.profile(name, recipe_version)['recipe']])
        files = {path: (bodies[source], mode) for path, (source, mode) in d.payload(name, recipe_version).items()}
        if mutate:
            mutate(pkg, build, files)
        metadata = lambda row: ''.join(k + ' = ' + v + '\n' for k, vs in row.items() for v in vs).encode()
        files.update({'.PKGINFO': (metadata(pkg), 0o644), '.BUILDINFO': (metadata(build), 0o644),
                      '.MTREE': (b'SYNTHETIC archive fixture, no native builder\n', 0o644)})
        path = self.work / 'synthetic.pkg.tar'
        with tarfile.open(path, 'w', format=tarfile.USTAR_FORMAT) as archive:
            for key, (raw, mode) in files.items():
                member = tarfile.TarInfo(key)
                member.size, member.mode = len(raw), mode
                archive.addfile(member, io.BytesIO(raw))
        return path

    def test_all_sources_deterministic_relocation_and_static_recipe_checks(self):
        c = d.module('expansion_static_checks', HERE.parent / 'checks/package_checks.py')
        for name in NAMES:
            with self.subTest(name=name):
                one, two = self.work / (name + '-one'), self.work / (name + '-two')
                result = d.pack(self.recipe(name), name, REVISION, one)
                self.assertEqual(result, d.pack(self.recipe(name), name, REVISION, two))
                self.assertEqual({p.name: p.read_bytes() for p in one.iterdir()},
                                 {p.name: p.read_bytes() for p in two.iterdir()})
                raw = (one / 'source.tar').read_bytes()
                saved, bodies = d.unpacked(raw, result['bundle_sha256'])
                expected, info = self.contents(name)
                self.assertEqual(bodies, expected)
                self.assertEqual(set(bodies), {'PKGBUILD', '.SRCINFO', *info['source']})
                self.assertEqual(json.loads((one / 'source-map.json').read_bytes()),
                                 {k: d.s.digest(v) for k, v in bodies.items()})
                relocated = self.work / (name + '-relocated')
                d.write_fresh(relocated, bodies)
                report = c.recipe(relocated / 'PKGBUILD')
                self.assertEqual(report['errors'], [])
                self.assertEqual(report['status'], 'static-pass')
                self.assertEqual(saved['package']['version'], d.profile(name)['version'])
                self.assertEqual(saved['dependencies']['depends'], info['depends'])
                self.assertEqual(saved['archive_status'], 'UNBOUND_NO_ARCHIVE_SUPPLIED')
                self.assertIsNone(saved['archive_binding'])
                self.assertFalse((one / 'source-delivery.json').exists())
                self.assertEqual(saved['native_build'], 'NOT_RUN')
                self.assertFalse(saved['legal_acceptance'])

    def test_original_python_checks_run_after_relocation_without_recipe_hooks(self):
        for name in NAMES:
            with self.subTest(name=name):
                bodies, _ = self.contents(name)
                target = self.work / name
                d.write_fresh(target, bodies)
                home, temp = self.work / 'private-home', self.work / 'private-tmp'
                home.mkdir(exist_ok=True); temp.mkdir(exist_ok=True)
                env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'HOME': str(home), 'TMPDIR': str(temp),
                       'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONPATH': '',
                       'XDG_CONFIG_HOME': str(home / 'config'), 'XDG_CACHE_HOME': str(home / 'cache'),
                       'XDG_DATA_HOME': str(home / 'data')}
                for command in d.profile(name)['checks']:
                    run = subprocess.run(command, cwd=target, env=env, capture_output=True, timeout=60)
                    self.assertEqual(run.returncode, 0, (command, (run.stdout + run.stderr).decode()))
                self.assertEqual({p.name: p.read_bytes() for p in target.iterdir()}, bodies)

    def test_recipe_specific_payload_matches_actual_literal_install_lines(self):
        for name in NAMES:
            with self.subTest(name=name):
                bodies, _ = self.contents(name)
                actual = {}
                # Read these pinned install statements as data. No shell actor runs.
                for line in bodies['PKGBUILD'].decode().splitlines():
                    if line.strip().startswith('install -Dm'):
                        _, mode, source, dest = shlex.split(line)
                        self.assertTrue(source.startswith('$srcdir/'))
                        self.assertTrue(dest.startswith('$pkgdir/'))
                        actual[dest.removeprefix('$pkgdir/').replace('$pkgname', name)] = (
                            source.removeprefix('$srcdir/'), int(mode.removeprefix('-Dm'), 8))
                self.assertEqual(actual, d.payload(name))
                self.assertEqual(len(actual), 10 if name.endswith('setup') else 4)

    def test_srcinfo_exactly_matches_literal_recipe_metadata(self):
        for name in NAMES:
            with self.subTest(name=name):
                bodies, info = self.contents(name)
                literal = {}
                for match in re.finditer(r'^([a-z][a-z0-9_]*)=(\([^)]*\)|[^\n]+)',
                                         bodies['PKGBUILD'].decode(), re.M):
                    key, value = match.groups()
                    self.assertNotIn('$', value)
                    self.assertNotIn('`', value)
                    literal[key] = shlex.split(value[1:-1] if value.startswith('(') else value,
                                              comments=True)
                self.assertEqual(info['pkgbase'], [name])
                for key in ('pkgname', 'pkgver', 'pkgrel', 'pkgdesc', 'url', 'epoch', 'arch', 'license',
                            'depends', 'makedepends', 'checkdepends', 'optdepends', 'provides',
                            'conflicts', 'replaces', 'backup', 'install', 'source', 'sha256sums'):
                    self.assertEqual(info.get(key, []), literal.get(key, []), key)

    def test_every_declared_source_recipe_and_srcinfo_tamper_refused(self):
        for name in NAMES:
            source = self.work / name
            shutil.copytree(self.recipe(name), source)
            bodies, _ = self.contents(name)
            for key, original in bodies.items():
                with self.subTest(name=name, key=key):
                    (source / key).write_bytes(original + b'changed\n')
                    with self.assertRaises(d.s.Error):
                        d.pack(source, name, REVISION, self.work / 'refused')
                    self.assertFalse((self.work / 'refused').exists())
                    (source / key).write_bytes(original)

    def test_each_synthetic_archive_binds_exact_metadata_payload_and_transport(self):
        for name in NAMES:
            with self.subTest(name=name):
                archive = self.archive(name)
                review = self.work / 'review'
                review.write_bytes(b'SYNTHETIC fixture; native/M2/release NOT RUN\n')
                output = self.work / name
                result = d.pack(self.recipe(name), name, REVISION, output, archive=archive,
                                review=review, review_status='SYNTHETIC source association only', synthetic=True)
                saved, bodies = d.unpacked((output / 'source.tar').read_bytes(), result['bundle_sha256'])
                self.assertEqual(saved['archive_binding']['archive_sha256'], d.s.digest(archive.read_bytes()))
                self.assertEqual(saved['archive_binding']['native_execution'], 'NOT_ESTABLISHED')
                index = d.s.decode((output / 'source-delivery.json').read_bytes())
                self.assertIs(index['synthetic'], True)
                row = dict(id=name + '-index', path='source-delivery.json', sha256=d.s.digest(d.encoded(index)))
                record = index['packages'][0]
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

    def test_each_archive_identity_dependency_build_and_payload_mismatch_refuses(self):
        def replace(row, key, values):
            return lambda pkg, build, files: (pkg if row == 'pkg' else build).__setitem__(key, values)
        changes = [replace('pkg', 'pkgver', ['0.0.0-1']), replace('pkg', 'pkgbase', ['other']),
                   replace('pkg', 'arch', ['aarch64']), replace('pkg', 'license', ['GPL-3.0-only']),
                   replace('pkg', 'depend', []), replace('pkg', 'optdepend', ['unreviewed: extra']),
                   replace('pkg', 'conflict', ['unreviewed']), replace('build', 'pkgname', ['other']),
                   replace('build', 'pkgver', ['other']), replace('build', 'pkgarch', ['aarch64']),
                   replace('build', 'pkgbuild_sha256sum', ['0' * 64]),
                   lambda p, b, f: f.update({'usr/bin/extra': (b'extra\n', 0o755)})]
        for name in NAMES:
            path = 'usr/bin/' + name
            for change in changes + [lambda p, b, f: f.__setitem__(path, (b'wrong\n', 0o755)),
                                     lambda p, b, f: f.__setitem__(path, (f[path][0], 0o644)),
                                     lambda p, b, f: f.pop(path)]:
                with self.subTest(name=name, change=change):
                    archive = self.archive(name, change)
                    with self.assertRaises((d.s.Error, ValueError)):
                        d.pack(self.recipe(name), name, REVISION, self.work / 'refused', archive=archive)
                    self.assertFalse((self.work / 'refused').exists())

    def test_unbound_cannot_emit_association_or_claim_native(self):
        for name in NAMES:
            with self.subTest(name=name):
                review = self.work / 'review'
                review.write_bytes(b'only source review\n')
                with self.assertRaises(d.s.Error):
                    d.pack(self.recipe(name), name, REVISION, self.work / 'refused',
                           review=review, review_status='source only')
                self.assertFalse((self.work / 'refused').exists())
                bodies, info = self.contents(name)
                saved = d.manifest(name, bodies, info, REVISION, None)
                changed = copy.deepcopy(saved); changed['native_build'] = 'PASS'
                raw = d.tar_bytes(dict(bodies, **{'bundle.json': d.encoded(changed)}))
                with self.assertRaises(d.s.Error):
                    d.unpacked(raw, d.s.digest(raw))

    def test_explicit_setup8_and_retained_setup7_select_by_exact_pairs(self):
        name = 'cachy-asahi-setup'
        current, _ = self.contents(name)
        old, old_info = self.contents(name, '0.1.0-7')
        self.assertEqual((len(current), len(old)), (20, 11))
        self.assertEqual(d.source_profile(name, current), d.profile(name, '0.3.0-1'))
        self.assertEqual(d.source_profile(name, old), d.profile(name, '0.1.0-7'))
        self.assertEqual((len(d.payload(name, '0.3.0-1')), len(d.payload(name, '0.1.0-7'))), (10, 6))
        target = self.work / 'retained-setup7'
        result = d.pack(self.recipe(name, '0.1.0-7'), name,
                        'dc01063ab4fd2d8c36a1e4c453811ffa8c27bb06', target)
        self.assertEqual(result['bundle_sha256'],
                         'de14f6f70187dae2f9c7ef706803fb5266a6986d11e2fd091c6842c71db1996f')
        self.assertEqual(result['package']['version'], '0.1.0-7')
        self.assertEqual(d.manifest(name, old, old_info, REVISION, None)['package']['version'], '0.1.0-7')
        for leaf in ('PKGBUILD', '.SRCINFO'):
            mixed = dict(current, **{leaf: old[leaf]})
            with self.subTest(leaf=leaf), self.assertRaisesRegex(d.s.Error, 'recipe/SRCINFO changed'):
                d.source_set(name, mixed.__getitem__)
        for package in NAMES:
            with self.subTest(package=package), self.assertRaisesRegex(d.s.Error, 'unreviewed recipe version'):
                d.profile(package, '0.1.0-999')
        with self.assertRaises(d.s.Error):
            d.profile('cachy-asahi-setup8')

    def test_setup_archive_binding_does_not_transfer_across_versions(self):
        name = 'cachy-asahi-setup'
        # Snapshot the current synthetic archive before the helper reuses its path.
        current_archive = self.archive(name)
        current_copy = self.work / 'current.pkg.tar'
        current_copy.write_bytes(current_archive.read_bytes())
        old_archive = self.archive(name, recipe_version='0.1.0-7')
        for version, matching, other in (('0.3.0-1', current_copy, old_archive),
                                         ('0.1.0-7', old_archive, current_copy)):
            bodies, info = self.contents(name, version)
            with self.subTest(version=version):
                bound = d.bind_archive(matching, name, bodies, info)
                self.assertEqual(bound['pkgbuild_sha256'], d.profile(name, version)['recipe'])
                self.assertEqual(bound['native_execution'], 'NOT_ESTABLISHED')
                with self.assertRaisesRegex(d.s.Error, 'identity/dependencies mismatch'):
                    d.bind_archive(other, name, bodies, info)


if __name__ == '__main__':
    unittest.main(verbosity=2)

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Mirror build inputs stay data; package archives are synthetic host fixtures."""
import copy
import gzip
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).absolute().parent
ROOT = next(p for p in HERE.parents if (p / 'scripts/build/source_materials.py').is_file())
FROZEN = ROOT / 'artifacts/development/release-source-mirror-incremental-development-20261027/proposed/scripts/release'
RELEASE_TESTS = ROOT / 'scripts/release'
FIXTURES = RELEASE_TESTS if (RELEASE_TESTS / 'test_release_source_mirror_incremental.py').is_file() else FROZEN


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


f = module('consumer_original_fixtures', FIXTURES / 'test_release_source_mirror.py')
incremental = module('consumer_successor_fixtures', FIXTURES / 'test_release_source_mirror_incremental.py')
c = module('mirror_consumer_under_test', HERE / 'mirror_consumer.py')
DEPS = c.dependencies(ROOT / 'scripts/build')
DEPS['mirror'] = incremental.m  # Explicit trusted pending-successor dependency.
m = incremental.m


class OriginalConsumerFixture(f.ReleaseFixture):
    """Exact reviewed current/legacy source bytes with synthetic archive evidence."""
    def __init__(self, root, legacy=False, name='cachy-asahi-maintenance'):
        super().__init__(root, names=(name,)); self.name = name
        if not legacy:
            return
        version = {'cachy-asahi-maintenance':'0.1.0-1', 'cachy-asahi-session-diagnostics':'0.1.0-2'}[name]
        source = ROOT / 'scripts/release/fixtures/recipe-source-legacy' / (name + '-' + version + '.tar.gz')
        with gzip.GzipFile(fileobj=io.BytesIO(source.read_bytes())) as stream:
            raw = stream.read(f.recipe.MAX_TOTAL + 1)
        saved, bodies = f.recipe.unpacked(raw, m.digest(raw))
        self.bodies[name] = bodies
        package = self.package(name); package['version'] = version
        package['filename'] = name + '-' + version + '-any.pkg.tar.gz'
        provenance = self.provenance[name]
        provenance['package']['version'] = version; provenance['recipe_sha256'] = m.digest(bodies['PKGBUILD'])
        provenance['sources'][0]['sha256'] = m.digest(bodies['PKGBUILD'])
        self.archive_rows[name] = {key:(bodies[source], mode)
                                  for key,(source,mode) in f.recipe.payload(name, version).items()}
        self.archive_rows[name].update({
            '.PKGINFO':(f.metadata(dict(pkgname=[name], pkgbase=[name], pkgver=[version], arch=['any'], license=['MIT'])), 0o644),
            '.BUILDINFO':(f.metadata(dict(format=['2'], pkgname=[name], pkgver=[version], pkgarch=['any'],
                pkgbuild_sha256sum=[m.digest(bodies['PKGBUILD'])], installed=['python-3.14-1-aarch64'])), 0o644),
            '.MTREE':(b'Synthetic legacy package archive; no native execution.\n', 0o644)})
        self.refresh_archive(name); self.refresh_source(name); self.refresh()


def selectors(fixture, name=None):
    name = name or fixture.name
    package = fixture.package(name); bodies = fixture.bodies[name]
    return (fixture.pin, name, package['version'], package['arch'], package['sha256'],
            m.digest(bodies['PKGBUILD']), m.digest(bodies['.SRCINFO']))


def prepare_fixture(fixture, raw=None, name=None, deps=DEPS):
    if raw is None:
        raw = fixture.build()[0]
    return c.prepare(raw, m.digest(raw), *selectors(fixture, name), deps)


class ConsumerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='mirror-consumer-')
        self.addCleanup(self.temp.cleanup); self.root = Path(self.temp.name)
        self.original = OriginalConsumerFixture(self.root / 'original')

    def materialized(self, fixture=None, leaf='context'):
        fixture = fixture or self.original
        prepared = prepare_fixture(fixture)
        output = self.root / leaf
        receipt = c.materialize(prepared, output, DEPS)
        return fixture, prepared, output, receipt

    def test_exact_current_original_sources_materialize_for_static_build_v2(self):
        fixture, prepared, output, receipt = self.materialized()
        actual = {p.relative_to(output / 'recipe').as_posix():p.read_bytes()
                  for p in (output / 'recipe').rglob('*') if p.is_file()}
        self.assertEqual(actual, fixture.bodies[fixture.name])
        self.assertFalse((output / 'recipe/bundle.json').exists())
        report = DEPS['build'].recipe(output / 'recipe/PKGBUILD')
        self.assertEqual(report['errors'], [])
        self.assertEqual(json.loads((output / 'reviewed-inputs.json').read_bytes()), report['input_sha256'])
        self.assertEqual(report['input_sha256']['PKGBUILD'], m.digest(fixture.bodies[fixture.name]['PKGBUILD']))
        self.assertTrue(c.verify_context(output, receipt['selection_sha256'], DEPS))
        self.assertEqual(os.stat(output).st_mode & 0o777, 0o700)
        self.assertTrue(all(os.stat(p).st_mode & 0o077 == 0 for p in output.rglob('*')))

    def test_real_legacy_source_recipe_pair_and_buildinfo_identity_preserved(self):
        fixture = OriginalConsumerFixture(self.root / 'legacy', legacy=True)
        _, prepared, output, receipt = self.materialized(fixture, 'legacy-context')
        actual = {p.relative_to(output / 'recipe').as_posix():p.read_bytes()
                  for p in (output / 'recipe').rglob('*') if p.is_file()}
        self.assertEqual(actual, fixture.bodies[fixture.name])
        selected = f.recipe.source_profile(fixture.name, actual)
        self.assertEqual(selected['version'], '0.1.0-1')
        self.assertEqual(selected['recipe'], m.digest(actual['PKGBUILD']))
        buildinfo = (output / 'evidence/BUILDINFO').read_bytes()
        self.assertIn(('pkgbuild_sha256sum = ' + selected['recipe']).encode(), buildinfo)
        self.assertIn(b'pkgver = 0.1.0-1', buildinfo)
        self.assertTrue(c.verify_context(output, receipt['selection_sha256'], DEPS))

    def test_exact_selectors_refuse_wrong_package_version_arch_archive_recipe_srcinfo(self):
        raw = self.original.build()[0]; args = list(selectors(self.original))
        for index, value in ((0, 'f' * 64), (1, 'not-retained'), (2, '99-1'), (3, 'aarch64'),
                             (4, 'a' * 64), (5, 'b' * 64), (6, 'c' * 64)):
            changed = list(args); changed[index] = value
            with self.subTest(selector=index), self.assertRaises((ValueError, KeyError)):
                c.prepare(raw, m.digest(raw), *changed, DEPS)
        with self.assertRaises(ValueError):
            c.prepare(raw, '0' * 64, *args, DEPS)

    def test_relocation_needs_no_original_mirror_or_recipe_directory(self):
        fixture, prepared, output, receipt = self.materialized()
        moved = self.root / 'relocated'; shutil.copytree(output, moved)
        shutil.rmtree(fixture.root)
        self.assertTrue(c.verify_context(moved, receipt['selection_sha256'], DEPS))
        self.assertEqual((moved / 'recipe/PKGBUILD').read_bytes(), prepared['bodies']['recipe/PKGBUILD'])

    def test_native_request_is_concrete_inputs_with_null_actual_selectors(self):
        _, prepared, output, receipt = self.materialized()
        request = json.loads((output / 'builder-request.json').read_bytes())
        self.assertEqual(request, prepared['native_request'])
        self.assertTrue(request['actual_selectors'])
        self.assertTrue(all(value is None for value in request['actual_selectors'].values()))
        text = json.dumps(request)
        self.assertIn('build_v2.py', text)
        self.assertIn('--network', text); self.assertIn('none', text)
        self.assertIn('--mode', text); self.assertIn('native', text)
        for key in ('actual_archive_sha256', 'actual_archive_bytes', 'actual_buildinfo_sha256'):
            self.assertIsNone(request[key])
        self.assertEqual(request['build_tool_sha256'], m.digest((ROOT / 'scripts/build/build_v2.py').read_bytes()))
        self.assertEqual(request['entry_script_sha256'], m.digest((ROOT / 'scripts/build/container-entry-v2.sh').read_bytes()))

    def test_current_canonical_single_release_verifier_is_usable(self):
        deps = c.dependencies(ROOT / 'scripts/build')
        prepared = prepare_fixture(self.original, deps=deps)
        output = self.root / 'canonical-context'; receipt = c.materialize(prepared, output, deps)
        self.assertTrue(c.verify_context(output, receipt['selection_sha256'], deps))

    def test_context_selection_pin_is_required(self):
        _, _, output, receipt = self.materialized()
        with self.assertRaisesRegex(ValueError, 'selection checksum'):
            c.verify_context(output, '0' * 64, DEPS)

    def test_rehashed_mirror_source_license_and_ambiguous_package_refused(self):
        raw, manifest, _ = self.original.build()
        original = incremental.members(raw)
        for kind in ('source-profile', 'license-object', 'ambiguous-package'):
            files = dict(original); changed = copy.deepcopy(manifest)
            if kind == 'source-profile':
                changed['packages'][0]['source_files']['PKGBUILD'] = changed['packages'][0]['source_files']['LICENSE']
            elif kind == 'license-object':
                path = 'objects/' + m.digest(self.original.bodies[self.original.name]['LICENSE'])
                files[path] += b'altered license'
            else:
                changed['packages'].append(copy.deepcopy(changed['packages'][0]))
            files['mirror.json'] = m.encoded(changed); altered = m.tar_bytes(files)
            with self.subTest(kind=kind), self.assertRaises((ValueError, KeyError)):
                prepare_fixture(self.original, altered)

    def test_frozen_current_and_legacy_profiles_and_helpers_unchanged(self):
        paths = [ROOT / 'scripts/release' / name for name in
                 ('release_source_mirror.py', 'recipe_source_delivery.py', 'source_delivery.py')]
        before = {path:path.read_bytes() for path in paths}
        profiles = copy.deepcopy(DEPS['recipe'].PROFILES); legacy_profiles = copy.deepcopy(DEPS['recipe'].LEGACY_PROFILES)
        legacy = OriginalConsumerFixture(self.root / 'legacy-held', legacy=True)
        self.materialized(legacy, 'legacy-held-context')
        self.assertEqual(before, {path:path.read_bytes() for path in paths})
        self.assertEqual(profiles, DEPS['recipe'].PROFILES)
        self.assertEqual(legacy_profiles, DEPS['recipe'].LEGACY_PROFILES)

    def test_no_network_subprocess_or_retained_source_execution(self):
        with patch.object(socket, 'socket', side_effect=AssertionError('network forbidden')), \
             patch.object(socket, 'getaddrinfo', side_effect=AssertionError('DNS forbidden')), \
             patch.object(subprocess, 'Popen', side_effect=AssertionError('subprocess forbidden')):
            fixture, prepared, output, receipt = self.materialized()
            c.verify_context(output, receipt['selection_sha256'], DEPS)
        self.assertFalse(list(output.rglob('__pycache__')))

    def test_context_recipe_license_buildinfo_and_reviewed_input_tamper_refused(self):
        _, _, output, receipt = self.materialized()
        for relative in ('recipe/PKGBUILD', 'recipe/LICENSE', 'evidence/BUILDINFO', 'reviewed-inputs.json'):
            path = output / relative; original = path.read_bytes(); mode = path.stat().st_mode & 0o777
            path.chmod(0o600); path.write_bytes(original + b'changed')
            with self.subTest(path=relative), self.assertRaises((ValueError, OSError, KeyError)):
                c.verify_context(output, receipt['selection_sha256'], DEPS)
            path.write_bytes(original); path.chmod(mode)

    def test_missing_foreign_symlink_and_hardlink_context_inputs_refused(self):
        _, _, output, receipt = self.materialized()
        target = output / 'recipe/LICENSE'; body = target.read_bytes(); mode = target.stat().st_mode & 0o777
        target.unlink()
        with self.assertRaises((ValueError, OSError, KeyError)):
            c.verify_context(output, receipt['selection_sha256'], DEPS)
        external = self.root / 'outside'; external.write_bytes(body)
        for kind in ('symlink', 'hardlink'):
            if kind == 'symlink': target.symlink_to(external)
            else: os.link(external, target)
            with self.subTest(kind=kind), self.assertRaises((ValueError, OSError, KeyError)):
                c.verify_context(output, receipt['selection_sha256'], DEPS)
            target.unlink()
        target.write_bytes(body); target.chmod(mode)
        foreign = output / 'unexpected'; foreign.write_bytes(b'foreign')
        with self.assertRaises((ValueError, OSError, KeyError)):
            c.verify_context(output, receipt['selection_sha256'], DEPS)

    def test_existing_output_and_symlink_ancestor_refuse_without_overwrite(self):
        prepared = prepare_fixture(self.original)
        output = self.root / 'existing'; output.mkdir(mode=0o700); (output / 'keep').write_bytes(b'original')
        with self.assertRaises((ValueError, OSError)):
            c.materialize(prepared, output, DEPS)
        self.assertEqual((output / 'keep').read_bytes(), b'original')
        real = self.root / 'real'; real.mkdir(mode=0o700)
        alias = self.root / 'alias'; alias.symlink_to(real)
        with self.assertRaises((ValueError, OSError)):
            c.materialize(prepared, alias / 'context', DEPS)
        self.assertFalse((real / 'context').exists())

    def test_group_or_world_writable_output_parent_refused_before_creation(self):
        prepared = prepare_fixture(self.original)
        parent = self.root / 'writable-parent'; parent.mkdir(mode=0o700)
        for mode in (0o720, 0o702):
            parent.chmod(mode); output = parent / ('context-' + oct(mode))
            with self.subTest(mode=oct(mode)), self.assertRaisesRegex(ValueError, 'output parent'):
                c.materialize(prepared, output, DEPS)
            self.assertFalse(output.exists())
        parent.chmod(0o700)

    def test_repinned_context_cannot_drop_actual_selectors_or_supply_native_image(self):
        _, _, output, receipt = self.materialized()
        request_path = output / 'builder-request.json'; selection_path = output / 'selection.json'
        original_request = json.loads(request_path.read_bytes())
        original_selection = json.loads(selection_path.read_bytes())
        for kind in ('empty-selectors', 'concrete-image'):
            request = copy.deepcopy(original_request)
            if kind == 'empty-selectors':
                request['actual_selectors'] = {}
            else:
                index = request['argv_template'].index('--image') + 1
                request['argv_template'][index] = 'sha256:' + 'a' * 64
            request_raw = m.encoded(request)
            selection = copy.deepcopy(original_selection)
            selection['files']['builder-request.json'].update(sha256=m.digest(request_raw), bytes=len(request_raw))
            selection_raw = m.encoded(selection)
            for path, raw in ((request_path, request_raw), (selection_path, selection_raw)):
                path.chmod(0o600); path.write_bytes(raw); path.chmod(0o400)
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, 'NULL'):
                c.verify_context(output, m.digest(selection_raw), DEPS)


class HTTPSConsumerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='mirror-consumer-https-')
        self.addCleanup(self.temp.cleanup); self.root = Path(self.temp.name)
        self.first = incremental.SuccessorFixture(self.root / 'first', 'consumer-release-one', 1)
        self.second = incremental.SuccessorFixture(self.root / 'second', 'consumer-release-two', 2)
        previous = self.first.build()[0]
        self.history = m.update(previous, m.digest(previous), self.first.pin, self.second.root, self.second.pin,
            incremental.DEPS, inputs=self.second.inputs_path, inputs_sha256=m.digest(self.second.inputs_raw),
            retained_root=self.second.retained, directory=ROOT / 'scripts/release')[0]

    def materialized(self, fixture=None, leaf='context'):
        fixture = fixture or self.first
        prepared = prepare_fixture(fixture, self.history)
        output = self.root / leaf; receipt = c.materialize(prepared, output, DEPS)
        return fixture, prepared, output, receipt

    def test_retained_history_selects_exact_old_or_new_source_sets(self):
        for index, fixture in enumerate((self.first, self.second)):
            _, _, output, receipt = self.materialized(fixture, 'context-' + str(index))
            actual = {p.name:p.read_bytes() for p in (output / 'source-material/srcdest').iterdir()}
            self.assertEqual(sorted(actual.values()), sorted((fixture.source, fixture.unchanged)))
            self.assertTrue(c.verify_context(output, receipt['selection_sha256'], DEPS))
            self.assertEqual((output / 'recipe/retained.py').read_bytes(), fixture.bodies[fixture.name]['retained.py'])

    def test_existing_source_materials_prepare_accepts_materialized_inputs(self):
        fixture, prepared, output, receipt = self.materialized()
        report = DEPS['build'].recipe(output / 'recipe/PKGBUILD')
        self.assertEqual(report['errors'], [])
        plan_path = output / 'retained/source-plan.json'
        checked = DEPS['materials'].prepare(report, plan_path, m.digest(plan_path.read_bytes()),
            output / 'retained/catalog/source-catalog.json', output / 'retained/cache')
        self.assertEqual(sorted(item['record']['material']['sha256'] for item in checked['selected']),
                         sorted((m.digest(fixture.source), m.digest(fixture.unchanged))))
        stage = output / 'second-source-material'
        DEPS['materials'].stage(checked, stage)
        self.assertEqual(sorted(path.read_bytes() for path in (stage / 'srcdest').iterdir()),
                         sorted((fixture.source, fixture.unchanged)))

    def test_remote_archive_cache_receipt_and_license_tamper_refused(self):
        fixture, prepared, output, receipt = self.materialized()
        targets = [next((output / 'source-material/srcdest').iterdir()),
                   output / 'retained/cache/objects' / m.digest(fixture.source),
                   next((output / 'retained/cache/receipts').iterdir()),
                   output / 'retained/catalog/LICENSE']
        for path in targets:
            original = path.read_bytes(); mode = path.stat().st_mode & 0o777
            path.chmod(0o600); path.write_bytes(original + b'changed')
            with self.subTest(path=str(path)), self.assertRaises((ValueError, OSError, KeyError)):
                c.verify_context(output, receipt['selection_sha256'], DEPS)
            path.write_bytes(original); path.chmod(mode)

    def test_remote_materialization_is_offline_and_survives_relocation(self):
        with patch.object(socket, 'socket', side_effect=AssertionError('network forbidden')), \
             patch.object(socket, 'getaddrinfo', side_effect=AssertionError('DNS forbidden')), \
             patch.object(subprocess, 'Popen', side_effect=AssertionError('subprocess forbidden')):
            fixture, prepared, output, receipt = self.materialized()
            moved = self.root / 'moved'; shutil.copytree(output, moved)
            for source in (self.first, self.second):
                shutil.rmtree(source.root); shutil.rmtree(source.retained)
            self.assertTrue(c.verify_context(moved, receipt['selection_sha256'], DEPS))
        self.assertFalse(list(moved.rglob('__pycache__')))


if __name__ == '__main__':
    unittest.main()

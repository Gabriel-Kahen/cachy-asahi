import contextlib
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tarfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts/build'))
import build_v2 as build
import compare_v2 as compare
import source_materials as m


class VersionedInterfaceTests(unittest.TestCase):
    def test_compare_uses_versioned_artifact_binding(self):
        self.assertIs(compare.bind_artifact, build.bind_artifact)
        self.assertEqual(Path(build.__file__), ROOT / 'scripts/build/build_v2.py')
        self.assertEqual(Path(compare.__file__), ROOT / 'scripts/build/compare_v2.py')

    def test_versioned_cli_imports_ignore_ambient_helpers_under_isolation(self):
        with tempfile.TemporaryDirectory() as temporary:
            ambient = Path(temporary)
            marker = ambient / 'ambient-imported'
            for name in ('build', 'build_v2', 'source_materials', 'source_cache', 'package_checks'):
                (ambient / (name + '.py')).write_text(
                    'from pathlib import Path\nPath(' + repr(str(marker)) + ').touch()\n'
                    'raise RuntimeError("ambient helper")\n')
            for name in ('build_v2.py', 'compare_v2.py'):
                result = subprocess.run([sys.executable, '-I', '-S', '-B',
                    str(ROOT / 'scripts/build' / name), '--help'], cwd=ambient,
                    env=dict(os.environ, PYTHONPATH=str(ambient)), capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                self.assertIn(b'--source-plan' if name == 'build_v2.py' else b'--require-bytes', result.stdout)
            self.assertFalse(marker.exists())


class OfflineSourcesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.recipe = self.root / 'recipe'; self.recipe.mkdir()
        self.raw = b'SYNTHETIC opaque archive bytes; never extracted or executed\n'
        self.notice = b'SYNTHETIC notice; no legal approval\n'
        self.url = 'https://example.invalid/revision.tar.gz'
        self.source = 'upstream.tar.gz::' + self.url
        self.row = dict(material=dict(id='upstream-1', path='sources/revision.tar.gz',
                        bytes=len(self.raw), sha256=m.sd.digest(self.raw)),
                        url=self.url, revision='SYNTHETIC-reviewed-revision', license='MIT; unreviewed',
                        license_evidence=[dict(id='notice', path='NOTICE', bytes=len(self.notice),
                                              sha256=m.sd.digest(self.notice))])
        (self.root / 'NOTICE').write_bytes(self.notice)
        (self.recipe / 'local.txt').write_text('local recipe input\n')
        (self.recipe / 'PKGBUILD').write_text("pkgname=example\npkgver=1\npkgrel=1\narch=('aarch64')\n"
            "license=('MIT')\nsource=('" + self.source + "' 'local.txt')\nsha256sums=('" +
            self.row['material']['sha256'] + "' '" + build.digest(self.recipe / 'local.txt') + "')\n")
        self.catalog = self.root / 'catalog.json'
        self.catalog.write_bytes(m.cache.encoded(dict(schema_version=1, purpose='source-cache-inputs', sources=[self.row])))
        self.catalog_sha = build.digest(self.catalog)
        self.report = build.recipe(self.recipe / 'PKGBUILD')
        self.assertEqual(self.report['errors'], [])
        self.plan = dict(schema_version=1, purpose='offline-build-sources',
                         recipe_inputs=self.report['input_sha256'], catalog_sha256=self.catalog_sha,
                         sources=[dict(source=self.source, id='upstream-1', revision=self.row['revision'])])
        self.plan_path = self.root / 'plan.json'
        self.cache = self.root / 'cache'; m.cache.initialize(self.cache)
        self.object = self.cache / 'objects' / self.row['material']['sha256']
        self.object.write_bytes(self.raw); self.object.chmod(0o600)
        with patch.object(m.cache, 'transport', side_effect=AssertionError('network attempted')):
            m.cache.run(self.cache, self.catalog, self.catalog_sha, ['upstream-1'], offline=False)
        self.receipt = next((self.cache / 'receipts').iterdir())
        self.lock = self.root / 'packages.lock'; self.lock.write_text('base-devel 1-1\n')
        self.reviewed = self.root / 'reviewed.json'
        self.reviewed.write_text(json.dumps(self.report['input_sha256']))
        self.output = self.root / 'build-output'

    def save_plan(self):
        self.plan_path.write_bytes(m.cache.encoded(self.plan))
        return build.digest(self.plan_path)

    def prepare(self):
        with patch.object(m.cache, 'transport', side_effect=AssertionError('network attempted')):
            return m.prepare(self.report, self.plan_path, self.save_plan(), self.catalog, self.cache)

    def argv(self):
        return ['build_v2.py', str(self.recipe), '--image', 'sha256:' + 'a' * 64,
                '--output', str(self.output), '--mode', 'emulated', '--source-date-epoch', '1',
                '--expected-packages', str(self.lock), '--reviewed-inputs', str(self.reviewed),
                '--source-plan', str(self.plan_path), '--source-plan-sha256', self.save_plan(),
                '--source-catalog', str(self.catalog), '--source-cache', str(self.cache)]

    def refused_before_docker(self, argv=None):
        with patch.object(sys, 'argv', argv or self.argv()), patch.object(build, 'capture') as capture, \
             patch.object(build.subprocess, 'run') as run, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(build.main(), 1)
            capture.assert_not_called(); run.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_stages_selected_bytes_and_complete_provenance_without_mutating_cache(self):
        before = {str(p.relative_to(self.cache)): p.read_bytes() for p in self.cache.rglob('*') if p.is_file()}
        prepared = self.prepare()
        parent = self.root / 'private'; parent.mkdir(mode=0o700)
        destination = parent / 'source-material'
        selection = m.stage(prepared, destination)
        self.assertEqual((destination / 'srcdest/upstream.tar.gz').read_bytes(), self.raw)
        self.assertEqual((destination / 'srcdest/upstream.tar.gz').stat().st_mode & 0o777, 0o400)
        self.assertEqual([p.name for p in (destination / 'srcdest').iterdir()], ['upstream.tar.gz'])
        self.assertEqual(selection['sources'][0]['record'], self.row)
        self.assertEqual(json.loads((destination / 'receipts/upstream-1.json').read_bytes())['source'], self.row)
        self.assertEqual((destination / 'notices' / m.sd.digest(self.notice)).read_bytes(), self.notice)
        self.assertEqual(build.digest(destination / 'source-plan.json'), selection['plan_sha256'])
        self.assertFalse(selection['legal_acceptance']); self.assertFalse(selection['source_completeness_accepted'])
        self.assertEqual(before, {str(p.relative_to(self.cache)): p.read_bytes() for p in self.cache.rglob('*') if p.is_file()})

    def test_missing_object_refused_before_docker(self):
        self.object.unlink(); self.refused_before_docker()

    def test_changed_object_refused_before_docker(self):
        self.object.write_bytes(b'X' + self.raw[1:]); self.refused_before_docker()

    def test_missing_receipt_refused_before_docker(self):
        self.receipt.unlink(); self.refused_before_docker()

    def test_changed_receipt_refused_before_docker(self):
        self.receipt.write_text('{}'); self.refused_before_docker()

    def test_missing_notice_refused_before_docker(self):
        (self.root / 'NOTICE').unlink(); self.refused_before_docker()

    def test_wrong_revision_url_checksum_or_id_refused(self):
        original = copy.deepcopy(self.plan)
        for field, value in [('revision', 'another-revision'), ('source', 'https://elsewhere.invalid/file'), ('id', 'unknown')]:
            with self.subTest(field=field):
                self.plan = copy.deepcopy(original); self.plan['sources'][0][field] = value
                self.refused_before_docker()
        self.plan = original
        self.report['metadata']['sha256sums'][0] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
            self.prepare()

    def test_source_plan_pin_and_catalog_pin_are_independent(self):
        argv = self.argv(); argv[argv.index('--source-plan-sha256') + 1] = '0' * 64
        self.refused_before_docker(argv)
        self.plan['catalog_sha256'] = '0' * 64; self.refused_before_docker()

    def test_plan_bound_to_every_recipe_input(self):
        self.plan['recipe_inputs']['local.txt'] = '0' * 64; self.refused_before_docker()

    def test_recipe_change_after_review_refused_before_docker(self):
        (self.recipe / 'local.txt').write_text('changed\n'); self.refused_before_docker()

    def test_duplicate_unknown_or_incomplete_bindings_refused(self):
        original = copy.deepcopy(self.plan)
        for rows in ([], original['sources'] * 2, [dict(original['sources'][0], extra=True)]):
            self.plan = dict(original, sources=rows); self.refused_before_docker()

    def test_optional_arguments_are_all_or_none_and_require_network_none(self):
        argv = self.argv()
        for option in ('--source-plan', '--source-plan-sha256', '--source-catalog', '--source-cache'):
            changed = list(argv); index = changed.index(option); del changed[index:index + 2]
            self.refused_before_docker(changed)
        self.refused_before_docker(argv + ['--network', 'bridge'])

    def test_symlink_or_hardlink_cache_objects_refused(self):
        other = self.root / 'object'; other.write_bytes(self.raw); other.chmod(0o600)
        self.object.unlink(); self.object.symlink_to(other); self.refused_before_docker()
        self.object.unlink(); os.link(other, self.object); self.refused_before_docker()

    def test_object_changed_between_preflight_and_stage_refused(self):
        prepared = self.prepare(); self.object.write_bytes(b'X' + self.raw[1:])
        parent = self.root / 'private'; parent.mkdir(mode=0o700)
        with self.assertRaisesRegex(ValueError, 'byte pin mismatch'):
            m.stage(prepared, parent / 'material')

    def test_staging_parent_must_be_private_and_destination_fresh(self):
        prepared = self.prepare()
        parent = self.root / 'public'; parent.mkdir(mode=0o755)
        with self.assertRaisesRegex(ValueError, 'private owned staging parent'):
            m.stage(prepared, parent / 'material')
        parent.chmod(0o700); (parent / 'material').mkdir()
        with self.assertRaises(FileExistsError):
            m.stage(prepared, parent / 'material')

    def test_plain_https_and_aarch64_sources(self):
        for suffix in ('', '_aarch64'):
            self.report['metadata'] = {'source' + suffix: [self.url],
                                      'sha256sums' + suffix: [self.row['material']['sha256']]}
            self.plan['sources'][0]['source'] = self.url
            self.assertEqual(self.prepare()['selected'][0]['filename'], 'revision.tar.gz')

    def test_filename_collision_and_vcs_are_refused(self):
        for source in ('local.txt::' + self.url, '../escape::' + self.url,
                       'git+https://example.invalid/repo#commit=' + 'a' * 40):
            self.report['metadata']['source'][0] = source
            self.plan['sources'][0]['source'] = source
            with self.subTest(source=source), self.assertRaises(ValueError):
                self.prepare()

    def test_mocked_container_gets_only_readonly_staging_and_failure_retains_provenance(self):
        def capture(command):
            return json.dumps([dict(Architecture='arm64', Os='linux', Id='sha256:' + 'a' * 64)]) \
                if command[1:3] == ['image', 'inspect'] else 'x86_64'
        with patch.object(sys, 'argv', self.argv()), patch.object(build, 'capture', side_effect=capture), \
             patch.object(build.subprocess, 'run', return_value=subprocess.CompletedProcess([], 17)) as run, \
             contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(build.main(), 1)
        command = run.call_args.args[0]
        self.assertEqual(command[command.index('--network') + 1], 'none')
        self.assertIn('CACHY_ASAHI_OFFLINE_SOURCES=1', command)
        entry = ROOT / 'scripts/build/container-entry-v2.sh'
        self.assertIn(f'type=bind,src={entry},dst=/builder-entry.sh,readonly', command)
        self.assertIn(f'type=bind,src={self.output}/source-material/srcdest,dst=/offline-sources,readonly', command)
        self.assertNotIn(str(self.cache), ' '.join(command))
        evidence = json.loads((self.output / 'provenance.json').read_text())
        self.assertEqual(evidence['status'], 'failed'); self.assertEqual(evidence['exit_code'], 17)
        self.assertEqual(evidence['source_material']['sources'][0]['record'], self.row)
        for name, checksum in evidence['files'].items():
            self.assertEqual(build.digest(self.output / name), checksum)

    def test_container_seeds_writable_private_srcdest_from_readonly_files(self):
        source = (ROOT / 'scripts/build/container-entry-v2.sh').read_text()
        start = source.index('seed_offline_sources() {'); end = source.index('\n}', start) + 2
        directory = self.root / 'mounted'; directory.mkdir()
        (directory / 'archive.tar.gz').write_bytes(self.raw); (directory / 'archive.tar.gz').chmod(0o400)
        target = self.root / 'tmpfs-source'
        script = source[start:end] + '\nseed_offline_sources "$1" "$2"\n[[ $SRCDEST == "$2" ]]\n'
        result = subprocess.run(['bash', '-euc', script, 'source-seed-control', str(directory), str(target)],
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((target / 'archive.tar.gz').read_bytes(), self.raw)
        self.assertEqual(target.stat().st_mode & 0o777, 0o700)
        self.assertTrue((target / 'archive.tar.gz').stat().st_mode & 0o200)
        self.assertEqual((directory / 'archive.tar.gz').stat().st_mode & 0o777, 0o400)

    def test_mocked_success_preserves_source_hashes_and_comparison_detects_staged_tamper(self):
        def capture(command):
            return json.dumps([dict(Architecture='arm64', Os='linux', Id='sha256:' + 'a' * 64)]) \
                if command[1:3] == ['image', 'inspect'] else 'x86_64'
        def run(command, **kwargs):
            artifacts = self.output / 'artifacts'
            kwargs['stdout'].write(b'SYNTHETIC container response; no build executed\n')
            for name in ('environment.txt', 'config.sha256', 'makepkg.conf', 'pacman.conf'):
                (artifacts / name).write_text('SYNTHETIC container response\n')
            (artifacts / 'packages.lock').write_text(self.lock.read_text())
            (artifacts / 'generated.SRCINFO').write_text(''.join(
                f'{key} = {value}\n' for key, values in self.report['metadata'].items() for value in values))
            payload = {'.PKGINFO': b'pkgname = example\npkgbase = example\npkgver = 1-1\narch = aarch64\nlicense = MIT\n',
                '.BUILDINFO': ('format = 2\npkgname = example\npkgver = 1-1\npkgarch = aarch64\n'
                    'pkgbuild_sha256sum = ' + self.report['input_sha256']['PKGBUILD'] + '\n').encode(),
                '.MTREE': b'SYNTHETIC mtree\n', 'usr/share/example/fixture': b'SYNTHETIC payload\n'}
            with tarfile.open(artifacts / 'example-1-1-aarch64.pkg.tar.gz', 'w:gz') as archive:
                for name, content in payload.items():
                    member = tarfile.TarInfo(name); member.size = len(content); member.mode = 0o644
                    archive.addfile(member, io.BytesIO(content))
            return subprocess.CompletedProcess(command, 0)
        with patch.object(sys, 'argv', self.argv()), patch.object(build, 'capture', side_effect=capture), \
             patch.object(build.subprocess, 'run', side_effect=run), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(build.main(), 0)
        record, reports = compare.verify(self.output)
        self.assertEqual(record['status'], 'built-package-static-pass')
        self.assertEqual(len(reports), 1)
        self.assertIn('source-material/srcdest/upstream.tar.gz', record['files'])
        source = self.output / 'source-material/srcdest/upstream.tar.gz'
        source.chmod(0o600); source.write_bytes(b'changed staged material')
        with self.assertRaisesRegex(ValueError, 'missing/changed evidence'):
            compare.verify(self.output)

    def test_compare_refuses_different_source_material_even_with_matching_package_metadata(self):
        common = dict(clean_environment_id='first', image='image', image_id='image', mode='emulated',
            source_date_epoch=1, recipe_inputs={}, recipe_metadata={}, expected_packages_sha256='lock',
            entry_script_sha256='entry')
        left = dict(common, source_material={'plan_sha256': 'a' * 64})
        right = dict(common, clean_environment_id='second', source_material={'plan_sha256': 'b' * 64})
        with patch.object(compare, 'verify', side_effect=[(left, {}), (right, {})]):
            self.assertIn('input mismatch: source_material', compare.compare('first', 'second')['errors'])


if __name__ == '__main__':
    unittest.main()

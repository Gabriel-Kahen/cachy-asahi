"""Pure temporary-file/mocked-process checks; no native build or Docker calls."""
import importlib.util
import io
import json
from pathlib import Path
import signal
import struct
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('lsp_proposal', HERE / 'run.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
ROOT = HERE.parents[2]
TMP = ROOT / 'artifacts/development/asahi-lsp-tests/tmp'


class CallerTests(unittest.TestCase):
    def setUp(self):
        TMP.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=TMP)
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.args = SimpleNamespace(product=self.base / 'product', desktop=self.base / 'desktop',
                                    builder=self.base / 'builder', private=self.base / 'private',
                                    output=self.base / 'public', archive=None)

    def fake_command(self, argv, log, timeout):
        if 'compare.py' in str(argv[3]):
            log.write_text(json.dumps({'errors': [], 'packages': {'candidate': {
                'bytes_equal': True, 'installed_contents_equal': True, 'pkginfo_equal': True}}}))
        else:
            build = Path(argv[-1])
            build.mkdir()
            (build / 'build.log').write_text('private source excerpt MUST_NOT_EXPORT\nLSP_STAGE build PASS\n')
            log.write_text('private host diagnostics MUST_NOT_EXPORT\n')

    def execute(self, **overrides):
        checks = SimpleNamespace(recipe=lambda _: {'errors': [], 'input_sha256': {'PKGBUILD': 'a' * 64}})
        values = {'preflight': lambda _: ('sha256:' + 'a' * 64, self.base / 'lock'),
                  'source': lambda target, retained: target.write_bytes(b'PRIVATE_SOURCE_SENTINEL'),
                  'module': lambda _: checks, 'command': self.fake_command,
                  'observations': lambda *_: {'image_id': 'sha256:' + 'a' * 64,
                    'expected_packages_sha256': runner.LOCK, 'artifact_sha256': 'b' * 64}}
        values.update(overrides)
        with patch.multiple(runner, **values):
            return runner.run(self.args)

    def test_success_exports_observations_without_private_source_or_logs(self):
        self.assertEqual(self.execute(), 0)
        self.assertFalse(self.args.private.exists())
        public = ''.join(p.read_text() for p in self.args.output.iterdir())
        self.assertNotIn('MUST_NOT_EXPORT', public)
        self.assertNotIn('PRIVATE_SOURCE_SENTINEL', public)
        report = json.loads((self.args.output / 'result.json').read_text())
        self.assertEqual(report['cleanup']['builder_image'], 'BORROWED-PRESERVED')
        self.assertEqual(len(report['builds']), 2)

    def test_failed_build_keeps_failure_class_and_retires_private_inputs(self):
        def fail(*_):
            raise runner.CommandFailure(42)
        self.assertEqual(self.execute(command=fail), 1)
        report = json.loads((self.args.output / 'result.json').read_text())
        self.assertEqual(report['failed_stage'], 'build-1')
        self.assertEqual(report['child_exit_code'], 42)
        self.assertFalse(self.args.private.exists())

    def test_diagnostic_failure_never_skips_cleanup(self):
        with patch.object(runner, 'diagnostics', side_effect=OSError('private path/secret')):
            self.assertEqual(self.execute(), 1)
        self.assertFalse(self.args.private.exists())
        report = json.loads((self.args.output / 'result.json').read_text())
        self.assertEqual(report['cleanup']['status'], 'PASS')
        self.assertNotIn('secret', json.dumps(report))

    def test_cancellation_during_final_save_changes_public_status(self):
        original = runner.save
        injected = False
        def save(path, value):
            nonlocal injected
            original(path, value)
            if path.name == 'result.json' and not injected:
                injected = True
                signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
        with patch.object(runner, 'save', side_effect=save):
            self.assertEqual(self.execute(), 1)
        report = json.loads((self.args.output / 'result.json').read_text())
        self.assertTrue(report['cancelled'])
        self.assertEqual(report['status'], 'FAIL')

    def test_markers_exclude_source_excerpts_and_limit_records(self):
        root = self.base / 'raw'
        build = root / 'build-1'
        build.mkdir(parents=True)
        log = build / 'build.log'
        log.write_text('copyright source excerpt\nLSP_STAGE build PASS\nLSP_STAGE build PASS secret\n')
        self.assertEqual(runner.diagnostics(root), [{'build': 'build-1', 'marker': 'LSP_STAGE build PASS'}])
        log.write_text('LSP_STAGE build PASS\n' * 257)
        with self.assertRaisesRegex(ValueError, 'diagnostic-count-exceeded'):
            runner.diagnostics(root)

    def test_cleanup_removes_only_recorded_owned_container_and_preserves_image(self):
        private = self.base / 'raw'
        build = private / 'build-1'
        build.mkdir(parents=True)
        name = 'cachy-asahi-' + 'f' * 16
        (build / 'provenance.json').write_text(json.dumps({'clean_environment_id': name}))
        with patch.object(runner, 'capture', side_effect=[name, '']), \
             patch.object(runner.subprocess, 'run') as process:
            report = runner.cleanup(private, [build])
        self.assertEqual(report['status'], 'PASS')
        self.assertEqual(process.call_args.args[0], ['docker', 'rm', '-f', name])
        self.assertFalse(private.exists())

    def test_cleanup_uncertainty_preserves_private_inputs_and_fails(self):
        private = self.base / 'raw'
        build = private / 'build-1'
        build.mkdir(parents=True)
        (build / 'provenance.json').write_text(json.dumps({'clean_environment_id': 'unowned'}))
        with patch.object(runner, 'capture') as capture:
            report = runner.cleanup(private, [build])
        self.assertEqual(report['status'], 'FAIL')
        self.assertTrue(private.exists())
        capture.assert_not_called()

    def test_wrong_retained_source_is_rejected_before_copy(self):
        source = self.base / 'wrong.tar.gz'
        source.write_bytes(b'wrong source')
        target = self.base / 'out.tar.gz'
        with self.assertRaisesRegex(ValueError, 'retained-source-differs'):
            runner.source(target, source)
        self.assertFalse(target.exists())

    def test_effective_configuration_is_closed_to_headless_generic_flags(self):
        log = self.base / 'build.log'
        def write(feature='lv2', flags='-march=armv8-a -mtune=generic -O2'):
            log.write_text('source excerpt ignored\n' + '\n'.join(
                'LSP_CONFIG ' + key + ' ' + (feature if key == 'BUILD_FEATURES' else flags)
                for key in runner.CONFIG_KEYS) + '\n')
        write()
        self.assertEqual(runner.configuration(log)['BUILD_FEATURES'], 'lv2')
        write(feature='lv2 ui')
        with self.assertRaisesRegex(ValueError, 'headless-features-differ'):
            runner.configuration(log)
        write(flags='-march=armv8-a -mtune=generic -flto')
        with self.assertRaisesRegex(ValueError, 'generic-flags-differ'):
            runner.configuration(log)
        write(flags='copyright source excerpt')
        with self.assertRaisesRegex(ValueError, 'config-token-invalid'):
            runner.configuration(log)

    def test_duplicate_or_missing_config_records_fail(self):
        log = self.base / 'build.log'
        log.write_text('LSP_CONFIG BUILD_FEATURES lv2\n' * 2)
        with self.assertRaisesRegex(ValueError, 'config-record-invalid'):
            runner.configuration(log)
        log.write_text('LSP_CONFIG BUILD_FEATURES lv2\n')
        with self.assertRaisesRegex(ValueError, 'config-records-missing'):
            runner.configuration(log)

    def test_real_package_inspector_and_closed_payload_projection(self):
        checks = runner.module(ROOT / 'scripts/checks/package_checks.py')
        build = self.base / 'build-1'
        artifacts = build / 'artifacts'
        artifacts.mkdir(parents=True)
        runner.save(build / 'provenance.json', {'status': 'built-package-static-pass',
            'recipe_inputs': {'PKGBUILD': 'a' * 64}, 'image_id': 'sha256:' + 'b' * 64,
            'expected_packages_sha256': runner.LOCK})
        (build / 'build.log').write_text('\n'.join('LSP_CONFIG ' + key + ' ' +
            ('lv2' if key == 'BUILD_FEATURES' else '-march=armv8-a -mtune=generic -O2')
            for key in runner.CONFIG_KEYS) + '\n')
        ident = b'\x7fELF\x02\x01\x01' + b'\0' * 9
        elf = ident + struct.pack('<HHIQQQIHHHHHH', 3, 183, 1, 0, 64, 0, 0, 64, 56, 1, 0, 0, 0)
        elf += struct.pack('<IIQQQQQQ', 1, 5, 0, 0, 0, 120, 120, 16384)
        name = 'lsp-plugins-lv2-headless-development'
        files = {'.PKGINFO': f'pkgname = {name}\npkgver = 1.2.35-1\narch = aarch64\nlicense = LGPL-3.0-or-later\n'.encode(),
            '.BUILDINFO': f'format = 2\npkgname = {name}\npkgver = 1.2.35-1\npkgarch = aarch64\npkgbuild_sha256sum = {"a" * 64}\n'.encode(),
            '.MTREE': b'fixture', 'usr/lib/lv2/lsp-plugins.lv2/lsp-plugins-lv2.so': elf,
            'usr/lib/lv2/lsp-plugins.lv2/manifest.ttl': b'PRIVATE_TTL_SENTINEL'}
        for notice in ('COPYING', 'COPYING.LESSER', 'LV2-COPYING', 'Ardour-inline-display-NOTICE', 'SOURCE-NOTICE'):
            files['usr/share/licenses/' + name + '/' + notice] = b'PRIVATE_NOTICE_SENTINEL'
        package = artifacts / (name + '.pkg.tar.gz')
        def write():
            with tarfile.open(package, 'w:gz') as archive:
                for path, content in files.items():
                    entry = tarfile.TarInfo(path)
                    entry.size = len(content)
                    entry.mode = 0o755 if path.endswith('.so') else 0o644
                    archive.addfile(entry, io.BytesIO(content))
        write()
        report = runner.observations(build, checks)
        self.assertEqual(next(iter(report['elf'].values()))['errors'], [])
        self.assertNotIn('PRIVATE_TTL_SENTINEL', json.dumps(report))
        self.assertNotIn('PRIVATE_NOTICE_SENTINEL', json.dumps(report))
        files['usr/bin/unexpected'] = b'not allowed'
        write()
        with self.assertRaisesRegex(ValueError, 'unexpected-payload'):
            runner.observations(build, checks)


if __name__ == '__main__':
    unittest.main()

"""Inert caller controls: no Docker, package build, network or plugin execution."""
import importlib.util
import io
import json
from pathlib import Path
import signal
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('offline_caller', HERE / 'run.py')
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)
TMP = HERE.parents[3] / 'tmp'


class CommandFailure(ValueError):
    def __init__(self, code):
        self.code = code


class CallerTests(unittest.TestCase):
    def setUp(self):
        TMP.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=TMP)
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.args = SimpleNamespace(product=self.base / 'product', desktop=self.base / 'desktop',
            builder=self.base / 'builder', private=self.base / 'private', output=self.base / 'public', archive=None)
        self.pair = self.base / 'pair'
        (self.pair / 'recipe').mkdir(parents=True)
        (self.pair / 'recipe/PKGBUILD').write_text('inert recipe')
        self.calls = []
        self.image = 'sha256:' + 'a' * 64
        self.api = SimpleNamespace(PRODUCT='b' * 40, DESKTOP='c' * 40, LOCK='d' * 64,
            SOURCE_SHA='e' * 64, SOURCE_NAME='source.tar.gz', EPOCH=1787491172,
            preflight=lambda _: (self.image, self.base / 'lock'), ordinary=lambda _: None,
            source=lambda target, _: target.write_bytes(b'PRIVATE_SOURCE_SENTINEL'),
            module=lambda _: SimpleNamespace(recipe=lambda _: {'errors': [], 'input_sha256': {'PKGBUILD': 'f' * 64}}),
            command=self.command, observations=lambda *_: self.row(), CommandFailure=CommandFailure,
            diagnostics=lambda _: [], cleanup=self.held_cleanup, capture=lambda _: '')

    def row(self):
        return {'image_id': self.image, 'expected_packages_sha256': self.api.LOCK,
                'artifact_sha256': run.ARCHIVE, 'members': {run.LIB_PATH: {'sha256': run.LIBRARY}}}

    def runtime(self):
        return {'schema_version': 1, 'status': 'PASS', 'failure_class': None, 'stage': 'complete',
            'candidate_sha256': run.LIBRARY,
            'inventory': {'count': 574, 'unchanged': True, 'before_sha256': self.api.LOCK, 'after_sha256': self.api.LOCK},
            'loader': {'status': 'PASS'}, 'processing': {'status': 'PASS', 'case_count': 48, 'instance_count': 96}}

    def held_cleanup(self, private, builds):
        import shutil
        shutil.rmtree(private)
        return {'status': 'PASS', 'private_removed': True, 'builder_image': 'BORROWED-PRESERVED'}

    def command(self, argv, log, limit):
        self.calls.append((argv, limit))
        log.write_text('PRIVATE_DIAGNOSTIC_SENTINEL')
        if argv[0] == 'docker':
            out = self.args.private / 'runtime'
            run.save(out / 'observations.json', self.runtime())
        else:
            build = Path(argv[-1])
            (build / 'artifacts').mkdir(parents=True)
            (build / 'artifacts/candidate.pkg.tar.xz').write_bytes(b'inert')

    def execute(self, **overrides):
        for name, value in overrides.items():
            setattr(self.api, name, value)
        with patch.object(run, 'PAIR', self.pair), patch.object(run, 'pair_api', return_value=self.api), \
             patch.object(run, 'extract_bundle', side_effect=lambda _, __, p: p.mkdir()):
            return run.run(self.args)

    def result(self):
        return json.loads((self.args.output / 'result.json').read_text())

    def test_one_build_and_one_runtime_with_no_pair_or_private_export(self):
        self.assertEqual(self.execute(), 0)
        self.assertEqual([limit for _, limit in self.calls], [2460, 360])
        self.assertEqual(len(self.calls), 2)
        self.assertIn('--network', self.calls[0][0])
        self.assertNotIn('compare.py', str(self.calls))
        self.assertEqual(set(p.name for p in self.args.output.iterdir()), run.PUBLIC)
        public = ''.join(p.read_text() for p in self.args.output.iterdir())
        self.assertNotIn('PRIVATE_', public)
        self.assertFalse(self.args.private.exists())
        self.assertEqual(self.result()['native_rebuilds'], 1)
        self.assertEqual(self.result()['active_algorithm_reference'], 'NOT ESTABLISHED')
        self.assertEqual(self.result()['hardware'], 'NOT RUN')

    def test_nonzero_runtime_preserves_fixed_feature_port_timeout_and_signal_failures(self):
        original = self.command
        def fail(argv, log, limit):
            original(argv, log, limit)
            if argv[0] == 'docker':
                row = self.runtime()
                row.update(status='FAIL', stage='processing', failure_class='host_required-feature-unsupported')
                run.save(self.args.private / 'runtime/observations.json', row)
                raise CommandFailure(1)
        self.assertEqual(self.execute(command=fail), 1)
        result = self.result()
        self.assertEqual(result['runtime_failure'], {'stage': 'processing',
            'failure_class': 'host_required-feature-unsupported'})
        public = json.loads((self.args.output / 'runtime.json').read_text())
        self.assertEqual(public['status'], 'FAIL')
        self.assertEqual(set(public), {'schema_version', 'status', 'stage', 'failure_class', 'inventory'})
        self.assertFalse(self.args.private.exists())
        for code in ('host_port-shape-invalid', 'timeout', 'signal'):
            public['failure_class'] = code
            path = self.base / 'failed.json'
            run.save(path, public)
            with patch.object(run, 'pair_api', return_value=self.api):
                self.assertEqual(run.runtime_report(path, allow_failure=True)['failure_class'], code)
        public['failure_class'] = 'private arbitrary diagnostic'
        run.save(path, public)
        with self.assertRaises(ValueError):
            run.runtime_report(path, allow_failure=True)

    def test_wrong_rebuild_hash_stops_before_runtime(self):
        row = self.row()
        row['artifact_sha256'] = '0' * 64
        self.assertEqual(self.execute(observations=lambda *_: row), 1)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.result()['failed_stage'], 'build-1')

    def test_build_failure_is_not_retried(self):
        def fail(*args):
            self.calls.append(args)
            raise CommandFailure(42)
        self.assertEqual(self.execute(command=fail), 1)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.result()['child_exit_code'], 42)
        self.assertFalse(self.args.private.exists())

    def test_diagnostics_failure_still_cleans_and_fails(self):
        def fail(_):
            raise OSError('PRIVATE_SOURCE_SENTINEL')
        self.assertEqual(self.execute(diagnostics=fail), 1)
        self.assertFalse(self.args.private.exists())
        self.assertNotIn('PRIVATE_SOURCE_SENTINEL', json.dumps(self.result()))

    def test_final_save_cancellation_never_reports_pass(self):
        original = run.save
        injected = False
        def save(path, value):
            nonlocal injected
            original(path, value)
            if path.name == 'result.json' and not injected:
                injected = True
                signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
        with patch.object(run, 'save', side_effect=save):
            self.assertEqual(self.execute(), 1)
        self.assertTrue(self.result()['cancelled'])
        self.assertEqual(self.result()['status'], 'FAIL')

    def test_runtime_isolation_flags_and_no_device_or_socket_mount(self):
        argv = run.runtime_command(self.image, 'owned', Path('/private/bundle'), Path('/private/out'),
                                   Path('/private/lock'), Path('/product'))
        for flag in ('--read-only', '--network=none', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                     '--pids-limit=128', '--memory=1g', '--cpus=2', '--pull=never', '--platform=linux/arm64'):
            self.assertIn(flag, argv)
        self.assertFalse(any('docker.sock' in str(v) or '/dev/snd' in str(v) or '--device' in str(v) for v in argv))
        self.assertEqual(sum('dst=/out' in str(v) for v in argv), 1)
        self.assertEqual(sum('readonly' in str(v) for v in argv), 4)

    def test_runtime_rejects_private_paths_nonfinite_and_incomplete_grid(self):
        path = self.base / 'runtime.json'
        for transform in (lambda row: row.update(extra='/private/source'),
                          lambda row: row['processing'].update(peak=float('nan')),
                          lambda row: row['processing'].update(case_count=47),
                          lambda row: row['inventory'].update(unchanged=False)):
            row = self.runtime()
            transform(row)
            path.write_text(json.dumps(row))
            with patch.object(run, 'pair_api', return_value=self.api), self.assertRaises(ValueError):
                run.runtime_report(path)

    def test_cleanup_is_scoped_and_unknown_handle_preserves_inputs(self):
        private = self.base / 'owned'
        private.mkdir()
        run.save(private / 'runtime-container.json', {'name': 'unowned'})
        with patch.object(run, 'pair_api', return_value=self.api), patch.object(run.subprocess, 'run') as proc:
            self.assertEqual(run.cleanup(private, [])['status'], 'FAIL')
        proc.assert_not_called()
        self.assertTrue(private.exists())
        name = 'cachy-asahi-lsp-offline-' + 'f' * 16
        run.save(private / 'runtime-container.json', {'name': name})
        with patch.object(run, 'pair_api', return_value=self.api), \
             patch.object(self.api, 'capture', side_effect=[name, '']) as capture, \
             patch.object(run.subprocess, 'run') as proc:
            self.assertEqual(run.cleanup(private, [])['status'], 'PASS')
        self.assertEqual(proc.call_args.args[0], ['docker', 'rm', '-f', name])
        self.assertTrue(all(name in ' '.join(call.args[0]) for call in capture.call_args_list))

    def test_bundle_rejects_unaccepted_hash_before_extraction(self):
        archive = self.base / 'wrong.pkg.tar.xz'
        archive.write_bytes(b'wrong')
        with self.assertRaisesRegex(ValueError, 'accepted-package-differs'):
            run.extract_bundle(archive, self.row(), self.base / 'bundle')
        self.assertFalse((self.base / 'bundle').exists())

    def test_closed_bundle_fixture_copies_only_200_reviewed_regular_members(self):
        import hashlib
        prefix = 'usr/lib/lv2/lsp-plugins.lv2/'
        files = {run.LIB_PATH: b'INERT_LIBRARY_BYTES'}
        files.update({prefix + f'fixture-{i}.ttl': b'INERT_TTL' for i in range(199)})
        archive = self.base / 'fixture.pkg.tar.xz'
        with tarfile.open(archive, 'w:xz') as stream:
            for name, content in dict(files, **{'usr/bin/ignored': b'NOT_EXTRACTED'}).items():
                info = tarfile.TarInfo(name)
                info.size = len(content)
                stream.addfile(info, io.BytesIO(content))
        package_hash = run.sha(archive)
        library_hash = hashlib.sha256(files[run.LIB_PATH]).hexdigest()
        report = {'artifact_sha256': package_hash, 'members': {name: {
            'type': '0', 'size': len(content), 'sha256': hashlib.sha256(content).hexdigest()}
            for name, content in files.items()}}
        target = self.base / 'bundle'
        with patch.object(run, 'ARCHIVE', package_hash), patch.object(run, 'LIBRARY', library_hash):
            run.extract_bundle(archive, report, target)
        self.assertEqual(len(list(target.iterdir())), 200)
        self.assertEqual((target / 'lsp-plugins-lv2.so').stat().st_mode & 0o777, 0o755)
        self.assertFalse((target / 'ignored').exists())


if __name__ == '__main__':
    unittest.main()

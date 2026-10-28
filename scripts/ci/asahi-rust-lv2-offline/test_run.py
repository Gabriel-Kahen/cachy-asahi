"""Inert accepted-bundle and caller controls; never build or execute a plugin."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import signal
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / 'scripts/ci/asahi-lsp-offline/run.py').is_file())
spec = importlib.util.spec_from_file_location('rust_run_test', HERE / 'run.py')
r = importlib.util.module_from_spec(spec); spec.loader.exec_module(r)
HELD = r.s.held('run', ROOT / 'scripts/ci/asahi-lsp-offline')
COMMON = r.s.held('container', ROOT / 'scripts/ci/asahi-lsp-offline')
spec = importlib.util.spec_from_file_location('rust_container_fixture', HERE / 'test_container.py')
fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)
TMP = HERE / 'tmp'; TMP.mkdir(exist_ok=True)


class CommandFailure(ValueError):
    def __init__(self, code): self.code = code


class CallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=TMP); self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.args = SimpleNamespace(product=self.base / 'product', desktop=self.base / 'desktop', builder=self.base / 'base',
                                    private=self.base / 'private', output=self.base / 'public')
        (self.base / 'incoming/audio-archives').mkdir(parents=True)
        self.image = 'sha256:' + 'a' * 64
        self.calls = []
        self.api = SimpleNamespace(preflight=lambda _: (self.image, self.base / 'lock'), ordinary=lambda _: None,
                                   module=lambda _: None, command=self.command, CommandFailure=CommandFailure)
        self.held = SimpleNamespace(HERE=HELD.HERE, pair_api=lambda: self.api, cleanup=self.cleanup,
                                   runtime_command=HELD.runtime_command, no_private_values=HELD.no_private_values)

    def cleanup(self, private, _):
        import shutil
        shutil.rmtree(private)
        return {'status': 'PASS', 'private_removed': True, 'builder_image': 'BORROWED-PRESERVED'}

    def report(self):
        inputs = r.s.inputs()['packages']
        candidates = {row['name']: next(x['sha256'] for x in row['payload'] if x['path'] == '/' + row['elf_paths'][0])
                      for row in inputs}
        host = {'sha256': 'a' * 64, 'source_sha256': r.s.sha(HERE / 'host.c'),
                'compiler_sha256': 'b' * 64, 'pkg_config_sha256': 'c' * 64, 'readelf_sha256': 'd' * 64,
                'lilv_pc_sha256': 'e' * 64, 'compile_flags': COMMON.FLAGS + ['-I/usr/include/lilv-0', '-llilv-0', '-ldl', '-lm']}
        elf = {name: {'class': 'ELF64', 'machine': 'AArch64', 'needed': ['libc.so.6'], 'path_tags': [],
                       'version_requirements': ['GLIBC_2.17'], 'sha256': digest, 'load_segments': 4,
                       'structural_16k': 'PASS', 'hardware_status': 'NOT RUN'}
               for name, digest in dict(candidates, host=host['sha256']).items()}
        return {'schema_version': 1, 'status': 'PASS', 'failure_class': None, 'stage': 'complete',
                'inventory': {'count': 574, 'before_sha256': r.s.LOCK, 'after_sha256': r.s.LOCK, 'unchanged': True},
                'headers': {key: row[1] for key, row in COMMON.HEADERS.items()}, 'candidates': candidates,
                'host': host, 'elf': elf, 'processing': fixture.passing(),
                'loader': {row['name']: {'status': 'PASS', 'selected_uris': [uri], 'descriptor_count': 1,
                    'loaded_libraries': [{'identity': 'candidate/' + Path(row['elf_paths'][0]).parent.name + '/' +
                                         Path(row['elf_paths'][0]).name, 'sha256': candidates[row['name']]}]}
                           for row, uri in zip(inputs, r.s.URIS)}}

    def command(self, argv, log, limit):
        self.calls.append((argv, limit)); log.write_text('PRIVATE_DIAGNOSTIC')
        r.s.save(self.args.private / 'runtime/observations.json', self.report())

    def held(self, name, directory=None): return self.held if name == 'run' else COMMON

    def execute(self):
        with patch.object(r.s, 'held', side_effect=lambda name, directory=None: self.held if name == 'run' else COMMON), \
             patch.object(r, 'bundles', side_effect=lambda _, target, *args: target.mkdir() or [{'name': 'inert-fixed-input'}]):
            return r.run(self.args)

    def result(self): return json.loads((self.args.output / 'result.json').read_text())

    def test_exact_one_runtime_zero_builds_and_no_private_output(self):
        self.assertEqual(self.execute(), 0)
        self.assertEqual(len(self.calls), 1); self.assertEqual(self.calls[0][1], 420)
        argv = self.calls[0][0]
        for flag in ('--network=none', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                     '--memory=1g', '--cpus=2', '--pids-limit=128'): self.assertIn(flag, argv)
        self.assertFalse(any('docker.sock' in str(x) or '--device' in str(x) for x in argv))
        self.assertIn('dst=/held,readonly', ' '.join(map(str, argv)))
        self.assertNotIn('build.py', str(argv)); self.assertNotIn('compare.py', str(argv))
        self.assertEqual({p.name for p in self.args.output.iterdir()}, r.s.PUBLIC)
        self.assertNotIn('PRIVATE_DIAGNOSTIC', ''.join(p.read_text() for p in self.args.output.iterdir()))
        self.assertEqual(self.result()['native_rebuilds'], 0); self.assertEqual(self.result()['instances'], 120)
        self.assertFalse(self.args.private.exists())

    def test_nonzero_runtime_preserves_fixed_failure_and_cleans(self):
        def fail(argv, log, limit):
            self.command(argv, log, limit)
            value = self.report(); value.update(status='FAIL', stage='processing', failure_class='host_wet-rms-gate-failed')
            r.s.save(self.args.private / 'runtime/observations.json', value); raise CommandFailure(1)
        self.api.command = fail
        self.assertEqual(self.execute(), 1)
        result = self.result()
        self.assertEqual(result['runtime_failure']['failure_class'], 'host_wet-rms-gate-failed')
        public = json.loads((self.args.output / 'runtime.json').read_text())
        self.assertEqual(set(public), {'schema_version', 'status', 'stage', 'failure_class', 'inventory'})
        self.assertFalse(self.args.private.exists())

    def test_failed_or_changed_runtime_never_retries(self):
        self.api.command = Mock(side_effect=CommandFailure(42))
        self.assertEqual(self.execute(), 1); self.api.command.assert_called_once()
        self.assertEqual(self.result()['child_exit_code'], 42)
        self.assertEqual(self.result()['runtime_failure']['failure_class'], 'unavailable-or-invalid-report')

    def test_host_side_schema_failure_is_fixed_visible_fail_and_still_cleans(self):
        original = self.command
        def malformed(argv, log, limit):
            original(argv, log, limit)
            value = self.report(); value['processing']['cases'][0]['rate_hz'] = 7
            r.s.save(self.args.private / 'runtime/observations.json', value)
        self.api.command = malformed
        self.assertEqual(self.execute(), 1)
        self.assertEqual(self.result()['failed_stage'], 'runtime')
        self.assertEqual(self.result()['error_kind'], 'Failure')
        self.assertEqual(self.result()['runtime_failure'], {'stage': 'projection', 'failure_class': 'case_grid'})
        self.assertFalse(self.args.private.exists())

    def test_final_save_signal_keeps_failure(self):
        original = r.s.save; injected = False
        def save(path, value):
            nonlocal injected
            original(path, value)
            if path.name == 'result.json' and not injected:
                injected = True; signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
        with patch.object(r.s, 'save', side_effect=save): self.assertEqual(self.execute(), 1)
        self.assertTrue(self.result()['cancelled']); self.assertEqual(self.result()['status'], 'FAIL')

    def test_public_projection_refuses_private_text_bad_elf_or_missing_cases(self):
        path = self.base / 'report.json'
        for mutate in (lambda x: x.update(private='/private/path'),
                       lambda x: x['processing']['cases'].pop(),
                       lambda x: x['elf']['host'].update(path_tags=['RPATH']),
                       lambda x: x['host'].update(source_sha256='0' * 64),
                       lambda x: x['inventory'].update(unchanged=False)):
            row = self.report(); mutate(row); r.s.save(path, row)
            with patch.object(r.s, 'held', return_value=COMMON), self.assertRaises((ValueError, COMMON.Failure)):
                r.runtime_report(path, self.held)

    def bundle_fixture(self):
        full = self.base / 'full'; full.mkdir()
        archives = self.base / 'archives'; archives.mkdir()
        rows = copy.deepcopy(r.s.inputs()['packages']); reports = {}
        for row in rows:
            members = {}
            content = {}
            for name in row['directories']:
                members[name] = {'type': '5', 'mode': 0o755, 'uid': 0, 'gid': 0}
            for item in row['payload']:
                name = item['path'].lstrip('/'); raw = b'INERT:' + name.encode(); content[name] = raw
                item['sha256'] = hashlib.sha256(raw).hexdigest()
                members[name] = {'type': '0', 'mode': item['mode'], 'uid': 0, 'gid': 0, 'sha256': item['sha256']}
            for name in ('.PKGINFO', '.BUILDINFO', '.MTREE'):
                members[name] = {'type': '0', 'mode': 0o644, 'uid': 0, 'gid': 0}
            archive = archives / row['filename']
            with tarfile.open(archive, 'w:xz') as stream:
                for name, raw in content.items():
                    entry = tarfile.TarInfo(name); entry.size = len(raw); stream.addfile(entry, io.BytesIO(raw))
            row.update(size=archive.stat().st_size, sha256=r.s.sha(archive))
            reports[archive.name] = {'sha256': row['sha256'], 'metadata': {'.PKGINFO': row['metadata']},
                                     'errors': [], 'members': members, 'elf': {row['elf_paths'][0]: {'errors': []}}}
        raw = json.dumps(rows).encode(); (full / 'audio-inputs.json').write_bytes(raw)
        pins = dict(r.s.inputs(), packages=rows, audio_policy_sha256=hashlib.sha256(raw).hexdigest())
        inspector = r.s.load('rust_inspector_fixture', ROOT / 'scripts/ci/full-development-composition/audio_inputs.py')
        return full, archives, pins, reports, inspector

    def test_two_closed_bundles_copy_only_six_reviewed_files(self):
        full, archives, pins, reports, inspector = self.bundle_fixture()
        checks = SimpleNamespace(package=lambda path: reports[path.name])
        with patch.object(r.s, 'inputs', return_value=pins), patch.object(r.s, 'load', return_value=inspector):
            observed = r.bundles(archives, self.base / 'bundles', checks, full)
        self.assertEqual(len(observed), 2)
        files = [p for p in (self.base / 'bundles').rglob('*') if p.is_file()]
        self.assertEqual(len(files), 6); self.assertEqual(sum(p.suffix == '.so' for p in files), 2)
        self.assertFalse(any('licenses' in str(p) for p in files))

    def test_archive_hash_mismatch_stops_before_package_parser(self):
        full, archives, pins, reports, inspector = self.bundle_fixture()
        pins['packages'][0]['sha256'] = '0' * 64
        (full / 'audio-inputs.json').write_text(json.dumps(pins['packages']))
        pins['audio_policy_sha256'] = r.s.sha(full / 'audio-inputs.json'); checks = SimpleNamespace(package=Mock())
        with patch.object(r.s, 'inputs', return_value=pins), patch.object(r.s, 'load', return_value=inspector), \
             self.assertRaisesRegex(ValueError, 'accepted-package-bytes-differ'):
            r.bundles(archives, self.base / 'bundles', checks, full)
        checks.package.assert_not_called()

    def test_frozen_inspector_refuses_changed_notice_or_extra_payload(self):
        for change in ('notice', 'extra'):
            with self.subTest(change=change):
                with tempfile.TemporaryDirectory(dir=TMP) as tmp:
                    old = self.base; self.base = Path(tmp)
                    full, archives, pins, reports, inspector = self.bundle_fixture()
                    report = reports[pins['packages'][0]['filename']]
                    if change == 'notice': report['members']['usr/share/licenses/bankstown/LICENSE']['sha256'] = '0' * 64
                    else: report['members']['usr/bin/unexpected'] = {'type': '0', 'mode': 0o755, 'sha256': '0' * 64}
                    with patch.object(r.s, 'inputs', return_value=pins), patch.object(r.s, 'load', return_value=inspector), \
                         self.assertRaises(AssertionError):
                        r.bundles(archives, self.base / 'bundles', SimpleNamespace(package=lambda path: reports[path.name]), full)
                    self.base = old


if __name__ == '__main__': unittest.main()

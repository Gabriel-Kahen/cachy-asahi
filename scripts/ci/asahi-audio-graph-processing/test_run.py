"""Inert caller ownership, input and failure controls; no runtime actors."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import signal
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('graph_caller_test', HERE / 'run.py')
r = importlib.util.module_from_spec(spec); spec.loader.exec_module(r)
HELD = r.s.held('run'); COMMON = r.s.held('container')
TMP = HERE / 'tmp'; TMP.mkdir(exist_ok=True)


class CommandFailure(ValueError):
    def __init__(self, code): self.code = code


class CallerTests(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory(dir=TMP); self.addCleanup(t.cleanup); self.base = Path(t.name)
        (self.base / 'incoming/audio-archives').mkdir(parents=True)
        self.args = SimpleNamespace(product=self.base / 'product', desktop=self.base / 'desktop', builder=self.base / 'builder',
                                    private=self.base / 'private', output=self.base / 'public')
        self.api = SimpleNamespace(preflight=lambda _: ('sha256:' + 'a' * 64, self.base / 'lock'), ordinary=lambda _: None,
                                   module=lambda _: None, CommandFailure=CommandFailure, command=Mock())
        self.held = SimpleNamespace(HERE=HELD.HERE, pair_api=lambda: self.api, runtime_command=HELD.runtime_command,
                                   no_private_values=HELD.no_private_values, cleanup=self.cleanup)
        self.report = {'status': 'PASS', 'schema_version': 1, 'adapter': {'sha256':'a'*64}}

    def cleanup(self, private, builds):
        self.assertEqual(builds, []); shutil.rmtree(private)
        return {'status': 'PASS', 'private_removed': True, 'builder_image': 'BORROWED-PRESERVED'}

    def execute(self, prepare=None):
        def prep(_, target, *args):
            target.mkdir(); (target / 'data').mkdir(); return [{'name': 'inert'}]
        with patch.object(r.s, 'held', side_effect=lambda name, directory=None: self.held if name == 'run' else COMMON), \
             patch.object(r, 'prepare_inputs', side_effect=prepare or prep), patch.object(r, 'runtime_report', return_value=self.report):
            return r.run(self.args)

    def result(self): return json.loads((self.args.output / 'result.json').read_text())

    def test_one_isolated_runtime_and_no_build_or_processing_actor(self):
        self.assertEqual(self.execute(), 0)
        self.api.command.assert_called_once(); argv, _, limit = self.api.command.call_args.args
        self.assertEqual(limit, 900)
        for flag in ('--network=none', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                     '--memory=1g', '--cpus=2', '--pids-limit=128'): self.assertIn(flag, argv)
        self.assertIn('dst=/usr/share/asahi-audio,readonly', ' '.join(map(str, argv)))
        self.assertIn('dst=/held,readonly', ' '.join(map(str, argv)))
        self.assertNotIn('docker.sock', str(argv)); self.assertNotIn('--device', str(argv))
        self.assertNotIn('build.py', str(argv)); self.assertNotIn('compare.py', str(argv))
        result = self.result()
        self.assertEqual((result['positive_streams'], result['failure_controls'], result['process_calls']), (16, 8, 2048))
        self.assertEqual(result['native_rebuilds'], 0); self.assertEqual(result['processing'], 'PASS')
        self.assertFalse(self.args.private.exists()); self.assertEqual(set(p.name for p in self.args.output.iterdir()), r.s.PUBLIC)

    def test_native_child_failure_and_original_code_survive_cleanup(self):
        self.api.command.side_effect = CommandFailure(73)
        self.report = {'status': 'FAIL', 'stage': 'cases', 'failure_class': 'host_metadata'}
        self.assertEqual(self.execute(), 1)
        result = self.result(); self.assertEqual(result['child_exit_code'], 73)
        self.assertEqual(result['runtime_failure'], {'stage': 'cases', 'failure_class': 'host_metadata'})
        self.assertEqual(result['cleanup']['status'], 'PASS')

    def test_cancel_before_runtime_cannot_leave_pass_or_run_actor(self):
        self.assertEqual(self.execute(prepare=Mock(side_effect=KeyboardInterrupt())), 1)
        self.api.command.assert_not_called(); self.assertTrue(self.result()['cancelled'])
        self.assertEqual(self.result()['status'], 'FAIL')

    def test_bad_public_projection_does_not_get_credited_from_zero_exit(self):
        with patch.object(r, 'runtime_report', side_effect=ValueError('bad')):
            # execute() owns this patch: explicitly exercise equivalent run setup.
            with patch.object(r.s, 'held', side_effect=lambda name, directory=None: self.held if name == 'run' else COMMON), \
                 patch.object(r, 'prepare_inputs', return_value=[]):
                self.assertEqual(r.run(self.args), 1)
        self.assertEqual(self.result()['status'], 'FAIL')

    def test_late_signal_during_public_write_cannot_leave_pass(self):
        save = r.s.save; handlers = {}; fired = []
        def install(sig, handler):
            old = handlers.get(sig, signal.SIG_DFL); handlers[sig] = handler; return old
        def saving(path, value):
            save(path, value)
            if Path(path) == self.args.output / 'result.json' and not fired:
                fired.append(True); handlers[signal.SIGTERM](signal.SIGTERM, None)
        with patch.object(r.signal, 'signal', side_effect=install), patch.object(r.s, 'save', side_effect=saving):
            self.assertEqual(self.execute(), 1)
        self.assertTrue(self.result()['cancelled']); self.assertEqual(self.result()['status'], 'FAIL')


class ProjectionTests(unittest.TestCase):
    def test_caller_uses_real_complete_contract_and_rejects_corrupt_hash(self):
        spec = importlib.util.spec_from_file_location('graph_public_fixture', HERE / 'test_container.py')
        fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)
        with patch.object(fixture.c, 'common', return_value=COMMON): value = fixture.passing()
        t = tempfile.TemporaryDirectory(dir=TMP); self.addCleanup(t.cleanup)
        path = Path(t.name) / 'runtime.json'; r.s.save(path, value)
        self.assertEqual(r.runtime_report(path, HELD)['status'], 'PASS')
        value['positive_cases'][0]['libraries'][0]['sha256'] = '0' * 64
        r.s.save(path, value)
        with self.assertRaises(COMMON.Failure): r.runtime_report(path, HELD)


class InputTests(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory(dir=TMP); self.addCleanup(t.cleanup); self.base = Path(t.name)
        self.archives = self.base / 'archives'; self.archives.mkdir(); self.full = self.base / 'full'; self.full.mkdir()
        self.data = r.s.graphs(); self.rows = []
        self.names = {c['graph_path'] for c in self.data['cases']} | {f['path'] for f in self.data['firs']}

    def fixture(self, unsafe=None):
        for pkg in ('asahi-audio', 'bankstown', 'triforce-lv2', 'lsp-plugins-lv2'):
            if pkg == 'asahi-audio': names = sorted(self.names)
            elif pkg == 'lsp-plugins-lv2': names = ['usr/lib/lv2/lsp-plugins.lv2/' + str(i) + '.ttl' for i in range(199)] + ['usr/lib/lv2/lsp-plugins.lv2/lsp-plugins-lv2.so', 'usr/lib/lv2/lsp-plugins.lv2/lsp-plugins-lv2ui.so']
            else:
                short = pkg.removesuffix('-lv2'); names = ['usr/lib/lv2/' + short + '.lv2/' + x for x in ('manifest.ttl', short + '.ttl', short + '.so')]
            path = self.archives / (pkg + '.pkg.tar.xz'); rows = []
            with tarfile.open(path, 'w:xz') as t:
                for i, name in enumerate(names):
                    member = tarfile.TarInfo(name); member.size = 5; member.mode = 0o644
                    if unsafe == 'link' and pkg == 'asahi-audio' and i == 0:
                        member.type = tarfile.SYMTYPE; member.linkname = '/outside'; member.size = 0
                    t.addfile(member, io.BytesIO(b'inert'))
                    if unsafe == 'duplicate' and pkg == 'asahi-audio' and i == 0: t.addfile(member, io.BytesIO(b'inert'))
                    rows.append(dict(path='/' + name, mode=0o644, sha256=hashlib.sha256(b'inert').hexdigest()))
            row = dict(name=pkg, version='inert', filename=path.name, size=path.stat().st_size, sha256=r.s.sha(path), payload=rows)
            if pkg == 'lsp-plugins-lv2':
                signature = self.archives / (path.name + '.sig'); signature.write_bytes(b'sig')
                row.update(signature_size=3, signature_sha256=r.s.sha(signature))
            self.rows.append(row)
        policy = self.full / 'audio-inputs.json'; policy.write_text(json.dumps(self.rows))
        return dict(packages=self.rows, audio_policy_sha256=r.s.sha(policy), audio_inputs_helper_sha256='0' * 64)

    def prepare(self, pins):
        with patch.object(r.s, 'inputs', return_value=pins), \
             patch.object(r.s, 'load', return_value=SimpleNamespace(inspect=Mock())):
            return r.prepare_inputs(self.archives, self.base / 'candidate', SimpleNamespace(package=Mock(return_value={})), self.full)

    def test_exact227_selected_files_ui_staged_and_no_install(self):
        rows = self.prepare(self.fixture()); target = self.base / 'candidate'
        self.assertEqual(sum(x['selected_files'] for x in rows), 227)
        self.assertEqual(len([p for p in (target / 'data').rglob('*') if p.is_file()]), 20)
        self.assertTrue((target / 'lv2/lsp-plugins.lv2/lsp-plugins-lv2ui.so').is_file())
        self.assertFalse((target / 'usr').exists())

    def test_symlink_and_duplicate_payload_refuse(self):
        pins = self.fixture(unsafe='link')
        with self.assertRaisesRegex(ValueError, 'unsafe-selected-member'): self.prepare(pins)

    def test_duplicate_member_refuses_even_with_mocked_outer_inspector(self):
        pins = self.fixture(unsafe='duplicate')
        with self.assertRaisesRegex(ValueError, 'unsafe-selected-member'): self.prepare(pins)

    def test_signature_drift_refuses(self):
        pins = self.fixture(); (self.archives / 'lsp-plugins-lv2.pkg.tar.xz.sig').write_bytes(b'bad')
        with self.assertRaisesRegex(ValueError, 'official-signature-pin-differs'): self.prepare(pins)

    def test_archive_drift_refuses(self):
        pins = self.fixture(); (self.archives / self.rows[0]['filename']).write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'accepted-package-bytes-differ'): self.prepare(pins)


if __name__ == '__main__': unittest.main()

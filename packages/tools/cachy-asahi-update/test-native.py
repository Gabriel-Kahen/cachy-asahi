#!/usr/bin/env python3
"""Data-only adapter tests; never launch Docker or invoke a compiler."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tarfile
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

BASE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('updater_native', BASE / 'updater-native.py')
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)

IMAGE = 'sha256:' + 'a' * 64
CONTAINER_ID = 'b' * 64
NONCE = 'c' * 32
CONTROLLER_SHA = 'd' * 64
WORKER_NAME = 'cachy-asahi-updater-' + NONCE


def observed_state(name, image, nonce, controller_sha, raw_path=None):
    return {'schema_version': 1, 'container_id': CONTAINER_ID, 'image_id': image,
            'controller_sha256': controller_sha,
            'name_sha256': hashlib.sha256(name.encode()).hexdigest(),
            'nonce_sha256': hashlib.sha256(nonce.encode()).hexdigest(),
            'status': 'exited', 'running': False, 'paused': False, 'restarting': False,
            'dead': False, 'oom_killed': False, 'exit_code': 0, 'state_error_present': False}


def inspection_row():
    return {'Id': CONTAINER_ID, 'Image': IMAGE, 'Name': '/' + WORKER_NAME,
            'Config': {'Env': ['CACHY_ASAHI_CONTAINER=1', 'CACHY_ASAHI_IMAGE_ID=' + IMAGE,
                              'CACHY_ASAHI_UPDATE_BUILD_NONCE=' + NONCE,
                              'CACHY_ASAHI_CONTROLLER_SHA256=' + CONTROLLER_SHA,
                              'SOURCE_DATE_EPOCH=1789753605', 'PATH=/usr/bin:/bin']},
            'State': {'Status': 'exited', 'Running': False, 'Paused': False,
                      'Restarting': False, 'Dead': False, 'OOMKilled': False,
                      'ExitCode': 0, 'Error': ''}}


class NativeTests(unittest.TestCase):
    def setUp(self):
        # Existing launch tests continue to exercise real parent cleanup while
        # the separately tested inspection boundary never reaches Docker.
        inspection = mock.patch.object(native, 'inspect_worker', side_effect=observed_state, create=True)
        inspection.start()
        self.addCleanup(inspection.stop)

    def inputs(self):
        return (json.loads((native.ROOT / 'scripts/ci/inputs.lock.json').read_bytes()),
                json.loads((native.ROOT / 'scripts/port/updater-extension/builder-extension.lock.json').read_bytes()),
                json.loads((native.ROOT / 'scripts/port/updater-extension/extension-receipt.json').read_bytes()),
                (native.ROOT / 'scripts/port/updater-extension/expected-packages.lock').read_bytes())

    def test_real_pinned_plan_preserves_refreshed_baseline(self):
        real_pinned=native.pinned
        def retained_helper(path, expected):
            if path==native.ROOT/'scripts/ci/native_arm.py':
                return real_pinned(BASE/'fixtures/native-arm-reviewed.py',expected)
            return real_pinned(path,expected)
        with mock.patch.object(native,'pinned',side_effect=retained_helper):
            inputs, expected = native.plan()
        self.assertEqual(len(native.inventory(inputs)), 354)
        original = native.inventory(self.inputs()[0])
        self.assertEqual({k: native.inventory(inputs)[k] for k in original}, original)
        self.assertEqual(hashlib.sha256(expected).hexdigest(), native.PINS['scripts/port/updater-extension/expected-packages.lock'])

    def test_retained_fixture_never_becomes_runtime_fallback(self):
        pin=native.PINS['scripts/ci/native_arm.py']
        fixture=BASE/'fixtures/native-arm-reviewed.py'
        self.assertEqual(native.sha(fixture),pin)
        self.assertEqual(pin,'a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898')
        historical=BASE/'fixtures/native-arm-original.py'
        self.assertEqual(native.sha(historical),'2443ba8a5e7635bbb4d312072c8913a56e06f26764555c7a779533b655982947')
        with self.assertRaisesRegex(ValueError,'frozen input changed'):
            native.pinned(historical,pin)
        with tempfile.TemporaryDirectory() as tmp:
            inflight=Path(tmp)/'native_arm.py'
            inflight.write_bytes(fixture.read_bytes()+b'\n# in-flight helper fixture\n')
            with self.assertRaisesRegex(ValueError,'frozen input changed'):
                native.pinned(inflight,pin)
        self.assertEqual(native.PINS['scripts/ci/inputs.lock.json'],'3c16c37d1b12cc84a88572e82ab8ad59e7f3b5ed0d08f09ddf72a69f4711d650')

    def test_live_plan_uses_authorized_helper_bytes(self):
        # Data reads only: the shared helper is hashed, never imported/executed.
        inputs, expected=native.plan()
        self.assertEqual(len(native.inventory(inputs)),354)
        self.assertEqual(native.sha(native.ROOT/'scripts/ci/native_arm.py'),
                         native.sha(BASE/'fixtures/native-arm-reviewed.py'))
        self.assertEqual(hashlib.sha256(expected).hexdigest(),
                         native.PINS['scripts/port/updater-extension/expected-packages.lock'])

    def test_inputs_are_not_mutated(self):
        values = self.inputs()
        saved = copy.deepcopy(values)
        native.merge(*values)
        self.assertEqual(values, saved)

    def test_extension_replacement_and_receipt_gaps_refused(self):
        for change in ('baseline', 'signer', 'size', 'duplicate', 'receipt', 'conflict', 'missing'):
            base, extension, receipt, expected = self.inputs()
            if change == 'baseline': base['packages'][0]['version'] += '.changed'
            if change == 'signer': extension['signer_fingerprint'] = '0' * 40
            if change == 'size': extension['packages'].pop()
            if change == 'duplicate': extension['packages'][1] = extension['packages'][0]
            if change == 'receipt': receipt['extension_lock_sha256'] = '0' * 64
            if change == 'conflict': receipt['conflicts'] = ['fixture']
            if change == 'missing': receipt['deptest_missing'] = ['fixture']
            with self.subTest(change=change), self.assertRaises(ValueError):
                native.merge(base, extension, receipt, expected)

    def test_frozen_byte_drift_and_symlink_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'input'
            path.write_bytes(b'fixture')
            pin = native.sha(path)
            self.assertEqual(native.pinned(path, pin), b'fixture')
            path.write_bytes(b'drift')
            with self.assertRaises(ValueError): native.pinned(path, pin)
            link = Path(tmp) / 'link'
            link.symlink_to(path)
            with self.assertRaises(ValueError): native.pinned(link, native.sha(path))

    def test_only_native_nonroot_coordinator_can_enter_build(self):
        with mock.patch.object(native.platform, 'machine', return_value='x86_64'), mock.patch.object(native.subprocess, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'native nonroot'):
                native.build(Path('/absent'), 'a'*64, Path('/absent'), Path('/absent'))
            run.assert_not_called()

    def test_effective_identity_must_match_positive_real_identity(self):
        for ids in ((1000, 0, 1000, 1000), (1000, 1000, 1000, 0),
                    (1000, 1001, 1000, 1000), (1000, 1000, 1000, 1001),
                    (0, 0, 1000, 1000), (1000, 1000, 0, 0)):
            with self.subTest(ids=ids), \
                    mock.patch.object(native.platform, 'system', return_value='Linux'), \
                    mock.patch.object(native.platform, 'machine', return_value='aarch64'), \
                    mock.patch.object(native.os, 'getuid', return_value=ids[0]), \
                    mock.patch.object(native.os, 'geteuid', return_value=ids[1]), \
                    mock.patch.object(native.os, 'getgid', return_value=ids[2]), \
                    mock.patch.object(native.os, 'getegid', return_value=ids[3]), \
                    mock.patch.object(native, 'pinned') as pinned, \
                    mock.patch.object(native.subprocess, 'run') as run:
                with self.assertRaisesRegex(ValueError, 'native nonroot'):
                    native.build(Path('/absent'), 'a'*64, Path('/absent'), Path('/absent'))
                pinned.assert_not_called()
                run.assert_not_called()

    def test_signed_archive_tool_hashes_and_aliases_without_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp)
            path = cache / 'fixture.tar.gz'
            with tarfile.open(path, 'w:gz') as archive:
                for tool in native.TOOLS:
                    info = tarfile.TarInfo('usr/bin/' + tool)
                    if tool == 'cc':
                        info.type, info.linkname = tarfile.SYMTYPE, 'gcc'
                        archive.addfile(info)
                    elif tool == 'python':
                        info.type, info.linkname = tarfile.SYMTYPE, '../lib/python-real'
                        archive.addfile(info)
                    else:
                        data = ('fixture:' + tool).encode()
                        info.size = len(data)
                        archive.addfile(info, io.BytesIO(data))
                data = b'fixture:python'
                info = tarfile.TarInfo('usr/lib/python-real');info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
            pins = native.tool_pins({'rootfs': {'filename': path.name, 'sha256': native.sha(path)}, 'packages': []}, cache)
            self.assertEqual(pins['tools']['/usr/bin/cc'], pins['tools']['/usr/bin/gcc'])
            self.assertEqual(pins['tools']['/usr/bin/python']['resolved_path'], '/usr/lib/python-real')
            self.assertEqual(pins['tools']['/usr/bin/python']['sha256'], hashlib.sha256(b'fixture:python').hexdigest())

    def test_launch_refuses_recipe_drift_before_any_docker_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            recipe = root / 'recipe';recipe.mkdir()
            (recipe / 'PKGBUILD').write_text('reviewed')
            approved = native.tree_hashes(recipe)
            entry = root / 'entry';entry.write_text('entry fixture')
            (recipe / 'PKGBUILD').write_text('changed after review')
            with mock.patch.object(native.subprocess, 'run') as run, self.assertRaisesRegex(ValueError, 'recipe changed'):
                native.launch('sha256:' + 'a'*64, recipe, root/'lock', {}, entry,
                              root/'out', None, {}, approved, native.sha(entry))
            run.assert_not_called()

    def test_launch_refuses_recipe_drift_during_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            recipe = root / 'recipe';recipe.mkdir()
            (recipe / 'PKGBUILD').write_text('reviewed')
            approved = native.tree_hashes(recipe)
            entry = root / 'entry';entry.write_text('entry fixture')
            original_copy = native.shutil.copytree
            def changed_copy(source, target):
                original_copy(source, target)
                (target / 'PKGBUILD').write_text('changed while copying')
            with mock.patch.object(native.shutil, 'copytree', side_effect=changed_copy), mock.patch.object(native.subprocess, 'run') as run:
                with self.assertRaisesRegex(ValueError, 'during snapshot'):
                    native.launch('sha256:' + 'a'*64, recipe, root/'lock', {}, entry,
                                  root/'out', None, {}, approved, native.sha(entry))
            run.assert_not_called()

    def test_cleanup_failure_cannot_leave_successful_build_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); recipe = root/'recipe';recipe.mkdir()
            (recipe/'PKGBUILD').write_text('fixture')
            approved = native.tree_hashes(recipe)
            entry = root/'entry';entry.write_text('fixture entry')
            lock = root/'lock';lock.write_bytes(b'fixture 1\n')
            output = root/'output'
            checks = SimpleNamespace(metadata=lambda _: {}, package=lambda _: {'errors': []})
            bind = SimpleNamespace(bind_generated=lambda *_: None, bind_artifact=lambda *_: [])
            def run(command, **kwargs):
                if command[1] == 'run':
                    artifacts = output/'artifacts'
                    (artifacts/'packages.lock').write_bytes(lock.read_bytes())
                    (artifacts/'generated.SRCINFO').write_text('fixture')
                    (artifacts/'fixture.pkg.tar.zst').write_bytes(b'package fixture')
                    return SimpleNamespace(returncode=0)
                raise native.subprocess.TimeoutExpired(command, 60)
            with mock.patch.object(native.subprocess, 'run', side_effect=run), mock.patch.object(native.subprocess, 'check_output', return_value=b'[]'), mock.patch.object(native, 'load_module', return_value=bind):
                with self.assertRaisesRegex(ValueError, 'cleanup failed'):
                    native.launch('sha256:'+'a'*64, recipe, lock, {}, entry, output,
                                  checks, {}, approved, native.sha(entry))
            record = json.loads((output/'provenance.json').read_bytes())
            self.assertEqual(record['native_compilation'], 'FAIL-container-cleanup')
            self.assertIn('TimeoutExpired', record['container_cleanup_error'])

    def test_special_recipe_input_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            (path / 'link').symlink_to('/absent')
            with self.assertRaises(ValueError): native.tree_hashes(path)

    def test_cancellation_during_docker_run_and_cleanup_in_private_process(self):
        # Real signals affect only this private Python fixture; every Docker
        # endpoint and archive check is mocked before launch is called.
        script = '''import importlib.util,json,os,signal,sys
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
p=Path(sys.argv[1]); spec=importlib.util.spec_from_file_location('native',p)
n=importlib.util.module_from_spec(spec); spec.loader.exec_module(n)
signal.signal(signal.SIGTERM,n.cancel)
signal.signal(signal.SIGINT,n.cancel)
root=Path(sys.argv[2]); phase=sys.argv[3]
recipe=root/'recipe';recipe.mkdir();(recipe/'PKGBUILD').write_text('fixture')
entry=root/'entry';entry.write_text('fixture');lock=root/'lock';lock.write_bytes(b'fixture 1\\n')
out=root/'out'
def run(command,**kw):
 if command[1]=='run':
  if phase=='run':os.kill(os.getpid(),signal.SIGTERM)
  a=out/'artifacts';(a/'packages.lock').write_bytes(lock.read_bytes())
  (a/'generated.SRCINFO').write_text('fixture');(a/'fixture.pkg.tar.zst').write_bytes(b'fixture')
 if command[1]=='rm' and phase=='cleanup':os.kill(os.getpid(),signal.SIGTERM)
 if command[1]=='rm' and phase=='inspection-cleanup':os.kill(os.getpid(),signal.SIGINT)
 return SimpleNamespace(returncode=0)
checks=SimpleNamespace(metadata=lambda _: {},package=lambda _: {'errors': []})
bind=SimpleNamespace(bind_generated=lambda *_:None,bind_artifact=lambda *_:[])
def output(command,**kw):return b'' if command[1]=='ps' else b'[]'
def observed(name,image,nonce,controller_sha,raw_path):
 if phase in ('inspection','inspection-cleanup'):os.kill(os.getpid(),signal.SIGTERM)
 return {'schema_version':1,'container_id':'b'*64,'image_id':image,'controller_sha256':controller_sha,'name_sha256':n.hashlib.sha256(name.encode()).hexdigest(),'nonce_sha256':n.hashlib.sha256(nonce.encode()).hexdigest(),'status':'exited','running':False,'paused':False,'restarting':False,'dead':False,'oom_killed':False,'exit_code':0,'state_error_present':False}
with mock.patch.object(n.subprocess,'run',side_effect=run),mock.patch.object(n.subprocess,'check_output',side_effect=output),mock.patch.object(n,'load_module',return_value=bind),mock.patch.object(n,'inspect_worker',side_effect=observed,create=True):
 try:n.launch('sha256:'+'a'*64,recipe,lock,{},entry,out,checks,{},n.tree_hashes(recipe),n.sha(entry))
 except KeyboardInterrupt:pass
 else:raise AssertionError('cancellation did not propagate')
'''
        for phase in ('run', 'cleanup', 'inspection', 'inspection-cleanup'):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as temp:
                process = subprocess.run([sys.executable, '-c', script,
                                          str(BASE / 'updater-native.py'), temp, phase],
                                         capture_output=True, timeout=5)
                self.assertEqual(process.returncode, 0, process.stderr.decode())
                record = json.loads((Path(temp) / 'out/provenance.json').read_bytes())
                self.assertEqual(record['native_compilation'], 'FAIL-container-cleanup' if phase == 'cleanup' else 'FAIL')
                self.assertEqual(record['cancel_signal'], 'SIGTERM')
                self.assertTrue(record['cancelled'])
                self.assertTrue(record['container_absence_verified'])
                self.assertTrue(record['container_cleanup_attempted'])
                self.assertEqual(record['container_removal_succeeded'], phase in ('run', 'inspection'))
                self.assertEqual(record['container_cleanup_complete'], phase in ('run', 'inspection'))
                self.assertEqual(record['stage'], 'finalized')
                if phase.startswith('inspection'):
                    self.assertEqual(record['worker_failure_code'], 'inspection-cancelled')
                    self.assertEqual(record['worker_run_returncode'], 0)

    def test_cleanup_absence_cannot_be_assumed_from_rm_exit(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); recipe = root/'recipe';recipe.mkdir()
            (recipe/'PKGBUILD').write_text('fixture')
            entry = root/'entry';entry.write_text('fixture')
            lock = root/'lock';lock.write_bytes(b'fixture 1\n');out=root/'out'
            checks = SimpleNamespace(metadata=lambda _: {}, package=lambda _: {'errors': []})
            bind = SimpleNamespace(bind_generated=lambda *_:None, bind_artifact=lambda *_:[])
            def run(command, **kwargs):
                if command[1] == 'run':
                    a=out/'artifacts';(a/'packages.lock').write_bytes(lock.read_bytes())
                    (a/'generated.SRCINFO').write_text('fixture')
                    (a/'fixture.pkg.tar.zst').write_bytes(b'fixture')
                return SimpleNamespace(returncode=0)
            with mock.patch.object(native.subprocess, 'run', side_effect=run), \
                    mock.patch.object(native.subprocess, 'check_output', side_effect=lambda cmd, **kw: b'remaining-container\n' if cmd[1] == 'ps' else b'[]'), \
                    mock.patch.object(native, 'load_module', return_value=bind):
                with self.assertRaisesRegex(ValueError, 'cleanup failed'):
                    native.launch('sha256:'+'a'*64,recipe,lock,{},entry,out,checks,{},native.tree_hashes(recipe),native.sha(entry))
            record = json.loads((out/'provenance.json').read_bytes())
            self.assertEqual(record['native_compilation'], 'FAIL-container-cleanup')
            self.assertFalse(record['container_absence_verified'])
            self.assertTrue(record['container_removal_succeeded'])
            self.assertFalse(record['container_cleanup_complete'])

    def test_success_requires_completed_cleanup_and_verified_absence(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);recipe=root/'recipe';recipe.mkdir();(recipe/'PKGBUILD').write_text('fixture')
            entry=root/'entry';entry.write_text('fixture');lock=root/'lock';lock.write_bytes(b'fixture');out=root/'out'
            def run(cmd, **kw):
                if cmd[1] == 'run':
                    a=out/'artifacts';(a/'packages.lock').write_bytes(lock.read_bytes())
                    (a/'generated.SRCINFO').write_text('fixture');(a/'fixture.pkg.tar.zst').write_bytes(b'fixture')
                return SimpleNamespace(returncode=0)
            checks=SimpleNamespace(metadata=lambda _: {},package=lambda _: {'errors': []})
            bind=SimpleNamespace(bind_generated=lambda *_:None,bind_artifact=lambda *_:[])
            with mock.patch.object(native.subprocess,'run',side_effect=run), \
                    mock.patch.object(native.subprocess,'check_output',side_effect=lambda cmd, **kw: b'' if cmd[1]=='ps' else b'[]'), \
                    mock.patch.object(native,'load_module',return_value=bind):
                native.launch('sha256:'+'a'*64,recipe,lock,{},entry,out,checks,{},native.tree_hashes(recipe),native.sha(entry))
            record=json.loads((out/'provenance.json').read_bytes())
            self.assertEqual(record['native_compilation'],'PASS-private-native-package-static-checks')
            self.assertTrue(record['container_cleanup_complete'])
            self.assertTrue(record['container_absence_verified'])

    def test_primary_failure_survives_cleanup_interruption(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);recipe=root/'recipe';recipe.mkdir()
            (recipe/'PKGBUILD').write_text('fixture');entry=root/'entry';entry.write_text('fixture')
            lock=root/'lock';lock.write_bytes(b'fixture');out=root/'out'
            def run(cmd, **kw):
                if cmd[1] == 'run':raise ValueError('original fixture failure')
                raise KeyboardInterrupt()
            with mock.patch.object(native.subprocess, 'run', side_effect=run), \
                    mock.patch.object(native.subprocess, 'check_output', return_value=b''):
                with self.assertRaisesRegex(ValueError, 'original fixture failure'):
                    native.launch('sha256:'+'a'*64,recipe,lock,{},entry,out,None,{},native.tree_hashes(recipe),native.sha(entry))
            record=json.loads((out/'provenance.json').read_bytes())
            self.assertEqual(record['error_type'], 'ValueError')
            self.assertEqual(record['error'], 'original fixture failure')
            self.assertIn('KeyboardInterrupt',record['container_cleanup_error'])
            self.assertEqual(record['native_compilation'], 'FAIL')

    def test_atomic_final_status_cancellation_supersedes_pass(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'result.json';record={'native_pair':'PASS'}
            original=native.save;calls=[]
            def interrupted(path, value):
                original(path,value)
                calls.append(1)
                if len(calls)==1:raise native.BuildCancelled(signal.SIGTERM)
            with mock.patch.object(native,'save',side_effect=interrupted):
                with self.assertRaises(native.BuildCancelled):
                    native.final_status(path,record,'native_pair')
            self.assertEqual(json.loads(path.read_bytes())['native_pair'],'FAIL')
            self.assertFalse(any(Path(temp).glob('.result.json-*')))

    def test_pair_failure_has_terminal_result_without_raw_command_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);recipe=root/'recipe';recipe.mkdir()
            (recipe/'PKGBUILD').write_text('fixture')
            candidate={'adapter_sha256':native.sha(BASE/'updater-native.py'), 'immutable_inputs':native.PINS,
                       'recipe_path':str(recipe),'recipe_input_sha256':native.tree_hashes(recipe),
                       'entry_script_sha256':native.sha(BASE/'native-entry.py')}
            path=root/'candidate.json';native.save(path,candidate)
            error=subprocess.CalledProcessError(9,['secret-vendor-command'],output=b'raw secret output',stderr=b'raw secret stderr')
            bootstrap=SimpleNamespace(probe=lambda _: {'docker_endpoint':'unix:///run/docker.sock'},
                                      audit=mock.Mock(side_effect=error))
            with mock.patch.object(native.platform,'system',return_value='Linux'), \
                    mock.patch.object(native.platform,'machine',return_value='aarch64'), \
                    mock.patch.object(native.os,'getuid',return_value=1000), \
                    mock.patch.object(native.os,'geteuid',return_value=1000), \
                    mock.patch.object(native.os,'getgid',return_value=1000), \
                    mock.patch.object(native.os,'getegid',return_value=1000), \
                    mock.patch.object(native,'plan',return_value=({},b'fixture')), \
                    mock.patch.object(native,'load_module',return_value=bootstrap), \
                    mock.patch.dict(os.environ,{},clear=False):
                with self.assertRaises(subprocess.CalledProcessError) as caught:
                    native.build(path,native.sha(path),root/'cache',root/'out')
                self.assertIs(caught.exception,error)
            data=(root/'out/result.json').read_text();record=json.loads(data)
            self.assertEqual(record['native_pair'],'FAIL')
            self.assertEqual(record['failed_stage'],'input-authentication')
            self.assertEqual(record['stage'],'finalized')
            self.assertNotIn('secret',data)
            self.assertNotIn('DOCKER_HOST',data)

    def test_pair_sigterm_during_probe_writes_fail_result(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);recipe=root/'recipe';recipe.mkdir();(recipe/'PKGBUILD').write_text('fixture')
            candidate={'adapter_sha256':native.sha(BASE/'updater-native.py'), 'immutable_inputs':native.PINS,
                       'recipe_path':str(recipe),'recipe_input_sha256':native.tree_hashes(recipe),
                       'entry_script_sha256':native.sha(BASE/'native-entry.py')}
            path=root/'candidate.json';native.save(path,candidate)
            bootstrap=SimpleNamespace(probe=mock.Mock(side_effect=native.BuildCancelled(signal.SIGTERM)))
            with mock.patch.object(native.platform,'system',return_value='Linux'), \
                    mock.patch.object(native.platform,'machine',return_value='aarch64'), \
                    mock.patch.object(native.os,'getuid',return_value=1000), \
                    mock.patch.object(native.os,'geteuid',return_value=1000), \
                    mock.patch.object(native.os,'getgid',return_value=1000), \
                    mock.patch.object(native.os,'getegid',return_value=1000), \
                    mock.patch.object(native,'plan',return_value=({},b'fixture')), \
                    mock.patch.object(native,'load_module',return_value=bootstrap):
                with self.assertRaises(native.BuildCancelled):
                    native.build(path,native.sha(path),root/'cache',root/'out')
            record=json.loads((root/'out/result.json').read_bytes())
            self.assertEqual(record['native_pair'],'FAIL')
            self.assertTrue(record['cancelled'])
            self.assertEqual(record['cancel_signal'],'SIGTERM')
            self.assertEqual(record['failed_stage'],'native-probe')


class WorkerInspectionTests(unittest.TestCase):
    def parse(self, row=None, raw=None, expected_id=None):
        return native.parse_worker_inspection(
            json.dumps([inspection_row() if row is None else row]).encode() if raw is None else raw,
            WORKER_NAME, IMAGE, NONCE, CONTROLLER_SHA, expected_id)

    def test_valid_inspection_exports_only_bound_finite_state(self):
        row = inspection_row()
        row['Config']['Env'].append('UNRELATED_SECRET=must-stay-private')
        row['State']['Error'] = 'private-path-secret'
        result = self.parse(row)
        expected = observed_state(WORKER_NAME, IMAGE, NONCE, CONTROLLER_SHA)
        expected['state_error_present'] = True
        self.assertEqual(result, expected)
        self.assertNotIn('secret', json.dumps(result))
        self.assertNotIn(WORKER_NAME, json.dumps(result))
        self.assertNotIn(NONCE, json.dumps(result))

    def test_identity_fields_and_expected_id_are_exact(self):
        for field, value in [('Id', None), ('Id', 1), ('Id', 'b' * 63),
                             ('Id', 'B' * 64), ('Image', 'sha256:' + 'f' * 64),
                             ('Image', True), ('Name', '/foreign-worker'), ('Name', None)]:
            row = inspection_row(); row[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.parse(row)
        with self.assertRaises(ValueError) as caught:
            self.parse(expected_id='f' * 64)
        self.assertEqual(caught.exception.code, 'inspection-id-drift')

    def test_env_identity_duplicates_types_and_bounds_refused(self):
        for key in ('CACHY_ASAHI_CONTAINER', 'CACHY_ASAHI_IMAGE_ID',
                    'CACHY_ASAHI_UPDATE_BUILD_NONCE', 'CACHY_ASAHI_CONTROLLER_SHA256',
                    'SOURCE_DATE_EPOCH'):
            row = inspection_row()
            row['Config']['Env'] = [entry for entry in row['Config']['Env'] if not entry.startswith(key + '=')]
            with self.subTest(missing=key), self.assertRaises(ValueError): self.parse(row)
            row['Config']['Env'].append(key + '=wrong')
            with self.subTest(wrong=key), self.assertRaises(ValueError): self.parse(row)
        for entries in (None, 'CACHY_ASAHI_CONTAINER=1', [True],
                        inspection_row()['Config']['Env'] + ['PATH=duplicate'],
                        inspection_row()['Config']['Env'] + ['bad-entry'],
                        inspection_row()['Config']['Env'] + ['X=' + 'a' * 8193],
                        inspection_row()['Config']['Env'] + [f'K{i}=x' for i in range(129)],
                        inspection_row()['Config']['Env'] + [f'K{i}=' + 'a' * 7000 for i in range(10)]):
            row = inspection_row(); row['Config']['Env'] = entries
            with self.subTest(entries_type=type(entries).__name__), self.assertRaises(ValueError): self.parse(row)

    def test_state_boolean_integer_error_and_enum_types_refused(self):
        for field in ('Running', 'Paused', 'Restarting', 'Dead', 'OOMKilled'):
            for value in (0, 1, None, 'false'):
                row = inspection_row(); row['State'][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(ValueError): self.parse(row)
        for field, values in [('ExitCode', (-1, 256, True, None, '0')),
                              ('Status', ('unknown', None, True)), ('Error', (None, True, 'x' * 8193))]:
            for value in values:
                row = inspection_row(); row['State'][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(ValueError): self.parse(row)
        for field in ('State', 'Config'):
            row = inspection_row(); row.pop(field)
            with self.subTest(missing=field), self.assertRaises(ValueError): self.parse(row)

    def test_json_shape_duplicate_depth_node_and_byte_limits(self):
        raw = json.dumps([inspection_row()]).encode()
        duplicate = raw.replace(b'"ExitCode": 0', b'"ExitCode": 0, "ExitCode": 1')
        oversized = raw + b' ' * (1024**2)
        node_row = inspection_row(); node_row['unrelated'] = [0] * 8193
        deep_row = inspection_row(); deep_row['unrelated'] = 0
        deep_raw = json.dumps([deep_row]).encode().replace(b'"unrelated": 0',
                    b'"unrelated": ' + b'[' * 9000 + b'0' + b']' * 9000)
        for value in (b'not-json', b'[]', b'{}', b'[null]', json.dumps([inspection_row()] * 2).encode(),
                      duplicate, oversized, json.dumps([node_row]).encode(), deep_raw):
            with self.subTest(length=len(value)), self.assertRaises(ValueError): self.parse(raw=value)

    def test_unicode_poison_has_typed_finite_failure(self):
        for field in ('env', 'error'):
            row = inspection_row()
            if field == 'env': row['Config']['Env'].append('SECRET=\ud800')
            else: row['State']['Error'] = '\ud800'
            with self.subTest(field=field), self.assertRaises(native.WorkerObservationError): self.parse(row)
        with self.assertRaises(native.WorkerObservationError): self.parse(raw=b'\xff')

    def test_two_queries_use_one_deadline_and_anchor_id(self):
        first = json.dumps([inspection_row()]).encode()
        second_row = inspection_row(); second_row['State']['ExitCode'] = 137
        second_row['State']['OOMKilled'] = True
        second = json.dumps([second_row]).encode()
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / 'inspection.json'
            with mock.patch.object(native, 'capture_inspection', side_effect=[first, second]) as capture:
                result = native.inspect_worker(WORKER_NAME, IMAGE, NONCE, CONTROLLER_SHA, target)
            self.assertEqual(capture.call_count, 2)
            self.assertEqual([call.args[0] for call in capture.call_args_list], [WORKER_NAME] * 2)
            self.assertEqual(capture.call_args_list[0].args[1], capture.call_args_list[1].args[1])
            self.assertTrue(result['oom_killed'])
            self.assertEqual(result['exit_code'], 137)
            self.assertEqual(result['container_id'], CONTAINER_ID)
            self.assertTrue(target.is_file())

    def test_second_id_drift_cannot_publish_state(self):
        first = json.dumps([inspection_row()]).encode()
        row = inspection_row(); row['Id'] = 'f' * 64
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(native, 'capture_inspection', side_effect=[first, json.dumps([row]).encode()]):
            with self.assertRaises(ValueError) as caught:
                native.inspect_worker(WORKER_NAME, IMAGE, NONCE, CONTROLLER_SHA, Path(temporary) / 'raw')
            self.assertEqual(caught.exception.code, 'inspection-id-drift')


class InspectionCaptureTests(unittest.TestCase):
    class PipeProcess:
        """Finite actual read pipe; no executable or child process is created."""
        def __init__(self, data=b'fixture-json', code=0, waits=None):
            read_fd, write_fd = os.pipe()
            try: os.write(write_fd, data)
            finally: os.close(write_fd)
            self.stdout = os.fdopen(read_fd, 'rb')
            self.final_code, self.returncode = code, None
            self.waits = list(waits or [])
            self.terminated = self.killed = False
            self.wait_calls = []
        def poll(self): return self.returncode
        def wait(self, timeout):
            self.wait_calls.append(timeout)
            if self.waits:
                error = self.waits.pop(0)
                if error is not None: raise error
            self.returncode = self.final_code
            return self.returncode
        def terminate(self): self.terminated = True
        def kill(self): self.killed = True

    def capture(self, process, read=None):
        with mock.patch.object(native.subprocess, 'Popen', return_value=process) as popen:
            if read is None:
                data = native.capture_inspection(WORKER_NAME, native.time.monotonic() + 60)
            else:
                with mock.patch.object(native.os, 'read', side_effect=read):
                    data = native.capture_inspection(WORKER_NAME, native.time.monotonic() + 60)
        self.assertEqual(popen.call_args.args[0], ['docker', 'inspect', WORKER_NAME])
        self.assertEqual(popen.call_args.kwargs['stdout'], subprocess.PIPE)
        self.assertEqual(popen.call_args.kwargs['stderr'], subprocess.DEVNULL)
        self.assertTrue(process.stdout.closed)
        return data

    def test_finite_actual_pipe_output_reaped_and_closed(self):
        process = self.PipeProcess()
        self.assertEqual(self.capture(process), b'fixture-json')
        self.assertEqual(process.returncode, 0)
        self.assertEqual(len(process.wait_calls), 1)
        self.assertFalse(process.terminated)

    def test_exact_byte_bound_and_overflow_terminate_without_more_reads(self):
        process = self.PipeProcess(b'x')
        self.assertEqual(len(self.capture(process, [b'x' * 65536] * 16 + [b''])), 1024**2)
        process = self.PipeProcess(b'x')
        reader = mock.Mock(side_effect=[b'x' * 65536] * 17 + [AssertionError('read after bound')])
        with self.assertRaises(ValueError) as caught:
            self.capture(process, reader)
        self.assertEqual(caught.exception.code, 'inspection-output-limit')
        self.assertEqual(reader.call_count, 17)
        self.assertTrue(process.terminated)
        self.assertEqual(process.returncode, 0)
        self.assertTrue(process.stdout.closed)

    def test_failed_command_has_finite_code_and_closed_pipe(self):
        process = self.PipeProcess(code=125)
        with self.assertRaises(ValueError) as caught: self.capture(process)
        self.assertEqual(caught.exception.code, 'inspection-command-failed')
        self.assertTrue(process.stdout.closed)
        self.assertEqual(process.returncode, 125)

    def test_boolean_process_status_cannot_attest_command_success(self):
        for code in (False, True, None, '0'):
            process = self.PipeProcess(code=code)
            with self.subTest(code=code), self.assertRaises(native.WorkerObservationError) as caught:
                self.capture(process)
            self.assertEqual(caught.exception.code, 'inspection-command-failed')
            self.assertTrue(process.stdout.closed)

    def test_expired_after_eof_never_starts_unbounded_normal_wait(self):
        clock = [0]
        process = self.PipeProcess(b'x')
        def eof(_fd, _limit):
            clock[0] = 61
            return b''
        with mock.patch.object(native.time, 'monotonic', side_effect=lambda: clock[0]), \
                mock.patch.object(native.subprocess, 'Popen', return_value=process), \
                mock.patch.object(native.os, 'read', side_effect=eof):
            with self.assertRaises(native.WorkerObservationError) as caught:
                native.capture_inspection(WORKER_NAME, 60)
        self.assertEqual(caught.exception.code, 'inspection-timeout')
        self.assertEqual(process.wait_calls, [1])
        self.assertTrue(process.terminated)
        self.assertTrue(process.stdout.closed)

    def test_expired_deadline_launches_nothing(self):
        with mock.patch.object(native.subprocess, 'Popen') as popen:
            with self.assertRaises(ValueError) as caught:
                native.capture_inspection(WORKER_NAME, native.time.monotonic() - 1)
        self.assertEqual(caught.exception.code, 'inspection-timeout')
        popen.assert_not_called()

    def test_spawn_and_read_io_failures_are_distinct(self):
        with mock.patch.object(native.subprocess, 'Popen', side_effect=OSError(5, 'private fixture')):
            with self.assertRaises(ValueError) as caught:
                native.capture_inspection(WORKER_NAME, native.time.monotonic() + 60)
        self.assertEqual(caught.exception.code, 'inspection-launch-failed')
        process = self.PipeProcess(b'x')
        with self.assertRaises(ValueError) as caught: self.capture(process, [OSError(5, 'private fixture')])
        self.assertEqual(caught.exception.code, 'inspection-io-failed')
        self.assertTrue(process.terminated)
        self.assertTrue(process.stdout.closed)

    def test_wait_timeout_terminates_then_kills_and_reaps(self):
        timeout = subprocess.TimeoutExpired(['docker'], 1)
        process = self.PipeProcess(waits=[timeout, timeout, None])
        with self.assertRaises(ValueError) as caught: self.capture(process)
        self.assertEqual(caught.exception.code, 'inspection-timeout')
        self.assertTrue(process.terminated)
        self.assertTrue(process.killed)
        self.assertEqual(process.wait_calls[-2:], [1, 2])
        self.assertTrue(process.stdout.closed)

    def test_cancellation_preserved_even_if_cleanup_interrupted(self):
        first = native.BuildCancelled(signal.SIGTERM)
        second = native.BuildCancelled(signal.SIGINT)
        process = self.PipeProcess(b'x', waits=[second])
        with self.assertRaises(native.BuildCancelled) as caught: self.capture(process, [first])
        self.assertIs(caught.exception, first)
        self.assertTrue(process.terminated)
        self.assertTrue(process.stdout.closed)

    def test_cleanup_failure_revokes_otherwise_successful_capture(self):
        process = self.PipeProcess()
        stream = process.stdout
        def close():
            stream.close()
            raise OSError(5, 'private close fixture')
        process.stdout = mock.Mock(wraps=stream)
        process.stdout.close.side_effect = close
        with self.assertRaises(ValueError) as caught: self.capture(process)
        self.assertEqual(caught.exception.code, 'inspection-cleanup-failed')
        self.assertTrue(stream.closed)


class ParentWorkerBranchTests(unittest.TestCase):
    def launch(self, code=0, branch=None, state_change=None, observe_error=None, run_error=None, cleanup_error=None):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); recipe = root / 'recipe'; recipe.mkdir()
            (recipe / 'PKGBUILD').write_text('fixture')
            entry = root / 'entry'; entry.write_text('fixture entry')
            lock = root / 'lock'; lock.write_bytes(b'fixture 1\n')
            output = root / 'output'; calls = []; before = []
            def run(argv, **kwargs):
                calls.append(argv[1])
                if argv[1] == 'run':
                    if run_error is not None: raise run_error
                    artifacts = output / 'artifacts'
                    if branch != 'inventory-missing':
                        (artifacts / 'packages.lock').write_bytes(b'wrong\n' if branch == 'inventory-mismatch' else lock.read_bytes())
                    (artifacts / 'generated.SRCINFO').write_text('fixture')
                    (artifacts / 'fixture.pkg.tar.zst').write_bytes(b'fixture package')
                    if branch == 'symlink': (artifacts / 'link').symlink_to('/absent-fixture')
                    return SimpleNamespace(returncode=code)
                if cleanup_error is not None: raise cleanup_error
                return SimpleNamespace(returncode=0)
            def inspect(*args):
                before.append(json.loads((output / 'provenance.json').read_bytes()))
                if observe_error is not None: raise observe_error
                state = observed_state(*args)
                if state_change: state.update(state_change)
                return state
            checks = SimpleNamespace(metadata=lambda _: {}, package=lambda _: {'errors': []})
            binds = SimpleNamespace(bind_generated=lambda *_: None, bind_artifact=lambda *_: [])
            error = None
            with mock.patch.object(native.subprocess, 'run', side_effect=run), \
                    mock.patch.object(native.subprocess, 'check_output', return_value=b''), \
                    mock.patch.object(native, 'inspect_worker', side_effect=inspect), \
                    mock.patch.object(native, 'load_module', return_value=binds):
                try:
                    native.launch(IMAGE, recipe, lock, {}, entry, output, checks, {}, native.tree_hashes(recipe), native.sha(entry))
                except BaseException as caught: error = caught
            return json.loads((output / 'provenance.json').read_bytes()), error, calls, before

    def test_worker_returncode_durably_captured_before_inspection(self):
        for code in (0, 1, 125, 137, -15, -64, 255):
            record, error, calls, before = self.launch(code=code)
            with self.subTest(code=code):
                self.assertEqual(before[0]['worker_run_returncode'], code)
                self.assertEqual(record['worker_run_returncode'], code)
                self.assertEqual(record['worker_check'], 'complete' if code == 0 else 'worker-run-result')
                self.assertEqual(record['worker_failure_code'], None if code == 0 else 'worker-nonzero-returncode')
                self.assertEqual(error is None, code == 0)
                self.assertTrue(record['container_cleanup_complete'])
                self.assertIn('rm', calls)

    def test_invalid_returncodes_never_become_boolean_or_claimed_code(self):
        for code in (True, False, None, '1', 1.0, -65, 256):
            with self.subTest(code=code):
                record, error, calls, before = self.launch(code=code)
                self.assertIsNone(record['worker_run_returncode'])
                self.assertEqual(record['worker_failure_code'], 'worker-returncode-invalid')
                self.assertFalse(before)
                self.assertIsInstance(error, ValueError)
                self.assertTrue(record['container_cleanup_complete'])

    def test_inventory_and_symlink_have_distinct_finite_branches(self):
        for branch, check, failure in [('inventory-missing', 'worker-inventory', 'worker-inventory-unavailable'),
                                       ('inventory-mismatch', 'worker-inventory', 'worker-inventory-mismatch'),
                                       ('symlink', 'worker-artifact-shape', 'worker-output-symlink')]:
            with self.subTest(branch=branch):
                record, error, calls, before = self.launch(branch=branch)
                self.assertEqual(record['worker_check'], check)
                self.assertEqual(record['worker_failure_code'], failure)
                self.assertEqual(record['worker_run_returncode'], 0)
                self.assertTrue(record['container_cleanup_complete'])
                self.assertIsInstance(error, FileNotFoundError if branch == 'inventory-missing' else ValueError)

    def test_success_requires_actual_accepted_container_state(self):
        for change in ({'oom_killed': True}, {'exit_code': 137}, {'running': True},
                       {'paused': True}, {'restarting': True}, {'dead': True},
                       {'state_error_present': True}, {'status': 'created'}):
            with self.subTest(change=change):
                record, error, calls, before = self.launch(state_change=change)
                self.assertEqual(record['worker_failure_code'], 'worker-container-state-unaccepted')
                self.assertEqual(record['worker_run_returncode'], 0)
                self.assertTrue(record['container_cleanup_complete'])
                self.assertIsInstance(error, ValueError)

    def test_inspection_failure_preserves_run_code_and_independent_cleanup(self):
        error = native.WorkerObservationError('container-inspection', 'inspection-id-drift')
        record, caught, calls, before = self.launch(code=125, observe_error=error)
        self.assertEqual(record['worker_failure_code'], 'inspection-id-drift')
        self.assertEqual(record['worker_run_returncode'], 125)
        self.assertIsNone(record['worker_container_state'])
        self.assertEqual(record['error_type'], 'ValueError')
        self.assertIs(caught, error)
        self.assertTrue(record['container_cleanup_complete'])

    def test_worker_launch_exception_has_null_code_and_cleanup(self):
        for error, expected in [(OSError(5, 'fixture'), 'worker-run-launch-failed'),
                                (subprocess.TimeoutExpired(['docker'], 1), 'worker-run-timeout'),
                                (native.BuildCancelled(signal.SIGTERM), 'worker-run-cancelled')]:
            with self.subTest(error=type(error).__name__):
                record, caught, calls, before = self.launch(run_error=error)
                self.assertIsNone(record['worker_run_returncode'])
                self.assertEqual(record['worker_failure_code'], expected)
                self.assertIs(caught, error)
                self.assertTrue(record['container_cleanup_complete'])
                self.assertFalse(before)

    def test_repeated_inspection_and_cleanup_cancellation_preserve_primary(self):
        first = native.BuildCancelled(signal.SIGTERM)
        second = native.BuildCancelled(signal.SIGINT)
        record, caught, calls, before = self.launch(observe_error=first, cleanup_error=second)
        self.assertIs(caught, first)
        self.assertEqual(record['worker_failure_code'], 'inspection-cancelled')
        self.assertEqual(record['worker_run_returncode'], 0)
        self.assertEqual(record['cancel_signal'], 'SIGTERM')
        self.assertTrue(record['cancelled'])
        self.assertTrue(record['container_absence_verified'])
        self.assertFalse(record['container_cleanup_complete'])

    def test_first_finite_observation_failure_cannot_be_replaced(self):
        record = {'worker_check': 'worker-run', 'worker_failure_code': None}
        native.worker_observation_failure(record, native.BuildCancelled(signal.SIGTERM))
        native.worker_observation_failure(record,
            native.WorkerObservationError('container-inspection', 'inspection-id-drift'))
        self.assertEqual(record, {'worker_check': 'worker-run', 'worker_failure_code': 'worker-run-cancelled'})

    def test_observation_failure_survives_build_and_public_projection(self):
        public_spec = importlib.util.spec_from_file_location('native_failure_public', BASE / 'public-evidence.py')
        public = importlib.util.module_from_spec(public_spec); public_spec.loader.exec_module(public)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); recipe = root / 'recipe'; recipe.mkdir()
            (recipe / 'PKGBUILD').write_text('fixture')
            approved = native.tree_hashes(recipe)
            candidate = {'adapter_sha256': native.sha(BASE / 'updater-native.py'), 'immutable_inputs': native.PINS,
                         'recipe_path': str(recipe), 'recipe_input_sha256': approved,
                         'entry_script_sha256': native.sha(BASE / 'native-entry.py')}
            path = root / 'candidate.json'; native.save(path, candidate)
            output = root / 'out'; expected = b'fixture 1\n'
            def image_build(_inputs, _cache, out, _extra):
                (out / 'packages.lock').write_bytes(expected)
                return IMAGE
            bootstrap = SimpleNamespace(probe=lambda _: {'docker_endpoint': 'unix:///run/docker.sock'},
                                        audit=lambda *_: None, build=image_build)
            checks = SimpleNamespace(recipe=lambda _: {'errors': [], 'input_sha256': approved, 'metadata': {}})
            def module(name, _path):
                return bootstrap if name == 'updater_native_bootstrap' else checks
            def run(argv, **_kwargs):
                return SimpleNamespace(returncode=125 if argv[1] == 'run' else 0)
            actual_stat = Path.stat
            def stat(path, *args, **kwargs):
                value = actual_stat(path, *args, **kwargs)
                if path == root / 'cache':
                    fields = list(value); fields[4] = 1000
                    return os.stat_result(fields)
                return value
            with mock.patch.object(native.platform, 'system', return_value='Linux'), \
                    mock.patch.object(native.platform, 'machine', return_value='aarch64'), \
                    mock.patch.object(native.os, 'getuid', return_value=1000), \
                    mock.patch.object(native.os, 'geteuid', return_value=1000), \
                    mock.patch.object(native.os, 'getgid', return_value=1000), \
                    mock.patch.object(native.os, 'getegid', return_value=1000), \
                    mock.patch.object(native.Path, 'stat', stat), \
                    mock.patch.object(native, 'plan', return_value=({}, expected)), \
                    mock.patch.object(native, 'tool_pins', return_value={}), \
                    mock.patch.object(native, 'load_module', side_effect=module), \
                    mock.patch.object(native, 'inspect_worker', side_effect=observed_state), \
                    mock.patch.object(native.subprocess, 'run', side_effect=run), \
                    mock.patch.object(native.subprocess, 'check_output', return_value=b''), \
                    mock.patch.dict(os.environ, {}, clear=False):
                with self.assertRaises(native.WorkerObservationError) as caught:
                    native.build(path, native.sha(path), root / 'cache', output)
            self.assertEqual(caught.exception.code, 'worker-nonzero-returncode')
            result = json.loads((output / 'result.json').read_bytes())
            worker = json.loads((output / 'build-1/provenance.json').read_bytes())
            projected_result, projected_worker = public.native_result(result), public.provenance(worker)
            self.assertEqual(projected_result['native_pair'], 'FAIL')
            self.assertEqual(projected_result['failed_stage'], 'worker-1')
            self.assertEqual(projected_result['error_type'], 'ValueError')
            self.assertEqual(projected_worker['error_type'], 'ValueError')
            self.assertEqual(projected_worker['worker_run_returncode'], 125)
            self.assertEqual(projected_worker['worker_failure_code'], 'worker-nonzero-returncode')
            self.assertTrue(projected_worker['container_cleanup_complete'])


if __name__ == '__main__':
    unittest.main()

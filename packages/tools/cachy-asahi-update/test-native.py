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


def synthetic_diagnostic_capture(artifacts, recipe, expected_recipe, provenance):
    """Synthetic bound success isolates legacy parent/package/cleanup gates."""
    value = dict(schema_version=1, controller_sha256=provenance['controller_sha256'],
        image_id=provenance['image_id'], entry_script_sha256=provenance['entry_script_sha256'],
        controller_validated=True, status='PASS', operation='complete', first_failure=None,
        command=None, compiler_launch_attempted=True, compiler_return_observed=True,
        compiler_returncode=0, compilation_accepted=True, cancelled=False,
        diagnostic_write_failed=False, publication='NOT ACCEPTED', hardware='NOT RUN')
    checksum = hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()
    return dict(worker_diagnostic_status='BOUND', worker_diagnostic_reason='bound',
                worker_diagnostic_sha256=checksum, worker_diagnostic=value), True


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
        # Diagnostic capture is synthetic here; actual capture has its own lane.
        capture = mock.patch.object(native, 'capture_worker_diagnostic',
                                    side_effect=synthetic_diagnostic_capture, create=True)
        capture.start(); self.addCleanup(capture.stop)

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
def synthetic_capture(artifacts,recipe,expected,provenance):
 # Synthetic bound success isolates the original real signal/cleanup branch.
 value=dict(schema_version=1,controller_sha256=provenance['controller_sha256'],image_id=provenance['image_id'],entry_script_sha256=provenance['entry_script_sha256'],controller_validated=True,status='PASS',operation='complete',first_failure=None,command=None,compiler_launch_attempted=True,compiler_return_observed=True,compiler_returncode=0,compilation_accepted=True,cancelled=False,diagnostic_write_failed=False,publication='NOT ACCEPTED',hardware='NOT RUN')
 return dict(worker_diagnostic_status='BOUND',worker_diagnostic_reason='bound',worker_diagnostic_sha256=n.hashlib.sha256(json.dumps(value).encode()).hexdigest(),worker_diagnostic=value),True
with mock.patch.object(n.subprocess,'run',side_effect=run),mock.patch.object(n.subprocess,'check_output',side_effect=output),mock.patch.object(n,'load_module',return_value=bind),mock.patch.object(n,'inspect_worker',side_effect=observed,create=True),mock.patch.object(n,'capture_worker_diagnostic',side_effect=synthetic_capture,create=True):
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
                    mock.patch.object(native, 'load_module', return_value=binds), \
                    mock.patch.object(native, 'capture_worker_diagnostic', side_effect=synthetic_diagnostic_capture, create=True):
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


class ParentDiagnosticCaptureTests(unittest.TestCase):
    """Actual captured source/record gate with synthetic Docker and package actors."""
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('parent_actual_diagnostic', BASE/'worker-diagnostic.py')
        cls.diagnostic = importlib.util.module_from_spec(spec); spec.loader.exec_module(cls.diagnostic)

    def launch(self, case='complete', code=0, cleanup=False, package=False, late=False, capture_cancel=False, state_change=None):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); recipe = root/'recipe'; recipe.mkdir()
            (recipe/'PKGBUILD').write_bytes(b'fixture recipe')
            source = (BASE/'public-evidence.py').read_bytes()
            if case == 'source-import': source += b'\nimport socket\n'
            (recipe/'public-evidence.py').write_bytes(source)
            entry = root/'entry'; entry.write_bytes(b'fixture entry; never executed')
            lock = root/'lock'; lock.write_bytes(b'base 1\n')
            output = root/'output'; calls, reads, captured, originals = [], [], [], []
            expected = native.tree_hashes(recipe)
            def run(argv, **kwargs):
                calls.append(list(argv))
                if argv[1] == 'run':
                    artifacts = output/'artifacts'
                    controller = json.loads((output/'inputs/controller-input.json').read_bytes())
                    recorder = self.diagnostic.Recorder(artifacts, bindings={
                        'controller_sha256':native.sha(output/'inputs/controller-input.json'),
                        'image_id':controller['image_id'], 'entry_script_sha256':controller['entry_script_sha256']})
                    recorder.controller_validated()
                    if case == 'known':
                        with recorder.step('metadata-source'):
                            recorder.fail('source-pins', ValueError('PRIVATE_INNER_FAILURE'))
                    else:
                        recorder.command_start('cargo-build')
                        recorder.command_result('cargo-build', True, True, 0)
                        recorder.compiler_accepted(); recorder.finish(True)
                    path = artifacts/'worker-diagnostic.json'
                    original = path.read_bytes(); originals.append(original)
                    row = self.diagnostic.loads(original)
                    if case == 'missing': path.unlink()
                    elif case == 'oversize': path.write_bytes(b'x'*4097)
                    elif case == 'invalid': row['PRIVATE_SUBJECT']='secret'; path.write_text(json.dumps(row))
                    elif case == 'unbound': row['controller_sha256']='f'*64; path.write_text(json.dumps(row))
                    elif case == 'entry-unbound': row['entry_script_sha256']='f'*64; path.write_text(json.dumps(row))
                    elif case == 'source-drift': (output/'inputs/recipe/public-evidence.py').write_bytes(source+b'\n# drift\n')
                    elif case == 'source-link':
                        target=output/'inputs/recipe/public-evidence.py';target.unlink();target.symlink_to(BASE/'public-evidence.py')
                    elif case == 'record-link':
                        saved=root/'external-record';saved.write_bytes(path.read_bytes());path.unlink();path.symlink_to(saved)
                    elif case in ('not-accepted', 'no-launch', 'cancelled', 'write-failed', 'running'):
                        if case == 'not-accepted': row['compilation_accepted']=False
                        if case == 'no-launch':
                            row.update(compiler_launch_attempted=False, compiler_return_observed=False,
                                       compiler_returncode=None, compilation_accepted=False)
                        if case == 'cancelled': row.update(status='CANCELLED', cancelled=True)
                        if case == 'write-failed': row.update(status='FAIL', diagnostic_write_failed=True)
                        if case == 'running': row['status']='RUNNING'
                        path.write_bytes(self.diagnostic.encoded(row))
                    (artifacts/'packages.lock').write_bytes(lock.read_bytes())
                    (artifacts/'generated.SRCINFO').write_bytes(b'fixture SRCINFO')
                    (artifacts/'fixture.pkg.tar.zst').write_bytes(b'fixture package')
                    return SimpleNamespace(returncode=code)
                if cleanup: raise OSError('synthetic cleanup failure')
                return SimpleNamespace(returncode=0)
            def inspect(name, image, nonce, controller_sha, raw_path):
                reads.append('inspection')
                state = observed_state(name, image, nonce, controller_sha, raw_path)
                state['exit_code']=code if code >= 0 else 1
                if state_change: state.update(state_change)
                return state
            actual_capture = native.capture_worker_diagnostic
            def capture(artifacts, copied_recipe, approved, provenance):
                reads.append('diagnostic')
                if capture_cancel: raise native.BuildCancelled(signal.SIGTERM)
                result = actual_capture(artifacts, copied_recipe, approved, provenance)
                captured.append(copy.deepcopy(result))
                if late:
                    # A later complete file may never promote the captured UNKNOWN.
                    (root/'late').mkdir(mode=0o700)
                    recorder = self.diagnostic.Recorder(root/'late', bindings={
                        'controller_sha256':provenance['controller_sha256'], 'image_id':provenance['image_id'],
                        'entry_script_sha256':provenance['entry_script_sha256']})
                    value = recorder.snapshot(); value.update(controller_validated=True, status='PASS',
                        operation='complete', compiler_launch_attempted=True, compiler_return_observed=True,
                        compiler_returncode=0, compilation_accepted=True)
                    (artifacts/'worker-diagnostic.json').write_bytes(self.diagnostic.encoded(value))
                return result
            checks = SimpleNamespace(metadata=lambda _: {}, package=lambda _: {'errors':['package gate'] if package else []})
            binds = SimpleNamespace(bind_generated=lambda *_:None, bind_artifact=lambda *_:[])
            error = None
            with mock.patch.object(native.subprocess,'run',side_effect=run), \
                    mock.patch.object(native.subprocess,'check_output',return_value=b'') as queries, \
                    mock.patch.object(native,'inspect_worker',side_effect=inspect), \
                    mock.patch.object(native,'capture_worker_diagnostic',side_effect=capture) as capture_mock, \
                    mock.patch.object(native,'diagnostic_bytes',wraps=native.diagnostic_bytes) as bytes_read, \
                    mock.patch.object(native,'load_module',return_value=binds):
                try:
                    native.launch(IMAGE,recipe,lock,{},entry,output,checks,{},expected,native.sha(entry))
                except BaseException as caught: error=caught
            record = json.loads((output/'provenance.json').read_bytes())
            # Capture adds no Docker commands; original inspection actor is stubbed.
            self.assertEqual([argv[1] for argv in calls], ['run','rm'])
            self.assertEqual(queries.call_count,1)
            self.assertEqual(queries.call_args.args[0][:3], ['docker','ps','--all'])
            self.assertEqual(reads, ['inspection','diagnostic'])
            self.assertEqual(capture_mock.call_count,1)
            names = [item.args[1] for item in bytes_read.call_args_list]
            self.assertEqual(names.count('public-evidence.py'),0 if capture_cancel else 1)
            self.assertEqual(names.count('worker-diagnostic.json'),
                0 if capture_cancel or case in {'source-drift','source-link','source-import'} else 1)
            if case == 'complete' and not capture_cancel:
                self.assertEqual(record['worker_diagnostic_sha256'],hashlib.sha256(originals[0]).hexdigest())
            return record, error, captured

    def test_complete_bound_record_required_before_original_package_acceptance(self):
        record,error,captured=self.launch()
        self.assertIsNone(error)
        self.assertEqual(record['worker_diagnostic_status'],'BOUND')
        self.assertEqual(record['worker_diagnostic_reason'],'bound')
        self.assertEqual(record['worker_check'],'complete')
        self.assertTrue(captured[0][1])
        self.assertTrue(record['container_cleanup_complete'])

    def test_nonzero_keeps_bound_known_inner_cause_before_original_refusal(self):
        record,error,captured=self.launch(case='known',code=1)
        self.assertEqual(error.code,'worker-nonzero-returncode')
        self.assertEqual(record['worker_diagnostic_status'],'BOUND')
        self.assertEqual(record['worker_diagnostic']['first_failure']['predicate'],'source-pins')
        self.assertFalse(captured[0][1])
        self.assertEqual(record['worker_run_returncode'],1)
        self.assertTrue(record['container_cleanup_complete'])

    def test_unknown_diagnostics_never_promote_zero_return(self):
        for case,reason in [('missing','missing'),('oversize','unavailable'),('invalid','invalid'),
                            ('unbound','unbound'),('entry-unbound','unbound'),('source-drift','source-invalid'),
                            ('source-link','source-invalid'),('source-import','source-invalid'),('record-link','unavailable')]:
            with self.subTest(case=case):
                record,error,captured=self.launch(case=case)
                self.assertEqual(error.code,'worker-diagnostic-incomplete')
                self.assertEqual(record['worker_diagnostic_status'],'UNKNOWN')
                self.assertEqual(record['worker_diagnostic_reason'],reason)
                self.assertIsNone(record['worker_diagnostic'])
                self.assertFalse(captured[0][1])
                self.assertTrue(record['container_cleanup_complete'])

    def test_missing_nonzero_record_keeps_original_outer_failure(self):
        record,error,captured=self.launch(case='missing',code=1)
        self.assertEqual(error.code,'worker-nonzero-returncode')
        self.assertEqual(record['worker_diagnostic_status'],'UNKNOWN')
        self.assertEqual(record['worker_diagnostic_reason'],'missing')

    def test_incomplete_cancelled_or_write_failed_bound_record_never_promotes(self):
        for case in ('not-accepted','no-launch','cancelled','write-failed','running'):
            with self.subTest(case=case):
                record,error,captured=self.launch(case=case)
                self.assertEqual(error.code,'worker-diagnostic-incomplete')
                self.assertEqual(record['worker_diagnostic_status'],'BOUND')
                self.assertFalse(captured[0][1])
                self.assertEqual(record['native_compilation'],'FAIL')

    def test_later_complete_bytes_cannot_replace_once_captured_missing(self):
        record,error,captured=self.launch(case='missing',late=True)
        self.assertEqual(error.code,'worker-diagnostic-incomplete')
        self.assertEqual(record['worker_diagnostic_status'],'UNKNOWN')
        self.assertEqual(record['worker_diagnostic_reason'],'missing')
        self.assertIsNone(record['worker_diagnostic_sha256'])

    def test_capture_control_cancellation_is_preserved_with_cleanup(self):
        record,error,captured=self.launch(capture_cancel=True)
        self.assertIsInstance(error,native.BuildCancelled)
        self.assertTrue(record['cancelled'])
        self.assertEqual(record['native_compilation'],'FAIL')
        self.assertTrue(record['container_cleanup_complete'])
        self.assertEqual(record['worker_diagnostic_status'],'UNKNOWN')

    def test_bound_record_cannot_bypass_original_package_or_cleanup_failure(self):
        for options in ({'package':True},{'cleanup':True}):
            with self.subTest(options=options):
                record,error,captured=self.launch(**options)
                self.assertEqual(record['worker_diagnostic_status'],'BOUND')
                self.assertTrue(captured[0][1])
                self.assertIsInstance(error,ValueError)
                self.assertTrue(record['native_compilation'].startswith('FAIL'))


    def test_bound_complete_diagnostic_never_overrides_observed_state_flags(self):
        for change in ({'oom_killed':True}, {'state_error_present':True}, {'dead':True}):
            with self.subTest(change=change):
                record,error,captured=self.launch(state_change=change)
                self.assertTrue(captured[0][1])
                self.assertEqual(record['worker_diagnostic_status'],'BOUND')
                self.assertEqual(error.code,'worker-container-state-unaccepted')
                self.assertTrue(record['container_cleanup_complete'])


class EntryDiagnosticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for name, filename in [('entry', 'native-entry.py'), ('diagnostic', 'worker-diagnostic.py')]:
            spec = importlib.util.spec_from_file_location('entry_test_' + name, BASE / filename)
            value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
            setattr(cls, name, value)

    def fixture(self, case):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        root = Path(temporary.name); out = root / 'out'; out.mkdir(mode=0o700)
        recipe = root / 'recipe'; recipe.mkdir(); (recipe / '.SRCINFO').write_bytes(b'pkgbase = fixture\n')
        lock = root / 'expected'; lock.write_bytes(b'base 1\n')
        for name in ('makepkg.conf', 'pacman.conf'):
            (root / name).write_text('fixture')
        mappings = {'/out': out, '/tmp/work': root / 'work', '/tmp/build-home': root / 'home',
                    '/expected-packages.lock': lock, '/inputs/recipe': recipe,
                    '/etc/makepkg.conf': root / 'makepkg.conf', '/etc/pacman.conf': root / 'pacman.conf'}
        def path(value): return mappings.get(str(value), Path(value))
        original_copytree, original_copyfile = self.entry.shutil.copytree, self.entry.shutil.copyfile
        def copytree(src, dst): return original_copytree(path(src), path(dst))
        def copyfile(src, dst, **options): return original_copyfile(path(src), path(dst), **options)
        worker = SimpleNamespace()
        worker.set_diagnostic = lambda value: setattr(worker, 'diagnostic', value)
        def observe():
            if case == 'observe': raise OSError('PRIVATE_SUBJECT_ERROR')
            return {'image_id': IMAGE, 'nonce': NONCE}
        worker.observe = observe
        worker.guard = lambda facts: None
        worker.verify_controller = lambda *args: {'image_id': IMAGE}
        calls = []
        def run(argv, cwd, env, output, stem, **options):
            calls.append((list(argv), stem, options))
            recorder = worker.diagnostic; recorder.command_start(stem)
            data = b'base 1\n' if stem == 'inventory-entry' else b'pkgbase = fixture\n' if stem == 'srcinfo' else b''
            if case == 'inventory' and stem == 'inventory-entry': data = b'different 2\n'
            if case == 'srcinfo' and stem == 'srcinfo': data = b'pkgbase = changed\n'
            if stem == 'makepkg' and case in {'nested', 'unknown', 'cancel'}:
                if case == 'nested':
                    child = self.diagnostic.Recorder(out, recorder.bindings)
                    with child.step('metadata-source'):
                        error = ValueError('PRIVATE_CHILD_SOURCE_ERROR')
                        child.fail('source-pins', error)
                error = KeyboardInterrupt() if case == 'cancel' else ValueError('PRIVATE_MAKEPKG_ERROR')
                recorder.command_result(stem, True, case != 'cancel', None if case == 'cancel' else 1,
                                        failure_code='UNKNOWN', error=error)
                raise error
            (output / (stem + '.stdout')).write_bytes(data)
            (output / (stem + '.stderr')).write_bytes(b'PRIVATE_STDERR_PAYLOAD')
            recorder.command_result(stem, True, True, 0)
            if stem == 'makepkg' and case == 'success':
                (cwd / 'fixture.pkg.tar.zst').write_bytes(b'fixture bytes, no real package')
            return data
        worker.run = run
        helper = SimpleNamespace(Recorder=lambda **kw: self.diagnostic.Recorder(out, **kw),
            binding_values=lambda entry_path: {'controller_sha256': CONTROLLER_SHA,
                'image_id': IMAGE, 'entry_script_sha256': hashlib.sha256((BASE / 'native-entry.py').read_bytes()).hexdigest()})
        def loaded(name, filename):
            if 'diagnostic' in name: return helper
            if case == 'import': raise ValueError('PRIVATE_IMPORT_ERROR')
            return worker
        patches = [mock.patch.object(self.entry, 'Path', side_effect=path),
                   mock.patch.object(self.entry, 'module', side_effect=loaded),
                   mock.patch.object(self.entry.shutil, 'copytree', side_effect=copytree),
                   mock.patch.object(self.entry.shutil, 'copyfile', side_effect=copyfile),
                   mock.patch.dict(os.environ, {'CACHY_ASAHI_CONTROLLER_SHA256': CONTROLLER_SHA})]
        for item in patches: item.start(); self.addCleanup(item.stop)
        return out, calls

    def failed(self, case, exception=ValueError):
        out, calls = self.fixture(case)
        with self.assertRaises(exception): self.entry.main()
        value = self.diagnostic.loads((out / 'worker-diagnostic.json').read_bytes())
        self.assertNotIn('PRIVATE_', json.dumps(value))
        self.assertFalse((out / 'entry-result.json').exists())
        self.assertFalse(value['compilation_accepted'])
        return value, calls

    def test_failure_before_metadata_import_is_recorded(self):
        value, calls = self.failed('import')
        self.assertEqual(value['first_failure']['operation'], 'entry-worker-import')
        self.assertEqual(value['first_failure']['predicate'], 'UNKNOWN')
        self.assertFalse(value['controller_validated']); self.assertFalse(calls)

    def test_observation_failure_preserves_error_kind_without_subject_text(self):
        value, calls = self.failed('observe', OSError)
        self.assertEqual(value['first_failure']['operation'], 'entry-observe')
        self.assertEqual(value['first_failure']['error_kind'], 'OSError')
        self.assertFalse(calls)

    def test_original_inventory_and_srcinfo_predicates_remain_required(self):
        # Each fixture is separate; no helper/worker/bootstrap actor is genuine.
        value, calls = self.failed('inventory')
        self.assertEqual(value['first_failure']['predicate'], 'entry-inventory')
        self.assertEqual([item[1] for item in calls], ['inventory-entry'])

    def test_original_srcinfo_predicate_is_not_promoted(self):
        value, calls = self.failed('srcinfo')
        self.assertEqual(value['first_failure']['predicate'], 'entry-srcinfo')
        self.assertEqual([item[1] for item in calls], ['inventory-entry', 'srcinfo'])

    def test_nested_first_failure_is_not_replaced_by_makepkg_or_finally(self):
        value, calls = self.failed('nested')
        self.assertEqual(value['first_failure']['predicate'], 'source-pins')
        self.assertEqual(value['first_failure']['operation'], 'metadata-source')
        self.assertFalse(value['compiler_launch_attempted'])

    def test_uninstrumented_makepkg_failure_remains_unknown(self):
        value, calls = self.failed('unknown')
        self.assertEqual(value['first_failure']['predicate'], 'UNKNOWN')
        self.assertEqual(value['first_failure']['command']['returncode'], 1)
        self.assertFalse(value['compiler_launch_attempted'])

    def test_cancelled_command_does_not_invent_return_or_compiler_attempt(self):
        value, calls = self.failed('cancel', KeyboardInterrupt)
        self.assertEqual(value['status'], 'CANCELLED'); self.assertTrue(value['cancelled'])
        self.assertIsNone(value['first_failure']['command']['returncode'])
        self.assertFalse(value['first_failure']['command']['return_observed'])
        self.assertFalse(value['compiler_launch_attempted'])

    def test_package_count_gate_is_still_required(self):
        value, calls = self.failed('package')
        self.assertEqual(value['first_failure']['predicate'], 'entry-package-count')

    def test_entry_success_keeps_original_commands_and_is_not_compile_proof(self):
        out, calls = self.fixture('success'); self.entry.main()
        value = self.diagnostic.loads((out / 'worker-diagnostic.json').read_bytes())
        self.assertEqual(value['status'], 'PASS'); self.assertIsNone(value['first_failure'])
        self.assertTrue((out / 'entry-result.json').exists())
        self.assertFalse(value['compiler_launch_attempted']); self.assertFalse(value['compilation_accepted'])
        self.assertEqual([item[1] for item in calls], ['inventory-entry', 'srcinfo', 'source-verification', 'makepkg'])
        self.assertEqual(calls[-2][0], ['/usr/bin/makepkg', '--verifysource', '--nodeps', '--noconfirm'])
        self.assertEqual(calls[-1][0], ['/usr/bin/makepkg', '--cleanbuild', '--clean', '--force', '--log', '--nodeps', '--noconfirm'])
        self.assertEqual(calls[-2][2], {'timeout': 120}); self.assertEqual(calls[-1][2], {'timeout': 1500})


class DiagnosticCorrectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('corrected_diagnostic', BASE/'worker-diagnostic.py')
        cls.helper = importlib.util.module_from_spec(spec); spec.loader.exec_module(cls.helper)

    def fixture(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        root = Path(temporary.name); out = root/'out'; out.mkdir(mode=0o700)
        recorder = self.helper.Recorder(out, dict(controller_sha256=CONTROLLER_SHA,
            image_id=IMAGE, entry_script_sha256='c'*64))
        return root, out, recorder

    def test_issued_return_and_first_cause_precede_log_interruption(self):
        for control in (KeyboardInterrupt(), SystemExit(4)):
            with self.subTest(control=type(control).__name__):
                _, out, recorder = self.fixture(); recorder.operation='entry-makepkg'
                with mock.patch.object(recorder, '_logs', side_effect=control):
                    with self.assertRaises(type(control)) as caught:
                        recorder.command_result('makepkg', True, True, 7,
                            failure_code='UNKNOWN', error=ValueError('private cause'))
                self.assertIs(caught.exception, control)
                value=self.helper.loads((out/'worker-diagnostic.json').read_bytes())
                self.assertEqual(value, recorder.snapshot())
                self.assertTrue(value['cancelled']); self.assertEqual(value['status'],'CANCELLED')
                self.assertEqual(value['first_failure']['error_kind'],'ValueError')
                self.assertEqual(value['first_failure']['command']['returncode'],7)
                self.assertTrue(value['first_failure']['command']['return_observed'])

    def test_final_root_close_failure_revokes_durable_pass(self):
        _, out, recorder=self.fixture(); recorder.controller_validated()
        root_method=recorder._root; close=self.helper.os.close; roots=[]; fired=[]
        def root():
            result=root_method(); roots.append(result[0]); return result
        def closing(fd):
            close(fd)
            if roots and fd==roots[0] and not fired:
                fired.append(True); raise OSError('private final close')
        with mock.patch.object(recorder,'_root',side_effect=root), \
                mock.patch.object(self.helper.os,'close',side_effect=closing):
            recorder.finish(True)
        self.assertTrue(fired); self.assertFalse((out/'worker-diagnostic.json').exists())
        self.assertEqual(recorder.snapshot()['status'],'FAIL')
        self.assertTrue(recorder.snapshot()['diagnostic_write_failed'])
        recorder.finish(False)
        self.assertEqual(self.helper.loads((out/'worker-diagnostic.json').read_bytes())['status'],'FAIL')

    def test_final_close_control_is_latched_and_propagated_without_replacing_business(self):
        _, out, recorder=self.fixture(); recorder.fail('source-pins',ValueError('private source'))
        first=recorder.snapshot()['first_failure']; root_method=recorder._root
        close=self.helper.os.close; roots=[]; fired=[]; control=KeyboardInterrupt()
        def root():
            result=root_method(); roots.append(result[0]); return result
        def closing(fd):
            close(fd)
            if roots and fd==roots[0] and not fired:
                fired.append(True); raise control
        with mock.patch.object(recorder,'_root',side_effect=root), \
                mock.patch.object(self.helper.os,'close',side_effect=closing):
            with self.assertRaises(KeyboardInterrupt) as caught: recorder.finish(False)
        self.assertIs(caught.exception,control)
        self.assertEqual(recorder.snapshot()['first_failure'],first)
        self.assertTrue(recorder.snapshot()['cancelled'])
        self.assertEqual(recorder.snapshot()['status'],'CANCELLED')
        self.assertFalse((out/'worker-diagnostic.json').exists())

    def test_replaced_temp_inode_is_detected_and_revoked(self):
        _,out,recorder=self.fixture(); recorder.controller_validated()
        forged=recorder.snapshot(); forged.update(status='PASS',operation='complete')
        raw=self.helper.encoded(forged); replace=self.helper.os.replace; mutations=[]
        def swapping(source,destination,**options):
            directory=options['src_dir_fd']; self.helper.os.unlink(source,dir_fd=directory)
            fd=self.helper.os.open(source,self.helper.os.O_WRONLY|self.helper.os.O_CREAT|self.helper.os.O_EXCL,0o600,dir_fd=directory)
            try: self.helper.os.write(fd,raw)
            finally: self.helper.os.close(fd)
            mutations.append(True); return replace(source,destination,**options)
        with mock.patch.object(self.helper.os,'replace',side_effect=swapping):
            recorder.fail('source-pins',ValueError('private business'))
        self.assertTrue(mutations); self.assertFalse((out/'worker-diagnostic.json').exists())
        self.assertEqual(recorder.snapshot()['first_failure']['predicate'],'source-pins')
        self.assertTrue(recorder.snapshot()['diagnostic_write_failed'])

    def test_ancestor_alias_cannot_redirect_log_read(self):
        root,_,_=self.fixture(); selected=root/'selected'; foreign=root/'foreign'
        selected.mkdir(); foreign.mkdir(); target=selected/'makepkg.stdout'
        target.write_bytes(b'original'); (foreign/target.name).write_bytes(b'foreign')
        opening=self.helper.os.open; mutations=[]
        def swapping(name,*args,**options):
            if name=='selected' and 'dir_fd' in options and not mutations:
                selected.rename(root/'original'); selected.symlink_to(foreign,target_is_directory=True); mutations.append(True)
            return opening(name,*args,**options)
        with mock.patch.object(self.helper.os,'open',side_effect=swapping):
            with self.assertRaises(OSError): self.helper.regular(target,self.helper.LOG_LIMIT)
        self.assertTrue(mutations)

    def test_ancestor_alias_cannot_create_foreign_lock(self):
        root,_,_=self.fixture(); selected=root/'selected'; foreign=root/'foreign'
        output=selected/'output'; other=foreign/'output'
        output.mkdir(parents=True,mode=0o700); other.mkdir(parents=True,mode=0o700)
        opening=self.helper.os.open; mutations=[]
        def swapping(name,*args,**options):
            if name=='selected' and 'dir_fd' in options and not mutations:
                selected.rename(root/'original'); selected.symlink_to(foreign,target_is_directory=True); mutations.append(True)
            return opening(name,*args,**options)
        with mock.patch.object(self.helper.os,'open',side_effect=swapping):
            recorder=self.helper.Recorder(output,dict(controller_sha256=CONTROLLER_SHA,image_id=IMAGE,entry_script_sha256='c'*64))
        self.assertTrue(mutations); self.assertTrue(recorder.snapshot()['diagnostic_write_failed'])
        self.assertFalse((other/'.worker-diagnostic.lock').exists())
        self.assertFalse((other/'worker-diagnostic.json').exists())


if __name__ == '__main__':
    unittest.main()

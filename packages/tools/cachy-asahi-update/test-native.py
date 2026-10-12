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


class NativeTests(unittest.TestCase):
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
 return SimpleNamespace(returncode=0)
checks=SimpleNamespace(metadata=lambda _: {},package=lambda _: {'errors': []})
bind=SimpleNamespace(bind_generated=lambda *_:None,bind_artifact=lambda *_:[])
def output(command,**kw):return b'' if command[1]=='ps' else b'[]'
with mock.patch.object(n.subprocess,'run',side_effect=run),mock.patch.object(n.subprocess,'check_output',side_effect=output),mock.patch.object(n,'load_module',return_value=bind):
 try:n.launch('sha256:'+'a'*64,recipe,lock,{},entry,out,checks,{},n.tree_hashes(recipe),n.sha(entry))
 except KeyboardInterrupt:pass
 else:raise AssertionError('cancellation did not propagate')
'''
        for phase in ('run', 'cleanup'):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as temp:
                process = subprocess.run([sys.executable, '-c', script,
                                          str(BASE / 'updater-native.py'), temp, phase],
                                         capture_output=True, timeout=5)
                self.assertEqual(process.returncode, 0, process.stderr.decode())
                record = json.loads((Path(temp) / 'out/provenance.json').read_bytes())
                self.assertEqual(record['native_compilation'], 'FAIL' if phase == 'run' else 'FAIL-container-cleanup')
                self.assertEqual(record['cancel_signal'], 'SIGTERM')
                self.assertTrue(record['cancelled'])
                self.assertTrue(record['container_absence_verified'])
                self.assertTrue(record['container_cleanup_attempted'])
                self.assertEqual(record['container_removal_succeeded'], phase == 'run')
                self.assertEqual(record['container_cleanup_complete'], phase == 'run')
                self.assertEqual(record['stage'], 'finalized')

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


if __name__ == '__main__':
    unittest.main()

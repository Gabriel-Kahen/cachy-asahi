"""Synthetic committed-source fixtures; no Git writes or project imports."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import sys
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('updater_source_contract', Path(__file__).with_name('source.py'))
source = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(source)
COMMIT = 'a' * 40

LIFECYCLE = r'''
import json,os,signal,subprocess,sys,time,types
from pathlib import Path
m=types.ModuleType('fixture_source')
exec(compile(Path(sys.argv[1]).read_bytes(),sys.argv[1],'exec'),m.__dict__)
mode=sys.argv[2]; children=[]; old_called=[]
def raising(number,frame):
    old_called.append(number)
    raise RuntimeError('old raising handler reached')
saved={s:signal.getsignal(s) for s in (signal.SIGINT,signal.SIGTERM,signal.SIGALRM)}
for s in saved: signal.signal(s,raising)
prior_mask=signal.pthread_sigmask(signal.SIG_BLOCK,set())
prior_reaper=m._subreaper()
real_popen=subprocess.Popen
real_signal=signal.signal
def install(number,handler):
    if mode=='first-install' and isinstance(getattr(handler,'__self__',None),m._Signals):
        if not children:
            children.append(None)
            os.kill(os.getpid(),signal.SIGTERM)
    return real_signal(number,handler)
signal.signal=install
def launch(command,**kwargs):
    assert kwargs['start_new_session'] is True
    assert callable(kwargs['preexec_fn'])
    if mode=='mask':
        code='import signal,json; print(json.dumps([int(s) for s in signal.pthread_sigmask(signal.SIG_BLOCK,set())]))'
    elif mode=='descendant':
        code='import os,signal,time; p=os.fork(); signal.signal(signal.SIGTERM,signal.SIG_IGN) if p==0 else None; os.close(1) if p==0 else print(p,flush=True); time.sleep(30) if p==0 else None'
    elif mode=='cleanup-entry': code='print("complete")'
    else: code='import time; time.sleep(30)'
    child=real_popen([sys.executable,'-I','-B','-c',code],**kwargs)
    children.append(child)
    if mode=='spawn-gap': os.kill(os.getpid(),signal.SIGTERM)
    return child
subprocess.Popen=launch
real_cleanup=m._cleanup
def cleanup(child):
    if mode=='cleanup-entry': os.kill(os.getpid(),signal.SIGTERM)
    return real_cleanup(child)
m._cleanup=cleanup
try:
    if mode=='alarm': signal.setitimer(signal.ITIMER_REAL,.05)
    started=time.monotonic()
    cancelled=None
    try: output=m._git(Path('/tmp'),['fixture'],4096,time.monotonic()+3)
    except m.SourceCancelled as error: cancelled=error
    elapsed=time.monotonic()-started
    signal.setitimer(signal.ITIMER_REAL,0)
    assert not old_called
    assert all(signal.getsignal(s) is raising for s in saved)
    assert signal.pthread_sigmask(signal.SIG_BLOCK,set())==prior_mask
    assert m._subreaper()==prior_reaper
    if mode in ('first-install','spawn-gap','alarm','cleanup-entry'):
        assert cancelled is not None and not cancelled.cleanup_failed
        assert cancelled.signum==(signal.SIGALRM if mode=='alarm' else signal.SIGTERM)
        assert elapsed<1.5
    else:
        assert cancelled is None
        if mode=='mask': assert not (set(json.loads(output)) & {int(s) for s in saved})
        if mode=='descendant':
            descendant=int(output.strip())
            try: os.kill(descendant,0)
            except ProcessLookupError: pass
            else: raise AssertionError('unreaped descendant')
    for child in children:
        if child is None: continue
        assert child.poll() is not None
        try: os.killpg(child.pid,0)
        except ProcessLookupError: pass
        else: raise AssertionError('owned group remains')
    print('PASS')
finally:
    signal.setitimer(signal.ITIMER_REAL,0)
    signal.signal=real_signal
    for s,h in saved.items(): signal.signal(s,h)
    for child in children:
        if child is not None and child.poll() is None:
            try: os.killpg(child.pid,signal.SIGKILL)
            except ProcessLookupError: pass
            child.wait(timeout=3)
'''


class SourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.stage = sorted(source.CONTROLLERS)
        self.committed = {}
        package = {}
        for index in range(63):
            name = 'file-' + str(index) + '.txt'
            data = ('package ' + str(index)).encode()
            self.put(source.PACKAGE + name, data)
            package[name] = source.digest(data)
        root_names = ['scripts/build/build.py', 'scripts/checks/package_checks.py',
                      'scripts/ci/integration_export.py', 'scripts/ci/native_arm.py',
                      'scripts/ci/inputs.lock.json',
                      'scripts/port/updater-extension/builder-extension.lock.json',
                      'scripts/port/updater-extension/expected-packages.lock',
                      'scripts/port/updater-extension/extension-receipt.json']
        roots = {}
        for name in root_names:
            data = name.encode()
            self.put(name, data)
            roots[name] = source.digest(data)
        for name in source.HELPERS | source.CONTROLLERS:
            self.put(name, name.encode(), 0o755 if name.endswith('stage.py') else 0o644)
        data = json.dumps({'schema_version': 1, 'files_sha256': package,
                           'root_files_sha256': roots}, sort_keys=True).encode()
        self.put(source.READY, data)
        self.ready_sha = source.digest(data)
        self.head = COMMIT
        self.patch = mock.patch.object(source, '_git', side_effect=self.git)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def put(self, name, data=b'fixture', mode=0o644):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(mode)
        blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        self.committed[name] = (data, mode, blob)
        return path

    def git(self, root, args, limit, deadline):
        self.assertEqual(root, self.root)
        self.assertGreater(deadline, source.time.monotonic())
        if args == ['rev-parse', '--show-toplevel']:
            return os.fsencode(self.root) + b'\n'
        if args == ['rev-parse', '--verify', 'HEAD']:
            return (self.head + '\n').encode()
        if args[0] == 'ls-tree':
            self.assertEqual(args[:4], ['ls-tree', '-z', COMMIT, '--'])
            name = args[4]
            if name not in self.committed:
                return b''
            data, mode, blob = self.committed[name]
            return ('100' + oct(mode)[2:] + ' blob ' + blob + '\t' + name + '\0').encode()
        if args[0] == 'cat-file':
            self.assertEqual(args[:2], ['cat-file', 'blob'])
            return next(row[0] for row in self.committed.values() if row[2] == args[2])
        self.fail('unexpected Git query')

    def collect(self):
        return source.collect(self.root, COMMIT, self.stage, self.ready_sha)

    def test_full_required_closure_and_modes(self):
        contract = self.collect()
        self.assertEqual(len(contract['files']), 80)
        self.assertTrue(source.HELPERS | source.CONTROLLERS <= set(contract['files']))
        self.assertEqual(contract['files'][source.STAGE + 'stage.py']['git_mode'], '100755')
        self.assertEqual(contract['files'][source.STAGE + 'stage.py']['file_mode'], 0o755)
        source.verify(self.root, contract)

    def test_wrong_ready_or_head_and_noncanonical_commit_refused(self):
        for commit, ready in [('a' * 39, self.ready_sha), ('A' * 40, self.ready_sha),
                              (COMMIT, 'b' * 64), (COMMIT, True)]:
            with self.subTest(commit=commit, ready=ready), self.assertRaises(ValueError):
                source.collect(self.root, commit, self.stage, ready)
        self.head = 'b' * 40
        with self.assertRaisesRegex(ValueError, 'source-head-commit'):
            self.collect()

    def test_untracked_required_file_refused(self):
        del self.committed[source.STAGE + 'source.py']
        with self.assertRaisesRegex(ValueError, 'source-tracked-blob'):
            self.collect()

    def test_worktree_bytes_and_modes_must_match_git(self):
        name = 'scripts/build/compare.py'
        path = self.root / name
        path.write_bytes(b'changed bytes')
        with self.assertRaisesRegex(ValueError, 'source-git-byte-drift'):
            self.collect()
        path.write_bytes(self.committed[name][0]); path.chmod(0o755)
        with self.assertRaisesRegex(ValueError, 'source-git-mode-drift'):
            self.collect()
        path.chmod(0o600)
        with self.assertRaisesRegex(ValueError, 'source-regular-mode'):
            self.collect()

    def test_reviewed_package_bytes_cannot_follow_new_git_content(self):
        self.put(source.PACKAGE + 'file-0.txt', b'new committed bytes')
        with self.assertRaisesRegex(ValueError, 'source-reviewed-byte-drift'):
            self.collect()

    def test_extra_package_and_omitted_controller_code_refused(self):
        path = self.put(source.PACKAGE + 'extra.py')
        with self.assertRaisesRegex(ValueError, 'source-package-closure'):
            self.collect()
        path.unlink()
        self.put(source.STAGE + 'test_broker.py')
        with self.assertRaisesRegex(ValueError, 'source-stage-closure'):
            self.collect()
        self.stage.append(source.STAGE + 'test_broker.py')
        self.assertIn(source.STAGE + 'test_broker.py', self.collect()['files'])
        path = self.put(source.STAGE + 'unlisted.sh', b'never executed')
        with self.assertRaisesRegex(ValueError, 'source-stage-closure'):
            self.collect()
        path.unlink()
        self.put(source.STAGE + 'stage.lock.json', b'external contract; deliberately nonrecursive')
        self.assertNotIn(source.STAGE + 'stage.lock.json', self.collect()['files'])

    def test_missing_self_and_duplicate_stage_paths_refused(self):
        for names in [self.stage[:-1], self.stage + self.stage[:1], ['../evil.py'], self.stage + ['outside.py']]:
            with self.subTest(names=names), self.assertRaises(ValueError):
                source.collect(self.root, COMMIT, names, self.ready_sha)

    def test_symlink_hardlink_fifo_and_symlink_parent_refused(self):
        path = self.root / 'scripts/build/compare.py'
        data = path.read_bytes(); path.unlink(); path.symlink_to('/etc/passwd')
        with self.assertRaises((ValueError, OSError)):
            self.collect()
        path.unlink(); path.write_bytes(data); path.chmod(0o644)
        link = self.root / 'hardlink'; os.link(path, link)
        with self.assertRaisesRegex(ValueError, 'source-regular-mode'):
            self.collect()
        link.unlink(); path.unlink(); os.mkfifo(path)
        with self.assertRaisesRegex(ValueError, 'source-regular-mode'):
            self.collect()
        path.unlink(); path.write_bytes(data); path.chmod(0o644)
        directory = self.root / 'scripts/build'
        directory.rename(self.root / 'build-original'); directory.symlink_to(self.root / 'build-original')
        with self.assertRaisesRegex(ValueError, 'source-parent-directory'):
            self.collect()

    def test_contract_tampering_and_extra_records_refused(self):
        contract = self.collect()
        for key, value in [('sha256', 'b' * 64), ('git_blob', 'b' * 40),
                           ('git_mode', '100755'), ('file_mode', True)]:
            changed = copy.deepcopy(contract)
            changed['files'][source.READY][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                source.verify(self.root, changed)
        changed = copy.deepcopy(contract); del changed['files']['scripts/build/compare.py']
        with self.assertRaisesRegex(ValueError, 'source-contract-drift'):
            source.verify(self.root, changed)
        for field, value in [('total_bytes', True), ('schema_version', True), ('extra', 1)]:
            changed = copy.deepcopy(contract); changed[field] = value
            with self.assertRaisesRegex(ValueError, 'source-contract-schema'):
                source.verify(self.root, changed)

    def test_cache_is_excluded_never_read_or_imported(self):
        self.put(source.PACKAGE + '__pycache__/malicious.pyc', b'raise RuntimeError("must never execute")')
        contract = self.collect()
        self.assertFalse(any('__pycache__' in name for name in contract['files']))

    def test_final_hash_and_head_races_refused(self):
        original = self.git
        count = 0
        def drift(root, args, limit, deadline):
            nonlocal count
            result = original(root, args, limit, deadline)
            if args == ['rev-parse', '--verify', 'HEAD']:
                count += 1
                if count == 2:
                    (self.root / source.STAGE / 'stage.py').write_bytes(b'late drift')
            return result
        with mock.patch.object(source, '_git', side_effect=drift), self.assertRaisesRegex(ValueError, 'source-final-drift'):
            self.collect()
        self.put(source.STAGE + 'stage.py', (source.STAGE + 'stage.py').encode(), 0o755)
        count = 0
        def head_drift(root, args, limit, deadline):
            nonlocal count
            if args == ['rev-parse', '--verify', 'HEAD']:
                count += 1
                if count == 2:
                    self.head = 'b' * 40
            return original(root, args, limit, deadline)
        with mock.patch.object(source, '_git', side_effect=head_drift), self.assertRaisesRegex(ValueError, 'source-head-drift'):
            self.collect()

    def test_finite_file_and_total_bytes_bounds(self):
        with mock.patch.object(source, 'MAX_FILES', 77), self.assertRaisesRegex(ValueError, 'source-file-count'):
            self.collect()
        contract = self.collect()
        with mock.patch.object(source, 'MAX_BYTES', contract['total_bytes'] - 1), self.assertRaisesRegex(ValueError, 'source-total-bound'):
            self.collect()

    def test_duplicate_json_and_noncanonical_path_refused(self):
        data = (self.root / source.READY).read_bytes().replace(b'"schema_version": 1', b'"schema_version": 1, "schema_version": 1')
        self.put(source.READY, data); self.ready_sha = source.digest(data)
        with self.assertRaisesRegex(ValueError, 'source-json-duplicate'):
            self.collect()
        for name in ('/absolute', '../escape', 'a/../b', 'a//b', 'a/./b', 'a\nb', ''):
            with self.subTest(name=name), self.assertRaises(ValueError):
                source.relative(name)

    def test_git_queries_have_finite_output_deadline_and_curated_environment(self):
        self.patch.stop()
        popen = source.subprocess.Popen
        processes = []
        for code, limit, seconds, expected in [
            ('print("ok")', 16, 2, b'ok\n'),
            ('print("x"*64)', 16, 2, 'source-git-output-bound'),
            ('import time;time.sleep(10)', 16, 0.05, 'source-git-deadline'),
            ('raise SystemExit(2)', 16, 2, 'source-git-query')]:
            def fixture(command, **kwargs):
                self.assertEqual(command[0], '/usr/bin/git')
                self.assertIn('--no-replace-objects', command)
                self.assertEqual(kwargs['env']['GIT_CONFIG_GLOBAL'], '/dev/null')
                self.assertEqual(kwargs['env']['GIT_NO_LAZY_FETCH'], '1')
                self.assertNotIn('GIT_DIR', kwargs['env'])
                process = popen([sys.executable, '-I', '-B', '-c', code], **kwargs)
                processes.append(process)
                return process
            with mock.patch.object(source.subprocess, 'Popen', side_effect=fixture):
                if isinstance(expected, bytes):
                    self.assertEqual(source._git(self.root, ['rev-parse', 'HEAD'], limit,
                                                source.time.monotonic() + seconds), expected)
                else:
                    with self.assertRaisesRegex(ValueError, expected):
                        source._git(self.root, ['rev-parse', 'HEAD'], limit, source.time.monotonic() + seconds)
            self.assertIsNotNone(processes[-1].poll())

    def lifecycle(self, mode):
        result = subprocess.run([sys.executable, '-I', '-B', '-c', LIFECYCLE,
                                 str(Path(__file__).with_name('source.py').absolute()), mode],
                                capture_output=True, timeout=8)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stdout, b'PASS\n')

    def test_real_first_handler_install_cancellation_does_not_spawn(self):
        self.lifecycle('first-install')

    def test_real_spawn_registration_gap_cancellation_reaps_group(self):
        self.lifecycle('spawn-gap')

    def test_real_alarm_cancellation_reaps_group_and_restores_handlers(self):
        self.lifecycle('alarm')

    def test_real_cleanup_entry_signal_stays_nonraising_until_reaped(self):
        self.lifecycle('cleanup-entry')

    def test_real_child_mask_restoration_and_owned_descendant_reaping(self):
        self.lifecycle('mask')
        self.lifecycle('descendant')

    def signal_cleanup_fixture(self, fault):
        self.patch.stop()
        popen = source.subprocess.Popen
        handlers = {s: source.signal.getsignal(s) for s in (source.signal.SIGTERM, source.signal.SIGINT, source.signal.SIGALRM)}
        mask = source.signal.pthread_sigmask(source.signal.SIG_BLOCK, set())
        processes = []
        def fixture(_command, **kwargs):
            child = popen([sys.executable, '-I', '-B', '-c', 'print("done")'], **kwargs)
            processes.append(child); return child
        with mock.patch.object(source.subprocess, 'Popen', side_effect=fixture), fault:
            with self.assertRaises((ValueError, source.SourceCancelled)) as raised:
                source._git(self.root, ['fixture'], 32, source.time.monotonic() + 2)
        if isinstance(raised.exception, source.SourceCancelled):
            self.assertTrue(raised.exception.cleanup_failed)
        else:
            self.assertEqual(str(raised.exception), 'source-git-cleanup')
        self.assertEqual({s: source.signal.getsignal(s) for s in handlers}, handlers)
        self.assertEqual(source.signal.pthread_sigmask(source.signal.SIG_BLOCK, set()), mask)
        self.assertIsNotNone(processes[0].poll())
        with self.assertRaises(ProcessLookupError): os.killpg(processes[0].pid, 0)

    def test_pending_consumption_failures_restore_all_handlers_and_fail_closed(self):
        self.signal_cleanup_fixture(mock.patch.object(source.signal, 'sigpending', side_effect=OSError('fixture')))

    def test_wait_consumption_failure_retains_cancelled_cleanup_failure(self):
        pending = mock.patch.object(source.signal, 'sigpending', return_value={source.signal.SIGTERM})
        with pending:
            self.signal_cleanup_fixture(mock.patch.object(source.signal, 'sigtimedwait', side_effect=OSError('fixture')))

    def test_handler_restoration_failure_retries_and_never_passes(self):
        original = source.signal.signal; old = source.signal.getsignal(source.signal.SIGTERM); failed = False
        def restore(number, handler):
            nonlocal failed
            if number == source.signal.SIGTERM and handler == old and not failed:
                failed = True; raise OSError('fixture')
            return original(number, handler)
        self.signal_cleanup_fixture(mock.patch.object(source.signal, 'signal', side_effect=restore))
        self.assertTrue(failed)

    def test_mask_restoration_failure_retries_and_never_passes(self):
        original = source.signal.pthread_sigmask; count = 0; parent = os.getpid()
        def restore(operation, mask):
            nonlocal count
            if operation == source.signal.SIG_SETMASK and os.getpid() == parent:
                count += 1
                if count == 2: raise OSError('fixture')
            return original(operation, mask)
        self.signal_cleanup_fixture(mock.patch.object(source.signal, 'pthread_sigmask', side_effect=restore))
        self.assertGreaterEqual(count, 3)


if __name__ == '__main__':
    unittest.main()

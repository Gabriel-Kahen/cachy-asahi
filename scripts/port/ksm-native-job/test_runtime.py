# SPDX-License-Identifier: MIT
"""Real small private processes/signals/files; no Docker or packages."""
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('ksm_runtime_tests_subject', HERE / 'runtime.py')
runtime = importlib.util.module_from_spec(spec)
exec(compile((HERE / 'runtime.py').read_bytes(), str(HERE / 'runtime.py'), 'exec'), runtime.__dict__)


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.env = {'PATH': '/usr/bin:/bin', 'HOME': str(self.root), 'LC_ALL': 'C'}
        # This host's temporary filesystem may have less than the production
        # 8GiB reserve; small process fixtures explicitly simulate capacity.
        self.enterContext(patch.object(runtime.os, 'fstatvfs', return_value=SimpleNamespace(f_bavail=32 * 1024**3, f_frsize=1)))
        self.runner = runtime.Runner(self.env, self.root, self.root / 'logs', deadline_seconds=10)
        self.addCleanup(self.runner.close)

    def command(self, code):
        return [sys.executable, '-I', '-B', '-c', code]

    def test_combined_output_exit_status_and_private_log(self):
        result = self.runner.run(self.command('import sys;print("out");print("err",file=sys.stderr)'), log='child.log')
        self.assertEqual(result.returncode, 0)
        self.assertIn(b'out', result.stdout); self.assertIn(b'err', result.stdout)
        path = self.root / 'logs/child.log'
        self.assertEqual(path.read_bytes(), result.stdout)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(self.runner.resource_observation['status'], 'PASS-observed-resources')
        self.assertEqual(self.runner.run(self.command('raise SystemExit(7)')).returncode, 7)

    def test_child_resource_limits_pdeath_signal_and_unmasked_signals(self):
        code = '''import ctypes,json,resource,signal
value=ctypes.c_int();lib=ctypes.CDLL(None);lib.prctl(2,ctypes.byref(value),0,0,0)
print(json.dumps({'pdeath':value.value,'mask':[int(x) for x in signal.pthread_sigmask(signal.SIG_BLOCK,[])],
'core':resource.getrlimit(resource.RLIMIT_CORE),'nofile':resource.getrlimit(resource.RLIMIT_NOFILE),
'as':resource.getrlimit(resource.RLIMIT_AS),'fsize':resource.getrlimit(resource.RLIMIT_FSIZE)}))'''
        observed = json.loads(self.runner.run(self.command(code)).stdout)
        self.assertEqual(observed['pdeath'], signal.SIGKILL)
        self.assertFalse(set(observed['mask']) & set(runtime.SIGNALS))
        self.assertEqual(observed['core'], [0, 0]); self.assertEqual(observed['nofile'], [128, 128])
        self.assertLessEqual(observed['as'][0], 10 * 1024**3)
        self.assertLessEqual(observed['fsize'][0], 4 * 1024**3)

    def test_output_limit_kills_owned_child_and_preserves_bounded_log(self):
        children, original = [], subprocess.Popen
        def spawn(*args, **kwargs):
            child = original(*args, **kwargs); children.append(child); return child
        with patch.object(runtime.subprocess, 'Popen', side_effect=spawn), self.assertRaisesRegex(ValueError, 'output-bound'):
            self.runner.run(self.command('import os,time;os.write(1,b"x"*1000);time.sleep(3)'), limit=50, log='limit.log')
        self.assertEqual((self.root / 'logs/limit.log').stat().st_size, 50)
        self.assertIsNotNone(children[0].poll())
        with self.assertRaises(ProcessLookupError): os.killpg(children[0].pid, 0)

    def test_timeout_and_absolute_aggregate_deadline_refuse_late_success(self):
        with self.assertRaisesRegex(ValueError, 'command-timeout'):
            self.runner.run(self.command('import time;time.sleep(3)'), timeout=.05)
        self.runner.deadline = time.monotonic() - .01
        with patch.object(runtime.subprocess, 'Popen') as spawn, self.assertRaisesRegex(ValueError, 'deadline-exhausted'):
            self.runner.run(self.command('print("late")'))
        spawn.assert_not_called()

    def signal_case(self, signum, *, assignment=False, cleanup_signal=False):
        original, children = subprocess.Popen, []
        prior = {sig: signal.getsignal(sig) for sig in runtime.SIGNALS}
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        def spawn(*args, **kwargs):
            child = original(*args, **kwargs); children.append(child)
            if assignment:
                os.kill(os.getpid(), signum)
                self.assertIn(signum, signal.sigpending())
            return child
        original_cleanup = runtime._cleanup
        def cleanup(child):
            if cleanup_signal:
                for sig in runtime.SIGNALS: os.kill(os.getpid(), sig)
            return original_cleanup(child)
        code = f'import os,signal,time;time.sleep(.03);os.kill({os.getpid()},{int(signum)});time.sleep(3)'
        if assignment: code = 'import time;time.sleep(3)'
        with patch.object(runtime.subprocess, 'Popen', side_effect=spawn), \
             patch.object(runtime, '_cleanup', side_effect=cleanup), self.assertRaises(runtime.Cancelled):
            self.runner.run(self.command(code))
        self.assertEqual({sig: signal.getsignal(sig) for sig in runtime.SIGNALS}, prior)
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, set()), mask)
        self.assertIsNone(runtime._ACTIVE)
        for child in children:
            self.assertIsNotNone(child.poll())
            with self.assertRaises(ProcessLookupError): os.killpg(child.pid, 0)

    def test_real_sigint_and_sigterm_cancel_active_child(self):
        for sig in runtime.SIGNALS:
            with self.subTest(signal=sig): self.signal_case(sig)

    def test_signals_after_spawn_before_assignment_cannot_lose_child(self):
        for sig in runtime.SIGNALS:
            with self.subTest(signal=sig): self.signal_case(sig, assignment=True)

    def test_second_signals_during_disposal_are_deferred(self):
        self.signal_case(signal.SIGTERM, cleanup_signal=True)

    def test_real_late_signal_during_log_fsync_cancels_completed_child(self):
        original = os.fsync
        def sync(fd):
            original(fd); os.kill(os.getpid(), signal.SIGTERM)
        with patch.object(runtime.os, 'fsync', side_effect=sync), self.assertRaises(runtime.Cancelled):
            self.runner.run(self.command('print("completed")'), log='late.log')
        self.assertEqual((self.root / 'logs/late.log').read_bytes(), b'completed\n')

    def test_parent_exit_kills_direct_private_child(self):
        # The supervisor is itself a tiny isolated child; its abrupt exit tests PDEATHSIG.
        pidfile = self.root / 'pid'
        code = f'''import importlib.util,os,sys,time
s=importlib.util.spec_from_file_location('r',{str(HERE / 'runtime.py')!r});r=importlib.util.module_from_spec(s);s.loader.exec_module(r)
r.os.fstatvfs=lambda _:type('FixtureDisk',(),{{'f_bavail':32*1024**3,'f_frsize':1}})()
runner=r.Runner({self.env!r},{str(self.root)!r},{str(self.root / 'nested')!r},deadline_seconds=5)
def exit_parent():
 time.sleep(.04);os._exit(0)
runner.run([sys.executable,'-I','-B','-c',"import os,time;open({str(pidfile)!r},'w').write(str(os.getpid()));time.sleep(3)"],service=exit_parent)
'''
        # Adopt this fixture's orphan only; group-specific reaping preserves other actors.
        result = subprocess.run(self.command(code), env=self.env, timeout=2, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(result.returncode, 0)
        pid = int(pidfile.read_text())
        end = time.monotonic() + 1
        while time.monotonic() < end:
            try:
                waited, _ = os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                waited = pid
            if waited: break
            time.sleep(.01)
        with self.assertRaises(ProcessLookupError): os.kill(pid, 0)

    def test_cleanup_reaps_same_group_grandchild_and_keeps_unrelated_child(self):
        unrelated = subprocess.Popen(self.command('import time;time.sleep(3)'), start_new_session=True)
        try:
            code = 'import os,time;pid=os.fork();print(pid,flush=True) if pid else time.sleep(3)'
            result = self.runner.run(self.command(code))
            descendant = int(result.stdout)
            with self.assertRaises(ProcessLookupError): os.kill(descendant, 0)
            self.assertIsNone(unrelated.poll())
        finally:
            unrelated.terminate(); unrelated.wait(timeout=1)

    def test_service_callback_nested_runner_uses_same_deadline(self):
        events = []
        class Service:
            def poll(inner):
                if not events:
                    with runtime.Runner(self.env, self.root, self.root / 'broker', deadline_at=self.runner.deadline) as nested:
                        events.append(nested.run(self.command('print("broker")')).stdout)
        result = self.runner.run(self.command('import time;time.sleep(.07);print("producer")'), service=Service())
        self.assertEqual(events, [b'broker\n']); self.assertEqual(result.stdout, b'producer\n')

    def test_callback_failure_and_callback_deadline_cleanup_outer_child(self):
        def fail(): raise ValueError('broker-failed')
        with self.assertRaisesRegex(ValueError, 'broker-failed'):
            self.runner.run(self.command('import time;time.sleep(3)'), service=fail)
        # Leave real fork/setup time before deliberately exhausting the callback budget.
        callbacks = []
        def late():
            callbacks.append(True)
            time.sleep(1.05)
        with self.assertRaisesRegex(ValueError, 'command-timeout'):
            self.runner.run(self.command('import time;time.sleep(3)'), timeout=1, service=late)
        self.assertEqual(callbacks, [True])

    def test_sealed_fd_is_transportable_and_parent_retains_it(self):
        fd = os.memfd_create('fixture', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        try:
            os.write(fd, b'captured fixture')
            seals = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
            result = self.runner.run(self.command(f'print(open("/proc/self/fd/{fd}").read())'), pass_fds=(fd,))
            self.assertEqual(result.stdout, b'captured fixture\n'); os.fstat(fd)
        finally: os.close(fd)
        plain = os.open(self.root / 'plain', os.O_CREAT | os.O_RDWR, 0o600)
        try:
            with self.assertRaises((ValueError, OSError)): self.runner.run(self.command('pass'), pass_fds=(plain,))
        finally: os.close(plain)

    def test_resource_regular_singlelink_directory_observation(self):
        (self.root / 'file').write_bytes(b'private')
        observed = self.runner.check_resources()
        self.assertTrue(observed['known']); self.assertEqual(observed['bytes'], 7)
        for kind in ('symlink', 'hardlink', 'fifo'):
            path = self.root / 'unsafe'
            if kind == 'symlink': path.symlink_to(self.root / 'file')
            elif kind == 'hardlink': os.link(self.root / 'file', path)
            else: os.mkfifo(path)
            with self.subTest(kind=kind), self.assertRaises(runtime.ResourceFailure) as caught:
                self.runner.check_resources()
            self.assertFalse(caught.exception.observation['known']); self.assertEqual(caught.exception.observation['status'], 'FAIL')
            path.unlink()

    def test_resource_byte_count_depth_and_disk_reserve_fail_closed(self):
        (self.root / 'file').write_bytes(b'12345')
        with patch.object(runtime, 'MAX_PRIVATE', 4), self.assertRaisesRegex(runtime.ResourceFailure, 'private-byte-bound'):
            self.runner.check_resources()
        with patch.object(runtime, 'MAX_NODES', 1), self.assertRaisesRegex(runtime.ResourceFailure, 'private-entry-bound'):
            self.runner.check_resources()
        (self.root / 'deep/next').mkdir(parents=True)
        with patch.object(runtime, 'MAX_DEPTH', 1), self.assertRaisesRegex(runtime.ResourceFailure, 'private-depth-bound'):
            self.runner.check_resources()
        with patch.object(runtime.os, 'fstatvfs', return_value=type('Disk', (), {'f_bavail': 1, 'f_frsize': 1})()), \
             self.assertRaisesRegex(runtime.ResourceFailure, 'private-disk-reserve'):
            self.runner.check_resources()

    def test_periodic_disk_and_file_violation_disposes_child(self):
        code = f'import time;open({str(self.root / "growth")!r},"wb").write(b"x"*100);time.sleep(3)'
        with patch.object(runtime, 'MAX_PRIVATE', 50), patch.object(runtime, 'RESOURCE_INTERVAL', .01), \
             self.assertRaisesRegex(runtime.ResourceFailure, 'private-byte-bound'):
            self.runner.run(self.command(code))

    def test_invalid_argv_log_and_limits_do_not_spawn(self):
        cases = [([], {}), (['relative'], {}), (self.command('pass'), {'limit': True}),
                 (self.command('pass'), {'log': '../outside'}), (self.command('pass'), {'timeout': float('inf')})]
        for argv, kwargs in cases:
            with self.subTest(argv=argv, kwargs=kwargs), patch.object(runtime.subprocess, 'Popen') as spawn, self.assertRaises(ValueError):
                self.runner.run(argv, **kwargs)
            spawn.assert_not_called()

    def test_close_releases_retained_directories(self):
        fds = [self.runner._root_fd, self.runner._log_fd]
        self.runner.close()
        for fd in fds:
            with self.assertRaises(OSError): os.fstat(fd)

    def test_owned_rpc_socket_exact_identity_and_absent_unregistration(self):
        path = self.root / 'broker.sock'
        with socket.socket(socket.AF_UNIX) as server:
            server.bind(str(path)); path.chmod(0o600)
            info = path.lstat(); identity = (info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))
            with self.assertRaisesRegex(runtime.ResourceFailure, 'unbound-private-socket'): self.runner.check_resources()
            self.runner.register_socket(path, identity)
            self.assertEqual(self.runner.check_resources()['owned_rpc_sockets'], 1)
            with runtime.Runner(self.env, self.root, self.root / 'nested-socket', allowed_sockets=dict(self.runner.allowed_sockets)) as nested:
                self.assertEqual(nested.run(self.command('print("bound socket")')).returncode, 0)
            with self.assertRaisesRegex(ValueError, 'owned-socket-still-present'): self.runner.unregister_socket(path)
            path.chmod(0o644)
            with self.assertRaisesRegex(runtime.ResourceFailure, 'unbound-private-socket'): self.runner.check_resources()
            path.chmod(0o600); path.unlink()
            with self.assertRaisesRegex(runtime.ResourceFailure, 'owned-private-socket-missing'): self.runner.check_resources()
            self.runner.unregister_socket(path)
            self.assertEqual(self.runner.check_resources()['owned_rpc_sockets'], 0)

    def test_second_socket_and_wrong_owned_identity_refused(self):
        paths = [self.root / 'first.sock', self.root / 'second.sock']
        servers = [socket.socket(socket.AF_UNIX), socket.socket(socket.AF_UNIX)]
        try:
            for server, path in zip(servers, paths): server.bind(str(path)); path.chmod(0o600)
            identities = [(i.st_dev, i.st_ino, i.st_uid, i.st_gid, stat.S_IMODE(i.st_mode)) for i in [p.lstat() for p in paths]]
            with self.assertRaisesRegex(ValueError, 'owned-socket-identity-mismatch'):
                self.runner.register_socket(paths[0], identities[0][:1] + (identities[0][1] + 1,) + identities[0][2:])
            self.runner.register_socket(paths[0], identities[0])
            with self.assertRaisesRegex(ValueError, 'one-owned-socket-only'): self.runner.register_socket(paths[1], identities[1])
        finally:
            for server in servers: server.close()
            for path in paths: path.unlink(missing_ok=True)

    def test_exported_deferral_remembers_real_signals_before_state_check(self):
        prior = {s: signal.getsignal(s) for s in runtime.SIGNALS}
        with self.assertRaises(runtime.Cancelled):
            with runtime.cancellation_handlers() as state:
                with runtime.defer_signals() as events:
                    for signum in runtime.SIGNALS: os.kill(os.getpid(), signum)
                self.assertEqual(events, list(runtime.SIGNALS))
                self.assertEqual(state.signum, runtime.SIGNALS[-1])
                state.check()
        self.assertEqual({s: signal.getsignal(s) for s in runtime.SIGNALS}, prior)
        with runtime.defer_signals() as events: os.kill(os.getpid(), signal.SIGTERM)
        self.assertEqual(events, [signal.SIGTERM])
        self.assertEqual({s: signal.getsignal(s) for s in runtime.SIGNALS}, prior)

    def test_term_ignoring_child_is_killed_within_three_second_disposal(self):
        original, children = subprocess.Popen, []
        def spawn(*args, **kwargs):
            child = original(*args, **kwargs); children.append(child); return child
        start = time.monotonic()
        code = 'import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);print("ready",flush=True);time.sleep(5)'
        with patch.object(runtime.subprocess, 'Popen', side_effect=spawn), self.assertRaisesRegex(ValueError, 'command-timeout'):
            self.runner.run(self.command(code), timeout=.08)
        self.assertLess(time.monotonic() - start, 3.5)
        self.assertEqual(children[0].returncode, -signal.SIGKILL)
        with self.assertRaises(ProcessLookupError): os.killpg(children[0].pid, 0)

    def test_removed_log_path_refuses_hidden_fd_write(self):
        def remove_log(): (self.root / 'logs/gone.log').unlink(missing_ok=True)
        with self.assertRaises(OSError): self.runner.run(self.command('print("private")'), log='gone.log', service=remove_log)

    def test_atomic_download_and_receipt_renames_rescan_new_targets(self):
        for replace in (False, True):
            with self.subTest(receipt_replace=replace):
                partial=self.root/'acquisition.partial'; target=self.root/'acquisition.json'
                partial.write_bytes(b'finite authenticated bytes'); original=os.stat; fired=[]
                def stat_then_rename(name,*args,**kwargs):
                    if name==partial.name and 'dir_fd' in kwargs and not fired:
                        (partial.replace if replace else partial.rename)(target); fired.append(True)
                    return original(name,*args,**kwargs)
                with patch.object(runtime.os,'stat',side_effect=stat_then_rename):
                    result=self.runner.check_resources()
                self.assertTrue(fired); self.assertEqual(result['entries'],3)
                self.assertEqual(result['files'],1); self.assertEqual(result['bytes'],target.stat().st_size)
                self.assertEqual(result['status'],'PASS-observed-resources'); target.unlink()

    def test_atomic_rename_target_still_obeys_byte_quota(self):
        partial=self.root/'archive.partial'; partial.write_bytes(b'12345'); original=os.stat; fired=[]
        def stat_then_rename(name,*args,**kwargs):
            if name==partial.name and 'dir_fd' in kwargs and not fired:
                partial.rename(self.root/'archive.tar.xz'); fired.append(True)
            return original(name,*args,**kwargs)
        with patch.object(runtime.os,'stat',side_effect=stat_then_rename),patch.object(runtime,'MAX_PRIVATE',4), \
             self.assertRaisesRegex(runtime.ResourceFailure,'private-byte-bound'):
            self.runner.check_resources()
        self.assertTrue(fired)

    def test_vanishing_entry_charged_before_stat_and_node_quota(self):
        leaf=self.root/'gone'; leaf.write_bytes(b'x'); original=os.stat; fired=[]
        def disappear(name,*args,**kwargs):
            if name==leaf.name and 'dir_fd' in kwargs and not fired:
                leaf.unlink(); fired.append(True)
            return original(name,*args,**kwargs)
        with patch.object(runtime.os,'stat',side_effect=disappear): result=self.runner.check_resources()
        self.assertEqual(result['entries'],2); self.assertEqual(result['bytes'],0)
        leaf.write_bytes(b'x'); fired.clear()
        with patch.object(runtime,'MAX_NODES',0),patch.object(runtime.os,'stat',side_effect=disappear), \
             self.assertRaisesRegex(runtime.ResourceFailure,'private-entry-bound'):
            self.runner.check_resources()
        self.assertFalse(fired,'entry cap runs before descendant stat')

    def test_file_vanishing_before_open_keeps_already_observed_bytes(self):
        leaf=self.root/'gone'; leaf.write_bytes(b'12345'); original=os.open; fired=[]
        def disappear(name,*args,**kwargs):
            if name==leaf.name and 'dir_fd' in kwargs and not fired:
                leaf.unlink(); fired.append(True)
            return original(name,*args,**kwargs)
        with patch.object(runtime.os,'open',side_effect=disappear): result=self.runner.check_resources()
        self.assertTrue(fired); self.assertEqual(result['bytes'],5); self.assertEqual(result['files'],1)

    def test_missing_basename_reappearing_in_retry_is_refused(self):
        leaf=self.root/'gone'; leaf.write_bytes(b'x'); original_stat=os.stat; original_scan=os.scandir; fired=[]; scans=[]
        def disappear(name,*args,**kwargs):
            if name==leaf.name and 'dir_fd' in kwargs and not fired:
                leaf.unlink(); fired.append(True)
            return original_stat(name,*args,**kwargs)
        def rescan(fd):
            if isinstance(fd,int) and os.fstat(fd).st_ino==self.root.stat().st_ino:
                scans.append(True)
                if len(scans)==2: leaf.write_bytes(b'reappeared unknown bytes')
            return original_scan(fd)
        with patch.object(runtime.os,'stat',side_effect=disappear),patch.object(runtime.os,'scandir',side_effect=rescan), \
             self.assertRaisesRegex(runtime.ResourceFailure,'private-node-reappeared'):
            self.runner.check_resources()
        self.assertEqual(len(scans),2)

    def test_scan_root_replacement_and_missing_root_are_refused(self):
        for missing in (False,True):
            with self.subTest(missing=missing),tempfile.TemporaryDirectory() as temporary:
                base=Path(temporary); root=base/'private'; root.mkdir(mode=0o700)
                runner=runtime.Runner(self.env,root,root/'logs',deadline_seconds=10)
                original=os.scandir; fired=[]; inode=root.stat().st_ino
                def scan(fd):
                    entries=original(fd)
                    if isinstance(fd,int) and os.fstat(fd).st_ino==inode and not fired:
                        root.rename(base/'old-private'); fired.append(True)
                        if not missing: root.mkdir(mode=0o700)
                    return entries
                try:
                    with patch.object(runtime.os,'scandir',side_effect=scan),self.assertRaises(runtime.ResourceFailure):
                        runner.check_resources()
                    self.assertTrue(fired)
                finally: runner.close()

    def test_opened_child_directory_move_and_replacement_are_refused(self):
        for replacement in (False,True):
            with self.subTest(replacement=replacement):
                child=self.root/'child'; child.mkdir(); inode=child.stat().st_ino; original=os.scandir; fired=[]
                def scan(fd):
                    entries=original(fd)
                    if isinstance(fd,int) and os.fstat(fd).st_ino==inode and not fired:
                        child.rename(self.root/'moved'); fired.append(True)
                        if replacement: child.mkdir()
                    return entries
                with patch.object(runtime.os,'scandir',side_effect=scan),self.assertRaises(runtime.ResourceFailure):
                    self.runner.check_resources()
                self.assertTrue(fired); (self.root/'moved').rmdir()
                if replacement: child.rmdir()

    def test_opened_regular_move_outside_parent_is_not_unobserved_disappearance(self):
        leaf=self.root/'file'; leaf.write_bytes(b'x'); original=os.open; fired=[]
        outside=self.root/'outside-parent'; outside.mkdir()
        def opened_then_move(name,*args,**kwargs):
            fd=original(name,*args,**kwargs)
            if name==leaf.name and 'dir_fd' in kwargs and not fired:
                leaf.rename(outside/'moved'); fired.append(True)
            return fd
        with patch.object(runtime.os,'open',side_effect=opened_then_move),self.assertRaises(runtime.ResourceFailure):
            self.runner.check_resources()
        self.assertTrue(fired)

    def test_pinned_producer_atomic_renames_at_all_three_observation_points(self):
        for receipt in (False,True):
            for point in ('before-stat','before-open','after-open'):
                with self.subTest(receipt_replace=receipt,point=point),tempfile.TemporaryDirectory(dir=self.root) as temporary:
                    root=Path(temporary);target=root/('acquisition.json' if receipt else 'archive.tar.xz')
                    if receipt: target.write_bytes(b'previous receipt')
                    fd,name=tempfile.mkstemp(prefix='acquisition.' if receipt else target.name+'.',suffix='.partial',dir=root)
                    source=Path(name);data=b'finite completed acquisition bytes';os.write(fd,data);os.close(fd)
                    runner=runtime.Runner(self.env,root,root/'logs',deadline_seconds=10)
                    original_stat=os.stat; original_open=os.open; fired=[]; calls=[]
                    def rename():
                        (source.replace if receipt else source.rename)(target);fired.append(True)
                    def observe(name,*args,**kwargs):
                        if name==source.name and 'dir_fd' in kwargs:
                            calls.append(True)
                            if not fired and (point=='before-stat' or point=='after-open' and len(calls)==2): rename()
                        return original_stat(name,*args,**kwargs)
                    def opened(name,*args,**kwargs):
                        if name==source.name and 'dir_fd' in kwargs and point=='before-open' and not fired: rename()
                        return original_open(name,*args,**kwargs)
                    try:
                        with patch.object(runtime.os,'stat',side_effect=observe),patch.object(runtime.os,'open',side_effect=opened):
                            result=runner.check_resources()
                        self.assertTrue(fired);self.assertEqual(target.read_bytes(),data)
                        self.assertEqual(result['status'],'PASS-observed-resources')
                        self.assertGreaterEqual(result['bytes'],len(data));self.assertLessEqual(result['bytes'],len(data)+len(b'previous receipt'))
                        self.assertGreaterEqual(result['entries'],3)
                        if point=='after-open': self.assertGreater(result['rebinding_entries'],0)
                    finally: runner.close()

    def test_post_open_same_parent_rename_survives_actual_process_resource_tick(self):
        source=self.root/'archive.part.partial';target=self.root/'archive.tar.xz';source.write_bytes(b'finite bytes')
        original=os.stat;calls=[];fired=[]
        def observe(name,*args,**kwargs):
            if name==source.name and 'dir_fd' in kwargs:
                calls.append(True)
                if len(calls)==2: source.rename(target);fired.append(True)
            return original(name,*args,**kwargs)
        with patch.object(runtime.os,'stat',side_effect=observe):
            result=self.runner.run(self.command('print("completed after rename")'))
        self.assertEqual(result.returncode,0);self.assertEqual(result.stdout,b'completed after rename\n')
        self.assertTrue(fired);self.assertEqual(target.read_bytes(),b'finite bytes')

    def test_post_open_file_loss_replacement_and_foreign_candidate_refused(self):
        for action in ('unlink','replace-inode','foreign-owner'):
            with self.subTest(action=action),tempfile.TemporaryDirectory(dir=self.root) as temporary:
                root=Path(temporary);source=root/'file.partial';target=root/'final';source.write_bytes(b'original')
                runner=runtime.Runner(self.env,root,root/'logs',deadline_seconds=10);original=os.stat;calls=[];fired=[]
                def observe(name,*args,**kwargs):
                    if name==source.name and 'dir_fd' in kwargs:
                        calls.append(True)
                        if len(calls)==2:
                            if action=='unlink': source.unlink()
                            elif action=='replace-inode': source.unlink();target.write_bytes(b'different inode')
                            else: source.rename(target)
                            fired.append(True)
                    info=original(name,*args,**kwargs)
                    if action=='foreign-owner' and name==target.name and 'dir_fd' in kwargs:
                        fields=list(info);fields[4]=0;return os.stat_result(fields)
                    return info
                try:
                    with patch.object(runtime.os,'stat',side_effect=observe),self.assertRaises(runtime.ResourceFailure):
                        runner.check_resources()
                    self.assertTrue(fired)
                finally:runner.close()

    def test_rebinding_auxiliary_search_checks_unsafe_nodes_before_they_can_vanish(self):
        source=self.root/'file.partial';target=self.root/'final';source.write_bytes(b'finite bytes');bad=self.root/'unsafe'
        original=os.stat;calls=[];observed=[]
        def observe(name,*args,**kwargs):
            if name==source.name and 'dir_fd' in kwargs:
                calls.append(True)
                if len(calls)==2: source.rename(target);os.mkfifo(bad)
            info=original(name,*args,**kwargs)
            if name==bad.name and 'dir_fd' in kwargs: bad.unlink();observed.append(True)
            return info
        with patch.object(runtime.os,'stat',side_effect=observe), \
             self.assertRaisesRegex(runtime.ResourceFailure,'unsupported-private-node'):
            self.runner.check_resources()
        self.assertTrue(observed,'unsafe observed metadata must fail even when its name is now absent')

    def test_rebinding_new_name_and_observed_bytes_preserve_quota_limits(self):
        source=self.root/'file.partial';target=self.root/'final';source.write_bytes(b'12345');original=os.stat;calls=[]
        def observe(name,*args,**kwargs):
            if name==source.name and 'dir_fd' in kwargs:
                calls.append(True)
                if len(calls)==2: source.rename(target)
            return original(name,*args,**kwargs)
        with patch.object(runtime.os,'stat',side_effect=observe),patch.object(runtime,'MAX_NODES',2), \
             self.assertRaisesRegex(runtime.ResourceFailure,'private-entry-bound') as error:
            self.runner.check_resources()
        self.assertEqual(error.exception.observation['entries'],3);self.assertEqual(error.exception.observation['bytes'],5)
        target.rename(source);calls.clear()
        def growth(name,*args,**kwargs):
            if name==source.name and 'dir_fd' in kwargs:
                calls.append(True)
                if len(calls)==2: source.rename(target);target.write_bytes(b'123456')
            return original(name,*args,**kwargs)
        with patch.object(runtime.os,'stat',side_effect=growth),patch.object(runtime,'MAX_PRIVATE',5), \
             self.assertRaisesRegex(runtime.ResourceFailure,'private-byte-bound') as error:
            self.runner.check_resources()
        self.assertEqual(error.exception.observation['bytes'],6)

    def test_rebinding_search_budget_is_finite(self):
        source=self.root/'file.partial';target=self.root/'final';source.write_bytes(b'x');original_stat=os.stat
        original_scan=os.scandir;calls=[];root_inode=self.root.stat().st_ino;scans=[]
        class DuplicateEntries:
            def __init__(self,scan):self.scan=scan
            def __enter__(self):
                rows=list(self.scan.__enter__());return iter(rows*4)
            def __exit__(self,*args):return self.scan.__exit__(*args)
        def observe(name,*args,**kwargs):
            if name==source.name and 'dir_fd' in kwargs:
                calls.append(True)
                if len(calls)==2:source.rename(target)
            return original_stat(name,*args,**kwargs)
        def scan(fd):
            result=original_scan(fd)
            if isinstance(fd,int) and os.fstat(fd).st_ino==root_inode:
                scans.append(True)
                if len(scans)==2:return DuplicateEntries(result)
            return result
        with patch.object(runtime.os,'stat',side_effect=observe),patch.object(runtime.os,'scandir',side_effect=scan), \
             patch.object(runtime,'MAX_NODES',3),self.assertRaisesRegex(runtime.ResourceFailure,'private-rebinding-entry-bound'):
            self.runner.check_resources()

    def test_rebinding_refuses_already_walked_directory_replacement(self):
        directory=self.root/'a-directory';directory.mkdir();source=self.root/'z.partial';source.write_bytes(b'x')
        target=self.root/'final';original_stat=os.stat;original_scan=os.scandir;calls=[];fired=[]
        class Ordered:
            def __init__(self,scan):self.scan=scan
            def __enter__(self):return iter(sorted(self.scan.__enter__(),key=lambda entry:entry.name))
            def __exit__(self,*args):return self.scan.__exit__(*args)
        def scan(fd):return Ordered(original_scan(fd))
        def observe(name,*args,**kwargs):
            if name==source.name and 'dir_fd' in kwargs:
                calls.append(True)
                if len(calls)==2:
                    source.rename(target);directory.rename(self.root/'old-directory');directory.mkdir()
                    os.mkfifo(directory/'unseen-unsafe');fired.append(True)
            return original_stat(name,*args,**kwargs)
        with patch.object(runtime.os,'stat',side_effect=observe),patch.object(runtime.os,'scandir',side_effect=scan), \
             self.assertRaisesRegex(runtime.ResourceFailure,'private-directory-identity-changed'):
            self.runner.check_resources()
        self.assertTrue(fired)

    def test_root_lifecycle_receipt_post_open_rename_remains_strict(self):
        runner,expected,pins,inputs,populate=self.lifecycle_fixture()
        with runner.lifecycle_outputs(expected,pins,inputs):
            stage,receipt=populate();self.simulate_root_metadata(receipt)
            original=runtime.os.stat;calls=[];fired=[]
            def observe(name,*args,**kwargs):
                if name==receipt.name and 'dir_fd' in kwargs:
                    calls.append(True)
                    if len(calls)==2:receipt.rename(stage/'installed/moved-receipt');fired.append(True)
                return original(name,*args,**kwargs)
            with patch.object(runtime.os,'stat',side_effect=observe),self.assertRaises(runtime.ResourceFailure):
                runner.check_resources()
            self.assertTrue(fired)

    def test_lifecycle_input_capture_stays_immutable_across_same_parent_rename(self):
        runner,expected,pins,inputs,populate=self.lifecycle_fixture()
        with runner.lifecycle_outputs(expected,pins,inputs) as grant:
            stage,receipt=populate();self.simulate_root_metadata(receipt)
            source=stage/'source/scripts/port/ksm-lifecycle/worker.py';original=runtime.os.stat;fired=[]
            def observe(name,*args,**kwargs):
                if name==source.name and 'dir_fd' in kwargs and not fired:
                    source.rename(source.with_name('worker-moved.py'));fired.append(True)
                return original(name,*args,**kwargs)
            with patch.object(runtime.os,'stat',side_effect=observe),self.assertRaises((OSError,ValueError)):
                grant.read(source,2*1024**2)
            self.assertTrue(fired)

    def test_foreign_owner_and_non_enoent_descendant_failures_are_refused(self):
        leaf=self.root/'file'; leaf.write_bytes(b'x'); original=os.stat
        for failure in ('owner','permission','io'):
            with self.subTest(failure=failure):
                def observe(name,*args,**kwargs):
                    if name==leaf.name and 'dir_fd' in kwargs:
                        if failure=='permission': raise PermissionError('fixture')
                        if failure=='io': raise OSError('fixture')
                        info=original(name,*args,**kwargs)
                        return SimpleNamespace(st_uid=info.st_uid+1)
                    return original(name,*args,**kwargs)
                with patch.object(runtime.os,'stat',side_effect=observe),self.assertRaises(runtime.ResourceFailure):
                    self.runner.check_resources()

    def test_actual_process_supervision_survives_atomic_rename_resource_observation(self):
        partial=self.root/'archive.partial';partial.write_bytes(b'finite bytes');original=os.stat;fired=[]
        def moved(name,*args,**kwargs):
            if name==partial.name and 'dir_fd' in kwargs and not fired:
                partial.rename(self.root/'archive.tar.xz');fired.append(True)
            return original(name,*args,**kwargs)
        with patch.object(runtime.os,'stat',side_effect=moved):
            result=self.runner.run(self.command('print("finite completed")'))
        self.assertEqual(result.returncode,0);self.assertEqual(result.stdout,b'finite completed\n')
        self.assertTrue(fired)

    def test_repeated_rename_churn_refuses_after_three_bounded_scan_rounds(self):
        (self.root/'gone0').write_bytes(b'x');original=os.stat;renamed=[]
        def moved(name,*args,**kwargs):
            if isinstance(name,str) and name=='gone'+str(len(renamed)) and 'dir_fd' in kwargs:
                (self.root/name).rename(self.root/('gone'+str(len(renamed)+1)));renamed.append(name)
            return original(name,*args,**kwargs)
        with patch.object(runtime.os,'stat',side_effect=moved), \
             self.assertRaisesRegex(runtime.ResourceFailure,'private-scan-unstable') as error:
            self.runner.check_resources()
        self.assertEqual(len(renamed),3);self.assertEqual(error.exception.observation['entries'],4)

    def lifecycle_fixture(self):
        temporary=self.root/'tmp'; temporary.mkdir(mode=0o700)
        env={**self.env,'TMPDIR':str(temporary)}
        runner=runtime.Runner(env,self.root,self.root/'grant-logs',deadline_seconds=10)
        self.addCleanup(runner.close)
        files={name:b'# pinned source fixture\n'+name.encode() for name in (
            'scripts/client/stage.py','scripts/ci/source_suites.py','scripts/port/ksm-lifecycle/stage.py',
            'scripts/port/ksm-lifecycle/worker.py','scripts/port/ksm-lifecycle/contract.py')}
        pins={name:hashlib.sha256(data).hexdigest() for name,data in files.items()}
        filename='cachy-asahi-ksmctl-0.1.0-1-any.pkg.tar.xz'
        inputs={'bootstrap.json':b'{}\n','packages.lock':b'fixture lock\n','current-inputs.json':b'{}',
                'approved-inputs.json':b'{"fixture":true}\n',filename:b'fixture archive'}
        input_pins={name:hashlib.sha256(data).hexdigest() for name,data in inputs.items()}
        expected={'schema_version':1,'purpose':'ksm-diagnostic-development-lifecycle','scope':'DEVELOPMENT TEST ONLY',
            'phase':'lifecycle','source_commit':'a'*40,'run_id':'7','daemon_id':'daemon1234','image_id':'sha256:'+'b'*64,
            'uid':os.getuid(),'package':{'filename':filename,'sha256':input_pins[filename]},
            'approved_inputs_sha256':input_pins['approved-inputs.json'],'bootstrap_sha256':input_pins['bootstrap.json'],
            'packages_sha256':input_pins['packages.lock'],'current_inputs_sha256':input_pins['current-inputs.json'],
            'source_sha256':pins}
        record={**expected,'nonce':'c'*32,'signing':{'fingerprint':'D'*40,'signature_sha256':'e'*64,'public_key_sha256':'f'*64}}
        def populate(mode=0o644):
            stage=temporary/'ksm-private-stage-abcdefgh'; stage.mkdir(mode=0o700)
            source=stage/'source'; source.mkdir(mode=0o700); installed=stage/'installed'; installed.mkdir(mode=0o700)
            for name,data in {**files,**inputs,'inputs.json':json.dumps(record,sort_keys=True).encode()}.items():
                path=source/name; path.parent.mkdir(parents=True,exist_ok=True); path.write_bytes(data); path.chmod(0o644)
            receipt=installed/'worker-receipt.json'; receipt.write_bytes(b'{"partial":true}\n'); receipt.chmod(mode)
            return stage,receipt
        return runner,expected,pins,input_pins,populate

    def simulate_root_metadata(self, receipt, *, uid=0, gid=0):
        inode=receipt.stat().st_ino; original_stat=os.stat; original_fstat=os.fstat; original_open=os.open
        def root(info):
            if info.st_ino==inode:
                row=list(info); row[4]=uid; row[5]=gid; return os.stat_result(row)
            return info
        def observe(*args,**kwargs): return root(original_stat(*args,**kwargs))
        def inspect(*args,**kwargs): return root(original_fstat(*args,**kwargs))
        def opened(name,flags,*args,**kwargs):
            if name==receipt.name and 'dir_fd' in kwargs and not flags & os.O_PATH:
                raise PermissionError('fixture root receipt requires metadata-only O_PATH')
            return original_open(name,flags,*args,**kwargs)
        self.enterContext(patch.object(runtime.os,'stat',side_effect=observe))
        self.enterContext(patch.object(runtime.os,'fstat',side_effect=inspect))
        self.enterContext(patch.object(runtime.os,'open',side_effect=opened))

    def test_exact_root_lifecycle_receipt_modes_are_metadata_only_and_quota_charged(self):
        runner,expected,pins,inputs,populate=self.lifecycle_fixture()
        with runner.lifecycle_outputs(expected,pins,inputs):
            stage,receipt=populate(0o600); self.simulate_root_metadata(receipt)
            first=runner.check_resources(); self.assertGreaterEqual(first['bytes'],receipt.stat().st_size)
            receipt.chmod(0o644); second=runner.check_resources()
            self.assertEqual(second['status'],'PASS-observed-resources')
            with patch.object(runtime,'MAX_PRIVATE',0),self.assertRaisesRegex(runtime.ResourceFailure,'private-byte-bound'):
                runner.check_resources()
        with self.assertRaisesRegex(runtime.ResourceFailure,'private-foreign-owner'): runner.check_resources()

    def test_root_lifecycle_grant_refuses_wrong_contract_and_source_bytes(self):
        runner,expected,pins,inputs,populate=self.lifecycle_fixture()
        with runner.lifecycle_outputs(expected,pins,inputs):
            stage,receipt=populate(); self.simulate_root_metadata(receipt)
            contract=stage/'source/inputs.json'; record=json.loads(contract.read_bytes()); record['source_commit']='0'*40
            contract.write_text(json.dumps(record))
            with self.assertRaises(runtime.ResourceFailure): runner.check_resources()
            record['source_commit']=expected['source_commit']; contract.write_text(json.dumps(record,sort_keys=True))
            (stage/'source/scripts/port/ksm-lifecycle/worker.py').write_bytes(b'foreign source')
            with self.assertRaises(runtime.ResourceFailure): runner.check_resources()

    def test_root_lifecycle_grant_refuses_unknown_leaf_mode_size_and_links(self):
        runner,expected,pins,inputs,populate=self.lifecycle_fixture()
        with runner.lifecycle_outputs(expected,pins,inputs):
            stage,receipt=populate(); self.simulate_root_metadata(receipt)
            receipt.chmod(0o666)
            with self.assertRaises(runtime.ResourceFailure): runner.check_resources()
            receipt.chmod(0o644); receipt.write_bytes(b'x'*(1024**2+1))
            with self.assertRaises(runtime.ResourceFailure): runner.check_resources()
            receipt.write_bytes(b'bounded'); os.link(receipt,stage/'installed/extra-hardlink')
            with self.assertRaises(runtime.ResourceFailure): runner.check_resources()
            (stage/'installed/extra-hardlink').unlink(); receipt.rename(stage/'installed/unknown.json')
            with self.assertRaises(runtime.ResourceFailure): runner.check_resources()

    def test_root_lifecycle_grant_refuses_replaced_stage_and_contract_after_binding(self):
        runner,expected,pins,inputs,populate=self.lifecycle_fixture()
        with runner.lifecycle_outputs(expected,pins,inputs):
            stage,receipt=populate(); self.simulate_root_metadata(receipt); runner.check_resources()
            contract=stage/'source/inputs.json'; original=contract.read_bytes(); record=json.loads(original);record['nonce']='0'*32
            contract.write_text(json.dumps(record,sort_keys=True))
            with self.assertRaises(runtime.ResourceFailure): runner.check_resources()
            contract.write_bytes(original); stage.rename(stage.with_name('moved-stage')); stage.mkdir(mode=0o700)
            with self.assertRaises(runtime.ResourceFailure): runner.check_resources()

    def test_root_lifecycle_grant_refuses_copied_input_hash_drift(self):
        runner,expected,pins,inputs,populate=self.lifecycle_fixture()
        with runner.lifecycle_outputs(expected,pins,inputs):
            stage,receipt=populate(); self.simulate_root_metadata(receipt)
            (stage/'source/packages.lock').write_bytes(b'changed inventory')
            with self.assertRaisesRegex(runtime.ResourceFailure,'lifecycle-source-input-pin-drift'):
                runner.check_resources()

    def test_root_lifecycle_grant_requires_exact_root_gid(self):
        runner,expected,pins,inputs,populate=self.lifecycle_fixture()
        with runner.lifecycle_outputs(expected,pins,inputs):
            stage,receipt=populate(); self.simulate_root_metadata(receipt,gid=1)
            with self.assertRaisesRegex(runtime.ResourceFailure,'bounded-root-lifecycle-receipt-required'):
                runner.check_resources()

    def test_root_lifecycle_grant_refuses_duplicate_contract_fields(self):
        runner,expected,pins,inputs,populate=self.lifecycle_fixture()
        with runner.lifecycle_outputs(expected,pins,inputs):
            stage,receipt=populate(); self.simulate_root_metadata(receipt)
            contract=stage/'source/inputs.json'; data=contract.read_bytes()
            contract.write_bytes(b'{"phase":"lifecycle",'+data[1:])
            with self.assertRaisesRegex(runtime.ResourceFailure,'duplicate-lifecycle-output-contract-field'):
                runner.check_resources()

    def test_root_lifecycle_grant_requires_fresh_owned_exact_tmp_namespace(self):
        runner,expected,pins,inputs,populate=self.lifecycle_fixture();populate()
        with self.assertRaises((ValueError,OSError)):
            with runner.lifecycle_outputs(expected,pins,inputs): pass
        without=runtime.Runner(self.env,self.root,self.root/'no-tmp-logs',deadline_seconds=10)
        self.addCleanup(without.close)
        with self.assertRaises((ValueError,OSError)):
            with without.lifecycle_outputs(expected,pins,inputs): pass

    def test_root_lifecycle_grant_refuses_replaced_receipt_inode(self):
        runner,expected,pins,inputs,populate=self.lifecycle_fixture()
        with runner.lifecycle_outputs(expected,pins,inputs):
            stage,receipt=populate(); self.simulate_root_metadata(receipt); runner.check_resources()
            receipt.rename(stage/'installed/moved-receipt');receipt.write_bytes(b'foreign replacement');receipt.chmod(0o644)
            with self.assertRaises(runtime.ResourceFailure): runner.check_resources()

    def test_resource_observation_unavailable_is_unknown_failure(self):
        with patch.object(runtime.os, 'fstatvfs', side_effect=OSError('unavailable')), self.assertRaises(runtime.ResourceFailure) as caught:
            self.runner.check_resources()
        self.assertFalse(caught.exception.observation['known'])
        self.assertEqual(caught.exception.observation['reason'], 'resource-observation-unavailable')

    def test_sealed_elf_exec_transport_and_absolute_private_log(self):
        fd = os.memfd_create('reviewed-true-elf-fixture', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        try:
            data = Path('/usr/bin/true').read_bytes()
            self.assertTrue(data.startswith(b'\x7fELF'))
            os.write(fd, data)
            seals = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
            result = self.runner.run([f'/proc/self/fd/{fd}'], pass_fds=(fd,), log=self.root / 'logs/elf.log')
            self.assertEqual(result.returncode, 0); os.fstat(fd)
            self.assertEqual(stat.S_IMODE((self.root / 'logs/elf.log').stat().st_mode), 0o600)
        finally: os.close(fd)

    def sealed_true(self):
        fd = os.memfd_create('cleanup-benign-elf', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        self.addCleanup(os.close, fd)
        os.write(fd, Path('/usr/bin/true').read_bytes())
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK |
                    fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE)
        return fd, [f'/proc/self/fd/{fd}', '--host=unix:///run/docker.sock',
                    'rm', '--force', '--volumes', 'a' * 64]

    def test_cleanup_image_capability_requires_no_prune_and_refuses_force(self):
        fd,command=self.sealed_true();image='sha256:'+'a'*64
        prefix=command[:2]
        with runtime.cancellation_handlers():
            result=self.runner.run(prefix+['image','rm','--no-prune',image],pass_fds=(fd,),cleanup=True)
            self.assertEqual(result.returncode,0)
            for deletion in (['image','rm',image],['image','rm','--force','--no-prune',image],['rmi','--no-prune',image]):
                with patch.object(runtime.subprocess,'Popen') as spawn,self.assertRaisesRegex(ValueError,'cleanup-command-refused'):
                    self.runner.run(prefix+deletion,pass_fds=(fd,),cleanup=True)
                spawn.assert_not_called()

    def test_phase_scope_clamps_nested_scopes_without_extending_aggregate(self):
        aggregate = self.runner.deadline
        phase = time.monotonic() + .2
        with self.runner.phase_scope(phase):
            self.assertEqual(self.runner.phase_deadline, phase)
            with self.runner.phase_scope(aggregate):
                self.assertEqual(self.runner.phase_deadline, phase)
            with self.assertRaisesRegex(ValueError, 'invalid-phase-deadline'):
                with self.runner.phase_scope(aggregate + 1): pass
        self.assertEqual(self.runner.phase_deadline, aggregate)
        self.assertEqual(self.runner.deadline, aggregate)
        with patch.object(runtime.subprocess, 'Popen') as spawn:
            with self.assertRaisesRegex(ValueError, 'invalid-phase-deadline'):
                with self.runner.phase_scope(time.monotonic() - 1):
                    self.runner.run(self.command('print("never")'))
            spawn.assert_not_called()

    def test_nested_service_cannot_borrow_time_reserved_for_later_phases(self):
        nested = runtime.Runner(self.env, self.root, self.root / 'nested-logs',
                                deadline_seconds=10, deadline_at=self.runner.deadline)
        self.addCleanup(nested.close)
        children, original = [], subprocess.Popen
        def spawn(*args, **kwargs):
            child = original(*args, **kwargs); children.append(child); return child
        def service():
            with nested.phase_scope(self.runner.phase_deadline):
                nested.run(self.command('import time;time.sleep(3)'), timeout=5)
        started = time.monotonic()
        with patch.object(runtime.subprocess, 'Popen', side_effect=spawn):
            with self.runner.phase_scope(started + .12), self.assertRaisesRegex(ValueError, 'timeout|deadline'):
                self.runner.run(self.command('import time;time.sleep(3)'), service=service)
        self.assertLess(time.monotonic() - started, 1)
        self.assertGreater(self.runner.deadline, time.monotonic() + 1)
        self.assertEqual(len(children), 2)
        for child in children:
            self.assertIsNotNone(child.poll())
            with self.assertRaises(ProcessLookupError): os.killpg(child.pid, 0)

    def test_cleanup_actual_sealed_elf_after_resource_failure_and_sticky_cancel(self):
        fd, argv = self.sealed_true()
        (self.root / 'unsafe').symlink_to('/tmp')
        with self.assertRaises(runtime.ResourceFailure): self.runner.check_resources()
        failure = dict(self.runner.resource_observation)
        children, original = [], subprocess.Popen
        def spawn(*args, **kwargs):
            child = original(*args, **kwargs); children.append(child); return child
        previous = {sig: signal.getsignal(sig) for sig in runtime.SIGNALS}
        with patch.object(runtime.subprocess, 'Popen', side_effect=spawn), self.assertRaises(runtime.Cancelled):
            with runtime.cancellation_handlers() as state:
                with runtime.defer_signals():
                    os.kill(os.getpid(), signal.SIGTERM)
                    with self.assertRaises(runtime.Cancelled):
                        self.runner.run(argv, pass_fds=(fd,))
                    result = self.runner.run(argv, pass_fds=(fd,), cleanup=True)
                    self.assertEqual(result.returncode, 0)
                    self.assertEqual(state.signum, signal.SIGTERM)
                    self.assertEqual(self.runner.resource_observation, failure)
                    self.assertEqual(len(children), 1)
                runtime.check_cancelled()
        self.assertEqual({sig: signal.getsignal(sig) for sig in runtime.SIGNALS}, previous)
        self.assertIsNotNone(children[0].poll())
        with self.assertRaises(ProcessLookupError): os.killpg(children[0].pid, 0)

    def test_cleanup_second_real_signal_during_disposal_keeps_cancellation(self):
        fd, argv = self.sealed_true()
        original, disposed = runtime._cleanup, []
        def cleanup(child):
            os.kill(os.getpid(), signal.SIGINT)
            original(child); disposed.append(child.pid)
        with patch.object(runtime, '_cleanup', side_effect=cleanup), self.assertRaises(runtime.Cancelled):
            with runtime.cancellation_handlers() as state:
                with runtime.defer_signals():
                    runtime.mark_cancelled()
                    self.assertEqual(self.runner.run(argv, pass_fds=(fd,), cleanup=True).returncode, 0)
                    self.assertEqual(state.signum, signal.SIGINT)
                    self.assertEqual(len(disposed), 1)
                    with self.assertRaises(ProcessLookupError): os.killpg(disposed[0], 0)
                runtime.check_cancelled()

    def test_cleanup_refuses_unscoped_cancel_unsealed_and_broader_commands(self):
        fd, argv = self.sealed_true()
        with patch.object(runtime.subprocess, 'Popen') as spawn:
            with self.assertRaisesRegex(ValueError, 'parent-deferred'):
                self.runner.run(argv, pass_fds=(fd,), cleanup=True)
            with runtime.cancellation_handlers():
                for args in (['build', '.'], ['run', 'image'], ['create', 'image'], ['start', 'a' * 64],
                             ['sh', '-c', 'true'], ['rm', '--force', '--volumes', 'unowned']):
                    with self.subTest(args=args), self.assertRaisesRegex(ValueError, 'command-refused'):
                        self.runner.run(argv[:2] + args, pass_fds=(fd,), cleanup=True)
                with self.assertRaisesRegex(ValueError, 'endpoint-required'):
                    self.runner.run([argv[0], '--host=tcp://remote', *argv[2:]], pass_fds=(fd,), cleanup=True)
                with self.assertRaisesRegex(ValueError, 'sealed-no-log'):
                    self.runner.run(argv, pass_fds=(fd,), log='never.log', cleanup=True)
                with self.assertRaisesRegex(ValueError, 'sealed-no-log'):
                    self.runner.run(argv, pass_fds=(fd,), service=lambda: None, cleanup=True)
                with self.assertRaisesRegex(ValueError, 'owned-sealed-elf'):
                    self.runner.run(['/usr/bin/true', *argv[1:]], pass_fds=(fd,), cleanup=True)
                unsealed = os.memfd_create('not-sealed', os.MFD_ALLOW_SEALING)
                try:
                    os.write(unsealed, Path('/usr/bin/true').read_bytes())
                    with self.assertRaisesRegex(ValueError, 'unsealed-pass-fd'):
                        self.runner.run([f'/proc/self/fd/{unsealed}', *argv[1:]], pass_fds=(unsealed,), cleanup=True)
                finally: os.close(unsealed)
            spawn.assert_not_called()
        with self.assertRaises(runtime.Cancelled):
            with runtime.cancellation_handlers():
                runtime.mark_cancelled()
                with self.assertRaisesRegex(ValueError, 'parent-deferred'):
                    self.runner.run(argv, pass_fds=(fd,), cleanup=True)

    def test_cancellation_bridge_preserves_first_mark_and_checks_explicitly(self):
        runtime.check_cancelled()
        with self.assertRaisesRegex(ValueError, 'active-cancellation'):
            runtime.mark_cancelled()
        with self.assertRaises(runtime.Cancelled):
            with runtime.cancellation_handlers() as state:
                runtime.mark_cancelled(signal.SIGINT)
                runtime.mark_cancelled(signal.SIGTERM)
                self.assertEqual(state.signum, signal.SIGINT)
                runtime.check_cancelled()

    def test_cleanup_output_cap_kills_actual_sealed_elf_without_private_writes(self):
        fd = os.memfd_create('cleanup-output-fixture', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        self.addCleanup(os.close, fd)
        os.write(fd, Path('/usr/bin/yes').read_bytes())
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK |
                    fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE)
        children, original = [], subprocess.Popen
        def spawn(*args, **kwargs):
            child = original(*args, **kwargs); children.append(child); return child
        before = set(self.root.rglob('*'))
        # The benign output fixture lacks Docker's CLI; command grammar is
        # independently exercised above, while this case isolates the cap.
        with runtime.cancellation_handlers(), patch.object(runtime.subprocess, 'Popen', side_effect=spawn), \
             patch.object(runtime, '_cleanup_grammar', return_value=None):
            with self.assertRaisesRegex(ValueError, 'output-bound'):
                self.runner.run([f'/proc/self/fd/{fd}'],
                                limit=runtime.MAX_OUTPUT, pass_fds=(fd,), cleanup=True)
        self.assertEqual(set(self.root.rglob('*')), before)
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].poll())
        with self.assertRaises(ProcessLookupError): os.killpg(children[0].pid, 0)

    def test_cleanup_cannot_bypass_expired_phase_deadline(self):
        fd, argv = self.sealed_true()
        with runtime.cancellation_handlers(), self.runner.phase_scope(time.monotonic() + .02):
            time.sleep(.03)
            with patch.object(runtime.subprocess, 'Popen') as spawn:
                with self.assertRaisesRegex(ValueError, 'phase-deadline-exhausted'):
                    self.runner.run(argv, pass_fds=(fd,), cleanup=True)
                spawn.assert_not_called()



class RuntimeObservationTests(unittest.TestCase):
    setUp = RuntimeTests.setUp
    command = RuntimeTests.command
    def test_actual_return_and_existing_natural_poll_are_distinct_from_cleanup(self):
        observed=runtime.RunObservation();self.runner.observation=observed
        result=self.runner.run(self.command('raise SystemExit(7)'))
        self.assertEqual(result.returncode,7)
        self.assertEqual(observed.summary(),{'started':True,'natural_poll_code':7,'runner_return_code':7,
            'reaping':'COMPLETED','reaped_code':7,'before_cleanup':{'state':'exited','returncode':7}})

    def test_callback_broken_pipe_leaves_return_unobserved_and_reaps_owned_sleeper(self):
        observed=runtime.RunObservation();self.runner.observation=observed
        def broken():
            read,write=os.pipe();os.close(read)
            try:os.write(write,b'finite reply')
            finally:os.close(write)
        with self.assertRaises(BrokenPipeError):self.runner.run(self.command('import time;time.sleep(30)'),service=broken)
        row=observed.summary();self.assertTrue(row['started']);self.assertIsNone(row['natural_poll_code'])
        self.assertIsNone(row['runner_return_code']);self.assertEqual(row['reaping'],'COMPLETED')
        self.assertIsNotNone(row['reaped_code'])
        self.assertEqual(row['before_cleanup'],{'state':'alive','returncode':None})

    def test_callback_broken_pipe_observes_already_exited_child_before_cleanup(self):
        observed=runtime.RunObservation();self.runner.observation=observed
        children=[];spawn=runtime.subprocess.Popen
        def start(*args,**kwargs):
            child=spawn(*args,**kwargs);children.append(child);return child
        def broken():
            os.waitid(os.P_PID,children[0].pid,os.WEXITED|os.WNOWAIT)
            read,write=os.pipe();os.close(read)
            try:os.write(write,b'finite reply')
            finally:os.close(write)
        with patch.object(runtime.subprocess,'Popen',side_effect=start),self.assertRaises(BrokenPipeError):
            self.runner.run(self.command('raise SystemExit(1)'),service=broken)
        self.assertEqual(observed.before_cleanup,{'state':'exited','returncode':1})
        self.assertIsNone(observed.natural_poll_code);self.assertIsNone(observed.runner_return_code)
        self.assertEqual(observed.reaped_code,1)

    def test_zero_exit_precleanup_agrees_without_rewriting_other_observations(self):
        observed=runtime.RunObservation();self.runner.observation=observed
        self.assertEqual(self.runner.run(self.command('raise SystemExit(0)')).returncode,0)
        self.assertEqual(observed.before_cleanup,{'state':'exited','returncode':0})
        self.assertEqual((observed.natural_poll_code,observed.runner_return_code,observed.reaped_code),(0,0,0))

    def test_precleanup_poll_errors_preserve_original_callback_exception_identity(self):
        spawn=runtime.subprocess.Popen
        for first in (ValueError('original callback'),runtime.Cancelled(signal.SIGTERM)):
            for fault in (OSError('unavailable poll'),runtime.Cancelled(signal.SIGINT)):
                with self.subTest(first=type(first),fault=type(fault)):
                    observed=runtime.RunObservation();self.runner.observation=observed
                    calls=[];disposing=[];cleanup=runtime._cleanup
                    def dispose(child):
                        disposing.append(True);return cleanup(child)
                    def start(*args,**kwargs):
                        child=spawn(*args,**kwargs);poll=child.poll
                        def broken_poll():
                            if disposing:return poll()
                            calls.append(True);child.poll=poll;raise fault
                        child.poll=broken_poll;return child
                    def fail():raise first
                    with patch.object(runtime.subprocess,'Popen',side_effect=start), \
                         patch.object(runtime,'_cleanup',side_effect=dispose),self.assertRaises(type(first)) as caught:
                        self.runner.run(self.command('import time;time.sleep(30)'),service=fail)
                    self.assertIs(caught.exception,first);self.assertEqual(calls,[True])
                    self.assertEqual(observed.before_cleanup,{'state':'unavailable','returncode':None})
                    self.assertEqual(observed.reaping,'COMPLETED')

    def test_precleanup_codes_are_exact_bounded_and_no_handle_is_unavailable(self):
        for value in (None,-128,-6,0,255,True,False,-129,256,'1',1.0):
            with self.subTest(value=value):
                observed=runtime.RunObservation();calls=[]
                def poll():calls.append(True);return value
                observed.observe_before_cleanup(SimpleNamespace(poll=poll))
                expected=({'state':'alive','returncode':None} if value is None else
                    {'state':'exited','returncode':value} if type(value) is int and -128<=value<=255 else
                    {'state':'unavailable','returncode':None})
                self.assertEqual(observed.summary()['before_cleanup'],expected);self.assertEqual(calls,[True])
        observed=runtime.RunObservation();self.runner.observation=observed
        first=OSError('spawn unavailable')
        with patch.object(runtime.subprocess,'Popen',side_effect=first),self.assertRaises(OSError) as caught:
            self.runner.run(self.command('pass'))
        self.assertIs(caught.exception,first);self.assertFalse(observed.started)
        self.assertEqual(observed.before_cleanup,{'state':'unavailable','returncode':None})
        self.assertEqual(observed.reaping,'NOT RUN')

    def test_registration_failure_samples_actual_handle_before_cleanup(self):
        observed=runtime.RunObservation();self.runner.observation=observed
        first=OSError('registration unavailable');selector=runtime.selectors.DefaultSelector
        def create():
            instance=selector();instance.register=lambda *_: (_ for _ in ()).throw(first);return instance
        with patch.object(runtime.selectors,'DefaultSelector',side_effect=create),self.assertRaises(OSError) as caught:
            self.runner.run(self.command('import time;time.sleep(30)'))
        self.assertIs(caught.exception,first)
        self.assertEqual(observed.before_cleanup,{'state':'alive','returncode':None})
        self.assertEqual(observed.reaping,'COMPLETED')

    def test_observation_dispatch_failure_preserves_first_exception_and_cleanup(self):
        first=BrokenPipeError('original reply failure')
        for fault in (OSError('observation unavailable'),runtime.Cancelled(signal.SIGINT)):
            with self.subTest(fault=type(fault)):
                observed=runtime.RunObservation();self.runner.observation=observed
                def fail():raise first
                with patch.object(observed,'observe_before_cleanup',side_effect=fault),self.assertRaises(BrokenPipeError) as caught:
                    self.runner.run(self.command('import time;time.sleep(30)'),service=fail)
                self.assertIs(caught.exception,first)
                self.assertEqual(observed.before_cleanup,{'state':'unavailable','returncode':None})
                self.assertEqual(observed.reaping,'COMPLETED')

    def test_late_log_error_keeps_poll_but_never_claims_runner_return(self):
        observed=runtime.RunObservation();self.runner.observation=observed
        original=self.runner._check_log;calls=[]
        def late(*args):
            calls.append(1)
            if len(calls)>=2:raise OSError('private log observation failure')
            return original(*args)
        with patch.object(self.runner,'_check_log',side_effect=late),self.assertRaises(OSError):
            self.runner.run(self.command('raise SystemExit(0)'),log='probe.log')
        self.assertEqual(observed.natural_poll_code,0);self.assertIsNone(observed.runner_return_code)
        self.assertEqual(observed.reaping,'COMPLETED')

    def test_cleanup_failure_is_observation_and_preserves_original_exception(self):
        observed=runtime.RunObservation();self.runner.observation=observed
        original=runtime._cleanup
        def fail(process):original(process);raise ValueError('private cleanup failure')
        with patch.object(runtime,'_cleanup',side_effect=fail),self.assertRaisesRegex(ValueError,'private cleanup'):
            self.runner.run(self.command('raise SystemExit(0)'))
        self.assertEqual(observed.reaping,'FAILED');self.assertEqual(observed.reaped_code,0)
        self.assertIsNone(observed.runner_return_code)

    def test_observer_adds_exactly_one_poll_before_any_cleanup_operation(self):
        traces=[]
        original_spawn=runtime.subprocess.Popen;original_cleanup=runtime._cleanup
        for enabled in (False,True):
            trace=[]
            def spawn(*args,**kwargs):
                process=original_spawn(*args,**kwargs);poll=process.poll
                def observed_poll():trace.append('poll');return poll()
                process.poll=observed_poll;return process
            def cleanup(process):trace.append('cleanup');return original_cleanup(process)
            def fail():raise BrokenPipeError('closed fixture reply')
            self.runner.observation=runtime.RunObservation() if enabled else None
            with patch.object(runtime.subprocess,'Popen',side_effect=spawn),patch.object(runtime,'_cleanup',side_effect=cleanup):
                with self.assertRaises(BrokenPipeError):
                    self.runner.run(self.command('import time;time.sleep(30)'),service=fail)
            traces.append(trace)
        # Callback fails before the ordinary loop poll. Cleanup itself is unchanged.
        self.assertEqual([x[:x.index('cleanup')] for x in traces],[[],['poll']])
        self.assertEqual([x.count('cleanup') for x in traces],[1,1])
        self.assertTrue(all(x and set(x)<={'poll','cleanup'} for x in traces))



if __name__ == '__main__':
    unittest.main()

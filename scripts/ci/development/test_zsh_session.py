# SPDX-License-Identifier: MIT
"""Source-only models/private files; no actual Session authority or actors."""
import ast
from contextlib import ExitStack, nullcontext
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


adapter = load('zsh_session_fixture', HERE / 'zsh_session.py')
addon = load('zsh_session_held_addon_fixture', HERE / 'zsh_addon.py')


class BudgetTests(unittest.TestCase):
    def test_job_cutoff_clips_stage_and_reserves_cleanup_without_renewal(self):
        tick = [100.0]
        with patch.object(adapter.time, 'monotonic', side_effect=lambda: tick[0]):
            budget = adapter.Budget(500.0)
            self.assertEqual((budget.start, budget.end, budget.work_end), (100.0, 500.0, 380.0))
            self.assertEqual(budget.remaining(1200), 280.0)
            tick[0] = 200.0
            self.assertEqual(budget.remaining(1200), 180.0)
            self.assertEqual(budget.remaining(1200, True), 300.0)
            self.assertEqual((budget.end, budget.work_end), (500.0, 380.0))

    def test_long_job_retains_original_1200_total_and_1080_work_caps(self):
        with patch.object(adapter.time, 'monotonic', return_value=50.0):
            budget = adapter.Budget(9000.0)
            self.assertEqual((budget.end, budget.work_end), (1250.0, 1130.0))

    def test_nonfinite_boolean_and_expired_job_cutoffs_refuse(self):
        with patch.object(adapter.time, 'monotonic', return_value=10.0):
            for value in (True, False, None, '500', float('nan'), float('inf'), -1, 10, 9):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    adapter.Budget(value)

    def test_operation_caps_cannot_expand_or_renew_budget(self):
        with patch.object(adapter.time, 'monotonic', return_value=0.0):
            budget = adapter.Budget(1200.0)
            for value in (True, False, 0, -1, 1201, float('inf'), float('nan'), '1'):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    budget.remaining(value)

    def test_work_expiry_keeps_existing_cleanup_endpoint(self):
        tick = [0.0]
        with patch.object(adapter.time, 'monotonic', side_effect=lambda: tick[0]):
            budget = adapter.Budget(600.0)
            tick[0] = 480.0
            with self.assertRaises(ValueError):
                budget.remaining(1)
            self.assertEqual(budget.remaining(1200, True), 120.0)
            tick[0] = 600.0
            with self.assertRaises(ValueError):
                budget.remaining(1, True)


class ContextRefusalTests(unittest.TestCase):
    def test_detached_fake_session_refuses_before_context_method(self):
        calls = []
        fake = SimpleNamespace(job_deadline=1200.0, source_graph={},
                               original_context=lambda **kw: calls.append(kw))
        with patch.object(adapter.time, 'monotonic', return_value=0.0), self.assertRaises(ValueError):
            adapter.borrow_context(fake, object(), Path('/inert-full-root'), 100.0)
        self.assertEqual(calls, [])

    def test_same_named_class_and_instance_method_shadow_are_not_authority(self):
        calls = []
        Fake = type('Session', (), {'original_context': lambda self, **kw: calls.append(kw)})
        fake = Fake()
        fake.job_deadline, fake.source_graph = 1200.0, {}
        fake.original_context = lambda **kw: calls.append(kw)
        with patch.object(adapter.time, 'monotonic', return_value=0.0), self.assertRaises(ValueError):
            adapter.borrow_context(fake, object(), Path('/inert-full-root'), 100.0)
        self.assertEqual(calls, [])


class SourceBoundaryTests(unittest.TestCase):
    def test_top_level_imports_are_stdlib_and_no_old_authority_dispatch(self):
        tree = ast.parse((HERE / 'zsh_session.py').read_bytes())
        allowed = {'argparse', 'contextlib', 'hashlib', 'importlib', 'json', 'math', 'os', 'pathlib',
                   'platform', 're', 'selectors', 'shutil', 'signal', 'stat', 'subprocess',
                   'sys', 'tempfile', 'time', 'types'}
        for node in tree.body:
            if isinstance(node, ast.Import):
                self.assertTrue(all(alias.name.split('.')[0] in allowed for alias in node.names))
            elif isinstance(node, ast.ImportFrom):
                self.assertIn(node.module.split('.')[0], allowed)
        forbidden = {'SourceAuthority', 'prepare_initial_view', 'BytesLoader', 'run_native', '_AUTHORITY_ENTRY'}
        calls = {n.func.id if isinstance(n.func, ast.Name) else n.func.attr
                 for n in ast.walk(tree) if isinstance(n, ast.Call)
                 and isinstance(n.func, (ast.Name, ast.Attribute))}
        self.assertEqual(calls & forbidden, set())


class PrivateFileTests(unittest.TestCase):
    """Models only: these sources/context bytes cannot grant actual Session custody."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.tick = [0.0]
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(adapter.time, 'monotonic', side_effect=lambda: self.tick[0]))
        self.stack.enter_context(patch.object(adapter.signal, 'pthread_sigmask', return_value=set()))
        self.budget = adapter.Budget(1200.0)
        self.guards = []
        self.rows = {'scripts/build/container-entry.sh': {'sha256': 'a' * 64, 'mode': 0o644}}
        self.raw = {'scripts/build/build.py': b'# captured inert build\n',
                    'scripts/build/compare.py': b'# captured inert compare\n',
                    'scripts/checks/package_checks.py': b'# captured inert checker\n'}
        self.session = SimpleNamespace(cancelled=False, sources=SimpleNamespace(
            root=self.root/'full-root', raw=self.raw, original_rows=self.rows,
            guard=lambda *args: self.guards.append(args)))
        files = {name: {**row, 'bytes': 1, 'source_node': [1], 'copy_node': [2]}
                 for name, row in self.rows.items()}
        self.context = {'root': self.root/'actual-view-model',
                        'receipt': json.dumps({'files': files}).encode()}

    def test_bootstrap_embeds_exact_three_captured_sources_and_private_mode(self):
        output = self.root/'bootstrap.py'
        script = self.context['root']/'scripts/build/build.py'
        adapter.write_bootstrap_session(output, self.session, self.context, script, self.budget)
        tree = ast.parse(output.read_bytes())
        declaration = next(n for n in tree.body if isinstance(n, ast.Assign)
                           and any(isinstance(t, ast.Name) and t.id == 'M' for t in n.targets))
        modules = ast.literal_eval(declaration.value)
        self.assertEqual(set(modules), {'build', 'compare', 'package_checks'})
        for name, relative in (('build','scripts/build/build.py'), ('compare','scripts/build/compare.py'),
                               ('package_checks','scripts/checks/package_checks.py')):
            self.assertEqual(modules[name], {'path': str(self.context['root']/relative), 'data': self.raw[relative]})
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.guards, [(1080.0, False), (1080.0, False)])
        self.assertEqual(list(self.root.rglob('*.pyc')), [])

    def test_bootstrap_wrong_script_or_existing_foreign_target_refuses(self):
        output = self.root/'foreign.py'; output.write_bytes(b'foreign retained')
        with self.assertRaises(ValueError):
            adapter.write_bootstrap_session(self.root/'new.py', self.session, self.context,
                                             self.root/'wrong/build.py', self.budget)
        with self.assertRaises(FileExistsError):
            adapter.write_bootstrap_session(output, self.session, self.context,
                self.context['root']/'scripts/build/compare.py', self.budget)
        self.assertEqual(output.read_bytes(), b'foreign retained')
        self.assertFalse((self.root/'new.py').exists())

    def test_postmask_expiry_allocates_no_bootstrap_file(self):
        def masking(how, numbers):
            if how == signal.SIG_BLOCK:
                self.tick[0] = 1080.0
            return set()
        with patch.object(adapter.signal, 'pthread_sigmask', side_effect=masking), self.assertRaises(ValueError):
            adapter.write_bytes(self.root/'expired.py', b'# inert\n', self.budget)
        self.assertFalse((self.root/'expired.py').exists())

    def test_partial_writes_keep_original_deadline_and_exact_bytes(self):
        original_write = os.write
        writes = []
        def short(fd, data):
            writes.append(len(data)); self.tick[0] += 1
            return original_write(fd, data[:2])
        with patch.object(adapter.os, 'write', side_effect=short):
            adapter.write_bytes(self.root/'short.py', b'1234567', self.budget)
        self.assertEqual((self.root/'short.py').read_bytes(), b'1234567')
        self.assertEqual(writes, [7, 5, 3, 1])
        self.assertEqual((self.budget.end, self.budget.work_end), (1200.0, 1080.0))

    def test_reader_latency_stops_before_next_chunk_and_closes_owned_descriptor(self):
        source=self.root/'large.input';source.write_bytes(b'a'*140000)
        actual_read,actual_close=os.read,os.close
        chunks=[]
        def delayed(fd,size):
            self.assertLessEqual(size,65536)
            data=actual_read(fd,size);chunks.append(len(data));self.tick[0]=1080.0
            return data
        with patch.object(adapter.os,'read',side_effect=delayed), patch.object(adapter.os,'close',wraps=actual_close) as close:
            with self.assertRaises(ValueError):adapter.read_session(addon,source,self.budget)
        self.assertEqual(chunks,[65536])
        self.assertEqual(close.call_count,1)
        self.assertEqual((self.budget.end,self.budget.work_end),(1200.0,1080.0))

    def test_reader_foreign_link_is_refused_before_open(self):
        source=self.root/'source';source.write_bytes(b'foreign fixture retained')
        link=self.root/'symlink';link.symlink_to(source)
        with patch.object(adapter.os,'open',wraps=os.open) as opened, self.assertRaises(ValueError):
            adapter.read_session(addon,link,self.budget)
        opened.assert_not_called()
        self.assertEqual(source.read_bytes(),b'foreign fixture retained')

    def test_partial_receipt_expiry_disposes_temporary_without_late_commit(self):
        target=self.root/'receipt.json';actual_write=os.write
        writes=[]
        def delayed(fd,data):
            writes.append(len(data));written=actual_write(fd,data[:2]);self.tick[0]=1080.0
            return written
        with patch.object(addon,'defer_cancel',side_effect=lambda:nullcontext([])), patch.object(adapter.os,'write',side_effect=delayed):
            with self.assertRaises(ValueError):adapter.save_session(addon,target,{'status':'PASS'},self.budget)
        self.assertEqual(len(writes),1)
        self.assertFalse(target.exists())
        self.assertEqual(list(self.root.glob('*.partial-*')),[])
        self.assertFalse(addon._RECEIPT_FDS)
        self.assertFalse(addon._RECEIPT_FILES)
        self.assertEqual(self.budget.work_end,1080.0)

    def test_reader_postmask_control_keeps_registered_fd_and_closes_it(self):
        source=self.root/'masked.input';source.write_bytes(b'private inert bytes')
        first=KeyboardInterrupt('modeled pending control after read allocation')
        original_open,original_close=os.open,os.close
        descriptors=[];restores=[0]
        def opened(*args,**kwargs):
            fd=original_open(*args,**kwargs);descriptors.append(fd);return fd
        def mask(how,numbers):
            if how==signal.SIG_SETMASK:
                restores[0]+=1
                if restores[0]==1:raise first
            return set()
        try:
            with patch.object(adapter.os,'open',side_effect=opened), patch.object(adapter.signal,'pthread_sigmask',side_effect=mask):
                with self.assertRaises(KeyboardInterrupt) as caught:adapter.read_session(addon,source,self.budget)
            self.assertIs(caught.exception,first)
            self.assertEqual(len(descriptors),1)
            with self.assertRaises(OSError):os.fstat(descriptors[0])
        finally:
            for fd in descriptors:
                try:original_close(fd)
                except OSError:pass

    def test_reader_late_lstat_refuses_before_fd_allocation(self):
        source=self.root/'late-stat.input';source.write_bytes(b'inert')
        original=Path.lstat
        def delayed(path,*args,**kwargs):
            result=original(path,*args,**kwargs)
            if path==source:self.tick[0]=1080.0
            return result
        with patch.object(Path,'lstat',delayed), patch.object(adapter.os,'open',wraps=os.open) as opened:
            with self.assertRaises(ValueError):adapter.read_session(addon,source,self.budget)
        opened.assert_not_called()

    def test_late_urandom_refuses_receipt_temporary_allocation(self):
        target=self.root/'no-late-receipt.json';original_open=addon.receipt_open
        allocations=[]
        def allocate(path,flags,**kwargs):
            if flags & os.O_CREAT:allocations.append(str(path))
            return original_open(path,flags,**kwargs)
        def delayed(size):self.tick[0]=1080.0;return b'x'*size
        with patch.object(addon,'defer_cancel',side_effect=lambda:nullcontext([])), patch.object(adapter.os,'urandom',side_effect=delayed), patch.object(addon,'receipt_open',side_effect=allocate):
            with self.assertRaises(ValueError):adapter.save_session(addon,target,{'status':'PASS'},self.budget)
        self.assertEqual(allocations,[])
        self.assertFalse(target.exists())
        self.assertFalse(addon._RECEIPT_FDS)

    def test_persistent_read_close_fault_preserves_firstcause_and_records_uncertainty(self):
        source=self.root/'close-fault.input';source.write_bytes(b'inert')
        first=OSError('first modeled read fault');original_open,original_close=os.open,os.close
        descriptors=[]
        def opened(*args,**kwargs):
            fd=original_open(*args,**kwargs);descriptors.append(fd);return fd
        try:
            with patch.object(adapter.os,'open',side_effect=opened), patch.object(adapter.os,'read',side_effect=first), patch.object(adapter.os,'close',side_effect=OSError('persistent modeled close fault')):
                with self.assertRaises(OSError) as caught:adapter.read_session(addon,source,self.budget)
            self.assertIs(caught.exception,first)
            self.assertTrue(self.budget.io_uncertain)
            self.assertEqual(len(descriptors),1)
            self.assertTrue(os.fstat(descriptors[0]))
        finally:
            for fd in descriptors:
                try:original_close(fd)
                except OSError:pass

    def test_actual_receipt_files_project_only_selected_original_rows(self):
        attempt=self.root/'attempt';attempt.mkdir()
        (attempt/'provenance.json').write_text('{}')
        before=copy.deepcopy(self.rows)
        with self.assertRaisesRegex(ValueError,'attempt-binding-refused'):
            adapter.validate_attempt_session(addon,self.session,self.context,attempt,{}, {},{},self.budget)
        self.assertEqual(self.rows,before)
        self.assertEqual(self.guards,[(1080.0,False)])

    def test_receipt_source_hash_or_mode_drift_refuses_before_held_validator(self):
        for field, value in (('sha256','b'*64), ('mode',0o755)):
            context = dict(self.context)
            receipt = json.loads(context['receipt'])
            receipt['files']['scripts/build/container-entry.sh'][field] = value
            context['receipt'] = json.dumps(receipt).encode()
            with self.subTest(field=field), patch.object(adapter,'read_session') as reader:
                with self.assertRaisesRegex(ValueError,'original-row-drift'):
                    adapter.validate_attempt_session(addon,self.session,context,
                        self.root/'absent-attempt',{}, {},{},self.budget)
                reader.assert_not_called()

    def test_validator_projection_cannot_mutate_selected_original_rows(self):
        before = copy.deepcopy(self.rows)
        context_before=self.context['receipt']
        attempt=self.root/'attempt';attempt.mkdir()
        (attempt/'provenance.json').write_text('{}')
        with self.assertRaisesRegex(ValueError,'attempt-binding-refused'):
            adapter.validate_attempt_session(addon,self.session,self.context,attempt,{}, {},{},self.budget)
        self.assertEqual(self.rows,before)
        self.assertEqual(self.context['receipt'],context_before)


class DockerWrapperModelTests(unittest.TestCase):
    def test_exact_actor_environment_endpoint_and_cleanup_quota_forwarding(self):
        config = {'actor_env': {'PATH':'/usr/bin:/bin','HOME':'/private/model-home','LC_ALL':'C'},
                  'docker':'/inert/docker','endpoint':'unix:///inert/model.sock',
                  'docker_config':'/private/model-config','quota_root':'/private/model-output'}
        budget = object(); owner = adapter.SessionDocker(addon,config,budget)
        with patch.object(owner,'tools') as tools, patch.object(adapter,'supervised_session',return_value=(0,b'fixture')) as run:
            self.assertEqual(owner.execute(['container','ls'],cap=17,cleanup=True),(0,b'fixture'))
        self.assertEqual(tools.call_args_list, [unittest.mock.call(True),unittest.mock.call(True)])
        args,kwargs = run.call_args
        self.assertIs(args[0],addon)
        self.assertEqual(args[1],['/inert/docker','--host','unix:///inert/model.sock','--config','/private/model-config','container','ls'])
        self.assertEqual(args[2],config['actor_env'])
        self.assertIs(args[3],budget)
        self.assertEqual(args[4],17)
        self.assertEqual(kwargs,{'cleanup':True,'new_group':True,'quota_root':None})

    def test_container_inspection_and_absence_remain_held_primitives(self):
        owner = adapter.SessionDocker(addon,{'actor_env':{}},object())
        with patch.object(addon.Docker,'inspect',return_value={'fixture':True}) as inspect:
            self.assertEqual(owner.inspect('a'*64,True),{'fixture':True})
            inspect.assert_called_once_with(owner,'a'*64,True)
        with patch.object(addon.Docker,'absence',return_value=None) as absence:
            self.assertIsNone(owner.absence('model-clean-name','b'*64,True))
            absence.assert_called_once_with(owner,'model-clean-name','b'*64,True)

    def test_held_byte_pair_refuses_content_only_or_ambiguous_success(self):
        pair = {'status':'contents-reproduced','errors':[], 'packages':{
            'cachy-asahi-zsh-autosuggestions-0.7.1-1-any.pkg.tar.zst':{
                'installed_contents_equal':True,'pkginfo_equal':True,'bytes_equal':True,'buildinfo_equal':False}}}
        addon.validate_pair(pair)
        for field,value in (('bytes_equal',False),('bytes_equal',1),('pkginfo_equal',False),('buildinfo_equal',1)):
            candidate = copy.deepcopy(pair); next(iter(candidate['packages'].values()))[field] = value
            with self.subTest(field=field,value=value), self.assertRaises(ValueError):
                addon.validate_pair(candidate)

    def test_body_firstcause_survives_both_final_tool_and_daemon_faults(self):
        config={'actor_env':{},'docker':'/inert/docker','endpoint':'unix:///inert/socket',
                'docker_config':'/inert/config','quota_root':'/inert/output','daemon_binding':{}}
        owner=adapter.SessionDocker(addon,config,object())
        first=KeyboardInterrupt('first model actor control')
        tool_calls,binding_calls=[],[]
        def tools(cleanup):
            tool_calls.append(cleanup)
            if len(tool_calls)==2:raise OSError('later tools fault')
        def binding(cleanup):
            binding_calls.append(cleanup)
            if len(binding_calls)==2:raise OSError('later daemon fault')
        with patch.object(owner,'tools',side_effect=tools), patch.object(owner,'binding',side_effect=binding), patch.object(adapter,'supervised_session',side_effect=first):
            with self.assertRaises(KeyboardInterrupt) as caught:owner.execute(['fixture'])
        self.assertIs(caught.exception,first)
        self.assertEqual(tool_calls,[False,False])
        self.assertEqual(binding_calls,[False,False])


class SupervisionModelTests(unittest.TestCase):
    """No child, signals or process groups exist: every operation is an inert model."""
    def setUp(self):
        self.tick, self.signals, self.waits = [0.0], [], []
        self.state, self.group = 0, False
        self.blocks = [b'model bytes', b'']
        self.stdout = SimpleNamespace(closed=False)
        self.stdout.close = lambda: setattr(self.stdout, 'closed', True)
        self.process = SimpleNamespace(pid=987654321, stdout=self.stdout,
                                       poll=lambda: self.state, wait=self.wait,
                                       send_signal=lambda number: self.signals.append(number))
        self.selector = SimpleNamespace(active=True)
        self.selector.register = lambda *_: None
        self.selector.unregister = lambda *_: setattr(self.selector, 'active', False)
        self.selector.get_map = lambda: {9:self.stdout} if self.selector.active else {}
        self.selector.select = lambda timeout: [(SimpleNamespace(fd=9,fileobj=self.stdout),1)]
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(adapter.time, 'monotonic', side_effect=lambda: self.tick[0]))
        self.budget = adapter.Budget(1200.0)
        self.popen = self.stack.enter_context(patch.object(adapter.subprocess, 'Popen', return_value=self.process))
        self.stack.enter_context(patch.object(adapter.selectors, 'DefaultSelector',
                                            side_effect=lambda: nullcontext(self.selector)))
        self.stack.enter_context(patch.object(adapter.os, 'read', side_effect=lambda *_: self.blocks.pop(0)))
        self.stack.enter_context(patch.object(adapter.os, 'killpg', side_effect=self.killpg))
        self.stack.enter_context(patch.object(adapter.signal, 'pthread_sigmask', return_value=set()))
        self.stack.enter_context(patch.object(addon, 'defer_cancel', side_effect=lambda: nullcontext([])))
        prior = list(addon._PROCESS_DISPOSAL_UNCERTAIN)
        self.addCleanup(lambda: addon._PROCESS_DISPOSAL_UNCERTAIN.__setitem__(slice(None),prior))

    def wait(self, timeout):
        self.waits.append(timeout)
        if self.state is None:
            raise subprocess.TimeoutExpired('inert-model',timeout)
        return self.state

    def killpg(self, pid, number):
        self.assertEqual(pid,self.process.pid)
        self.signals.append(number)
        if number == 0 and not self.group:
            raise ProcessLookupError()
        if number == signal.SIGKILL:
            self.state,self.group = -9,False

    def run_model(self, **kwargs):
        return adapter.supervised_session(addon, ['/inert-never-executed'], {'PATH':'/inert'},
                                          self.budget,1,**kwargs)

    def test_success_retains_bytes_closes_pipe_and_proves_group_absence(self):
        self.assertEqual(self.run_model(),(0,b'model bytes'))
        self.assertTrue(self.stdout.closed)
        self.assertEqual(self.signals,[0])
        self.assertEqual(self.waits,[1])

    def test_postmask_expiry_refuses_before_popen_and_no_log(self):
        def mask(how,numbers):
            if how == signal.SIG_BLOCK:
                self.tick[0] = 1.0
            return set()
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory)/'absent.log'
            with patch.object(adapter.signal,'pthread_sigmask',side_effect=mask), self.assertRaises(ValueError):
                self.run_model(log=log)
            self.assertFalse(log.exists())
        self.popen.assert_not_called()

    def test_argv_materialization_latency_refuses_before_popen(self):
        test = self
        class SlowArgv:
            def __iter__(self):
                test.tick[0] += .6
                return iter(['/inert-never-executed'])
        with self.assertRaises(ValueError):
            adapter.supervised_session(addon,SlowArgv(),{},self.budget,1)
        self.popen.assert_not_called()

    def test_read_firstcause_survives_term_fault_and_owned_kill_reap(self):
        first = OSError('first read failure')
        self.state,self.group = None,True
        original = self.killpg
        def term_fault(pid,number):
            if number == signal.SIGTERM:
                self.signals.append(number)
                raise OSError('later TERM failure')
            return original(pid,number)
        with patch.object(adapter.os,'read',side_effect=first), patch.object(adapter.os,'killpg',side_effect=term_fault):
            with self.assertRaises(OSError) as caught:
                self.run_model()
        self.assertIs(caught.exception,first)
        self.assertTrue(self.stdout.closed)
        self.assertIn(signal.SIGKILL,self.signals)
        self.assertEqual(first.process_cleanup_status,'PASS')
        self.assertTrue(all(0 <= value <= 2 for value in self.waits))

    def test_control_on_mask_restore_retains_child_for_disposal(self):
        first = KeyboardInterrupt('first modeled control')
        self.state,self.group = None,True
        restores = [0]
        def mask(how,numbers):
            if how == signal.SIG_SETMASK:
                restores[0] += 1
                if restores[0] == 1:
                    raise first
            return set()
        with patch.object(adapter.signal,'pthread_sigmask',side_effect=mask), self.assertRaises(KeyboardInterrupt) as caught:
            self.run_model()
        self.assertIs(caught.exception,first)
        self.assertTrue(self.stdout.closed)
        self.assertIn(signal.SIGKILL,self.signals)

    def test_expiry_during_completed_wait_cannot_return_success(self):
        original = self.wait
        def wait(timeout):
            result = original(timeout); self.tick[0] = 1080.0
            return result
        self.process.wait = wait
        with self.assertRaises(ValueError):
            self.run_model()
        self.assertTrue(self.stdout.closed)
        self.assertEqual(self.budget.end,1200.0)


class FinalizationModelTests(unittest.TestCase):
    """Explicit context substitute: never an actual suspended Session acceptance."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.output = Path(self.tmp.name)/'output'; self.output.mkdir(mode=0o700)
        self.tick = [0.0]
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(adapter.time,'monotonic',side_effect=lambda:self.tick[0]))
        self.stack.enter_context(patch.object(addon,'defer_cancel',side_effect=lambda:nullcontext([])))
        self.context = {'root':Path('/inert-model-view'),'receipt':b'private model receipt',
                        'sha256':'a'*64,'original':{'fixture':object()},'aliases':{'fixture':object()}}
        self.context_calls = []
        self.stack.enter_context(patch.object(adapter,'borrow_context',side_effect=self.context_check))
        self.session,self.controller = object(),object()
        self.budget = adapter.Budget(1200.0)
        self.result = {'stage':'zsh-addon','status':'PASS','attempts':[], 'public':[],
                       'hardware_status':'NOT RUN','installation':'NOT RUN','provisional':True}
        saved = {name:dict(getattr(addon,name)) for name in
                 ('_RECEIPT_FILES','_RECEIPT_FDS','_RECEIPT_UNCERTAIN')}
        self.assertTrue(all(not value for value in saved.values()))
        def restore():
            for name,value in saved.items():
                getattr(addon,name).clear();getattr(addon,name).update(value)
        self.addCleanup(restore)

    def context_check(self,*args):
        self.context_calls.append((args[-1],len(addon._RECEIPT_FILES)))
        return self.context

    def finalize(self,configs=None):
        return adapter.finalize_stage_session(addon,self.session,self.controller,Path('/inert-full-root'),
            self.context,self.output,self.result,configs or [],self.budget)

    def test_three_private_receipts_retained_and_registry_restored_before_postcontext(self):
        value = self.finalize()
        self.assertEqual(value['status'],'PASS')
        self.assertEqual(value['cleanup']['status'],'PASS')
        self.assertEqual(self.context_calls,[(1200.0,0),(1200.0,0)])
        self.assertEqual(addon._RECEIPT_FILES,{})
        for relative in ('adapter-status/result.json','public/receipt.json','result.json'):
            path = self.output/relative
            self.assertEqual(json.loads(path.read_bytes())['status'],'PASS')
            self.assertEqual(path.stat().st_mode & 0o777,0o600)

    def test_cleanup_fault_attempts_later_owned_lane_and_preserves_prior_business_code(self):
        self.result.update(status='FAIL',first_failure='first-native-build-failure')
        calls=[]
        def cleanup(helper,config,deadline):
            calls.append(config['fixture'])
            if config['fixture']==1:
                raise OSError('later cleanup fault')
            return {'status':'PASS'}
        with patch.object(adapter,'cleanup_attempt_session',side_effect=cleanup):
            value=self.finalize([{'fixture':1},{'fixture':2}])
        self.assertEqual(calls,[1,2])
        self.assertEqual(value['first_failure'],'first-native-build-failure')
        self.assertEqual(value['status'],'FAIL')
        self.assertEqual(value['cleanup']['status'],'UNKNOWN')

    def test_late_postcontext_drift_cannot_return_pass(self):
        calls=[0]
        def context(*args):
            calls[0]+=1
            if calls[0]==2:
                raise ValueError('late context drift')
            return self.context
        with patch.object(adapter,'borrow_context',side_effect=context):
            value=self.finalize()
        self.assertEqual(value['status'],'FAIL')
        self.assertEqual(value['public'],[])
        self.assertFalse(any((self.output/name).exists() for name in
                             ('adapter-status/result.json','public/receipt.json','result.json')))

    def test_control_firstcause_survives_later_cleanup_fault_and_remaining_lanes(self):
        first=KeyboardInterrupt('first modeled cleanup control')
        calls=[]
        def cleanup(helper,config,deadline):
            calls.append(config['fixture'])
            if config['fixture']==1:raise first
            raise OSError('later modeled fault')
        with patch.object(adapter,'cleanup_attempt_session',side_effect=cleanup), self.assertRaises(KeyboardInterrupt) as caught:
            self.finalize([{'fixture':1},{'fixture':2}])
        self.assertIs(caught.exception,first)
        self.assertEqual(calls,[1,2])
        self.assertEqual(self.result['status'],'FAIL')

    def test_foreign_receipt_registry_node_refuses_retirement(self):
        foreign = Path(self.tmp.name)/'outside.json';foreign.write_bytes(b'foreign retained')
        addon._RECEIPT_FILES[str(foreign)] = {'identity':addon.receipt_identity(foreign.lstat()),
                                           'sha256':hashlib.sha256(foreign.read_bytes()).hexdigest()}
        with self.assertRaises(ValueError):
            adapter.restore_receipts(addon,self.output,self.budget)
        self.assertIn(str(foreign),addon._RECEIPT_FILES)
        self.assertEqual(foreign.read_bytes(),b'foreign retained')

    def test_uncertain_descriptor_state_refuses_registry_restoration(self):
        addon._RECEIPT_UNCERTAIN['model-only'] = True
        with self.assertRaises(ValueError):
            adapter.restore_receipts(addon,self.output,self.budget)

    def test_local_io_uncertainty_cannot_be_cleanup_or_stage_pass(self):
        self.budget.io_uncertain.append('model-only persistent descriptor-close uncertainty')
        value=self.finalize()
        self.assertEqual(value['status'],'FAIL')
        self.assertEqual(value['cleanup']['status'],'UNKNOWN')


class OrchestrationModelTests(unittest.TestCase):
    """Borrow/prerequisite/actor/attempt checks are explicit substitutes, not authority."""
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.home=Path(self.tmp.name)
        self.root=self.home/'full-root';self.root.mkdir()
        self.view=self.home/'view';self.view.mkdir()
        self.native=self.home/'native';self.native.mkdir()
        self.output=self.home/'zsh-output'
        self.controller=SimpleNamespace(native_out=str(self.native),commit='c'*40)
        self.context={'root':self.view,'receipt':b'modeled original receipt','sha256':'a'*64,
                      'original':{'fixture':object()},'aliases':{'fixture':object()}}
        package={'source_root':'packages/shells/model-zsh','build_helper_reviewed_inputs':{'PKGBUILD':'f'*64}}
        contract={'schema_version':1,'acceptance':'strict-native-byte-pair',
                  'docker_adaptation':'run-to-create-inspect-start-retain','package':package}
        raw={adapter.CONTRACT:json.dumps(contract).encode(),adapter.ADDON:b'# never executed addon model\n',
             adapter.SELF:b'# never executed adapter model\n',
             'scripts/build/build.py':b'# never executed build model\n',
             'scripts/build/compare.py':b'# never executed compare model\n',
             'scripts/checks/package_checks.py':b'# never executed checker model\n'}
        self.session=SimpleNamespace(job_deadline=1200.0,cancelled=False,
            source_graph={'zsh':{'zsh_addon':addon}},
            sources=SimpleNamespace(root=self.root,raw=raw,grant_pin='b'*64,guard=lambda *_:None))
        self.pair={'status':'contents-reproduced','errors':[], 'packages':{
            'cachy-asahi-zsh-autosuggestions-0.7.1-1-any.pkg.tar.zst':{
             'installed_contents_equal':True,'pkginfo_equal':True,'bytes_equal':True,'buildinfo_equal':True}}}
        self.commands=[];self.archive_calls=[];self.borrow_calls=[]
        self.stack=ExitStack();self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(adapter.time,'monotonic',return_value=0.0))
        self.stack.enter_context(patch.object(adapter.signal,'pthread_sigmask',return_value=set()))
        self.stack.enter_context(patch.object(addon,'defer_cancel',side_effect=lambda:nullcontext([])))
        self.stack.enter_context(patch.object(adapter,'borrow_context',side_effect=self.borrow))
        self.stack.enter_context(patch.object(adapter,'validate_contract_session',return_value=None))
        self.stack.enter_context(patch.object(adapter,'prerequisite_session',return_value={
            'image_id':'sha256:'+'d'*64,'packages_sha256':'e'*64,'packages_lock':str(self.native/'packages.lock'),'epoch':1}))
        config={'image':'sha256:'+'d'*64,'python':sys.executable,'epoch':1,'actor_env':{'PATH':'/usr/bin:/bin','HOME':str(self.home)}}
        self.stack.enter_context(patch.object(adapter,'actor_config',return_value=config))
        class InertDocker:
            def __init__(inner,*args):pass
            def call(inner,argv,*args):
                if argv[0]=='info':
                    return json.dumps({'ID':'model-daemon','Architecture':'aarch64','OSType':'linux',
                        'ServerVersion':'model','DockerRootDir':'/inert','DefaultRuntime':'runc'}).encode()
                return json.dumps([{'Id':config['image'],'Architecture':'arm64','Os':'linux','Config':{}}]).encode()
            def binding(inner,*args):pass
            def absence(inner,*args):pass
        self.stack.enter_context(patch.object(adapter,'SessionDocker',InertDocker))
        self.supervisor=self.stack.enter_context(patch.object(adapter,'supervised_session',side_effect=self.supervise))
        self.stack.enter_context(patch.object(adapter,'validate_attempt_session',side_effect=self.archive))
        self.stack.enter_context(patch.object(adapter,'cleanup_attempt_session',return_value={'status':'PASS'}))
        saved={name:dict(getattr(addon,name)) for name in ('_RECEIPT_FILES','_RECEIPT_FDS','_RECEIPT_UNCERTAIN')}
        self.assertTrue(all(not value for value in saved.values()))
        def restore():
            for name,value in saved.items():getattr(addon,name).clear();getattr(addon,name).update(value)
        self.addCleanup(restore)

    def borrow(self,*args):
        self.borrow_calls.append(args[-1]);return self.context

    def supervise(self,helper,argv,env,deadline,cap,*args,**kwargs):
        self.commands.append((list(argv),dict(env),deadline,cap))
        if '--output' in argv:
            number=len(self.commands)
            lane=self.output/f'lane-{number}'
            (lane/'owned.json').write_text('{}')
            return 0,b''
        return 0,json.dumps(self.pair).encode()

    def archive(self,helper,session,context,attempt,package,prerequisite,owned,deadline):
        number=len(self.archive_calls)+1;self.archive_calls.append(str(attempt))
        return {'name':'model-archive','sha256':'f'*64,'bytes':1,
                'cid':str(number)*64,'clean_environment_id':f'model-clean-{number}'}

    def run_model(self):
        return adapter.run_zsh(self.controller,self.root,self.output,session=self.session,actor_contract_raw=b'{}')

    def test_two_distinct_clean_attempts_and_strict_comparison_are_provisional(self):
        result=self.run_model()
        self.assertEqual(result['status'],'PASS')
        self.assertTrue(result['provisional'])
        self.assertEqual((result['installation'],result['hardware_status']),('NOT RUN','NOT RUN'))
        self.assertEqual(len(result['attempts']),2)
        self.assertNotEqual(result['attempts'][0]['archive']['cid'],result['attempts'][1]['archive']['cid'])
        self.assertEqual([row[3] for row in self.commands],[360,360,120])
        self.assertTrue(all(row[2] is self.commands[0][2] for row in self.commands))
        self.assertEqual((self.commands[0][2].end,self.commands[0][2].work_end),(1200.0,1080.0))
        for argv,env,_,_ in self.commands[:2]:
            self.assertEqual(argv[argv.index('--mode')+1],'native')
            self.assertEqual(argv[argv.index('--network')+1],'none')
            self.assertEqual(env['PYTHONDONTWRITEBYTECODE'],'1')
        self.assertIn('--require-bytes',self.commands[2][0])
        self.assertEqual(self.borrow_calls,[1080.0,1080.0,1080.0,1080.0,1200.0,1200.0])
        self.assertFalse(addon._RECEIPT_FILES)

    def test_reused_clean_identity_refuses_before_comparison(self):
        def repeated(*args):return {'cid':'1'*64,'clean_environment_id':'reused-model'}
        with patch.object(adapter,'validate_attempt_session',side_effect=repeated):result=self.run_model()
        self.assertEqual(result['status'],'FAIL')
        self.assertEqual(result['first_failure'],'clean-pair-identity-refused')
        self.assertEqual(len(self.commands),2)

    def test_first_build_failure_does_not_start_second_attempt_or_compare(self):
        self.supervisor.side_effect=lambda *args,**kwargs:(7,b'first failed build model')
        result=self.run_model()
        self.assertEqual(result['status'],'FAIL')
        self.assertEqual(result['first_failure'],'native-build-failed')
        self.assertEqual(self.supervisor.call_count,1)
        self.assertEqual(result['attempts'],[])

    def test_original_control_survives_later_finalization_fault(self):
        first=KeyboardInterrupt('first modeled build control')
        self.supervisor.side_effect=first
        with patch.object(adapter,'finalize_stage_session',side_effect=OSError('later modeled finalization fault')), self.assertRaises(KeyboardInterrupt) as caught:
            self.run_model()
        self.assertIs(caught.exception,first)

    def test_boolean_contract_schema_refuses_before_prerequisite_or_build(self):
        contract=json.loads(self.session.sources.raw[adapter.CONTRACT])
        contract['schema_version']=True
        self.session.sources.raw[adapter.CONTRACT]=json.dumps(contract).encode()
        with patch.object(adapter,'prerequisite_session') as prerequisite:
            result=self.run_model()
        self.assertEqual(result['status'],'FAIL')
        self.assertEqual(result['first_failure'],'contract-policy-refused')
        prerequisite.assert_not_called()
        self.supervisor.assert_not_called()


class OriginalInputFixtureTests(unittest.TestCase):
    """Private metadata fixtures test binding/count only; no original producer ran."""
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.out=Path(self.tmp.name)
        self.controller=SimpleNamespace(native_out=str(self.out),image='sha256:'+'a'*64)
        self.inputs={'rootfs_packages':[{'name':[f'p{index:03d}'],'version':['1']} for index in range(341)],
                     'packages':[],'source_date_epoch':1}
        self.raw=adapter.encoded(self.inputs)
        self.session=SimpleNamespace(sources=SimpleNamespace(raw={'scripts/ci/inputs.lock.json':self.raw}))
        self.stack=ExitStack();self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(adapter.time,'monotonic',return_value=0.0))
        self.stack.enter_context(patch.object(adapter.signal,'pthread_sigmask',return_value=set()))
        self.budget=adapter.Budget(1200.0)

    def metadata(self):
        lock=''.join(f'p{index:03d} 1\n' for index in range(341)).encode()
        self.out.joinpath('inputs.lock.json').write_bytes(self.raw)
        self.out.joinpath('packages.lock').write_bytes(lock)
        self.out.joinpath('image-id').write_text(self.controller.image+'\n')
        self.out.joinpath('result.json').write_bytes(adapter.encoded({'native_build':'PASS','reviewed_inputs_sha256':adapter.sha(self.raw)}))
        self.out.joinpath('bootstrap.json').write_bytes(adapter.encoded({'status':'image-provisioned',
            'image_id':self.controller.image,'packages_lock_sha256':adapter.sha(lock),'inputs_sha256':adapter.sha(self.raw)}))

    def test_captured_original_input_drift_refuses_before_image_or_package_files(self):
        self.out.joinpath('result.json').write_text('{}')
        self.out.joinpath('bootstrap.json').write_text('{}')
        self.out.joinpath('inputs.lock.json').write_text('{"foreign":true}')
        with self.assertRaisesRegex(ValueError,'original-inputs-drift'):
            adapter.prerequisite_session(addon,self.session,self.controller,self.budget)
        self.assertFalse(self.out.joinpath('image-id').exists())
        self.assertFalse(self.out.joinpath('packages.lock').exists())

    def test_exact_captured_inputs_and_341_package_fixture_bind(self):
        self.metadata()
        value=adapter.prerequisite_session(addon,self.session,self.controller,self.budget)
        self.assertEqual(value['package_count'],341)
        self.assertEqual(value['image_id'],self.controller.image)
        self.assertEqual(value['packages_sha256'],adapter.sha((self.out/'packages.lock').read_bytes()))

    def test_fewer_package_rows_and_changed_bootstrap_input_hash_refuse(self):
        self.metadata()
        self.out.joinpath('packages.lock').write_text('p000 1\n')
        with self.assertRaises(ValueError):adapter.prerequisite_session(addon,self.session,self.controller,self.budget)
        self.metadata()
        bootstrap=json.loads((self.out/'bootstrap.json').read_bytes());bootstrap['inputs_sha256']='b'*64
        self.out.joinpath('bootstrap.json').write_bytes(adapter.encoded(bootstrap))
        with self.assertRaises(ValueError):adapter.prerequisite_session(addon,self.session,self.controller,self.budget)


class TransitiveReadFixtureTests(unittest.TestCase):
    """Real private reads and closed report models; no native archive/build authority."""
    setUp=PrivateFileTests.setUp

    def pending_control(self,callback):
        first=KeyboardInterrupt('pending private-file fixture control')
        original_open,original_close=os.open,os.close
        descriptors=[];restores=[0]
        primitive_ids={name:id(getattr(addon,name)) for name in ('read','tree','validate_contract','validate_attempt')}
        def opened(*args,**kwargs):
            fd=original_open(*args,**kwargs);descriptors.append(fd);return fd
        def mask(how,numbers):
            if how==signal.SIG_SETMASK:
                restores[0]+=1
                if restores[0]==1:raise first
            return set()
        try:
            with patch.object(adapter.os,'open',side_effect=opened), patch.object(adapter.signal,'pthread_sigmask',side_effect=mask):
                with self.assertRaises(KeyboardInterrupt) as caught:callback()
            self.assertIs(caught.exception,first)
            self.assertEqual(len(descriptors),1)
            with self.assertRaises(OSError):os.fstat(descriptors[0])
            self.assertFalse(self.budget.io_uncertain)
            self.assertEqual(primitive_ids,{name:id(getattr(addon,name)) for name in primitive_ids})
        finally:
            for fd in descriptors:
                try:original_close(fd)
                except OSError:pass

    def package_fixture(self):
        source_root='packages/shells/'+addon.PACKAGE
        directory=self.root/source_root;directory.mkdir(parents=True)
        names=('.SRCINFO','PKGBUILD','LICENSE.project','LICENSE.upstream','NOTICE','README.md',
               'check-module.py','integration-proposal.json','opt-in.zsh','source-provenance.json',
               'usage.md','zsh-autosuggestions.zsh')
        rows={}
        for name in names:
            raw=b'x'*(54910-11 if name=='zsh-autosuggestions.zsh' else 1)
            (directory/name).write_bytes(raw)
            rows[name]={'sha256':adapter.sha(raw),'bytes':len(raw),'mode':0o644}
        payload_sources={'usr/share/cachy-asahi/zsh-autosuggestions/zsh-autosuggestions.zsh':'zsh-autosuggestions.zsh',
            'usr/share/cachy-asahi/zsh-autosuggestions/opt-in.zsh':'opt-in.zsh',
            'usr/share/cachy-asahi/zsh-autosuggestions/README.md':'usage.md',
            'usr/share/licenses/'+addon.PACKAGE+'/LICENSE.upstream':'LICENSE.upstream',
            'usr/share/licenses/'+addon.PACKAGE+'/LICENSE.project':'LICENSE.project',
            'usr/share/licenses/'+addon.PACKAGE+'/NOTICE':'NOTICE'}
        return {'name':addon.PACKAGE,'version':'0.7.1-1','arch':'any','license':['MIT'],
            'depends':['zsh>=4.3.11'],'upstream_revision':'85919cd1ffa7d2d5412f6d3fe437ebdbeeec4fc5',
            'source_root':source_root,'source_files':rows,'optdepends':[],
            'build_helper_reviewed_inputs':{name:row['sha256'] for name,row in rows.items()},
            'expected_payloads':{name:{'source':source,**rows[source],'type':'regular','uid':0,'gid':0}
                                  for name,source in payload_sources.items()}}

    def test_tools_private_read_control_closes_descriptor_without_addon_global_rebinding(self):
        executable=self.root/'docker-fixture';executable.write_bytes(b'inert docker fixture bytes')
        owner=adapter.SessionDocker(addon,{'actor_env':{},'docker':str(executable)},self.budget)
        self.pending_control(lambda:owner.tools())

    def test_tree_private_read_control_closes_descriptor_without_addon_global_rebinding(self):
        directory=self.root/'tree';directory.mkdir();(directory/'inert').write_bytes(b'inert')
        self.pending_control(lambda:adapter.tree_session(addon,directory,deadline=self.budget))

    def test_attempt_provenance_control_closes_descriptor_without_addon_global_rebinding(self):
        attempt=self.root/'attempt';attempt.mkdir();(attempt/'provenance.json').write_text('{}')
        self.pending_control(lambda:adapter.validate_attempt_session(addon,self.session,self.context,
            attempt,{}, {},{},self.budget))

    def test_contract_private_read_control_closes_descriptor_without_addon_global_rebinding(self):
        package=self.package_fixture()
        self.pending_control(lambda:adapter.validate_contract_session(addon,self.root,package,self.budget))

    def test_contract_selected_twelve_rows_six_payloads_and_drift_are_checked(self):
        package=self.package_fixture()
        adapter.validate_contract_session(addon,self.root,package,self.budget)
        package['expected_payloads']['usr/share/cachy-asahi/zsh-autosuggestions/opt-in.zsh']['mode']=0o755
        with self.assertRaisesRegex(ValueError,'payload-map-invalid'):
            adapter.validate_contract_session(addon,self.root,package,self.budget)

    def test_tree_halfway_expiry_stops_after_first_chunk_without_open_fd(self):
        directory=self.root/'tree';directory.mkdir();(directory/'inert').write_bytes(b'a'*140000)
        original=os.read;chunks=[]
        def read(fd,size):
            raw=original(fd,size);chunks.append(len(raw));self.tick[0]=1080.0;return raw
        with patch.object(adapter.os,'read',side_effect=read), self.assertRaises(ValueError):
            adapter.tree_session(addon,directory,deadline=self.budget)
        self.assertEqual(chunks,[65536])
        self.assertFalse(self.budget.io_uncertain)

    def attempt_fixture(self):
        package=self.package_fixture()
        attempt=self.root/'attempt';attempt.mkdir();(attempt/'inputs').mkdir();(attempt/'artifacts').mkdir()
        for name in package['source_files']:
            (attempt/'inputs'/name).write_bytes((self.root/package['source_root']/name).read_bytes())
        archive_name=addon.PACKAGE+'-0.7.1-1-any.pkg.tar.zst'
        archive=b'inert static report fixture; not a native package archive'
        (attempt/'artifacts'/archive_name).write_bytes(archive)
        checksum=adapter.sha(archive)
        members={name:{'type':'0','mode':0o644,'uid':0,'gid':0,
                       'size':row['bytes'],'sha256':row['sha256']}
                 for name,row in package['expected_payloads'].items()}
        members.update({name:{'type':'0','mode':0o644,'uid':0,'gid':0,'size':0,'sha256':adapter.sha(b'')}
                        for name in addon.META})
        inspected={'artifact':archive_name,'sha256':checksum,'status':'artifact-static-pass',
            'errors':[],'elf':False,'members':members,'metadata':{
            '.PKGINFO':{'pkgname':[addon.PACKAGE],'pkgver':['0.7.1-1'],'arch':['any'],'license':['MIT'],
                        'depend':['zsh>=4.3.11'],'optdepend':[]},
            '.BUILDINFO':{'pkgbuild_sha256sum':[package['build_helper_reviewed_inputs']['PKGBUILD']]}}}
        validation={'errors':[],'artifacts':[inspected]}
        (attempt/'validation.json').write_bytes(adapter.encoded(validation))
        package_lock=b'inert-fixture-package 1\n'
        for name in ('expected-packages.lock','artifacts/packages.lock'):(attempt/name).write_bytes(package_lock)
        for name in ('build.log','artifacts/generated.SRCINFO','artifacts/environment.txt','artifacts/config.sha256',
                     'artifacts/makepkg.conf','artifacts/pacman.conf'):(attempt/name).write_bytes(b'inert fixture\n')
        required=('build.log','validation.json','expected-packages.lock','artifacts/packages.lock',
                  'artifacts/generated.SRCINFO','artifacts/environment.txt','artifacts/config.sha256',
                  'artifacts/makepkg.conf','artifacts/pacman.conf')
        files={name:adapter.sha((attempt/name).read_bytes()) for name in required}
        prerequisite={'image_id':'sha256:'+'a'*64,'epoch':1,'packages_sha256':adapter.sha(package_lock)}
        owned={'name':'model-clean-name','cid':'b'*64,'status':'EXITED','observed':True,'exit_code':0}
        record={'status':'built-package-static-pass','exit_code':0,'mode':'native','network':'none',
            'image':prerequisite['image_id'],'image_id':prerequisite['image_id'],'source_date_epoch':1,
            'recipe_inputs':package['build_helper_reviewed_inputs'],'expected_packages_sha256':prerequisite['packages_sha256'],
            'entry_script_sha256':self.rows['scripts/build/container-entry.sh']['sha256'],
            'clean_environment_id':owned['name'],'files':files,'artifacts':{archive_name:checksum}}
        (attempt/'provenance.json').write_bytes(adapter.encoded(record))
        return attempt,package,prerequisite,owned,record

    def test_full_static_report_model_retains_metadata_payload_and_archive_name_predicates(self):
        attempt,package,prerequisite,owned,record=self.attempt_fixture()
        value=adapter.validate_attempt_session(addon,self.session,self.context,attempt,package,prerequisite,owned,self.budget)
        self.assertEqual(value['name'],addon.PACKAGE+'-0.7.1-1-any.pkg.tar.zst')
        self.assertEqual(value['cid'],owned['cid'])
        self.assertEqual(value['sha256'],next(iter(record['artifacts'].values())))
        self.assertEqual(self.guards,[(1080.0,False),(1080.0,False)])

    def test_attempt_same_archive_bytes_with_wrong_report_metadata_or_payload_refuses(self):
        attempt,package,prerequisite,owned,record=self.attempt_fixture()
        original=(attempt/'validation.json').read_bytes()
        for field in ('metadata','payload'):
            validation=json.loads(original);row=validation['artifacts'][0]
            if field=='metadata':row['metadata']['.PKGINFO']['license']=['GPL']
            else:row['members']['usr/share/cachy-asahi/zsh-autosuggestions/opt-in.zsh']['mode']=0o755
            (attempt/'validation.json').write_bytes(adapter.encoded(validation))
            record['files']['validation.json']=adapter.sha((attempt/'validation.json').read_bytes())
            (attempt/'provenance.json').write_bytes(adapter.encoded(record))
            with self.subTest(field=field),self.assertRaises(ValueError):
                adapter.validate_attempt_session(addon,self.session,self.context,attempt,package,prerequisite,owned,self.budget)


class GateProfileModelTests(unittest.TestCase):
    """Actual held command grammar; Docker and full inspect report are inert substitutes."""
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        root=Path(self.tmp.name);attempt=root/'attempt'
        self.config={'actor_env':{},'image':'sha256:'+'a'*64,'uid':1000,'gid':1001,'epoch':1,
            'attempt':str(attempt),'entry':str(root/'container-entry.sh'),'cidfile':str(root/'cid'),
            'owned':str(root/'owned.json'),'endpoint':'unix:///inert/socket','daemon_id':'model-daemon',
            'stage_end':1200.0,'work_end':1080.0,'gate_end':270.0}
        self.name='cachy-asahi-'+'b'*16;self.cid='c'*64;self.reply=self.cid
        self.argv=['run','--rm','--name',self.name,'--pull=never','--platform','linux/arm64',
            '--user','1000:1001','--cap-drop=ALL','--security-opt=no-new-privileges','--read-only',
            '--pids-limit','512','--memory','4g','--cpus','4','--network','none',
            '--tmpfs','/tmp:rw,nosuid,nodev,exec,size=4g','--env','CACHY_ASAHI_CONTAINER=1',
            '--env','SOURCE_DATE_EPOCH=1','--mount',f'type=bind,src={attempt}/inputs,dst=/inputs,readonly',
            '--mount',f'type=bind,src={attempt}/artifacts,dst=/out','--mount',
            f'type=bind,src={self.config["entry"]},dst=/builder-entry.sh,readonly','--mount',
            f'type=bind,src={attempt}/expected-packages.lock,dst=/expected-packages.lock,readonly',
            '--entrypoint','/bin/bash',self.config['image'],'/builder-entry.sh']
        self.calls=[];self.inspect_status='created'
        self.stack=ExitStack();self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(adapter.time,'monotonic',return_value=0.0))
        self.stack.enter_context(patch.object(adapter.signal,'pthread_sigmask',return_value=set()))
        self.stack.enter_context(patch.object(addon,'defer_cancel',side_effect=lambda:nullcontext([])))
        self.stack.enter_context(patch.object(addon,'validate_container',return_value=None))
        test=self
        class DockerModel:
            def __init__(inner,*args):pass
            def binding(inner,*args):test.calls.append('binding')
            def absence(inner,*args):test.calls.append('absence')
            def call(inner,argv,*args):
                test.calls.append(argv)
                Path(test.config['cidfile']).write_text(test.cid+'\n')
                return (test.reply+'\n').encode()
            def inspect(inner,cid,*args):
                test.calls.append('inspect')
                state={'Status':test.inspect_status,'Running':False,'Paused':False,'Restarting':False,
                       'Dead':False,'OOMKilled':False,'ExitCode':7,'Error':''}
                test.inspect_status='exited'
                return {'State':state}
            def execute(inner,argv,*args):
                test.calls.append(argv)
                receipt=json.loads(Path(test.config['owned']).read_bytes())
                test.assertEqual(receipt['status'],'OBSERVED_BEFORE_START')
                test.assertIs(receipt['observed'],True)
                return 0,b'inert attached fixture bytes'
        self.stack.enter_context(patch.object(adapter,'SessionDocker',DockerModel))
        prior=dict(addon._RECEIPT_FILES)
        self.addCleanup(lambda:(addon._RECEIPT_FILES.clear(),addon._RECEIPT_FILES.update(prior)))

    def test_exact_nonroot_readonly_profile_creates_inspects_then_starts_owned_cid(self):
        code,data=adapter.gate_session(addon,self.config,self.argv)
        self.assertEqual((code,data),(7,b'inert attached fixture bytes'))
        create=next(row for row in self.calls if isinstance(row,list) and row[0]=='create')
        self.assertEqual(create,['create','--cidfile',self.config['cidfile'],*self.argv[2:]])
        self.assertEqual([row for row in self.calls if isinstance(row,list) and row[0]=='start'],
                         [['start','--attach',self.cid]])
        record=json.loads(Path(self.config['owned']).read_bytes())
        self.assertEqual((record['status'],record['exit_code']),('EXITED',7))

    def test_privilege_network_root_and_extra_mount_refuse_before_docker_actor_model(self):
        changed=[]
        for option,value in (('--network','host'),('--user','0:0'),('--memory','8g')):
            argv=list(self.argv);argv[argv.index(option)+1]=value;changed.append(argv)
        changed.append([item for item in self.argv if item!='--read-only'])
        changed.append([*self.argv,'--privileged'])
        changed.append([*self.argv,'--mount','type=bind,src=/,dst=/host'])
        for argv in changed:
            with self.subTest(argv=argv),self.assertRaises(ValueError):adapter.gate_session(addon,self.config,argv)
        self.assertEqual(self.calls,[])
        self.assertFalse(Path(self.config['owned']).exists())

    def test_wrong_create_reply_and_prestarted_inspection_never_start(self):
        self.reply='d'*64
        with self.assertRaisesRegex(ValueError,'create-cid-unproved'):adapter.gate_session(addon,self.config,self.argv)
        self.assertFalse(any(isinstance(row,list) and row[0]=='start' for row in self.calls))
        for key in ('owned','cidfile'):Path(self.config[key]).unlink()
        addon._RECEIPT_FILES.clear();self.calls.clear();self.reply=self.cid;self.inspect_status='running'
        with self.assertRaisesRegex(ValueError,'container-started-before-inspection'):adapter.gate_session(addon,self.config,self.argv)
        self.assertFalse(any(isinstance(row,list) and row[0]=='start' for row in self.calls))


if __name__ == '__main__':
    unittest.main()

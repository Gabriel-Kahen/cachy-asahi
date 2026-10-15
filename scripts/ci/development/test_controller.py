#!/usr/bin/env python3
import json
from pathlib import Path
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import controller
from common import save


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.output = self.root / 'output'; self.output.mkdir()
        self.dev = controller.Development(self.root, self.output, self.root / 'cache', {})
        self.initial = SimpleNamespace(cancelled=False, installed='sha256:' + 'a' * 64)
        controller.CANCELLED = False
        self.events = []
        self.base = ModuleType('base_stages'); self.virtual = ModuleType('virtual_stage')
        self.base.run_ksm = self.stage('ksm')
        self.base.run_arm = self.stage('arm-c01-base')
        self.virtual.run_virtual = self.stage('virtual', 'CAPTURED_REQUIRES_VISUAL_REVIEW')
        self.modules = patch.dict(sys.modules, {'base_stages': self.base, 'virtual_stage': self.virtual})
        self.modules.start(); self.addCleanup(self.modules.stop)
        self.client = patch.object(controller, 'run_client', self.stage('client'))
        self.client.start(); self.addCleanup(self.client.stop)

    def stage(self, name, status='PASS'):
        def action(initial, root, output, *args):
            self.assertIsNotNone(initial.installed)
            self.events.append(name)
            output.mkdir()
            directory = 'owner-public' if name == 'client' else 'adapter-status' if name == 'virtual' else 'public'
            public = output / directory; public.mkdir()
            save(public / 'result.json', {'status':status})
            return {'status':status,'prerequisite':{'status':'PASS'},'public':[str(public)]}
        return action

    def native(self, initial_pass=True, cleanup_pass=True):
        def main(argv, integration_consumers):
            integration_consumers(self.initial)
            self.events.append('cleanup')
            self.initial.installed = None
            (self.output / 'integration').mkdir()
            save(self.output / 'integration/result.json', {'status':'PASS' if initial_pass and cleanup_pass else 'FAIL',
                                                         'owned_image_cleanup':{'status':'PASS' if cleanup_pass else 'FAIL'}})
            return 0 if initial_pass and cleanup_pass else 1
        return SimpleNamespace(main=main)

    def bundle(self, root):
        return (root / 'result.json').read_bytes()

    def publish(self, bundle=None):
        return controller.publish(self.dev, bundle or self.bundle, emit=lambda *args,**kwargs:None)

    def test_consumers_run_before_cleanup_and_review_is_preserved(self):
        self.dev.run(self.native(), [])
        self.assertEqual(self.events, ['ksm','arm-c01-base','client','virtual','cleanup'])
        self.assertIsNone(self.initial.installed)
        self.assertTrue(self.publish())
        self.assertEqual(self.dev.report['status'], 'CAPTURED_REQUIRES_VISUAL_REVIEW')
        self.assertEqual(self.dev.report['hardware_validation'], 'NOT RUN')

    def test_followup_success_cannot_erase_initial_failure(self):
        self.dev.run(self.native(initial_pass=False), [])
        self.assertFalse(self.publish())
        self.assertEqual(self.dev.report['initial_integration'], 'FAIL')
        self.assertEqual(self.dev.report['status'], 'FAIL')

    def test_successful_capture_adapter_cannot_erase_visual_review(self):
        original = self.stage('virtual')
        def capture(*args):
            return dict(original(*args), owner_status='CAPTURED_REQUIRES_VISUAL_REVIEW', visual_review='REQUIRED')
        self.virtual.run_virtual = capture
        self.dev.run(self.native(), [])
        self.assertTrue(self.publish())
        self.assertEqual(self.dev.report['status'], 'CAPTURED_REQUIRES_VISUAL_REVIEW')

    def test_cleanup_failure_is_authoritative(self):
        self.dev.run(self.native(cleanup_pass=False), [])
        self.assertFalse(self.publish())
        self.assertEqual(self.dev.report['initial_cleanup']['status'], 'FAIL')

    def test_inconsistent_pass_summary_with_failed_cleanup_is_refused(self):
        native = self.native()
        original = native.main
        def inconsistent(*args, **kwargs):
            original(*args, **kwargs)
            save(self.output / 'integration/result.json', {'status':'PASS', 'owned_image_cleanup':{'status':'FAIL'}})
            return 0
        native.main = inconsistent
        self.dev.run(native, [])
        self.assertFalse(self.publish())
        self.assertEqual(self.dev.report['status'], 'FAIL')

    def test_one_followup_failure_does_not_suppress_other_independent_stages(self):
        self.base.run_ksm = self.stage('ksm', 'FAIL')
        self.dev.run(self.native(), [])
        self.assertIn('virtual', self.events)
        self.assertFalse(self.publish())
        self.assertEqual(self.dev.report['stages']['ksm']['status'], 'FAIL')

    def test_missing_installed_prerequisite_remains_named_not_run(self):
        self.virtual.run_virtual = self.stage('virtual', 'NOT RUN')
        self.dev.run(self.native(), [])
        self.assertFalse(self.publish())
        self.assertEqual(self.dev.report['stages']['virtual']['status'], 'NOT RUN')

    def test_adapter_exception_is_fixed_failure_without_exception_content(self):
        def fail(*args): raise ValueError('untrusted confidential content')
        self.base.run_ksm = fail
        self.dev.run(self.native(), [])
        self.assertIn('virtual', self.events)
        self.assertNotIn('confidential', json.dumps(self.dev.report))
        self.assertFalse(self.publish())

    def test_public_path_escape_refused(self):
        def fail(initial, root, output):
            return {'status':'PASS','public':[str(self.root / 'outside')]}
        self.base.run_ksm = fail
        self.dev.run(self.native(), [])
        self.assertEqual(self.dev.report['stages']['ksm']['status'], 'FAIL')
        self.assertFalse(self.publish())

    def test_private_descendant_is_not_a_public_selector(self):
        def unsafe(initial, root, output):
            path = output / 'unselected-private/.gnupg/private-keys-v1.d'
            path.mkdir(parents=True)
            (path / 'mock.key').write_text('synthetic fixture')
            return {'status':'PASS','public':[str(output / 'unselected-private')]}
        self.base.run_ksm = unsafe
        self.dev.run(self.native(), [])
        self.assertEqual(self.dev.report['stages']['ksm']['status'], 'FAIL')
        self.assertFalse(self.publish())
        self.assertFalse(any('unselected-private' in row['name'] for row in self.dev.report['bundles']))

    def test_sensitive_content_inside_an_allowed_selector_is_not_published(self):
        original = self.stage('ksm')
        def unsafe(*args):
            value = original(*args)
            path = Path(value['public'][0]) / '.gnupg/private-keys-v1.d'
            path.mkdir(parents=True); (path / 'mock.key').write_text('synthetic fixture')
            return value
        self.base.run_ksm = unsafe
        self.dev.run(self.native(), [])
        self.assertFalse(self.publish())
        self.assertEqual(self.dev.report['publication'], 'FAIL')

    def test_unknown_suffix_cannot_publish_private_armor(self):
        original = self.stage('ksm')
        def unsafe(*args):
            value = original(*args)
            (Path(value['public'][0]) / 'certificate.asc').write_text('-----BEGIN PGP PRIVATE KEY BLOCK-----\nsynthetic\n')
            return value
        self.base.run_ksm = unsafe
        self.dev.run(self.native(), [])
        self.assertFalse(self.publish())
        self.assertEqual(self.dev.report['publication'], 'FAIL')

    def test_publication_failure_turns_success_into_failure(self):
        self.dev.run(self.native(), [])
        def fail(root):
            if root.name == 'public': raise ValueError('oversize required material')
            return self.bundle(root)
        self.assertFalse(self.publish(fail))
        self.assertEqual(self.dev.report['publication'], 'FAIL')
        self.assertEqual(json.loads((self.output / 'development-summary/result.json').read_text())['status'], 'FAIL')

    def test_final_summary_failure_rewrites_durable_status(self):
        self.dev.run(self.native(), [])
        def fail(root):
            if root.name == 'development-summary': raise OSError()
            return self.bundle(root)
        self.assertFalse(self.publish(fail))
        self.assertEqual(json.loads((self.output / 'result.json').read_text())['status'], 'FAIL')

    def test_late_restoration_cancellation_rewrites_durable_terminal_summary(self):
        self.dev.run(self.native(), []); self.assertTrue(self.publish())
        import signal
        thrown = []
        def restoration(sig, handler):
            if handler == signal.SIG_DFL and not thrown:
                thrown.append(True); raise KeyboardInterrupt()
        with patch.object(signal, 'pthread_sigmask', return_value=set()), patch.object(signal, 'sigpending', return_value=set()), \
                patch.object(signal, 'setitimer'), patch.object(signal, 'signal', side_effect=restoration):
            with patch('builtins.print'):
                self.assertTrue(controller.close_boundary(self.dev, {signal.SIGINT:signal.SIG_DFL, signal.SIGTERM:signal.SIG_DFL}, (0,0)))
        report = json.loads((self.output / 'development-summary/result.json').read_text())
        self.assertEqual(report['status'], 'FAIL'); self.assertTrue(report['cancelled'])

    def test_pending_delivery_interrupt_at_unmask_is_recorded_before_old_handlers(self):
        self.dev.run(self.native(), []); self.assertTrue(self.publish())
        import signal
        delivered = []
        def masking(operation, mask):
            if operation == signal.SIG_SETMASK and not delivered:
                delivered.append(True); raise KeyboardInterrupt()
            return set()
        with patch.object(signal, 'pthread_sigmask', side_effect=masking), patch.object(signal, 'sigpending', return_value=set()), \
                patch.object(signal, 'setitimer'), patch.object(signal, 'signal') as restoring, patch('builtins.print'):
            self.assertTrue(controller.close_boundary(self.dev, {signal.SIGINT:signal.SIG_DFL}, (0,0)))
        report = json.loads((self.output / 'development-summary/result.json').read_text())
        self.assertEqual(report['status'], 'FAIL'); self.assertTrue(report['cancelled'])

    def test_cancelled_callback_stops_followups_and_retains_failure(self):
        def cancel(initial, root, output):
            controller.CANCELLED = True
            raise KeyboardInterrupt()
        self.base.run_ksm = cancel
        self.dev.run(self.native(), [])
        self.assertEqual(self.dev.report['stages']['ksm']['status'], 'FAIL')
        self.assertEqual(self.dev.report['stages']['arm-c01-base']['status'], 'NOT RUN')
        self.assertFalse(self.publish())
        self.assertEqual(json.loads((self.output / 'development-summary/result.json').read_text())['status'], 'FAIL')

    def test_public_tree_rejects_symlink_hardlink_and_nonregular(self):
        import os
        directory = self.root / 'projection'; directory.mkdir()
        source = directory / 'receipt.json'; source.write_text('{}')
        link = directory / 'link'; link.symlink_to(source)
        with self.assertRaises(ValueError): controller.public_tree(directory)
        link.unlink(); os.link(source, link)
        with self.assertRaises(ValueError): controller.public_tree(directory)
        link.unlink(); source.unlink(); os.mkfifo(directory / 'fifo')
        with self.assertRaises(ValueError): controller.public_tree(directory)


class ComposedForwardingTests(unittest.TestCase):
    """Inert stages model forwarding; namespace/frame guards have separate real-source tests."""
    def setUp(self):
        ControllerTests.setUp(self)
        self.alarm=patch.object(controller.signal,'setitimer');self.alarm.start();self.addCleanup(self.alarm.stop)
        self.J=controller.time.monotonic()+300
        self.dev.deadline=self.J
        self.contexts=[]
        self.dev.repository_session=SimpleNamespace(original_context=lambda **kw:self.contexts.append(kw))
        self.guard=patch.object(controller,'broad_source_guard',return_value=('SOURCE MODEL',))
        self.guard.start();self.addCleanup(self.guard.stop)
        self.parent_modules=patch.dict(sys.modules,{'common':sys.modules['common'],'packet':controller.packet})
        self.parent_modules.start();self.addCleanup(self.parent_modules.stop)

    def stage(self,name,status='PASS'):
        base=ControllerTests.stage(self,name,status)
        def action(*args,deadline=None):
            self.assertEqual(deadline,self.J)
            return base(*args)
        return action

    def test_fixed_deadline_reaches_four_stages_and_alarm_is_preserved(self):
        with patch.object(controller.signal,'setitimer') as timer:
            self.dev.consume(self.initial)
        self.assertEqual(self.events,['ksm','arm-c01-base','client','virtual'])
        self.assertEqual(len(self.contexts),5)
        self.assertTrue(all(row=={'deadline':self.J,'controller':self.initial} for row in self.contexts))
        self.assertTrue(all(call.args[1]>0 for call in timer.call_args_list))
        self.assertEqual(self.dev.deadline,self.J)

    def test_expired_cutoff_refuses_before_any_stage(self):
        self.dev.deadline=controller.time.monotonic()-1
        with self.assertRaises(ValueError):self.dev.consume(self.initial)
        self.assertEqual(self.events,[])

    def test_source_identity_change_does_not_promote_returned_stage_pass(self):
        observations=iter([('first',),('first',),('changed',),('changed',),('changed',),('changed',)])
        with patch.object(controller,'broad_source_guard',side_effect=lambda *a:next(observations)):
            self.dev.consume(self.initial)
        self.assertEqual(self.events,['ksm'])
        self.assertEqual(self.dev.report['stages']['ksm']['status'],'FAIL')
        self.assertTrue(all(self.dev.report['stages'][name]['status']=='FAIL' for name in ('arm-c01-base','client','virtual')))

    def test_first_error_survives_terminal_cancellation(self):
        self.dev.report['error_code']='original-first-failure'
        controller.CANCELLED=True
        import signal
        with patch.object(signal,'pthread_sigmask',return_value=set()),patch.object(signal,'sigpending',return_value=set()), \
             patch.object(signal,'setitimer'),patch.object(signal,'signal'),patch('builtins.print'):
            self.assertTrue(controller.close_boundary(self.dev,{signal.SIGINT:signal.SIG_DFL},(0,0)))
        self.assertEqual(self.dev.report['error_code'],'original-first-failure')
        self.assertEqual(self.dev.report['status'],'FAIL')
        self.assertIsNone(self.dev.repository_capture)


class RecoveryDeadlineTests(unittest.TestCase):
    """Private selectors and controlled clock expiry; no stage actors or grants."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.output = self.root / 'output'; self.output.mkdir()
        self.J = 200.0; self.now = 100.0
        self.dev = controller.Development(self.root, self.output, self.root / 'cache', {}, deadline=self.J)
        self.clock = patch.object(controller.time, 'monotonic', side_effect=lambda:self.now)
        self.clock.start(); self.addCleanup(self.clock.stop)
        self.base = ModuleType('base_stages'); self.virtual = ModuleType('virtual_stage')
        self.base.recovery_public = lambda name, output, **kw:[output / 'adapter-status']
        self.virtual.public_paths = lambda output:[output / 'adapter-status']
        self.modules = patch.dict(sys.modules, {'base_stages':self.base, 'virtual_stage':self.virtual})
        self.modules.start(); self.addCleanup(self.modules.stop)
        for name in controller.STAGES:
            self.dev.report['stages'][name] = {'status':'FAIL', 'error_code':'original-first-failure'}
            (self.output / name / 'adapter-status').mkdir(parents=True)

    def recover(self, name):
        self.dev.recover_public(name, self.output / name)

    def refused(self, name):
        self.assertEqual(self.dev.report['stages'][name],
                         {'status':'FAIL', 'error_code':'original-first-failure', 'failure_retention':'FAIL'})
        self.assertEqual(self.dev.deadline, self.J)

    def test_base_selectors_receive_exact_J_and_legacy_kwargs_stay_empty(self):
        calls = []
        def selected(name, output, **kwargs):
            calls.append((name, kwargs)); return []
        self.base.recovery_public = selected
        for deadline, expected in ((self.J, {'deadline':self.J}), (None, {})):
            self.dev.deadline = deadline
            for name in ('ksm', 'arm-c01-base'):self.recover(name)
            self.assertEqual(calls[-2:], [('ksm',expected), ('arm-c01-base',expected)])

    def test_finite_recovery_accepts_all_four_selectors_without_new_budget(self):
        for name in controller.STAGES:
            self.recover(name)
            self.assertIn((self.output / name / 'adapter-status').absolute(), self.dev.public)
            self.assertNotIn('failure_retention', self.dev.report['stages'][name])
        self.assertEqual(self.dev.deadline, self.J)

    def test_expired_J_refuses_before_all_selectors(self):
        self.now = self.J
        with patch.object(self.base, 'recovery_public') as base, patch.object(self.virtual, 'public_paths') as virtual, \
             patch.object(Path, 'is_dir') as client:
            for name in controller.STAGES:self.recover(name); self.refused(name)
        base.assert_not_called(); virtual.assert_not_called(); client.assert_not_called()
        self.assertEqual(self.dev.public, [])

    def test_expiry_inside_base_or_virtual_selector_refuses_returned_paths(self):
        def expired(*args, **kwargs):
            self.now = self.J; return [args[-1] / 'adapter-status']
        self.base.recovery_public = expired; self.virtual.public_paths = expired
        for name in ('ksm', 'arm-c01-base', 'virtual'):
            self.now = 100.0; self.recover(name); self.refused(name)
        self.assertEqual(self.dev.public, [])

    def test_client_expiry_inside_each_directory_probe_refuses_selection(self):
        for expiry_call in (1, 2):
            with self.subTest(expiry_call=expiry_call):
                self.now = 100.0; calls = []
                def probe(path):
                    calls.append(path.name)
                    if len(calls) == expiry_call:self.now = self.J
                    return True
                with patch.object(Path, 'is_dir', probe):self.recover('client')
                self.refused('client')
                self.assertEqual(len(calls), expiry_call)
                self.assertEqual(self.dev.public, [])

    def test_expiry_while_iterator_yields_cannot_accept_path(self):
        def selected(output):
            def paths():
                yield output / 'adapter-status'
                self.now = self.J
                yield output / 'virtual-public/result'
            return paths()
        self.virtual.public_paths = selected
        self.recover('virtual'); self.refused('virtual')
        self.assertEqual(self.dev.public, [(self.output / 'virtual/adapter-status').absolute()])

    def test_expiry_on_empty_iterator_completion_is_retention_failure(self):
        def selected(output):
            def paths():
                self.now = self.J
                yield from ()
            return paths()
        self.virtual.public_paths = selected
        self.recover('virtual'); self.refused('virtual')
        self.assertEqual(self.dev.public, [])

    def test_expiry_during_path_validation_prevents_acceptance(self):
        original = Path.absolute
        def expired(path):
            self.now = self.J; return original(path)
        with patch.object(Path, 'absolute', expired):self.recover('ksm')
        self.refused('ksm'); self.assertEqual(self.dev.public, [])

    def test_expiry_after_retention_is_reported_without_renewal(self):
        test = self
        class Retained(list):
            def append(self, path):
                super().append(path); test.now = test.J
        self.dev.public = Retained()
        self.recover('ksm'); self.refused('ksm')

    def test_path_refusal_preserves_first_failure(self):
        self.base.recovery_public = lambda *args, **kwargs:[self.root / 'outside']
        self.recover('ksm'); self.refused('ksm')
        self.assertEqual(self.dev.public, [])

    def test_recovery_interrupt_records_retention_failure_and_preserves_cancel(self):
        self.dev.report['cancelled'] = True
        self.dev.report['stages']['virtual']['error_code'] = 'cancelled'
        def interrupted(output):raise KeyboardInterrupt()
        self.virtual.public_paths = interrupted
        with self.assertRaises(KeyboardInterrupt):self.recover('virtual')
        self.assertEqual(self.dev.report['stages']['virtual'],
                         {'status':'FAIL', 'error_code':'cancelled', 'failure_retention':'FAIL'})
        self.assertTrue(self.dev.report['cancelled']); self.assertEqual(self.dev.deadline, self.J)

    def test_expired_recovery_preserves_authoritative_cancellation(self):
        self.now = self.J; self.dev.report['cancelled'] = True
        self.dev.report['stages']['ksm']['error_code'] = 'cancelled'
        self.recover('ksm')
        self.assertEqual(self.dev.report['stages']['ksm'],
                         {'status':'FAIL', 'error_code':'cancelled', 'failure_retention':'FAIL'})
        self.assertTrue(self.dev.report['cancelled']); self.assertEqual(self.dev.public, [])


class InstallerRoutingModels(unittest.TestCase):
    """Explicit inert SDK/bridge models; actual native frames, authority and P0 NOT RUN."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name);self.output = self.root/'output';self.output.mkdir()
        self.J = controller.time.monotonic()+300;self.events = []
        self.runtime = {'cli_sha256':'b'*64,'endpoint_identity':{'fixture':'NO ACTOR'},'env':{}}
        self.packet = {'schema_version':2,'composition':controller.packet.INSTALLER_COMPOSITION,'source_files':{}}
        self.dev = controller.Development(self.root,self.output,self.root/'cache',self.packet,deadline=self.J,
            composition=controller.packet.INSTALLER_COMPOSITION,clock_nonce='c'*32,runtime_contract=self.runtime)
        self.initial = SimpleNamespace(cancelled=False)
        events = self.events
        class SourcesModel:
            def class_state(self, *args):events.append('SDK class MODEL')
            def guard(self, *args):events.append('SDK guard MODEL')
            def graph_namespace(self, *args):events.append('SDK namespace MODEL')
            def source_graph(self, session):events.append('SDK graph MODEL');return self.graph
        class SessionModel:
            def original_context(self, **kwargs):
                events.append('original context MODEL');return {'native_frames':'NOT RUN'}
        self.sources = SourcesModel();self.sources.root = self.root
        self.sources.raw = {'scripts/ci/development/repository_handoff.py':b'SDK SOURCE MODEL ONLY',
                            controller.INSTALLER_PATH:b'BRIDGE SOURCE MODEL ONLY'}
        self.sources.grant = {'source_files':{controller.INSTALLER_PATH:{'sha256':controller.hashlib.sha256(self.sources.raw[controller.INSTALLER_PATH]).hexdigest()}},
            'actor_contract_sha256':controller.hashlib.sha256((json.dumps(self.runtime,sort_keys=True,indent=2)+'\n').encode()).hexdigest()}
        self.bridge = ModuleType(controller.INSTALLER_NAME);self.bridge.__file__ = str(self.root/controller.INSTALLER_PATH)
        self.bridge.OWN = controller.INSTALLER_PATH
        self.bridge.ISSUER_SHA = controller.hashlib.sha256(self.sources.raw['scripts/ci/development/repository_handoff.py']).hexdigest()
        self.reply = {'status':'PASS','stage':'native-install-preflight','receiver':{'status':'PASS_NATIVE_PREFLIGHT_ONLY',
            'phase':'complete','ABI':'NOT_RUN','matrix':'NOT_RUN'},'cleanup':{'remove_exit':0,'absent':True},
            'elapsed_seconds':0.1,'ABI':'NOT RUN','native_matrix':'NOT RUN','hardware_validation':'NOT RUN',
            'selected_for_release':False,'public':[]}
        self.bridge.__dict__.update(events=events,reply=self.reply,failure=None,after=None)
        exec("def namespace(module, raw, pin):\n events.append('bridge namespace MODEL')\n"
             "def run(session, initial, output, *, deadline, nonce, runtime_contract):\n"
             " events.append(('bridge run MODEL',deadline,nonce,runtime_contract))\n"
             " if failure is not None:raise failure\n"
             " if after is not None:after()\n return reply\n",self.bridge.__dict__)
        self.sources.graph = {controller.INSTALLER_PATH:self.bridge}
        self.session = SessionModel();self.session.sources = self.sources
        self.session.composition = controller.packet.INSTALLER_COMPOSITION;self.session.job_deadline = self.J
        self.session.controller = self.initial;self.session.native_consumer_observation = ('FRAME MODEL','RUN FRAME MODEL',self.initial)
        self.session.result = {'initial_exit_code':None};self.session.source_graph = {'native_preflight':self.bridge}
        self.owner = ModuleType('development_repository_handoff');self.owner.Session = SessionModel;self.owner.Sources = SourcesModel
        self.dev.repository_session = self.session
        self.modules = patch.dict(sys.modules,{'development_repository_handoff':self.owner,controller.INSTALLER_NAME:self.bridge})
        self.modules.start();self.addCleanup(self.modules.stop)
        timer = patch.object(controller.signal,'setitimer');timer.start();self.addCleanup(timer.stop)
        controller.CANCELLED = False

    def runs(self):return [row for row in self.events if type(row) is tuple]

    def test_installer_runs_exact_graph_callback_after_context_without_broad_prerequisites(self):
        self.dev.report['initial_integration'] = 'FAIL';self.dev.report['repository_handoff'] = {'status':'FAIL'}
        with patch.object(controller,'broad_source_guard',side_effect=AssertionError('broad operations forbidden')):
            self.dev.consume(self.initial)
        self.assertEqual(len(self.runs()),1);self.assertLess(self.events.index('original context MODEL'),self.events.index(self.runs()[0]))
        self.assertEqual(self.runs()[0][1:],(self.J,'c'*32,self.runtime));self.assertEqual(self.dev.deadline,self.J)
        self.assertEqual(self.dev.report['stages']['native-install-preflight']['status'],'PASS')
        self.assertTrue(all(self.dev.report['stages'][name]['status']=='NOT RUN' for name in controller.STAGES))
        self.assertEqual(self.dev.report['status'],'FAIL');self.assertEqual(self.dev.report['hardware_validation'],'NOT RUN')

    def test_modes_must_be_builtin_closed_and_packet_session_bound_before_callback(self):
        class Foreign:
            def __eq__(self, value):raise AssertionError('foreign equality forbidden')
            def __hash__(self):raise AssertionError('foreign hash forbidden')
        for value in (None, True, {}, Foreign(), 'foreign', controller.packet.COMPOSITION):
            self.dev.composition = value
            with self.assertRaises(ValueError):self.dev.consume(self.initial)
        self.dev.composition = controller.packet.INSTALLER_COMPOSITION;self.session.composition = controller.packet.COMPOSITION
        with self.assertRaisesRegex(ValueError,'owner-refused'):self.dev.consume(self.initial)
        self.assertFalse(self.runs())

    def test_wrong_issuer_standin_refuses_before_run(self):
        self.bridge.ISSUER_SHA = '7202c974547c05ca8b7f0ad9772d4ac849d9d684d4105a979a3290e7d6622acb'
        with self.assertRaisesRegex(ValueError,'issuer-refused'):self.dev.consume(self.initial)
        self.assertFalse(self.runs());self.assertEqual(self.dev.report['stages']['native-install-preflight']['status'],'FAIL')

    def test_graph_registry_and_class_substitutions_refuse(self):
        foreign = ModuleType(controller.INSTALLER_NAME);foreign.__file__ = self.bridge.__file__
        for change, restore in ((lambda:self.sources.graph.update({controller.INSTALLER_PATH:foreign}),
                                 lambda:self.sources.graph.update({controller.INSTALLER_PATH:self.bridge})),
                                (lambda:sys.modules.update({controller.INSTALLER_NAME:foreign}),
                                 lambda:sys.modules.update({controller.INSTALLER_NAME:self.bridge})),
                                (lambda:self.session.source_graph.update(native_preflight=foreign),
                                 lambda:self.session.source_graph.update(native_preflight=self.bridge)),
                                (lambda:setattr(self.owner,'Sources',type('ForeignSources',(),{})),
                                 lambda:setattr(self.owner,'Sources',type(self.sources)))):
            change()
            try:
                with self.assertRaises(ValueError):self.dev.consume(self.initial)
            finally:restore()
        self.assertFalse(self.runs())

    def test_callback_foreign_globals_wrong_qualname_and_module_refuse(self):
        original = self.bridge.run
        copy = controller.types.FunctionType(original.__code__,dict(self.bridge.__dict__),'run')
        for candidate in (copy, lambda *args,**kwargs:self.reply, object()):
            self.bridge.run = candidate
            with self.assertRaisesRegex(ValueError,'callback-refused'):self.dev.consume(self.initial)
        self.bridge.run = original;self.assertFalse(self.runs())

    def test_nonce_runtime_shape_and_hash_refuse_without_execution(self):
        for nonce in (None,True,'bad','A'*32,'c'*33):
            self.dev.clock_nonce = nonce
            with self.assertRaisesRegex(ValueError,'runtime-refused'):self.dev.consume(self.initial)
        self.dev.clock_nonce = 'c'*32
        for runtime in ({},dict(self.runtime,extra='UNSELECTED'),dict(self.runtime,cli_sha256='a'*64)):
            self.dev.runtime_contract = runtime
            with self.assertRaisesRegex(ValueError,'runtime-refused'):self.dev.consume(self.initial)
        self.assertFalse(self.runs())

    def test_expired_J_refuses_before_callback_and_does_not_renew(self):
        self.dev.deadline = controller.time.monotonic()-1;expired = self.dev.deadline
        with self.assertRaisesRegex(ValueError,'deadline'):self.dev.consume(self.initial)
        self.assertFalse(self.events);self.assertEqual(self.dev.deadline,expired)

    def test_expiry_after_return_never_promotes_limited_pass(self):
        self.bridge.after = lambda:setattr(self.dev,'deadline',controller.time.monotonic()-1)
        with self.assertRaisesRegex(ValueError,'deadline'):self.dev.consume(self.initial)
        self.assertEqual(len(self.runs()),1);self.assertEqual(self.dev.report['stages']['native-install-preflight']['status'],'FAIL')

    def test_ordinary_cancel_fatal_exact_objects_preserve_first_report_cause(self):
        self.dev.report['error_code'] = 'original-first-cause'
        for first in (ValueError('private ordinary'),KeyboardInterrupt(),SystemExit(7)):
            self.bridge.failure = first
            with self.assertRaises(type(first)) as caught:self.dev.consume(self.initial)
            self.assertIs(caught.exception,first);self.assertEqual(self.dev.report['error_code'],'original-first-cause')
            self.assertEqual(self.dev.report['stages']['native-install-preflight']['status'],'FAIL')
            self.assertTrue(all(self.dev.report['stages'][name]['status']=='NOT RUN' for name in controller.STAGES))
        self.assertTrue(self.dev.report['cancelled'])

    def test_later_persistence_failure_cannot_replace_first_bridge_exception(self):
        self.dev.report['error_code'] = 'original-first-cause'
        for first in (ValueError('first ordinary'),KeyboardInterrupt(),SystemExit(7)):
            self.bridge.failure = first
            with patch.object(self.dev,'persist',side_effect=OSError('later persistence')):
                with self.assertRaises(type(first)) as caught:self.dev.consume(self.initial)
            self.assertIs(caught.exception,first);self.assertEqual(self.dev.report['error_code'],'original-first-cause')
            self.assertEqual(self.dev.report['status_persistence'],'FAIL')
        self.assertTrue(self.dev.report['cancelled'])

    def test_persistence_failure_after_success_remains_fatal_without_limited_PASS(self):
        later = OSError('terminal persistence')
        with patch.object(self.dev,'persist',side_effect=later):
            with self.assertRaises(OSError) as caught:self.dev.consume(self.initial)
        self.assertIs(caught.exception,later)
        self.assertEqual(self.dev.report['status'],'FAIL');self.assertEqual(self.dev.report['status_persistence'],'FAIL')
        self.assertEqual(self.dev.report['stages']['native-install-preflight']['status'],'FAIL')

    def test_pending_cancellation_never_enters_bridge(self):
        controller.CANCELLED = True
        with self.assertRaises(KeyboardInterrupt):self.dev.consume(self.initial)
        self.assertFalse(self.runs());self.assertTrue(self.dev.report['cancelled']);controller.CANCELLED = False

    def test_late_graph_drift_refuses_returned_pass(self):
        foreign = ModuleType(controller.INSTALLER_NAME)
        self.bridge.after = lambda:sys.modules.update({controller.INSTALLER_NAME:foreign})
        with self.assertRaisesRegex(ValueError,'graph-refused'):self.dev.consume(self.initial)
        self.assertIs(sys.modules[controller.INSTALLER_NAME],foreign)
        self.assertEqual(self.dev.report['stages']['native-install-preflight']['status'],'FAIL')

    def test_public_result_status_cleanup_types_and_claims_are_closed(self):
        import copy
        pristine = copy.deepcopy(self.reply)
        changes = (lambda r:r.update(status='PASS_NATIVE_PREFLIGHT_ONLY'),lambda r:r.update(extra=True),
                   lambda r:r.update(public=['/unselected']),lambda r:r.update(selected_for_release=True),
                   lambda r:r.update(ABI='PASS'),lambda r:r['cleanup'].update(remove_exit=False),
                   lambda r:r['cleanup'].update(absent=1),lambda r:r['receiver'].update(status='PASS'),
                   lambda r:r['receiver'].update(matrix='PASS'),lambda r:r.update(elapsed_seconds=True))
        for change in changes:
            candidate = copy.deepcopy(pristine);change(candidate);self.bridge.reply = candidate
            with self.assertRaisesRegex(ValueError,'result-refused'):self.dev.consume(self.initial)
        self.assertEqual(self.dev.report['stages']['native-install-preflight']['status'],'FAIL')

    def test_limited_pass_cannot_publish_whole_project_pass_even_with_unrelated_pass_labels(self):
        self.dev.consume(self.initial)
        self.dev.report.update(initial_integration='PASS',initial_cleanup={'status':'PASS'},cancelled=False,
            repository_handoff={'status':'PASS','cleanup':'PASS','restage':'PASS','input_acceptance':'PASS'})
        for name in controller.STAGES:self.dev.report['stages'][name] = {'status':'PASS'}
        self.dev.publication_deadline = self.J
        with patch.object(controller,'phase_capture',return_value=object()),patch.object(controller,'phase_bundle',return_value=b'MODEL'), \
             patch.object(controller,'public_tree'):
            accepted = controller.publish(self.dev,lambda root:b'MODEL',emit=lambda *args,**kwargs:None)
        self.assertFalse(accepted);self.assertEqual(self.dev.report['status'],'FAIL')
        self.assertEqual(self.dev.report['stages']['native-install-preflight']['status'],'PASS')

    def test_owned_registry_retirement_removes_only_exact_captured_module(self):
        self.dev.consume(self.initial)
        self.assertTrue(controller.retire_installer_module(self.session,self.dev))
        self.assertNotIn(controller.INSTALLER_NAME,sys.modules)
        self.assertTrue(controller.retire_installer_module(self.session,self.dev))

    def test_foreign_replacement_or_missing_owned_graph_is_preserved_and_refuses_cleanup(self):
        self.dev.consume(self.initial);foreign = ModuleType(controller.INSTALLER_NAME)
        sys.modules[controller.INSTALLER_NAME] = foreign
        self.assertFalse(controller.retire_installer_module(self.session,self.dev));self.assertIs(sys.modules[controller.INSTALLER_NAME],foreign)
        self.session.source_graph.clear()
        self.assertFalse(controller.retire_installer_module(self.session,self.dev));self.assertIs(sys.modules[controller.INSTALLER_NAME],foreign)

    def test_unselected_session_mode_refuses_retirement_without_foreign_equality(self):
        class Foreign:
            def __eq__(self, other):raise AssertionError('foreign mode equality forbidden')
        self.session.composition = Foreign()
        with self.assertRaisesRegex(ValueError,'retirement-refused'):controller.retire_installer_module(self.session,self.dev)
        self.assertIs(sys.modules[controller.INSTALLER_NAME],self.bridge)

    def test_run_composed_rejects_selected_mode_mismatch_before_session_execution(self):
        self.session.composition = controller.packet.COMPOSITION
        with self.assertRaisesRegex(ValueError,'session-refused'):
            self.dev.run_composed(self.session,SimpleNamespace(),self.runtime,[])
        self.assertFalse(self.runs())


class InstallerCliModeModels(unittest.TestCase):
    """Private clock/packet dispatch models, no actual grant, original frames or actors."""
    def setUp(self):
        self.fixture = ClockContractTests();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)

    def test_explicit_closed_CLI_modes_forward_and_default_repository_remains(self):
        for mode in controller.packet.COMPOSED_MODES:
            args = ['--inputs-sha256','a'*64,'--recipes-sha256','b'*64,'--integration-sha256','c'*64,
                '--development-sha256','d'*64,'--cache','/model/cache','--output','/model/output','--composition',mode]
            with patch.object(controller,'composed_main',return_value=7) as dispatch:
                self.assertEqual(controller.main(args),7)
            self.assertEqual(dispatch.call_args.args[0].composition,mode)

    def test_foreign_explicit_mode_refuses_before_private_input_or_packet(self):
        args = self.fixture.boundary_args();args.composition = 'foreign'
        with patch.object(controller,'private_input') as capture,patch.object(controller.packet,'preflight_composed') as preflight:
            with self.assertRaisesRegex(ValueError,'contract-refused'):controller.composed_main(args,{},entry=self.fixture.entry)
        capture.assert_not_called();preflight.assert_not_called()

    def test_packet_preflight_receives_explicit_mode_and_wrong_returned_mode_refuses(self):
        args = self.fixture.boundary_args();args.composition = controller.packet.INSTALLER_COMPOSITION
        value = {'schema_version':2,'composition':controller.packet.COMPOSITION,'metadata_pins':{}}
        with patch.object(controller,'private_input',return_value=self.fixture.raw(self.fixture.value)), \
             patch.object(controller.signal,'getitimer',return_value=(0.0,0.0)),patch.object(controller.signal,'signal'), \
             patch.object(controller.signal,'setitimer'),patch.object(controller,'close_boundary',return_value=False), \
             patch.object(controller.packet,'preflight_composed',return_value=value) as preflight,patch('builtins.print'):
            with self.assertRaisesRegex(ValueError,'contract-refused'):controller.composed_main(args,{},entry=self.fixture.entry)
        self.assertEqual(preflight.call_args.kwargs,{'composition':controller.packet.INSTALLER_COMPOSITION})


    def test_installer_finalization_preserves_exact_bootstrap_first_cause(self):
        args = self.fixture.boundary_args();args.composition = controller.packet.INSTALLER_COMPOSITION
        for first in (ValueError('bootstrap first'),KeyboardInterrupt(),SystemExit(3)):
            with patch.object(controller,'private_input',return_value=self.fixture.raw(self.fixture.value)), \
                 patch.object(controller.signal,'getitimer',return_value=(0.0,0.0)),patch.object(controller.signal,'signal'), \
                 patch.object(controller.signal,'setitimer'),patch.object(controller,'close_boundary',side_effect=OSError('later finalization')), \
                 patch.object(controller.packet,'preflight_composed',side_effect=first),patch('builtins.print'):
                with self.assertRaises(type(first)) as caught:controller.composed_main(args,{},entry=self.fixture.entry)
            self.assertIs(caught.exception,first)

    def test_installer_failed_retirement_overrides_only_provisional_success(self):
        args = self.fixture.boundary_args();args.composition = controller.packet.INSTALLER_COMPOSITION;args.check_only = True
        value = {'schema_version':2,'composition':controller.packet.INSTALLER_COMPOSITION,'metadata_pins':{}}
        with patch.object(controller,'private_input',return_value=self.fixture.raw(self.fixture.value)), \
             patch.object(controller.signal,'getitimer',return_value=(0.0,0.0)),patch.object(controller.signal,'signal'), \
             patch.object(controller.signal,'setitimer'),patch.object(controller,'close_boundary',return_value=False), \
             patch.object(controller,'retire_installer_module',return_value=False), \
             patch.object(controller.packet,'preflight_composed',return_value=value),patch('builtins.print'):
            with self.assertRaisesRegex(ValueError,'finalization-failed'):controller.composed_main(args,{},entry=self.fixture.entry)


class InstallerConstructorSourceTests(unittest.TestCase):
    """Actual captured SDK construction with finite synthetic contracts; no execution grant or actors."""
    @classmethod
    def setUpClass(cls):
        import test_repository_handoff
        cls.fixture = test_repository_handoff.CapturedGraphFixtures;cls.fixture.setUpClass()
        cls.addClassCleanup(cls.fixture.doClassCleanups)

    def test_actual_source_constructor_propagates_closed_installer_mode_before_allocation(self):
        import copy,hashlib,time,types
        sources = self.fixture.sources;root = self.fixture.root;modules = {}
        sha = lambda raw:hashlib.sha256(raw).hexdigest()
        encoded = lambda value:(json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
        with patch.dict(sys.modules,{}):
            for name in ('common','packet','captured_installer_controller'):
                path = 'scripts/ci/development/'+('controller' if name=='captured_installer_controller' else name)+'.py'
                module = types.ModuleType(name);module.__file__ = str(root/path);sys.modules[name] = module
                exec(compile(sources.raw[path],module.__file__,'exec'),module.__dict__);modules[name] = module
            parent = modules['captured_installer_controller'];output = self.fixture.output.parent/'installer-proposed-output'
            cache = output.parent/'installer-proposed-cache';J = time.monotonic()+60
            packet_model = {'schema_version':2,'composition':'installer-preflight','source_files':copy.deepcopy(sources.grant['source_files']),
                'metadata_pins':{name:sha(sources.raw[name]) for name in modules['packet'].COMPOSED_PINS}}
            grant = copy.deepcopy(sources.grant)
            grant['callbacks'] = {'existing_consumers':{'path':'scripts/ci/development/controller.py','module':parent.__name__,'qualname':'Development.consume'},
                **{role:{'path':'scripts/ci/development/repository_authority.py','module':'development_repository_authority',
                         'qualname':'RootCallbacks.'+role} for role in ('public_receiver','authority_provider')}}
            grant['original_view']['root'] = str(output/'repository-handoff/original-view')
            runtime = {'cli_sha256':'b'*64,'endpoint_identity':{'fixture':'NO ACTOR'},'env':{}}
            argv = parent.original_argv(output,cache,packet_model['metadata_pins'])
            grant['initial_invocation_sha256'] = sha(encoded({'argv':argv,'output':str(output/'repository-handoff')}))
            actor_raw = encoded(runtime);grant['actor_contract_sha256'] = sha(actor_raw)
            raw = encoded(grant);pin = sha(raw)
            env = {'GITHUB_SHA':grant['source_commit'],'GITHUB_RUN_ID':grant['run_id'],'GITHUB_RUN_ATTEMPT':grant['run_attempt']}
            with patch.dict(controller.os.environ,env):
                session,callbacks,actual,selected = parent.composed_sources(root,packet_model,raw,pin,actor_raw,output,cache,J,
                    composition='installer-preflight')
                self.assertEqual(session.composition,'installer-preflight');self.assertEqual(session.job_deadline,J)
                self.assertEqual(selected,argv);self.assertEqual(actual,runtime);self.assertIs(callbacks._session,session)
                self.assertFalse(session.used);self.assertIsNone(session.view_root);self.assertEqual(session.source_graph,{})
                self.assertFalse(output.exists());self.assertFalse(cache.exists());self.assertNotIn(parent.INSTALLER_NAME,sys.modules)
                for name in ('development_repository_handoff','development_repository_authority'):sys.modules.pop(name,None)
                for mode in (None,True,{},'foreign','repository-svg'):
                    with self.subTest(mode=type(mode).__name__),self.assertRaisesRegex(ValueError,'contract-refused'):
                        parent.composed_sources(root,packet_model,raw,pin,actor_raw,output,cache,J,composition=mode)
                    self.assertFalse(output.exists());self.assertFalse(cache.exists())
                with self.assertRaisesRegex(ValueError,'contract-refused'):
                    parent.composed_sources(root,packet_model,raw,pin,actor_raw,output,cache,J)


class ClockContractTests(unittest.TestCase):
    """Private file/domain and finite issuance models, not an actual Root clock grant."""
    def setUp(self):
        import time
        self.entry=time.monotonic();self.pin='b'*64
        self.env={'GITHUB_SHA':'a'*40,'GITHUB_WORKFLOW_SHA':'a'*40,'GITHUB_RUN_ID':'123','GITHUB_RUN_ATTEMPT':'2'}
        self.domain=controller.clock_domain()
        self.value={'schema_version':1,'purpose':'development-workflow-clock','source_commit':'a'*40,'run_id':'123',
            'run_attempt':'2','nonce':'c'*32,'issued_monotonic':self.entry-10,'deadline_monotonic':self.entry-10+10800,
            'allowance_seconds':10800,'clock_domain':self.domain,'issuer_source_sha256':self.pin,'issuer_workflow_commit':'a'*40}
        self.patch=patch.dict(controller.os.environ,self.env);self.patch.start();self.addCleanup(self.patch.stop)
        self.issuer=patch.object(controller,'CLOCK_ISSUER_SHA256',self.pin);self.issuer.start();self.addCleanup(self.issuer.stop)

    def raw(self,value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()

    def test_model_clock_is_clipped_once_without_renewal(self):
        J,end=controller.workflow_clock(self.raw(self.value),entry=self.entry)
        self.assertEqual(J,self.entry+10080);self.assertEqual(end,self.value['deadline_monotonic'])
        with patch.object(controller.time,'monotonic',return_value=self.entry+100):
            self.assertEqual(controller.workflow_clock(self.raw(self.value),entry=self.entry),(J,end))

    def test_unregistered_issuer_wrong_job_and_workflow_refuse(self):
        with patch.object(controller,'CLOCK_ISSUER_SHA256',None):
            with self.assertRaises(ValueError):controller.workflow_clock(self.raw(self.value),entry=self.entry)
        for name in ('source_commit','run_id','run_attempt','issuer_workflow_commit','issuer_source_sha256'):
            value=dict(self.value);value[name]='d'*40
            with self.subTest(name=name),self.assertRaises(ValueError):controller.workflow_clock(self.raw(value),entry=self.entry)

    def test_clock_types_expiry_renewal_extra_keys_and_domains_refuse(self):
        import copy
        for key,value in (('issued_monotonic',True),('deadline_monotonic',float('inf')),('deadline_monotonic',10**1000),
                ('deadline_monotonic',self.value['deadline_monotonic']+1),('allowance_seconds',True),('nonce','wrong'),('extra','PRIVATE')):
            candidate=copy.deepcopy(self.value);candidate[key]=value
            with self.subTest(key=key,value=str(value)[:40]),self.assertRaises(ValueError):
                controller.workflow_clock(self.raw(candidate),entry=self.entry)
        for key,value in (('boot_id','d'*36),('time_namespace_device',True),('time_namespace_inode',0),('clock_id','UTC'),('extra',1)):
            candidate=copy.deepcopy(self.value);candidate['clock_domain'][key]=value
            with self.subTest(domain=key),self.assertRaises(ValueError):controller.workflow_clock(self.raw(candidate),entry=self.entry)
        with patch.object(controller.time,'monotonic',return_value=self.value['deadline_monotonic']):
            with self.assertRaises(ValueError):controller.workflow_clock(self.raw(self.value),entry=self.entry)

    def test_private_capture_exact_env_pin_mode_link_type_and_mutation(self):
        import hashlib,os
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);root.chmod(0o700);path=root/'clock.json';raw=self.raw(self.value)
            path.write_bytes(raw);path.chmod(0o600);pin=hashlib.sha256(raw).hexdigest()
            env={'DEVELOPMENT_CLOCK_PATH':str(path),'DEVELOPMENT_CLOCK_SHA256':pin}
            with patch.dict(controller.os.environ,env),patch.object(controller,'ROOT',root/'checkout'):
                self.assertEqual(controller.private_input(path,pin,'DEVELOPMENT_CLOCK',16384),raw)
                path.chmod(0o644)
                with self.assertRaises(ValueError):controller.private_input(path,pin,'DEVELOPMENT_CLOCK',16384)
                path.chmod(0o600);os.link(path,root/'link')
                with self.assertRaises(ValueError):controller.private_input(path,pin,'DEVELOPMENT_CLOCK',16384)
                (root/'link').unlink()
                read=controller.os.read;changed=[]
                def mutate(fd,size):
                    result=read(fd,size)
                    if not changed:changed.append(True);path.write_bytes(b'changed')
                    return result
                with patch.object(controller.os,'read',side_effect=mutate),self.assertRaises(ValueError):
                    controller.private_input(path,pin,'DEVELOPMENT_CLOCK',16384)
                path.unlink();path.symlink_to(root/'missing')
                with self.assertRaises((ValueError,OSError)):controller.private_input(path,pin,'DEVELOPMENT_CLOCK',16384)

    def test_missing_composed_inputs_refuse_before_source_or_output(self):
        args=SimpleNamespace(clock=None)
        with patch.object(controller.packet,'preflight_composed',side_effect=AssertionError('must not preflight')):
            with self.assertRaises(ValueError):controller.composed_main(args,{},entry=self.entry)

    def test_actual_argv_is_explicit19_and_output_bound(self):
        output=Path('/tmp/model-development');cache=Path('/tmp/model-cache')
        pins={'scripts/ci/'+name+'.lock.json':str(number)*64 for number,name in enumerate(('inputs','recipes','integration'),1)}
        argv=controller.original_argv(output,cache,pins)
        self.assertEqual(len(argv),19)
        self.assertEqual(argv[argv.index('--inputs')+1],str(output/'repository-handoff/original-view/scripts/ci/inputs.lock.json'))
        self.assertEqual(argv[argv.index('--integration-output')+1],str(output/'integration'))


    def boundary_args(self):
        return SimpleNamespace(clock=Path('/model/clock'),clock_sha256=self.pin,execution_grant=Path('/model/grant'),
            execution_grant_sha256=self.pin,runtime_contract=Path('/model/runtime'),runtime_contract_sha256=self.pin,
            packet=Path('/model/packet'),development_sha256=self.pin,check_only=True)

    def test_active_enclosing_alarm_is_refused_without_renewing_or_installing_handlers(self):
        import signal
        with patch.object(controller,'private_input',return_value=self.raw(self.value)), \
             patch.object(signal,'getitimer',return_value=(5.0,0.0)),patch.object(signal,'signal') as install, \
             patch.object(controller.packet,'preflight_composed') as preflight:
            with self.assertRaisesRegex(ValueError,'active-enclosing-timer-refused'):
                controller.composed_main(self.boundary_args(),{},entry=self.entry)
            install.assert_not_called();preflight.assert_not_called()

    def test_partial_handler_install_restores_every_recorded_handler_before_source(self):
        import signal
        controller.CANCELLED=False;calls=[]
        def install(sig,handler):
            calls.append((sig,handler))
            if sig==signal.SIGTERM and handler is controller.interrupt:raise OSError('fixture install fault')
        previous={signal.SIGINT:signal.default_int_handler,signal.SIGTERM:signal.SIG_DFL,signal.SIGALRM:signal.SIG_DFL}
        with patch.object(controller,'private_input',return_value=self.raw(self.value)), \
             patch.object(signal,'getitimer',return_value=(0.0,0.0)), \
             patch.object(signal,'getsignal',side_effect=lambda sig:previous[sig]),patch.object(signal,'signal',side_effect=install), \
             patch.object(signal,'setitimer'),patch.object(signal,'pthread_sigmask',return_value=set()), \
             patch.object(signal,'sigpending',return_value=set()),patch('builtins.print'), \
             patch.object(controller.packet,'preflight_composed') as preflight:
            with self.assertRaises(OSError):controller.composed_main(self.boundary_args(),{},entry=self.entry)
        preflight.assert_not_called()
        for pair in previous.items():self.assertIn(pair,calls)

    def test_early_pending_cancel_remains_fail_not_successful_check_only(self):
        import signal
        controller.CANCELLED=False
        with patch.object(controller,'private_input',return_value=self.raw(self.value)), \
             patch.object(signal,'getitimer',return_value=(0.0,0.0)),patch.object(signal,'signal'), \
             patch.object(signal,'setitimer'),patch.object(signal,'pthread_sigmask',return_value=set()), \
             patch.object(signal,'sigpending',return_value={signal.SIGTERM}),patch('builtins.print') as report, \
             patch.object(controller.packet,'preflight_composed',return_value={'metadata_pins':{}}):
            with self.assertRaisesRegex(ValueError,'composed-finalization-failed'):
                controller.composed_main(self.boundary_args(),{},entry=self.entry)
        self.assertTrue(controller.CANCELLED)
        self.assertTrue(any('composed-boundary-finalization-failed' in str(call) for call in report.call_args_list))
        controller.CANCELLED=False


class PhaseSchemaTests(unittest.TestCase):
    """Actual captured pure phase codecs, synthetic byte maps; no signing/native authority."""
    @classmethod
    def setUpClass(cls):
        import test_repository_handoff
        cls.fixture=test_repository_handoff.CapturedGraphFixtures;cls.fixture.setUpClass()
        cls.addClassCleanup(cls.fixture.doClassCleanups)
        cls.modules=cls.fixture.session.source_graph['phase']

    def setUp(self):
        import copy,hashlib
        self.copy=copy.deepcopy;self.sha=lambda raw:hashlib.sha256(raw).hexdigest();self.a=self.modules['adapter']
        pin='b'*64;fp='A'*40
        roles={'signer-A':{'fingerprint':fp,'certificate_sha256':pin,'certificate':'public/TEST-signer-A-public.asc'},
               'signer-B':{'fingerprint':'B'*40,'certificate_sha256':'c'*64,'certificate':'public/TEST-signer-B-public.asc'},
               'verifier':{'fingerprint':'C'*40,'certificate_sha256':'d'*64,'certificate':'public/TEST-verifier-public.asc'}}
        input_rows=[]
        for number in range(15):
            role='signer-A' if number<7 else 'signer-B'
            input_rows.append({'path':'public/object-'+str(number),'signature':'public/object-'+str(number)+'.sig','signer':role,
                'data_sha256':pin,'signature_sha256':pin,'fingerprint':roles[role]['fingerprint'],
                'certificate_sha256':roles[role]['certificate_sha256'],'snapshot_integrity':'VALID',
                'snapshot_authorization':'SNAPSHOT_ONLY','terminal_authorization':'REVOKED' if role=='signer-A' else 'VALID_AT_OBSERVATION'})
        self.lineage={'schema_version':2,'purpose':'phase-aware-separate-test-signer-restaging','development_only':True,
            'original_B_continuity':False,'repository_authority_sha256':pin,'metadata_sha256':pin,'repository_source_commit':'a'*40,
            'archive_role':'updated','input_lineage':input_rows,'original_signer_roles':roles,
            'original_crypto_verification':'independent-public-key-phase-verification','phase_receipt_sha256':pin,
            'phase_request_sha256':pin,'current_A_authorization':'REVOKED',
            'archives':[]}
        archives={}
        for name in sorted(self.a.ORIGINALS):
            filename=name+'-0.1.0-1-any.pkg.tar.xz';raw=('SOURCE STRUCTURAL FIXTURE '+name+'\n').encode()
            archives['bundle/repo/'+filename]=raw;archives['bundle/repo/'+filename+'.sig']=b'PUBLIC STRUCTURAL SIG\n'
            self.lineage['archives'].append({'name':name,'filename':filename,'sha256':self.sha(raw),'version':'0.1.0-1',
                                           'original_signer':'B'*40,'original_signature_sha256':pin})
        self.files={'bundle/evidence/lineage.json':self.a.encoded(self.lineage),'bundle/release.json':b'{}\n',
                    'logs/000.stdout':b'','logs/000.stderr':b'',**archives}
        self.public={name:{'sha256':self.sha(raw),'bytes':len(raw)} for name,raw in self.files.items()}
        commands=[{'argv':['/usr/bin/gpg',*controller.TEST_GENERATE],'exit_code':0,'expected':0,
            'stdout':'logs/000.stdout','stdout_sha256':self.sha(b''),'stderr':'logs/000.stderr','stderr_sha256':self.sha(b'')}]
        for number,expected in ((1,0),(2,'nonzero')):
            for stream in ('stdout','stderr'):self.files[f'logs/{number:03d}.{stream}']=b''
            commands.append({'argv':['/usr/bin/python3','-I','client.py','verify'],'exit_code':0 if expected==0 else 1,
                'expected':expected,'stdout':f'logs/{number:03d}.stdout','stdout_sha256':self.sha(b''),
                'stderr':f'logs/{number:03d}.stderr','stderr_sha256':self.sha(b'')})
        self.public.update({name:{'sha256':self.sha(raw),'bytes':len(raw)} for name,raw in self.files.items()})
        self.value={'schema_version':2,'purpose':'phase-aware-separate-test-restage','status':'PASS','development_only':True,
            'selected_for_release':False,'original_B_continuity':False,**{name:'NOT RUN' for name in
            ('stable_promotion','production_trust','published_endpoint','hardware_validation','installation','native_build')},
            'repository_authority_sha256':pin,'software_environment':{'architecture':'aarch64','page_size':4096,'execution':'local-bounded-private-processes'},
            'blockers':[],'cleanup':{'status':'PASS','private_state_absent':True,'signer_agent_stop':'PASS'},
            'phase_receipt_sha256':pin,'phase_request_sha256':pin,'original_crypto_verification':'independent-public-key-phase-verification',
            'current_A_authorization':'REVOKED','repository_input_acceptance':'PASS','commands':commands,
            'tool_sha256':{name:pin for name in self.a.TOOLS},'signer':fp,'namespace':'test-restage.'+pin[:16],
            'lineage':self.lineage,'release_sha256':self.sha(self.files['bundle/release.json']),'release_semantics':'PASS',
            'client_cases':[{'name':name,'result':'PASS','expected_rejection':rejection,'checkpoint_before':before,'checkpoint_after':after,
                            'command_record':1 if rejection is None else 2} for name,rejection,before,after in (
                ('cold-readonly',None,None,None),('apply-1',None,None,'d'*64),('repeat-readonly',None,'d'*64,'d'*64),
                ('apply-2',None,'d'*64,'e'*64),('signed-rollback-rejected','metadata sequence rollback','e'*64,'e'*64),
                ('signed-same-sequence-change-rejected','same sequence has altered metadata bytes','e'*64,'e'*64),
                ('wrong-namespace-rejected','metadata namespace/signer differs from external pin','e'*64,'e'*64))],
            'new_signature_and_database_sha256':{Path(name).name:row['sha256'] for name,row in self.public.items() if name.endswith('.pkg.tar.xz.sig')},'source_sha256':self.a.SOURCES,'metadata_sha256':pin,'public_files':self.public}
        self.descriptor={'public_files':self.public}

    def check(self,value=None):
        return controller.phase_result(self.value if value is None else value,self.files,self.descriptor,self.modules)

    def test_source_defined_public_semantics_and_empty_test_generation_model(self):
        self.assertEqual(set(self.value),controller.PHASE_RESULT_KEYS);self.check()
        self.assertTrue(controller.public_policy().PRIVATE_CONTENT.search(self.a.encoded(self.value).decode()))
        self.assertEqual(self.value['native_build'],'NOT RUN')

    def test_wrong_passphrase_action_value_location_or_executable_refuse(self):
        for kind in ('nonempty','missing','option-equals','file-option','wrong-action','false','wrong-tool','extra-key','alias'):
            value=self.copy(self.value);argv=value['commands'][0]['argv']
            if kind=='nonempty':argv[6]='PRIVATE'
            elif kind=='missing':del argv[6]
            elif kind=='option-equals':argv[5]='--passphrase='
            elif kind=='file-option':argv[5]='--passphrase-file'
            elif kind=='wrong-action':argv[7]='--export-secret-keys'
            elif kind=='false':argv[6]=False
            elif kind=='wrong-tool':argv[0]='/usr/bin/python3'
            elif kind=='extra-key':value['commands'][0]['passphrase']=''
            else:value['random_current_A_authorization']='REVOKED'
            with self.subTest(kind=kind),self.assertRaises((ValueError,TypeError)):
                self.check(value)

    def test_semantic_slot_enum_signer_alias_and_credential_keys_refuse(self):
        for kind in ('current','slot','signer','snapshot','terminal','extra','credentials'):
            value=self.copy(self.value);row=value['lineage']['input_lineage'][0]
            if kind=='current':value['current_A_authorization']='VALID_AT_OBSERVATION'
            elif kind=='slot':value['authorization']='REVOKED'
            elif kind=='signer':row['signer']='signer-B'
            elif kind=='snapshot':row['snapshot_authorization']='VALID'
            elif kind=='terminal':row['terminal_authorization']='VALID_AT_OBSERVATION'
            elif kind=='extra':row['random_authorization']='REVOKED'
            else:value['lineage']['original_signer_roles']['signer-A']['password']='PRIVATE'
            with self.subTest(kind=kind),self.assertRaises((ValueError,TypeError)):
                self.check(value)

    def test_log_hash_and_cleanup_type_status_and_claims_refuse(self):
        for mutate in (lambda value:value['commands'][0].update(stdout_sha256='a'*64),
                       lambda value:value['cleanup'].update(private_state_absent=1),
                       lambda value:value.update(native_build='PASS'),lambda value:value.update(status='FAIL'),
                       lambda value:value.update(extra='PRIVATE'),lambda value:value['client_cases'].pop()):
            value=self.copy(self.value);mutate(value)
            with self.assertRaises((ValueError,TypeError)):
                self.check(value)

    def test_parsed_pass_without_guarded_session_return_has_no_export_authority(self):
        with tempfile.TemporaryDirectory() as temporary:
            output=Path(temporary);dev=controller.Development(output,output,output/'cache',{'schema_version':2})
            dev.report['repository_handoff']=self.copy(self.value)
            with self.assertRaisesRegex(ValueError,'phase-return-authority-required'):
                controller.phase_capture(dev,controller.time.monotonic()+30)

    def test_actual_composed_source_constructor_requires_exact_callbacks_and_invocation(self):
        import types,copy,time
        sources=self.fixture.sources;root=self.fixture.root;modules={}
        with patch.dict(sys.modules,{}):
            for name in ('common','packet','captured_composed_controller'):
                path='scripts/ci/development/'+('controller' if name=='captured_composed_controller' else name)+'.py'
                module=types.ModuleType(name);module.__file__=str(root/path);sys.modules[name]=module
                exec(compile(sources.raw[path],module.__file__,'exec'),module.__dict__);modules[name]=module
            parent=modules['captured_composed_controller'];output=self.fixture.output.parent/'proposed-output';cache=output.parent/'proposed-cache'
            packet_model={'schema_version':2,'composition':'repository-svg','source_files':copy.deepcopy(sources.grant['source_files']),
                'metadata_pins':{name:self.sha(sources.raw[name]) for name in modules['packet'].COMPOSED_PINS}}
            grant=copy.deepcopy(sources.grant)
            grant['callbacks']={'existing_consumers':{'path':'scripts/ci/development/controller.py','module':parent.__name__,'qualname':'Development.consume'},
                **{role:{'path':'scripts/ci/development/repository_authority.py','module':'development_repository_authority',
                         'qualname':'RootCallbacks.'+role} for role in ('public_receiver','authority_provider')}}
            grant['original_view']['root']=str(output/'repository-handoff/original-view')
            runtime={'cli_sha256':'b'*64,'endpoint_identity':{'fixture':'NO ACTOR'},'env':{}}
            argv=parent.original_argv(output,cache,packet_model['metadata_pins'])
            grant['initial_invocation_sha256']=self.sha(self.a.encoded({'argv':argv,'output':str(output/'repository-handoff')}))
            actor_raw=self.a.encoded(runtime);grant['actor_contract_sha256']=self.sha(actor_raw)
            raw=self.a.encoded(grant);pin=self.sha(raw)
            env={'GITHUB_SHA':grant['source_commit'],'GITHUB_RUN_ID':grant['run_id'],'GITHUB_RUN_ATTEMPT':grant['run_attempt']}
            with patch.dict(controller.os.environ,env):
                session,callbacks,actual,selected=parent.composed_sources(root,packet_model,raw,pin,actor_raw,output,cache,time.monotonic()+60)
                self.assertEqual(selected,argv);self.assertEqual(actual,runtime);self.assertFalse(session.used)
                self.assertIsNone(session.view_root);self.assertFalse(output.exists());self.assertFalse(cache.exists())
                self.assertIs(callbacks._session,session)
                for name in ('development_repository_handoff','development_repository_authority'):sys.modules.pop(name,None)
                for kind in ('input-hash','source','callback'):
                    changed=copy.deepcopy(grant)
                    if kind=='input-hash':changed['initial_invocation_sha256']='a'*64
                    elif kind=='source':changed['source_files'].pop('scripts/virtual/image_decode_report.py')
                    else:changed['callbacks']['existing_consumers']['qualname']='Development.run'
                    blob=self.a.encoded(changed)
                    with self.subTest(kind=kind),self.assertRaises(ValueError):
                        parent.composed_sources(root,packet_model,blob,self.sha(blob),actor_raw,output,cache,time.monotonic()+60)
                    self.assertFalse(output.exists())

    def test_actual_captured_parent_module_source_guard_and_tamper(self):
        import types
        sources=self.fixture.sources;root=self.fixture.root
        names=('common','packet','base_stages','virtual_stage','captured_parent_controller')
        paths={name:'scripts/ci/development/'+('controller' if name=='captured_parent_controller' else name)+'.py' for name in names}
        loaded={}
        with patch.dict(sys.modules,{}):
            for name in names:
                module=types.ModuleType(name);module.__file__=str(root/paths[name]);sys.modules[name]=module
                exec(compile(sources.raw[paths[name]],module.__file__,'exec'),module.__dict__);loaded[name]=module
            modules={paths[name]:loaded[name] for name in names}
            # No callbacks or actors; this checks the actual captured implementations.
            observation=controller.broad_source_guard(self.fixture.session,modules,self.fixture.deadline)
            self.assertEqual(observation,controller.broad_source_guard(self.fixture.session,modules,self.fixture.deadline))
            with patch.object(loaded['base_stages'],'KSM_PIN','a'*64),self.assertRaises(ValueError):
                controller.broad_source_guard(self.fixture.session,modules,self.fixture.deadline)
            old=loaded['base_stages'].run_ksm
            foreign=types.FunctionType(old.__code__,dict(old.__globals__),old.__name__)
            with patch.object(loaded['base_stages'],'run_ksm',foreign),self.assertRaises(ValueError):
                controller.broad_source_guard(self.fixture.session,modules,self.fixture.deadline)
            missing=types.ModuleType('base_stages')
            with patch.dict(sys.modules,base_stages=missing),self.assertRaises(ValueError):
                controller.broad_source_guard(self.fixture.session,modules,self.fixture.deadline)

    def test_phase_bundle_uses_immutable_bytes_after_origin_changes(self):
        import io,tarfile,time
        files={'result.json':b'captured'};raw=controller.phase_bundle(files,time.monotonic()+30)
        files['result.json']=b'changed'
        with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as archive:
            self.assertEqual(archive.extractfile('phase-public/result.json').read(),b'captured')
        with self.assertRaises(ValueError):controller.phase_bundle(files,time.monotonic()-1)


    def captured_files(self,root):
        files={**self.files,'result.json':self.a.encoded(self.value)}
        descriptor={'path':str(root),'receipt_sha256':self.sha(files['result.json']),
                    'receipt_bytes':len(files['result.json']),
                    'public_files':{name:{'sha256':self.sha(raw),'bytes':len(raw)} for name,raw in files.items()}}
        root.mkdir(mode=0o700)
        for name,raw in files.items():
            path=root/name
            for parent in reversed(path.relative_to(root).parents):
                (root/parent).mkdir(mode=0o700,exist_ok=True)
            path.write_bytes(raw);path.chmod(0o644)
        return files,descriptor

    def test_same_captured_bytes_survive_late_source_mutation_without_reread(self):
        import time,io,tarfile
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)/'phase-public';files,descriptor=self.captured_files(root)
            original=controller.read_regular;changed=[]
            def mutate(path,*args,**kwargs):
                raw=original(path,*args,**kwargs)
                if path.name=='result.json' and not changed:
                    changed.append(True);path.write_bytes(b'{"status":"FAIL","password":"PRIVATE"}')
                return raw
            with patch.object(controller,'read_regular',side_effect=mutate):
                captured=controller.phase_files(root,descriptor,self.modules,time.monotonic()+30)
            self.assertEqual(captured,files);self.assertNotEqual((root/'result.json').read_bytes(),files['result.json'])
            archive=controller.phase_bundle(captured,time.monotonic()+30)
            with tarfile.open(fileobj=io.BytesIO(archive),mode='r:gz') as bundle:
                self.assertEqual(bundle.extractfile('phase-public/result.json').read(),files['result.json'])

    def test_real_mapped_node_extra_type_link_permissions_and_digest_refuse(self):
        import os,time
        for kind in ('extra','symlink','hardlink','fifo','directory-mode','file-mode','bytes','bool-size'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as temp:
                root=Path(temp)/'phase-public';files,descriptor=self.captured_files(root)
                path=root/'logs/000.stdout'
                if kind=='extra':(root/'not-mapped.json').write_bytes(b'{}')
                elif kind=='symlink':path.unlink();path.symlink_to(root/'logs/000.stderr')
                elif kind=='hardlink':path.unlink();os.link(root/'logs/000.stderr',path)
                elif kind=='fifo':path.unlink();os.mkfifo(path)
                elif kind=='directory-mode':(root/'logs').chmod(0o755)
                elif kind=='file-mode':path.chmod(0o600)
                elif kind=='bytes':path.write_bytes(b'changed')
                else:descriptor['public_files']['logs/000.stdout']['bytes']=False
                with self.assertRaises((ValueError,OSError)):
                    controller.phase_files(root,descriptor,self.modules,time.monotonic()+30)

    def test_canonical_raw_json_unknown_fields_and_privacy_have_no_export_fallback(self):
        import time
        for kind in ('noncanonical','escaped-token','unknown-json','private-log','private-armor'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as temp:
                root=Path(temp)/'phase-public';files,descriptor=self.captured_files(root)
                name='result.json'
                if kind=='noncanonical':raw=json.dumps(self.value).encode()
                elif kind=='escaped-token':raw=files[name].replace(b'--passphrase',b'--pass\\u0070hrase')
                elif kind=='unknown-json':name='bundle/base.json';raw=b'{"random_authorization":"REVOKED"}'
                elif kind=='private-log':name='logs/000.stdout';raw=b'Bearer PRIVATE'
                else:name='public-key.gpg';raw=b'-----BEGIN PGP PRIVATE KEY BLOCK-----'
                path=root/name;path.write_bytes(raw);path.chmod(0o644)
                descriptor['public_files'][name]={'sha256':self.sha(raw),'bytes':len(raw)}
                if name=='result.json':descriptor.update(receipt_sha256=self.sha(raw),receipt_bytes=len(raw))
                else:
                    value=self.copy(self.value);value['public_files']={name:row for name,row in descriptor['public_files'].items() if name!='result.json'}
                    if name=='logs/000.stdout':value['commands'][0]['stdout_sha256']=self.sha(raw)
                    result=self.a.encoded(value);(root/'result.json').write_bytes(result)
                    descriptor.update(receipt_sha256=self.sha(result),receipt_bytes=len(result))
                    descriptor['public_files']['result.json']={'sha256':self.sha(result),'bytes':len(result)}
                with self.assertRaises((ValueError,OSError)):
                    controller.phase_files(root,descriptor,self.modules,time.monotonic()+30)

    def test_actual_three_public_certificate_roles_and_archive_map_shape(self):
        self.check()
        self.assertEqual(set(self.value['lineage']['original_signer_roles']),{'signer-A','signer-B','verifier'})
        for kind in ('missing-verifier','foreign-role','malformed-certificate','duplicate-fingerprint','archive-extra','archive-hash','archive-signer','wrong-role-count'):
            value=self.copy(self.value);lineage=value['lineage'];roles=lineage['original_signer_roles']
            if kind=='missing-verifier':roles.pop('verifier')
            elif kind=='foreign-role':roles['unknown']=roles.pop('verifier')
            elif kind=='malformed-certificate':roles['verifier']['certificate']='../foreign'
            elif kind=='duplicate-fingerprint':roles['verifier']['fingerprint']=roles['signer-A']['fingerprint']
            elif kind=='archive-extra':lineage['archives'][0]['extra']='not allowed'
            elif kind=='archive-hash':lineage['archives'][0]['sha256']='a'*64
            elif kind=='archive-signer':lineage['archives'][0]['original_signer']='A'*40
            else:
                row=lineage['input_lineage'][7];row.update(signer='signer-A',fingerprint='A'*40,
                    certificate_sha256=roles['signer-A']['certificate_sha256'],terminal_authorization='REVOKED')
            files={**self.files,'bundle/evidence/lineage.json':self.a.encoded(lineage)}
            descriptor={'public_files':{**self.public,'bundle/evidence/lineage.json':{'bytes':len(files['bundle/evidence/lineage.json']),
                'sha256':self.sha(files['bundle/evidence/lineage.json'])}}}
            value['public_files']=descriptor['public_files']
            with self.subTest(kind=kind),self.assertRaises(ValueError):
                controller.phase_result(value,files,descriptor,self.modules)

    def test_declared_client_rejection_and_checkpoint_shape_must_match_source_plan(self):
        for kind in ('rejection','checkpoint','bool','exit'):
            value=self.copy(self.value)
            if kind=='rejection':value['client_cases'][4]['expected_rejection']='other'
            elif kind=='checkpoint':value['client_cases'][1]['checkpoint_after']=None
            elif kind=='bool':value['client_cases'][0]['command_record']=False
            else:value['client_cases'][4]['command_record']=1
            with self.subTest(kind=kind),self.assertRaises(ValueError):self.check(value)

class EarlyEntryModels(unittest.TestCase):
    """Synthetic clock/domain and inert boundary models; no issuance or native authority."""
    def setUp(self):
        from contextlib import ExitStack
        self.stack=ExitStack();self.addCleanup(self.stack.close)
        self.now=100000.0
        self.stack.enter_context(patch.object(controller.time,'monotonic',side_effect=lambda:self.now))
        self.domain={'clock_id':'CLOCK_MONOTONIC','boot_id':'MODEL','time_namespace_device':1,'time_namespace_inode':2}
        self.stack.enter_context(patch.object(controller,'clock_domain',return_value=self.domain))
        self.fixture=ClockContractTests();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.value=dict(self.fixture.value,issued_monotonic=99800.0,deadline_monotonic=110600.0)
        self.entry=100000.0;self.early=99820.0;self.J=109900.0
        controller.CANCELLED=False

    def clock(self,early=None,value=None,entry=None):
        return controller.workflow_clock(self.fixture.raw(self.value if value is None else value),
            entry=self.entry if entry is None else entry,controller_entry=early)

    def args(self,early=None):
        args=self.fixture.boundary_args();args.controller_entry_monotonic=early
        args.composition=controller.packet.INSTALLER_COMPOSITION
        return args

    def cli(self,mode=None,early=None):
        argv=['--inputs-sha256','a'*64,'--recipes-sha256','b'*64,'--integration-sha256','c'*64,
              '--development-sha256','d'*64,'--cache','/model/cache','--output','/model/output','--check-only']
        if mode is not None:argv+=['--composition',mode]
        if early is not None:argv+=['--controller-entry-monotonic',str(early)]
        return argv

    def test_earlier_entry_shortens_and_endpoints_never_extend_local_cutoff(self):
        local,end=self.clock();self.assertEqual((local,end),(110080.0,110600.0))
        for early,expected in ((self.early,self.J),(99800.0,109880.0),(self.entry,local)):
            with self.subTest(early=early):
                J,workflow_end=self.clock(early);self.assertEqual(J,expected)
                self.assertLessEqual(J,local);self.assertEqual(workflow_end,end)
        late=self.entry+600;self.now=late
        J,end=self.clock(self.early,entry=late);self.assertEqual((J,end),(self.J,110600.0))
        self.assertEqual(self.clock(entry=late)[0],110480.0)

    def test_nonfinite_future_preissuance_bool_int_and_foreign_types_refuse_without_hooks(self):
        hooks=[]
        class ForeignFloat(float):
            def __le__(self,other):hooks.append('le');return True
            def __ge__(self,other):hooks.append('ge');return True
            def __float__(self):hooks.append('float');return 99820.0
        for early in (float('nan'),float('inf'),-float('inf'),self.entry+.01,99799.99,True,False,99820,'99820',ForeignFloat(99820)):
            with self.subTest(kind=type(early).__name__),self.assertRaisesRegex(ValueError,'controller-entry-refused'):
                self.clock(early)
        self.assertEqual(hooks,[])

    def test_domain_and_issuer_binding_precede_early_scalar_validation(self):
        wrong=dict(self.value,clock_domain=dict(self.domain,time_namespace_inode=3))
        with self.assertRaisesRegex(ValueError,'clock-domain-refused'):self.clock(True,value=wrong)
        wrong=dict(self.value,issuer_source_sha256='d'*64)
        with self.assertRaisesRegex(ValueError,'issuer-not-registered'):self.clock(True,value=wrong)
        wrong=dict(self.value,run_id='124')
        with self.assertRaisesRegex(ValueError,'binding-refused'):self.clock(True,value=wrong)

    def test_early_cutoff_equality_refuses_before_source_grant_runtime_or_timer(self):
        self.now=self.J
        with patch.object(controller,'private_input',return_value=self.fixture.raw(self.value)) as capture, \
             patch.object(controller.packet,'preflight_composed') as source, \
             patch.object(controller,'composed_sources') as construction,patch.object(controller.signal,'setitimer') as timer:
            with self.assertRaisesRegex(ValueError,'deadline-exceeded'):
                controller.composed_main(self.args(self.early),{},entry=self.now)
        self.assertEqual(capture.call_count,1);self.assertEqual(capture.call_args.args[2],'DEVELOPMENT_CLOCK')
        source.assert_not_called();construction.assert_not_called();timer.assert_not_called()

    def test_invalid_early_refuses_after_only_clock_capture(self):
        for early in (True,self.entry+1,99799.0,float('inf')):
            with self.subTest(early=early),patch.object(controller,'private_input',return_value=self.fixture.raw(self.value)) as capture, \
                 patch.object(controller.packet,'preflight_composed') as source,patch.object(controller.signal,'signal') as handlers:
                with self.assertRaisesRegex(ValueError,'controller-entry-refused'):
                    controller.composed_main(self.args(early),{},entry=self.entry)
                self.assertEqual(capture.call_count,1);source.assert_not_called();handlers.assert_not_called()

    def test_expired_child_clock_refuses_even_with_valid_earlier_entry(self):
        self.now=self.value['deadline_monotonic']
        with self.assertRaisesRegex(ValueError,'clock-time-refused'):self.clock(self.early,entry=self.now)

    def test_cli_records_child_entry_before_parser_and_delivers_exact_float(self):
        import argparse
        events=[];factory=argparse.ArgumentParser
        def monotonic():events.append('entry');return self.entry
        def parser(*args,**kwargs):events.append('parser');return factory(*args,**kwargs)
        for mode in controller.packet.COMPOSED_MODES:
            with patch.object(controller.time,'monotonic',side_effect=monotonic), \
                 patch.object(controller,'argparse',SimpleNamespace(ArgumentParser=parser)), \
                 patch.object(controller,'composed_main',return_value=7) as dispatch:
                self.assertEqual(controller.main(self.cli(mode,self.early)),7)
            self.assertEqual(dispatch.call_args.kwargs,{'entry':self.entry})
            self.assertIs(type(dispatch.call_args.args[0].controller_entry_monotonic),float)
            self.assertEqual(dispatch.call_args.args[0].controller_entry_monotonic,self.early)
            self.assertEqual(events[-2:],['entry','parser'])
        self.assertEqual(events,['entry','parser']*len(controller.packet.COMPOSED_MODES))

    def test_legacy_explicit_flag_refuses_before_any_packet_read(self):
        for early in (self.early,'nan','inf'):
            with self.subTest(early=early),patch.object(controller.packet,'preflight') as source, \
                 patch.object(controller,'private_input') as private,patch.object(controller,'composed_main') as composed:
                with self.assertRaisesRegex(ValueError,'requires-composition'):controller.main(self.cli(early=early))
                source.assert_not_called();private.assert_not_called();composed.assert_not_called()

    def test_absent_flag_retains_legacy_dispatch_and_composed_local_entry(self):
        with patch.object(controller.packet,'preflight',return_value={'metadata_pins':{'scripts/ci/inputs.lock.json':'a'*64,
             'scripts/ci/recipes.lock.json':'b'*64,'scripts/ci/integration.lock.json':'c'*64}}),patch('builtins.print'):
            self.assertEqual(controller.main(self.cli()),0)
        with patch.object(controller,'composed_main',return_value=7) as dispatch:
            self.assertEqual(controller.main(self.cli(controller.packet.COMPOSITION)),7)
        self.assertIsNone(dispatch.call_args.args[0].controller_entry_monotonic)
        self.assertEqual(self.clock(),(self.entry+10080,110600.0))

    def test_delivery_retains_J_through_all_stages_and_keeps_reserved_publication_tail(self):
        from contextlib import ExitStack
        from unittest.mock import Mock
        with tempfile.TemporaryDirectory() as temporary,ExitStack() as stack:
            root=Path(temporary);checkout=root/'checkout';args=self.args(self.early);args.check_only=False
            args.output=root/'output';args.cache=root/'cache'
            value={'schema_version':2,'composition':args.composition,'metadata_pins':{}}
            runtime={'cli_sha256':'b'*64,'endpoint_identity':{'model':True},'env':{}}
            session=SimpleNamespace(job_deadline=self.J,sources=SimpleNamespace(module=Mock(return_value=SimpleNamespace(bundle=Mock()))))
            callbacks=object();argv=['MODEL'];dev=Mock();dev.report={};captures=[];cutoffs=[]
            def capture(path,pin,kind,limit):
                captures.append(kind)
                return self.fixture.raw(self.value) if kind=='DEVELOPMENT_CLOCK' else b'MODEL'
            stack.enter_context(patch.object(controller,'ROOT',checkout));stack.enter_context(patch.object(controller.Path,'cwd',return_value=checkout))
            stack.enter_context(patch.object(controller,'private_input',side_effect=capture))
            preflight=stack.enter_context(patch.object(controller.packet,'preflight_composed',return_value=value))
            sources=stack.enter_context(patch.object(controller,'composed_sources',return_value=(session,callbacks,runtime,argv)))
            construct=stack.enter_context(patch.object(controller,'Development',return_value=dev))
            stack.enter_context(patch.object(controller.signal,'getitimer',return_value=(0.0,0.0)))
            stack.enter_context(patch.object(controller.signal,'signal'));timers=stack.enter_context(patch.object(controller.signal,'setitimer'))
            stack.enter_context(patch.object(controller,'close_boundary',return_value=False));stack.enter_context(patch.object(controller,'retire_installer_module',return_value=True))
            original=controller.within
            stack.enter_context(patch.object(controller,'within',side_effect=lambda J:(cutoffs.append(J),original(J))[1]))
            publish=stack.enter_context(patch.object(controller,'publish',return_value=False))
            self.assertEqual(controller.composed_main(args,{},entry=self.entry),1)
            self.assertEqual(captures,['DEVELOPMENT_CLOCK','DEVELOPMENT_EXECUTION_GRANT','DEVELOPMENT_RUNTIME_CONTRACT'])
            self.assertEqual(sources.call_args.args[-1],self.J);self.assertEqual(construct.call_args.kwargs['deadline'],self.J)
            self.assertEqual(construct.call_args.kwargs['clock_nonce'],self.value['nonce'])
            self.assertIs(construct.call_args.kwargs['runtime_contract'],runtime)
            dev.run_composed.assert_called_once_with(session,callbacks,runtime,argv)
            self.assertEqual(preflight.call_args.kwargs,{'composition':args.composition})
            self.assertEqual(cutoffs[:-2],[self.J]*len(cutoffs[:-2]));self.assertEqual(cutoffs[-2:],[self.entry+120]*2)
            self.assertEqual(dev.publication_deadline,self.entry+120)
            self.assertEqual(timers.call_args_list[0].args,(controller.signal.ITIMER_REAL,self.J-self.entry))
            self.assertEqual(timers.call_args_list[-1].args,(controller.signal.ITIMER_REAL,120.0));publish.assert_called_once()

    def test_J_does_not_renew_across_repeated_clock_validation(self):
        expected=self.clock(self.early)
        self.now+=500
        self.assertEqual(self.clock(self.early,entry=self.entry+500),expected)

    def test_cli_boolean_spelling_fails_parser_before_private_or_source(self):
        with patch.object(controller,'private_input') as private,patch.object(controller.packet,'preflight_composed') as source, \
             patch('sys.stderr'),self.assertRaises(SystemExit):
            controller.main(self.cli(controller.packet.INSTALLER_COMPOSITION,'true'))
        private.assert_not_called();source.assert_not_called()

class DownloadDiagnosticSdkTests(unittest.TestCase):
    """Real captured SDK/driver guards; no HTTP, signals, native actor or guard patch."""
    @classmethod
    def setUpClass(cls):
        import test_repository_handoff
        class Graph(test_repository_handoff.CapturedGraphFixtures):
            ADDITIONAL_SOURCES = ('scripts/ci/development/p0_ci.py',
                'scripts/ci/root-administration/p0_launch.py')
        cls.fixture=Graph;Graph.setUpClass();cls.addClassCleanup(Graph.doClassCleanups)
        cls.sdk=Graph.a
        cls.driver=Graph.sources.module('development_p0_ci','scripts/ci/development/p0_ci.py')
        cls.launcher=Graph.sources.module('maintained_download_launcher','scripts/ci/root-administration/p0_launch.py')
        registry=patch.dict(sys.modules,{cls.driver.__name__:cls.driver,cls.launcher.__name__:cls.launcher})
        registry.start();cls.addClassCleanup(registry.stop)

    def setUp(self):
        import copy
        f=self.fixture;grant=copy.deepcopy(f.grant)
        grant['purpose']='reviewed-installer-P0-preparation'
        grant['callbacks']['existing_consumers']={'path':'scripts/ci/development/p0_ci.py',
            'module':self.driver.__name__,'qualname':'Preparation.prepare'}
        self.sources=self.sdk.Sources(f.root,grant,f.deadline)
        self.owner=self.driver.Preparation(self.sources,self.sdk,SimpleNamespace(PREP_QUARANTINE=[]),
            SimpleNamespace(),{'nonce':'maintained-fixture','url_overrides':{},'cache_mode':'selected-HTTPS'},
            {},f.output,f.output/'cache',f.deadline,f.deadline+90,{})
        self.owner.current_inputs_raw=self.driver.current_inputs(self.sources.raw['scripts/ci/inputs.lock.json'])
        value=self.driver.decode(self.owner.current_inputs_raw)
        self.items=list(value['keyring_files'])
        for item in (value['rootfs'],*value['packages']):
            self.items.extend((item,{'filename':item['filename']+'.sig','size':item['signature_size'],
                'sha256':item['signature_sha256'],'url':item['url']+'.sig'}))
        self.owner.bind_download_rows(self.items)
        self.assertEqual(len(self.owner.download_rows),501)
        self.driver._DOWNLOAD_LATCH=None
        self.addCleanup(setattr,self.driver,'_DOWNLOAD_LATCH',None)

    def prepare_admission(self, *, system='Linux', machine='aarch64', acquisition_error=None):
        """Actual prepare admission; inert owner/FS adapters stop before any tool actor."""
        import ast
        from types import MethodType
        inputs=self.driver.decode(self.owner.current_inputs_raw)
        events=[];captured=[];stop=RuntimeError('inert tool-constructor boundary')
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        out=Path(temporary.name);out.chmod(0o700)
        owner=SimpleNamespace(sources=SimpleNamespace(raw=self.sources.raw),deadline=self.owner.deadline,
            plan={'inputs':inputs,'current_inputs_raw':self.owner.current_inputs_raw,
                  'input_successor':dict(self.driver.INPUT_SUCCESSOR)},out=out,cache=out/'cache',
            runtime={'docker':{}},cli=None,gpg_file=None,current_inputs_raw=None)
        def callback(name,method,deadline):
            self.assertEqual(name,'existing_consumers');self.assertIs(method.__func__,self.driver.Preparation.prepare)
            self.assertEqual(deadline,owner.deadline);events.append('callback')
        def cached(items,cache):
            self.assertIs(cache,owner.cache);self.assertIsNone(owner.cli);self.assertIsNone(owner.gpg_file)
            events.append('cached');captured.extend(items)
            if acquisition_error is not None:raise acquisition_error
        def tool(**kwargs):
            events.append('tool-boundary');self.assertEqual(set(kwargs),{'create_validator'})
            raise stop
        tree=ast.parse(Path(__file__).with_name('p0_native_arm.py').read_bytes())
        signature=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='signature_item')
        self.assertFalse(any(isinstance(node,(ast.Call,ast.Import,ast.ImportFrom)) for node in ast.walk(signature)))
        native={}
        exec(compile(ast.Module([signature],type_ignores=[]),'<pure-native-signature-data>','exec'),native)
        owner.sources.callback=callback
        owner.prepare=MethodType(self.driver.Preparation.prepare,owner)
        owner.guard=lambda:events.append('guard')
        owner.seed_four=lambda:events.append('seed')
        owner.cached=cached
        owner.native=SimpleNamespace(signature_item=native['signature_item'])
        owner.transport=SimpleNamespace(DockerTransport=tool,
            read_file=lambda *a,**k:self.fail('GPG tool was opened before boundary'))
        def write(path,raw,deadline):
            self.assertEqual(path,out/'inputs.lock.json');self.assertEqual(raw,self.owner.current_inputs_raw)
            self.assertEqual(deadline,owner.deadline);events.append('write-inputs')
        def read(path,deadline,**kwargs):
            self.assertEqual(path,out/'inputs.lock.json');self.assertTrue(kwargs['private'])
            self.assertEqual(deadline,owner.deadline);events.append('read-inputs');return self.owner.current_inputs_raw
        with patch.object(self.driver,'write_private',side_effect=write), \
             patch.object(self.driver,'read',side_effect=read), \
             patch.object(self.driver.os,'uname',return_value=SimpleNamespace(sysname=system,machine=machine)):
            try:owner.prepare()
            except BaseException as error:caught=error
            else:self.fail('inert constructor boundary not reached')
        return owner,captured,events,caught,stop

    def test_prepare_acquires_exact_current_rows_before_tool_construction(self):
        owner,items,events,caught,stop=self.prepare_admission()
        self.assertIs(caught,stop);self.assertEqual(items,self.items);self.assertEqual(len(items),501)
        self.assertEqual(len({item['filename'] for item in items}),501)
        self.assertIs(items[3],owner.plan['inputs']['rootfs'])
        for i,item in enumerate(owner.plan['inputs']['packages']):self.assertIs(items[5+2*i],item)
        self.assertEqual(events,['callback','guard','write-inputs','read-inputs','guard','seed','cached','tool-boundary'])
        self.assertIsNone(owner.cli);self.assertIsNone(owner.gpg_file)

    def test_prepare_wrong_platform_refuses_before_acquisition_and_tools(self):
        for system,machine in (('Darwin','aarch64'),('Linux','x86_64'),('Linux','arm64')):
            with self.subTest(system=system,machine=machine):
                owner,items,events,caught,stop=self.prepare_admission(system=system,machine=machine)
                self.assertIs(type(caught),ValueError);self.assertEqual(caught.args,('prep-host-ARM',))
                self.assertEqual(items,[]);self.assertNotIn('cached',events);self.assertNotIn('tool-boundary',events)
                self.assertIsNone(owner.cli);self.assertIsNone(owner.gpg_file)

    def test_prepare_acquisition_preserves_exact_primary_cause_and_cancel_flags(self):
        for first in (ValueError('PRIVATE ACQUISITION'),KeyboardInterrupt('prep-original-end')):
            with self.subTest(kind=type(first)):
                prior=RuntimeError('PRIOR');first.__cause__=prior
                first.native_preflight_cancelled=True;first.native_preflight_cleanup_uncertain=True
                owner,items,events,caught,stop=self.prepare_admission(acquisition_error=first)
                self.assertIs(caught,first);self.assertIs(first.__cause__,prior)
                self.assertTrue(first.native_preflight_cancelled);self.assertTrue(first.native_preflight_cleanup_uncertain)
                self.assertEqual(items,self.items);self.assertNotIn('tool-boundary',events)
                self.assertIsNone(owner.cli);self.assertIsNone(owner.gpg_file)

    def capture(self,error,ordinal=0,sample=None):
        with patch.object(self.driver.time,'monotonic',return_value=self.owner.deadline-1 if sample is None else sample):
            self.owner.capture_download(error,ordinal,self.items[ordinal])
        self.driver.mark_pipeline_failure(error,'download-input')
        self.driver.latch_download(self.owner,error)
        return self.driver.download_diagnostic(error)

    def compatibility(self):
        self.owner.guard()  # Actual Preparation.guard -> actual Sources.guard.
        self.sources.class_state(self.owner,'scripts/ci/development/p0_ci.py',self.driver)
        self.sources.callback('existing_consumers',self.owner.prepare,self.owner.deadline)
        self.sources.graph_namespace(self.driver,'scripts/ci/development/p0_ci.py',
            {'scripts/ci/development/p0_ci.py':self.driver},{},{})
        f=self.fixture
        with patch.dict(self.driver.os.environ,GITHUB_SHA=f.grant['source_commit'],GITHUB_RUN_ID='123',GITHUB_RUN_ATTEMPT='2'):
            self.sdk.authority_state(f.sources,f.callback.public_receiver,f.deadline)

    def test_real_sdk_callback_namespace_and_authority_routes_accept_lifecycle(self):
        self.compatibility()
        first=KeyboardInterrupt('PRIVATE NOT PUBLIC')
        self.owner.alarm_interrupt=first
        with patch.object(self.driver.time,'monotonic',return_value=self.owner.deadline):
            self.owner.capture_download(first,0,self.items[0])
        self.driver.mark_pipeline_failure(first,'download-input')
        self.compatibility()  # Live declared slots may retain BaseException.
        self.driver.latch_download(self.owner,first)
        self.compatibility()  # Module latch does not pollute issuer state.
        result=self.driver.download_diagnostic(first)
        self.assertEqual(result['refusal_code'],'DL_KBI_AFTER_PREP_ALRM')
        self.assertEqual(set(result),{'schema_version','stage','operation','exception_type','refusal_code'})
        self.assertNotIn('PRIVATE',json.dumps(result));self.assertIsNone(self.driver.download_diagnostic(first))
        self.compatibility()

    def test_real_sdk_still_rejects_foreign_callback_code_defaults_and_state(self):
        import types
        callback=self.owner.prepare
        foreign=types.FunctionType(callback.__func__.__code__,dict(callback.__func__.__globals__),callback.__func__.__name__)
        foreign.__qualname__=callback.__func__.__qualname__
        with self.assertRaises(self.sdk.Refused):
            self.sources.callback('existing_consumers',types.MethodType(foreign,self.owner),self.owner.deadline)
        original=self.driver.Preparation.fetch.__kwdefaults__
        try:
            self.driver.Preparation.fetch.__kwdefaults__={'ordinal':0}
            with self.assertRaises(self.sdk.Refused):
                self.sources.class_state(self.owner,'scripts/ci/development/p0_ci.py',self.driver)
        finally:self.driver.Preparation.fetch.__kwdefaults__=original
        self.owner.injected=KeyboardInterrupt()
        with self.assertRaises(self.sdk.Refused):self.sources.class_state(self.owner,'scripts/ci/development/p0_ci.py',self.driver)
        del self.owner.injected
        self.compatibility()

    def test_real_authority_state_does_not_gain_BaseException_exemption(self):
        f=self.fixture;callback=f.callback
        descriptor=vars(type(callback))['_failure'];old=descriptor.__get__(callback,type(callback))
        try:
            descriptor.__set__(callback,KeyboardInterrupt('PRIVATE'))
            with patch.dict(self.driver.os.environ,GITHUB_SHA=f.grant['source_commit'],GITHUB_RUN_ID='123',GITHUB_RUN_ATTEMPT='2'):
                with self.assertRaises(self.sdk.Refused):self.sdk.authority_state(f.sources,callback.public_receiver,f.deadline)
        finally:descriptor.__set__(callback,old)
        self.compatibility()

    def test_canonical_current501_identity_and_mixed_inputs_refuse(self):
        import copy
        for kind in ('historical','ordinal-bool','ordinal-range','equal-row','swapped-rows','field-drift','tuple-replacement'):
            with self.subTest(kind=kind):
                self.owner.download_failure=None;self.driver._DOWNLOAD_LATCH=None
                ordinal=0;item=self.items[0]
                if kind=='historical':
                    self.owner.current_inputs_raw=self.sources.raw['scripts/ci/inputs.lock.json'];self.owner.bind_download_rows(self.items)
                elif kind=='ordinal-bool':ordinal=True
                elif kind=='ordinal-range':ordinal=501
                elif kind=='equal-row':item=copy.deepcopy(item)
                elif kind=='swapped-rows':
                    changed=list(self.items);changed[:2]=reversed(changed[:2]);self.owner.bind_download_rows(changed)
                elif kind=='field-drift':item['url']+='?drift'
                else:self.owner.download_rows=tuple(list(self.owner.download_rows))
                error=ValueError('PRIVATE');self.owner.capture_download(error,ordinal,item)
                self.driver.mark_pipeline_failure(error,'download-input');self.driver.latch_download(self.owner,error)
                self.assertIsNone(self.driver.download_diagnostic(error))
                if kind=='field-drift':item['url']=item['url'].removesuffix('?drift')
                self.owner.current_inputs_raw=self.driver.current_inputs(self.sources.raw['scripts/ci/inputs.lock.json'])
                self.owner.bind_download_rows(self.items)

    def test_first_primary_and_cancel_cleanup_do_not_replace_projection(self):
        first=ValueError('PRIVATE FIRST');second=KeyboardInterrupt('PRIVATE LATER')
        prior=RuntimeError('PRIVATE PRIOR CAUSE');first.__cause__=prior
        self.owner.capture_download(first,0,self.items[0]);self.owner.capture_download(second,1,self.items[1])
        self.assertIs(self.owner.download_failure[0],first)
        self.assertIs(self.driver.merge(first,second),first)
        self.driver.mark_pipeline_failure(first,'download-input');self.driver.latch_download(self.owner,second)
        self.assertIsNone(self.driver.download_diagnostic(second))
        self.driver.latch_download(self.owner,first);result=self.driver.download_diagnostic(first)
        self.assertEqual(result['operation'],self.driver.DOWNLOAD_PREFIX+'000')
        self.assertEqual(result['refusal_code'],'DL_VALUEERROR')
        self.assertTrue(first.native_preflight_cancelled);self.assertTrue(first.native_preflight_cleanup_uncertain)
        self.assertIs(first.__cause__,prior);self.assertEqual(first.args,('PRIVATE FIRST',))

    def test_alarm_requires_exact_exception_identity_and_clock_is_bounded(self):
        for sample,label in ((self.owner.deadline-1,'BEFORE'),(self.owner.deadline,'AFTER'),(10**10000,'UNKNOWN'),
                             (float('nan'),'UNKNOWN'),(True,'UNKNOWN')):
            for own in (False,True):
                with self.subTest(label=label,own=own):
                    self.owner.download_failure=None;error=KeyboardInterrupt('prep-original-end')
                    self.owner.alarm_interrupt=error if own else KeyboardInterrupt('prep-original-end')
                    result=self.capture(error,sample=sample)
                    self.assertEqual(result['refusal_code'],'DL_KBI_'+label+('_PREP_ALRM' if own else '_UNATTRIBUTED'))

    def test_actual_alarm_handler_binds_exception_identity_without_real_signal(self):
        import ast,inspect
        pipeline=ast.parse(inspect.getsource(self.driver.pipeline)).body[0]
        expired=next(n for n in ast.walk(pipeline) if isinstance(n,ast.FunctionDef) and n.name=='expired')
        wrapper=ast.FunctionDef(name='factory',args=ast.arguments(posonlyargs=[],args=[ast.arg(arg='owner')],
            kwonlyargs=[],kw_defaults=[],defaults=[]),body=[expired,ast.Return(value=ast.Name(id='expired',ctx=ast.Load()))],decorator_list=[])
        scope={};exec(compile(ast.fix_missing_locations(ast.Module(body=[wrapper],type_ignores=[])),
            self.driver.__file__,'exec'),scope)
        handler=scope['factory'](self.owner)
        with self.assertRaises(KeyboardInterrupt) as caught:handler(None,None)
        self.assertIs(self.owner.alarm_interrupt,caught.exception)
        self.assertEqual(self.capture(caught.exception)['refusal_code'],'DL_KBI_BEFORE_PREP_ALRM')
        self.owner.download_failure=None
        different=KeyboardInterrupt(*caught.exception.args)
        self.assertEqual(self.capture(different)['refusal_code'],'DL_KBI_BEFORE_UNATTRIBUTED')

    def test_clock_failure_cannot_replace_first_or_leak_raw_context(self):
        first=KeyboardInterrupt('PRIVATE');secondary=KeyboardInterrupt('PRIVATE CLOCK')
        with patch.object(self.driver.time,'monotonic',side_effect=secondary):self.owner.capture_download(first,0,self.items[0])
        self.driver.mark_pipeline_failure(first,'download-input');self.driver.latch_download(self.owner,first)
        result=self.driver.download_diagnostic(first)
        self.assertTrue(first.native_preflight_cancelled);self.assertTrue(first.native_preflight_cleanup_uncertain)
        self.assertIsNotNone(result)
        self.assertEqual(result['refusal_code'],'DL_KBI_UNKNOWN_UNATTRIBUTED')
        self.assertNotIn('PRIVATE',json.dumps(result))

    def test_exact_HTTP_status_storage_types_and_subclasses_stay_closed(self):
        import urllib.error
        class Hostile:
            def __str__(self):raise AssertionError('foreign string conversion')
            def __eq__(self,other):raise AssertionError('foreign equality')
        class ForeignHTTP(urllib.error.HTTPError):
            def __getattribute__(self,name):
                if name in ('code','__dict__','args'):raise AssertionError('foreign getter')
                return super().__getattribute__(name)
        for status,label in ((404,'DL_HTTP_404'),(599,'DL_HTTP_OTHER'),(True,'DL_HTTP_UNKNOWN'),
                             ('404','DL_HTTP_UNKNOWN'),(Hostile(),'DL_HTTP_UNKNOWN')):
            with self.subTest(kind=type(status).__name__):
                self.owner.download_failure=None
                error=urllib.error.HTTPError.__new__(urllib.error.HTTPError)
                BaseException.__init__(error,'PRIVATE')
                BaseException.__dict__['__dict__'].__get__(error)['code']=status
                result=self.capture(error);self.assertEqual(result['refusal_code'],label)
                self.assertNotIn('PRIVATE',json.dumps(result))
        self.owner.download_failure=None
        error=ForeignHTTP.__new__(ForeignHTTP);BaseException.__init__(error,'PRIVATE')
        result=self.capture(error);self.assertEqual(result['refusal_code'],'DL_OTHER')

    def test_hostile_exception_metaclass_and_forged_context_do_not_gain_origin(self):
        class Meta(type):
            def __eq__(cls,other):raise AssertionError('foreign metaclass equality')
        class Foreign(ValueError,metaclass=Meta):pass
        first=Foreign('PRIVATE');self.assertEqual(self.capture(first)['refusal_code'],'DL_OTHER')
        first=ValueError('PRIVATE');first.nativeci_pipeline_operation='download-input'
        first.nativeci_diagnostic={'schema_version':1,'stage':'pipeline','operation':self.driver.DOWNLOAD_PREFIX+'000',
            'exception_type':'ValueError','refusal_code':'DL_VALUEERROR'}
        fake=SimpleNamespace(download_failure=(first,0,(self.driver.DOWNLOAD_PREFIX+'000','DL_VALUEERROR')))
        self.driver.latch_download(fake,first);self.assertIsNone(self.driver.download_diagnostic(first))
        self.owner.download_failure=(ValueError('DIFFERENT PRIMARY'),0,(self.driver.DOWNLOAD_PREFIX+'000','DL_VALUEERROR'))
        self.driver.latch_download(self.owner,first);self.assertIsNone(self.driver.download_diagnostic(first))

    def inert_fetch(self,*,read_error=None,close_error=None,eof_expiry=False,success=False,rename_error=None):
        """Actual fetch + actual SDK guards; only HTTP, partial FS and body hash are models."""
        import stat
        item=self.items[0];size=item['size'];clock={'now':self.owner.deadline-10}
        class PathModel:
            name='fixture-target'
            def with_name(path,name):return path
            def exists(path):return False
            def is_symlink(path):return False
            def lstat(path):return node()
            def rename(path,target):
                renamed.append(target)
                if rename_error is not None:raise rename_error
                if not success:raise AssertionError('no target publication expected')
        written=bytearray();closed=[];renamed=[];counts={'Preparation.guard':0,'Sources.guard':0}
        def node(fd=10):
            return SimpleNamespace(st_dev=1,st_ino=fd,st_mode=stat.S_IFREG|0o600,st_uid=1000,st_gid=1000,
                st_nlink=1,st_size=len(written) if fd==10 else 0,st_mtime_ns=1,st_ctime_ns=1)
        def write(fd,value):written.extend(value);return len(value)
        partial_os=SimpleNamespace(O_WRONLY=1,O_CREAT=2,O_EXCL=4,O_NOFOLLOW=8,O_CLOEXEC=16,
            open=lambda *a:10,fstat=node,geteuid=lambda:1000,write=write,close=lambda fd:closed.append(fd))
        class Response:
            url='https://fixture.invalid/input'
            def __init__(response):response.count=0;response.done=False
            def fileno(response):return 20
            def isclosed(response):return response.done
            def close(response):
                if close_error is not None:raise close_error
                response.done=True
            def read(response,quota):
                self.assertEqual(quota,65536)
                if read_error is not None:raise read_error
                response.count+=1
                if response.count==1:return b'x'*size
                if eof_expiry:clock['now']=self.owner.deadline
                response.done=True;return b''
        response=Response()
        class Digest:
            def update(digest,value):pass
            def hexdigest(digest):return item['sha256']
        # No real package bytes are accepted: this hash adapter solely reaches
        # the post-EOF boundary while retaining canonical current row identity.
        code_names={self.owner.guard.__func__.__code__:'Preparation.guard',self.sources.guard.__func__.__code__:'Sources.guard'}
        def profile(frame,event,arg):
            if event=='call' and frame.f_code in code_names:counts[code_names[frame.f_code]]+=1
        prior_profile=sys.getprofile();caught=None
        try:
            sys.setprofile(profile)
            with patch.dict(self.driver.__dict__,os=partial_os,hashlib=SimpleNamespace(sha256=Digest)), \
                 patch.object(self.driver.urllib.request,'build_opener',return_value=SimpleNamespace(open=lambda *a,**k:response)), \
                 patch.object(self.driver.time,'monotonic',side_effect=lambda:clock['now']):
                if success:self.owner.fetch(item,PathModel(),ordinal=0)
                else:
                    with self.assertRaises(BaseException) as result:self.owner.fetch(item,PathModel(),ordinal=0)
                    caught=result.exception
        finally:sys.setprofile(prior_profile)
        self.fetch_trace={'rename_count':len(renamed),'counts':counts,'bytes_written':len(written),'body_reads':response.count}
        return caught,closed,response

    def test_actual_fetch_real_sdk_success_retires_once_without_diagnostic(self):
        caught,closed,response=self.inert_fetch(success=True)
        self.assertIsNone(caught);self.assertEqual(closed,[10]);self.assertTrue(response.done)
        self.assertEqual(self.fetch_trace,{'rename_count':1,'counts':{'Preparation.guard':7,'Sources.guard':7},
            'bytes_written':self.items[0]['size'],'body_reads':2})
        self.assertIsNone(self.owner.download_failure);self.assertIsNone(self.driver._DOWNLOAD_LATCH)
        self.compatibility()

    def test_actual_fetch_real_sdk_EOF_expiry_is_attributed_without_publication(self):
        first,closed,response=self.inert_fetch(eof_expiry=True)
        self.assertEqual(first.args,('p0-original-end',));self.assertEqual(closed,[10]);self.assertTrue(response.done)
        self.assertIs(self.owner.download_failure[0],first)
        self.driver.latch_download(self.owner,first);value=self.driver.download_diagnostic(first)
        self.assertEqual(value['operation'],self.driver.DOWNLOAD_PREFIX+'000')
        self.assertEqual(value['refusal_code'],'DL_VALUEERROR')
        self.compatibility()

    def test_actual_fetch_real_sdk_preserves_body_first_over_cleanup_cancel(self):
        first=ValueError('PRIVATE BODY');secondary=KeyboardInterrupt('PRIVATE CLEANUP')
        caught,closed,response=self.inert_fetch(read_error=first,close_error=secondary)
        self.assertIs(caught,first);self.assertIs(self.owner.download_failure[0],first);self.assertEqual(closed,[10])
        self.assertTrue(first.native_preflight_cancelled);self.assertTrue(first.native_preflight_cleanup_uncertain)
        self.assertIn(response,self.owner.retained)
        self.driver.latch_download(self.owner,first);value=self.driver.download_diagnostic(first)
        self.assertEqual(value['refusal_code'],'DL_VALUEERROR');self.assertNotIn('PRIVATE',json.dumps(value))
        # Real SDK validation remains meaningful after quarantine is cleared
        # only in this isolated fixture; production's retention stays asserted.
        self.assertIn(self.owner,self.driver.PREPARATION_QUARANTINE)
        self.sources.class_state(self.owner,'scripts/ci/development/p0_ci.py',self.driver)
        self.sources.callback('existing_consumers',self.owner.prepare,self.owner.deadline)
        self.driver.PREPARATION_QUARANTINE.remove(self.owner)

    def test_whole_fetch_prevalidation_and_rename_edge_are_attributed(self):
        # Fixed retained inputs refuse before any HTTP/FD model is entered.
        ordinal=next(i for i,item in enumerate(self.items) if item['filename'] in self.driver.OVERRIDE_ROWS)
        with self.assertRaisesRegex(ValueError,'prep-fixed-four-no-HTTPS-fallback') as caught:
            self.owner.fetch(self.items[ordinal],SimpleNamespace(),ordinal=ordinal)
        self.driver.latch_download(self.owner,caught.exception)
        self.assertEqual(self.driver.download_diagnostic(caught.exception)['refusal_code'],'prep-fixed-four-no-HTTPS-fallback')
        self.owner.download_failure=None
        first=OSError('PRIVATE RENAME');caught,closed,response=self.inert_fetch(rename_error=first)
        self.assertIs(caught,first);self.assertEqual(closed,[10]);self.assertTrue(response.done)
        self.assertEqual(self.fetch_trace['rename_count'],1);self.assertTrue(first.native_preflight_cleanup_uncertain)
        self.driver.latch_download(self.owner,first)
        self.assertEqual(self.driver.download_diagnostic(first)['refusal_code'],'DL_OSERROR')

    def test_launcher_authenticates_same_primary_projection_and_outer_context(self):
        first=ValueError('PRIVATE');self.owner.capture_download(first,0,self.items[0])
        self.driver.mark_pipeline_failure(first,'download-input');self.driver.latch_download(self.owner,first)
        accessor=self.launcher.capture_download_accessor(self.driver);self.assertIsNotNone(accessor)
        accepted=[]
        result=self.launcher.attach_diagnostic(first,'pipeline','run-pipeline','pipeline',
            driver_accessor=accessor,accepted_context=accepted)
        self.assertEqual(result['operation'],self.driver.DOWNLOAD_PREFIX+'000');self.assertEqual(len(accepted),1)
        first.__dict__['nativeci_diagnostic']={'FOREIGN':'PRIVATE'}
        outer=self.launcher.attach_diagnostic(first,'entry','validate-entry','launcher',accepted_context=accepted)
        self.assertEqual(outer,result);self.assertIsNot(outer,result)
        other=ValueError('PRIVATE');self.launcher.attach_diagnostic(other,'entry','validate-entry','launcher',accepted_context=accepted)
        self.assertNotIn(other.nativeci_diagnostic['operation'],self.launcher.DOWNLOAD_OPERATIONS)

    def test_launcher_foreign_indexed_attrs_and_wrong_crossfields_fall_back(self):
        valid={'schema_version':1,'stage':'pipeline','operation':self.driver.DOWNLOAD_PREFIX+'000',
            'exception_type':'ValueError','refusal_code':'DL_VALUEERROR'}
        first=ValueError('PRIVATE');first.nativeci_diagnostic=dict(valid)
        self.launcher.attach_diagnostic(first,'pipeline','run-pipeline','pipeline')
        self.assertEqual(first.nativeci_diagnostic['operation'],'run-pipeline')
        for mutate in (lambda x:x.update(schema_version=True),lambda x:x.update(operation=self.driver.DOWNLOAD_PREFIX+'501'),
                       lambda x:x.update(exception_type='OSError'),lambda x:x.update(extra='PRIVATE'),
                       lambda x:x.update(stage='entry')):
            changed=dict(valid);mutate(changed);self.assertIsNone(self.launcher.validate_diagnostic(changed))
        self.assertEqual(self.launcher.validate_diagnostic(valid),valid)

    def test_launcher_accessor_replacement_code_and_signature_mutation_refuse(self):
        import types
        function=self.driver.download_diagnostic;accessor=self.launcher.capture_download_accessor(self.driver)
        code=function.__code__;defaults=function.__defaults__;qualname=function.__qualname__
        for kind in ('replacement','code','defaults','qualname'):
            with self.subTest(kind=kind):
                try:
                    if kind=='replacement':self.driver.download_diagnostic=types.FunctionType(code,dict(function.__globals__),function.__name__)
                    elif kind=='code':function.__code__=code.replace(co_name='foreign')
                    elif kind=='defaults':function.__defaults__=(None,)
                    else:function.__qualname__='foreign'
                    first=ValueError('PRIVATE');first.nativeci_pipeline_operation='download-input'
                    self.launcher.attach_diagnostic(first,'pipeline','run-pipeline','pipeline',driver_accessor=accessor)
                    self.assertEqual(first.nativeci_diagnostic['operation'],'download-input')
                finally:
                    self.driver.download_diagnostic=function;function.__code__=code;function.__defaults__=defaults;function.__qualname__=qualname

    def test_launcher_legacy_SDK_specificity_wins_and_original_args_set_is_460(self):
        first=ValueError('PRIVATE');self.driver.attach_sdk_preflight(first,'preparation-sdk-preflight')
        old=dict(first.nativeci_diagnostic)
        self.launcher.attach_diagnostic(first,'pipeline','run-pipeline','pipeline',
            driver_accessor=self.launcher.capture_download_accessor(self.driver))
        self.assertEqual(first.nativeci_diagnostic,old)
        self.assertEqual(len(self.launcher.LEGACY_DIAGNOSTIC_CODES),460)
        indexed=ValueError('DL_HTTP_404')
        self.assertEqual(self.launcher.diagnostic(indexed,'pipeline','download-input','pipeline')['refusal_code'],'UNKNOWN')

    def test_launcher_optional_collector_interrupt_keeps_primary_and_sticky_flags(self):
        class InterruptingTable(dict):
            def __getitem__(self,key):raise KeyboardInterrupt('PRIVATE COLLECTOR')
        first=ValueError('PRIVATE PRIMARY');self.owner.capture_download(first,0,self.items[0])
        self.driver.mark_pipeline_failure(first,'download-input');self.driver.latch_download(self.owner,first)
        accessor=self.launcher.capture_download_accessor(self.driver)
        # Fault injection into the optional collector, never SDK admission.
        with patch.dict(self.driver.__dict__,DOWNLOAD_TYPES=InterruptingTable(self.driver.DOWNLOAD_TYPES)):
            self.launcher.attach_diagnostic(first,'pipeline','run-pipeline','pipeline',driver_accessor=accessor)
        self.assertTrue(first.native_preflight_cancelled);self.assertTrue(first.native_preflight_cleanup_uncertain)
        self.assertEqual(first.args,('PRIVATE PRIMARY',));self.assertEqual(first.nativeci_diagnostic['operation'],'download-input')
        self.assertNotIn('PRIVATE',json.dumps(first.nativeci_diagnostic))

    def test_launcher_pipeline_invocation_keeps_original_eight_arguments(self):
        import ast,inspect
        tree=ast.parse(inspect.getsource(self.launcher._run))
        assignments=[n for n in ast.walk(tree) if isinstance(n,ast.Assign)]
        binding=next(n.value for n in assignments if any(isinstance(t,ast.Name) and t.id=='pipeline_arguments' for t in n.targets))
        self.assertEqual([ast.literal_eval(k) for k in binding.keys],['entry','outer_end','expected_source_commit','source_root',
            'work_root','cache','prep_template_raw','prep_template_sha256'])
        call=next(n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='pipeline_callable')
        self.assertFalse(call.args);self.assertEqual([(k.arg,ast.dump(k.value)) for k in call.keywords],[(None,"Name(id='pipeline_arguments', ctx=Load())")])

    def test_workflow_selected_validator_and_launcher_sets_conform(self):
        import ast
        path=Path(__file__).resolve().parents[3]/'.github/workflows/native-arm-p0.yml'
        text=path.read_text();lines=text.splitlines()
        start=next(i for i,line in enumerate(lines) if line.strip()=='run: |')+1
        tree=ast.parse('\n'.join(line[10:] for line in lines[start:]))
        names={'DIAGNOSTIC_STAGES','DIAGNOSTIC_CODES','DIAGNOSTIC_TYPES','DOWNLOAD_OPERATIONS','DOWNLOAD_CODE_TYPES',
               'DOWNLOAD_CODES','DOWNLOAD_GUARD_CODES','WORKFLOW_CODES'}
        nodes=[]
        for node in tree.body:
            if isinstance(node,ast.Assign) and any((isinstance(t,ast.Name) and t.id in names) or
                (isinstance(t,ast.Subscript) and isinstance(t.value,ast.Name) and t.value.id in names) for t in node.targets):nodes.append(node)
            elif isinstance(node,ast.FunctionDef) and node.name in ('validate_diagnostic','consult_launcher_codes'):nodes.append(node)
        scope={'types':__import__('types')};exec(compile(ast.fix_missing_locations(ast.Module(body=nodes,type_ignores=[])),str(path),'exec'),scope)
        self.assertEqual(scope['DOWNLOAD_OPERATIONS'],self.launcher.DOWNLOAD_OPERATIONS)
        self.assertEqual(scope['DOWNLOAD_CODE_TYPES'],self.launcher.DOWNLOAD_CODE_TYPES)
        self.assertEqual(self.driver.DOWNLOAD_TYPES,self.launcher.DOWNLOAD_CODE_TYPES)
        self.assertEqual((len(self.driver.DOWNLOAD_OPERATIONS),len(self.driver.DOWNLOAD_CODES),len(self.driver.DOWNLOAD_GUARD_CODES)),(501,39,13))
        scope['consult_launcher_codes'](self.launcher)
        self.assertEqual(len(scope['DIAGNOSTIC_CODES']),503)
        self.assertEqual(len(scope['DIAGNOSTIC_CODES']-scope['DOWNLOAD_CODES']),464)
        self.assertEqual(len(set().union(*self.launcher.DIAGNOSTIC_CODES.values())),499)
        value={'schema_version':1,'stage':'pipeline','operation':self.driver.DOWNLOAD_PREFIX+'000',
            'exception_type':'ValueError','refusal_code':'DL_VALUEERROR'}
        self.assertEqual(scope['validate_diagnostic'](value),self.launcher.validate_diagnostic(value))
        value['exception_type']='OSError';self.assertIsNone(scope['validate_diagnostic'](value))


    def preserved_primary(self,kind=KeyboardInterrupt):
        primary=kind('PRIVATE PRIMARY');prior=ValueError('PRIVATE PRIOR CAUSE');primary.__cause__=prior
        try:raise primary
        except BaseException:pass
        return primary,primary.__traceback__,prior

    def test_secondary_classification_is_total_and_avoids_hostile_type_hooks(self):
        probes=[]
        class Meta(type):
            @property
            def __mro__(cls):probes.append('metaclass-mro');raise AssertionError('foreign mro')
            def __eq__(cls,other):probes.append('metaclass-equality');raise AssertionError('foreign equality')
        class SelfHostile(RuntimeError,metaclass=Meta):
            @property
            def __class__(self):probes.append('class');raise self
        first,tb,prior=self.preserved_primary();secondary=SelfHostile('PRIVATE SECONDARY')
        self.assertIsNone(self.driver.download_fault(first,secondary))
        self.assertEqual(probes,[]);self.assertIs(first.__traceback__,tb);self.assertIs(first.__cause__,prior)
        self.assertEqual(first.args,('PRIVATE PRIMARY',));self.assertFalse(first.__dict__.get('native_preflight_cancelled',False))
        # Even primary state-update descriptors cannot escape the optional helper.
        class Primary(KeyboardInterrupt):
            @property
            def native_preflight_cancelled(self):return False
        blocked,tb,prior=self.preserved_primary(Primary)
        self.assertIsNone(self.driver.download_fault(blocked,KeyboardInterrupt('PRIVATE CANCEL')))
        self.assertIs(blocked.__traceback__,tb);self.assertIs(blocked.__cause__,prior)

    def test_clock_secondary_hostility_and_real_cancel_subclasses_preserve_collection(self):
        probes=[]
        class Meta(type):
            @property
            def __mro__(cls):probes.append('metaclass-mro');raise AssertionError('foreign mro')
        class Hostile(RuntimeError):
            @property
            def __class__(self):probes.append('class');raise self
        class Cancel(KeyboardInterrupt):
            @property
            def __class__(self):probes.append('cancel-class');raise self
        for secondary,cancelled in ((RuntimeError('PRIVATE CLOCK'),False),(Hostile('PRIVATE CLOCK'),False),(Cancel('PRIVATE CLOCK'),True)):
            with self.subTest(real_type=type(secondary).__name__):
                self.owner.download_failure=None;first,tb,prior=self.preserved_primary()
                with patch.object(self.driver.time,'monotonic',side_effect=secondary):self.owner.capture_download(first,0,self.items[0])
                self.assertIs(first.__traceback__,tb);self.assertIs(first.__cause__,prior);self.assertEqual(first.args,('PRIVATE PRIMARY',))
                self.assertIs(self.owner.download_failure[0],first)
                self.driver.mark_pipeline_failure(first,'download-input');self.driver.latch_download(self.owner,first)
                self.assertEqual(self.driver.download_diagnostic(first)['refusal_code'],'DL_KBI_UNKNOWN_UNATTRIBUTED')
                self.assertEqual(first.__dict__.get('native_preflight_cancelled') is True,cancelled)
                self.assertEqual(first.__dict__.get('native_preflight_cleanup_uncertain') is True,cancelled)
        self.assertEqual(probes,[])

    def test_whole_fetch_hostile_clock_cannot_replace_original_interrupt(self):
        probes=[]
        class SelfHostile(RuntimeError):
            @property
            def __class__(self):probes.append('class');raise self
        first,tb,prior=self.preserved_primary();secondary=SelfHostile('PRIVATE CLOCK')
        with patch.object(self.driver.time,'monotonic',side_effect=(first,secondary)) as clock:
            caught=None
            try:self.owner.fetch(self.items[0],object(),ordinal=0)
            except BaseException as error:caught=error
        self.assertIs(caught,first);self.assertEqual(clock.call_count,2);self.assertEqual(probes,[])
        self.assertEqual(first.args,('PRIVATE PRIMARY',));self.assertIs(first.__cause__,prior)
        self.assertIs(self.owner.download_failure[0],first)
        frames=[];tail=first.__traceback__
        while tail.tb_next is not None:frames.append(tail.tb_frame.f_code.co_name);tail=tail.tb_next
        self.assertIs(tail,tb);self.assertNotIn('download_fault',frames);self.assertNotIn('capture_download',frames)
        self.driver.latch_download(self.owner,first)
        self.assertEqual(self.driver.download_diagnostic(first)['refusal_code'],'DL_KBI_UNKNOWN_UNATTRIBUTED')

    def test_exact_accessor_hostile_secondary_replaces_foreign_indexed_record(self):
        probes=[]
        class SelfHostile(RuntimeError):
            @property
            def __class__(self):probes.append('class');raise self
        secondary=SelfHostile('PRIVATE SECONDARY')
        class FaultTable(dict):
            def __getitem__(self,key):probes.append('lookup');raise secondary
        first,tb,prior=self.preserved_primary(ValueError)
        self.owner.capture_download(first,0,self.items[0]);self.driver.mark_pipeline_failure(first,'download-input')
        self.driver.latch_download(self.owner,first)
        foreign={'schema_version':1,'stage':'pipeline','operation':self.driver.DOWNLOAD_PREFIX+'000',
            'exception_type':'ValueError','refusal_code':'DL_VALUEERROR'}
        first.nativeci_diagnostic=dict(foreign);accessor=self.launcher.capture_download_accessor(self.driver)
        self.assertIs(type(FaultTable()).__contains__,dict.__contains__)
        with patch.dict(self.driver.__dict__,DOWNLOAD_TYPES=FaultTable(self.driver.DOWNLOAD_TYPES)):
            self.assertIsNone(self.launcher.attach_diagnostic(first,'pipeline','run-pipeline','pipeline',driver_accessor=accessor))
        self.assertEqual(first.nativeci_diagnostic,{'schema_version':1,'stage':'pipeline','operation':'download-input',
            'exception_type':'ValueError','refusal_code':'UNKNOWN'})
        self.assertEqual(probes,['lookup']);self.assertIs(first.__traceback__,tb);self.assertIs(first.__cause__,prior)
        self.assertEqual(first.args,('PRIVATE PRIMARY',))
        self.assertNotEqual(first.nativeci_diagnostic,foreign)

    def test_exact_accessor_real_cancel_subclass_sets_sticky_flags_without_class_hook(self):
        probes=[]
        class Cancel(KeyboardInterrupt):
            @property
            def __class__(self):probes.append('class');raise self
        secondary=Cancel('PRIVATE CANCEL')
        class FaultTable(dict):
            def __getitem__(self,key):raise secondary
        first,tb,prior=self.preserved_primary(ValueError)
        self.owner.capture_download(first,0,self.items[0]);self.driver.mark_pipeline_failure(first,'download-input');self.driver.latch_download(self.owner,first)
        accessor=self.launcher.capture_download_accessor(self.driver)
        with patch.dict(self.driver.__dict__,DOWNLOAD_TYPES=FaultTable(self.driver.DOWNLOAD_TYPES)):
            self.launcher.attach_diagnostic(first,'pipeline','run-pipeline','pipeline',driver_accessor=accessor)
        self.assertEqual(probes,[]);self.assertIs(first.__traceback__,tb);self.assertIs(first.__cause__,prior)
        self.assertTrue(first.native_preflight_cancelled);self.assertTrue(first.native_preflight_cleanup_uncertain)
        self.assertEqual(first.nativeci_diagnostic['operation'],'download-input');self.assertEqual(first.args,('PRIVATE PRIMARY',))

    def test_prior_SDK_record_wins_without_consulting_faulty_accessor(self):
        probes=[]
        class FaultTable(dict):
            def __getitem__(self,key):probes.append(key);raise KeyboardInterrupt('PRIVATE')
        first,tb,prior=self.preserved_primary(ValueError)
        self.owner.capture_download(first,0,self.items[0]);self.driver.mark_pipeline_failure(first,'download-input');self.driver.latch_download(self.owner,first)
        self.driver.attach_sdk_preflight(first,'preparation-sdk-preflight');old=dict(first.nativeci_diagnostic)
        with patch.dict(self.driver.__dict__,DOWNLOAD_TYPES=FaultTable(self.driver.DOWNLOAD_TYPES)):
            self.launcher.attach_diagnostic(first,'pipeline','run-pipeline','pipeline',driver_accessor=self.launcher.capture_download_accessor(self.driver))
        self.assertEqual(first.nativeci_diagnostic,old);self.assertEqual(probes,[])
        self.assertIs(first.__traceback__,tb);self.assertIs(first.__cause__,prior);self.assertEqual(first.args,('PRIVATE PRIMARY',))


if __name__ == '__main__':
    unittest.main()

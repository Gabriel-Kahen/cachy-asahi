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


if __name__ == '__main__':
    unittest.main()

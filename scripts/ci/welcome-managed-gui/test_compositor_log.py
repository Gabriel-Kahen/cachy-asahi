"""Inert byte streams and mocked processes; no compositor or subprocess runs."""
import importlib.util
import io
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import compositor_log as L
from test_gui import ROOT


spec=importlib.util.spec_from_file_location('compositor_fixture_base',ROOT/'scripts/ci/desktop574_guest.py')
B=importlib.util.module_from_spec(spec);spec.loader.exec_module(B)


class Logging(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.logs=Path(self.tmp.name);self.events=[]
        self.process=SimpleNamespace(stdout=io.BytesIO(),stderr=io.BytesIO(),returncode=0,pid=123,
                                     poll=lambda:self.process.returncode)
        self.emit=patch.object(B,'emit',side_effect=lambda event,**values:self.events.append(dict(event=event,**values)))
        self.emit.start();self.addCleanup(self.emit.stop)

    def actor(self,stdout=b'',stderr=b'',stage='minimal'):
        self.process.stdout=io.BytesIO(stdout);self.process.stderr=io.BytesIO(stderr)
        with patch.object(B.subprocess,'Popen',return_value=self.process) as popen:
            actor=L.launch(B,stage,Path('profile.lua'),self.logs,{'sentinel':'unchanged'})
        self.assertEqual(popen.call_args.args[0],['/usr/bin/Hyprland','--config','profile.lua'])
        self.assertEqual(popen.call_args.kwargs['env'],{'sentinel':'unchanged'})
        for thread in actor.threads:thread.join(timeout=2)
        return actor

    def test_long_stdout_retained_and_counted_without_filtering(self):
        data=b'ERR: retained\n'*(B.MAX_LOG//13+1)
        actor=self.actor(data);actor.finish()
        self.assertEqual(actor.paths[0].read_bytes(),data)
        summary=self.events[-1];self.assertFalse(summary['overflow'])
        self.assertEqual(summary['streams'][0]['observed_bytes'],len(data))
        self.assertEqual(summary['streams'][0]['limit_bytes'],2*1024*1024)

    def test_exact_stdout_boundary_passes(self):
        actor=self.actor(b'x'*L.STDOUT_LIMIT);actor.finish()
        self.assertEqual(actor.counts[0],L.STDOUT_LIMIT);self.assertFalse(actor.overflow)

    def test_stdout_overflow_fatal_in_health_and_finish_with_bounded_file(self):
        actor=self.actor(b'x'*(L.STDOUT_LIMIT+1))
        for method in (actor.healthy,actor.finish):
            with self.assertRaisesRegex(ValueError,'minimal.stdout: 2097153/2097152 bytes'):method()
        self.assertEqual(actor.paths[0].stat().st_size,L.STDOUT_LIMIT)
        self.assertTrue(self.events[-1]['overflow'])

    def test_stderr_budget_unchanged_and_overflow_fatal(self):
        actor=self.actor(stderr=b'x'*(B.MAX_LOG+1))
        with self.assertRaisesRegex(ValueError,'minimal.stderr: 262145/262144 bytes'):actor.finish()
        self.assertEqual(actor.paths[1].stat().st_size,B.MAX_LOG)

    def test_drain_io_error_stays_fatal_and_counted(self):
        (self.logs/'minimal.stdout').write_bytes(b'existing')
        actor=self.actor(b'new')
        with self.assertRaisesRegex(ValueError,'drain_errors=1'):actor.finish()
        self.assertEqual(actor.paths[0].read_bytes(),b'existing')

    def test_live_process_and_incomplete_drain_stay_fatal(self):
        actor=self.actor();self.process.returncode=None
        with self.assertRaisesRegex(ValueError,'process not reaped'):actor.finish()
        self.process.returncode=0
        actor.threads=[SimpleNamespace(join=lambda timeout:None,is_alive=lambda:True)]
        with self.assertRaisesRegex(ValueError,'log drain incomplete'):actor.finish()

    def test_diagnostic_emission_cannot_mask_primary_overflow(self):
        actor=self.actor(b'x'*(L.STDOUT_LIMIT+1))
        with patch.object(B,'emit',side_effect=RuntimeError('secondary emit')):
            with self.assertRaisesRegex(ValueError,'2097153/2097152 bytes'):actor.finish()

    def test_shared_logger_budget_and_implementation_unchanged(self):
        self.assertEqual(B.MAX_LOG,256*1024)
        self.assertNotEqual(L.logged_type(B),B.Logged)
        self.assertEqual(B.Logged.drain.__module__,'compositor_fixture_base')
        with self.assertRaisesRegex(ValueError,'fixed compositor profile'):
            L.launch(B,'other',Path('config'),self.logs,{})

    def test_shared_actor_stdout_overflow_remains_fatal_at_256k(self):
        self.process.stdout=io.BytesIO(b'x'*(B.MAX_LOG+1))
        with patch.object(B.subprocess,'Popen',return_value=self.process):
            actor=B.Logged(['/fixture/not-executed'],'other',self.logs,{})
        with self.assertRaisesRegex(ValueError,'process log overflow/failure'):actor.finish()
        self.assertEqual(actor.paths[0].stat().st_size,256*1024)

    def test_overlay_has_same_budget_and_event_identity(self):
        actor=self.actor(b'ordinary',stage='overlay');actor.finish()
        self.assertEqual(self.events[-1]['stage'],'overlay')
        self.assertEqual(self.events[-1]['streams'][1]['limit_bytes'],B.MAX_LOG)


if __name__=='__main__':unittest.main()

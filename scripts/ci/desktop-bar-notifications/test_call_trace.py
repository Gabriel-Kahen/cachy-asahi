# SPDX-License-Identifier: MIT
"""Private file/phase controls; no Waybar, compositor, VM or existing session actors."""
import base64
import hashlib
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock,patch
import session as S
import test_slice as fixtures


class CallTrace(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.events=[];self.base=SimpleNamespace(MAX_LOG=256*1024,emit=lambda event,**kw:self.events.append(dict(event=event,**kw)))
        self.paths=[self.root/'minimal-waybar.stdout',self.root/'minimal-waybar.stderr']
        self.paths[0].write_bytes(b'GDBus-debug:Call:\n'+b'pending method\n'*600);self.paths[1].write_bytes(b'')
        self.logged=SimpleNamespace(process=SimpleNamespace(pid=445,poll=lambda:-15,returncode=-15),
            errors=[],overflow=False,threads=[],paths=self.paths)

    def test_only_logging_key_is_added_without_changing_session_or_backend(self):
        selected=dict(WAYLAND_DISPLAY='wayland-1',XDG_SESSION_TYPE='wayland',DISPLAY=':0',GDK_BACKEND='fixture')
        original=dict(selected);result=S.waybar_environment(selected)
        self.assertEqual(selected,original);self.assertEqual(result,original|dict(G_DBUS_DEBUG='call'))

    def test_complete_trace_survives_beyond_the_original_4k_tail(self):
        with patch.object(S,'base',self.base):S.retain_waybar_trace('minimal',self.logged)
        self.assertEqual(len(self.events),1);row=self.events[0]
        self.assertTrue(row['diagnostic_only']);self.assertEqual(row['pid'],445);self.assertEqual(row['returncode'],-15)
        for path,log in zip(self.paths,row['logs']):
            raw=base64.b64decode(log['content_base64'],validate=True)
            self.assertEqual(raw,path.read_bytes());self.assertEqual(log['bytes'],len(raw))
            self.assertEqual(log['sha256'],hashlib.sha256(raw).hexdigest());self.assertTrue(log['capture_complete'])
        self.assertGreater(row['logs'][0]['bytes'],4096)

    def test_original_per_stream_cap_remains_strict(self):
        self.paths[0].write_bytes(b'x'*(self.base.MAX_LOG+1))
        with patch.object(S,'base',self.base),self.assertRaises(ValueError):S.retain_waybar_trace('minimal',self.logged)
        self.assertEqual(self.events,[])

    def test_symlink_and_missing_log_refused(self):
        original=self.paths[0];alias=self.root/'alias';alias.symlink_to(original);self.logged.paths=[alias,self.paths[1]]
        with patch.object(S,'base',self.base),self.assertRaises(ValueError):S.retain_waybar_trace('minimal',self.logged)
        self.logged.paths=[self.root/'missing',self.paths[1]]
        with patch.object(S,'base',self.base),self.assertRaises(FileNotFoundError):S.retain_waybar_trace('minimal',self.logged)

    def test_live_overflowed_or_unjoined_logs_cannot_be_claimed_complete(self):
        for change in ('live','overflow','drain'):
            self.logged.process.poll=lambda:-15;self.logged.overflow=False;self.logged.threads=[]
            if change=='live':self.logged.process.poll=lambda:None
            elif change=='overflow':self.logged.overflow=True
            else:self.logged.threads=[SimpleNamespace(is_alive=lambda:True)]
            with patch.object(S,'base',self.base),self.assertRaises(ValueError):S.retain_waybar_trace('minimal',self.logged)

    def test_trace_failure_keeps_original_failure_and_all_owned_retirement(self):
        phase=fixtures.PhaseTests('test_changed_notification_payload_refuses_and_retires_all');phase.setUp()
        try:
            phase.bad_payload=True
            with patch.object(S,'retain_waybar_trace',side_effect=RuntimeError('secondary trace fault')) as trace:
                with self.assertRaisesRegex(ValueError,'notification payload differs'):phase.run_phase()
                trace.assert_called_once();self.assertIs(trace.call_args.args[1],phase.processes[1])
            phase.assert_retired();self.assertNotIn('phase_pass',[e['event'] for e in phase.emitted])
        finally:phase.doCleanups()

    def test_success_keeps_two_original_events_and_never_exports_failure_trace(self):
        phase=fixtures.PhaseTests('test_full_owned_lifecycle_capture_dismissal_clean_stops_and_preservation');phase.setUp()
        try:
            with patch.object(S,'retain_waybar_trace',side_effect=AssertionError('success trace forbidden')) as trace:
                phase.run_phase();trace.assert_not_called()
            phase.assert_retired();self.assertEqual([e['event'] for e in phase.emitted],['frame_ready','phase_pass'])
        finally:phase.doCleanups()


if __name__=='__main__':unittest.main(verbosity=2)

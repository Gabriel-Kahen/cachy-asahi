#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real PTY/refusal controls; explicit retained archives, no substitutes or skips."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import journey as J
from terminal import Terminal,members

FIRST=SETUP=EVIDENCE=None


class TerminalTests(unittest.TestCase):
    def setUp(self):
        self.assertNotEqual(os.geteuid(),0)
        self.temp=tempfile.TemporaryDirectory(prefix='first-login-pty-controls-')
        self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.out=self.root/'out';self.out.mkdir(mode=0o700)
        self.home=self.root/'home';self.home.mkdir(mode=0o700)
        self.env=dict(HOME=str(self.home),PATH='/usr/bin:/bin',LC_ALL='C.UTF-8',TERM='dumb')
        self.signals=J.load(HERE.parents[2]/'scripts/integration/onboarding.py')
        self.existing_home=os.environ.get('HOME')

    def terminal(self,code,seconds=.3,limit=2048):
        return Terminal('control',[sys.executable,'-I','-c',code],self.env,self.root,self.out,self.signals,seconds=seconds,limit=limit)

    def assert_clean_failure(self,terminal):
        row=json.loads((self.out/'control.json').read_bytes())
        self.assertEqual(row['status'],'FAIL');self.assertEqual(row['cleanup'],'REAPED_EMPTY_TWICE')
        self.assertFalse(members(terminal.sid));self.assertFalse(Path('/proc/'+str(terminal.sid)).exists())
        self.assertLessEqual(len((self.out/'control.pty').read_bytes()),terminal.limit)
        self.assertEqual(os.environ.get('HOME'),self.existing_home)
        return row

    def test_deadline_reaps_actual_tty_process(self):
        terminal=self.terminal('import time;time.sleep(10)',seconds=.15)
        with self.assertRaisesRegex(ValueError,'deadline'),terminal as t:t.expect('NEVER')
        self.assert_clean_failure(terminal)

    def test_output_cap_reaps_actual_tty_process(self):
        terminal=self.terminal('import os,time;os.write(1,b"X"*4096);time.sleep(10)',limit=256)
        with self.assertRaisesRegex(ValueError,'output cap'),terminal as t:t.expect('NEVER')
        self.assert_clean_failure(terminal)

    def test_echo_like_marker_does_not_satisfy_output_line(self):
        terminal=self.terminal('import time;print("typed-prefix CAA_FALSE_MARKER typed-suffix",flush=True);time.sleep(10)')
        with self.assertRaisesRegex(ValueError,'deadline'),terminal as t:t.expect('CAA_FALSE_MARKER',line=True)
        self.assert_clean_failure(terminal)

    def test_no_pty_fallback(self):
        with patch('terminal.pty.openpty',side_effect=OSError('controlled unavailable PTY')),self.assertRaisesRegex(OSError,'unavailable'):
            with self.terminal('print("must not run")'):pass
        row=json.loads((self.out/'control.json').read_bytes());self.assertEqual(row['status'],'FAIL')
        self.assertNotIn('returncode',row);self.assertEqual((self.out/'control.pty').read_bytes(),b'')

    def test_natural_eof_is_required_for_positive_session(self):
        terminal=self.terminal('import time;print("READY",flush=True);time.sleep(10)')
        with self.assertRaisesRegex(ValueError,'natural EOF'),terminal as t:t.expect('READY',line=True)
        self.assert_clean_failure(terminal)

    def test_actual_unexpected_exit_is_not_a_pass(self):
        terminal=self.terminal('print("READY",flush=True);raise SystemExit(7)')
        with self.assertRaisesRegex(ValueError,'zero'),terminal as t:t.expect('READY',line=True);t.eof()
        row=self.assert_clean_failure(terminal);self.assertEqual(row['returncode'],7)

    def test_sigterm_cleanup_retains_diagnostics_and_restores_handler(self):
        previous=signal.signal(signal.SIGTERM,self.signals.interrupt)
        try:
            terminal=self.terminal('import time;print("READY",flush=True);time.sleep(10)')
            with self.assertRaises(self.signals.Interrupted),terminal as t:
                t.expect('READY',line=True);os.kill(os.getpid(),signal.SIGTERM)
            self.assertIs(signal.getsignal(signal.SIGTERM),self.signals.interrupt)
            self.assertIn('Interrupted',self.assert_clean_failure(terminal)['error'])
        finally:signal.signal(signal.SIGTERM,previous)

    def test_fragmented_observation_and_real_terminal_eof(self):
        terminal=self.terminal('import os,time;os.write(1,b"CAA_SPLIT");time.sleep(.05);os.write(1,b"\\n");os.read(0,1)',seconds=1)
        with terminal as t:t.expect('CAA_SPLIT',line=True);t.eof()
        row=json.loads((self.out/'control.json').read_bytes());self.assertEqual(row['status'],'PASS')
        self.assertEqual(row['cleanup'],'REAPED_EMPTY_TWICE');self.assertTrue(row['natural_eof'])

    def test_cleanup_does_not_touch_foreign_session(self):
        foreign=subprocess.Popen([sys.executable,'-I','-c','import time;time.sleep(10)'],start_new_session=True)
        try:
            terminal=self.terminal('import time;time.sleep(10)',seconds=.15)
            with self.assertRaisesRegex(ValueError,'deadline'),terminal as t:t.expect('NEVER')
            self.assert_clean_failure(terminal);self.assertIsNone(foreign.poll())
        finally:foreign.terminate();foreign.wait(timeout=2)

    def test_changed_helper_refused_before_execution(self):
        poison=self.root/'poison.py';poison.write_text('raise RuntimeError("unreviewed code executed")\n')
        with self.assertRaisesRegex(ValueError,'before import'):J.load(poison)

    def test_bad_archive_refuses_before_intake_command(self):
        archive=self.root/'wrong.pkg.tar.zst';archive.write_bytes(b'not the selected archive')
        scratch=self.root/'scratch';scratch.mkdir(mode=0o700)
        with patch.object(J,'capture',side_effect=AssertionError('must refuse before command')),self.assertRaisesRegex(ValueError,'exact retained'):
            J.stage(archive,archive,scratch,self.signals,HERE.parents[2])

    def test_changed_template_refuses_before_any_shell(self):
        self.assertIsNotNone(FIRST,'explicit real archive input required')
        self.assertIsNotNone(SETUP,'explicit real Setup8 archive required')
        source=self.root/'selected-source';source.mkdir()
        for kind in ('fish','zsh'):
            path=source/('packages/shells/cachy-asahi-'+kind+'-config/config.'+kind)
            path.parent.mkdir(parents=True);path.write_bytes((HERE.parents[2]/path.relative_to(source)).read_bytes())
        helper=source/'scripts/integration/onboarding.py';helper.parent.mkdir(parents=True)
        helper.write_bytes((HERE.parents[2]/'scripts/integration/onboarding.py').read_bytes())
        changed=source/'packages/shells/cachy-asahi-fish-config/config.fish';changed.write_bytes(changed.read_bytes()+b'# altered profile\n')
        scratch=self.root/'scratch';scratch.mkdir(mode=0o700)
        with self.assertRaisesRegex(ValueError,'template source'):J.stage(FIRST,SETUP,scratch,self.signals,source)
        self.assertFalse((scratch/'driver').exists())

    def test_real_hidden_checkout_delivered_pty_journey(self):
        self.assertIsNotNone(FIRST,'explicit retained FirstLogin archive required')
        self.assertIsNotNone(SETUP,'explicit genuine Setup8 archive required')
        out=EVIDENCE if EVIDENCE else self.root/'actual-results'
        process=subprocess.run([sys.executable,'-I','-B',str(HERE/'journey.py'),'--first-login-archive',str(FIRST),'--setup-archive',str(SETUP),'--output',str(out),'--run-temporary-pty-journey'],capture_output=True,timeout=180)
        self.assertEqual(process.returncode,0,(process.stdout+process.stderr).decode(errors='replace'))
        result=json.loads((out/'result.json').read_bytes());self.assertEqual(result['status'],'PASS')
        self.assertTrue(result['source_hidden']);self.assertTrue(result['owned_private_workspace_removed'])
        self.assertEqual(result['pty_sessions'],7);self.assertEqual(result['natural_EOF_exits'],7);self.assertEqual(result['Ctrl_C_foreground_journeys'],2)
        self.assertEqual(set(result['user_edits']),{'.config/fish/config.fish','.zshrc'})
        for session in result['sessions']:
            self.assertTrue(session['natural_eof']);self.assertEqual(session['returncode'],0)
            self.assertEqual(session['cleanup'],'REAPED_EMPTY_TWICE');self.assertIsNone(session['cleanup_error'])
            self.assertNotIn('-c',session['argv'])
        interrupts=[a for row in result['sessions'] for a in row['actions'] if a['event']=='foreground-retired']
        self.assertEqual(len(interrupts),2)
        self.assertEqual(result['native_arm'],'NOT RUN');self.assertFalse(result['release_acceptance'])
        self.assertEqual(os.environ.get('HOME'),self.existing_home)


if __name__=='__main__':
    parser=argparse.ArgumentParser(add_help=False)
    parser.add_argument('--first-login-archive',type=Path,required=True);parser.add_argument('--setup-archive',type=Path,required=True)
    parser.add_argument('--evidence',type=Path)
    args,remaining=parser.parse_known_args();FIRST,SETUP,EVIDENCE=args.first_login_archive,args.setup_archive,args.evidence
    unittest.main(argv=[__file__,*remaining])

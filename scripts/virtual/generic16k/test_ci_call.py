# SPDX-License-Identifier: MIT
import contextlib
import io
import json
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import ci_call as caller


class CallerControls(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=caller.HERE)
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_source_hashes_refuse_changed_file_and_wrong_manifest_pin(self):
        data = b'fixed-source\n'
        (self.root/'one.py').write_bytes(data)
        raw = json.dumps({'schema': 1, 'files': {'one.py': {'sha256': caller.digest(data), 'bytes': len(data)}}}).encode()
        (self.root/'ci-files.json').write_bytes(raw)
        with patch.object(caller, 'HERE', self.root):
            self.assertEqual(caller.check_source(self.root, caller.digest(raw)), caller.digest(raw))
            (self.root/'one.py').write_bytes(b'changed')
            with self.assertRaises(ValueError): caller.check_source(self.root, caller.digest(raw))
            with self.assertRaises(ValueError): caller.check_source(self.root, 'a'*64)

    def test_public_frame_binds_exact_bytes_and_budget(self):
        public = self.root/'public'; public.mkdir()
        raw = b'{"status":"NOT RUN"}\n'
        (public/'status.json').write_bytes(raw)
        index = [{'name':'status.json', 'bytes':len(raw), 'sha256':caller.digest(raw)}]
        (public/'index.json').write_text(json.dumps(index))
        with contextlib.redirect_stdout(io.StringIO()) as captured:
            caller.publish(self.root)
        frame = captured.getvalue().splitlines()
        self.assertEqual(frame[0], 'GENERIC16K_PUBLIC_BEGIN')
        self.assertEqual(json.loads(frame[1])['files'][0]['sha256'], caller.digest(raw))
        (public/'status.json').write_bytes(raw+b'changed')
        with self.assertRaises(ValueError): caller.publish(self.root)
        index[0]['name']='../status.json'; (public/'index.json').write_text(json.dumps(index))
        with self.assertRaises(ValueError): caller.publish(self.root)

    def test_real_bounded_child_natural_exit_error_and_deadline_cleanup(self):
        env={'PATH':'/usr/bin:/bin'}
        result = caller.command([sys.executable,'-c','print("one")'], self.root/'ok.log', 3, env)
        self.assertEqual(result['returncode'],0)
        self.assertEqual((self.root/'ok.log').read_bytes(),b'one\n')
        with self.assertRaises(ValueError):
            caller.command([sys.executable,'-c','raise SystemExit(9)'],self.root/'fail.log',3,env)
        # TERM permits nested cleanup to finish before a watchdog resorts to KILL.
        script = ('import signal,time,pathlib,sys\n'
                  'def stop(*a):\n pathlib.Path(sys.argv[1]).write_text("cleaned");raise SystemExit(0)\n'
                  'signal.signal(signal.SIGTERM,stop)\nprint("ready",flush=True)\ntime.sleep(30)\n')
        marker = self.root/'cleaned'
        with self.assertRaises(ValueError):
            caller.command([sys.executable,'-c',script,str(marker)], self.root/'timeout.log', .5, env)
        self.assertEqual(marker.read_text(),'cleaned')


if __name__ == '__main__':
    unittest.main()

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Focused driver checks; run from checkout root, optionally MIRRORS_CLI=/path."""
import importlib.util
import json
import os
import sys
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('mirror_lifecycle', Path(__file__).with_name('lifecycle.py'))
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
CLI = Path(os.environ.get('MIRRORS_CLI', 'packages/tools/cachy-asahi-mirrors/cachy-asahi-mirrors')).absolute()


class Lifecycle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        global CLI
        if not os.access(CLI, os.X_OK):
            cls.stage = tempfile.TemporaryDirectory(prefix='mirrors-driver-cli-stage-')
            cls.addClassCleanup(cls.stage.cleanup)
            source = CLI.read_bytes()
            CLI = Path(cls.stage.name)/'cachy-asahi-mirrors'
            CLI.write_bytes(source); CLI.chmod(0o755)

    def test_real_cli_tls_recovery_and_retained_evidence(self):
        with tempfile.TemporaryDirectory(prefix='mirrors-driver-test-') as root:
            work = Path(root)
            result = M.run(CLI, work)
            self.assertEqual(result['status'], 'PASS_LOCAL_MIRROR_LIFECYCLE', result.get('error'))
            self.assertEqual(len(result['events']), 13)
            self.assertEqual(len(result['commands']), 42)
            self.assertEqual(sum(row['exit'] == -9 for row in result['commands']), 9)
            self.assertTrue(result['private_TLS_key_removed'])
            self.assertFalse((work/'fixture-key.pem').exists())
            self.assertEqual((work/'roundtrip/mirrorlist').read_bytes(), M.ORIGINAL)
            self.assertFalse((work/'absent/mirrorlist').exists())
            self.assertEqual((work/'restoring-user-edit/mirrorlist').read_bytes(), M.EDIT)
            self.assertEqual(json.loads((work/'prepared-user-edit/journal.json').read_bytes())['phase'], 'PREPARED')
            for row in result['commands']:
                prefix = work/'transcripts'/('%03d' % row['index'])
                self.assertEqual(M.sha(prefix.with_suffix('.stdout').read_bytes()), row['stdout_sha256'])
                self.assertEqual(M.sha(prefix.with_suffix('.stderr').read_bytes()), row['stderr_sha256'])
                self.assertEqual(M.sha(prefix.with_suffix('.command.json').read_bytes()), row['command_sha256'])
            public = json.dumps(result)
            self.assertNotIn('BEGIN PRIVATE KEY', public)
            self.assertNotIn('Server = preserve-exactly', public)
            self.assertNotIn(str(work), public)

    def test_workspace_refuses_existing_or_nonprivate_input(self):
        with tempfile.TemporaryDirectory(prefix='mirrors-driver-guard-') as root:
            work = Path(root); outside = work/'preserve'
            outside.write_bytes(b'original')
            with self.assertRaisesRegex(ValueError, 'empty absolute private'):
                M.run(CLI, work)
            self.assertEqual(outside.read_bytes(), b'original')
            outside.unlink(); work.chmod(0o750)
            with self.assertRaisesRegex(ValueError, 'mode0700'):
                M.run(CLI, work)
            work.chmod(0o700)
            self.assertEqual(list(work.iterdir()), [])

    def test_trace_anchor_refuses_unrecognized_source(self):
        with tempfile.TemporaryDirectory(prefix='mirrors-driver-ast-') as root:
            path = Path(root)/'different-cli'; path.write_text('def activate():\n    pass\n')
            with self.assertRaisesRegex(ValueError, 'trace point missing'):
                M.pause_point(path, 'prepared')
        for phase in ('prepared', 'activated', 'restoring', 'restored'):
            function, line = M.pause_point(CLI, phase)
            self.assertIn(function, ('activate', 'install_pending', 'restore'))
            self.assertGreater(line, 0)


if __name__ == '__main__':
    if '--cli' in sys.argv:
        position = sys.argv.index('--cli')
        CLI = Path(sys.argv[position+1]).absolute()
        del sys.argv[position:position+2]
    unittest.main()

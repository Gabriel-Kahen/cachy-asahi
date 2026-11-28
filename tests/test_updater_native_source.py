"""Replay the native workflow's reviewed source validation without ARM or Docker."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
REVIEWED_COMMIT = '6302e2994ee4a25a3e9ad3aee24f1416375505cb'


class UpdaterNativeSourceTests(unittest.TestCase):
    def test_workflow_pins_match_committed_source(self):
        checkout = Path(os.environ.get('UPDATER_NATIVE_SOURCE_REPLAY',
                                       ROOT / '.ci-inputs/updater-native-reviewed')).resolve()
        self.assertTrue((checkout / '.git').exists(),
                        f'Expected reviewed updater checkout at {checkout} ({REVIEWED_COMMIT})')
        commit = subprocess.check_output(['git', 'rev-parse', '--verify', 'HEAD'], cwd=checkout,
                                         text=True, timeout=5).strip()
        self.assertEqual(commit, REVIEWED_COMMIT)
        workflow = (checkout / '.github/workflows/native-arm-updater.yml').read_text()
        pins = {}
        for name in ('READY', 'STAGE', 'SOURCE'):
            matches = re.findall(rf'^      {name}_SHA256: ([0-9a-f]{{64}})$', workflow, re.M)
            self.assertEqual(len(matches), 1, name)
            pins[name] = matches[0]

        stage = checkout / 'scripts/port/updater-native-stage/stage.py'
        self.assertEqual(hashlib.sha256(stage.read_bytes()).hexdigest(), pins['STAGE'])
        result = subprocess.run([sys.executable, '-I', '-B', str(stage), 'preflight',
                                 '--root', str(checkout), '--source-commit', commit,
                                 '--ready-sha256', pins['READY'],
                                 '--bootstrap-stage-sha256', pins['STAGE'],
                                 '--bootstrap-source-sha256', pins['SOURCE']],
                                capture_output=True, text=True, timeout=65)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report['source_preflight'], 'PASS')
        self.assertEqual(report['source_commit'], commit)
        self.assertEqual(report['native_compilation'], 'NOT RUN')


if __name__ == '__main__':
    unittest.main()

"""Run the native workflow's source validation without ARM or Docker."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]


class UpdaterNativeSourceTests(unittest.TestCase):
    def test_workflow_pins_match_committed_source(self):
        workflow = (ROOT / '.github/workflows/native-arm-updater.yml').read_text()
        pins = {}
        for name in ('READY', 'STAGE', 'SOURCE'):
            matches = re.findall(rf'^      {name}_SHA256: ([0-9a-f]{{64}})$', workflow, re.M)
            self.assertEqual(len(matches), 1, name)
            pins[name] = matches[0]

        stage = ROOT / 'scripts/port/updater-native-stage/stage.py'
        self.assertEqual(hashlib.sha256(stage.read_bytes()).hexdigest(), pins['STAGE'])
        commit = subprocess.check_output(['git', 'rev-parse', '--verify', 'HEAD'], cwd=ROOT,
                                         text=True, timeout=5).strip()
        result = subprocess.run([sys.executable, '-I', '-B', str(stage), 'preflight',
                                 '--root', str(ROOT), '--source-commit', commit,
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

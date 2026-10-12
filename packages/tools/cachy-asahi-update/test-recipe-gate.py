#!/usr/bin/env python3
"""Execute only extracted gate function with mocked Python in private Bash."""
from pathlib import Path
import subprocess
import tempfile
import unittest


class GatePropagation(unittest.TestCase):
    def test_native_gate_failure_stops_before_source_verifier(self):
        text = Path(__file__).with_name('PKGBUILD').read_text()
        body = text.split('\n_review_gate() {\n', 1)[1].split('\n}\n', 1)[0]
        with tempfile.TemporaryDirectory(prefix='cachy-update-gate-fixture-') as tmp:
            root = Path(tmp)
            harness = '''python() {
  printf '%s\\n' "$1" >> "$fixture_log"
  case "$1" in */build-gate.py) return 23 ;; *) return 0 ;; esac
}
_review_gate() {
''' + body + '\n}\n_review_gate\n'
            result = subprocess.run(['/usr/bin/bash', '--noprofile', '--norc', '-c', harness],
                cwd=root, env={'PATH':'/usr/bin:/bin','srcdir':str(root),
                               'CACHY_ASAHI_CONTROLLER_SHA256':'fixture-not-native',
                               'fixture_log':str(root/'calls')}, capture_output=True)
            self.assertEqual(result.returncode, 23, result.stderr.decode())
            self.assertEqual((root/'calls').read_text().splitlines(), ['/inputs/recipe/build-gate.py'])


if __name__ == '__main__':
    unittest.main()

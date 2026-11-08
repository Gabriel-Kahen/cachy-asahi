#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run successor source/archive and moved-CLI controls on existing static CI."""
from pathlib import Path
import subprocess
import sys
import unittest

PACKAGE = Path(__file__).resolve().parents[2] / 'packages/tools/cachy-asahi-desktop-tools2'


class DesktopToolsSuccessor(unittest.TestCase):
    def run_controls(self, relative):
        result = subprocess.run([sys.executable, '-I', '-B', str(PACKAGE / relative)],
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_source_delivery(self):
        self.run_controls('test_export_source.py')

    def test_relocated_cli(self):
        self.run_controls('cachy-asahi-desktop-tools-0.1.1/test_package.py')


if __name__ == '__main__':
    unittest.main()

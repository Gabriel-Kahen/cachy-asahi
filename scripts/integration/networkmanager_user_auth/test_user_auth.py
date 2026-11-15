#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Host refusal controls; actual authorization observations use the opt-in CLI."""
import os
from pathlib import Path
import subprocess
import sys
import unittest

HERE=Path(__file__).resolve().parent


class EntryControls(unittest.TestCase):
    def test_ordinary_role_cannot_load_container_helpers_on_host(self):
        env=dict(os.environ);env.pop('CACHY_ASAHI_USER_AUTH_TEST',None)
        p=subprocess.run([sys.executable,str(HERE/'roles.py'),'identity'],env=env,capture_output=True,text=True)
        self.assertEqual(p.returncode,2);self.assertIn('owned container only',p.stderr)
        self.assertNotIn('/opt/nm-private-bus',p.stderr)

    def test_root_fixture_cannot_start_bus_or_daemon_on_host(self):
        env=dict(os.environ);env.pop('CACHY_ASAHI_USER_AUTH_TEST',None)
        p=subprocess.run([sys.executable,str(HERE/'fixture.py')],env=env,capture_output=True,text=True)
        self.assertNotEqual(p.returncode,0);self.assertIn('owned container only',p.stderr)
        self.assertNotIn('FileNotFoundError',p.stderr)


if __name__=='__main__':unittest.main(verbosity=2)

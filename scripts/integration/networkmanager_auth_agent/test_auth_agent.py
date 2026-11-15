#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Host-execution refusals for private credential and agent entry points."""
import os
from pathlib import Path
import subprocess
import sys
import unittest

HERE=Path(__file__).resolve().parent


class Refusals(unittest.TestCase):
    def test_credentials_cannot_read_or_change_host_account_state(self):
        env=dict(os.environ);env.pop('CACHY_ASAHI_PAM_ACTOR',None)
        p=subprocess.run([sys.executable,str(HERE/'credential.py')],env=env,stdin=subprocess.DEVNULL,capture_output=True,text=True)
        self.assertNotEqual(p.returncode,0);self.assertIn('owned credential fixture only',p.stderr)
        self.assertNotIn('shadow',p.stderr)

    def test_agent_and_bootstrap_require_their_owned_container(self):
        env=dict(os.environ)
        for key in ['CACHY_ASAHI_USER_AUTH_TEST','CACHY_ASAHI_PAM_ACTOR']:env.pop(key,None)
        for script,message in [('probe.py','owned ordinary-UID container only'),('authenticate.py','owned ordinary PAM actor only'),('bootstrap.py','owned PAM actor only')]:
            with self.subTest(script=script):
                p=subprocess.run([sys.executable,str(HERE/script)],env=env,capture_output=True,text=True)
                self.assertNotEqual(p.returncode,0);self.assertIn(message,p.stderr)
                self.assertNotIn('FileNotFoundError',p.stderr)


if __name__=='__main__':unittest.main(verbosity=2)

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded current-host observation; exact inherited tiny-child allowance only."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import test_guest_startup_data as startup
import contextlib
import importlib.util
import io
import json
import os
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SUBJECT=Path(__file__).resolve().parents[1]/'payload/native/platform_namespace_policy_v1.py'
PREFIX=b'PLATFORM_NAMESPACE_POLICY_GUEST_IDENTITY_V2 '


class GuestIdentityData(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec=importlib.util.spec_from_file_location('maintained_identity_subject',SUBJECT)
        cls.m=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.m)

    def args(self):return SimpleNamespace(case='baseline',image='sha256:'+'a'*64)

    def test_exact_identity_still_required_and_duplicate_groups_not_hidden(self):
        m=self.m
        with patch.object(m.os,'getuid',return_value=1001),patch.object(m.os,'geteuid',return_value=1001),\
             patch.object(m.os,'getgid',return_value=1001),patch.object(m.os,'getegid',return_value=1001),\
             patch.object(m.os,'getgroups',return_value=[1001,998]),\
             patch.object(m.os,'uname',return_value=SimpleNamespace(machine='aarch64')),\
             patch.object(m.Path,'cwd',return_value=Path('/tmp')),patch.object(m,'_frozen_guest',return_value='NEW_INERT_CONTINUATION')as frozen:
            self.assertEqual(m.guest_identity_data_v2(self.args())['failed_checks'],[])
            self.assertEqual(m.guest_v2(self.args()),'NEW_INERT_CONTINUATION');frozen.assert_called_once()
            for method,value,check in [('getuid',0,'uid'),('geteuid',0,'euid'),('getgid',0,'gid'),
                                       ('getegid',0,'egid'),('getgroups',[998,1001,1001],'groups')]:
                with patch.object(m.os,method,return_value=value):
                    data=m.guest_identity_data_v2(self.args());self.assertIn(check,data['failed_checks'])
                    sink=io.TextIOWrapper(io.BytesIO(),encoding='utf-8')
                    with patch.object(m.sys,'stderr',sink),self.assertRaises(m.MatrixGuard):m.guest_v2(self.args())
                    sink.flush();line=sink.buffer.getvalue();self.assertTrue(line.startswith(PREFIX));self.assertLess(len(line),2048)
                    self.assertIs(json.loads(line[len(PREFIX):])['acceptance'],False)
            self.assertEqual(frozen.call_count,1)
            with patch.object(m.os,'getgroups',return_value=list(range(80))):
                data=m.guest_identity_data_v2(self.args());self.assertEqual(data['observed']['groups_count'],80)
                self.assertFalse(data['observed']['groups_complete']);self.assertEqual(len(data['observed']['groups']),64)

    def test_actual_host_diagnostics_before_refusal_without_guest_or_probe(self):
        # Real current-host identity is observed, but the frozen guest/probe has a
        # hard test sentinel and must never be invoked by this diagnostic control.
        child=startup.CHILD_GUARD+'''import importlib.util,json,os
from pathlib import Path
from types import SimpleNamespace
spec=importlib.util.spec_from_file_location('maintained_host_identity',sys.argv[1])
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
def forbidden(args):raise RuntimeError('FROZEN_GUEST_MUST_NOT_RUN_IN_HOST_CONTROL')
m._frozen_guest=forbidden
m.guest_v2(SimpleNamespace(case='baseline',image='sha256:'+'a'*64))
'''
        result=startup.launch(['-c',child,str(SUBJECT)])
        self.assertEqual(result.returncode,1);self.assertEqual(result.stdout,b'')
        lines=[line[len(PREFIX):]for line in result.stderr.splitlines()if line.startswith(PREFIX)]
        self.assertEqual(len(lines),1);value=json.loads(lines[0]);observed=value['observed']
        self.assertEqual(observed['uid'],os.getuid());self.assertEqual(observed['euid'],os.geteuid())
        self.assertEqual(observed['gid'],os.getgid());self.assertEqual(observed['egid'],os.getegid())
        self.assertEqual(observed['groups'],sorted(os.getgroups())[:64]);self.assertEqual(observed['cwd'],str(Path.cwd())[:512])
        self.assertEqual(observed['arch'],os.uname().machine[:64]);self.assertTrue(value['failed_checks'])
        self.assertEqual(value['phase'],'BEFORE_FROZEN_IDENTITY_GUARD');self.assertEqual(value['namespace_effect'],'UNKNOWN')
        self.assertNotIn(b'FROZEN_GUEST_MUST_NOT_RUN_IN_HOST_CONTROL',result.stderr)
        self.assertIn(b'exact unprivileged prepared native guest',result.stderr)


if __name__=='__main__':unittest.main()

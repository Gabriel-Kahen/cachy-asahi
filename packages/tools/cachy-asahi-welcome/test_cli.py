#!/usr/bin/env python3
"""Run against the compiled native program; no GUI/launch/package operations."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

BINARY=Path(sys.argv[1] if len(sys.argv)>1 else './cachy-asahi-welcome').resolve()
sys.argv=sys.argv[:1]


class CLI(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        root=Path(self.temp.name)
        self.env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','HOME':str(root),
                  'XDG_CONFIG_HOME':str(root/'config'),'XDG_CACHE_HOME':str(root/'cache'),
                  'XDG_DATA_HOME':str(root/'data'),'XDG_STATE_HOME':str(root/'state'),
                  'DISPLAY':'','WAYLAND_DISPLAY':'','DBUS_SESSION_BUS_ADDRESS':'unix:path=/nonexistent'}
        self.root=root

    def call(self,*args):
        return subprocess.run([str(BINARY),*args],env=self.env,text=True,capture_output=True,timeout=10)

    def test_JSON_without_display_reports_actual_system_and_separate_acceptance(self):
        value=self.call('--status','--json'); self.assertEqual(value.returncode,0,value.stderr)
        data=json.loads(value.stdout)
        self.assertEqual(data['architecture'],os.uname().machine)
        self.assertEqual(data['kernel'],os.uname().release)
        self.assertEqual(data['page_size'],os.sysconf('SC_PAGE_SIZE'))
        self.assertEqual(data['hardware_compatibility'],'not-assessed')
        self.assertEqual(data['schema_version'],1); self.assertEqual(len(data['packages']),6)
        for record in data['packages'].values():
            self.assertIn(record['state'],('installed','not-found','unknown'))
            self.assertEqual(record['version'] is not None,record['state']=='installed')
        self.assertEqual(list(self.root.iterdir()),[])

    def test_text_status_without_display(self):
        value=self.call('--status'); self.assertEqual(value.returncode,0,value.stderr)
        self.assertIn('Architecture: '+os.uname().machine,value.stdout)
        self.assertIn('Hardware compatibility: not assessed',value.stdout)

    def test_help_and_version_without_display(self):
        help_text=self.call('--help'); self.assertEqual(help_text.returncode,0)
        self.assertIn('--status',help_text.stdout); self.assertIn('--guide',help_text.stdout)
        version=self.call('--version'); self.assertEqual(version.returncode,0)
        self.assertEqual(version.stdout,'cachy-asahi Welcome 0.1.0\n')

    def test_conflicting_unknown_and_path_guide_arguments_are_rejected(self):
        for args in (('--json',),('--unknown',),('--status','--guide','first-run'),('--version','--status'),
                     ('--guide','../../etc/shadow'),('positional',)):
            with self.subTest(args=args):
                result=self.call(*args); self.assertEqual(result.returncode,2)
                self.assertEqual(result.stdout,'')

    def test_GUI_without_display_has_useful_CLI_fallback(self):
        value=self.call(); self.assertEqual(value.returncode,1)
        self.assertIn('--status',value.stderr)


if __name__=='__main__': unittest.main()

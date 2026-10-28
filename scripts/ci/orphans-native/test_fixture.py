"""Real host libalpm temporary-metadata controls; never run on hosted Ubuntu.

Native evidence instead requires the original18 recipe checks and actual installed fixture.
"""
import copy
import ctypes
import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import contract as C
import fixture as F
import job as J
import run as R

ROOT=Path(os.environ.get('ORPHANS_NATIVE_SOURCE',Path(__file__).resolve().parents[3]))
HERE=Path(__file__).resolve().parent
TOOL=ROOT/'packages/tools/cachy-asahi-orphans/cachy-asahi-orphans'


class Metadata(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.db=self.root/'var/lib/pacman'
        (self.db/'local').mkdir(parents=True);(self.db/'local/ALPM_DB_VERSION').write_text('9\n');F.populate(self.db)
        with patch.object(F,'CLI',str(TOOL)):self.M=F.module()
    def cli(self,*args,code=0):
        result=subprocess.run([sys.executable,'-B',str(TOOL),*map(str,args)],capture_output=True,text=True,timeout=30)
        self.assertEqual(result.returncode,code,result.stdout+result.stderr);return json.loads(result.stdout)
    def test_actual_physical_fixture_cli_selected_plan_verify_and_metadata_preservation(self):
        before,_=self.M.database_snapshot(self.db);assessment=self.root/'assessment.json';plan=self.root/'plan.json'
        self.cli('assess','--root',self.root,'--dbpath',self.db,'--protect','fixture-user-protected','--output',assessment)
        report=json.loads(assessment.read_bytes());self.assertEqual(report['candidates'],['fixture-leaf','fixture-oldprovider'])
        rows=report['packages'];self.assertEqual(rows['fixture-consumer']['satisfiers']['depends']['fixture-virtual>=2'],'fixture-provider')
        self.assertEqual(rows['fixture-optional']['optional_required_by'],['fixture-app']);self.assertEqual(rows['fixture-cycle-a']['required_by'],['fixture-cycle-b'])
        self.assertTrue(all(rows[n]['protected'] for n in ('glibc','linux-asahi','fixture-user-protected')))
        self.cli('plan',assessment,'--select','fixture-leaf','--select','fixture-oldprovider','--output',plan)
        self.assertEqual(self.cli('verify',plan)['verification'],'PASS_CURRENT_METADATA_ONLY')
        for name in ('fixture-provider','fixture-optional','fixture-cycle-a','fixture-manual','glibc','linux-asahi','fixture-user-protected','fixture-missing'):
            with self.subTest(name=name):self.cli('plan',assessment,'--select',name,'--output',self.root/('refused-'+name),code=1)
        self.assertEqual(self.M.database_snapshot(self.db)[0],before);self.assertFalse((self.db/'db.lck').exists())
    def test_actual_counterpart_lock_refusal_preserves_lock_and_nonlock_bytes(self):
        before,_=self.M.database_snapshot(self.db);holder=self.M.Installed(self.root,self.db);owned=False
        try:
            for name in ('alpm_trans_init','alpm_trans_release'):
                function=getattr(holder.lib,name);function.argtypes=[ctypes.c_void_p,ctypes.c_int] if name.endswith('init') else [ctypes.c_void_p];function.restype=ctypes.c_int
            self.assertEqual(holder.lib.alpm_trans_init(holder.handle,0),0);owned=True;held=self.M.identity((self.db/'db.lck').lstat())
            self.assertIn('ALPM lock',self.cli('assess','--root',self.root,'--dbpath',self.db,code=1)['reason'])
            self.assertEqual(self.M.identity((self.db/'db.lck').lstat()),held)
            for name,row in before['nodes'].items():
                if row['kind']=='file':self.assertEqual(self.M.digest((self.db/name).read_bytes()),row['sha256'])
        finally:
            if owned:self.assertEqual(holder.lib.alpm_trans_release(holder.handle),0)
            holder.close()
        self.assertFalse((self.db/'db.lck').exists())


if __name__=='__main__':unittest.main()

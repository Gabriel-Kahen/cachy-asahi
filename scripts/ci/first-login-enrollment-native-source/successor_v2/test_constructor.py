# SPDX-License-Identifier: MIT
"""Real isolated constructor CLI, temporary Source DATA only; no native actors."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
SHA=hashlib.sha256((HERE/'profile.json').read_bytes()).hexdigest()
class Controls(unittest.TestCase):
 def run_cli(self,*args,home):
  return subprocess.run([sys.executable,'-I','-B',str(HERE/'prepare.py'),*map(str,args)],cwd=home,env={'PATH':'/usr/bin:/bin','HOME':str(home),'LC_ALL':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1'},capture_output=True,timeout=15)
 def test_actual_source_cli_and_fresh_no_replace(self):
  with tempfile.TemporaryDirectory(prefix='current-onboarding-constructor-DATA-')as name:
   home=Path(name);out=home/'source'
   argv=['--root',ROOT,'--profile-sha256',SHA,'--output',out]
   result=self.run_cli(*argv,home=home);self.assertEqual(result.returncode,0,result.stderr.decode());report=json.loads(result.stdout)
   lock=json.loads((out/'source.lock.json').read_bytes());self.assertEqual(report['files'],59);self.assertEqual(report['status'],'STAGED_CURRENT_SOURCE_ONLY_NOT_NATIVE_READY')
   self.assertTrue(all(v is None for v in lock['actual'].values()))
   for path,row in lock['files'].items():
    f=out/path;raw=f.read_bytes();self.assertEqual(dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),mode=f.stat().st_mode&0o777),row)
   before={str(p.relative_to(out)):p.read_bytes()for p in out.rglob('*')if p.is_file()};again=self.run_cli(*argv,home=home);self.assertNotEqual(again.returncode,0);self.assertEqual(before,{str(p.relative_to(out)):p.read_bytes()for p in out.rglob('*')if p.is_file()})
 def test_default_missing_and_bad_profile_refuse_without_output(self):
  with tempfile.TemporaryDirectory(prefix='current-onboarding-refusal-DATA-')as name:
   home=Path(name);out=home/'source';result=self.run_cli(home=home);self.assertNotEqual(result.returncode,0)
   result=self.run_cli('--root',ROOT,'--profile-sha256','0'*64,'--output',out,home=home);self.assertNotEqual(result.returncode,0);self.assertFalse(out.exists())
if __name__=='__main__':unittest.main(verbosity=2)

# SPDX-License-Identifier: MIT
"""Finite Source-top-level/benign-loader seams, never an actual Reader role."""
import argparse,importlib.util,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent;SOURCE=None
s=importlib.util.spec_from_file_location('math_successor_controls',HERE/'reader.py');M=importlib.util.module_from_spec(s);s.loader.exec_module(M)

def code():return {str(SOURCE/n):(SOURCE/n).read_bytes()for n in M.SOURCE}
class Controls(unittest.TestCase):
 def test_exact_six_source_import_declarations(self):M.code_contract(code())
 def test_wrong_code_body_refuses(self):
  c=code();name=next(iter(c));c[name]+=b'\n# changed\n'
  with self.assertRaisesRegex(ValueError,'body'):M.code_contract(c)
 def test_missing_or_extra_module_refuses(self):
  c=code();c.pop(next(iter(c)))
  with self.assertRaisesRegex(ValueError,'six'):M.code_contract(c)
  c=code();c[str(SOURCE/'unreviewed.py')]=b'import math\n'
  with self.assertRaisesRegex(ValueError,'body'):M.code_contract(c)
 def test_unlisted_declaration_or_dynamic_import_refuses(self):
  for raw in (b'import socket\n',b'from subprocess import run\n',b"__import__('os')\n",b'__import__(chosen)\n'):
   with self.subTest(raw=raw),self.assertRaises(ValueError):M.declarations(raw)
 def test_math_only_preload_belongs_to_python(self):
  p=M.preload_math();self.assertEqual(p['module'],'math');self.assertGreater(p['bytes'],0);self.assertEqual(len(p['sha256']),64)
 def child(self,mode):
  script='''import importlib.util,sys,json
from pathlib import Path
s=importlib.util.spec_from_file_location('finite_math_seam',Path(sys.argv[1]));m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
r=Path(sys.argv[2]);code={str(r/n):(r/n).read_bytes()for n in m.SOURCE};before='math'in sys.modules;sys.modules.pop('math',None) # Explicit cold-import fixture, including builtin-math Python.
f=(m.BASE if sys.argv[3]=='old'else m.Fence)(set(code),code,{},set());missing=[]
def observed(event,args):
 if event=='import'and args[0]not in f.imports:missing.append(args[0])
sys.addaudithook(observed);status='PASS_SIX_TOP_LEVEL_IMPORTS_ONLY';error=None
try:
 with f:
  for n in m.SOURCE:
   spec=f.spec('finite_Source_'+n.replace('/','_').replace('.','_'),r/n);v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
except PermissionError as e:status='REFUSED';error=str(e)
print(json.dumps(dict(status=status,missing=missing,math_before=before,cold_math_fixture=True,error=error,Reader_calls=0)))
'''
  r=subprocess.run([sys.executable,'-I','-B','-Werror::ResourceWarning','-c',script,str(HERE/'reader.py'),str(SOURCE),mode],capture_output=True,timeout=20);self.assertEqual(r.returncode,0,r.stderr.decode()[:1800]);return json.loads(r.stdout)
 def test_fresh_frozen_v1_reproduces_exact_missing_math(self):
  d=self.child('old');self.assertTrue(d['cold_math_fixture']);self.assertEqual(d['status'],'REFUSED');self.assertEqual(d['missing'],['math']);self.assertEqual(d['Reader_calls'],0)
 def test_fresh_v2_all_six_top_level_imports_no_reader(self):
  d=self.child('new');self.assertTrue(d['cold_math_fixture']);self.assertEqual(d['status'],'PASS_SIX_TOP_LEVEL_IMPORTS_ONLY');self.assertEqual(d['missing'],[]);self.assertEqual(d['Reader_calls'],0)
 def test_process_and_unknown_import_remain_denied(self):
  f=M.Fence(set(code()),code(),{},set())
  for event,args in [('subprocess.Popen',('x',)),('socket.connect',('x',)),('import',('not_in_reviewed_runtime',))]:
   f.enabled=True
   try:
    with self.subTest(event=event),self.assertRaises(PermissionError):f.check(event,args)
   finally:f.enabled=False
 def test_unknown_write_and_code_still_refuse(self):
  f=M.Fence(set(code()),code(),{},set())
  with tempfile.TemporaryDirectory()as d:
   f.enabled=True
   try:
    with self.assertRaises(PermissionError):f.check('open',(str(Path(d)/'unknown'),None,os.O_WRONLY|os.O_CREAT))
    with self.assertRaises(PermissionError):f.check('compile',(b'pass',str(Path(d)/'unknown.py')))
   finally:f.enabled=False
 def test_no_generic_import_allowance_or_source_revision(self):
  self.assertEqual(M.LEGACY.S.MAP,'2bbf2c808562d13a158d654f7e7d3adb71c7e577444e82ea05a0aad5cf0f3c97');self.assertEqual(M.LEGACY.SOURCE,'445b37a9475a4e92804954f4f0e3d0ac84cd9511')
  self.assertIs(M.Fence.check,M.BASE.check);self.assertIs(M.Fence.spec,M.BASE.spec);self.assertIs(M.Fence.__enter__,M.BASE.__enter__)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);a=p.parse_args();SOURCE=a.source.resolve();result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Controls));raise SystemExit(not(result.wasSuccessful()and result.testsRun==10 and not result.skipped))

#!/usr/bin/env python3
"""Finite explicit566 emission/refusals; default563 and all native actors held."""
import argparse,importlib.util,inspect,json,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
D=Path(__file__).resolve().parent;s=importlib.util.spec_from_file_location('_ancestry_factory_controls',D/'prepare.py');P=importlib.util.module_from_spec(s);s.loader.exec_module(P);SOURCE=EXPECTED=None
class Portable(unittest.TestCase):
 def test_explicit_profile_preserves_default_and_whole563_parent(self):
  self.assertEqual(inspect.signature(P.emit).parameters['profile'].default,'fresh_descriptor563');p,expected,bodies=P.ancestry_inputs();self.assertEqual(p['before'],json.loads((D/'source563.json').read_bytes()));self.assertEqual(len(expected),566);self.assertIsNone(p['actual']);self.assertEqual(p['clocks'],'ALL_ORIGINAL_LIMITS_HELD')
 def test_optional_support_drift_refuses_before_any_output(self):
  with tempfile.TemporaryDirectory()as t:
   root=Path(t);support=root/'support';shutil.copytree(D,support);f=support/'ancestry/latest_ancestry.py';f.write_bytes(f.read_bytes()+b'\n');source=root/'input';source.mkdir();output=root/'output'
   with patch.object(P,'HERE',support),self.assertRaisesRegex(ValueError,'ancestry emission support'):P.emit(source,output,'fresh_ancestry566')
   self.assertFalse(output.exists())
class Complete:
 def test_explicit_whole566_bytes_and_original563_full_guard(self):
  with tempfile.TemporaryDirectory()as t:
   root=Path(t);output=root/'output';auth=root/'authorization.json';argv=[sys.executable,'-I','-B',str(D/'prepare.py'),'--source',str(SOURCE),'--output',str(output),'--authorization',str(auth),'--profile','fresh_ancestry566'];r=subprocess.run(argv,capture_output=True,timeout=120);self.assertEqual(r.returncode,0,r.stderr.decode());self.assertEqual(r.stdout,b'');receipt=json.loads(auth.read_bytes());self.assertEqual(receipt['status'],'SOURCE_ONLY_EXACT566_FRESH_ANCESTRY_NATIVE_FIT_UNKNOWN');self.assertEqual(P.files(output),P.files(EXPECTED));self.assertEqual(receipt['files'],P.files(EXPECTED));saved,paths=dict(sys.modules),sys.path[:]
   try:
    lane=output/'latest/implementation'
    for q in output.rglob('*.py'):sys.modules.pop(q.stem,None)
    sys.path.insert(0,str(lane));s=importlib.util.spec_from_file_location('_maintained_complete566_guard',lane/'latest_guard.py');G=importlib.util.module_from_spec(s);s.loader.exec_module(G)
    with patch.object(subprocess,'run',side_effect=AssertionError('NO_ACTORS')),patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS')):v=G.verify();self.assertEqual(v['files'],566);self.assertEqual(v['cost_original_files'],563);G.authorize()
   finally:
    sys.path[:]=paths
    for n in set(sys.modules)-set(saved):sys.modules.pop(n,None)
    sys.modules.update(saved)
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path);p.add_argument('--expected',type=Path);a=p.parse_args();p.error('source and expected together')if bool(a.source)!=bool(a.expected)else None;SOURCE=None if a.source is None else a.source.absolute();EXPECTED=None if a.expected is None else a.expected.absolute();suite=unittest.defaultTestLoader.loadTestsFromTestCase(Portable)
 if SOURCE is not None:suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(type('WholeEmission',(Complete,unittest.TestCase),{})))
 result=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(not result.wasSuccessful())

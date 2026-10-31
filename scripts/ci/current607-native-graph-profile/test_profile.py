# SPDX-License-Identifier: MIT
"""Bounded factory refusals; optional real complete-source emission joins."""
import argparse,ast,importlib.util,json,shutil,subprocess,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('_fixed_current607_profile',HERE/'prepare.py');P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
SOURCE=EXPECTED=None
class Refusals(unittest.TestCase):
 def test_wrong_source_and_unknown_profile_refuse_before_output(self):
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);source=root/'source';source.mkdir();output=root/'output'
   for profile in('fresh_descriptor563','original555','fresh_descriptor559','unbounded'):
    with self.subTest(profile=profile),self.assertRaises(ValueError):P.emit(source,output,profile)
    self.assertFalse(output.exists())
 def test_exact_runtime_support_drift_refuses_before_output(self):
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);support=root/'support';shutil.copytree(HERE,support);path=support/'latest_descriptor.py';path.write_bytes(path.read_bytes()+b'\n');source=root/'source';source.mkdir();output=root/'output'
   with patch.object(P,'HERE',support),self.assertRaisesRegex(ValueError,'support body'):P.emit(source,output,'fresh_descriptor563')
   self.assertFalse(output.exists())
class CompleteEmission:
 def emit_cli(self,root,profile=None):
  output=root/'source';authorization=root/'authorization.json';argv=[sys.executable,'-I','-B',str(HERE/'prepare.py'),'--source',str(SOURCE),'--output',str(output),'--authorization',str(authorization)]
  if profile:argv+=['--profile',profile]
  p=subprocess.run(argv,capture_output=True,timeout=120);self.assertEqual(p.returncode,0,p.stderr.decode());self.assertEqual(p.stdout,b'');return output,json.loads(authorization.read_bytes())
 def test_default_cli_exact_corrected561_and_full_source_guard(self):
  with tempfile.TemporaryDirectory()as tmp:
   output,receipt=self.emit_cli(Path(tmp));self.assertEqual(P.files(output),P.files(EXPECTED));self.assertEqual(len(receipt['files']),563);self.assertEqual(receipt['status'],'SOURCE_ONLY_EXACT563_FAILED_PUBLIC_DATA_CAPTURE_UNQUALIFIED')
   for n in receipt['files']:self.assertEqual((output/n).read_bytes(),(EXPECTED/n).read_bytes())
   saved,paths=dict(sys.modules),sys.path[:]
   try:
    lane=output/'latest/implementation';sys.path.insert(0,str(lane))
    for f in output.rglob('*.py'):sys.modules.pop(f.stem,None)
    spec=importlib.util.spec_from_file_location('_maintained_corrected561_full_guard',lane/'latest_guard.py');G=importlib.util.module_from_spec(spec);spec.loader.exec_module(G)
    with patch.object(subprocess,'run',side_effect=AssertionError('NO_ACTORS')),patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS')):self.assertEqual(G.verify()['files'],563);G.authorize()
   finally:
    sys.path[:]=paths
    for n in set(sys.modules)-set(saved):sys.modules.pop(n,None)
    sys.modules.update(saved)
 def test_explicit_cli_exact_published561_and_existing_retained_member(self):
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);output,receipt=self.emit_cli(root,'fresh_descriptor563');self.assertEqual(P.files(output),P.files(EXPECTED));self.assertEqual(len(receipt['files']),563)
   for n in receipt['files']:self.assertEqual((output/n).read_bytes(),(EXPECTED/n).read_bytes())
   # Execute the exact unchanged source-owned export function over inert receipts.
   text=(output/'latest/implementation/latest_owner.py').read_text();tree=ast.parse(text);cls=next(n for n in tree.body if isinstance(n,ast.ClassDef)and n.name=='Integration');fn=next(n for n in cls.body if isinstance(n,ast.FunctionDef)and n.name=='export_names');space={};exec(compile(ast.Module(body=[fn],type_ignores=[]),'<exact-existing-export-closure>','exec'),space)
   out=root/'public';(out/'container').mkdir(parents=True);(out/'container/latest607-graph-timing.json').write_bytes(b'{"inert":"receipt"}\n');(out/'container/not-selected.bin').write_bytes(b'not exported');owner=types.SimpleNamespace(prior=types.SimpleNamespace(export_names=lambda out:[]));self.assertEqual(space['export_names'](owner,out),['container/latest607-graph-timing.json'])
if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--source',type=Path);parser.add_argument('--expected',type=Path);a=parser.parse_args();parser.error('--source and --expected must be supplied together')if bool(a.source)!=bool(a.expected)else None;SOURCE=None if a.source is None else a.source.absolute();EXPECTED=None if a.expected is None else a.expected.absolute();suite=unittest.defaultTestLoader.loadTestsFromTestCase(Refusals)
 if SOURCE is not None:suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(type('CompleteSourceEmission',(CompleteEmission,unittest.TestCase),{})))
 result=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(not result.wasSuccessful())

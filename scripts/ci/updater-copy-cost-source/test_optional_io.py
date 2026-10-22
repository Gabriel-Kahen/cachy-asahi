"""Source emitter and real scalar-helper controls; no updater actors."""
import ast,importlib.util,json,os,shutil,subprocess,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
import optional_io as O
F=O.F;PARENT=Path(os.environ['UPDATER_OPTIONAL_PARENT']);EXPECTED=Path(os.environ['UPDATER_OPTIONAL_EXPECTED']);LANE='scripts/ci/current604-public-pair-updater16k'

def helper(source):
 text=(source/LANE/'adapter.py').read_text()
 descriptor=ast.literal_eval(next(n.value for n in ast.parse(text).body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='DRIVER_DESCRIPTOR_SOURCE'for t in n.targets)))
 node=next(n for n in ast.walk(ast.parse(descriptor))if isinstance(n,ast.Call)and isinstance(n.func,ast.Name)and n.func.id=='compile')
 return ast.literal_eval(node.args[0])

def cost(source):
 m=types.ModuleType('_fixed_scalar_cost');exec(compile(helper(source),'<fixed-scalar-cost>','exec'),m.__dict__);return m

class Controls(unittest.TestCase):
 def test_whole_emission_and_real_isolated_cli(self):
  self.assertEqual(F.pins(F.tree(EXPECTED,checkout=True)),O.profile()['after'])
  with tempfile.TemporaryDirectory()as td:
   out=Path(td)/'source';p=subprocess.run([sys.executable,'-I','-B','-Werror',str(HERE/'optional_io.py'),'--parent',str(PARENT),'--output',str(out)],capture_output=True,timeout=30,check=True)
   self.assertEqual(p.stderr,b'');self.assertFalse(json.loads(p.stdout)['acceptance']);self.assertEqual(F.tree(out),F.tree(EXPECTED,checkout=True))
 def test_checkout_metadata_does_not_enter_complete_source_comparison(self):
  with tempfile.TemporaryDirectory()as td:
   checkout=Path(td)/'checkout';shutil.copytree(EXPECTED,checkout,ignore=shutil.ignore_patterns('.git'))
   (checkout/'.git').mkdir();(checkout/'.git/config').write_text('[core]\nrepositoryformatversion = 0\n')
   with patch.dict(globals(),{'EXPECTED':checkout}):self.test_whole_emission_and_real_isolated_cli()
 def test_parent_payload_profile_drift_and_alias_refuse_before_output(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);parent=root/'parent';shutil.copytree(PARENT,parent);out=root/'out'
   for mode in('drift','missing','extra'):
    p=parent/'LICENSE';raw=(PARENT/'LICENSE').read_bytes()
    if mode=='drift':p.write_bytes(raw+b'x')
    elif mode=='missing':p.unlink()
    else:p.write_bytes(raw);(parent/'foreign').write_bytes(b'x')
    with self.assertRaisesRegex(ValueError,'whole pinned'):O.emit(parent,out)
    self.assertFalse(out.exists())
    if not p.exists()or mode=='drift':p.write_bytes(raw)
   with self.assertRaisesRegex(ValueError,'fresh output'):O.emit(PARENT,PARENT)
   link=root/'link';link.symlink_to(PARENT,target_is_directory=True)
   with self.assertRaisesRegex(ValueError,'ordinary source'):O.emit(link,out)
   factory=root/'factory';shutil.copytree(HERE,factory)
   with patch.object(O,'HERE',factory):
    p=next(p for p in(factory/'optional-io-payload').rglob('*')if p.is_file());raw=p.read_bytes();p.write_bytes(raw+b'x')
    with self.assertRaisesRegex(ValueError,'whole five'):O.emit(PARENT,out)
    self.assertFalse(out.exists());p.write_bytes(raw);(factory/'optional-io-profile.json').write_bytes(b'{}')
    with self.assertRaisesRegex(ValueError,'whole optional'):O.emit(PARENT,out)
    self.assertFalse(out.exists())
 def test_actual_missing_io_old_silent_new_clocks_and_exception_preserved(self):
  opening=os.open
  def missing(path,*a,**k):
   if str(path)=='/proc/self/io':raise FileNotFoundError()
   return opening(path,*a,**k)
  output=[]
  with patch.object(os,'open',missing),patch.object(os,'write',side_effect=lambda fd,raw:output.append(raw)or len(raw)):
   cost(PARENT).cost('COPY','BEGIN');self.assertEqual(output,[])
   m=cost(EXPECTED)
   for _ in range(20):m.cost('COPY','POINT')
  self.assertEqual(len(output),12);self.assertLessEqual(sum(map(len,output)),3072)
  rows=[json.loads(raw.split(b' ',1)[1])for raw in output];self.assertTrue(all(len(r)==17 and r[0]==2 and r[9:16]==[-1]*7 for r in rows));self.assertEqual([r[1]for r in rows],list(range(1,13)))
  before,after=helper(PARENT),helper(EXPECTED)
  for name in('bind',):
   nodes=lambda s:next(n for n in ast.parse(s).body if isinstance(n,ast.FunctionDef)and n.name==name)
   self.assertEqual(ast.get_source_segment(before,nodes(before)),ast.get_source_segment(after,nodes(after)))
 def test_available_zero_accounting_is_distinct_from_unknown(self):
  m=cost(EXPECTED);seen=[];opening=os.open
  with tempfile.TemporaryDirectory()as td:
   p=Path(td)/'io';p.write_text(''.join(k+': 17\n'for k in m.COLUMNS[5:]))
   def available(path,*a,**k):return opening(p if str(path)=='/proc/self/io'else path,*a,**k)
   with patch.object(os,'open',available),patch.object(os,'write',side_effect=lambda fd,raw:seen.append(raw)or len(raw)):m.cost('COPY','BEGIN');m.cost('COPY','END')
  rows=[json.loads(raw.split(b' ',1)[1])for raw in seen];self.assertEqual(len(rows),2);self.assertTrue(all(r[9:16]==[0]*7 for r in rows))

if __name__=='__main__':unittest.main(verbosity=2)

"""Frozen Source387 projection/delivery controls; no actor or live observation."""
import ast,copy,hashlib,importlib.util,json,os,shutil,stat,tempfile,time,types,unittest
from pathlib import Path
from unittest.mock import Mock,patch
HERE=Path(__file__).resolve().parent
FAMILY=HERE.parent/'arm16k_perl_guest_hold_qmp_successor'
SOURCE=Path('/home/gabe/Documents/ChatGPT/cachy-asahi-perl-ldcache-lifecycle-successor-readiness-20261117-r2/constructed-source')
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
T=load('source387_qmp_transform',FAMILY/'transform.py')
def canonical(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def rows(files):return{n:dict(**T.pin(raw),mode=mode)for n,(raw,mode)in sorted(files.items())}

class Projection(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.lock=json.loads((SOURCE/'source.lock.json').read_bytes());cls.old={}
  for name,want in cls.lock['files'].items():
   path=SOURCE/name;raw=path.read_bytes();mode=stat.S_IMODE(path.stat().st_mode)
   if dict(**T.pin(raw),mode=mode)!=want:raise ValueError('genuine Source387 leaf drift')
   cls.old[name]=(raw,mode)
  cls.old['source.lock.json']=((SOURCE/'source.lock.json').read_bytes(),0o644)
  if T.pin(cls.old['source.lock.json'][0])!={'bytes':69318,'sha256':'06d227647cbbf5d357bcccccc77dde07344bea033880a87b5405e9679810b443'}:raise ValueError('genuine387lock')
  cls.controller=T.transform_controller(cls.old['controller.py'][0]);cls.adapter=T.transform_adapter(cls.old['adapter.py'][0]);cls.body=(FAMILY/T.MODULE).read_bytes()
 def test_whole387_inverse_and_unchanged_other_leaves(self):
  projected=dict(self.old,**{'controller.py':(self.controller,0o644),'adapter.py':(self.adapter,0o644),T.MODULE:(self.body,0o644)})
  projected['source.lock.json']=(canonical(dict(self.lock,files=rows({n:r for n,r in projected.items()if n!='source.lock.json'}))),0o644)
  restored=dict(projected);restored.pop(T.MODULE);restored['controller.py']=(T.inverse_controller(self.controller),0o644);restored['adapter.py']=(T.inverse_adapter(self.adapter),0o644)
  restored['source.lock.json']=(canonical(dict(self.lock,files=rows({n:r for n,r in restored.items()if n!='source.lock.json'}))),0o644)
  self.assertEqual(restored,self.old);self.assertEqual(len(restored),387)
  self.assertEqual(sum(len(b)for b,_ in restored.values()),4106688)
  self.assertEqual({n for n in self.old if n!='source.lock.json'and self.old[n]!=projected[n]},{'controller.py','adapter.py'})
  self.assertLessEqual(sum(len(b)for b,_ in projected.values()),4194304)
 def test_five_second_quit_and_natural_retirement_requirements_unchanged(self):
  def selected(raw):
   tree=ast.parse(raw);f=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='normal_hold_cleanup');calls=[n for n in ast.walk(f)if isinstance(n,ast.Call)]
   return[ast.dump(n)for n in calls if isinstance(n.func,ast.Name)and n.func.id=='quit_hold_qmp'or isinstance(n.func,ast.Attribute)and isinstance(n.func.value,ast.Name)and n.func.value.id=='K'and n.func.attr=='need']
  self.assertEqual(selected(self.old['controller.py'][0]),selected(self.controller));compile(self.controller,'projected-controller-only','exec')
 def test_preimage_or_projected_drift_refuses_exact_inverse(self):
  for function,body in((T.transform_controller,self.old['controller.py'][0]),(T.transform_adapter,self.old['adapter.py'][0]),(T.inverse_controller,self.controller),(T.inverse_adapter,self.adapter)):
   with self.subTest(function=function.__name__),self.assertRaises(ValueError):function(body+b'\n')
 def fixture(self,directory):
  root=Path(directory)/'source';root.mkdir();(root/'adapter.py').write_bytes(self.adapter)
  for n in('contracts.py','preboot.py','expected-cache-transition.tsv'):shutil.copyfile(SOURCE/n,root/n)
  for n in('guest','frozen'):shutil.copytree(SOURCE/n,root/n)
  (root/T.MODULE).write_bytes(self.body);(root/T.MODULE).chmod(0o644)
  K=load('source387_model_contracts',SOURCE/'contracts.py');tree=ast.parse((SOURCE/'test_controls.py').read_text());defs=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name in('pin','seal','modeled')]
  env=dict(K=K,HERE=SOURCE,Path=Path,copy=copy,time=time,hashlib=hashlib,os=os);exec(compile(ast.Module(body=defs,type_ignores=[]),'maintained-synthetic-factory','exec'),env)
  a=env['modeled'](dependency=True);cert=dict(zip(K.EVIDENCE,a[2:]));cert['_initialized_state']={'MODEL_ONLY':True};cert['_initialized_qualified']={'proof':{'MODEL_ONLY':True}}
  A=load('source387_exact_delivery_adapter',root/'adapter.py');fixture=A.contents(a[0],cert,env['pin']('MODEL_source'),'a'*32);out=Path(directory)/'fixture';out.mkdir()
  for n,(raw,mode)in fixture.items():
   p=out/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw);p.chmod(mode)
  return root,out,fixture,K
 def binder(self,root,K):
  tree=ast.parse(self.controller);f=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='bind_hold_observer')
  env=dict(module=lambda name:K,HERE=root,stat=stat,importlib=__import__('importlib'));exec(compile(ast.Module(body=[f],type_ignores=[]),'<fixed-delivery-loader>','exec'),env);return env['bind_hold_observer']
 def test_actual_adapter_contents_delivers_exact_module_and_cache_manifest(self):
  with tempfile.TemporaryDirectory()as d:
   root,out,fixture,K=self.fixture(d);self.assertEqual(fixture[T.MODULE],(self.body,0o644));self.assertEqual((out/T.MODULE).read_bytes(),self.body);self.assertEqual(stat.S_IMODE((out/T.MODULE).stat().st_mode),0o644)
   self.assertEqual((out/'expected-cache-transition.tsv').read_bytes(),(SOURCE/'expected-cache-transition.tsv').read_bytes())
   self.assertEqual(self.adapter.count(T.ADAPTER_ADDITION.encode()),1)
 def test_controller_loads_only_exact_delivered_fixed_path(self):
  with tempfile.TemporaryDirectory()as d:
   root,out,fixture,K=self.fixture(d);binder=self.binder(root,K);peer,serial,token=object(),object(),object();calls=[];binding=Mock(return_value=token);original=importlib.util.spec_from_file_location
   def spec(name,path):
    calls.append(Path(path));value=original(name,path);execute=value.loader.exec_module
    def execute_with_mock_probe(module):execute(module);module.Binding=binding
    value.loader.exec_module=execute_with_mock_probe;return value
   packet=dict(files=rows(fixture))
   with patch.object(importlib.util,'spec_from_file_location',side_effect=spec):self.assertIs(binder(peer,serial,out,packet),token)
   self.assertEqual(calls,[out/T.MODULE]);binding.assert_called_once_with(peer,serial)
 def test_changed_delivery_bytes_mode_or_membership_refuses_before_import(self):
  for change in('bytes','mode','membership'):
   with self.subTest(change=change),tempfile.TemporaryDirectory()as d:
    root,out,fixture,K=self.fixture(d);packet=dict(files=rows(fixture))
    if change=='bytes':(out/T.MODULE).write_bytes(self.body+b'\n')
    elif change=='mode':(out/T.MODULE).chmod(0o755)
    else:packet['files'].pop(T.MODULE)
    with patch.object(importlib.util,'spec_from_file_location',side_effect=AssertionError('must refuse before import')):
     with self.assertRaises(ValueError):self.binder(root,K)(None,None,out,packet)

if __name__=='__main__':unittest.main(verbosity=2)

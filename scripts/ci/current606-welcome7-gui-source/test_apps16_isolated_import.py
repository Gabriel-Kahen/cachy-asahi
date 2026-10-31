# SPDX-License-Identifier: MIT
"""Portable whole565 source reproduction and inert isolated startup regression."""
import argparse,ast,copy,importlib.util,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;p=argparse.ArgumentParser()
for n in('parent','expected','apps16-parent','cleanup'):p.add_argument('--'+n,type=Path,required=True)
a,rest=p.parse_known_args();PARENT,EXPECTED,APPS16,CLEANUP=(getattr(a,n).absolute()for n in('parent','expected','apps16_parent','cleanup'))
def load(n,p):s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
F=load('_maintained_isolated_factory',HERE/'prepare.py');M=load('_finite_isolated_source',HERE/'apps16_isolated_import.py');PROFILE,MAPS,PAYLOAD=M.inputs(F.__dict__)
FIXTURE_PROFILE={'bytes': 24880, 'sha256': '8914bc9335c0e5d900107baf4d0060d0026d0b335ccc83dfcae0a11d993b480c'}
STARTUP_PROBE={'bytes': 3693, 'sha256': '9949fef7585f8422d61d0f21a75eb6f46102ec2120dcf1b8e3d347b3ec111420'}
class Controls(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.temp=tempfile.TemporaryDirectory();cls.addClassCleanup(cls.temp.cleanup);cls.root=Path(cls.temp.name);cls.null561=cls.root/'null561';cls.null562=cls.root/'null562';cls.bound=cls.root/'bound';cls.null=cls.root/'null';F.prepare_apps16(CLEANUP,cls.null561,True);F.prepare_apps16_restore604(cls.null561,cls.null562,True);F.prepare_apps16_isolated_import(PARENT,cls.bound);F.prepare_apps16_isolated_import(cls.null562,cls.null,True)
 def test_exact_whole_selected_NULL_and_old_restore_route_outputs(self):
  self.assertEqual(F.files(self.bound),F.files(EXPECTED));self.assertEqual({n:F.pin(b)for n,b in F.files(self.null).items()},MAPS['unbound']);old=self.root/'old-restore';F.prepare_apps16_restore604(APPS16,old);self.assertEqual(F.files(old),F.files(PARENT));self.assertEqual({n:F.pin(b)for n,b in F.files(self.null562).items()},MAPS['null_before'])
 def test_all_old_functions_routes_and_whole_source_entry_security_inverse(self):
  text=(HERE/'prepare.py').read_text();functions={n.name:F.pin(ast.get_source_segment(text,n).encode())for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)}
  for n,w in PROFILE['held_functions'].items():self.assertEqual(functions[n],w,n)
  self.assertEqual(F.profile()['output']['source'],'bb72a0fc5e84af5621f0b783056137efdd780282')
  for root,null in((self.bound,False),(self.null,True)):
   A=load('_trusted_maintained_isolated_'+str(null),root/'admission.py')
   with patch.object(subprocess,'run',side_effect=AssertionError('NO_ACTORS')),patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS')):
    fact=A.source_context(root);self.assertEqual(fact['files'],565);self.assertEqual(fact['cleanup'],'ORIGINAL_POSITIVE15_AND_FAILURE_RESOURCE_RETIREMENT_HELD')
    if null:
     with self.assertRaisesRegex(ValueError,'BEFORE ACTORS'):A.prove(root)
    else:self.assertEqual(A.prove(root)['status'],'PASS_WHOLE565_ISOLATED_STARTUP_AND_ALL564_562_SOURCE_GATES')
 def test_actual_isolated_factory_CLI_variants_and_mutual_exclusion(self):
  for flag,parent,expected in(('--apps16-isolated-import',PARENT,self.bound),('--apps16-isolated-import-unbound',self.null562,self.null)):
   out=self.root/flag[2:];argv=[sys.executable,'-I','-B','-Werror',str(HERE/'prepare.py'),flag,'--predecessor-root',str(parent),'--output',str(out)];r=subprocess.run(argv,capture_output=True,cwd='/',timeout=30);self.assertEqual((r.returncode,r.stderr),(0,b''));self.assertEqual(F.files(out),F.files(expected));self.assertIsNone(json.loads(r.stdout)['actual_run']);self.assertEqual(json.loads(r.stdout)['native_fit'],'UNKNOWN');self.assertNotEqual(subprocess.run(argv,capture_output=True,timeout=30).returncode,0)
  argv=[sys.executable,'-I','-B',str(HERE/'prepare.py'),'--apps16-isolated-import','--apps16-restore604','--predecessor-root',str(PARENT),'--output',str(self.root/'never')];self.assertNotEqual(subprocess.run(argv,capture_output=True,timeout=10).returncode,0);self.assertFalse((self.root/'never').exists())
 def test_wrong_variant_alias_hardlink_output_and_prewrite_drift_refusals(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);out=root/'never';alias=root/'alias';alias.symlink_to(PARENT,target_is_directory=True)
   for parent,dest,null in((alias,out,False),(PARENT,PARENT/'never',False),(PARENT,root/'missing/../bad',False),(PARENT,out,True),(self.null562,out,False),(PARENT,out,1),(PARENT,HERE/'never',False)):
    with self.assertRaises((ValueError,OSError)):M.emit(F.__dict__,parent,dest,null)
   src=root/'parent';shutil.copytree(PARENT,src,ignore=shutil.ignore_patterns('.git'));leaf=src/'native.py';raw=leaf.read_bytes();leaf.write_bytes(raw+b'drift')
   with self.assertRaises(ValueError):M.emit(F.__dict__,src,out)
   leaf.write_bytes(raw);os.link(leaf,root/'linked')
   with self.assertRaises(ValueError):M.emit(F.__dict__,src,out)
   self.assertFalse(out.exists())
 def test_profile_payload_and_late_whole_input_drift_before_output(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);factory=root/'factory';shutil.copytree(HERE,factory);out=root/'never'
   for n in('apps16-isolated-import-profile.json','apps16-isolated-import-maps.json',*('apps16-isolated-import-payload/'+n for n in PAYLOAD)):
    leaf=factory/n;raw=leaf.read_bytes();leaf.write_bytes(raw+b'drift')
    with patch.object(M,'HERE',factory),self.assertRaises(ValueError):M.emit(F.__dict__,PARENT,out)
    self.assertFalse(out.exists());leaf.write_bytes(raw)
   src=root/'parent';shutil.copytree(PARENT,src,ignore=shutil.ignore_patterns('.git'));calls=0;read=F.files
   def late(path):
    nonlocal calls
    if path==src:
     calls+=1
     if calls==2:(src/'native.py').write_bytes((src/'native.py').read_bytes()+b'drift')
    return read(path)
   with patch.dict(F.__dict__,files=late),self.assertRaisesRegex(ValueError,'revalidation'):M.emit(F.__dict__,src,out)
   self.assertEqual(calls,2);self.assertFalse(out.exists())
 def test_four_exact_code_fixtures_actual_loader_transform_and_fresh_isolated_startup(self):
  raw=F.ordinary(HERE/'apps16-isolated-import-fixture.json');self.assertEqual(F.pin(raw),FIXTURE_PROFILE);self.assertEqual(F.pin(F.ordinary(HERE/'isolated_startup_probe.py')),STARTUP_PROBE);spec=json.loads(raw);fixtures=HERE/'apps16-isolated-import-fixtures';self.assertEqual({n:F.pin(b)for n,b in F.files(fixtures).items()},spec['files']);self.assertEqual(len(spec['cases']),4);factory=load('_actual_final565_factory',self.bound/'factory/factory.py');tree=ast.parse(F.ordinary(self.bound/'factory/factory.py'));transform=copy.deepcopy(next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='transform'));self.assertEqual(type(transform.body[-3]),ast.For);self.assertEqual(type(transform.body[-2]),ast.Expr);self.assertEqual(type(transform.body[-1]),ast.Return);transform.name='startup_only';transform.body=transform.body[:2]+transform.body[-3:];scope=dict(vars(factory));exec(compile(ast.fix_missing_locations(ast.Module(body=[transform],type_ignores=[])),'<actual-final-factory-loader-nodes>','exec'),scope);proof=[]
  shadow=self.root/'shadow';shadow.mkdir();(shadow/'post_session.py').write_text("raise AssertionError('ambient module must not load')\n")
  for case,row in spec['cases'].items():
   before=self.root/('fixture-before-'+case);before.mkdir()
   for n in row['before']:
    source=fixtures/'common'/n if n in spec['common']else fixtures/case/n;shutil.copyfile(source,before/n)
   self.assertEqual({n:F.pin(b)for n,b in F.files(before).items()},row['before']);after=self.root/('fixture-after-'+case);shutil.copytree(before,after);scope['startup_only'](after,case.split('-',1)[1]);self.assertEqual({n:F.pin(b)for n,b in F.files(after).items()},row['proposed'])
   for role,root,expect in(('before',before,'old-missing'),('proposed',after,'fixed')):
    shutil.copyfile(root/'desktop574_guest.py',root/'guest.py')
    for entry in('guest.py','doctor_worker.py','service_outcome.py'):
     argv=[sys.executable,'-I','-B','-Werror',str(HERE/'isolated_startup_probe.py'),'--root',str(root),'--entry',entry,'--expect',expect];r=subprocess.run(argv,cwd=shadow,env=dict(os.environ,PYTHONPATH=str(shadow)),capture_output=True,timeout=10);self.assertEqual((r.returncode,r.stderr),(0,b''));v=json.loads(r.stdout);self.assertEqual(v['sys_path'],'UNCHANGED');proof.append(dict(case=case,role=role,result=v))
  self.assertEqual(len(proof),24)
  if os.environ.get('GUI_ISOLATED_MAINTAINED_PROOF'):
   with Path(os.environ['GUI_ISOLATED_MAINTAINED_PROOF']).open('xb')as stream:stream.write(F.encoded(dict(status='PASS_ALL_FOUR_PRIVATE_CODE_FIXTURES_REAL_FACTORY_NODES_AND_FRESH_ISOLATED_STARTUP',rows=proof,actors='NOT_RUN',native_GUI='NOT_RUN')))
if __name__=='__main__':unittest.main(argv=[sys.argv[0],*rest],verbosity=2)

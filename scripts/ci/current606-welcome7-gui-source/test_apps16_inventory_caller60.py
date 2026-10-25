# SPDX-License-Identifier: MIT
"""Portable source570 caller60 reproduction; only public562 and570 are inputs."""
import argparse,ast,copy,importlib.util,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;p=argparse.ArgumentParser();p.add_argument('--parent',type=Path,required=True);p.add_argument('--expected',type=Path,required=True);a,rest=p.parse_known_args();PARENT,EXPECTED=a.parent.absolute(),a.expected.absolute()
def load(n,p):s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
F=load('_maintained_caller60_factory',HERE/'prepare.py');M=load('_finite_caller60_source',HERE/'apps16_inventory_caller60.py');PROFILE,MAPS,PAYLOAD,I,ISOLATED=M.inputs(F.__dict__)
class Controls(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.temp=tempfile.TemporaryDirectory();cls.addClassCleanup(cls.temp.cleanup);cls.root=Path(cls.temp.name);cls.known=cls.root/'known570';cls.null=cls.root/'NULL570';cls.results=[F.prepare_apps16_inventory_caller60(PARENT,cls.known),F.prepare_apps16_inventory_caller60(PARENT,cls.null,True)]
 def test_exact_whole_known_NULL_only_public562_and_old565_route_parity(self):
  self.assertEqual(F.files(self.known),F.files(EXPECTED));self.assertEqual({n:F.pin(b)for n,b in F.files(self.null).items()},MAPS['unbound']);old=self.root/'old565';F.prepare_apps16_isolated_import(PARENT,old);self.assertEqual({n:F.pin(b)for n,b in F.files(old).items()},ISOLATED[1]['selected'])
  for result in self.results:
   self.assertTrue(all(result[k]is None for k in('actual','actual_source','actual_ref','actual_run','current_source','current_ref','current_run')));self.assertEqual(result['acceptance'],'NOT_GRANTED');self.assertEqual(result['old35_fit'],'NOT_ESTABLISHED');self.assertEqual(result['M2_performance'],'NOT_RUN')
  for name in('factory/apps16_runtime.py','factory/apps16_diagnostic.py','factory/apps16-installed-profile.json'):self.assertEqual(F.ordinary(self.known/name),F.ordinary(old/name))
 def test_entire_old_prepare_main_functions_defaults_and_modules_held(self):
  text=F.ordinary(HERE/'prepare.py').decode();self.assertEqual(F.pin(M.main_inverse(F.__dict__,text).encode()),PROFILE['old_prepare']);functions={n.name:F.pin(ast.get_source_segment(text,n).encode())for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)}
  for name,w in PROFILE['held_functions'].items():self.assertEqual(functions[name],w,name)
  self.assertEqual(F.profile()['output']['source'],'bb72a0fc5e84af5621f0b783056137efdd780282');self.assertEqual(PROFILE['caps']['product_scan'],30);self.assertEqual(PROFILE['caps']['default_caller'],35);self.assertEqual(PROFILE['caps']['service'],1200);self.assertEqual(PROFILE['caps']['profile'],1080);self.assertEqual(PROFILE['caps']['fullscan'],600)
 def test_complete_source_entry_known_NULL_and_all_older_guards(self):
  for root,null in((self.known,False),(self.null,True)):
   A=load('_trusted_caller60_admission_'+str(null),root/'admission.py')
   with patch.object(subprocess,'run',side_effect=AssertionError('NO_ACTORS_API_GIT')),patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS_API_GIT')):
    value=A.source_context(root);self.assertEqual((value['files'],value['inventory_caller_seconds'],value['inventory_product_seconds'],value['default_caller_seconds']),(570,60,30,35));self.assertEqual(value['cleanup'],'ORIGINAL_POSITIVE15_AND_FAILURE_RESOURCE_RETIREMENT_HELD')
    if null:
     with self.assertRaisesRegex(ValueError,'BEFORE ACTORS'):A.prove(root)
    else:self.assertEqual(A.prove(root)['status'],'PASS_COMPLETE568_AND_FIXED_PRESECRET_PROFILE_CONTROLS_SOURCE_ONLY')
 def test_actual_isolated_CLI_modes_mutual_exclusion_and_existing_output(self):
  for flag,expected in(('--apps16-inventory-caller60',self.known),('--apps16-inventory-caller60-unbound',self.null)):
   output=self.root/flag[2:];argv=[sys.executable,'-I','-B','-Werror',str(HERE/'prepare.py'),flag,'--predecessor-root',str(PARENT),'--output',str(output)];r=subprocess.run(argv,cwd='/',capture_output=True,timeout=30);self.assertEqual((r.returncode,r.stderr),(0,b''));self.assertEqual(F.files(output),F.files(expected));self.assertIsNone(json.loads(r.stdout)['actual_run']);self.assertNotEqual(subprocess.run(argv,capture_output=True,timeout=30).returncode,0)
  output=self.root/'never-cli';r=subprocess.run([sys.executable,'-I','-B',str(HERE/'prepare.py'),'--apps16-inventory-caller60','--apps16-isolated-import','--predecessor-root',str(PARENT),'--output',str(output)],capture_output=True,timeout=10);self.assertNotEqual(r.returncode,0);self.assertFalse(output.exists())
 def test_source_profile_identity_and_real_private_FD_stage65_not_product_limit(self):
  cap=load('_source_owned_capacity',self.known/'factory/inventory_capacity.py');old=load('_held_default35',self.known/'factory/apps16_diagnostic.py');new=cap.diagnostic();profile=json.loads(F.ordinary(self.known/'factory/apps16-installed-profile.json'));tag=cap.annotation();before=dict(status='ACTUAL_INSTALLED_APPS16_AND_UNCHANGED_RUNTIME1_SOURCE_BYTES',version='0.1.0-16',recipe_source=profile['recipe_source'],files={**profile['payload'],**profile['runtime']},inventory_limit_seconds=30,GUI_command_limit_seconds=60,required_fresh_scans=2,inventory_validation_profile=tag);runtime=cap.runtime();runtime.validate(before,copy.deepcopy(before))
  for field,value in(('GUI_command_limit_seconds',35),('inventory_limit_seconds',60),('inventory_validation_profile',None)):
   bad=dict(before,**{field:value})
   with self.assertRaises(ValueError):runtime.validate(bad,bad)
  # Typed policy fixture only; no invented installed observation is claimed.
  with self.assertRaises(FileNotFoundError):runtime.observe(self.root/'missing-installed-prefix')
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);root.chmod(0o700);leaf=root/'inventory.json.stage.json';doc=dict(schema=1,status='DONE',phase='DONE',sequence=14,elapsed_seconds=55,authority='DIAGNOSTIC_ONLY_NOT_ACCEPTANCE');raw=(json.dumps(doc,sort_keys=True,indent=2,ensure_ascii=True)+'\n').encode();leaf.write_bytes(raw);leaf.chmod(0o600);fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
   try:
    with self.assertRaises(ValueError):old.retire(fd,root,leaf.name)
    self.assertTrue(leaf.exists());value=new.retire(fd,root,leaf.name);self.assertTrue(value['retired']);self.assertEqual(value['file'],F.pin(raw));self.assertFalse(leaf.exists())
    for seconds in(65.001,True,float('inf')):
     with self.assertRaises(ValueError):new.validate(dict(doc,elapsed_seconds=seconds))
   finally:os.close(fd)
   helper=root/'inventory_capacity.py';helper.write_bytes(F.ordinary(self.known/'factory/inventory_capacity.py'));m=load('_private_bad_profile',helper)
   for field,value in(('caller_seconds',45),('schema_version',True),('actual',1)):
    bad=copy.deepcopy(cap.SPEC);bad[field]=value;(root/'inventory-vm-profile.json').write_bytes(F.encoded(bad))
    with self.assertRaises(ValueError):m.profile()
 def test_alias_hardlink_wrong_profile_and_late_input_operands_refuse_before_writes(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);output=root/'never';alias=root/'alias';alias.symlink_to(PARENT,target_is_directory=True)
   for parent,out,unbound in((alias,output,False),(PARENT,PARENT/'never',False),(PARENT,HERE/'never',False),(PARENT,root/'missing/../never',False),(PARENT,output,1)):
    with self.assertRaises((ValueError,OSError)):M.emit(F.__dict__,parent,out,unbound)
   source=root/'public562';shutil.copytree(PARENT,source,ignore=shutil.ignore_patterns('.git'));calls=0;original=F.files
   def late(path):
    nonlocal calls
    if path==source:
     calls+=1
     if calls==2:(source/'native.py').write_bytes((source/'native.py').read_bytes()+b'drift')
    return original(path)
   with patch.dict(F.__dict__,files=late),self.assertRaisesRegex(ValueError,'revalidation'):M.emit(F.__dict__,source,output)
   self.assertEqual(calls,2);self.assertFalse(output.exists());shutil.rmtree(source);shutil.copytree(PARENT,source,ignore=shutil.ignore_patterns('.git'));os.link(source/'native.py',root/'linked')
   with self.assertRaises(ValueError):M.emit(F.__dict__,source,output)
   factory=root/'factory';shutil.copytree(HERE,factory)
   for n in('apps16-inventory-caller60-profile.json','apps16-inventory-caller60-maps.json','apps16-inventory-caller60-payload/inventory_capacity.py','apps16-inventory-caller60-payload/inventory_presecret_controls.py','apps16-inventory-caller60-payload/presecret-admission.fragment','apps16_restore604.py'):
    path=factory/n;raw=path.read_bytes();path.write_bytes(raw+b'drift')
    with patch.object(M,'HERE',factory),self.assertRaises(ValueError):M.emit(F.__dict__,PARENT,output)
    self.assertFalse(output.exists());path.write_bytes(raw)
   actual=F.ordinary;reads=0;target=HERE/'apps16-inventory-caller60-payload/inventory_capacity.py'
   def drift(path,*args):
    nonlocal reads
    raw=actual(path,*args)
    if path==target:
     reads+=1
     if reads==2:return raw+b'drift'
    return raw
   with patch.dict(F.__dict__,ordinary=drift),self.assertRaises(ValueError):M.emit(F.__dict__,PARENT,output)
   self.assertEqual(reads,2);self.assertFalse(output.exists())
if __name__=='__main__':unittest.main(argv=[sys.argv[0],*rest],verbosity=2)

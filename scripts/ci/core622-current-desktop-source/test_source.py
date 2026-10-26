# SPDX-License-Identifier: MIT
"""Public-source factory controls; no actors or parent programs are executed."""
import ast,importlib.util,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('core622_factory',HERE/'prepare.py');F=importlib.util.module_from_spec(spec);spec.loader.exec_module(F)
ROOTS={k:Path(os.environ['CORE622_'+k.upper()])for k in('parent','fresh607','core_record','fresh_record')}
EXPECTED=Path(os.environ['CORE622_EXPECTED'])

class Controls(unittest.TestCase):
 def test_actual_known_and_null_production_cli_exact_public66(self):
  with tempfile.TemporaryDirectory(prefix='core622-cli-')as t:
   for context in('known','null'):
    output=Path(t)/context;argv=[sys.executable,'-I','-B','-Werror',str(HERE/'prepare.py'),'--output',str(output),'--context',context]
    for k,p in ROOTS.items():argv+=['--'+k.replace('_','-'),str(p)]
    run=subprocess.run(argv,capture_output=True,text=True,timeout=60);self.assertEqual(run.returncode,0,run.stderr);receipt=json.loads(run.stdout);self.assertIsNone(receipt['actual']);self.assertFalse(receipt['native_acceptance']);self.assertEqual(receipt['files'],66);self.assertEqual(F.tree(output),F.tree(EXPECTED));self.assertTrue(all((output/n).stat().st_mode&0o777==0o644 for n in F.tree(output)))
    self.assertEqual(receipt['source'],None if context=='null'else'bbdf05888b8bacb8a7ee8dfde4def4d508cc812b')
 def test_full_before_inverse_held_bodies_and_current_closed_profile(self):
  values,p,_,_=F.compose(ROOTS);before=F.tree(ROOTS['parent']);self.assertEqual({n:F.pin(b)for n,b in values.items()},p['result']['files']);self.assertEqual(values,F.tree(EXPECTED));parent=json.loads(values['composition-parent.json']);restored=dict(values)
  for n in p['added']:restored.pop(n)
  for n,b in parent['changed'].items():restored[n]=b.encode()
  self.assertEqual(restored,before);self.assertEqual(len(p['held']),40)
  for n in p['held']:self.assertEqual(values[n],before[n])
  for n,b in values.items():
   if n.endswith('.py'):ast.parse(b,filename=n)
  profile=json.loads(values['profile.json']);self.assertEqual(profile['composition']['installed'],622);self.assertIsNone(profile['composition']['actual']);self.assertEqual(profile['composition']['normal_fresh607_installation'],'NOT_RUN');self.assertNotIn(b'/home/',values['composition.json'])
 def test_exact_roles_and_closed_source_membership(self):
  bad=dict(ROOTS,fresh_record=ROOTS['core_record'])
  with self.assertRaisesRegex(ValueError,'whole exact public role'):F.compose(bad)
  with tempfile.TemporaryDirectory(prefix='core622-input-')as t:
   parent=Path(t)/'parent';shutil.copytree(ROOTS['parent'],parent);roots=dict(ROOTS,parent=parent);(parent/'foreign-empty').mkdir()
   with self.assertRaisesRegex(ValueError,'closed source directory membership'):F.compose(roots)
   (parent/'foreign-empty').rmdir();(parent/'guest.py').write_bytes((parent/'guest.py').read_bytes()+b'\n')
   with self.assertRaisesRegex(ValueError,'whole exact public role'):F.compose(roots)
 def test_paths_aliases_actual_roots_and_normalization_before_writes(self):
  with tempfile.TemporaryDirectory(prefix='core622-path-')as t:
   root=Path(t);alias=root/'alias';alias.symlink_to(ROOTS['parent'],target_is_directory=True)
   for roots,output in[(dict(ROOTS,parent=alias),root/'no-alias'),(ROOTS,ROOTS['parent']/'no-descendant'),(ROOTS,HERE/'no-author'),(ROOTS,root/'native-actual-test'/'out')]:
    output.parent.mkdir(exist_ok=True)if output.parent==root/'native-actual-test'else None
    with self.assertRaises(ValueError):F.paths(roots,output)
    self.assertFalse(output.exists())
   with self.assertRaisesRegex(ValueError,'normalized'):F.paths(ROOTS,str(root/'sub')+'/../out')
 def test_late_genuine_input_drift_refuses_before_output(self):
  with tempfile.TemporaryDirectory(prefix='core622-late-')as t:
   root=Path(t);parent=root/'parent';shutil.copytree(ROOTS['parent'],parent);roots=dict(ROOTS,parent=parent);real=F.compose
   def changed(roles):
    result=real(roles);victim=parent/'guest.py';victim.write_bytes(victim.read_bytes()+b'\n');return result
   with patch.object(F,'compose',side_effect=changed):
    with self.assertRaisesRegex(ValueError,'late complete identity'):F.emit(roots,root/'out','known')
   self.assertFalse((root/'out').exists())
 def test_operand_and_profile_drift_refuse_without_emission(self):
  with tempfile.TemporaryDirectory(prefix='core622-factory-')as t:
   root=Path(t);factory=root/'factory';shutil.copytree(HERE,factory)
   with patch.object(F,'HERE',factory):
    payload=factory/'ownership622.py.in';payload.write_bytes(payload.read_bytes()+b'\n')
    with self.assertRaisesRegex(ValueError,'fixed readable source operand'):F.emit(ROOTS,root/'out','known')
    self.assertFalse((root/'out').exists());payload.write_bytes((HERE/'ownership622.py.in').read_bytes());(factory/'profile.json').write_bytes(b'{}\n')
    with self.assertRaisesRegex(ValueError,'fixed factory profile'):F.emit(ROOTS,root/'out','known')
 def test_no_parent_actor_execution_and_original_target_roles(self):
  tree=ast.parse((HERE/'prepare.py').read_bytes());imports=[n for n in ast.walk(tree)if isinstance(n,(ast.Import,ast.ImportFrom))];self.assertFalse(any(isinstance(n,ast.Import)and any(a.name.split('.')[0]in('subprocess','desktop622','adapter','case')for a in n.names)for n in imports));p=json.loads(F.read(HERE/'profile.json'));self.assertEqual(p['counts'],dict(before=51,after=66,held=40,changed=11,added=15));c=json.loads(F.read(HERE/'composition.json'));self.assertEqual(len(c['before607']),607);self.assertEqual(len(c['after622']),622);self.assertEqual(len(c['held']),602);self.assertNotIn('libfdk-aac',c['before607']);self.assertEqual(c['before607']['cachy-asahi-fdk-aac'],'3.0.0-1');self.assertTrue(all(c[k]is None for k in('source','ref','run','actual')))

class CurrentImportControls(unittest.TestCase):
 def test_whole_immediate_ae39_inverse_and_selfseal(self):
  values,p,_,_=F.compose(ROOTS);parent=json.loads(values['composition-parent.json']);record=parent['isolated_cache_import'];self.assertEqual(record['parent_source'],'ae39c1ba4c613d6a86e5582c2ab4c2d5495b2bd7');self.assertEqual(len(record['before']),66);restored=dict(values)
  for name,rules in record['edits'].items():
   text=restored[name].decode()
   for before,after in reversed(rules):self.assertEqual(text.count(after),1);text=text.replace(after,before,1)
   restored[name]=text.encode()
  parent.pop('isolated_cache_import');restored['composition-parent.json']=F.enc(parent);manifest=json.loads(restored['source-manifest.json']);manifest['files']={n:w for n,w in record['before'].items()if n not in('source-manifest.json','.github/workflows/native-arm-build.yml','.github/workflows/native-arm-core7-real-systemd.yml')};restored['source-manifest.json']=F.enc(manifest)
  text=restored['source622.py'].decode()
  for name,before in(('PRODUCTS',record['guard_products_before']),('SELF',record['guard_self_before'])):
   node=next(n for n in ast.parse(text).body if isinstance(n,ast.Assign)and n.targets[0].id==name);after=ast.get_source_segment(text,node);self.assertEqual(text.count(after),1);text=text.replace(after,before,1)
  for before,after in reversed(record['guard_edits']):self.assertEqual(text.count(after),1);text=text.replace(after,before,1)
  restored['source622.py']=text.encode();self.assertEqual({n:F.pin(b)for n,b in restored.items()},record['before']);self.assertEqual(sum(values[n]==restored[n]for n in values),61)
  constants={n.targets[0].id:ast.literal_eval(n.value)for n in ast.parse(text).body if isinstance(n,ast.Assign)and n.targets[0].id in('PRODUCTS','SELF')};self.assertTrue(all(F.pin(restored[n])==w for n,w in constants['PRODUCTS'].items()));seal=constants['SELF'];self.assertEqual(text.count(seal),1);self.assertEqual(F.pin(text.replace(seal,'@SELF@').encode())['sha256'],seal)
 def test_real_emitted_isolated_cache_cli_not_mocked_facade(self):
  import time
  with tempfile.TemporaryDirectory(prefix='core622-import-cli-')as td:
   root=Path(td);source=root/'source';F.emit(ROOTS,source,'known')
   for name in('carrier','updater','cache','incoming','preparation'):(root/name).mkdir(mode=0o700)
   cache=root/'cache';before=F.identity(cache.lstat());(root/'desktop622.py').write_text("raise AssertionError('FOREIGN_CWD_MUST_NOT_EXECUTE')\n");argv=[sys.executable,'-I','-B',str(source/'ownership622.py'),'--prepare-dependency-cache','--compiler6-source',str(ROOTS['fresh607']),'--carrier',str(root/'carrier'),'--updater',str(root/'updater'),'--desktop-lock',str(root/'desktop.lock'),'--cache',str(cache),'--incoming31',str(root/'incoming'),'--preparation',str(root/'preparation'),'--deadline',str(time.monotonic()+240)]
   run=subprocess.run(argv,cwd=root,stdin=subprocess.DEVNULL,capture_output=True,timeout=20,env=dict(PATH='/usr/bin:/bin',LANG='C',PYTHONDONTWRITEBYTECODE='1',PYTHONPATH=str(root)));text=run.stderr.decode();self.assertEqual(run.returncode,1);self.assertNotIn('ModuleNotFoundError',text);self.assertNotIn('FOREIGN_CWD_MUST_NOT_EXECUTE',text);self.assertIn('FileNotFoundError',text);self.assertIn('compiler6.py',text);self.assertIn('selected.prepare_with_dependencies',text);self.assertEqual(F.identity(cache.lstat()),before);self.assertEqual(list(cache.iterdir()),[])
   helper=source/'desktop622.py';helper.write_bytes(helper.read_bytes()+b'\n# private drift\n');run=subprocess.run(argv,cwd=root,stdin=subprocess.DEVNULL,capture_output=True,timeout=20,env=dict(PATH='/usr/bin:/bin',LANG='C',PYTHONDONTWRITEBYTECODE='1'));self.assertEqual(run.returncode,1);self.assertIn(b'exact held local desktop622 cache bootstrap',run.stderr);self.assertNotIn(b'FileNotFoundError',run.stderr);self.assertEqual(F.identity(cache.lstat()),before)

if __name__=='__main__':unittest.main(verbosity=2)

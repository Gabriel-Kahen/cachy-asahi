# SPDX-License-Identifier: MIT
"""Portable source fixtures and exact public-byte controls, never native acceptance."""
import base64,builtins,importlib.util,json,os,shutil,stat,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
sp=importlib.util.spec_from_file_location('_updater_argument_factory',HERE/'prepare.py');F=importlib.util.module_from_spec(sp);sp.loader.exec_module(F)
SOURCE=F.ordinary(os.environ['GUI_PROGRESS_INPUT']);EXPECTED=F.ordinary(os.environ['GUI_PROGRESS_EXPECTED'])
class Controls(unittest.TestCase):
 def test_literal_cli_both_receipts_all692_bytes_modes_and_null_actuals(self):
  expected=__import__('json').loads(F.read(HERE/'profile.json'))['result']['files']
  with tempfile.TemporaryDirectory()as td:
   for context in('known','null'):
    output=Path(td)/context;argv=[sys.executable,'-I','-B','-Werror',str(HERE/'prepare.py'),'--source',str(SOURCE),'--output',str(output),'--context',context]
    done=subprocess.run(argv,capture_output=True,timeout=30,umask=0o077);self.assertEqual(done.returncode,0,done.stderr.decode());row=json.loads(done.stdout)
    self.assertEqual({n:F.pin(b)for n,b in F.tree(output).items()},expected);self.assertEqual(len(row['files']),693);self.assertIsNone(row['source']);self.assertEqual(F.historical_inverse(F.tree(output)),F.tree(EXPECTED))
    self.assertTrue(all(row[k]is None for k in('actual_source','actual_ref','actual_run','Root_acceptance')));self.assertTrue(all(stat.S_IMODE((output/n).stat().st_mode)==0o644 for n in expected))
 def test_constructor_never_executes_supplied_source_or_actors(self):
  sentinel=object();saved=sys.modules.get('common',sentinel)
  try:
   sys.modules['common']=sentinel
   with patch.object(builtins,'exec',side_effect=AssertionError('NO_PARENT_EXECUTION')),patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS')),patch.object(base64,'b64decode',side_effect=AssertionError('NO_CODECS')):
    result,*_=F.compose(SOURCE)
   self.assertIs(sys.modules['common'],sentinel);self.assertEqual({n:F.pin(b)for n,b in result.items()},__import__('json').loads(F.read(HERE/'profile.json'))['result']['files'])
  finally:
   if saved is sentinel:sys.modules.pop('common',None)
   else:sys.modules['common']=saved
 def test_complete_parent_body_inverses_and_all679_held(self):
  values,p,*_=F.compose(SOURCE);before=F.tree(SOURCE);payload=F.reserved_inverse(F.expectation_inverse(F.historical_inverse(values)));mid=F.payload_inverse(payload);self.assertEqual({n:F.pin(b)for n,b in mid.items()},p['intermediate']['files']);parent=json.loads(mid['implementation/build-inventory-parent.json']);context=parent.pop('observer_progress')
  self.assertEqual(F.encoded(parent),before['implementation/build-inventory-parent.json']);self.assertEqual(context['files'],p['parent']['files']);self.assertEqual(context['source'],p['parent']['source']);self.assertIsNone(context['actual'])
  self.assertEqual(len(p['held']),679);self.assertEqual(len(p['changed']),13)
  for n in p['held']:self.assertEqual(values[n],before[n],n)
  self.assertEqual(F.historical_inverse(values),F.tree(EXPECTED))
  for field,value in(('actual',1),('source','0'*40),('variant','foreign')):
   hostile=dict(payload);parent=json.loads(hostile['implementation/build-inventory-parent.json']);parent['payload_progress'][field]=value;hostile['implementation/build-inventory-parent.json']=F.encoded(parent)
   with self.assertRaises(ValueError):F.payload_inverse(hostile)
  hostile=dict(payload);hostile['implementation/expected607.lock']+=b'\n'
  with self.assertRaises(ValueError):F.payload_inverse(hostile)
 def test_reserved_and_expectation_whole692_inverses_and_finite_delta(self):
  child,p,*_=F.compose(SOURCE);values=F.historical_inverse(child);self.assertEqual(values,F.tree(EXPECTED));reserved=F.expectation_inverse(values);payload=F.reserved_inverse(reserved)
  self.assertEqual({n:F.pin(b)for n,b in reserved.items()},p['reserved_result']['files']);self.assertEqual({n:F.pin(b)for n,b in payload.items()},p['payload_result']['files'])
  self.assertEqual({n for n in values if values[n]!=reserved[n]},{'implementation/test_source.py','implementation/build_inventory_guard.py','implementation/build-inventory-parent.json','source-manifest.json'})
  self.assertEqual(sum(reserved[n]==payload[n]for n in payload),684)
  for current,key,inverse in((values,'source_profile_expectation',F.expectation_inverse),(reserved,'reserved_recheck',F.reserved_inverse)):
   for field,value in(('actual',1),('source','0'*40),('ref','foreign'),('variant','null'),('schema',2)):
    hostile=dict(current);parent=json.loads(hostile['implementation/build-inventory-parent.json']);parent[key][field]=value;hostile['implementation/build-inventory-parent.json']=F.encoded(parent)
    with self.subTest(key=key,field=field),self.assertRaises(ValueError):inverse(hostile)
   hostile=dict(current);hostile['implementation/expected607.lock']+=b'\n'
   with self.assertRaises(ValueError):inverse(hostile)
 def test_production1200_prior1800_current3460_are_distinct(self):
  values,*_=F.compose(SOURCE);parent=json.loads(values['implementation/build-inventory-parent.json']);spec=parent['reserved_recheck']['reservation']
  self.assertEqual((spec['default_service_seconds'],spec['service_seconds']),(1200,3460));self.assertEqual((spec['loop_seconds'],spec['runtime_seconds'],spec['owner_wait_seconds']),(3560,4010,4460))
  reservation=spec['reservation'];self.assertEqual((reservation['pre_observer_seconds'],reservation['observer_seconds'],reservation['caller_seconds'],reservation['cleanup_seconds'],reservation['readback_tail_seconds']),(1800,1200,1210,450,1660));self.assertTrue(reservation['one_shared_deadline'])
  self.assertIsNone(spec['actual']);self.assertFalse(spec['acceptance']);self.assertEqual(spec['current3460_fit'],'NOT_ESTABLISHED')
  seam=json.loads(F.read(HERE/'expectation-seam.json'));self.assertEqual(len(seam['edits']),2)
  self.assertIn("self.assertEqual(q['service_seconds'],1800)",seam['edits'][0]['before'])
  self.assertIn('prior_selected_service_seconds',seam['edits'][0]['after']);self.assertIn('3460',seam['edits'][0]['after'])
 def test_historical_source_layer_inverse_and_live_bytes_held(self):
  values,p,*_=F.compose(SOURCE);prior=F.historical_inverse(values);self.assertEqual(prior,F.tree(EXPECTED));self.assertEqual(set(values)-set(prior),{'implementation/historical_source.py'})
  self.assertEqual({n for n in prior if prior[n]!=values[n]},{'implementation/test_source.py','implementation/test_observer.py','implementation/build_inventory_guard.py','implementation/build-inventory-parent.json','source-manifest.json','.github/workflows/native-arm-build.yml','.github/workflows/native-arm-latest607-welcome8-gui.yml','implementation/workflow_contract.py','implementation/workflow-derivation.json','implementation/test_runner_context.py'})
  for name in prior:
   if name not in {'implementation/test_source.py','implementation/test_observer.py','implementation/build_inventory_guard.py','implementation/build-inventory-parent.json','source-manifest.json','.github/workflows/native-arm-build.yml','.github/workflows/native-arm-latest607-welcome8-gui.yml','implementation/workflow_contract.py','implementation/workflow-derivation.json','implementation/test_runner_context.py'}:self.assertEqual(values[name],prior[name],name)
  hostile=dict(values);hostile['implementation/historical_source.py']+=b'\n'
  with self.assertRaises(ValueError):F.historical_inverse(hostile)
  for field,value in(('actual',1),('source','0'*40),('ref','foreign'),('variant','null')):
   hostile=dict(values);parent=json.loads(hostile['implementation/build-inventory-parent.json']);parent['historical_source'][field]=value;hostile['implementation/build-inventory-parent.json']=F.enc(parent)
   with self.subTest(field=field),self.assertRaises(ValueError):F.historical_inverse(hostile)
 def test_paths_double_slash_literal_cli_and_no_writes(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);source=root/'source';shutil.copytree(SOURCE,source);alias=root/'alias';alias.symlink_to(source,target_is_directory=True);actual=root/'native-actual-fixture';actual.mkdir()
   for supplied,out in((source,source),(source,source/'child'),(alias,root/'out'),(source,'relative'),(source,str(root)+'/a/../out'),(source,actual/'out'),(source,HERE/'out')):
    with self.subTest(out=out),self.assertRaises(ValueError):F.emit(supplied,out,'null')
   for supplied,out in((source,'//'+str(source).lstrip('/')+'/double-slash-output'),('//'+str(source).lstrip('/'),root/'alias-output')):
    before=F.scan(source);done=subprocess.run([sys.executable,'-I','-B','-Werror',str(HERE/'prepare.py'),'--source',str(supplied),'--output',str(out),'--context','null'],capture_output=True,timeout=10)
    self.assertNotEqual(done.returncode,0);self.assertIn(b'canonical resolved path required',done.stderr);self.assertFalse(Path(out).exists());self.assertEqual(F.scan(source),before)
   with self.assertRaises(ValueError):F.emit(source,root/'absent','foreign')
   self.assertFalse((root/'absent').exists())
 def test_whole_source_drift_empty_links_special_nodes_refused(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td)
   for kind in('drift','missing','foreign','empty','symlink','hardlink','fifo'):
    source=root/kind;shutil.copytree(SOURCE,source);leaf=source/'implementation/observer_apply.py'
    if kind=='drift':leaf.write_bytes(leaf.read_bytes()+b'\n')
    elif kind=='missing':leaf.unlink()
    elif kind=='foreign':(source/'foreign').write_bytes(b'foreign')
    elif kind=='empty':(source/'foreign-empty').mkdir()
    elif kind=='symlink':leaf.unlink();leaf.symlink_to(SOURCE/'implementation/observer_apply.py')
    elif kind=='hardlink':leaf.unlink();os.link(source/'implementation/observer_stage.py',leaf)
    else:leaf.unlink();os.mkfifo(leaf)
    out=root/(kind+'-output')
    with self.subTest(kind=kind),self.assertRaises(ValueError):F.emit(source,out,'known')
    self.assertFalse(out.exists())
 def test_profile_and_each_readable_operand_drift_refuse_prewrite(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td)
   for name in('profile.json',*F.compose(SOURCE)[1]['operands']):
    local=root/name;shutil.copytree(HERE,local);leaf=local/name;leaf.write_bytes(leaf.read_bytes()+b' ');previous=F.HERE
    try:
     F.HERE=local;out=root/(name+'-output')
     with self.subTest(name=name),self.assertRaises(ValueError):F.emit(SOURCE,out,'known')
     self.assertFalse(out.exists())
    finally:F.HERE=previous
 def test_late_inode_operand_drift_and_stable_atime_exclusion(self):
  self.assertNotIn('st_atime_ns',F.identity.__code__.co_consts)
  with tempfile.TemporaryDirectory()as td:
   root=Path(td)
   for kind in('source','operand'):
    source=root/(kind+'-source');local=root/(kind+'-factory');shutil.copytree(SOURCE,source);shutil.copytree(HERE,local);previous=F.HERE;original=F.scan;calls=[]
    def scan(path):
     value=original(path)
     if Path(path)==source and not calls:
      calls.append(True)
      if kind=='source':leaf=source/'implementation/observer_apply.py';replacement=source/'replacement';replacement.write_bytes(leaf.read_bytes());os.replace(replacement,leaf)
      else:leaf=local/'generated-policy.json';leaf.write_bytes(leaf.read_bytes()+b' ')
     return value
    try:
     F.HERE=local;out=root/(kind+'-output')
     with patch.object(F,'scan',side_effect=scan),self.assertRaises(ValueError):F.emit(source,out,'known')
     self.assertFalse(out.exists())
    finally:F.HERE=previous
if __name__=='__main__':unittest.main(verbosity=2)

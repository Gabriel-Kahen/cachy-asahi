#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pure DATA routing/replay controls: no Git, acquisition, actors or package API."""
import ast,copy,hashlib,os,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock,patch
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2];sys.path.insert(0,str(HERE))
import contract as O
import closed as C
import data_carrier as D
P=O.load('orphans03_hosted_controls',HERE/'hosted_producer.py')

class Hosted(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.home=Path(self.tmp.name);self.root=ROOT;self.carrier=self.home/'retained574-data';self.output=self.home/'native574';self.proof=self.home/'proof.json'
  self.original=O.load('orphans03_held_original_plan',ROOT/'scripts/ci/maintained_desktop574.py');self.inputs=O.read(ROOT/'scripts/ci/maintained-desktop574-inputs.json');self.profile=D.expected(ROOT);self.pairs=D.pairs(ROOT);total=D.check_files(self.profile['files'])
  self.transport=dict(status='EXACT_IMMUTABLE_ARCHIVE_DATA_NO_NATIVE_AUTHORITY',source=D.SOURCE,url=D.URL,requests=1,files=1154,file_map=self.profile['files'],content_bytes=total,archive=dict(bytes=total,sha256='1'*64),expanded_bytes=total+1024**2,normalized_files_mode=0o600,normalized_directories_mode=0o700,native_authority=False,git_authority=False,profile_sha256=O.digest(ROOT/D.PROFILE))
  cache=dict(before_files={},before_identity={},after_previous_identity={},added=1148,after_files=self.pairs,fresh_cache=False,all_previous_inode_metadata_bytes_unchanged=True,directory_identity=[1,2,0o700,1001,1001],after_directory_identity=[1,2,0o700,1001,1001],normalized_files_mode=0o600)
  lock=ROOT/'scripts/ci/maintained-desktop574-inputs.json'
  self.package=dict(status='EXACT_RETAINED_DATA_ARCHIVE_PREPARATION',mode='desktop574',source=D.SOURCE,actual=None,carrier=self.transport,receipt=dict(actual_authority=False,mode='desktop574',inputs=self.pairs,original_lock=dict(bytes=lock.stat().st_size,sha256=O.digest(lock)),cache=cache))
  self.other=[r for r in self.original.plan(self.inputs,self.output/'context') if r['target'].parent.name!='deps'];self.nonpackages=[dict(filename=r['filename'],bytes=r['size'],source=r['url']) for r in self.other]
  self.value=dict(status='PASS_RETAINED1148_DATA_ARCHIVE_AND_FIVE_ORIGINAL_NONPACKAGE_DATA',packages=self.package,nonpackages=self.nonpackages,actual=None)
  self.proof.write_bytes(O.encoded(dict(manifest_sha256=O.digest(ROOT/O.LANE/'source-manifest.json'),job_token='2'*16)))
 def routing(self,package=None):
  helper=SimpleNamespace(SOURCE=D.SOURCE,acquire=Mock(return_value=self.transport),seed=Mock(return_value=self.package if package is None else package),pairs=D.pairs,validate_receipt=D.validate_receipt)
  fetch=Mock(side_effect=lambda row:dict(filename=row['filename'],bytes=row['size'],source=row['url']));original=SimpleNamespace(plan=self.original.plan,fetch=fetch);self.last_fetch=fetch
  def loader(path,name):
   if path==self.root/O.LANE/'data_carrier.py':return helper
   if path==self.root/'scripts/ci/maintained_desktop574.py':return original
   raise AssertionError('unexpected DATA transport source load')
  with patch.object(P.C,'load',side_effect=loader),patch.object(P.C,'verify') as verify:result=P.prepare(self.root,self.carrier,self.output,self.proof)
  verify.assert_called_once_with(self.root,O.digest(ROOT/O.LANE/'source-manifest.json'));return result,helper,fetch
 def test_unchanged_original574_source_is_still_selected(self):
  self.assertEqual(O.digest(ROOT/'scripts/ci/maintained_desktop574.py'),'27ba4be42cf2bd41675073e07cccc917ae033f9d68b07a33cfd7f074ac27b760')
 def test_exact_one_data_acquire_seed_and_original_five_fetches(self):
  result,helper,fetch=self.routing();self.assertEqual(result,ROOT/'scripts/ci/maintained-desktop574-inputs.json');self.assertEqual(helper.acquire.call_count,1);self.assertEqual(helper.seed.call_count,1)
  self.assertEqual(helper.acquire.call_args.args[:2],(self.root,self.carrier));self.assertEqual(helper.seed.call_args.args[:3],(self.root,self.carrier,self.output/'context/deps'));self.assertEqual(helper.seed.call_args.args[-1],self.transport)
  self.assertEqual(fetch.call_count,5);self.assertEqual([c.args[0]['filename'] for c in fetch.call_args_list],[r['filename'] for r in self.other]);self.assertEqual(O.read(self.output/'retained-inputs.json'),self.value)
 def test_bad_data_preparation_receipt_cannot_pass_replay(self):
  for field in ('source','status'):
   package=copy.deepcopy(self.package);package[field]='wrong'
   with self.subTest(field=field),self.assertRaises(ValueError):self.routing(package)
   self.last_fetch.assert_not_called()
   if self.output.exists():__import__('shutil').rmtree(self.output)
 def test_closed_reader_accepts_data_only_without_native_or_git_authority(self):
  result=C.validate_transport(ROOT,self.value);self.assertEqual(result,dict(status='PASS_HOSTED_DATA_INPUT_RECEIPT_ONLY',packages=1148,nonpackages=5,source=D.SOURCE,native_authority=False,git_authority=False,requests=1))
 def test_reader_refuses_old_git_blob_receipt_or_extra_authority(self):
  for change in ('old','blob','git','native'):
   value=copy.deepcopy(self.value)
   if change=='old':value['status']='PASS_RETAINED1148_AND_FIVE_ORIGINAL_NONPACKAGE_DATA'
   elif change=='blob':value['packages']['carrier']['blob_joins']=1154
   else:value['packages']['carrier'][change+'_authority']=True
   with self.subTest(change=change),self.assertRaises(ValueError):C.validate_transport(ROOT,value)
 def test_reader_refuses_partial_wrong_or_noninteger_data_counts(self):
  for key,value in (('files',1153),('file_map',{}),('source','0'*40),('profile_sha256','0'*64),('requests',2),('requests',True),('normalized_files_mode',0o755)):
   receipt=copy.deepcopy(self.value);receipt['packages']['carrier'][key]=value
   with self.subTest(key=key),self.assertRaises(ValueError):C.validate_transport(ROOT,receipt)
 def test_reader_refuses_archive_cap_unknown_url_and_missing_expansion(self):
  for change in ('cap','url','expanded'):
   value=copy.deepcopy(self.value);carrier=value['packages']['carrier']
   if change=='cap':carrier['archive']['bytes']=carrier['content_bytes']+D.OVERHEAD+1
   elif change=='url':carrier['url']='https://elsewhere.invalid'
   else:carrier['expanded_bytes']=0
   with self.assertRaises(ValueError):C.validate_transport(ROOT,value)
 def test_reader_refuses_nonempty_partial_changed_cache(self):
  for key,value in (('before_files',{'foreign':{}}),('before_identity',{'foreign':[]}),('added',1147),('after_files',{}),('all_previous_inode_metadata_bytes_unchanged',False),('normalized_files_mode',0o644),('after_directory_identity',[1,3,0o700,1001,1001])):
   receipt=copy.deepcopy(self.value);receipt['packages']['receipt']['cache'][key]=value
   with self.subTest(key=key),self.assertRaises(ValueError):C.validate_transport(ROOT,receipt)
 def test_reader_refuses_missing_swapped_or_changed_original_five(self):
  for mode in ('missing','swapped','url','bytes'):
   value=copy.deepcopy(self.value)
   if mode=='missing':value['nonpackages'].pop()
   elif mode=='swapped':value['nonpackages'].reverse()
   elif mode=='url':value['nonpackages'][0]['source']='https://unreviewed.invalid'
   else:value['nonpackages'][0]['bytes']+=1
   with self.subTest(mode=mode),self.assertRaises(ValueError):C.validate_transport(ROOT,value)
 def test_reviewed_source_digest_refuses_before_actors(self):
  with self.assertRaisesRegex(ValueError,'digest'):C.verify(ROOT,'0'*64)
 def test_workflow_has_no_large_checkout_or_local_directory_dispatch_input(self):
  text=(HERE/'workflow.yml').read_text();self.assertEqual(text.count('uses: actions/checkout@'),1);self.assertNotIn('3d3c42e5aac5ba805825da76410c181273ba90b1',text);self.assertIn('--carrier "$RUNNER_TEMP/retained574-data"',text);self.assertIn('scripts/ci/orphans-live-native',text);self.assertIn('orphans03-explicit-target-',text);self.assertNotIn('retained_packages:',text);self.assertNotIn('retained_bootstrap:',text);self.assertNotIn('secrets.',text)
 def test_held_root_container_remains_writable_networkless_unprivileged(self):
  path=ROOT/'scripts/ci/welcome-native/run.py';node=next(n for n in ast.parse(path.read_bytes()).body if isinstance(n,ast.FunctionDef) and n.name=='docker');space={'os':os};exec(compile(ast.Module(body=[node],type_ignores=[]),str(path),'exec'),space);argv=space['docker']('sha256:'+'1'*64,'inert',Path('/tmp/inert'),root=True);self.assertNotIn('--read-only',argv);self.assertIn('--network=none',argv);self.assertNotIn('--privileged',argv)

if __name__=='__main__':unittest.main()

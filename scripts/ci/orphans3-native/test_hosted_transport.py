#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Hosted-route controls only: stub Git/cache/fetch; no acquisition or actors."""
import ast,copy,hashlib,json,os,shutil,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock,patch
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2];sys.path.insert(0,str(HERE))
import contract as O
import closed as C
P=O.load('hosted_producer_controls',HERE/'hosted_producer.py')
PRODUCER_SHA='dcecab1bc4e4c39f47235e2ae2c060d4668e9216fa483001e56fe25420a7ec76'

class Hosted(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.base=Path(self.tmp.name);self.root=self.base/'source';shutil.copytree(ROOT,self.root,ignore=shutil.ignore_patterns('.git','retained574'))
  self.carrier=self.root/'retained574';self.carrier.mkdir();self.output=self.base/'native574';self.proof=self.base/'proof.json';O.safe(self.root)
  O.load('fixture_original_plan',self.root/'scripts/ci/maintained_desktop574.py');self.original=sys.modules['fixture_original_plan'];self.inputs=O.read(self.root/'scripts/ci/maintained-desktop574-inputs.json');self.profile=O.read(self.root/'scripts/ci/setup6-retained-helpers/carrier-profile.json')
  self.pairs={}
  for row in self.inputs['packages']:
   self.pairs[row['filename']]=dict(bytes=row['size'],sha256=row['sha256']);self.pairs[row['filename']+'.sig']=dict(bytes=row['signature_size'],sha256=row['signature_sha256'])
  cache=dict(before_files={},before_identity={},after_previous_identity={},added=1148,after_files=self.pairs,fresh_cache=False,all_previous_inode_metadata_bytes_unchanged=True,directory_identity=[1,2,16832,1001,1001,2],after_directory_identity=[1,2,16832,1001,1001,2])
  identity=dict(source=self.profile['source'],ref=self.profile['ref'],files=1154,blob_joins=1154,tree='1'*40,status='WHOLE_IMMUTABLE_SOURCE_GIT_JOIN_NO_NATIVE_AUTHORITY')
  self.package=dict(status='EXACT_RETAINED_INPUT_PREPARATION_DATA_ONLY',mode='desktop574',source=self.profile['source'],actual=None,carrier=identity,receipt=dict(actual_authority=False,mode='desktop574',inputs=self.pairs,original_lock=dict(bytes=(self.root/'scripts/ci/maintained-desktop574-inputs.json').stat().st_size,sha256=O.digest(self.root/'scripts/ci/maintained-desktop574-inputs.json')),cache=cache))
  self.items=self.original.plan(self.inputs,self.output/'context');self.other=[r for r in self.items if r['target'].parent.name!='deps'];self.nonpackages=[dict(filename=r['filename'],bytes=r['size'],source=r['url']) for r in self.other]
  self.value=dict(status='PASS_RETAINED1148_AND_FIVE_ORIGINAL_NONPACKAGE_DATA',packages=self.package,nonpackages=self.nonpackages,actual=None)
  self.proof.write_bytes(O.encoded(dict(manifest_sha256=O.digest(self.root/O.LANE/'source-manifest.json'),job_token='2'*16)))
 def routing(self,package=None):
  helper=SimpleNamespace(prepare=Mock(return_value=self.package if package is None else package));fetch=Mock(side_effect=lambda row:dict(filename=row['filename'],bytes=row['size'],source=row['url']));original=SimpleNamespace(plan=self.original.plan,fetch=fetch)
  self.last_fetch=fetch
  def loader(path,name):
   if path==self.root/'scripts/ci/setup6-retained-helpers/prepare.py':return helper
   if path==self.root/'scripts/ci/maintained_desktop574.py':return original
   raise AssertionError('unexpected transport source load')
  with patch.object(P.C,'load',side_effect=loader):result=P.prepare(self.root,self.carrier,self.output,self.proof)
  return result,helper,fetch
 def test_setup8_producer_byte_held(self):self.assertEqual(hashlib.sha256((HERE/'hosted_producer.py').read_bytes()).hexdigest(),PRODUCER_SHA)
 def test_full_source_and_reviewed_digest(self):C.verify(self.root,O.digest(self.root/O.LANE/'source-manifest.json'))
 def test_wrong_reviewed_digest_refuses(self):
  with self.assertRaisesRegex(ValueError,'digest'):C.verify(self.root,'0'*64)
 def test_external_checkout_is_narrowly_excluded(self):
  (self.carrier/'data-placeholder').write_text('DATA not source')
  O.verify_source(self.root);extra=self.root/'other-carrier';extra.mkdir();(extra/'extra').write_text('unexpected')
  with self.assertRaisesRegex(ValueError,'source set'):O.verify_source(self.root)
 def test_external_checkout_alias_refused(self):
  self.carrier.rmdir();outside=self.base/'elsewhere';outside.mkdir();self.carrier.symlink_to(outside,target_is_directory=True)
  with self.assertRaisesRegex(ValueError,'ordinary directory'):O.verify_source(self.root)
 def test_helper_source_drift_refuses_before_data_calls(self):
  path=self.root/'scripts/ci/setup6-retained-helpers/prepare.py';path.write_bytes(path.read_bytes()+b'\n# drift\n')
  with self.assertRaises(ValueError):P.prepare(self.root,self.carrier,self.output,self.proof)
  self.assertFalse(self.output.exists())
 def test_exact_prepare_cache_routing_and_original_five_fetch_only(self):
  result,helper,fetch=self.routing();self.assertEqual(result,self.root/'scripts/ci/maintained-desktop574-inputs.json');args=helper.prepare.call_args.args
  self.assertEqual(args[:4],(self.carrier,self.output/'context/deps','desktop574',result));self.assertEqual(args[5],self.carrier/'.git');self.assertEqual(fetch.call_count,5);self.assertEqual([c.args[0]['filename'] for c in fetch.call_args_list],[r['filename'] for r in self.other]);self.assertEqual(list((self.output/'context/deps').iterdir()),[])
  receipt=O.read(self.output/'retained-inputs.json');self.assertEqual(C.validate_transport(self.root,receipt)['native_authority'],False)
 def test_bad_joins_or_nonempty_cache_prevent_any_fetch(self):
  for field in ('blob_joins','added','before_files','actual_authority'):
   package=copy.deepcopy(self.package)
   if field=='blob_joins':package['carrier'][field]=1153
   elif field=='actual_authority':package['receipt'][field]=True
   else:package['receipt']['cache'][field]=1147 if field=='added' else {'foreign':{}}
   with self.subTest(field=field),self.assertRaises(ValueError):self.routing(package)
   self.last_fetch.assert_not_called()
   if self.output.exists():shutil.rmtree(self.output)
 def test_collector_accepts_complete_data_receipt_without_native_authority(self):self.assertEqual(C.validate_transport(self.root,self.value),dict(status='PASS_HOSTED_INPUT_RECEIPT_ONLY',packages=1148,nonpackages=5,source=self.profile['source'],native_authority=False))
 def test_collector_rejects_partial_carrier_and_wrong_source(self):
  for field,value in (('files',1153),('blob_joins',1153),('source','0'*40)):
   receipt=copy.deepcopy(self.value);receipt['packages']['carrier'][field]=value
   with self.subTest(field=field),self.assertRaises(ValueError):C.validate_transport(self.root,receipt)
 def test_collector_rejects_nonempty_or_partial_cache(self):
  for field,value in (('before_files',{'foreign':{}}),('before_identity',{'changed':[]}),('added',1147),('after_files',{}),('all_previous_inode_metadata_bytes_unchanged',False)):
   receipt=copy.deepcopy(self.value);receipt['packages']['receipt']['cache'][field]=value
   with self.subTest(field=field),self.assertRaises(ValueError):C.validate_transport(self.root,receipt)
 def test_collector_rejects_missing_swapped_wrong_nonpackage(self):
  for mode in ('missing','swapped','hash-source','bytes'):
   receipt=copy.deepcopy(self.value)
   if mode=='missing':receipt['nonpackages'].pop()
   elif mode=='swapped':receipt['nonpackages'].reverse()
   elif mode=='hash-source':receipt['nonpackages'][0]['source']='https://unreviewed.invalid/rootfs'
   else:receipt['nonpackages'][0]['bytes']+=1
   with self.subTest(mode=mode),self.assertRaises(ValueError):C.validate_transport(self.root,receipt)
 def test_workflow_has_actual_pinned_checkout_and_no_local_directory_inputs(self):
  text=(self.root/O.LANE/'workflow.yml').read_text();self.assertIn('ref: ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad',text);self.assertIn('path: retained574',text);self.assertIn('--carrier "$GITHUB_WORKSPACE/retained574"',text);self.assertIn('--proof "$RUNNER_TEMP/orphans3-proof.json"',text);self.assertNotIn('retained_packages:',text);self.assertNotIn('retained_bootstrap:',text);self.assertNotIn('secrets.',text)
  self.assertLess(text.index('id: proof'),text.index('path: retained574'));self.assertLess(text.index('path: retained574'),text.index('"$SLICE/hosted_producer.py"'))
 def test_held_welcome_root_body_is_writable(self):
  path=self.root/'scripts/ci/welcome-native/run.py';node=next(n for n in ast.parse(path.read_bytes()).body if isinstance(n,ast.FunctionDef) and n.name=='docker');space={'os':os};exec(compile(ast.Module(body=[node],type_ignores=[]),str(path),'exec'),space);argv=space['docker']('sha256:'+'1'*64,'inert',Path('/tmp/inert'),root=True);self.assertNotIn('--read-only',argv);self.assertIn('--network=none',argv);self.assertNotIn('--privileged',argv)

if __name__=='__main__':unittest.main()

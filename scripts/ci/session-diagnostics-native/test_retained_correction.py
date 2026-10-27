# SPDX-License-Identifier: MIT
"""Focused correction controls; synthetic receipts never grant native authority."""
import copy,hashlib,importlib.util,json,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as C
import producer as P
import retained_inputs as R
ROOT=Path(__file__).resolve().parents[3]


def fixture():
 raw=(ROOT/'scripts/ci/maintained-desktop574-inputs.json').read_bytes();expected={}
 for row in json.loads(raw)['packages']:
  expected[row['filename']]=dict(bytes=row['size'],sha256=row['sha256'])
  expected[row['filename']+'.sig']=dict(bytes=row['signature_size'],sha256=row['signature_sha256'])
 before={n:expected[n] for n in R.RETAINED574_BEFORE};identities={n:[1,2,3] for n in before};directory=[1,2,0o40700,1000,1000,1]
 return dict(status='EXACT_RETAINED_INPUT_PREPARATION_DATA_ONLY',mode='desktop574',source=R.RETAINED574_SOURCE,actual=None,
  carrier=dict(source=R.RETAINED574_SOURCE,ref='codex/native574-complete-retained-inputs-v1',tree='e21f947bac3afdfbd67e4e65c8234b35ae42b00f',status='WHOLE_IMMUTABLE_SOURCE_GIT_JOIN_NO_NATIVE_AUTHORITY',files=1154,blob_joins=1154),
  receipt=dict(actual_authority=False,status='EXACT_PUBLIC_CACHE_INPUTS_JOINED_NOT_AUTHENTICATED',mode='desktop574',original_lock=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()),inputs=expected,
   cache=dict(after_files=expected,before_files=before,added=1128,fresh_cache=False,mode=0o700,owner='CALLER_UID',before_identity=identities,after_previous_identity=identities,all_previous_inode_metadata_bytes_unchanged=True,directory_identity=directory,after_directory_identity=directory)))


class Correction(unittest.TestCase):
 def test_complete_exact1148_data_receipt_without_native_credit(self):
  proof=R.validate_retained_inputs(fixture());self.assertEqual(proof['files'],1148);self.assertFalse(proof['actual_authority'])
 def test_missing_pin_prior_bytes_owner_directory_or_authority_refuses(self):
  for mutation in ('missing','hash','prior','owner','directory','authority','carrier','added'):
   value=copy.deepcopy(fixture());cache=value['receipt']['cache']
   if mutation=='missing':value['receipt']['inputs'].pop(next(iter(value['receipt']['inputs'])))
   elif mutation=='hash':value['receipt']['inputs'][next(iter(value['receipt']['inputs']))]['sha256']='0'*64
   elif mutation=='prior':cache['after_previous_identity']={}
   elif mutation=='owner':cache['owner']='ROOT'
   elif mutation=='directory':cache['directory_identity'][2]=0o40755
   elif mutation=='authority':value['receipt']['actual_authority']=True
   elif mutation=='carrier':value['carrier']['source']='0'*40
   else:cache['added']=1127
   with self.subTest(mutation=mutation),self.assertRaises(ValueError):R.validate_retained_inputs(value)
 def test_isolated_entry_verifies_before_helper_then_receipt_before_unchanged_exec(self):
  class Executed(Exception):pass
  with tempfile.TemporaryDirectory() as temp:
   out=Path(temp);events=[];receipt=fixture();original=C.verify_source
   def verified(root):original(root);events.append('verified')
   def prepare(carrier,cache,mode,lock,deadline,git_dir):
    self.assertEqual(events,['verified']);self.assertEqual(mode,'desktop574');self.assertEqual(cache,out/'context/deps');events.append('prepared');return receipt
   def execute(exe,argv):
    self.assertEqual(events,['verified','prepared']);self.assertEqual(json.loads((out/'session-diagnostics-retained-inputs.json').read_bytes()),receipt)
    self.assertEqual(argv,[sys.executable,'-I','-B',str(ROOT/'scripts/ci/maintained_desktop574.py'),'build','--inputs',str(ROOT/'scripts/ci/maintained-desktop574-inputs.json'),'--output',str(out),'--job-token','1'*16]);raise Executed()
   with patch.object(C,'verify_source',side_effect=verified),patch.object(P,'load_helper',return_value=types.SimpleNamespace(prepare=prepare)),patch.object(P.os,'execv',side_effect=execute):
    with self.assertRaises(Executed):P.main(['--source',str(ROOT),'--carrier',str(out/'carrier'),'--output',str(out),'--job-token','1'*16])
 def test_bad_receipt_never_executes_original_producer(self):
  with tempfile.TemporaryDirectory() as temp:
   bad=fixture();bad['receipt']['actual_authority']=True
   with patch.object(P,'load_helper',return_value=types.SimpleNamespace(prepare=lambda *args:bad)),patch.object(P.os,'execv',side_effect=AssertionError('must not exec')) as execute:
    with self.assertRaises(ValueError):P.main(['--source',str(ROOT),'--carrier',temp,'--output',temp,'--job-token','1'*16])
    execute.assert_not_called();self.assertFalse((Path(temp)/'session-diagnostics-retained-inputs.json').exists())
 def test_original_fetch_uses_exact_seed_without_network_and_refuses_bad_seed(self):
  spec=importlib.util.spec_from_file_location('held574fetch',ROOT/'scripts/ci/maintained_desktop574.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
  with tempfile.TemporaryDirectory() as temp:
   path=Path(temp)/'fixture';body=b'controlled bytes';path.write_bytes(body)
   item=dict(filename='fixture',target=path,size=len(body),sha256=hashlib.sha256(body).hexdigest(),url='https://offline.invalid/fixture')
   def no_network(*args,**kwargs):raise AssertionError('seeded item must not download')
   self.assertEqual(module.fetch(item,no_network)['source'],'existing_exact_seed')
   path.write_bytes(b'corrupt')
   with self.assertRaises(ValueError):module.fetch(item,no_network)
 def test_workflow_holds_budgets_and_replaces_only_preparation_route(self):
  text=(ROOT/'scripts/ci/session-diagnostics-native/workflow.yml.in').read_text()
  for marker in ('timeout-minutes: 100','timeout-minutes: 40','2300s','timeout-minutes: 43','2500s','330s','timeout-minutes: 2','--source "$GITHUB_WORKSPACE" --carrier "$GITHUB_WORKSPACE/retained574"'):
   self.assertIn(marker,text)
  self.assertLess(text.index('path: retained574'),text.index('Reconstruct pinned inputs'))
  self.assertIn('ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad',text)
 def test_whole_source_closure_and_registered_workflow_proof(self):
  C.verify_source(ROOT);spec=importlib.util.spec_from_file_location('correcteddiagnosticjob',ROOT/'scripts/ci/session-diagnostics-native/job.py');job=importlib.util.module_from_spec(spec);spec.loader.exec_module(job)
  job.manifest_files(ROOT,json.loads((ROOT/C.LANE/'source-manifest.json').read_bytes()))
  self.assertEqual((ROOT/C.ACTOR).read_bytes(),(ROOT/C.ALIAS).read_bytes())
 def test_retained_profile_covers_every_original_package_and_signature(self):
  lock=json.loads((ROOT/'scripts/ci/maintained-desktop574-inputs.json').read_bytes())
  profile=json.loads((ROOT/'scripts/ci/setup6-retained-helpers/carrier-profile.json').read_bytes())
  expected={}
  for row in lock['packages']:
   expected['packages/'+row['filename']]=dict(bytes=row['size'],sha256=row['sha256'])
   expected['packages/'+row['filename']+'.sig']=dict(bytes=row['signature_size'],sha256=row['signature_sha256'])
  self.assertEqual(len(expected),1148)
  self.assertEqual({n:p for n,p in profile['files'].items() if n.startswith('packages/')},expected)
  self.assertEqual(profile['files']['desktop574-inputs.lock.json'],dict(bytes=623664,sha256='b2a234c76c3a820382238023203a8b699a503153f63b938376fd16433c4d90f9'))
 def test_external_retained_carrier_is_data_not_unmanifested_source(self):
  import shutil
  spec=importlib.util.spec_from_file_location('externaldatadiagnosticjob',ROOT/C.LANE/'job.py');job=importlib.util.module_from_spec(spec);spec.loader.exec_module(job)
  manifest=json.loads((ROOT/C.LANE/'source-manifest.json').read_bytes())
  with tempfile.TemporaryDirectory() as temp:
   clone=Path(temp)/'context';shutil.copytree(ROOT,clone,ignore=shutil.ignore_patterns('.git','retained574','retained-public-inputs'))
   carrier=clone/'retained574';carrier.mkdir();(carrier/'DATA-NOT-SOURCE').write_bytes(b'SYNTHETIC; NOT A QUALIFIED CARRIER')
   job.manifest_files(clone,manifest)
   (clone/'unexpected.py').write_text('raise RuntimeError("unexpected source")\n')
   with self.assertRaisesRegex(ValueError,'unmanifested'):job.manifest_files(clone,manifest)


if __name__=='__main__':unittest.main()

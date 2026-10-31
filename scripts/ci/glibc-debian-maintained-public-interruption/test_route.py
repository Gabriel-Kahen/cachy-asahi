# SPDX-License-Identifier: MIT
"""Actual public inputs and original code conservation; no native actor fixtures."""
import ast,copy,importlib.util,json,os,shutil,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import prepare as P
HERE=Path(__file__).resolve().parent
ROOT=Path(os.environ.get('CAA3_PUBLIC_ROUTE_SOURCE',HERE.parents[2]));PACKET=Path(os.environ['CAA3_PUBLIC_ROUTE_PACKET'])
N=P.load('test_native_normal',HERE/'normal_gate.py')
def functions(path):
 raw=path.read_text();return{n.name:ast.get_source_segment(raw,n)for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)}
class Controls(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.temp=tempfile.TemporaryDirectory();cls.addClassCleanup(cls.temp.cleanup);cls.base=Path(cls.temp.name);cls.out=cls.base/'derived'
  with patch.object(subprocess,'Popen',side_effect=AssertionError('no actors/Git/network')):cls.result=P.derive(ROOT,cls.out)
 def setUp(self):
  p=patch.object(subprocess,'Popen',side_effect=AssertionError('no actors/Git/network'));p.start();self.addCleanup(p.stop)
 def test_real_public21_original_compiler_receipt_replay(self):
  v=P.validate_packet(ROOT,PACKET);self.assertEqual(v['files'],21);self.assertEqual(v['compile_pair']['run_id'],38994309021);self.assertIn('NOT_ALPM_OR16K',v['status'])
 def test_default_null_source_refuses_before_output_normal_io_or_import(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);(root/'policy.json').write_bytes(P.encoded(dict(status='UNBOUND_CAA3_PUBLIC_COMPILE_NATIVE_INTERRUPTION_ROUTE',authorization=None,packet=None,native_normal=None)))
   with patch.object(P,'HERE',root),patch.object(P,'load',side_effect=AssertionError('must refuse before imports')):
    with self.assertRaisesRegex(ValueError,'UNBOUND'):P.emit(Path('/absent'),self.base/'absent')
    with self.assertRaisesRegex(ValueError,'UNBOUND'):P.normal_ref(Path('/absent'))
  self.assertFalse((self.base/'absent').exists())
 def test_known_original_normal_body_and_failed_workflow_qualification(self):
  value=N.check_file(HERE/'known-native-normal.json');self.assertEqual(value['provider_archive_sha256'],P.AUTH['archive_sha256']);self.assertEqual(value['workflow_conclusion'],'failure');self.assertEqual(value['ordered_cleanup'],'PASS')
 def test_cross_provider_status_source_and_incomplete_normal_refuse(self):
  original=N.check_file(HERE/'known-native-normal.json')
  for key,bad in(('provider_archive_sha256','b852e3fc647d63699c5f42003a748cbd2268991dc2615a494dc3cdda4d757d12'),('status','ROOT_ACCEPTED_CONVENTIONAL_PROVIDER_INTERRUPTION_RECOVERY'),('source_sha','365c952fcfbdc7d4760313df4d5fa1da7c8a2120'),('ALPM_installation','NOT_RUN'),('page_size',16384),('complete574_maps',15),('normal_runtime_observations',7),('ordered_cleanup','UNKNOWN')):
   row=copy.deepcopy(original);row[key]=bad
   with self.subTest(key=key),self.assertRaises(ValueError):N.fields(row)
  row=copy.deepcopy(original);row['candidate']['version']='2.43.caa1-1'
  with self.assertRaises(ValueError):N.fields(row)
 def test_exact_normal_bytes_descriptor_missing_alias_and_tamper_refuse(self):
  for value in(None,{},dict(N.DECISION,ref='0'*40),dict(N.DECISION,sha256='0'*64)):
   with self.assertRaisesRegex(ValueError,'UNBOUND'):N.descriptor(value)
  self.assertEqual(N.descriptor(dict(N.DECISION)),N.DECISION)
  with self.assertRaisesRegex(ValueError,'exact published'):N.validate((HERE/'known-native-normal.json').read_bytes()+b'\n')
  with tempfile.TemporaryDirectory()as td:
   p=Path(td)/'decision';p.symlink_to(HERE/'known-native-normal.json')
   with self.assertRaisesRegex(ValueError,'ordinary'):N.check_file(p)
 def test_interruption_modules_and_owner_cleanup_byte_held(self):
  for name in('container.py','run.py','scrub.py','interruption.py','alpm-semantics.json','dependencies.json','normal-exec-change.json','smoke-normal.c','input-policy.json','candidate_gate.py'):
   self.assertEqual((self.out/P.NEW/name).read_bytes(),(self.out/P.PRIOR/name).read_bytes(),name)
  a,b=functions(self.out/(P.PRIOR+'-owner')/'job.py'),functions(self.out/(P.NEW+'-owner')/'job.py')
  for name in('execute_leased','execute','cleanup','retain','snapshot_source','consumer_records','owned_containers','verify_actor','materialize'):
   if name=='materialize':self.assertIn("public_input_index=ref(inputs,inputs/'packet.json')",b[name])
   elif name in a:self.assertEqual(a[name],b[name],name)
  self.assertIn('3800',b['execute_leased'])
 def test_only_declared_common_input_bodies_change(self):
  a,b=functions(self.out/P.PRIOR/'common.py'),functions(self.out/P.NEW/'common.py');self.assertEqual({n for n in a if a[n]!=b[n]},{'validate_candidate_inputs'})
  raw=(self.out/P.NEW/'common.py').read_text();self.assertIn('ROOT_BOUND_CAA3_PUBLIC_COMPILE_NATIVE_INTERRUPTION',raw);self.assertIn("HERE/'public_gate.py').validate",raw)
 def test_owner_selection_always_checks_normal_before_new_actor_paths(self):
  raw=(self.out/(P.NEW+'-owner')/'job.py').read_text();self.assertIn("/normal_gate.py').check_file(workspace/'"+P.ROUTE+"/native-normal.json')",raw);self.assertLess(raw.index('_selection_normal_original=selection'),raw.index("if __name__=='__main__':"))
  owner=P.load('unbound_interruption_owner',self.out/(P.NEW+'-owner')/'job.py')
  with self.assertRaisesRegex(ValueError,'UNBOUND'):owner.selection(self.out)
 def test_emitted_manifest_all_source_and_default_policy_close(self):
  value=json.loads((self.out/(P.NEW+'-owner')/'integration-manifest.json').read_bytes())
  for name,row in value['files'].items():self.assertEqual(P.pin((self.out/name).read_bytes()),row,name)
  policy=json.loads((self.out/(P.NEW+'-owner')/'policy.json').read_bytes());self.assertIsNone(policy['packet']);self.assertIn('UNBOUND',policy['status'])
 def test_real_public_drift_extra_missing_and_alias_refuse(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);(root/'packet.json').write_bytes((PACKET/'packet.json').read_bytes())
   with self.assertRaisesRegex(ValueError,'closure'):P.validate_packet(ROOT,root)
   complete=root/'complete';shutil.copytree(PACKET,complete);p=complete/'source-proof.json';p.write_bytes(p.read_bytes()+b'\n')
   with self.assertRaises(ValueError):P.validate_packet(ROOT,complete)
 def test_prepared_context_keeps_old_source_gate_counts_and_no_new_result(self):
  original=P.load('original_maintained_emitter',ROOT/P.EMITTER);self.assertEqual(len(original.source(ROOT)['files']),82)
  for role in('lifecycle','interruption'):
   before=ROOT/(original.OLD+role);after=self.out/(original.NEW+role)
   for name in('container.py','run.py','scrub.py')+(('interruption.py',)if role=='interruption'else()):self.assertEqual((before/name).read_bytes(),(after/name).read_bytes())
  interface=json.loads((HERE/'input-interface.json').read_bytes())
  for key in('source','ref','run','native_interruption_decision','future_full_normal16k_decision','future_interruption16k_decision'):self.assertIsNone(interface[key])
 def test_workflow_order_original_budgets_security_and_diagnostic_helper(self):
  text=(ROOT/P.WF).read_text();positions=[text.index(s)for s in('id: normal','id: adaptation','id: proof','id: packet','secrets.','Reuse unchanged owned574','"$SLICE/job.py" execute','"$SLICE/job.py" cleanup','"$SLICE/job.py" retain','uses: actions/upload-artifact')];self.assertEqual(positions,sorted(positions))
  for term in('timeout-minutes: 180','timeout-minutes: 80','timeout-minutes: 15','2300s','cancel-in-progress: false','normal-ref','--normal-decision-root','summary.py --help'):
   self.assertIn(term,text)
  self.assertIn(P.ROUTE+'/normal_gate.py',json.loads((HERE/'source-pins.json').read_bytes())['files'])
  self.assertNotIn('--privileged',text);self.assertNotIn('apparmor=unconfined',text)
  for name in('prepare.py','source-pins.json'):self.assertIn(P.pin((HERE/name).read_bytes())['sha256'],text)
if __name__=='__main__':unittest.main(verbosity=2)

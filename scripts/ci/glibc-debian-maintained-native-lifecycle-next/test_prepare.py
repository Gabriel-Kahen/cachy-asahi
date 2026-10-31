# SPDX-License-Identifier: MIT
"""Portable finite phase conversion and source-wiring controls. No actors."""
import ast,copy,importlib.util,json,shutil,subprocess,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;ROOT=next(p for p in HERE.parents if (p/'manifests/packages.toml').is_file());spec=importlib.util.spec_from_file_location('maintained_next',HERE/'prepare.py');P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
class Controls(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.addCleanup(self.t.cleanup);self.root=Path(self.t.name);p=patch.object(subprocess,'Popen',side_effect=AssertionError('no actor'));p.start();self.addCleanup(p.stop)
 def gate(self):
  S,load,pins,rows=P.helpers(ROOT);return S,load(ROOT,S.GATE)
 def receipt(self):
  _,G=self.gate();return dict(candidate=G.EXPECTED,status='ROOT_ACCEPTED_PRIVATE_GNU16K_RUNTIME',native_source='78dfd3bbd85a61a84dda2dfc601796ee89edfd5f',candidate_package_sha256=P.ARCHIVE,page_size=16384,cases=8,runtime_records=12,actual_parent_child_providers='PASS',ordered_cleanup='PASS',hardware='NOT_RUN',source_sha='1'*40,run_id=1)
 def test_exact98_emission_and16_pure_helper_closures_no_actors(self):
  S,load,pins,rows=P.helpers(ROOT);self.assertEqual(len(rows),98);self.assertEqual(len(pins),16)
  for name in (S.GATE,S.PHASE,S.OWNER,S.NORMAL):load(ROOT,name)
  with self.assertRaises(ValueError):load(ROOT,'unknown.py')
 def test_current_receipt_shape_only_never_creates_packet(self):
  _,G=self.gate();value=self.receipt();self.assertEqual(P.private(value,G),value);self.assertEqual(list(self.root.iterdir()),[])
 def test_old_gnu_caa2_wrong_source_archive_and_not_actual16k_refuse(self):
  _,G=self.gate();value=self.receipt()
  for key,bad in (('candidate',dict(G.EXPECTED,version='2.43.caa1-1')),('candidate',dict(G.EXPECTED,version='2.43.caa2-1')),('status','FAIL'),('native_source','0'*40),('candidate_package_sha256','b852e3fc647d63699c5f42003a748cbd2268991dc2615a494dc3cdda4d757d12'),('page_size',4096),('cases',7),('runtime_records',11),('actual_parent_child_providers','UNKNOWN'),('ordered_cleanup','UNKNOWN'),('hardware','PASS')):
   v=copy.deepcopy(value);v[key]=bad
   with self.subTest(key=key),self.assertRaises(ValueError):P.private(v,G)
 def test_package_build_or_source_carrier_does_not_supply_runtime(self):
  _,G=self.gate();value=self.receipt()
  for key,bad in (('source_sha',value['native_source']),('source_sha',G.EXPECTED['source_packet_ref']),('source_sha',P.PACKET_REF),('run_id',38994309021),('run_id',0),('source_sha','main')):
   v=copy.deepcopy(value);v[key]=bad
   with self.subTest(key=key),self.assertRaises(ValueError):P.private(v,G)
 def test_missing_receipt_and_digest_refuse_before_any_output_or_helper(self):
  args=NS(repo=ROOT,output=self.root/'output',private_decision=None,private_sha256=None)
  with patch.object(P,'helpers',side_effect=AssertionError('no helper before actual receipt')),self.assertRaisesRegex(ValueError,'UNBOUND'):P.convert(args)
  self.assertEqual(list(self.root.iterdir()),[])
 def test_changed_root_receipt_digest_refuses_before_packet_reads_output(self):
  p=self.root/'receipt';p.write_bytes(P.encoded(self.receipt()));args=NS(repo=ROOT,output=self.root/'output',private_decision=p,private_sha256='0'*64,packet=self.root/'MISSING')
  with self.assertRaisesRegex(ValueError,'decision digest'):P.convert(args)
  self.assertEqual({p.name for p in self.root.iterdir()},{'receipt'})
 def test_default_native_packet_policy_unbound_before_source_output(self):
  ci=self.root/'ci';ci.mkdir();shutil.copyfile(HERE/'source-pins.json',ci/'source-pins.json');policy=json.loads((HERE/'policy.json').read_bytes());policy.update(status='UNBOUND_CAA3_ACTUAL_CURRENT_PRIVATE16K_AND_NATIVE_PACKET',packet=None);(ci/'policy.json').write_bytes(P.encoded(policy))
  with patch.object(P,'HERE',ci),self.assertRaisesRegex(ValueError,'UNBOUND'):P.emit(NS(repo=ROOT,output=self.root/'never-created-next-source'))
  self.assertFalse((self.root/'never-created-next-source').exists())
 def test_first_stage_packet_cannot_be_bound_as_native_lifecycle(self):
  _,G=self.gate();v=dict(schema_version=1,status='ROOT_BOUND_IMMUTABLE_PROVIDER_PACKET',packet=dict(ref=P.PACKET_REF,directory='payload',index_sha256=P.INDEX['sha256']),candidate=G.EXPECTED)
  with self.assertRaisesRegex(ValueError,'future converted'):P.binding(v,G)
  v['packet']['ref']='2'*40;self.assertEqual(P.binding(v,G),v['packet'])
 def test_composed32_sources_bound_only_two_normal_owner_files_no_native_actor(self):
  repo=self.root/'repo';repo.mkdir();rows=P.source(ROOT)
  for name in rows:
   p=repo/name;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/name,p)
  ci=repo/'next-ci';ci.mkdir();shutil.copyfile(HERE/'source-pins.json',ci/'source-pins.json');_,G=self.gate();policy=dict(schema_version=1,status='ROOT_BOUND_IMMUTABLE_PROVIDER_PACKET',packet=dict(ref='2'*40,directory='payload',index_sha256='3'*64),candidate=G.EXPECTED);(ci/'policy.json').write_bytes(P.encoded(policy))
  with patch.object(P,'HERE',ci):value=P.emit(NS(repo=repo,output=repo/'generated'))
  output=repo/'generated';self.assertEqual(value['derived_files'],32);self.assertEqual(value['source_files'],98);self.assertEqual(value['changed_normal_owner_files'],['policy.json','integration-manifest.json']);self.assertEqual(json.loads((output/(P.NATIVE+'-owner')/'policy.json').read_bytes())['packet'],policy['packet']);self.assertIn('UNBOUND',json.loads((output/'scripts/ci/glibc-debian-maintained-provider-interruption-owner/policy.json').read_bytes())['status']);self.assertEqual((output/'manifests/packages.toml').read_bytes(),(ROOT/'manifests/packages.toml').read_bytes())
 def test_converter_calls_original_phase_candidate_and_both_normal13_checks(self):
  tree=ast.parse((HERE/'prepare.py').read_bytes());node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='convert');text=ast.get_source_segment((HERE/'prepare.py').read_text(),node);self.assertEqual(text.count('P.normal_checks('),2);self.assertIn('G.validate(C,temporary,index)',text);self.assertIn('pure(repo,P.PHASE).validate(C,a.packet,index)',text);self.assertIn("original_files=dict(index['files'])",text);self.assertIn('P.exact(row,P.read(temporary/n,256*MiB))',text);self.assertIn("len(files)==23",text)
 def test_wrong_helpers_fail_before_import_and_no_working_tree_mutation(self):
  repo=self.root/'repo';repo.mkdir();rows=P.source(ROOT)
  for name in rows:
   p=repo/name;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/name,p)
  (repo/P.STAGE).write_text('raise AssertionError("MUST NOT IMPORT")')
  with self.assertRaisesRegex(ValueError,'exact next-phase helper'):P.helpers(repo)
 def test_workflow_preserves_native_roles_bounds_summary_order_and_unbound_before_secrets(self):
  path='.github/workflows/native-arm-glibc-debian-maintained-provider-lifecycle.yml';root=next(p for p in HERE.parents if (p/path).is_file());text=(root/path).read_text();positions=[text.index(t) for t in ('id: adaptation','id: proof','id: packet','secrets.','Reuse unchanged owned574','"$SLICE/job.py" execute','"$SLICE/job.py" cleanup','"$SLICE/job.py" retain','--retain-exit "$retain_status"','uses: actions/upload-artifact')];self.assertEqual(positions,sorted(positions))
  for term in ('timeout-minutes: 180','timeout-minutes: 80','timeout-minutes: 15','timeout-minutes: 5','--workspace "$BUNDLE"','maintained-lifecycle-source','glibc-debian-maintained-provider-lifecycle-${{','if [ "$retain_status" -ne 0 ]; then exit "$retain_status"; fi','persist-credentials: false','cancel-in-progress: false'):self.assertIn(term,text)
  self.assertNotIn('--privileged',text);self.assertNotIn('--security-opt=apparmor=unconfined',text)
if __name__=='__main__':unittest.main(verbosity=2)

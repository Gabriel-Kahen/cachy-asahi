# SPDX-License-Identifier: MIT
"""Pure actual-source/operand controls; MODEL argv/failure data, never fake builds."""
import argparse,ast,copy,hashlib,importlib.util,json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('minimal206_constructor',HERE/'prepare.py');P=importlib.util.module_from_spec(s);s.loader.exec_module(P)
parser=argparse.ArgumentParser(add_help=False);parser.add_argument('--source95',type=Path,default=Path('/home/gabe/Documents/ChatGPT/cachy-asahi-llhttp-inner-public-retention-v6-20261117/artifacts/development/llhttp-inner-public-retention-v6-20261117-r1/Source95-DATA'));parser.add_argument('--intake',type=Path,default=HERE.parents[2]/'scripts/port/minimal-native-builder-inputs');parser.add_argument('--package-proof',type=Path,default=HERE/'fixtures/material-check.DATA.json');parser.add_argument('--acquisition-proof',type=Path,default=HERE/'fixtures/acquisition-with-catalogs.DATA.json');args,UNIT_ARGS=parser.parse_known_args();PARENT=args.source95;INTAKE=args.intake;PROOF=args.package_proof;RETRIEVAL=args.acquisition_proof
def module(path,name):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
class Controls(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.old=P.parent_bodies(PARENT);cls.native,cls.expected,cls.proofs,cls.signatures=P.intake(INTAKE,PROOF,RETRIEVAL);cls.b=P.assemble(cls.old,cls.native,cls.expected,cls.signatures);cls.temp=tempfile.TemporaryDirectory(prefix='minimal206-source-');cls.root=Path(cls.temp.name)/'Source';P.construct(PARENT,INTAKE,PROOF,RETRIEVAL,cls.root)
  cls.D=module(cls.root/P.NO/'data.py','minimal206_data');cls.C=module(cls.root/P.NB/'contract.py','minimal206_contract');cls.E=module(cls.root/P.NO/'public_evidence.py','minimal206_public');cls.Q=module(cls.root/P.NO/'source_readonly.py','minimal206_readonly');cls.profile=P.decode(cls.b[P.NB+'profile.json']);cls.policy=P.decode(cls.b[P.NO+'policy.json'])
 @classmethod
 def tearDownClass(cls):cls.temp.cleanup()
 def test_ACTUAL_whole_maintained_intake_and95_inputs_and_complete_inverse(self):
  self.assertEqual(P.inverse(self.b),self.old);self.assertEqual(len(self.b),96);self.assertLess(sum(map(len,self.b.values())),2*1024**2);self.assertEqual(P.pin(self.native),P.NATIVE);self.assertEqual(P.pin(self.expected),P.EXPECTED);self.assertEqual(len(self.expected.splitlines()),206);self.assertEqual(P.decode(self.native)['rootfs_packages'],P.decode(self.old[P.OB+'runtime/scripts/ci/inputs.lock.json'])['rootfs_packages']);self.D.source(self.root,P.pin(self.b['source-map.json'])['sha256'])
  marker=P.decode(self.b[P.MARKER]);self.assertEqual(marker['intake_lock'],P.pin((INTAKE/'source.lock.json').read_bytes()));self.assertEqual(marker['intake_revision'],P.INTAKE_REVISION)
  bad=dict(self.b);bad[P.MARKER]=P.encoded(dict(marker,intake_lock=P.ORIGINAL_INTAKE_LOCK));self.assertRaisesRegex(ValueError,'whole canonical',P.inverse,bad)
 def test_complete_changed_preimages_and_membership_tamper_refuse(self):
  for n in(P.NB+'expected206.lock',P.NB+'runtime/scripts/ci/inputs.lock.json',P.NB+'contract.py',P.NO+'hosted_owner.py',P.NO+'public_evidence.py',P.MARKER):
   bad=dict(self.b);bad[n]+=b'x'
   with self.subTest(leaf=n):self.assertRaises((ValueError,KeyError,json.JSONDecodeError),P.inverse,bad)
  bad=dict(self.b);bad['MODEL-unlisted']=b'never selected';self.assertRaises(ValueError,P.inverse,bad)
 def test_corrupt_parent_and206_operands_refuse(self):
  old=dict(self.old);old[P.OB+'runtime/scripts/ci/inputs.lock.json']+=b'x';self.assertRaises(ValueError,P.validate_parent,old);self.assertRaises(ValueError,P.assemble,self.old,self.native+b'x',self.expected,self.signatures);self.assertRaises(ValueError,P.assemble,self.old,self.native,self.expected+b'x',self.signatures)
 def test_recipe_and_all_history_bytes_preserved(self):
  for n,b in self.old.items():
   if '/recipe/'in n or n.startswith('previous-')or n.endswith(('recipe-pin.json','reviewed-inputs.json')):self.assertEqual(self.b[P.renamed(n)],b,n)
  self.assertEqual(self.b[P.NB+'runtime/scripts/ci/old_four_seed.py'],self.old[P.OB+'runtime/scripts/ci/old_four_seed.py'])
 def test_no_old_private_seed_or_secret_route_in_new_operation(self):
  w=self.b['.github/workflows/native-arm-llhttp-minimal-builder-source.yml'].decode();self.assertNotIn('secrets.',w);self.assertNotIn('CACHY_OLD_FOUR_',w);self.assertNotIn('CACHY_RETAINED_',w);self.assertNotIn('seed_current_build_cache(',self.b[P.NB+'entry.py'].decode());self.assertNotIn('expected349',self.b[P.NB+'profile.json'].decode());self.assertIn('builder_input_authentication',self.b[P.NB+'admission.TEMPLATE.json'].decode())
 def test_two_clean_build_and_required_byte_comparison_plans(self):
  builds,compare=self.C.plans(self.root/P.NB,Path('/MODEL/nonexecuted'),'sha256:'+'0'*64);self.assertEqual(len(builds),2)
  for i,args in enumerate(builds,1):self.assertEqual(args[args.index('--network')+1],'none');self.assertEqual(args[args.index('--expected-packages')+1],str(self.root/P.NB/'expected206.lock'));self.assertEqual(args[-1],'/MODEL/nonexecuted/build-'+str(i))
  self.assertIn('--require-bytes',compare);self.assertEqual(self.C.projected_build(self.b[P.NB+'runtime/scripts/build/build_v2.py']),self.b[P.NB+'runtime/scripts/build/build_llhttp-reference.py']);self.assertEqual(self.C.projected_compare(self.b[P.NB+'runtime/scripts/build/compare_v2.py']),self.b[P.NB+'runtime/scripts/build/compare_llhttp.py'])
 def test_public_signature_seed_exactly206_and_native_audit_still_follows(self):
  with tempfile.TemporaryDirectory(prefix='MODEL-public-signatures-')as t:
   cache=Path(t);cache.chmod(0o700);row=self.C.seed_minimal_public_signatures(cache,P.decode(self.native),self.profile);self.assertEqual(row['files'],206);self.assertEqual(row['bytes'],116596);self.assertEqual(len(list(cache.iterdir())),206)
   name=next(iter(self.signatures));p=cache/name;p.write_bytes(b'corrupt');self.assertRaises(ValueError,self.C.seed_minimal_public_signatures,cache,P.decode(self.native),self.profile)
  code=self.b[P.NB+'entry.py'].decode();self.assertLess(code.index('C.seed_minimal_public_signatures('),code.index('native.audit(inputs,'));self.assertLess(code.index('native.audit(inputs,'),code.index('image=native.build('))
 def test_all_resource_values_and_retention_allowlists_unchanged(self):
  self.assertEqual(self.profile['resources'],P.decode(self.old[P.OB+'profile.json'])['resources']);prior=P.decode(self.old[P.OLD+'owner/policy.json'])
  for k in('owner','daemon','controller','storage_bytes','cleanup_seconds','pair_seconds','host_reserve_bytes','controller_scope_seconds','controller_work_seconds','docker_cli_address_space','host_tools'):self.assertEqual(self.policy[k],prior[k])
  self.assertEqual(self.E.PUBLIC_LEAVES,tuple(prior['inner_public_retention']['public_leaves']));self.assertEqual(self.E.SUCCESS_REQUIRED,tuple(prior['inner_public_retention']['success_required']));self.assertEqual(self.E.MAX_BYTES,16*1024**2)
 def test_NULL_authentication_and_legacy_admission_refuse_before_actor(self):
  a=P.decode(self.b[P.NB+'admission.TEMPLATE.json']);r=P.decode(self.b[P.NB+'runtime.TEMPLATE.json']);self.assertIsNone(a['builder_input_authentication']);self.assertIsNone(r['builder_input_authentication']);self.assertRaisesRegex(ValueError,'authentication',self.C.minimal_inputs,a,r,self.profile)
  old_a=P.decode(self.old[P.OB+'admission.TEMPLATE.json']);old_r=P.decode(self.old[P.OB+'runtime.TEMPLATE.json']);self.assertRaises(ValueError,self.C.admitted,old_a,old_r,'0'*64,{},self.profile,1)
  self.assertTrue(all(x is None for x in P.decode(self.b['source-map.json'])['actual'].values()))
 def test_readonly_exact_Source_projection_and_overlap_refusals(self):
  nonce='a'*32
  with tempfile.TemporaryDirectory(prefix='MODEL-sourceRO-')as t:
   out=Path(t)/'owned';log=out/'volume'/'owner.log';args=self.D.service_args(nonce,'owner',self.policy['owner'],['/MODEL/not-executed'],log,os.getuid(),os.getgid());projected=self.Q.project_service(args,self.root,out,nonce,'owner');self.assertIn('--property=BindReadOnlyPaths='+str(self.root),projected);self.assertIn('--property=ReadOnlyPaths=/tmp /var/tmp /sys/fs/cgroup',projected);self.assertRaises(ValueError,self.Q.project_service,args,self.root,self.root/'overlap',nonce,'owner')
   changed=list(args);changed.insert(changed.index('--'),'--property=BindPaths=/MODEL');self.assertRaises(ValueError,self.Q.project_service,changed,self.root,out,nonce,'owner')
 def test_finite_failed_payload_receipts_retained_before_cleanup(self):
  expected=dict(source='1'*40,ref='refs/heads/codex/MODEL',source_map_sha256='2'*64,run='123456',attempt=1,job='pair',nonce='3'*32)
  with tempfile.TemporaryDirectory(prefix='MODEL-public-failure-')as t:
   root=Path(t);inner=root/'volume/work/llhttp-minimal-builder-native';inner.mkdir(parents=True);public=root/'evidence';report=dict(expected,status='HOLD',Root_acceptance=None,hardware='NOT RUN',release='NOT ADMITTED',failure=dict(type='MODEL_FAILURE_ONLY'))
   (inner/'report.json').write_bytes(P.encoded(report));(inner/'cleanup.json').write_bytes(P.encoded(dict(MODEL=True)));(inner/'bootstrap').mkdir();(inner/'bootstrap/acquisition.json').write_bytes(P.encoded(dict(status='MODEL_FAILURE_ONLY')));(inner/'private-MODEL-unread').mkdir();(inner/'private-MODEL-unread/never-open').write_bytes(b'MODEL irrelevant')
   row=self.E.export(inner,public,expected,os.getuid());self.assertEqual(row['status'],'EXPORTED');self.assertFalse(row['accepting']);self.assertEqual(P.decode((public/'report.json').read_bytes())['failure'],report['failure']);self.assertFalse((public/'private-MODEL-unread').exists())
   outer=dict(status='HOLD');self.E.preserve(outer,inner,public,expected,os.getuid());self.assertEqual(outer['status'],'HOLD');self.assertEqual(outer['inner_public_evidence']['status'],'REFUSED')
  code=self.b[P.NO+'hosted_owner.py'].decode();self.assertLess(code.index('        E.preserve('),code.index("report['cleanup']=owner.cleanup("));self.assertIn("if report['status']",code)
 def test_all_python_parses_and_closed_export_refuses_extra_member(self):
  for n,b in self.b.items():
   if n.endswith('.py'):ast.parse(b,filename=n)
  extra=self.root/'MODEL-unlisted';extra.write_bytes(b'never');extra.chmod(0o644)
  try:self.assertRaises(ValueError,self.D.source,self.root,P.pin(self.b['source-map.json'])['sha256'])
  finally:extra.unlink()
if __name__=='__main__':unittest.main(argv=['test_data.py',*UNIT_ARGS],verbosity=2)

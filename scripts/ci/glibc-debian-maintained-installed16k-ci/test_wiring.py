# SPDX-License-Identifier: MIT
"""Finite source composition controls; modeled decisions confer no authority."""
import copy,hashlib,importlib.util,json,re,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
ROOT=next(p for p in HERE.parents if (p/'manifests/packages.toml').is_file())
CI='scripts/ci/glibc-debian-maintained-installed16k-ci'
LANE='scripts/ci/glibc-debian-maintained-installed16k'
NEXT='scripts/ci/glibc-debian-maintained-native-lifecycle-next'
WF='.github/workflows/native-arm-glibc-debian-maintained-installed16k.yml'
def load(name,p):
 spec=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
class Controls(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.work=Path(self.temp.name);self.root=self.work/'repo';self.root.mkdir();self.ci=self.root/CI
  manifest=json.loads((HERE/'integration-manifest.json').read_bytes())
  for name in manifest['files']:
   source=HERE/Path(name).name if name.startswith(CI+'/') else ROOT/name
   p=self.root/name;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,p)
  shutil.copyfile(HERE/'integration-manifest.json',self.ci/'integration-manifest.json')
  self.A=load('maintained_ci_adapter',self.ci/'wiring.py');self.W=self.A.implementation(self.root)
  self.env=dict(SOURCE_SHA='1'*40,WORKFLOW_SHA='1'*40,GITHUB_SHA='1'*40,RUNNER_ARCH='ARM64',RUNNER_OS='Linux')
  p=patch.object(subprocess,'Popen',side_effect=AssertionError('actors forbidden'));p.start();self.addCleanup(p.stop)
 def repin(self,*names):
  p=self.ci/'integration-manifest.json';v=json.loads(p.read_bytes())
  for name in names:v['files'][name]=pin((self.root/name).read_bytes())
  p.write_bytes(encoded(v))
 def fixture(self):
  W=self.W;policy=W.decode(W.read(self.ci/'policy.json'));candidate=policy['candidate'];phase=W.load('fixture_phase',self.root/LANE/'phase_gate.py');inputs={};roots={}
  for i,kind in enumerate(W.KINDS,2):
   root=self.work/kind;root.mkdir();roots[kind]=root
   row=dict(candidate=candidate,status=phase.STATUSES[kind],source_sha=str(i)*40,run_id=i,hardware='NOT_RUN',release='NOT_ADMITTED',source_authority_sha256=candidate['authority_sha256'],native_pair=phase.PAIR,provider_archive_sha256=phase.PAIR['archive_sha256'],provider_archive_bytes=phase.ARCHIVE_BYTES)
   if kind=='native_lifecycle':row.update(ordered_cleanup='PASS',ALPM_installation='PASS',page_size=4096)
   else:row.update(cleanup='PASS',page_size=16384,scope='DATA_STAGED_PRIVATE_ROOT_NOT_ALPM_INSTALLATION',ALPM_installation='NOT_RUN')
   raw=encoded(row);(root/'decision.json').write_bytes(raw);inputs[kind]=dict(ref=str(i)*40,path='decision.json',**pin(raw))
  packet=dict(ref='4'*40,directory='payload',index_sha256='a'*64)
  policy.update(status='BOUND_BY_ROOT',binding=inputs,native_packet=packet);(self.ci/'policy.json').write_bytes(encoded(policy))
  p=self.root/NEXT/'policy.json';v=W.decode(W.read(p));v.update(status='ROOT_BOUND_IMMUTABLE_PROVIDER_PACKET',packet=packet);p.write_bytes(encoded(v));self.repin(CI+'/policy.json',NEXT+'/policy.json');return inputs,roots
 def heads(self,roots):return patch.object(self.W,'head',side_effect=lambda p:self.env['SOURCE_SHA'] if p==self.root else ('2' if p==roots['native_lifecycle'] else '3')*40)
 def assemble(self,inputs,roots):
  with self.heads(roots):return self.W.assemble(self.root,self.work/'vm',roots,inputs,self.env,self.work/'public')
 def alter(self,inputs,roots,kind,**changes):
  p=roots[kind]/'decision.json';v=json.loads(p.read_bytes());v.update(changes);p.write_bytes(encoded(v));inputs[kind].update(pin(p.read_bytes()));p=self.ci/'policy.json';v=json.loads(p.read_bytes());v['binding']=inputs;p.write_bytes(encoded(v));self.repin(CI+'/policy.json')
 def test_unbound_refuses_before_git_output_or_actor(self):
  p=self.ci/'policy.json';v=json.loads(p.read_bytes());v.update(status='UNBOUND_DO_NOT_EXECUTE',binding=dict.fromkeys(self.W.KINDS),native_packet=None);p.write_bytes(encoded(v))
  with self.assertRaisesRegex(ValueError,'UNBOUND'):self.W.preflight(self.root,dict.fromkeys(self.W.KINDS),self.env)
  self.assertEqual({p.name for p in self.work.iterdir()},{'repo'})
 def test_exact_descriptor_dispatch_and_json_refusals(self):
  inputs,_=self.fixture();W=self.W;policy=W.decode(W.read(self.ci/'policy.json'));self.assertEqual(W.selection(policy,inputs),inputs)
  for field,value in (('ref','main'),('path','../x'),('path','/x'),('bytes',True),('bytes',W.LIMIT+1),('sha256','a'*63)):
   v=copy.deepcopy(inputs);v['native_lifecycle'][field]=value
   with self.subTest(field=field,value=value),self.assertRaises(ValueError):W.selection(policy,v)
  for raw in (b'{"x":1,"x":2}',b'{"x":NaN}'):
   with self.assertRaises(ValueError):W.decode(raw)
  p=self.work/'alias';p.symlink_to(self.ci/'policy.json')
  with self.assertRaises(ValueError):W.read(p)
 def test_exact143_source_and_shared_derivation(self):
  W=self.W;self.assertEqual(len(W.check_source(self.root)),146);self.assertEqual(W.derivation['unchanged_shared_validation'],'ALL_OTHER_CODE_BYTE_IDENTICAL')
  self.assertIn('sys.modules[spec.name]=mod',self.A.derive(self.root)[0]);(self.root/self.A.SHARED).write_text('changed')
  with self.assertRaisesRegex(ValueError,'exact shared CI source pin'):self.A.derive(self.root)
 def test_native_packet_must_be_bound_and_identical_before_outputs(self):
  inputs,roots=self.fixture();p=self.root/NEXT/'policy.json';v=json.loads(p.read_bytes());v['packet']['index_sha256']='b'*64;p.write_bytes(encoded(v));self.repin(NEXT+'/policy.json')
  with self.heads(roots),self.assertRaisesRegex(ValueError,'exact Root published native packet'):self.W.preflight(self.root,inputs,self.env)
  self.assertFalse((self.work/'vm').exists())
 def test_frozen_source_arm_and_decision_checkout_required(self):
  inputs,roots=self.fixture()
  for key,value in [('SOURCE_SHA','main'),('WORKFLOW_SHA','4'*40),('GITHUB_SHA','4'*40),('RUNNER_ARCH','X64'),('RUNNER_OS','Windows')]:
   env=dict(self.env);env[key]=value
   with self.heads(roots),self.subTest(key=key),self.assertRaises(ValueError):self.W.preflight(self.root,inputs,env)
  with patch.object(self.W,'head',return_value='1'*40),self.assertRaisesRegex(ValueError,'decision checkout'):self.W.assemble(self.root,self.work/'vm',roots,inputs,self.env,self.work/'public')
  self.assertFalse((self.work/'vm').exists())
 def test_pinned_decision_bytes_required(self):
  inputs,roots=self.fixture();(roots['native_lifecycle']/'decision.json').write_text('changed')
  with self.assertRaisesRegex(ValueError,'decision bytes differ'):self.assemble(inputs,roots)
  self.assertFalse((self.work/'vm').exists())
 def test_full149_bundle_preserves116_and15_and_bound_gate(self):
  inputs,roots=self.fixture();receipt=self.assemble(inputs,roots);self.assertEqual((receipt['source_files'],receipt['derived_files'],receipt['bundle_files']),(119,31,153));self.assertEqual(receipt['runtime'],'NOT_RUN');vm=self.work/'vm';original=json.loads((vm/'adaptation.json').read_bytes());held=json.loads((self.root/LANE/'source-pins.json').read_bytes())['files']
  for name,row in held.items():self.assertEqual(pin((vm/name).read_bytes()),row)
  changed={n for n,row in original['files'].items() if pin((vm/n).read_bytes())!=row};self.assertEqual(changed,{LANE+'/input-policy.json',LANE+'/source-manifest.json'})
  C=self.W.load('joined_contract',vm/LANE/'contract.py');self.assertIs(sys.modules[C.__name__],C);C.check_source(vm);self.assertEqual(set(C.gate(vm/LANE/'prerequisites')),{'native_lifecycle','system16k'});self.W.public_check(self.work/'public')
  for name in original['files']:
   if name.endswith('.py'):compile((vm/name).read_bytes(),name,'exec')
 def test_native_binding_is_separate_and_vm_never_rewritten(self):
  inputs,roots=self.fixture();self.assemble(inputs,roots);vm=self.work/'vm';before={p.relative_to(vm).as_posix():pin(p.read_bytes()) for p in vm.rglob('*') if p.is_file()};output=self.root/'native-source'
  with self.heads(roots):receipt=self.A.native_source(self.W,self.root,vm,output,inputs,self.env)
  self.assertEqual(receipt['changed_normal_owner_files'],['policy.json','integration-manifest.json']);self.assertEqual(receipt['source_files'],98);self.assertEqual(receipt['derived_files'],32)
  self.assertEqual(before,{p.relative_to(vm).as_posix():pin(p.read_bytes()) for p in vm.rglob('*') if p.is_file()})
  owner='scripts/ci/glibc-debian-maintained-provider-lifecycle-owner';self.assertEqual(json.loads((vm/owner/'policy.json').read_bytes())['status'],'UNBOUND_CAA3_ACTUAL_NATIVE_PAIR_AND_PACKET');self.assertEqual(json.loads((output/owner/'policy.json').read_bytes())['status'],'ROOT_BOUND_IMMUTABLE_PROVIDER_PACKET')
 def test_native_source_refuses_noncheckout_output(self):
  inputs,roots=self.fixture();self.assemble(inputs,roots)
  with self.heads(roots),self.assertRaisesRegex(ValueError,'direct fresh checkout child'):self.A.native_source(self.W,self.root,self.work/'vm',self.work/'bad',inputs,self.env)
  self.assertFalse((self.work/'bad').exists())
 def test_staged_cannot_replace_actual_native_alpm(self):
  inputs,roots=self.fixture();self.alter(inputs,roots,'native_lifecycle',ALPM_installation='NOT_RUN',page_size=16384)
  with self.assertRaisesRegex(ValueError,'actual normal ALPM-installed native'):self.assemble(inputs,roots)
  self.assertFalse((self.work/'public').exists())
 def test_wrong_candidate_authority_and_pair_refuse(self):
  inputs,roots=self.fixture();self.alter(inputs,roots,'system16k',source_authority_sha256='0'*64)
  with self.assertRaisesRegex(ValueError,'identity/authority/archive'):self.assemble(inputs,roots)
  self.assertFalse((self.work/'public').exists())
 def test_export_closed_seven_bounded_metadata_files(self):
  inputs,roots=self.fixture();self.assemble(inputs,roots);public=self.work/'public';self.assertEqual(len(list(public.iterdir())),7);self.W.public_check(public);(public/'extra').write_text('extra')
  with self.assertRaisesRegex(ValueError,'closed wiring'):self.W.public_check(public)
 def test_workflow_separate_sources_order_bounds_roles_and_stamps(self):
  wf=ROOT/WF
  proposed=next((p/WF for p in HERE.parents if (p/WF).is_file()),None)
  if proposed is not None:wf=proposed
  text=wf.read_text();self.assertNotIn('runner.temp',text.split('    env:',1)[1].split('    steps:',1)[0]);positions=[text.index(s) for s in ('id: decisions','id: wiring','wiring.py native-source','id: proof','id: packet','Seed the six existing private','Reuse unchanged owned574','id: installed16k','PYBARRIER','"$SLICE/job.py" cleanup','"$SLICE/job.py" retain')];self.assertEqual(positions,sorted(positions))
  for term in ('--workspace "$NATIVE_BUNDLE"','--workspace "$VM_SOURCE" --acceptances "$VM_SOURCE/','NATIVE_LIFECYCLE_DECISION:','SYSTEM16K_DECISION:','timeout-minutes: 360','timeout-minutes: 220','timeout-minutes: 80','PASS_ALL_ACTORS_GROUPS_AND_DISKS_REMOVED',"len(value['files'])<=320",'544*1024**2','persist-credentials: false','--owner "$RUNNER_TEMP/provider-lifecycle-owner"','874ef68d04ac8c831b90bb01a387cfabb58fceb60842c49a0d0e58bcd6c146ad',"'native_lifecycle'", "'installed16k'"):
   self.assertIn(term,text)
  self.assertIn(pin((HERE/'wiring.py').read_bytes())['sha256'],text);self.assertIn(pin((HERE/'integration-manifest.json').read_bytes())['sha256'],text)
  for path in re.findall(r'python3 -I -B (scripts/[^ \n]+\.py)',text):self.assertTrue((self.root/path).is_file(),path)
  interface=json.loads((HERE/'input-interface.json').read_bytes());self.assertEqual(interface['source_bundles']['ci_pins'],141);self.assertEqual(interface['actual_execution'],'NOT_RUN')
if __name__=='__main__':unittest.main(verbosity=2)

# SPDX-License-Identifier: MIT
"""Portable bounded workflow/source controls. No Docker, QEMU or privileged actor."""
import copy,importlib.util,json,os,re,shutil,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;ROOT=next(p for p in HERE.parents if (p/'manifests/packages.toml').is_file());LANE='scripts/ci/glibc-gnu-provider-installed16k-interruption';WF='.github/workflows/native-arm-glibc-gnu-provider-installed16k-interruption.yml'
spec=importlib.util.spec_from_file_location('interrupted_wiring',HERE/'wiring.py');W=importlib.util.module_from_spec(spec);spec.loader.exec_module(W)
class Controls(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.work=Path(self.temp.name);self.root=self.work/'repo';self.root.mkdir();self.env=dict(SOURCE_SHA='1'*40,WORKFLOW_SHA='1'*40,GITHUB_SHA='1'*40,RUNNER_ARCH='ARM64',RUNNER_OS='Linux')
  manifest=W.decode(W.read(HERE/'integration-manifest.json'))
  for name in manifest['files']:
   src=ROOT/name
   if name.startswith(LANE+'/ci/'):src=HERE/Path(name).name
   dest=self.root/name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(src,dest)
  self.ci=self.root/LANE/'ci';shutil.copyfile(HERE/'integration-manifest.json',self.ci/'integration-manifest.json');p=patch.object(W,'HERE',self.ci);p.start();self.addCleanup(p.stop)
  p=patch.object(subprocess,'Popen',side_effect=AssertionError('actors forbidden'));p.start();self.addCleanup(p.stop)
 def fixture(self):
  inputs={};roots={};statuses=dict(native_interruption='ROOT_ACCEPTED_CONVENTIONAL_PROVIDER_INTERRUPTION_RECOVERY',normal_installed16k='ROOT_ACCEPTED_GENERIC16K_ALPM_PROVIDER_NORMAL_LIFECYCLE_AND_RECOVERY')
  for i,kind in enumerate(W.KINDS,2):
   root=self.work/kind;root.mkdir();roots[kind]=root;value=dict(status=statuses[kind],source_sha=str(i)*40,run_id=i,hardware='NOT_RUN',ordered_cleanup='PASS',provider_archive_sha256='b852e3fc647d63699c5f42003a748cbd2268991dc2615a494dc3cdda4d757d12',page_size=16384,ALPM_installation='PASS');raw=W.encoded(value);(root/'decision.json').write_bytes(raw);inputs[kind]=dict(ref=str(i)*40,path='decision.json',**W.pin(raw))
  policy=dict(schema_version=1,status='BOUND_BY_ROOT',binding=inputs);(self.ci/'policy.json').write_bytes(W.encoded(policy));self.repin_policy();return inputs,roots
 def repin_policy(self):
  p=self.ci/'integration-manifest.json';v=W.decode(W.read(p));v['files'][LANE+'/ci/policy.json']=W.pin(W.read(self.ci/'policy.json'));p.write_bytes(W.encoded(v))
 def heads(self,roots):return patch.object(W,'head',side_effect=lambda root:self.env['SOURCE_SHA'] if root==self.root else ('2' if root==roots['native_interruption'] else '3')*40)
 def assemble(self,inputs,roots):
  with self.heads(roots):return W.assemble(self.root,self.work/'bundle',roots,inputs,self.env,self.work/'public')
 def test_unbound_refuses_before_git_output_or_actor(self):
  with self.assertRaisesRegex(ValueError,'UNBOUND'):W.preflight(self.root,dict.fromkeys(W.KINDS),self.env)
  self.assertEqual(set(p.name for p in self.work.iterdir()),{'repo'})
 def test_closed_exact_root_bound_dispatch_inputs(self):
  inputs,_=self.fixture();policy=W.decode(W.read(self.ci/'policy.json'));self.assertEqual(W.selection(policy,inputs),inputs)
  for field,value in (('ref','4'*40),('path','other.json'),('bytes',1),('sha256','0'*64)):
   v=copy.deepcopy(inputs);v['native_interruption'][field]=value
   with self.subTest(field=field),self.assertRaises(ValueError):W.selection(policy,v)
 def test_descriptor_rejects_branch_traversal_symlink_and_unbounded_data(self):
  row=dict(ref='2'*40,path='decision.json',bytes=1,sha256='a'*64)
  for field,value in (('ref','main'),('path','../decision.json'),('path','/absolute'),('bytes',True),('bytes',W.LIMIT+1),('sha256','a'*63)):
   v=dict(row);v[field]=value
   with self.subTest(field=field),self.assertRaises(ValueError):W.descriptor(v)
  p=self.work/'link';p.symlink_to(self.ci/'policy.json')
  with self.assertRaises(ValueError):W.read(p)
 def test_duplicate_and_nonfinite_json_rejected(self):
  for raw in (b'{"a":1,"a":2}',b'{"a":NaN}'):
   with self.assertRaises(ValueError):W.decode(raw)
 def test_source_and_architecture_identity_required(self):
  inputs,roots=self.fixture()
  for field,value in (('GITHUB_SHA','4'*40),('WORKFLOW_SHA','4'*40),('SOURCE_SHA','main'),('RUNNER_ARCH','X64'),('RUNNER_OS','Windows')):
   env=dict(self.env);env[field]=value
   with self.heads(roots),self.subTest(field=field),self.assertRaises(ValueError):W.preflight(self.root,inputs,env)
 def test_exact113_source_closure_refuses_mutation(self):
  self.assertEqual(len(W.check_source(self.root)),115);(self.root/'scripts/ci/glibc-gnu-provider-interruption/container.py').write_text('changed')
  with self.assertRaisesRegex(ValueError,'exact workflow source'):W.check_source(self.root)
 def test_complete121_bundle_preserves104_and_changes_only_effective_policy_manifest(self):
  inputs,roots=self.fixture();value=self.assemble(inputs,roots);self.assertEqual(value['bundle_files'],124);self.assertEqual(value['runtime'],'NOT_RUN');bundle=self.work/'bundle';original=W.decode(W.read(bundle/'adaptation.json'));pins=W.decode(W.read(self.root/LANE/'source-pins.json'))['files']
  for name,row in pins.items():self.assertEqual(W.pin(W.read(bundle/name)),row)
  changed=[name for name,row in original['files'].items() if W.pin(W.read(bundle/name))!=row];self.assertEqual(set(changed),{LANE+'/input-policy.json',LANE+'/source-manifest.json'});W.public_check(self.work/'public')
  for name in original['files']:
   if name.endswith('.py'):compile(W.read(bundle/name),name,'exec')
 def test_decision_checkout_and_bytes_are_pinned(self):
  inputs,roots=self.fixture();(roots['native_interruption']/'decision.json').write_text('changed')
  with self.assertRaisesRegex(ValueError,'decision bytes differ'):self.assemble(inputs,roots)
  self.assertFalse((self.work/'bundle').exists())
 def test_wrong_decision_git_identity_refused_before_output(self):
  inputs,roots=self.fixture()
  with patch.object(W,'head',return_value='1'*40),self.assertRaisesRegex(ValueError,'decision checkout'):W.assemble(self.root,self.work/'bundle',roots,inputs,self.env,self.work/'public')
  self.assertFalse((self.work/'bundle').exists())
 def test_staged16k_does_not_substitute_for_normal_alpm_acceptance(self):
  inputs,roots=self.fixture();path=roots['normal_installed16k']/'decision.json';v=W.decode(W.read(path));v['ALPM_installation']='NOT_RUN';path.write_bytes(W.encoded(v));inputs['normal_installed16k'].update(W.pin(W.read(path)));p=W.decode(W.read(self.ci/'policy.json'));p['binding']=inputs;(self.ci/'policy.json').write_bytes(W.encoded(p));self.repin_policy()
  with self.assertRaisesRegex(ValueError,'full installed16K'):self.assemble(inputs,roots)
  self.assertFalse((self.work/'public').exists())
 def test_export_closed_metadata_no_source_payload(self):
  inputs,roots=self.fixture();self.assemble(inputs,roots);public=self.work/'public';self.assertEqual(len(list(public.iterdir())),7);self.assertLessEqual(sum(p.stat().st_size for p in public.iterdir()),512*1024+65536);(public/'unlisted').write_text('extra')
  with self.assertRaisesRegex(ValueError,'closed wiring'):W.public_check(public)
 def test_workflow_source_bundle_owner_cleanup_order_bounds_and_fixed_actions(self):
  wf=ROOT/WF
  if not wf.exists():wf=next(p for p in HERE.parents if (p/WF).is_file())/WF
  text=wf.read_text();job_env=text.split('    env:',1)[1].split('    steps:',1)[0];self.assertNotIn('runner.temp',job_env)
  gate=text.index('wiring.py preflight --workspace');bundle=text.index("printf 'BUNDLE=%s/interrupted16k-source");self.assertLess(gate,bundle);self.assertLess(bundle,text.index('id: wiring'));self.assertIn('>> \"$GITHUB_ENV\"',text[bundle:text.index('id: wiring')])
  positions=[text.index(s) for s in ('id: decisions','id: wiring','id: proof','id: packet','Seed the six existing private','Reuse unchanged owned574','id: installed16k','PYBARRIER','"$SLICE/job.py" cleanup','"$SLICE/job.py" retain')];self.assertEqual(positions,sorted(positions))
  for term in ('timeout-minutes: 360','timeout-minutes: 220','timeout-minutes: 80','--workspace "$BUNDLE" --acceptances "$BUNDLE/','--owner "$RUNNER_TEMP/provider-interruption-owner"','PASS_ALL_ACTORS_GROUPS_AND_DISKS_REMOVED','len(value[\'files\'])<=320','544*1024**2','persist-credentials: false','--workspace "$GITHUB_WORKSPACE"','874ef68d04ac8c831b90bb01a387cfabb58fceb60842c49a0d0e58bcd6c146ad'):
   self.assertIn(term,text)
  for name in re.findall(r'python3 -I -B (scripts/[^ \n]+\.py)',text):self.assertTrue((self.root/name).is_file(),name)
  self.assertNotIn('${{ inputs.native_interruption_decision }}',text.split('steps:')[1]);self.assertNotIn('private16K receipt before secrets or actors',text)
if __name__=='__main__':unittest.main(verbosity=2)

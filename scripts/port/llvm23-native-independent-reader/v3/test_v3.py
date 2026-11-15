# SPDX-License-Identifier: MIT
"""Fenced corrected Source DATA and actual-tuple guard models, no operational role."""
import argparse,ast,contextlib,copy,ctypes,fcntl,hashlib,importlib.util,json,os,socket,subprocess,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('corrected_reader',HERE/'reader.py');r=importlib.util.module_from_spec(s);s.loader.exec_module(r);v=r.v
SOURCE=PARENT=ANCESTOR=None
class Controls(unittest.TestCase):
 def setUp(self):
  v.END=time.monotonic()+120;stack=contextlib.ExitStack();self.addCleanup(stack.close)
  def denied(*a,**k):raise AssertionError('operational Reader/process/network/lease forbidden')
  stack.enter_context(patch.object(r,'main',denied));stack.enter_context(patch.object(v,'main',denied));stack.enter_context(patch.object(v,'replay',denied));stack.enter_context(patch.object(v,'full_zip',denied))
  for module,names in((fcntl,('flock',)),(ctypes,('CDLL',)),(socket,('socket','create_connection')),(subprocess,('Popen','run','check_output')),(os,('fork','forkpty','system','posix_spawn','posix_spawnp','execv','execve','execvp','execvpe','pidfd_open','unshare','setns'))):
   for n in names:
    if hasattr(module,n):stack.enter_context(patch.object(module,n,denied))
 def pins(self):return v.load(HERE/'pins.json')
 def found(self):return v.source_namespace(SOURCE,self.pins())
 def model(self):
  pins=self.pins();pins.update(source='7'*40,ref='refs/heads/codex/MODELED-CORRECTED253-NOT-ACTUAL');b=v.load(HERE/'binding.TEMPLATE.json');b['actual']=dict(source=pins['source'],ref=pins['ref'],run='11',job='22',attempt=1,approval='a'*64,authority='MODELED_ROOT_AUTHORITY',image='sha256:'+'b'*64,artifact='33',reader='MODELED_READER')
  for n in('provider_sha256','source_commit_sha256','export_sha256','package_sha256','reader_sha256','pins_sha256'):b[n]='c'*64
  b['original_archive']=dict(bytes=1,sha256='d'*64);b['full_original_decode']=dict(bytes=1,files=1,map_sha256='e'*64)
  return b,pins
 def test_NULL_Root_template_refuses(self):
  b=v.load(HERE/'binding.TEMPLATE.json');self.assertTrue(all(x is None for x in b['actual'].values()))
  with self.assertRaises(ValueError):r.binding(b,self.pins())
 def test_Reader_scope_projection_never_changes_actual_tuple(self):
  b,pins=self.model();before=copy.deepcopy(b);self.assertEqual(r.binding(b,pins),before);self.assertEqual(b['actual'],before['actual']);self.assertEqual(b['source_map_sha256'],pins['source_map_sha256']);self.assertNotEqual(b['actual']['source'],r.PARENT['source'])
 def test_frozen_v2_inputs_and_historical_projection_inverse(self):
  self.assertEqual(hashlib.sha256(r.B.raw('reader.py')).hexdigest(),r.B.PINS['reader.py']);fn,proof=r.B.historical_successor();self.assertEqual(proof['seams'],6);self.assertFalse(proof['actual_Source_ref_run_job_map_changes']);self.assertEqual(proof['inverse'],'EXACT_FUNCTION_BYTES')
  with patch.object(r.B,'raw',return_value=b'def source_successor():pass'):
   with self.assertRaises(ValueError):r.B.historical_successor()
 def test_full253_to251_to248_source_inverse(self):
  found=self.found();restored=r.inverse251(SOURCE,dict(self.pins(),_ancestor_path=str(ANCESTOR)),found,PARENT);self.assertEqual(len(found),253);self.assertEqual(len(restored),251)
 def test_inverse_metadata_and_closed_failure_refusals(self):
  found=self.found();actual=v.load;meta=actual(SOURCE/'successor-v3.json')
  for mode in('before','alias','count','member','head','artifact','started'):
   bad=copy.deepcopy(meta)
   if mode=='before':bad['changed']['hosted/common.py']['before']['sha256']='0'*64
   elif mode=='alias':bad['changed']['hosted/common.py']['inverse']['old']='arbitrary-alias'
   elif mode=='count':bad['changed']['hosted/common.py']['inverse']['count']=2
   elif mode=='member':bad['changed'].pop('hosted/common.py')
   elif mode=='head':bad['parent']['source']='0'*40
   elif mode=='artifact':bad['closed_failure']['artifact']='999'
   else:bad['closed_failure']['secret_input_bootstrap_native_started']=True
   with self.subTest(mode=mode),patch.object(v,'load',side_effect=lambda p,*a:bad if p==SOURCE/'successor-v3.json'else actual(p,*a)),self.assertRaises(ValueError):r.inverse251(SOURCE,dict(self.pins(),_ancestor_path=str(ANCESTOR)),found,PARENT)
 def observations(self):
  b,pins=self.model();a=b['actual'];approval=dict(status='ROOT_ADMITTED_SINGLE_NATIVE_LLVM23_ATTEMPT',authority=a['authority'],source_reviewed=True,holds_preserved=True,operation=pins['operation'],source=a['source'],ref=a['ref'],source_map_sha256=pins['source_map_sha256'],resources=pins['policy'])
  provider=dict(run=dict(id=11,run_attempt=1,event='workflow_dispatch',head_sha=a['source'],head_branch=a['ref'].removeprefix('refs/heads/'),repository={'full_name':'Gabriel-Kahen/cachy-asahi'},status='completed',conclusion='success'),job=dict(id=22,run_id=11,head_sha=a['source'],name='llvm23-native-v2',status='completed',conclusion='success'),artifact=dict(id=33,expired=False,name='llvm23-native-v2-11-1',workflow_run=dict(id=11,head_sha=a['source'])))
  return provider,approval,b,pins
 def test_current_provider_approval_artifact_tuple_is_preserved(self):r.admitted_provider(*self.observations())
 def test_old6d_head_or_map_never_substitutes_current_observations(self):
  for mode in('run','job','artifact','approval_source','approval_map','failed'):
   p,a,b,pins=self.observations()
   if mode in('run','job'):p[mode]['head_sha']=r.PARENT['source']
   elif mode=='artifact':p['artifact']['workflow_run']['head_sha']=r.PARENT['source']
   elif mode=='approval_source':a['source']=r.PARENT['source']
   elif mode=='approval_map':a['source_map_sha256']=r.PARENT['map_sha256']
   else:p['run']['conclusion']='failure'
   with self.subTest(mode=mode),self.assertRaises(ValueError):r.admitted_provider(p,a,b,pins)
 def test_actual_proof_uses253_members_and_new_common_blob(self):
  b,pins=self.model();found=self.found();readback=dict(status='PASS_EXACT_HOSTED_SOURCE_READBACK',files=found,binding=dict(b['actual'],source_map_sha256=pins['source_map_sha256']));r.proof_join(readback,found,b['actual'],pins)
  old=v.source_namespace(PARENT,r.B.old_pins)
  for mode in('common','membership','head','map'):
   bad=copy.deepcopy(readback)
   if mode=='common':bad['files']['hosted/common.py']=old['hosted/common.py']
   elif mode=='membership':bad['files']=old
   elif mode=='head':bad['binding']['source']=r.PARENT['source']
   else:bad['binding']['source_map_sha256']=r.PARENT['map_sha256']
   with self.subTest(mode=mode),self.assertRaises(ValueError):r.proof_join(bad,found,b['actual'],pins)
 def test_unchanged_volume_predicates_use_new_actual_head_not_old_pin(self):
  # Reuse only the trusted repository's synthetic DATA fixture; no role entry.
  path=HERE.parent/'v2/test_volume.py';spec=importlib.util.spec_from_file_location('frozen_volume_DATA_fixture',path);fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture);fixture.SOURCE=PARENT
  actual_load=fixture.r.load;new_pins=dict(r.B.old_pins,source='7'*40)
  with tempfile.TemporaryDirectory()as tmp,patch.object(fixture.r,'load',side_effect=lambda p,*a:new_pins if p==HERE.parent/'v2/pins.json'else actual_load(p,*a)):
   root=Path(tmp);producer,actual,_,_=fixture.fixture(root)
   self.assertEqual(actual['source'],'7'*40);self.assertEqual(r.B.old_pins['source'],r.PARENT['source'])
   v.volume_initialization(root,producer,actual,r.B.old_pins)
 def test_existing_resource_and_frozen_actor_policy_unchanged(self):
  pins=self.pins();old=r.B.old_pins;self.assertEqual(pins['policy'],old['policy']);self.assertEqual(pins['operation'],old['operation']);self.assertEqual(pins['inner_operation'],old['inner_operation']);self.assertEqual(pins['initializer_code_sha256'],old['initializer_code_sha256'])
  for name in('actor/entry.py','actor/runtime.py','actor/container_mode.py','actor/work_check.py','hosted/entry.py','hosted/producer.py','hosted/volume.py'):self.assertEqual(v.hashed(SOURCE/name),v.hashed(PARENT/name))

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--parent-source',type=Path,required=True);p.add_argument('--ancestor-source',type=Path,required=True);p.add_argument('--corrected-source',type=Path);a=p.parse_args();PARENT=a.parent_source.resolve();ANCESTOR=a.ancestor_source.resolve()
 with tempfile.TemporaryDirectory(prefix='llvm253-DATA-only-')as tmp:
  if a.corrected_source:SOURCE=a.corrected_source.resolve()
  else:
   # Trusted authoring constructor renders DATA only; no payload module is imported.
   path=HERE.parents[3]/'scripts/ci/llvm23-source-reference-native/successor_v3/prepare.py';s=importlib.util.spec_from_file_location('trusted_alias_DATA_constructor',path);c=importlib.util.module_from_spec(s);s.loader.exec_module(c);rows=c.render(c.parent(PARENT));SOURCE=Path(tmp)/'source';SOURCE.mkdir()
   for name,(raw,mode)in rows.items():leaf=SOURCE/name;leaf.parent.mkdir(parents=True,exist_ok=True);leaf.write_bytes(raw);leaf.chmod(mode)
  result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Controls));raise SystemExit(not result.wasSuccessful())

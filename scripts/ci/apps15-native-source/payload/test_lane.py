#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Finite source/refusal/ownership controls; no native results are fabricated."""
import ast,copy,json,os,subprocess,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import Mock,patch
import adapter as A
import contract as C
import job,run,preflight
ROOT=A.ROOT

def functions(raw):return {n.name:ast.dump(n,include_attributes=False)for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)}

class Controls(unittest.TestCase):
 def test_source_only_preflight_is_process_blocked_and_ids_stay_null(self):
  with patch.object(subprocess,'Popen',side_effect=AssertionError('processes forbidden')):
   value=preflight.inspect(ROOT)
  self.assertEqual(value['native'],'NOT_RUN');self.assertIsNone(value['run_id'])
  p=C.read(C.HERE/'input-policy.json')
  if p['status']=='UNBOUND_APPS15_CLIENT_NATIVE':self.assertIsNone(p['candidate_source']);self.assertTrue(all(r['source_sha']is None for r in p['products'].values()))
 def test_unbound_gate_stops_before_output_or_actor(self):
  with tempfile.TemporaryDirectory()as d,patch.object(C,'policy',side_effect=ValueError('UNBOUND')),patch.object(C,'load')as load:
   output=Path(d)/'absent'
   with self.assertRaisesRegex(ValueError,'UNBOUND'):run.execute(Path(d),Path(d),output,'a'*32)
   self.assertFalse(output.exists());load.assert_not_called()
 def test_cleanup_and_source_proof_functions_are_ast_held(self):
  old=functions(A.read(ROOT,A.OLD+'job.py'));new=functions(A.text(ROOT,'job.py'))
  for name in ('cleanup','inherited','save'):self.assertEqual(old[name],new[name])
  text=A.text(ROOT,'job.py');gate="    C.need(manifest.get('workflow_path')=='.github/workflows/native-arm-build.yml' and manifest.get('workflow_ref')=='refs/heads/codex/apps15-pair-native-v1' and manifest.get('repository')=='Gabriel-Kahen/cachy-asahi','exact registered Apps15 workflow context required')\n    C.need(environment.get('GITHUB_REPOSITORY')==manifest['repository'] and environment.get('GITHUB_EVENT_NAME')=='workflow_dispatch' and environment.get('GITHUB_REF')==manifest['workflow_ref'] and environment.get('GITHUB_WORKFLOW_REF')==manifest['repository']+'/'+manifest['workflow_path']+'@'+manifest['workflow_ref'] and environment.get('GITHUB_WORKFLOW')=='native-arm-apps15-client' and environment.get('GITHUB_JOB')=='native','registered Apps15 repository/ref/workflow/job identity required')\n    template=(C.HERE/'workflow.yml').read_text().replace('@JOB_SHA256@',C.digest(C.HERE/'job.py')).replace('@MANIFEST_SHA256@',C.digest(C.HERE/'source-manifest.json'))\n    for path in (manifest['workflow_path'],'.github/workflows/native-arm-apps15-client.yml'):C.checked(source,path,dict(bytes=len(template.encode()),sha256=hashlib.sha256(template.encode()).hexdigest()))\n";self.assertEqual(text.count(gate),1);self.assertEqual(old['prove'],functions(text.replace(gate,''))['prove'])
 def test_original_docker_resources_and_limits_remain(self):
  builder=A.builder(ROOT);builder.C=C;argv=builder.docker('sha256:'+'a'*64,'inert',Path('/tmp/inert'))
  for item in ('--network=none','--read-only','--memory=3g','--cpus=4','--pids-limit=256','--cap-drop=ALL','--security-opt=no-new-privileges'):self.assertIn(item,argv)
  body=A.text(ROOT,'run.py');self.assertIn('signal.setitimer(signal.ITIMER_REAL,2350)',body);self.assertIn("out/'lifecycle.log',600",body)
  self.assertIn('execute(argv,directory/\'build.log\',240)',A.read(ROOT,'scripts/ci/welcome-native/run.py'))
  self.assertEqual(job.inherited(ROOT).MAX_TOTAL,192*1024**2)
 def test_both_new_build_pairs_require_the_same_runtime575_image(self):
  raw=A.text(ROOT,'run.py')
  for role in ('apps','client'):self.assertIn("build_pair(C.ROLES['"+role+"'],runtime_image,runtime_base,runtime_lock,apps_actors)",raw)
  self.assertIn("for name in (C.ROLES['apps'],C.ROLES['client'])",raw)
  self.assertIn("[('base-consumers',6),('apps-consumers',4)]",A.text(ROOT,'job.py'))
 def test_actual_builder_no_checks_or_dependency_waiver(self):
  raw=(ROOT/'scripts/build/container-entry.sh').read_text()
  self.assertIn('makepkg --verifysource --noconfirm',raw);self.assertIn('makepkg --cleanbuild --clean --force --log --noconfirm',raw)
  self.assertNotRegex(raw,r'makepkg[^\n]*(?:--nodeps|--nocheck)')
  self.assertIn("'-T',*control['apps_dependencies']",(C.HERE/'runtime_image.py').read_text())
 def test_pair_gate_refuses_any_failed_equality(self):
  pair=C.load('new_pair_control',ROOT/'scripts/ci/tools-native/run.py')
  for field in ('installed_contents_equal','pkginfo_equal','bytes_equal','buildinfo_equal'):
   value=dict(status='contents-reproduced',errors=[],packages={'control':dict(installed_contents_equal=True,pkginfo_equal=True,bytes_equal=True,buildinfo_equal=True)})
   value['packages']['control'][field]=False
   with self.assertRaises(ValueError):pair.pair_gate(value)
 def test_old_apps6_metadata_cannot_bind_new7_recipe(self):
  checks=C.load('candidate_recipe_control',ROOT/'scripts/checks/package_checks.py');meta=checks.recipe(ROOT/'packages/tools/cachy-asahi-apps15/PKGBUILD')['metadata'];changed=copy.deepcopy(meta);changed['pkgrel']=['6']
  bind=C.load('metadata_bind_control',ROOT/'scripts/build/build.py')
  with self.assertRaisesRegex(ValueError,'pkgrel'):bind.bind_generated(meta,changed)
  errors=bind.bind_artifact(meta,dict(metadata={'.PKGINFO':{'pkgname':['cachy-asahi-apps'],'pkgver':['0.1.0-6']},'.BUILDINFO':{}},members={}),C.digest(ROOT/'packages/tools/cachy-asahi-apps15/PKGBUILD'))
  self.assertIn('artifact metadata differs from reviewed pkgver',errors)
 def test_no_cache_apply_and_original_apps_protocol_held(self):
  text=A.text(ROOT,'lifecycle.py');self.assertNotIn("'/usr/bin/cachy-asahi-cache'",text);self.assertNotIn('cache_apply=',text)
  for held in ("['list'],['search','sYnThEtIc'],['show','fixture']","annotation['consistency']=='TWO_MATCHING_READS_NO_LOCK_NO_DETECTED_DRIFT'","I.payloads(L,products)","L.preservation_check(home,before,output,outside)"):
   self.assertIn(held,text)
  self.assertIn("[C.ROLES[k] for k in ('client','apps','runtime')]",text)
 def test_no_partial_or_old_lifecycle_claim_is_accepted(self):
  for row in ({},{'status':'PASS_APPS_CACHE_INSTALLED_LIFECYCLE'},{'status':'PASS_APPS15_CLIENT_V2_INSTALLED_LIFECYCLE','page_size':16384}):
   with self.assertRaises(ValueError):C.validate_lifecycle(row)
 def test_required_signatures_and_only_fixture_authority_mount(self):
  self.assertIn('LocalFileSigLevel = Required',(C.HERE/'installed.py').read_text());text=A.text(ROOT,'run.py');self.assertEqual(text.count('dst=/authority'),1)
  build=functions(A.read(ROOT,'scripts/ci/welcome-native/run.py'))['build'];self.assertNotIn('/authority',build);self.assertNotIn('test-signing',build)
 def test_unknown_consumer_keeps_later_images_and_authority(self):
  with tempfile.TemporaryDirectory()as d:
   root=Path(d);runtime=root/'runtime';(runtime/'test-signing').mkdir(parents=True);held=runtime/'test-signing/held';held.write_bytes(b'held')
   old=NS(manifest_files=Mock(),retire_consumers=Mock(side_effect=ValueError('unknown consumer')),cleanup=Mock());producer=NS(retire_owned=Mock())
   with patch.dict(job.cleanup.__globals__,{'inherited':lambda _:old}),patch.object(C,'load',return_value=producer),patch.object(C,'read',return_value={}):
    value=job.cleanup(ROOT,{},root/'base',runtime,root/'cleanup.json',command=Mock())
   self.assertEqual(value['status'],'FAIL');self.assertEqual(value['authority'],'RETAINED');self.assertEqual(held.read_bytes(),b'held');old.cleanup.assert_not_called();producer.retire_owned.assert_not_called()
 def test_workflow_before_secrets_and_source_identity(self):
  text=(ROOT/'.github/workflows/native-arm-apps15-client.yml').read_text();self.assertLess(text.index('id: proof'),text.index('Checkout the whole exact public574'));self.assertNotIn('${{ secrets.',text)
  self.assertIn('ubuntu-24.04-arm',text);self.assertIn('cancel-in-progress: false',text);self.assertIn('timeout-minutes: 100',text)
  for marker in ('--network=none','--read-only'):self.assertIn(marker,A.read(ROOT,'scripts/ci/welcome-native/run.py'))

 def test_actual_generated_contract_loader_needs_no_module_registration(self):
  # Match lifecycle.main -> installed.load exactly; execute only trusted generated source.
  import installed as I,sys
  name='apps_cache_installed_contract';previous=sys.modules.pop(name,None)
  try:
   with tempfile.TemporaryDirectory()as d,patch.object(subprocess,'Popen',side_effect=AssertionError('loader control must not start actors')):
    context=Path(d);runner=A.runner(ROOT,context);path=runner/'contract.py'
    self.assertEqual((runner/'rules.py').read_bytes(),(C.HERE/'rules.py').read_bytes())
    loaded=I.load(name,path);self.assertNotIn(name,sys.modules)
    for value in ({},{'status':'PASS_APPS_CACHE_INSTALLED_LIFECYCLE'},{'status':'PASS_APPS15_CLIENT_V2_INSTALLED_LIFECYCLE','page_size':16384}):
     with self.assertRaisesRegex(ValueError,'distinct native4K software lifecycle required'):loaded.validate_lifecycle(value)
    held=" from rules import validate\n from types import SimpleNamespace\n return validate(SimpleNamespace(need=need,re=re,ROLES=ROLES),value)\n"
    original=" from rules import validate\n return validate(sys.modules[__name__],value)\n"
    text=path.read_text();self.assertEqual(text.count(held),1)
    before=runner/'before-contract.py';before.write_text(text.replace(held,original))
    broken=I.load(name,before);self.assertNotIn(name,sys.modules)
    with self.assertRaisesRegex(KeyError,name):broken.validate_lifecycle({})
  finally:
   if previous is not None:sys.modules[name]=previous

if __name__=='__main__':unittest.main(verbosity=2)

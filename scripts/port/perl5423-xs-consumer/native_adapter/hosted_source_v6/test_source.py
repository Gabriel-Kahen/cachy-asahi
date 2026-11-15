# SPDX-License-Identifier: MIT
"""Fenced v6 constructor DATA controls; no publish/main/payload import or actor."""
import argparse,ast,contextlib,copy,ctypes,fcntl,hashlib,importlib.util,json,os,re,socket,subprocess,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('v6_constructor_data',HERE/'prepare.py');P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
PARENT=None

def model_profile():
 return json.loads((HERE/'profile.json').read_bytes())

class Controls(unittest.TestCase):
 def setUp(self):
  stack=contextlib.ExitStack();self.addCleanup(stack.close)
  def denied(*a,**k):raise AssertionError('actor/publication forbidden in DATA constructor controls')
  stack.enter_context(patch.object(P.atomic,'publish',denied))
  for module,names in((ctypes,('CDLL',)),(fcntl,('flock',)),(subprocess,('run','Popen','check_output')),(socket,('socket','create_connection')),(os,('fork','forkpty','system','execv','execve','execvp','execvpe','posix_spawn','posix_spawnp','pidfd_open','unshare','setns'))):
   for name in names:
    if hasattr(module,name):stack.enter_context(patch.object(module,name,denied))
 def rendered(self,p=None):
  with patch.object(P,'profile',return_value=model_profile()if p is None else p):return P.render(PARENT,'MODELED_PROFILE_PIN_NOT_AUTHORITY')
 def test_exact_full316_parent_and321_inverse(self):
  before=P.previous(PARENT);files=self.rendered();self.assertEqual(len(files),321);self.assertEqual(P.inverse(files),before);self.assertEqual(P.atomic.tree(before),P.PARENT_TREE);self.assertEqual(json.loads(files['source-map.json'][0])['actual'],P.ACTUAL)
 def test_explicit_one_of13_revision_and_changed_actor_seam(self):
  before=P.previous(PARENT);files=self.rendered();native='consumer/native_adapter/native.py';self.assertNotEqual(files[native],before[native]);self.assertEqual(sum(files[n]==row for n,row in before.items()if n.startswith('consumer/')),12)
  for name in P.FROZEN_FUNCTIONS:self.assertEqual(P.functions(files[native][0])[name],P.functions(before[native][0])[name])
  self.assertNotEqual(P.functions(files[native][0])['actor'],P.functions(before[native][0])['actor'])
  for prefix in('held/','accepted/'):
   self.assertEqual({n:r for n,r in files.items()if n.startswith(prefix)},{n:r for n,r in before.items()if n.startswith(prefix)})
  for n in('xs/compiler_image.py','xs/prepare_inputs.py'):self.assertEqual(files[n],before[n])
 def test_new_alias_exact_hash_guard_and_unchanged_budget(self):
  before=P.previous(PARENT);files=self.rendered();self.assertNotIn(P.OLD_ALIAS,files);self.assertEqual(files[P.NEW_ALIAS],files[P.GENERIC]);old,new=before[P.GENERIC][0],files[P.GENERIC][0]
  expected=old.replace(b'native-arm-perl5423-xs-v5',b'native-arm-perl5423-xs-v6').replace(b'perl5423-native-xs-v5',P.OPERATION.encode()).replace(hashlib.sha256(before['xs/entry.py'][0]).hexdigest().encode(),hashlib.sha256(files['xs/entry.py'][0]).hexdigest().encode());self.assertEqual(new,expected)
  self.assertEqual(re.findall(rb'timeout-minutes:\s*(\d+)',old),re.findall(rb'timeout-minutes:\s*(\d+)',new))
 def test_payload_pin_mismatch_refused(self):
  p=model_profile();p['payload']['consumer/native_adapter/native.py']['sha256']='0'*64
  with self.assertRaises(ValueError):self.rendered(p)
 def test_actor_function_body_change_refused(self):
  actual=P.atomic.read;name='consumer/native_adapter/native.py';body,mode=actual(HERE/'payload'/name);changed=body.replace(b'def actor(admission_sha):',b'def actor(admission_sha):\n    # MODELED_FORBIDDEN_ACTOR_CHANGE',1);p=model_profile();p['payload'][name]=dict(**P.atomic.pin(changed),mode=mode)
  with patch.object(P.atomic,'read',side_effect=lambda path,*a:(changed,mode)if path==HERE/'payload'/name else actual(path,*a)),self.assertRaisesRegex(ValueError,'actor inventory seam'):self.rendered(p)
  changed=body.replace(b'DOCKER = [',b'DOCKER = [# MODELED_UNREVIEWED_GLOBAL\n',1);p=model_profile();p['payload'][name]=dict(**P.atomic.pin(changed),mode=mode)
  with patch.object(P.atomic,'read',side_effect=lambda path,*a:(changed,mode)if path==HERE/'payload'/name else actual(path,*a)),self.assertRaisesRegex(ValueError,'whole native body inverse'):self.rendered(p)
 def test_entry_must_bind_current_adapter_body(self):
  actual=P.atomic.read;name='xs/entry.py';body,mode=actual(HERE/'payload'/name);tree=ast.parse(body);node=next(n for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='NATIVE_SHA'for t in n.targets));old=node.value.value.encode();changed=body.replace(old,b'0'*64,1);p=model_profile();p['payload'][name]=dict(**P.atomic.pin(changed),mode=mode)
  with patch.object(P.atomic,'read',side_effect=lambda path,*a:(changed,mode)if path==HERE/'payload'/name else actual(path,*a)),self.assertRaisesRegex(ValueError,'exact revised native'):self.rendered(p)
 def test_all_five_archives_are_required_and_mutation_refuses(self):
  files=self.rendered()
  for name in P.ARCHIVE_MAP.values():
   bad=dict(files);bad.pop(name)
   with self.subTest(name=name),self.assertRaises(ValueError):P.inverse(bad)
  bad=dict(files);bad['previous-v5/native.py']=(b'MODELED_CHANGED_BODY',0o644)
  with self.assertRaises(ValueError):P.inverse(bad)
  bad=dict(files);bad['xs/compiler_image.py']=(b'MODELED_CHANGED_UNRELATED_BODY',0o644)
  with self.assertRaises(ValueError):P.inverse(bad)
 def test_profile_scope_no_authority_or_frozen_consumer_claim(self):
  files=self.rendered();v=json.loads(files['xs-provenance.json'][0]);self.assertTrue(all(x is None for x in v['actual'].values()));self.assertEqual(v['delegated_consumer_operation'],P.INNER);self.assertEqual(v['delegated_image_seal_operation'],P.IMAGE_OPERATION);self.assertEqual(v['native_adapter_revision']['unchanged_consumer_files'],12);self.assertEqual(v['native_adapter_revision']['consumer_files'],13);self.assertNotIn('actor',v['native_adapter_revision']['frozen_functions']);self.assertEqual(v['actor_revision']['global_path_guard'],'UNCHANGED');self.assertEqual(v['work_volume_policy']['budget_increase_seconds'],0);self.assertFalse(v['native_acceptance']);self.assertFalse(v['XS_acceptance'])
 def test_profile_hash_scope_and_payload_schema_validation(self):
  p=model_profile();raw=P.encode(p);sha=P.atomic.pin(raw)['sha256'];actual=P.atomic.read
  with patch.object(P.atomic,'read',side_effect=lambda path,*a:(raw,0o644)if path==HERE/'profile.json'else actual(path,*a)):
   self.assertEqual(P.profile(sha),p)
   with self.assertRaises(ValueError):P.profile('0'*64)
  for key,value in [('operation',P.IMAGE_OPERATION),('delegated_image_seal_operation','other'),('parent_source','0'*40),('actual',dict(P.ACTUAL,run='1')),('captured_config_fields',['Image'])]:
   bad=copy.deepcopy(p);bad[key]=value;raw=P.encode(bad)
   with self.subTest(key=key),patch.object(P.atomic,'read',return_value=(raw,0o644)),self.assertRaises(ValueError):P.profile(P.atomic.pin(raw)['sha256'])

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--previous-xs-source',type=Path,required=True);a=p.parse_args();PARENT=a.previous_xs_source.resolve();result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Controls));raise SystemExit(not result.wasSuccessful())

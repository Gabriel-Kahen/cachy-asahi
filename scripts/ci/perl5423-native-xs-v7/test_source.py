# SPDX-License-Identifier: MIT
"""Fenced Source326 and retained-path reproduction controls; no actors/publication."""
import argparse,ast,contextlib,copy,ctypes,fcntl,hashlib,importlib.util,json,os,socket,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;PARENT=DATA=None

def load(n):
 s=importlib.util.spec_from_file_location('xs_v7_test_'+n,HERE/(n+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
P=load('prepare');R=load('reproduce')
def model():return json.loads((HERE/'profile.json').read_bytes())
class Controls(unittest.TestCase):
 def setUp(self):
  stack=contextlib.ExitStack();self.addCleanup(stack.close)
  def denied(*a,**k):raise AssertionError('actor/custody/network/publication forbidden in Source DATA controls')
  stack.enter_context(patch.object(P.atomic,'publish',denied))
  for module,names in((ctypes,('CDLL',)),(fcntl,('flock',)),(subprocess,('run','Popen','check_output')),(socket,('socket','create_connection')),(os,('fork','forkpty','system','execv','execve','execvp','execvpe','posix_spawn','posix_spawnp','pidfd_open','unshare','setns'))):
   for n in names:
    if hasattr(module,n):stack.enter_context(patch.object(module,n,denied))
 def render(self,p=None):
  with patch.object(P,'profile',return_value=model()if p is None else p):return P.render(PARENT,'MODELED_PROFILE_PIN_NOT_AUTHORITY')
 def test_actual_path_object_failure_reproduced_before_sandbox_or_work(self):
  r=R.replay(DATA);self.assertEqual(r['failure'],'canonical shell-safe absolute path');self.assertEqual(r['call'],dict(type='PosixPath',value='/tmp/xs-sandbox.json',function='execute',line=176));self.assertFalse(r['actor_executed'])
 def test_string_argument_passes_strict_external_paths_only_until_fenced_sandbox(self):
  r=R.replay(DATA,True);self.assertEqual(r['status'],'STRING_ARGUMENT_REACHES_FENCED_SANDBOX_GATE');self.assertTrue(all(p['type']=='str'for p in r['paths']));self.assertFalse(r['actor_executed'])
 def test_global_path_guard_is_unmodified_and_stays_strict(self):
  m=R.module('trusted_preflight_guard',R.CONSUMER/'preflight.py');raw=(R.CONSUMER/'preflight.py').read_bytes();self.assertEqual(hashlib.sha256(raw).hexdigest(),'9e881d5144c49cfa6b4a9abe5bc5172f0d4f00038d94e52426dc88b05473bc0d')
  for value in(Path('/tmp/xs-sandbox.json'),'/tmp/../x','/tmp/a:b','/tmp/has space','/tmp//x','/tmp/x/','/',None):
   with self.subTest(value=str(value)),self.assertRaises(ValueError):m.path(value)
  self.assertEqual(m.path('/tmp/xs-sandbox.json'),Path('/tmp/xs-sandbox.json'))
 def test_exact_source326_inverse321_and_preserved_v6_inverse(self):
  files=self.render();before=P.previous(PARENT);self.assertEqual(len(files),326);self.assertEqual(P.inverse(files),before);self.assertEqual(len(P.V6.inverse(before)),316)
 def test_one_exact_call_conversion_and_no_other_native_change(self):
  files=self.render();before=P.previous(PARENT);name='consumer/native_adapter/native.py';p=model();self.assertEqual(files[name][0].replace(p['after'].encode(),p['before'].encode()),before[name][0]);a,b=P.V6.functions(before[name][0]),P.V6.functions(files[name][0]);self.assertNotEqual(a['actor'],b['actor']);self.assertEqual({n:x for n,x in a.items()if n!='actor'},{n:x for n,x in b.items()if n!='actor'})
 def test_all12_other_consumers_and_guard_and_runner_remain_byte_identical(self):
  files=self.render();before=P.previous(PARENT);self.assertEqual(sum(files[n]==r for n,r in before.items()if n.startswith('consumer/')),12)
  for prefix in('held/','accepted/'):
   self.assertEqual({n:r for n,r in files.items()if n.startswith(prefix)},{n:r for n,r in before.items()if n.startswith(prefix)})
  for n in('consumer/preflight.py','consumer/runner/run.py','xs/compiler_image.py','xs/prepare_inputs.py'):self.assertEqual(files[n],before[n])
 def test_any_unreviewed_native_or_global_change_refuses(self):
  old=P.previous(PARENT)['consumer/native_adapter/native.py'][0];new=(HERE/'payload/consumer/native_adapter/native.py').read_bytes()
  for changed in(new.replace(b'def actor(',b'#unreviewed\ndef actor(',1),new.replace(b'DOCKER = [',b'DOCKER = [#unreviewed\n',1),new.replace(b'str(sandbox_path)',b'sandbox_path.resolve()',1)):
   with self.assertRaises(ValueError):P.native_delta(old,changed,model())
 def test_profile_cannot_name_broad_guard_or_another_seam(self):
  old=P.previous(PARENT)['consumer/native_adapter/native.py'][0];new=(HERE/'payload/consumer/native_adapter/native.py').read_bytes();p=model();p['after']=p['after'].replace('str(sandbox_path)','sandbox_path')
  with self.assertRaises(ValueError):P.native_delta(old,new,p)
 def test_all_five_archived_bodies_and_literal_membership_required(self):
  files=self.render()
  for n in P.ARCHIVE_MAP.values():
   changed=dict(files);changed.pop(n)
   with self.subTest(path=n),self.assertRaises(ValueError):P.inverse(changed)
  for n in('previous-v6/native.py','previous-v6/source-map.json','consumer/preflight.py'):
   changed=dict(files);changed[n]=(b'MODELED_UNREVIEWED_CHANGE',0o644)
   with self.subTest(path=n),self.assertRaises(ValueError):P.inverse(changed)
 def test_entry_exact_body_hash_and_outer_literal_changes_only(self):
  files=self.render();before=P.previous(PARENT);old=before['xs/entry.py'][0];new=files['xs/entry.py'][0];newsha=P.atomic.pin(files['consumer/native_adapter/native.py'][0])['sha256'];oldsha=P.atomic.pin(before['consumer/native_adapter/native.py'][0])['sha256'];self.assertEqual(new.replace(newsha.encode(),oldsha.encode()).replace(b'native-arm-perl5423-xs-v7',b'native-arm-perl5423-xs-v6').replace(b'perl5423-native-xs-v7',b'perl5423-native-xs-v6'),old)
 def test_workflow_exact_aliases_and_unchanged_lane_budgets(self):
  files=self.render();old=P.previous(PARENT)[P.GENERIC][0];new=files[P.GENERIC][0];self.assertEqual(files[P.NEW_ALIAS],files[P.GENERIC]);self.assertNotIn(P.OLD_ALIAS,files)
  for literal in(b'group: native-arm-build',b'cancel-in-progress: false',b'queue: max',b'timeout-minutes: 225',b'timeout-minutes: 185'):
   self.assertEqual(old.count(literal),new.count(literal));self.assertGreater(new.count(literal),0)
 def test_unissued_selectors_and_fail_closed_scope(self):
  files=self.render();v=json.loads(files['xs-provenance.json'][0]);self.assertTrue(all(x is None for x in v['actual'].values()));self.assertFalse(v['native_acceptance']);self.assertFalse(v['XS_acceptance']);self.assertEqual(v['closed_failed_run'],'43753943999');self.assertEqual(v['delegated_consumer_operation'],'perl5423-native-xs-v1');self.assertEqual(v['work_volume_policy']['budget_increase_seconds'],0)
 def test_profile_hash_and_scope_fields_refuse_tampering(self):
  raw=(HERE/'profile.json').read_bytes();self.assertEqual(P.profile(P.atomic.pin(raw)['sha256']),model())
  with self.assertRaises(ValueError):P.profile('0'*64)
  for key,value in(('operation',P.V6.OPERATION),('parent_source','0'*40),('runner','CHANGED'),('global_path_guard','RELAXED'),('budget_increase_seconds',1),('actor_revision','FROZEN')):
   p=model();p[key]=value;body=P.encode(p)
   with self.subTest(key=key),patch.object(P.atomic,'read',return_value=(body,0o644)),self.assertRaises(ValueError):P.profile(P.atomic.pin(body)['sha256'])
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--previous-xs-source',type=Path,required=True);p.add_argument('--retained-v6-materialization',type=Path,required=True);a=p.parse_args();PARENT=a.previous_xs_source.resolve();DATA=a.retained_v6_materialization.resolve();r=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Controls));raise SystemExit(not r.wasSuccessful())

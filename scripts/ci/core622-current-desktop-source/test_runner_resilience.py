# SPDX-License-Identifier: MIT
"""New DATA construction controls; consume one pre-emitted diagnostic namespace."""
import ast,copy,importlib.util,json,os,tempfile,unittest
from unittest.mock import patch
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('_core622_opt_in_factory',HERE/'prepare.py')
F=importlib.util.module_from_spec(spec);spec.loader.exec_module(F)
EMITTED=Path(os.environ['CORE622_RESILIENCE_SOURCE']).resolve()
ROOTS={n:Path(os.environ['CORE622_'+n.upper()])for n in('parent','fresh607','core_record','fresh_record')}

def function(raw,name):
 text=raw.decode();return next(ast.get_source_segment(text,n)for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)and n.name==name)

class DefaultEmitCallControls(unittest.TestCase):
 def test_inherited_one_argument_hook_reaches_late_drift_refusal(self):
  # Own finite DATA inputs: no historical Source constructor or actor runs.
  self.assertEqual(json.loads(F.read(HERE/'profile.json'))['result']['source'],'ad09020a776c93fad3c2625c836a99cbde0c83b9')
  for resilient in(False,True):
   with self.subTest(runner_resilience=resilient),tempfile.TemporaryDirectory(prefix='core622-call-')as temporary:
    root=Path(temporary).resolve();roles={name:root/name for name in('parent','fresh607','core_record','fresh_record')}
    for path in roles.values():path.mkdir();(path/'probe.txt').write_bytes(b'finite DATA input\n')
    calls=[]
    def changed(inputs):
     calls.append(dict(inputs));states={name:F.scan(path)for name,path in inputs.items()}
     (inputs['parent']/'probe.txt').write_bytes(b'changed finite DATA input\n')
     return {},{},states,{}
    def opted(inputs,enabled):
     self.assertIs(enabled,True);return changed(inputs)
    with patch.object(F,'compose',side_effect=opted if resilient else changed):
     with self.assertRaisesRegex(ValueError,'late complete identity before any write'):
      if resilient:F.emit(roles,root/'out','null',runner_resilience=True)
      else:F.emit(roles,root/'out','known')
    self.assertEqual(calls,[roles]);self.assertFalse((root/'out').exists())

class Controls(unittest.TestCase):
 def setUp(self):
  self.values=F.tree(EMITTED);self.profile=json.loads(F.read(HERE/'profile.json'));self.before=F.before_resilience(self.values)
 def test_exact_single_emission_and_unbound_correct_predecessor(self):
  self.assertEqual(len(self.values),66);self.assertEqual({n:F.pin(v)for n,v in self.values.items()},self.profile['runner_resilience_result']['files']);self.assertEqual({n:F.pin(v)for n,v in self.before.items()},self.profile['resilience_parent']['files']);self.assertEqual(self.profile['resilience_parent']['source'],'ad09020a776c93fad3c2625c836a99cbde0c83b9');self.assertIsNone(self.profile['runner_resilience_result']['source']);self.assertIsNone(self.profile['runner_resilience_result']['ref']);self.assertTrue(all(p.stat().st_mode&0o777==0o644 for p in EMITTED.rglob('*')if p.is_file()))
 def test_default_constructor_still_exact_published_ad090_without_emission(self):
  values,p,_,_=F.compose(ROOTS)
  self.assertEqual(values,self.before);self.assertEqual(p['result']['source'],'ad09020a776c93fad3c2625c836a99cbde0c83b9');self.assertEqual({n:F.pin(v)for n,v in values.items()},p['result']['files']);self.assertNotIn('runner_resilience',json.loads(values['composition-parent.json']))
 def test_original_guard_bodies_and_whole_older_tail_held(self):
  record=json.loads(self.values['composition-parent.json'])['runner_resilience']
  for name in('verify','inverse'):self.assertEqual(function(self.values['source622.py'],name),function(self.before['source622.py'],name))
  current=function(self.values['source622.py'],'same66_before');self.assertEqual(current.count(record['guard_prefix']),1);self.assertEqual(current.replace(record['guard_prefix'],record['guard_anchor'],1),function(self.before['source622.py'],'same66_before'))
 def test_mutated_new_layer_or_parent_refused(self):
  bad=dict(self.values);bad['export622.py']+=b'\n# drift\n'
  with self.assertRaises(ValueError):F.before_resilience(bad)
  bad=dict(self.values);parent=json.loads(bad['composition-parent.json']);parent['runner_resilience']['parent_source']='25d7b6b33e2b357801e5e3e9e71f3a7351dbbfa7';bad['composition-parent.json']=F.enc(parent)
  with self.assertRaises(ValueError):F.before_resilience(bad)
 def test_only_explicit_boolean_selection_and_no_implicit_binding(self):
  for value in(1,None,'yes',{},[]):
   with self.subTest(value=value),self.assertRaises(ValueError):F.compose(ROOTS,value)
  p=self.profile['runner_resilience_result'];self.assertIsNone(p['actual']);self.assertEqual(p['parent_source'],self.profile['result']['source']);self.assertNotEqual(p['files'],self.profile['result']['files'])
 def test_source_members_caps_and_workload_commands_held(self):
  self.assertEqual(set(self.values),set(self.before));record=json.loads(self.values['composition-parent.json'])['runner_resilience'];self.assertEqual(record['workload_clocks_CPU_RAM_cleanup_data_caps'],'HELD')
  wf=self.values['workflow.yml.in'].decode();old=record['edits']['workflow.yml.in'][-1][0];self.assertEqual(wf.count(old),1);self.assertIn('timeout --signal=TERM --kill-after=60s 15600s',old);self.assertIn('timeout-minutes: 350',wf);self.assertIn('timeout-minutes: 270',wf)
  self.assertEqual(self.values['ownership622.py'],self.before['ownership622.py']);self.assertEqual(self.values['provision622.py'],self.before['provision622.py']);self.assertEqual(self.values['profile.json'],self.before['profile.json']);self.assertEqual(self.values['expected607.lock'],self.before['expected607.lock']);self.assertEqual(self.values['expected622.lock'],self.before['expected622.lock'])

def run_controls():
 suite=unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(case)for case in(Controls,DefaultEmitCallControls))
 result=unittest.TextTestRunner(verbosity=2).run(suite)
 return dict(status='PASS'if result.wasSuccessful()else'FAIL',tests=result.testsRun,errors=len(result.errors),failures=len(result.failures),factory_emissions=0,Source_prefix='NOT_RUN',old_suites='NOT_RUN',native='NOT_RUN',acceptance=False)

if __name__=='__main__':
 value=run_controls();print(json.dumps(value,sort_keys=True));raise SystemExit(value['status']!='PASS')

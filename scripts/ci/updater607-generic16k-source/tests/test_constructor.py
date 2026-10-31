# SPDX-License-Identifier: MIT
"""Source integration/refusal controls; no native/VM actors or actual replay."""
import ast,contextlib,importlib.util,json,os,shutil,subprocess,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('_constructor',ROOT/'prepare.py');factory=importlib.util.module_from_spec(spec);spec.loader.exec_module(factory)
fallback=json.loads((ROOT/'evidence/input-source-paths.json').read_text())if(ROOT/'evidence/input-source-paths.json').is_file()else{}
INPUTS={k:Path(os.environ.get(variable,fallback.get(k,'/missing-source-operand')))for k,variable in(('updater','UPDATER_SOURCE'),('fresh16k','FRESH16K_SOURCE'),('held','HELD_SOURCE'))}
CHILD=Path(os.environ.get('EMITTED_SOURCE',str(ROOT/'source')))
sys.path.insert(0,str(CHILD));sys.path.insert(0,str(CHILD/'parent360/implementation'))
import common as C,runtime as R
import custody,selected,kernel_data

@contextlib.contextmanager
def no_actors():
 with patch.object(subprocess,'run',side_effect=AssertionError('NO_ACTORS')),patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS')),patch.object(subprocess,'check_output',side_effect=AssertionError('NO_ACTORS')):yield

class Controls(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='source-controls-',dir=ROOT);self.addCleanup(self.tmp.cleanup);self.work=Path(self.tmp.name)
 def test_default_constructor_exact360_and_unused16k_refusal(self):
  with no_actors():fact=factory.construct(INPUTS['updater'],self.work/'default')
  self.assertEqual(fact['files'],360);self.assertEqual(factory.Q.rows(self.work/'default'),factory.Q.rows(INPUTS['updater']))
  with no_actors(),self.assertRaises(ValueError):factory.construct(INPUTS['updater'],self.work/'unused','generic4k',INPUTS['fresh16k'],None)
  self.assertFalse((self.work/'unused').exists())
 def test_missing_foreign_alias_overlap_and_output_reuse_refused_prewrite(self):
  attempts=[('missing',INPUTS['updater'],None,None),('foreign',INPUTS['fresh16k'],INPUTS['fresh16k'],INPUTS['held'])]
  alias=self.work/'source-alias';alias.symlink_to(INPUTS['updater'],target_is_directory=True);attempts.append(('alias',alias,INPUTS['fresh16k'],INPUTS['held']))
  for name,source,fresh,held in attempts:
   with self.subTest(name=name),no_actors(),self.assertRaises(ValueError):factory.construct(source,self.work/name,'generic16k',fresh,held)
   self.assertFalse((self.work/name).exists())
  with no_actors(),self.assertRaises(ValueError):factory.construct(INPUTS['updater'],INPUTS['updater']/'forbidden')
  exists=self.work/'exists';exists.mkdir()
  with no_actors(),self.assertRaises(ValueError):factory.construct(INPUTS['updater'],exists)
 def test_mutated_source_payload_never_executes_or_writes_output(self):
  source=self.work/'foreign';shutil.copytree(INPUTS['updater'],source,ignore=shutil.ignore_patterns('.git'));(source/'entry.py').write_text('raise AssertionError("INPUT_EXECUTED")\n')
  with no_actors(),self.assertRaises(ValueError):factory.construct(source,self.work/'rejected')
  self.assertFalse((self.work/'rejected').exists())
 def test_hardlinked_source_refused(self):
  source=self.work/'hardlink';shutil.copytree(INPUTS['updater'],source,ignore=shutil.ignore_patterns('.git'));os.link(source/'entry.py',self.work/'alias-entry')
  with no_actors(),self.assertRaises(ValueError):factory.construct(source,self.work/'rejected')
  self.assertFalse((self.work/'rejected').exists())
 def test_late_input_or_constructor_drift_refuses_before_first_write(self):
  original=factory.read_dependency;calls=0
  def late(path,role,profile):
   nonlocal calls
   values=original(path,role,profile);calls+=1
   return dict(values,**{'entry.py':values['entry.py']+b'\n# late drift\n'})if calls==2 else values
  with no_actors(),patch.object(factory,'read_dependency',side_effect=late),self.assertRaises(ValueError):factory.construct(INPUTS['updater'],self.work/'late-input')
  self.assertFalse((self.work/'late-input').exists())
  with no_actors(),patch.object(factory,'verify_factory',side_effect=[{'v':1},{'v':2}]),self.assertRaises(ValueError):factory.construct(INPUTS['updater'],self.work/'late-factory')
  self.assertFalse((self.work/'late-factory').exists())
 def test_real_parent_candidate_and_selected_emitter_match_three_constructor_capsules(self):
  api=R.Integration(INPUTS['held'],self.work,self.work,self.work,{},'a'*40)
  for case in C.CASES:
   target=self.work/case
   with no_actors():config,caller=selected.candidate(api,self.work,target,case,custody.profile()['kernel_descriptor'])
   self.assertEqual(custody.rows(target),custody.profile()['emitted_cases'][case]);self.assertEqual(caller,target/'scripts/ci/full-root-upgrade-caller')
   value=json.loads(config.read_bytes());prior=json.loads((CHILD/'parent360/cases'/case/'upgrade-config.json').read_bytes())
   for key in('stage_seconds','copy_seconds','driver_seconds','verify_seconds','release','scale','external_pins'):self.assertEqual(value[key],prior[key])
 def test_real_parent_owner_derivation_matches_constructor_without_execution(self):
  raw=C.read(INPUTS['held']/R.OLD/'run.py')
  with no_actors():body,proof=selected.owner(R.derive_owner(raw).encode())
  self.assertEqual(body.encode(),(CHILD/'emissions/owner16k.py').read_bytes());self.assertTrue(proof['whole_inverse'])
 def test_workflow_complete_inverse_and_page_selection_before_secrets(self):
  p=custody.profile();wf=json.loads((CHILD/'.github/workflows/native-arm-build.yml').read_bytes());proof=p['workflow_inverse']
  self.assertEqual(wf['on']['workflow_dispatch']['inputs']['page_profile']['default'],'generic4k');self.assertEqual(wf['jobs']['native']['timeout-minutes'],350)
  self.assertIn('test "$PAGE_PROFILE" = generic16k',next(s for s in wf['jobs']['native']['steps']if s.get('id')=='root_policy')['run'])
  start=proof['added_at'];self.assertEqual(wf['jobs']['native']['steps'][start:start+3],proof['added_steps']);del wf['jobs']['native']['steps'][start:start+3]
  for i,row in proof['changed_steps'].items():self.assertEqual(wf['jobs']['native']['steps'][int(i)],row['after']);wf['jobs']['native']['steps'][int(i)]=row['before']
  parent=json.loads((CHILD/'parent360/.github/workflows/native-arm-build.yml').read_bytes())
  for key in('name','concurrency','on'):wf[key]=parent[key]
  self.assertEqual(factory.Q.enc(wf),(CHILD/'parent360/.github/workflows/native-arm-build.yml').read_bytes())
 def test_current_guest_binding_refuses_missing_or_changed_context(self):
  raw=(CHILD/'vm/guest.py').read_text();node=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)and n.name=='require_current607');body=ast.get_source_segment(raw,node)
  expected=dict(source='a'*40,run='123',attempt='1',ref='refs/heads/codex/test',page_profile='generic16k');scope={'C':type('C',(),{'need':staticmethod(factory.Q.need)}),'CURRENT607_EXPECTED':expected};exec(compile(body,'<selected-source-guard>','exec'),scope)
  scope['require_current607']({'current607':expected})
  for value in(None,dict(expected,source='b'*40),dict(expected,attempt='2'),dict(expected,page_profile='generic4k')):
   with self.assertRaises(ValueError):scope['require_current607']({'current607':value})
 def test_full_parent_and_fixed_deadlines_preserved(self):
  self.assertEqual(factory.Q.rows(CHILD/'parent360'),factory.Q.rows(INPUTS['updater']))
  parent=json.loads((INPUTS['updater']/'implementation/profile.json').read_bytes());p=custody.profile();self.assertEqual(p['clocks'],parent['clocks']);self.assertEqual(p['dependency_cache'],parent['dependency_cache'])
  self.assertEqual(p['clocks']['owner'],3900);self.assertEqual(p['clocks']['job_owner'],15600)
 def test_selected_vm_uses_same_module_kernel_authorizer_and_current607_verifier(self):
  callback=lambda *args:None
  api=types.SimpleNamespace(_owner=types.SimpleNamespace(verify_result=callback))
  context=dict(source='a'*40,run='123',attempt='1',ref='refs/heads/codex/test',page_profile='generic16k')
  with no_actors():transport=selected.vm(api,None,types.SimpleNamespace(latest_decisions=self.work),context,lambda *args:None)
  original=next(c.cell_contents for c in transport.run.__closure__ if callable(c.cell_contents))
  self.assertIs(original.__globals__['kernel'],transport.kernel);self.assertIs(original.__globals__['authorize'],transport.authorize)
  self.assertIs(transport.old_verify(None),callback);self.assertEqual(transport._CURRENT607,context)
  self.assertEqual(transport._KERNEL_DESCRIPTOR,custody.profile()['kernel_descriptor'])
 def timer(self,clock=(10,11),fail=False,foreign=(0.0,0.0)):
  handler=object();events=[]
  with patch.object(selected.signal,'getitimer',return_value=foreign),patch.object(selected.signal,'getsignal',return_value=handler),patch.object(selected.signal,'signal',side_effect=lambda *a:events.append(('handler',a))),patch.object(selected.signal,'setitimer',side_effect=lambda *a:events.append(('timer',a))),patch.object(selected.time,'monotonic',side_effect=clock):
   def operation(*args):
    if fail:raise RuntimeError('ORIGINAL_FAILURE')
    return 'finished'
   return selected.transaction(operation,3900),events,handler
 def test_enclosing_transaction_timer_covers_whole_operation_and_restores(self):
  result,events,handler=self.timer();self.assertEqual(result,'finished');self.assertEqual(events[1],('timer',(selected.signal.ITIMER_REAL,3900)));self.assertEqual(events[-2],('timer',(selected.signal.ITIMER_REAL,0)));self.assertEqual(events[-1],('handler',(selected.signal.SIGALRM,handler)))
 def test_overrun_foreign_timer_and_original_failure_refuse_without_budget_reset(self):
  with self.assertRaises(ValueError):self.timer(clock=(10,3910))
  with self.assertRaises(ValueError):self.timer(foreign=(1.0,0.0))
  with self.assertRaisesRegex(RuntimeError,'ORIGINAL_FAILURE'):self.timer(fail=True)
 def test_alarm_refusal_propagates_and_original_signal_handler_is_restored(self):
  handlers=[];prior=object();timers=[]
  with patch.object(selected.signal,'getitimer',return_value=(0.0,0.0)),patch.object(selected.signal,'getsignal',return_value=prior),patch.object(selected.signal,'signal',side_effect=lambda *a:handlers.append(a[1])),patch.object(selected.signal,'setitimer',side_effect=lambda *a:timers.append(a)),patch.object(selected.time,'monotonic',return_value=10):
   def operation(*_):handlers[0](selected.signal.SIGALRM,None)
   with self.assertRaisesRegex(TimeoutError,'enclosing3900'):selected.transaction(operation,3900)
  self.assertIs(handlers[-1],prior);self.assertEqual(timers,[(selected.signal.ITIMER_REAL,3900),(selected.signal.ITIMER_REAL,0)])

if __name__=='__main__':unittest.main()

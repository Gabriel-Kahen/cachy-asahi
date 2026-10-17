# SPDX-License-Identifier: MIT
import ast,copy,sys,types,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent));import contract as C
M=C.load('independent_modes_test',C.HERE/'modes.py')
ROOT=C.HERE.parents[2];ORIGINAL=ROOT/'scripts/ci/apps-full574-native/job.py'
class Modes(unittest.TestCase):
 def test_both_functions_compile_and_inactive_trial_is_absent(self):
  raw=ORIGINAL.read_text()
  for trial,inactive,active in (('normal','interruption','lifecycle'),('interruption','lifecycle','interruption')):
   parts=M.derived(raw,trial)
   for name,text in parts.items():compile(text,'<finite-'+trial+'-'+name+'>','exec')
   calls=[n for n in ast.walk(ast.parse(parts['run'])) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='actor']
   roles=[n.args[5].value for n in calls]
   self.assertIn(active,roles);self.assertNotIn(inactive,roles);self.assertIn('source-verify',roles)
   for name in ('run','retain'):
    self.assertNotIn('life' if trial=='interruption' else 'interruption',{n.id for n in ast.walk(ast.parse(parts[name])) if isinstance(n,ast.Name)})
   self.assertIn('snapshot-after.json',parts['retain']);self.assertIn('security_capabilities',parts['retain']);self.assertIn('PASS_ORDERED_CONSUMERS_COPIES_KEYS_SOURCE_THEN_PRODUCER',parts['retain'])
   self.assertIn('exact independent trial roles and natural exits',parts['retain'])
  self.assertNotEqual(M.STATUS['normal'],M.STATUS['interruption'])
  self.assertTrue(all('ONLY' in s for s in M.STATUS.values()))
 def test_actor_real_command_shape_and_scoped_aggregate_envelope(self):
  def need(ok,why):
   if not ok:raise ValueError(why)
  for trial in M.TRIALS:
   for role,want in (('interruption',3000 if trial=='interruption' else 900),('lifecycle',3000),('source-verify',900),('signer',240)):
    calls=[];record={};api=types.SimpleNamespace(inspect=lambda *a:None if not calls else {},verify_actor=lambda *a:'a'*64)
    c=types.SimpleNamespace(need=need,LABEL=C.LABEL,LANE=C.LANE,save=lambda *a:None)
    ns=dict(C=c,os=types.SimpleNamespace(getuid=lambda:1001,getgid=lambda:1001),reserve=lambda *a:record)
    ns['reserve']=lambda *a:record.update(name='fixture-actor') or record
    exec(M.derived(ORIGINAL.read_text(),trial)['actor'],ns)
    def command(argv,flag,seconds):calls.append((argv,flag,seconds));return dict(code=0)
    report=dict(token='b'*32,image='sha256:'+'c'*64,snapshot_point={'archive_sha256':'d'*64})
    ns['actor'](Path('/source-root'),Path('/output'),report,command,api,role,'lifecycle.py')
    argv,flag,seconds=calls[0];self.assertEqual(seconds,want);self.assertFalse(flag)
    for original in ('--network=none','--read-only','--user=0:0','--cap-drop=ALL','--security-opt=no-new-privileges','--pids-limit=128','--memory=4g','--cpus=2','--ulimit=nofile=8192:8192'):self.assertIn(original,argv)
    if role in ('interruption','lifecycle'):self.assertIn('--cap-add=SETFCAP',argv)
    self.assertEqual(record['exit'],0)
 def test_legacy_actor_and_worker_source_are_unchanged(self):
  original=ORIGINAL.read_text();self.assertEqual(M.derived(original,'normal')['actor'],M.function(original,'actor'))
  worker=(ROOT/'scripts/ci/apps-full574-native/lifecycle.py').read_text();self.assertIn('end=time.monotonic()+600',worker);self.assertIn('reap_limit=5',worker)
  self.assertIn("3000 if role=='lifecycle' else 900 if role in ('extract','interruption','source-verify') else 240",original)
  # Only selected owner functions are re-emitted; no copier, lifecycle or cleanup replacement.
  self.assertEqual(set(M.derived(original,'interruption')),{'run','retain','actor','materialize','bind'})
 def test_wrong_or_missing_trial_proof_refuses_before_any_owner_or_actor(self):
  for mode in ('run','cleanup','retain'):
   for bad in (None,'normal','unknown'):
    calls=[]
    def need(ok,why):
     if not ok:raise ValueError(why)
    fake=types.SimpleNamespace(C=types.SimpleNamespace(need=need,source=lambda p:calls.append('source'),decode=lambda r:r,read=lambda p:{'trial':bad}))
    args=types.SimpleNamespace(mode=mode,source=Path('/source'),proof=Path('/proof'))
    with self.assertRaisesRegex(ValueError,'trial differs'):M.execute(fake,'interruption',args)
    self.assertEqual(calls,['source'])
 def test_unknown_mode_and_changed_source_seams_refuse(self):
  raw=ORIGINAL.read_text()
  for bad in ('',None,'both','NORMAL'):
   with self.assertRaisesRegex(ValueError,'explicit'):M.derived(raw,bad)
  for changed in (raw.replace("'lifecycle','lifecycle.py'","'lifecycle','different.py'"),raw.replace('else 900 if role','else 901 if role')):
   with self.assertRaises(ValueError):M.derived(changed,'interruption')
 def test_workflow_requires_mode_for_all_five_operations_and_retains_bounds(self):
  # Feed exact pre-successor workflow captured separately by test preparation.
  before=(ROOT/'.github/workflows/native-arm-orphans-full574-cleanup.yml').read_text()
  if '      trial:\n' in before:
   after=before
  else:after=M.workflow(before)
  self.assertIn('  group: native-arm-orphans-full574-cleanup-${{ inputs.trial }}',after);self.assertIn('  cancel-in-progress: false',after);self.assertIn('options: [normal, interruption]',after);self.assertIn('required: true',after)
  for mode in ('proof','check','retain'):self.assertEqual(after.count('"$SLICE/job.py" '+mode+' --trial "$TRIAL" --source'),1)
  for mode in ('run','cleanup'):self.assertEqual(after.count('"$SLICE/supervise.py" '+mode+' --handoff'),1)
  self.assertIn("--job-outcome '${{ steps.orphan_trial.outcome }}'",after)
  for bound in ('3550s','timeout-minutes: 120','--kill-after=10s 650s','--kill-after=10s 2300s'):self.assertIn(bound,after)
  self.assertIn("-p 'test*.py' -v",after)
  self.assertIn('orphans-full574-cleanup-${{ inputs.trial }}-',after)
 def test_retention_uses_selected_result_and_original_uncertainty_checks(self):
  raw=ORIGINAL.read_text();normal=M.derived(raw,'normal')['retain'];inter=M.derived(raw,'interruption')['retain']
  self.assertIn('life=C.result(',normal);self.assertIn("owner['lifecycle']==life",normal)
  for clause in ("interruption['packages_committed']=='UNKNOWN'","interruption['rollback']=='NOT_CLAIMED'","interruption['worker_group_absent']","interruption['direct_child_reaped']","interruption['time_limit']==600","interruption['reap_limit']==5","interruption['seconds']<=605","sum(row['bytes'] for row in interruption['outputs'].values())<=1024**2"):
   self.assertIn(clause,inter)
  for text in (normal,inter):
   self.assertIn("source_capabilities_sha256",text);self.assertIn("source_tree",text);self.assertIn("'export', 'extract', 'signer'",text)
if __name__=='__main__':unittest.main(verbosity=2)

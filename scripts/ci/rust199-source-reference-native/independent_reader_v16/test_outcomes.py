#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Finite qualification/global outcome and callback lifetime MODEL controls."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import sys
import unittest


def fence(event,args):
 if event.startswith(('subprocess.','socket.','ctypes.'))or event in('os.system','os.exec','os.fork','os.posix_spawn','fcntl.flock','resource.setrlimit'):
  raise AssertionError('Reader16 outcomes forbid actors/network/authority: '+event)


sys.addaudithook(fence)
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('reader16_outcome_models',HERE/'test_reader.py')
T=importlib.util.module_from_spec(spec);spec.loader.exec_module(T);R,S,E,B=T.R,T.S,T.E,T.B


def hosted(phase='bootstrap'):
 return dict(schema=4,phase=phase,dispatch_sha256='3'*64,native_acceptance=False,holds_preserved=True,status='BOOTSTRAP_QUALIFIED_TRANSFER_DATA_EXPORTED'if phase=='bootstrap'else'RUST199_BUILD_EXPORTED_RETIRED_PENDING_INDEPENDENT_READER')


class Lifetime:
 """Independent small state model; never imports or executes Source code."""
 def __init__(self):self.now=0;self.deadline=100;self.cancelled=False;self.closed=False;self.events=[];self.outer=lambda:self.events.append('outer')
 def active(self):
  if self.closed:raise ValueError('MODEL retired workspace')
  self.events.append('workspace')
 def report(self):
  if self.now>=self.deadline:raise ValueError('MODEL global deadline')
  if self.cancelled:raise ValueError('MODEL cancellation')
  if self.outer is not None:self.outer()
 def hash(self,callback):
  digest=hashlib.sha256()
  for block in(b'MODEL finalized controller',b''):callback();digest.update(block)
  return digest.hexdigest()


class OutcomeControls(unittest.TestCase):
 def setUp(self):S.END=None
 def test_model_finite_qualification_and_both_complete_hosted_phases_are_distinct_gates(self):
  q,provider,image=T.qualification_model();E.qualification(q,provider,image)
  self.assertEqual(q['status'],'PASS_NATIVE_SOURCE_QUALIFICATION_ONLY');self.assertFalse(q['native_acceptance'])
  for phase in('bootstrap','build'):R.phase_completion(hosted(phase),phase,'3'*64)
 def test_model_successful_qualification_plus_actual_global_failure_shape_refuses(self):
  q,provider,image=T.qualification_model();E.qualification(q,provider,image)
  row=hosted();actual=S.decode((HERE/'fixtures/source361-post-retire-guard-failure.ACTUAL.json').read_bytes());row.update(actual['hosted_failure'])
  with self.assertRaisesRegex(S.Hold,'PHASE_HOSTED_REPORT'):R.phase_completion(row,'bootstrap','3'*64)
  self.assertEqual(actual['qualification_status'],q['status']);self.assertEqual(actual['bootstrap'],'FAIL');self.assertEqual(actual['build'],'SKIPPED')
 def test_partial_qualification_cannot_replace_global_completion_or_erase_failure(self):
  for mutate in(lambda row:row.update(status='PASS_NATIVE_SOURCE_QUALIFICATION_ONLY'),lambda row:row.update(status='FAIL'),lambda row:row.update(error='MODEL retained failure'),lambda row:row.update(cleanup_error='MODEL cleanup failure'),lambda row:row.update(native_acceptance=True),lambda row:row.update(holds_preserved=False)):
   row=hosted();mutate(row)
   with self.assertRaisesRegex(S.Hold,'PHASE_HOSTED_REPORT|PHASE_COMPLETION_STATUS'):R.phase_completion(row,'bootstrap','3'*64)
 def test_failed_or_skipped_provider_job_refuses_even_with_finite_qualification_pass(self):
  q,provider,image=T.qualification_model();E.qualification(q,provider,image)
  sel=T.selected();run=T.run(sel);jobs=T.jobs(sel);B.terminal(run,jobs,sel)
  for phase,conclusion in(('bootstrap','failure'),('build','skipped')):
   bad=copy.deepcopy(jobs);next(row for row in bad['jobs']if row['name']=='rust199-'+phase+'-v4')['conclusion']=conclusion
   with self.assertRaisesRegex(S.Hold,'TERMINAL_PHASE_JOB'):B.terminal(run,bad,sel)
  bad=copy.deepcopy(run);bad['conclusion']='failure'
  with self.assertRaisesRegex(S.Hold,'TERMINAL_RUN_EXACT_TWO_JOB_WORKFLOW'):B.terminal(bad,jobs,sel)
 def test_old_active_callback_refuses_after_workspace_close(self):
  model=Lifetime();model.active();model.closed=True
  with self.assertRaisesRegex(ValueError,'MODEL retired workspace'):model.hash(model.active)
 def test_post_retirement_report_hash_keeps_outer_guard_without_retired_workspace_access(self):
  model=Lifetime();model.closed=True;digest=model.hash(model.report)
  self.assertEqual(digest,hashlib.sha256(b'MODEL finalized controller').hexdigest());self.assertEqual(model.events,['outer','outer'])
 def test_post_retirement_hash_still_refuses_global_timeout_cancellation_and_outer_failure(self):
  for state in('expired','cancelled','outer_failure'):
   model=Lifetime();model.closed=True
   if state=='expired':model.now=model.deadline
   elif state=='cancelled':model.cancelled=True
   else:
    def refuse():raise ValueError('MODEL outer guard')
    model.outer=refuse
   with self.assertRaises(ValueError):model.hash(model.report)
   self.assertNotIn('workspace',model.events)


if __name__=='__main__':unittest.main()

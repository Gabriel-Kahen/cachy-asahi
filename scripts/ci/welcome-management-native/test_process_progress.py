# SPDX-License-Identifier: MIT
"""Inert fixed-field progress controls. No GUI, helper or native process."""
import importlib.util,sys,unittest
from pathlib import Path
from unittest.mock import patch,Mock
HERE=Path(__file__).resolve().parent
ROOT=next(p for p in HERE.parents if (p/'manifests/packages.toml').is_file())
sys.path[:0]=[str(HERE),str(ROOT/'scripts/ci/welcome-management-native')]
def load(name,file):
 spec=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
R=load('progress_root','management_root.py');G=load('progress_phase','management_phase.py')
def statline(start=100,user=2,system=1,state='R'):
 fields=['0']*30;fields[0]=state;fields[11]=str(user);fields[12]=str(system);fields[19]=str(start)
 return '90 (name with ) parentheses) '+' '.join(fields)
def fields(pid,name,cap):
 return {'stat':statline(), 'status':'Uid:\t23001\t23001\t23001\t23001\nVmRSS:\t128 kB\nThreads:\t1\nOther: not retained\n',
 'wchan':'pipe_write\n','io':'rchar: 1\nwchar: 2\nsyscr: 3\nsyscw: 4\nread_bytes: 0\nwrite_bytes: 0\ncancelled_write_bytes: 0\n'}[name]
class Progress(unittest.TestCase):
 def test_exact_selected_fields_and_no_args_paths_or_environment(self):
  with patch.object(R,'progress_read',side_effect=fields),patch.object(R.select,'select',return_value=([],[],[])):
   row=R.progress_process(90,100,8)
  self.assertEqual(row,dict(status='OBSERVED_NONATOMIC_COUNTERS',state='R',starttime=100,user_ticks=2,system_ticks=1,rss_kib=128,threads=1,wchan='pipe_write',io=dict(rchar=1,wchar=2,syscr=3,syscw=4,read_bytes=0,write_bytes=0,cancelled_write_bytes=0)))
 def test_exited_pidfd_never_reads_reused_pid(self):
  with patch.object(R,'progress_read',side_effect=AssertionError('no read')),patch.object(R.select,'select',return_value=([8],[],[])):
   self.assertEqual(R.progress_process(90,100,8),dict(status='EXITED_HELD_PIDFD'))
 def test_changed_identity_uid_or_counter_refuses(self):
  for wrong in ('stat','status','io','wchan'):
   def altered(pid,name,cap):
    if name==wrong:return {'stat':statline(start=101),'status':'Uid: 0 0 0 0\nVmRSS: 128 kB\nThreads: 1\n','io':'rchar: 1\n','wchan':'secret/path'}[name]
    return fields(pid,name,cap)
   with self.subTest(field=wrong),patch.object(R,'progress_read',side_effect=altered),patch.object(R.select,'select',return_value=([],[],[])),self.assertRaises(ValueError):R.progress_process(90,100,8)
  count=[0]
  def drift(pid,name,cap):
   if name=='stat':count[0]+=1;return statline(user=3 if count[0]==1 else 2)
   return fields(pid,name,cap)
  with patch.object(R,'progress_read',side_effect=drift),patch.object(R.select,'select',return_value=([],[],[])),self.assertRaises(ValueError):R.progress_process(90,100,8)
 def test_mid_sample_exit_never_claims_stable_observation(self):
  with patch.object(R,'progress_read',side_effect=fields),patch.object(R.select,'select',side_effect=[([],[],[]),([8],[],[])]):
   self.assertEqual(R.progress_process(90,100,8),dict(status='EXITED_DURING_SAMPLE'))
 def test_exact_two_identities_low_frequency_and_hard_count(self):
  clock=[10.];seen=[]
  def sample(pid,start,fd):
   seen.append((pid,start,fd));return dict(status='OBSERVED_NONATOMIC_COUNTERS',state='R',starttime=2**64-1,user_ticks=2**64-1,system_ticks=2**64-1,rss_kib=2**64-1,threads=2**32-1,wchan='w'*128,io={k:2**64-1 for k in ('rchar','wchar','syscr','syscw','read_bytes','write_bytes','cancelled_write_bytes')})
  with patch.object(R.time,'monotonic',side_effect=lambda:clock[0]),patch.object(R,'progress_process',side_effect=sample):
   p=R.Progress(dict(pid=90,starttime=100,supervisor_pid=89,supervisor_starttime=99),8,9)
   for i in range(100):clock[0]=10+i;p.sample()
   value=p.value()
  self.assertEqual(len(value['samples']),7);self.assertEqual([s['elapsed_ms'] for s in value['samples']],[0,5000,10000,15000,20000,25000,30000])
  self.assertEqual(seen,[(90,100,8),(89,99,9)]*7);self.assertLess(len(R.C.encoded(value)),16384)
 def test_sampling_failure_is_bounded_not_original_failure_replacement(self):
  with patch.object(R,'progress_process',side_effect=PermissionError('/private/path must not escape')):
   p=R.Progress(dict(pid=90,starttime=100,supervisor_pid=89,supervisor_starttime=99),8,9);p.sample()
  value=p.value();self.assertNotIn('/private',str(value));self.assertEqual(value['samples'][0]['helper'],dict(status='UNAVAILABLE_OR_REFUSED',error_type='PermissionError'))
 def test_progress_reaches_only_existing_bounded_failure_operand(self):
  value=dict(schema_version=1,samples=[]);remember=Mock()
  with patch.object(G,'request',return_value=dict(helper_absent=False,supervisor_absent=True,gui_progress=value,unrelated='omit')):
   self.assertFalse(G.completed_report_state(remember))
  self.assertEqual(remember.call_args.args[0],dict(helper_absent=False,supervisor_absent=True,gui_progress=value))
  with patch.object(G,'request',return_value=dict(helper_absent=True,supervisor_absent=True,gui_progress={'schema_version':1,'huge':'x'*16384})):
   self.assertTrue(G.completed_report_state(remember))
  self.assertEqual(remember.call_args.args[0]['gui_progress'],dict(status='UNAVAILABLE_OR_REFUSED'))
if __name__=='__main__':unittest.main(verbosity=2)

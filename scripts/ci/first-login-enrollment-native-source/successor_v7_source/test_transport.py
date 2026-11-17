# SPDX-License-Identifier: MIT
"""Genuine Source196 public tuple plus actor-free nested transport MODEL controls.

No transport acquisition, native role, Original GET, lease, key or grant runs.
MODEL classifiers and child boundaries do not establish the unknown actual cause.
"""
import ast
import copy
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent

def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
 sys.modules[name]=module;spec.loader.exec_module(module);return module

B=load('transport_v7_basis_controls',HERE.parent/'test_source_failure_packet_v1.py')
OLD_S,OLD_M=B.S,B.M
S=load('transport_v7_stager_under_test',HERE/'payload/stager.py')
M=load('transport_v7_domain_under_test',HERE/'payload/material_domain.py')
L=load('transport_v7_hosted_under_test',HERE/'payload/hosted.py')
E=B.E
B.S,B.M=S,M
CANARY=B.CANARY
ACTUAL=HERE/'fixtures/public-failure-source196.ACTUAL.json'


class ActualTuple(unittest.TestCase):
 def test_exact_genuine_public_tuple_remains_unknown_native_cause(self):
  raw=ACTUAL.read_bytes();self.assertEqual(len(raw),5386)
  self.assertEqual(hashlib.sha256(raw).hexdigest(),'7700be9ccf5d8f2a1fe60d691769f8e3882a749e8698fc38731b98801242530a')
  value=json.loads(raw);failure=value['material_failure_before_cleanup']['source_failure']
  self.assertEqual(failure['packet'],B.packet('TRANSPORT_NATIVE248','COMMAND_FAILED',2))
  self.assertEqual(failure['stderr_pin'],dict(bytes=153,sha256='6c008c501b82973a52fc3267e3f18ab28bcf0ef4f6996527c7b2e3939fc87c25'))
  self.assertEqual(value['Original_job_log']['underlying_child_error_text'],'NOT_RETAINED')
  self.assertTrue(value['underlying_native248_failure_cause'].startswith('UNKNOWN_NOT_RETAINED'))
  self.assertFalse(value['native_acceptance']);self.assertIsNone(value['Root_final_acceptance'])
 def test_original_parent_packet_is_causally_nonidentifying(self):
  expected=json.loads(ACTUAL.read_bytes())['material_failure_before_cleanup']['source_failure']['stderr_pin']
  # The original producer accepts only phase/reason/ordinal, not any child cause.
  outputs=[]
  for distinct_model_error in (OSError(errno.ENOSPC,CANARY),TimeoutError(CANARY),ValueError(CANARY)):
   diagnostic={};OLD_S.diagnostic_phase(diagnostic,'TRANSPORT_NATIVE248');OLD_S.diagnostic_command(diagnostic,2)
   raw=OLD_S.failure_packet(diagnostic);outputs.append(raw)
   self.assertEqual(OLD_S.pin(raw),expected)
   self.assertNotIn(str(distinct_model_error).encode(),raw)
  self.assertEqual(len(set(outputs)),1)
 def test_historical_schema1_packet_remains_accepted(self):
  packet=json.loads(ACTUAL.read_bytes())['material_failure_before_cleanup']['source_failure']['packet']
  self.assertEqual(M.failure_packet(M.encoded(packet)),packet)



def nested(**changes):
 value=dict(schema=1,kind='CURRENT_RETAINED_TRANSPORT_FAILURE_V1',phase='METADATA_FETCH',
  operation='GIT_FETCH_METADATA',error_class='VALIDATION',errno=None,command_ordinal=1,
  git_exit=128,git_timeout=False,http_status=None)
 return dict(value,**changes)


def diagnostic(phase='TRANSPORT_NATIVE248',transport=None):
 return dict(phase=phase,reason='COMMAND_FAILED',command_ordinal=2,transport=transport)


def model_transport(error,phase='metadata_fetch',argv=None,deep=None,supervision=None):
 """MODEL exact code-object joins; these functions never dispatch an actor."""
 scope=dict(ERROR=error,PHASE=phase,ARGV=argv or ['/MODEL/git','fetch'],DEEP=deep,
  OUTCOME=B.outcome(128)if supervision is None else supervision)
 source="""
class Delivery:
 def __init__(self):self.phase=PHASE;self.rows=[]
 def file_pin(self):raise ERROR
 def tick(self):raise ERROR
 def command(self,argv):
  row={'supervision':OUTCOME};self.rows.append(row)
  if DEEP=='write_at':write_at()
  if DEEP=='file_pin':self.file_pin()
  if DEEP=='tick':self.tick()
  raise ERROR
def write_at():raise ERROR
def deliver(*args,**kwargs):
 C=CORE;delivery=C.Delivery()
 return delivery.command(ARGV)
"""
 # MODEL line numbers deliberately do not collide with frozen helper sites.
 exec(compile('\n'*400+source,'<MODEL-transport-code-joins>','exec'),scope)
 scope['CORE']=SimpleNamespace(Delivery=scope['Delivery'],write_at=scope['write_at'])
 return SimpleNamespace(deliver=scope['deliver']),scope


class Classifier(unittest.TestCase):
 def classify(self,error,**kwargs):
  transport,scope=model_transport(error,**kwargs)
  try:transport.deliver()
  except BaseException as caught:self.assertIs(caught,error);return S.transport_failure(caught,transport)
  self.fail('MODEL error did not propagate')
 def test_closed_phase_git_operation_and_exit_from_joined_model_frames(self):
  for phase,expected in (('setup','SETUP'),('metadata_fetch','METADATA_FETCH'),('metadata_proof','METADATA_PROOF'),
   ('required_blobs_fetch','REQUIRED_BLOBS_FETCH'),('complete_object_proof','COMPLETE_OBJECT_PROOF'),
   ('all_required_materialization','MATERIALIZATION'),('final_namespace_proof','FINAL_NAMESPACE_PROOF')):
   value=self.classify(ValueError(CANARY),phase=phase)
   self.assertEqual(value['phase'],expected);self.assertEqual(value['command_ordinal'],0)
   self.assertEqual(value['git_exit'],128);self.assertFalse(value['git_timeout']);self.assertIsNone(value['http_status'])
   self.assertEqual(value['operation'],'GIT_FETCH_BLOBS'if phase=='required_blobs_fetch'else'GIT_FETCH_METADATA')
 def test_deeper_logwrite_fileverify_and_tick_take_priority_over_git_argv(self):
  for deep,expected,error in (('write_at','RECEIPT_WRITE',OSError(errno.ENOSPC,CANARY,'/PRIVATE/PATH')),
   ('file_pin','FILE_VERIFY',ValueError(CANARY)),('tick','DEADLINE',TimeoutError(CANARY))):
   with self.subTest(deep=deep):
    value=self.classify(error,phase='all_required_materialization',argv=['/MODEL/git','cat-file','blob',CANARY],deep=deep)
    self.assertEqual(value['operation'],expected);self.assertNotIn(CANARY.encode(),S.encoded(value))
    self.assertNotIn(b'/PRIVATE',S.encoded(value));self.assertEqual(value['errno'],errno.ENOSPC if deep=='write_at'else None)
 def test_unjoined_same_name_frame_cannot_supply_transport_phase_or_git_facts(self):
  error=ValueError(CANARY);transport,scope=model_transport(error)
  other,_=model_transport(error,phase='required_blobs_fetch')
  try:transport.deliver()
  except ValueError as caught:value=S.transport_failure(caught,other)
  self.assertEqual(value['phase'],'ADMISSION');self.assertEqual(value['operation'],'DELIVERY')
  self.assertIsNone(value['command_ordinal']);self.assertIsNone(value['git_exit'])
 def test_error_class_is_finite_and_never_formats_exception(self):
  class PrivateNamedModelError(Exception):
   def __str__(self):raise AssertionError('private exception text requested')
  for error,expected in ((ValueError(CANARY),'VALIDATION'),(OSError(errno.EACCES,CANARY),'OS_ERROR'),
   (TimeoutError(CANARY),'TIMEOUT'),(UnicodeError(CANARY),'UNICODE'),
   (json.JSONDecodeError(CANARY,CANARY,0),'JSON'),(KeyboardInterrupt(CANARY),'CONTROL'),
   (PrivateNamedModelError(CANARY),'OTHER')):
   with self.subTest(expected=expected):
    value=self.classify(error);self.assertEqual(value['error_class'],expected)
    raw=S.encoded(value);self.assertNotIn(CANARY.encode(),raw);self.assertNotIn(b'PrivateNamedModelError',raw)
 def test_unlisted_errno_and_uncertain_git_exit_remain_absent(self):
  row=B.outcome(128);row['ownership']='UNKNOWN'
  value=self.classify(OSError(4095,CANARY),supervision=row)
  self.assertIsNone(value['errno']);self.assertIsNone(value['git_exit'])


class Packets(unittest.TestCase):
 def test_v2_roundtrip_and_three_validators_share_closed_transport_contract(self):
  for key,values in (('phase',S.TRANSPORT_PHASES),('operation',S.TRANSPORT_OPERATIONS),
   ('error_class',S.TRANSPORT_ERRORS),('errno',(None,*S.TRANSPORT_ERRNOS)),
   ('command_ordinal',(None,0,1169)),('git_exit',(None,-255,0,255)),('git_timeout',(None,False,True))):
   for value in values:
    packet=nested(**{key:value})
    with self.subTest(key=key,value=value):
     self.assertTrue(S.transport_packet(packet));self.assertTrue(M.transport_packet(packet));self.assertTrue(L.transport_packet(packet))
     raw=S.failure_packet(diagnostic(transport=packet));self.assertLessEqual(len(raw),1024)
     self.assertEqual(M.failure_packet(raw),dict(schema=2,kind='CURRENT_MATERIAL_STAGE_FAILURE_V2',**diagnostic(transport=packet)))
 def test_arbitrary_text_wrong_types_http_and_extra_fields_refuse(self):
  bad=[dict(nested(),secret=CANARY)]
  for key,value in (('schema',True),('schema',2),('kind',CANARY),('phase',CANARY),('operation',CANARY),
   ('error_class',CANARY),('errno',True),('errno',4095),('errno',CANARY),('command_ordinal',True),
   ('command_ordinal',1170),('command_ordinal',-1),('git_exit',True),('git_exit',256),
   ('git_timeout',1),('http_status',403),('http_status',CANARY)):
   bad.append(nested(**{key:value}))
  for value in bad:
   with self.subTest(value=value):
    self.assertFalse(S.transport_packet(value));self.assertFalse(M.transport_packet(value));self.assertFalse(L.transport_packet(value))
    with self.assertRaises(ValueError):S.failure_packet(diagnostic(transport=value))
    body=dict(schema=2,kind='CURRENT_MATERIAL_STAGE_FAILURE_V2',**diagnostic(transport=value))
    self.assertIsNone(M.failure_packet(M.encoded(body)))
 def test_nested_only_transport_or_child_and_entire_canonical_body_required(self):
  with self.assertRaises(ValueError):S.failure_packet(diagnostic('PRIVATE_SEED',nested()))
  raw=S.failure_packet(diagnostic(transport=nested()))
  for bad in (raw[:-1],raw+b'\0',raw+b'\n',raw+raw,b'x'*1025,b'{"schema":2,"schema":2}',b'\xff'):
   self.assertIsNone(M.failure_packet(bad))


class Retention(unittest.TestCase):
 setUp=B.Controls.setUp
 session=B.Controls.session
 values=B.Controls.values
 record=B.Controls.record
 process=B.Controls.process
 safe_record=B.Controls.safe_record
 def child_packet(self,**changes):
  return S.failure_packet(dict(phase='CHILD',reason='PHASE_FAILED',command_ordinal=None,transport=nested(),**changes))
 def test_only_complete_naturally_retired_failed_child_can_update_parent(self):
  raw=self.child_packet();valid=B.outcome(2);valid.pop('output')
  parent=diagnostic();self.assertTrue(S.retain_transport_failure(parent,valid,raw));self.assertEqual(parent['transport'],nested())
  for key,value in (('exit',0),('exit',True),('reaped',False),('ownership','UNKNOWN'),('group_census','UNKNOWN'),
   ('output_complete',False),('signals',['MODEL']),('timeout',True),('error',CANARY)):
   row=dict(valid,**{key:value});parent=diagnostic()
   with self.subTest(key=key):self.assertFalse(S.retain_transport_failure(parent,row,raw));self.assertIsNone(parent['transport'])
  for bad in (raw[:-1],raw+b'\0',b'',CANARY.encode(),S.failure_packet(diagnostic(transport=nested()))):
   parent=diagnostic();self.assertFalse(S.retain_transport_failure(parent,valid,bad));self.assertIsNone(parent['transport'])
  parent=diagnostic('PRIVATE_SEED');self.assertFalse(S.retain_transport_failure(parent,valid,raw))
 def test_real_runner_reads_nested_packet_before_unlink_and_keeps_nonzero_failure(self):
  parent=diagnostic();result=B.outcome(2);result.pop('output');raw=self.child_packet();events=[]
  owner=SimpleNamespace(prepare=lambda:None,supervise=lambda *a,**k:dict(result));executor=SimpleNamespace(checked_tool=lambda row:row['path'])
  runner=S.Runner(owner,self.root,time.monotonic()+100,executor,{'python3':dict(path='/usr/bin/python3')},parent)
  runner.rows=[{},{}]
  def spawn(argv,**args):
   args['stdout'].write(CANARY.encode());args['stderr'].write(raw);events.append('MODEL_SPAWN');return SimpleNamespace(pid=123)
  retain=S.retain_transport_failure
  def before_unlink(*args):
   self.assertEqual((self.root/'command-02.stderr').read_bytes(),raw);events.append('RETAIN_BEFORE_UNLINK');return retain(*args)
  with patch.object(S.subprocess,'Popen',side_effect=spawn),patch.object(S.os,'waitid',return_value=object()),patch.object(S,'retain_transport_failure',side_effect=before_unlink):
   with self.assertRaises(ValueError):runner.run(['/usr/bin/python3','MODEL_TRANSPORT'],15)
  self.assertEqual(events,['MODEL_SPAWN','RETAIN_BEFORE_UNLINK']);self.assertEqual(parent['transport'],nested())
  self.assertEqual(parent['command_ordinal'],2);self.assertEqual(len(runner.rows),2);self.assertEqual(list(self.root.glob('command-*')),[])
  self.assertNotIn(CANARY.encode(),S.failure_packet(parent))
 def test_nested_runner_packet_flows_domain_hosted_before_close_without_acceptance(self):
  raw=S.failure_packet(diagnostic(transport=nested()));session=self.session();values=self.values()
  with self.process(session,raw,2):
   with self.assertRaises(ValueError):session.stage(secrets=values)
  self.assertEqual(session.state,'HOLD_CLOSEONLY');self.assertEqual(values,{})
  record=self.record();self.safe_record(record,'AVAILABLE');self.assertEqual(record['packet']['transport'],nested())
  (self.control/'private').mkdir();M.write(self.control/'private/context.json',self.r['context'])
  plan=SimpleNamespace(control=self.control,material_session=session);projected=L.material_stage_failure(plan)
  self.assertEqual(projected['availability'],'AVAILABLE');self.assertEqual(projected['packet']['transport'],nested())
  self.assertEqual(projected['stderr_pin'],M.pin(raw));self.assertNotIn(CANARY.encode(),M.encoded(projected))
  self.assertIsNone(projected['Root_final_acceptance']);self.assertFalse(projected['hardware_acceptance'])
  receipt=dict(owned_storage_absent=True,scope_absence=dict(scope=M.scope_name(B.NONCE),absent_twice=True),binding=self.r['context']['binding'],nonce=B.NONCE,request_pin=M.pin(M.encoded(self.r)),**M.FINAL)
  M.write(self.control/'material-domain-close.json',receipt)
  with self.process(session,b'',0):self.assertTrue(session.close()['closed'])
  self.assertEqual(L.material_stage_failure(plan)['packet']['transport'],nested())
 def test_hosted_rejects_unknown_nested_text_even_with_rejoined_stream_pin(self):
  raw=S.failure_packet(diagnostic(transport=nested()));session=self.session()
  with self.process(session,raw,2):
   with self.assertRaises(ValueError):session.stage(secrets=self.values())
  (self.control/'private').mkdir();M.write(self.control/'private/context.json',self.r['context'])
  record=self.record();record['packet']['transport']['operation']=CANARY
  record['stderr_pin']=M.pin(M.encoded(record['packet']));session.receipts[0]['stderr_pin']=record['stderr_pin']
  (self.control/'material-stage-failure.json').write_bytes(M.encoded(record))
  self.assertEqual(L.material_stage_failure(SimpleNamespace(control=self.control,material_session=session)),dict(status='UNAVAILABLE_OR_UNSAFE'))
 def test_actual_transport_child_route_attaches_closed_model_frame_record(self):
  error=OSError(errno.EACCES,CANARY,'/PRIVATE/PATH');transport,_=model_transport(error,phase='required_blobs_fetch')
  request=dict(native_profile={'MODEL':'profile'},public_profile={'MODEL':'other'},transport_policy={'MODEL':'policy'})
  with patch.object(S,'child_request',return_value=request),patch.object(S,'child_authority',return_value=(self.root,{},{})),patch.object(S,'selected',return_value=transport):
   with self.assertRaises(OSError)as raised:S.child_main('transport',self.root/'request.json','a'*64,'native248')
  self.assertIs(raised.exception,error);value=error._current_transport_failure
  self.assertEqual(value['phase'],'REQUIRED_BLOBS_FETCH');self.assertEqual(value['operation'],'GIT_FETCH_BLOBS')
  self.assertEqual(value['error_class'],'OS_ERROR');self.assertEqual(value['errno'],errno.EACCES)
  self.assertNotIn(CANARY.encode(),S.encoded(value));self.assertNotIn(b'/PRIVATE',S.encoded(value))
 def test_child_cli_propagates_only_closed_transport_attribute(self):
  error=ValueError(CANARY);error._current_transport_failure=nested();stderr=B.Stderr()
  guard=ast.parse(Path(S.__file__).read_bytes()).body[-1];namespace=dict(S.__dict__,__name__='__main__')
  def fail(*args,**kwargs):raise error
  namespace['child_main']=fail
  with patch.object(S.sys,'argv',['stager','transport','--request',str(self.root/'unused'),'--request-sha256','a'*64,'--which','native248']),patch.object(S.sys,'stderr',stderr):
   with self.assertRaises(SystemExit)as stop:exec(compile(ast.Module(body=[guard],type_ignores=[]),'<MODEL-v7-child-cli>','exec'),namespace)
  self.assertEqual(stop.exception.code,2);value=M.failure_packet(stderr.buffer.getvalue())
  self.assertEqual(value['transport'],nested());self.assertEqual(value['phase'],'CHILD');self.assertNotIn(CANARY.encode(),stderr.buffer.getvalue())
 def test_held_stderr_capture_helpers_remain_byte_exact_and_no_actor_attempts(self):
  def bodies(module):
   source=Path(module.__file__).read_text();tree=ast.parse(source)
   return {n.name:ast.get_source_segment(source,n)for n in tree.body if isinstance(n,ast.FunctionDef)}
  old,new=bodies(OLD_M),bodies(M)
  for name in ('stderr_identity','retired_stderr'):self.assertEqual(new[name],old[name])
  self.assertEqual(B.ACTORS,[])


if __name__=='__main__':unittest.main(verbosity=2)

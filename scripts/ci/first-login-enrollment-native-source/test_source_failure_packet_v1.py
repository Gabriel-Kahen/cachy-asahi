# SPDX-License-Identifier: MIT
"""Fenced MODEL controls for failure-only Source stderr and caller retention.

These controlled refusals are not a reproduction of the unknown native cause.
No operational process, namespace, lease, network, credential or key is used.
"""
import ast
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
NATIVE=HERE/'payload/native'
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
M=load('failure_packet_domain_under_test',NATIVE/'material_domain_current_v3.py')
S=load('failure_packet_stager_under_test',NATIVE/'stage_materials_current_v3_python_v1.py')
E=load('failure_packet_unchanged_executor',NATIVE/'owned_executor_current_v3.py')
ACTORS=[]
def fence(event,args):
 if event.startswith(('subprocess.','socket.','ctypes.','os.exec','os.spawn','os.fork','os.posix_spawn'))or event in('os.system','resource.setrlimit','fcntl.flock','os.setuid','os.setgid','os.setgroups','os.chown','os.kill','os.killpg'):
  ACTORS.append(event);raise AssertionError('FENCED Source failure DATA controls: '+event)
sys.addaudithook(fence)
PHASES=('ENTRY','AUTHORIZE','SOURCE','NATIVE_CONTEXT','INPUTS','HELPERS','TOOLS','STORAGE','SCOPE','TRANSPORT_PUBLIC14','TRANSPORT_NATIVE248','PRIVATE_SEED','PUBLIC14_PREPARE','NATIVE248_PREPARE','DOWNLOAD','COMPLETE517','FINALIZE','CHILD')
REASONS=('PHASE_FAILED','COMMAND_FAILED')
NONCE='a'*64
CANARY='PRIVATE_MODEL_CANARY_7b9f_NEVER_EXPORT'
TOOLS={name:dict(path='/usr/bin/'+name,MODEL_ONLY=True)for name in('python3','systemd-run','sudo')}

def packet(phase='DOWNLOAD',reason='COMMAND_FAILED',ordinal=3):
 return dict(schema=1,kind='CURRENT_MATERIAL_STAGE_FAILURE_V1',phase=phase,reason=reason,command_ordinal=ordinal)
def outcome(exit=0,output=b''):
 return dict(reaped=True,ownership='REAPED',group_census='EMPTY_TWICE',output_complete=True,signals=[],timeout=False,error=None,exit=exit,output=output)
class Stderr:
 def __init__(self):self.buffer=io.BytesIO()
 def write(self,text):self.buffer.write(text.encode());return len(text)
 def flush(self):pass

class Controls(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(prefix='FENCED-source-failure-');self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
  self.control=self.root/'control';self.control.mkdir(mode=0o700)
  self.r=dict(control_root=str(self.control),shared_timing=dict(deadline_monotonic=time.monotonic()+4000,expires_epoch=time.time()+4000),context=dict(binding={'MODEL':'not-authority'},PRIVATE_BODY=CANARY),private_request=CANARY)
  now=int(time.time());self.d=dict(nonce=NONCE,issued_epoch=now-10,expires_epoch=now+4000,programs=dict(base_inputs={'MODEL':'only'}))
  self.g=dict(storage_parent=str(self.root/'owned-storage'),expires_epoch=now+4000)
 def session(self):return M.MaterialSession(self.r,(self.root,self.d,{},self.g,E,S,SimpleNamespace()))
 def values(self):return {n:CANARY for n in S.secret_names()}
 def record(self):return M.decoded(M.read(self.control/'material-stage-failure.json'))
 def row(self,raw,**changes):
  result=outcome(7);result.pop('output');result['error']=CANARY
  return dict(kind='STAGE',output_pin=M.pin(CANARY.encode()),stderr_pin=M.pin(raw),supervision=result,**changes)
 @contextlib.contextmanager
 def process(self,session,stderr=b'',exit=7,stdout=b'',events=None):
  events=[]if events is None else events
  @contextlib.contextmanager
  def errors():
   stream=io.BytesIO(stderr);stream.seek(0,io.SEEK_END)
   try:yield stream
   finally:stream.close()
  def secret(values,names):
   try:yield io.BytesIO(CANARY.encode())
   finally:values.clear()
  def spawn(*a,**kw):events.append('MODELED_SPAWN');return object()
  session.O=SimpleNamespace(prepare=lambda:None,supervise=lambda *a,**kw:outcome(exit,stdout))
  with patch.object(M,'scope_path',return_value=SimpleNamespace(exists=lambda:False)),patch.object(M,'scope_tools',return_value=TOOLS),patch.object(E,'require_runtime_capabilities'),patch.object(E,'stderr_buffer',errors),patch.object(M,'sealed_secret_input',side_effect=secret),patch.object(M.subprocess,'Popen',side_effect=spawn),patch.object(M,'absent',side_effect=lambda nonce,deadline,closing=False:dict(scope=M.scope_name(nonce,closing),absent_twice=True)):
   yield events
 def safe_record(self,value,availability):
  self.assertEqual(set(value),{'schema','kind','status','availability','packet','request_pin','context_pin','stdout_pin','stderr_pin','retirement_pin',*M.FINAL})
  self.assertIs(type(value['schema']),int);self.assertEqual(value['schema'],1);self.assertEqual(value['kind'],'CURRENT_MATERIAL_STAGE_FAILURE_RECORD_V1');self.assertEqual(value['status'],'DIAGNOSTIC_ONLY');self.assertEqual(value['availability'],availability)
  self.assertEqual(value['request_pin'],M.pin(M.encoded(self.r)));self.assertEqual(value['context_pin'],M.pin(M.encoded(self.r['context'])))
  for k,v in M.FINAL.items():self.assertEqual(value[k],v)
  text=M.encoded(value);self.assertNotIn(CANARY.encode(),text);self.assertNotIn(b'PRIVATE_BODY',text);self.assertNotIn(b'argv',text);self.assertNotIn(b'exception',text)
 def test_01_exact_canonical_closed_enum_packet_roundtrip(self):
  for phase in PHASES:
   for reason in REASONS:
    for ordinal in(None,0,26):
     value=packet(phase,reason,ordinal);self.assertEqual(M.failure_packet(M.encoded(value)),value)
 def test_02_entire_packet_rejects_malformed_extra_and_noncanonical_bodies(self):
  good=M.encoded(packet());bad=[None,'not bytes',0,{},b'',b'\xff',b'null\n',b'[]\n',b'{',good[:-1],good+b'\n',good+b'PRIVATE',good+good,b'x'*1025,b'{"schema":1,"schema":1}',b'{"x":NaN}',json.dumps(packet()).encode()]
  for body in bad:
   with self.subTest(body=str(body)[:60]):self.assertIsNone(M.failure_packet(body))
  for key,value in(('schema',True),('schema',2),('kind',CANARY),('phase',CANARY),('phase',[]),('reason',{}),('reason',CANARY),('command_ordinal',True),('command_ordinal',-1),('command_ordinal',27),('command_ordinal','3'),('command_ordinal',1.0),('command_ordinal',{'private':CANARY}),('extra',CANARY)):
   v=packet();v[key]=value
   with self.subTest(key=key,value=value):self.assertIsNone(M.failure_packet(M.encoded(v)))
 def test_03_safe_record_joins_original_request_context_stream_and_retirement_pins(self):
  session=self.session();raw=M.encoded(packet());row=self.row(raw);session.retain_stage_failure(row,raw,True);value=self.record();self.safe_record(value,'AVAILABLE');self.assertEqual(value['packet'],packet());self.assertEqual(value['stdout_pin'],row['output_pin']);self.assertEqual(value['stderr_pin'],M.pin(raw));self.assertEqual(value['retirement_pin'],M.pin(M.encoded(row['supervision'])));self.assertEqual(stat.S_IMODE((self.control/'material-stage-failure.json').stat().st_mode),0o600)
 def test_04_absent_extra_truncated_or_unjoined_stderr_is_only_unavailable(self):
  cases=[(None,False),(b'',True),(M.encoded(dict(packet(),extra=CANARY)),True),(M.encoded(packet())[:-3],True),(M.encoded(packet()),False)]
  for raw,complete in cases:
   session=self.session();row=self.row(raw or b'');session.retain_stage_failure(row,raw,complete);value=self.record();self.safe_record(value,'UNAVAILABLE');self.assertIsNone(value['packet']);session.request.unlink();(self.control/'material-stage-failure.json').unlink()
  session=self.session();raw=M.encoded(packet());row=self.row(raw);row['stderr_pin']=M.pin(b'changed');session.retain_stage_failure(row,raw,True);self.safe_record(self.record(),'UNAVAILABLE')
 def test_05_uncertain_or_missing_retirement_never_authenticates_packet(self):
  raw=M.encoded(packet())
  for change in(('ownership','UNKNOWN'),('reaped',False),('output_complete',False),('exit',True)):
   session=self.session();row=self.row(raw);row['supervision'][change[0]]=change[1];session.retain_stage_failure(row,raw,True);self.safe_record(self.record(),'UNAVAILABLE');session.request.unlink();(self.control/'material-stage-failure.json').unlink()
  session=self.session();row=self.row(raw);row.pop('supervision');session.retain_stage_failure(row,raw,True);self.safe_record(self.record(),'UNAVAILABLE')
 def test_06_retention_is_once_and_never_replaces_existing_file_or_original_failure(self):
  session=self.session();raw=M.encoded(packet());row=self.row(raw);session.retain_stage_failure(row,raw,True);original=(self.control/'material-stage-failure.json').read_bytes();session.retain_stage_failure({},CANARY.encode(),True);self.assertEqual((self.control/'material-stage-failure.json').read_bytes(),original)
  with patch.object(M,'write',side_effect=OSError(CANARY)):session.retain_stage_failure(row,raw,True)
  self.assertEqual((self.control/'material-stage-failure.json').read_bytes(),original)
 def test_07_real_execute_retains_failed_child_before_mandatory_cleanup(self):
  session=self.session();raw=M.encoded(packet());values=self.values();events=[];natural=E.natural
  def reject(row):
   events.append('NATURAL_GATE');return natural(row)
  original_write=M.write
  def retain(path,value):
   result=original_write(path,value)
   if Path(path).name=='material-stage-failure.json':events.append('RETAIN_BEFORE_CLOSE')
   return result
  with self.process(session,raw,7,events=events),patch.object(E,'natural',side_effect=reject),patch.object(M,'write',side_effect=retain):
   with self.assertRaises(ValueError):session.stage(secrets=values)
  self.assertEqual(session.state,'HOLD_CLOSEONLY');self.assertEqual(values,{});self.assertTrue(session.stage_submitted);self.safe_record(self.record(),'AVAILABLE');self.assertEqual(events,['MODELED_SPAWN','NATURAL_GATE','RETAIN_BEFORE_CLOSE'])
  receipt=dict(owned_storage_absent=True,scope_absence=dict(scope=M.scope_name(NONCE),absent_twice=True),binding=self.r['context']['binding'],nonce=NONCE,request_pin=M.pin(M.encoded(self.r)),**M.FINAL);M.write(self.control/'material-domain-close.json',receipt)
  with self.process(session,b'',0):closed=session.close()
  self.assertTrue(closed['closed']);self.assertEqual(session.state,'CLOSED');self.assertIsNone(closed['Root_final_acceptance']);self.assertEqual(session.close(),closed);self.safe_record(self.record(),'AVAILABLE')
 def test_08_malformed_diagnostics_do_not_clear_nonzero_hold_or_block_close(self):
  for raw in(b'',CANARY.encode(),M.encoded(packet())[:-1],M.encoded(dict(packet(),secret=CANARY))):
   session=self.session();values=self.values()
   with self.process(session,raw,7):
    with self.assertRaises(ValueError):session.stage(secrets=values)
   self.assertEqual(session.state,'HOLD_CLOSEONLY');self.safe_record(self.record(),'UNAVAILABLE');session.request.unlink();(self.control/'material-stage-failure.json').unlink()
 def test_09_natural_successful_execute_creates_no_failure_record(self):
  session=self.session();values=self.values()
  with self.process(session,b'',0):row=session.execute(secrets=values)
  self.assertTrue(row['natural']);self.assertFalse((self.control/'material-stage-failure.json').exists());self.assertEqual(values,{})
 def test_10_postexecute_validation_failure_retains_only_unavailable_and_hold(self):
  session=self.session();values=self.values()
  with self.process(session,b'',0):
   with self.assertRaises(FileNotFoundError):session.stage(secrets=values)
  self.assertEqual(session.state,'HOLD_CLOSEONLY');self.safe_record(self.record(),'UNAVAILABLE');self.assertEqual(values,{})
 def stage_call(self,provider):
  return S.stage_materials(source_root=self.root,delegation_raw=b'MODEL',delegation_sha256='a'*64,context={},grant_raw=b'MODEL',grant_sha256='b'*64,output=self.root/'unused',secret_provider=provider,base_lock={},bootstrap_profile={})
 def test_11_stager_failure_emits_only_safe_packet_preserves_original_exception_and_erases_values(self):
  error=ValueError(CANARY);values=self.values();provider=S.OneShotSecrets(values);stderr=Stderr()
  with patch.object(S,'_stage_materials',side_effect=error),patch.object(S.sys,'stderr',stderr):
   with self.assertRaises(ValueError)as raised:self.stage_call(provider)
  self.assertIs(raised.exception,error);self.assertEqual(values,{});raw=stderr.buffer.getvalue();self.assertIsNotNone(M.failure_packet(raw));self.assertNotIn(CANARY.encode(),raw);self.assertIs(getattr(error,'_current_material_failure_emitted',False),True)
 def test_12_diagnostic_write_failure_never_masks_original_stager_exception(self):
  error=ValueError(CANARY);provider=S.OneShotSecrets(self.values());stderr=SimpleNamespace(buffer=SimpleNamespace(write=lambda raw:(_ for _ in ()).throw(OSError(CANARY))))
  with patch.object(S,'_stage_materials',side_effect=error),patch.object(S.sys,'stderr',stderr):
   with self.assertRaises(ValueError)as raised:self.stage_call(provider)
  self.assertIs(raised.exception,error);self.assertIsNot(getattr(error,'_current_material_failure_emitted',False),True)
 def test_13_domain_main_never_duplicates_emitted_packet_or_exports_exception_type(self):
  class PrivateModelException(ValueError):pass
  for marker in(None,False,True,1):
   error=PrivateModelException(CANARY)
   if marker is not None:setattr(error,'_current_material_failure_emitted',marker)
   stderr=Stderr()
   with patch.object(M.sys,'argv',['domain','stage-entry','--request',str(self.root/'unused'),'--request-sha256','a'*64]),patch.object(M,'root_entry',side_effect=error),patch.object(M.sys,'stderr',stderr):
    with self.assertRaises(SystemExit)as stop:M.main()
   self.assertEqual(stop.exception.code,2);raw=stderr.buffer.getvalue()
   if marker is True:self.assertEqual(raw,b'')
   else:self.assertIsNotNone(M.failure_packet(raw))
   self.assertNotIn(CANARY.encode(),raw);self.assertNotIn(b'PrivateModelException',raw)
 def test_14_close_failure_emits_no_stage_packet(self):
  stderr=Stderr()
  with patch.object(M.sys,'argv',['domain','close-entry','--request',str(self.root/'unused'),'--request-sha256','a'*64]),patch.object(M,'root_entry',side_effect=ValueError(CANARY)),patch.object(M.sys,'stderr',stderr):
   with self.assertRaises(SystemExit)as stop:M.main()
  self.assertEqual(stop.exception.code,2);self.assertEqual(stderr.buffer.getvalue(),b'')
 def test_15_failure_file_io_error_preserves_original_execute_gate_and_secret_erasure(self):
  session=self.session();values=self.values();raw=M.encoded(packet());actual=M.write
  def fail(path,value):
   if Path(path).name=='material-stage-failure.json':raise OSError(CANARY)
   return actual(path,value)
  with self.process(session,raw,7),patch.object(M,'write',side_effect=fail):
   with self.assertRaises(ValueError):session.stage(secrets=values)
  self.assertEqual(values,{});self.assertEqual(session.state,'HOLD_CLOSEONLY');self.assertFalse((self.control/'material-stage-failure.json').exists())
 def test_16_actual_stager_runner_sets_bounded_ordinal_without_retaining_private_streams(self):
  provider=S.OneShotSecrets(self.values());stderr=Stderr();seen=[]
  def stage(**kw):
   diagnostic=kw['_diagnostic'];S.diagnostic_phase(diagnostic,'PRIVATE_SEED')
   result=outcome(7);result.pop('output');owner=SimpleNamespace(prepare=lambda:None,supervise=lambda *a,**k:dict(result));executor=SimpleNamespace(checked_tool=lambda row:row['path']);runner=S.Runner(owner,self.root,time.monotonic()+100,executor,{'python3':dict(path='/usr/bin/python3')},diagnostic);runner.rows=[{'MODEL_prior_command':True}for _ in range(26)]
   def spawn(argv,**args):
    args['stdout'].write(CANARY.encode());args['stderr'].write(CANARY.encode());seen.append('MODELED_STAGER_SPAWN');return SimpleNamespace(pid=123)
   with patch.object(S.subprocess,'Popen',side_effect=spawn),patch.object(S.os,'waitid',return_value=object()):runner.run(['/usr/bin/python3',CANARY],15,env={'MODEL_SECRET':CANARY})
  with patch.object(S,'_stage_materials',side_effect=stage),patch.object(S.sys,'stderr',stderr):
   with self.assertRaises(ValueError):self.stage_call(provider)
  value=M.failure_packet(stderr.buffer.getvalue());self.assertEqual(value,packet('PRIVATE_SEED','COMMAND_FAILED',26));self.assertEqual(seen,['MODELED_STAGER_SPAWN']);self.assertNotIn(CANARY.encode(),stderr.buffer.getvalue());self.assertEqual(list(self.root.glob('command-*')),[])
 def test_17_successful_runner_resets_failure_ordinal_and_emits_no_packet(self):
  diagnostic=dict(phase='DOWNLOAD',reason='PHASE_FAILED',command_ordinal=None);good=outcome();good.pop('output');owner=SimpleNamespace(prepare=lambda:None,supervise=lambda *a,**k:dict(good));executor=SimpleNamespace(checked_tool=lambda row:row['path']);runner=S.Runner(owner,self.root,time.monotonic()+100,executor,{'python3':dict(path='/usr/bin/python3')},diagnostic);stderr=Stderr()
  with patch.object(S.subprocess,'Popen',return_value=SimpleNamespace(pid=123)),patch.object(S.os,'waitid',return_value=object()),patch.object(S.sys,'stderr',stderr):self.assertEqual(runner.run(['/usr/bin/python3','MODEL'],15),b'')
  self.assertEqual(diagnostic,dict(phase='DOWNLOAD',reason='PHASE_FAILED',command_ordinal=None));self.assertEqual(stderr.buffer.getvalue(),b'');self.assertEqual(len(runner.rows),1)
 def test_18_actual_child_cli_guard_emits_one_canonical_packet_without_private_text(self):
  guard=ast.parse(Path(S.__file__).read_bytes()).body[-1];self.assertIsInstance(guard,ast.If);namespace=dict(S.__dict__,__name__='__main__')
  def fail(*args,**kwargs):raise ValueError(CANARY)
  namespace['child_main']=fail;stderr=Stderr()
  with patch.object(S.sys,'argv',['stager','download','--request',str(self.root/'unused'),'--request-sha256','a'*64]),patch.object(S.sys,'stderr',stderr):
   with self.assertRaises(SystemExit)as stopped:exec(compile(ast.Module(body=[guard],type_ignores=[]),str(S.__file__)+':CLI-model','exec'),namespace)
  self.assertEqual(stopped.exception.code,2);raw=stderr.buffer.getvalue();self.assertEqual(M.failure_packet(raw),packet('CHILD','PHASE_FAILED',None));self.assertNotIn(CANARY.encode(),raw)
 def test_19_successful_stage_wrapper_and_domain_main_emit_no_failure_packet(self):
  provider=S.OneShotSecrets(self.values());stderr=Stderr();model=dict(status='MODEL_RETURN_ONLY_NOT_NATIVE_ACCEPTANCE')
  with patch.object(S,'_stage_materials',return_value=model),patch.object(S.sys,'stderr',stderr):self.assertIs(self.stage_call(provider),model)
  self.assertEqual(stderr.buffer.getvalue(),b'');self.assertIsNone(provider.values)
  with patch.object(M.sys,'argv',['domain','stage-entry','--request',str(self.root/'unused'),'--request-sha256','a'*64]),patch.object(M,'root_entry',return_value=None),patch.object(M.sys,'stderr',stderr):self.assertIsNone(M.main())
  self.assertEqual(stderr.buffer.getvalue(),b'')
 def test_20_immutable_executor_and_policies_still_unissued(self):
  self.assertEqual(M.pin(Path(E.__file__).read_bytes()),M.EXECUTOR_PIN);self.assertIsNone(M.PROPOSAL['Root_issuance']);self.assertIsNone(S.PROPOSAL['Root_acceptance']);self.assertEqual(M.PROPOSAL['scope_limits'],S.SCOPE)
 def test_21_no_actual_actor_was_attempted(self):self.assertEqual(ACTORS,[])

if __name__=='__main__':unittest.main(verbosity=2)

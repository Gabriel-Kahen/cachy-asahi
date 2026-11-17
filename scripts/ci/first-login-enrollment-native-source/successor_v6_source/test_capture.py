# SPDX-License-Identifier: MIT
"""MODEL child lifecycle, real reserved memfd/seals/offsets, no actor execution.

The subprocess and owned supervision boundary is inert. The actual material
session, fixed packet producer, reservation and public projection execute.
"""
import contextlib
import errno
import fcntl
import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('capture_controls_basis',HERE.parent/'test_source_failure_packet_v1.py')
B=importlib.util.module_from_spec(spec);spec.loader.exec_module(B)
M,E,S=B.M,B.E,B.S
spec=importlib.util.spec_from_file_location('capture_original_hosted_operand',HERE.parent/'successor_v7_source/main_route/legacy_input.py')
LEGACY=importlib.util.module_from_spec(spec);spec.loader.exec_module(LEGACY)
L=LEGACY.load_hosted('capture_hosted_projection')


class Controls(unittest.TestCase):
 setUp=B.Controls.setUp
 session=B.Controls.session
 values=B.Controls.values
 record=B.Controls.record
 safe_record=B.Controls.safe_record
 @contextlib.contextmanager
 def child(self,session,raw=b'',exit=2,stdout=b'',mutation=None,after=None,write_limit=None):
  events=[];held=[];read_written_span=os.pread
  def private(values,names):
   try:yield None
   finally:values.clear()
  def spawn(argv,**kw):
   stream=kw['stderr'];self.assertEqual(os.fstat(stream.fileno()).st_size,E.MAX_OUTPUT)
   self.assertEqual(stream.tell(),0);self.assertEqual(os.pread(stream.fileno(),8,0),b'\0'*8)
   # dup models the inherited descriptor's shared open-file description.
   writer=os.dup(stream.fileno());held.append(writer);events.append('MODEL_SPAWN')
   return SimpleNamespace(writer=writer,stream=stream)
  def supervise(child,**kw):
   self.assertEqual(kw['max_output'],65536);self.assertEqual(kw['retirement'],1)
   self.assertGreater(kw['cap'],0);self.assertLessEqual(kw['cap'],3603)
   submitted=raw if write_limit is None else raw[:write_limit]
   before=os.lseek(child.writer,0,os.SEEK_CUR);written=None;write_errno=None
   try:written=os.write(child.writer,submitted)
   except OSError as error:
    write_errno=error.errno;self.assertEqual(write_errno,errno.EPERM);events.append('BOUNDED_WRITE_REFUSED')
   offset=os.lseek(child.writer,0,os.SEEK_CUR)
   self.assertEqual(offset,os.lseek(child.stream.fileno(),0,os.SEEK_CUR));self.assertEqual(before,0)
   if write_errno is None:
    self.assertIs(type(written),int);self.assertTrue(0<=written<=len(submitted));self.assertEqual(offset,written)
   else:self.assertIsNone(written);self.assertEqual(offset,before)
   self.assertTrue(0<=offset<=E.MAX_OUTPUT)
   # Keep this MODEL observation separate from production pread fault injection.
   span=read_written_span(child.writer,offset,0);self.assertEqual(span,submitted[:offset])
   self.write_observation=dict(requested_bytes=len(raw),submitted_bytes=len(submitted),returned_count=written,
    errno=write_errno,writer_offset=offset,shared_offset=child.stream.tell(),written_pin=M.pin(span))
   events.append('MODEL_REAP_EMPTY_TWICE')
   row=B.outcome(exit,stdout)
   if mutation is not None:mutation(child,row)
   return row
  session.O=SimpleNamespace(prepare=lambda:events.append('PREPARE'),supervise=supervise)
  original=M.retired_stderr
  def capture(*args):
   self.assertEqual(events[-1],'MODEL_REAP_EMPTY_TWICE')
   result=original(*args);events.append('CAPTURE_FROZEN')
   if after is not None:after(held[0],result)
   return result
  try:
   with patch.object(M,'scope_path',return_value=SimpleNamespace(exists=lambda:False)),patch.object(M,'scope_tools',return_value=B.TOOLS),patch.object(M,'sealed_secret_input',side_effect=private),patch.object(M.subprocess,'Popen',side_effect=spawn),patch.object(M,'absent',side_effect=lambda nonce,deadline,closing=False:dict(scope=M.scope_name(nonce,closing),absent_twice=True)),patch.object(M,'retired_stderr',side_effect=capture):yield events
  finally:
   for fd in held:os.close(fd)
 def test_empty_close_reads_zero_bytes_from_real_one_mib_reservation(self):
  session=self.session()
  with self.child(session,exit=0)as events:row=session.execute(closing=True)
  self.assertTrue(row['natural']);self.assertEqual(row['stderr_pin'],M.pin(b''));self.assertEqual(row['output_pin'],M.pin(b''))
  self.assertEqual(events,['PREPARE','MODEL_SPAWN','MODEL_REAP_EMPTY_TWICE','CAPTURE_FROZEN'])
  self.assertFalse((self.control/'material-stage-failure.json').exists())
 def test_fixed_packet_retained_before_success_exit_gate_and_public_projection(self):
  diagnostic=dict(phase='PRIVATE_SEED',reason='COMMAND_FAILED',command_ordinal=26)
  raw=S.failure_packet(diagnostic);session=self.session();values=self.values()
  with self.child(session,raw,stdout=b'PRIVATE OUTPUT'):
   with self.assertRaises(ValueError):session.stage(secrets=values)
  self.assertEqual(session.state,'HOLD_CLOSEONLY');self.assertEqual(values,{})
  value=self.record();self.safe_record(value,'AVAILABLE');self.assertEqual(value['packet'],B.packet('PRIVATE_SEED','COMMAND_FAILED',26))
  row=session.receipts[0];self.assertEqual(row['stderr_pin'],M.pin(raw));self.assertEqual(row['output_pin'],M.pin(b'PRIVATE OUTPUT'))
  self.assertEqual(row['supervision']['exit'],2);self.assertFalse(row['natural'])
  (self.control/'private').mkdir();M.write(self.control/'private/context.json',self.r['context'])
  plan=SimpleNamespace(control=self.control,material_session=session)
  projected=L.material_stage_failure(plan);self.assertEqual(projected['availability'],'AVAILABLE')
  self.assertEqual(projected['stderr_pin'],M.pin(raw));self.assertNotIn(b'PRIVATE OUTPUT',M.encoded(projected));self.assertNotIn(B.CANARY.encode(),M.encoded(projected))
 def test_short_malformed_truncated_extra_zero_and_oversize_packets_are_unavailable(self):
  good=S.failure_packet(dict(phase='TOOLS',reason='PHASE_FAILED',command_ordinal=None))
  (self.control/'private').mkdir();M.write(self.control/'private/context.json',self.r['context'])
  cases=[(raw,None)for raw in(b'',b'x',good[:-1],good+b'\0',good+b'\n',b'{',b'\xff',b'x'*1025,b'x'*E.MAX_OUTPUT,b'x'*(E.MAX_OUTPUT+1))]
  # Deterministic short-write MODEL: submit a real capacity-sized prefix of a
  # larger logical body. This does not claim the hosted syscall returned short.
  cases.append((b'x'*(E.MAX_OUTPUT+1),E.MAX_OUTPUT))
  for raw,write_limit in cases:
   with self.subTest(length=len(raw),write_limit=write_limit):
    session=self.session();values=self.values()
    def growth_refusal(child,row):
     self.assertEqual(self.write_observation['returned_count'],E.MAX_OUTPUT)
     self.assertEqual(self.write_observation['shared_offset'],E.MAX_OUTPUT)
     with self.assertRaises(OSError)as denied:os.write(child.writer,b'x')
     self.assertEqual(denied.exception.errno,errno.EPERM)
     self.assertEqual(os.lseek(child.writer,0,os.SEEK_CUR),E.MAX_OUTPUT)
    with self.child(session,raw,write_limit=write_limit,mutation=growth_refusal if write_limit is not None else None):
     with self.assertRaises(ValueError):session.stage(secrets=values)
    record=self.record();self.safe_record(record,'UNAVAILABLE');self.assertIsNone(record['packet'])
    observation=self.write_observation
    expected_pin=observation['written_pin']if observation['shared_offset']<E.MAX_OUTPUT else None
    self.assertEqual(record['stderr_pin'],expected_pin)
    self.assertEqual(session.receipts[0].get('stderr_pin'),expected_pin)
    self.assertEqual(session.state,'HOLD_CLOSEONLY');self.assertEqual(values,{})
    self.assertEqual(session.receipts[0]['supervision']['exit'],2);self.assertFalse(session.receipts[0]['natural'])
    projected=L.material_stage_failure(SimpleNamespace(control=self.control,material_session=session))
    self.assertEqual(projected['availability'],'UNAVAILABLE');self.assertIsNone(projected['packet'])
    self.assertEqual(projected['stderr_pin'],expected_pin)
    session.request.unlink();(self.control/'material-stage-failure.json').unlink()
 def test_zero_suffix_is_payload_and_never_stripped_to_fabricate_packet(self):
  raw=S.failure_packet(dict(phase='ENTRY',reason='PHASE_FAILED',command_ordinal=None))+b'\0'*17
  session=self.session()
  with self.child(session,raw):
   with self.assertRaises(ValueError):session.stage(secrets=self.values())
  self.safe_record(self.record(),'UNAVAILABLE');self.assertEqual(session.receipts[0]['stderr_pin'],M.pin(raw))
 def test_post_retirement_write_is_refused_and_pin_stays_whole(self):
  raw=S.failure_packet(dict(phase='SOURCE',reason='PHASE_FAILED',command_ordinal=None));session=self.session()
  def after(fd,body):
   self.assertEqual(body,raw)
   with self.assertRaises(OSError)as denied:os.write(fd,b'PRIVATE LATE WRITE')
   self.assertEqual(denied.exception.errno,errno.EPERM)
   self.assertEqual(fcntl.fcntl(fd,fcntl.F_GET_SEALS)&fcntl.F_SEAL_WRITE,fcntl.F_SEAL_WRITE)
  with self.child(session,raw,after=after):
   with self.assertRaises(ValueError):session.stage(secrets=self.values())
  self.safe_record(self.record(),'AVAILABLE');self.assertEqual(self.record()['stderr_pin'],M.pin(raw))
 def test_descriptor_replacement_refuses_even_same_capacity_and_packet(self):
  raw=S.failure_packet(dict(phase='SCOPE',reason='PHASE_FAILED',command_ordinal=None));session=self.session()
  def replace(child,row):
   with E.stderr_buffer()as other:
    os.write(other.fileno(),raw);os.dup2(other.fileno(),child.stream.fileno())
  with self.child(session,raw,mutation=replace):
   with self.assertRaises(ValueError):session.stage(secrets=self.values())
  self.safe_record(self.record(),'UNAVAILABLE');self.assertIsNone(self.record()['stderr_pin'])
 def test_short_pread_and_uncertain_retirement_refuse_without_packet(self):
  raw=S.failure_packet(dict(phase='STORAGE',reason='PHASE_FAILED',command_ordinal=None))
  cases=[('short',None),('group',lambda child,row:row.update(group_census='UNKNOWN')),('reap',lambda child,row:row.update(reaped=False)),('ownership',lambda child,row:row.update(ownership='UNKNOWN')),('timeout',lambda child,row:row.update(timeout=True)),('signals',lambda child,row:row.update(signals=[15])),('error',lambda child,row:row.update(error='PRIVATE')),('output',lambda child,row:row.update(output_complete=False))]
  original=os.pread
  for name,mutation in cases:
   with self.subTest(case=name):
    session=self.session()
    def pread(fd,count,offset):return original(fd,max(0,count-1),offset)if name=='short'and count==len(raw)else original(fd,count,offset)
    with self.child(session,raw,mutation=mutation),patch.object(M.os,'pread',side_effect=pread):
     with self.assertRaises(ValueError):session.stage(secrets=self.values())
    self.safe_record(self.record(),'UNAVAILABLE');self.assertIsNone(self.record()['stderr_pin']);self.assertEqual(session.receipts[0]['supervision']['exit'],2)
    session.request.unlink();(self.control/'material-stage-failure.json').unlink()
 def test_no_actual_actor_attempted(self):self.assertEqual(B.ACTORS,[])


if __name__=='__main__':unittest.main(verbosity=2)

#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Pure MODEL metadata controls; no selected filesystem path is accessed."""
import builtins
import copy
from datetime import datetime,timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('no_package_metadata_MODEL',HERE/'metadata.py')
M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)
NONCE='a'*32
ATIME=b'2026-11-16 10:20:30.123456789 +0000'
MTIME=b'2026-11-16 10:21:31.987654321 +0000'


def fence(event,args):
 if event.startswith(('subprocess.','socket.','ctypes.','os.exec','os.fork','os.posix_spawn'))or event in('os.system','fcntl.flock'):
  raise AssertionError('metadata MODEL actor fence: '+event)
sys.addaudithook(fence)


class Poison:
 def touched(self,*args,**kwargs):raise AssertionError('PRIVATE_UNSELECTED_VALUE_WAS_ACCESSED')
 __str__=__repr__=__bool__=__iter__=__getattr__=touched


def row(index=0):
 seconds=(datetime(2026,11,16,10,20,30,tzinfo=timezone.utc)-datetime(1970,1,1,tzinfo=timezone.utc)).days*86400+10*3600+20*60+30
 return dict(type='directory',mode=0o700 if index==0 else 0o755,uid=0,gid=0,inode=16+index,
             links=2+index,size=4096,atime=seconds,atime_ns=123456789,mtime=seconds+61,mtime_ns=987654321)


def scan():return dict(observed_paths=list(M.PATHS),nodes={path:row(i)for i,path in enumerate(M.PATHS)})


def projection():return M.project_scan(scan())


def frame(*,stage='after_login',nonce=NONCE,missing=(),rows=None):
 if rows is None:
  rows=[]
  for index,path in enumerate(M.PATHS):
   if path in missing:rows.append(path.encode()+b'|ABSENT');continue
   r=row(index)
   values=(path,str(r['inode']),str(r['links']),format(r['mode'],'o'),str(r['uid']),str(r['gid']),str(r['size']))
   rows.append('|'.join(values).encode()+b'|'+ATIME+b'|'+MTIME)
 binding=(nonce+' '+stage).encode()
 return M.BEGIN+binding+b'\n'+b'\n'.join(rows)+b'\n'+M.END+binding+b'\n'


def phases():
 p=projection();return {stage:copy.deepcopy(p)for stage in M.PHASES}


class Controls(unittest.TestCase):
 def test_fixed_fifteen_public_rows_and_explicit_absence(self):
  value=scan();del value['nodes']['var/cache/ldconfig'];observed=M.project_scan(value)
  self.assertEqual(tuple(observed),M.PATHS)
  self.assertEqual(len(observed),15);self.assertIsNone(observed['var/cache/ldconfig'])
  self.assertEqual(tuple(observed['root']),M.FIELDS)
  self.assertEqual(observed['etc'],row(1))
 def test_partial_unobserved_duplicate_unknown_or_reordered_coverage_refuses(self):
  partial=dict(nodes={path:row(i)for i,path in enumerate(M.PATHS[:10])})
  with self.assertRaisesRegex(ValueError,'complete fixed public metadata lookup coverage'):M.project_scan(partial)
  wrong=(None,tuple(M.PATHS),list(M.PATHS[:10]),list(M.PATHS)+['PRIVATE_PATH'],
         [M.PATHS[1],M.PATHS[0],*M.PATHS[2:]],list(M.PATHS[:-1])+[M.PATHS[0]],
         list(M.PATHS[:-1])+['PRIVATE_PATH'],list(M.PATHS[:-1])+[Poison()])
  for coverage in wrong:
   value=scan();value['observed_paths']=coverage
   with self.assertRaises(ValueError)as caught:M.project_scan(value)
   self.assertNotIn('PRIVATE',str(caught.exception))
  # Coverage is scope, not authenticity: the Root caller must bind its actual
  # independently observed fifteen lookups. No omitted path becomes unobserved.
  complete=scan();complete['nodes']={}
  self.assertEqual(M.project_scan(complete),dict.fromkeys(M.PATHS))
 def test_unknown_nodes_top_level_data_and_private_row_values_are_never_accessed(self):
  value=scan();value['nodes']['PRIVATE_UNSELECTED_NODE']=Poison();value['PRIVATE_RECORDS']=Poison()
  for public in M.PATHS:
   value['nodes'][public].update(sha256=Poison(),xattrs=Poison(),body=Poison(),crtime=Poison(),symlink_target=Poison())
  self.assertEqual(M.project_scan(value),projection())
  self.assertNotIn('PRIVATE',json.dumps(M.project_scan(value)))
 def test_nonordinary_selected_nodes_refuse_without_private_value_access(self):
  for kind in('file','symlink','fifo',None,Poison()):
   value=scan();value['nodes']['root'].update(type=kind,body=Poison(),xattrs=Poison())
   with self.assertRaises(ValueError)as caught:M.project_scan(value)
   self.assertNotIn('PRIVATE',str(caught.exception))
 def test_selected_private_values_wrong_integer_types_and_missing_fields_refuse(self):
  for field in M.FIELDS[1:]:
   for wrong in(None,True,'PRIVATE_VALUE',1.5,Poison()):
    value=scan();value['nodes']['root'][field]=wrong
    with self.subTest(field=field),self.assertRaises(ValueError)as caught:M.project_scan(value)
    self.assertNotIn('PRIVATE',str(caught.exception))
   value=scan();del value['nodes']['root'][field]
   with self.assertRaises(ValueError):M.project_scan(value)
 def test_integer_bounds_are_exact_and_no_float_rounding_occurs(self):
  for field,(low,high)in M.BOUNDS.items():
   for edge in(low,high):
    value=scan();value['nodes']['root'][field]=edge
    self.assertEqual(M.project_scan(value)['root'][field],edge)
   for outside in(low-1,high+1,10**100):
    value=scan();value['nodes']['root'][field]=outside
    with self.subTest(field=field,outside=outside),self.assertRaises(ValueError):M.project_scan(value)
 def test_scan_schema_refuses_without_exporting_raw_values(self):
  for value in(None,[],{}):
   with self.assertRaises(ValueError):M.project_scan(value)
  for nodes in(None,[],{'root':None},{'root':[]}):
   value=scan();value['nodes']=nodes
   with self.assertRaises(ValueError):M.project_scan(value)
 def test_valid_probe_stage_nonce_order_and_nanoseconds_join_projection(self):
  for stage in M.GUEST_PHASES:
   observed=M.parse_frame(frame(stage=stage),NONCE,stage)
   self.assertEqual(observed,projection())
   self.assertEqual(observed['root']['atime_ns'],123456789)
   self.assertEqual(observed['root']['mtime_ns'],987654321)
  value=M.parse_frame(frame(missing=('var/cache/ldconfig','var/log')),NONCE,'after_login')
  self.assertIsNone(value['var/cache/ldconfig']);self.assertIsNone(value['var/log'])
 def test_selected_crlf_transport_and_outside_private_bytes_are_not_exported(self):
  raw=b'\xffPRIVATE_PREFIX\r\n'+frame().replace(b'\n',b'\r\n')+b'PRIVATE_SUFFIX\xff'
  observed=M.parse_frame(raw,NONCE,'after_login')
  self.assertEqual(observed,projection());self.assertNotIn('PRIVATE',json.dumps(observed))
 def test_replay_cumulative_stage_nonce_and_missing_terminator_refusals(self):
  cases=(frame()+frame(),frame()+frame(stage='before_logout'),frame(nonce='b'*32),
         frame(stage='before_logout'),frame()[:-1],frame().replace(M.END,b'OTHER_END '),b'x'+frame())
  for value in cases:
   with self.assertRaises(ValueError):M.parse_frame(value,NONCE,'after_login')
  for nonce,stage in(('A'*32,'after_login'),(NONCE,'offline_before'),(None,'after_login'),(NONCE,Poison())):
   with self.assertRaises(ValueError):M.parse_frame(frame(),nonce,stage)
 def test_serial_bound_and_bytes_type_refusals(self):
  raw=frame();prefix=b'X'*(M.SERIAL_CAP-len(raw)-1)+b'\n'
  self.assertEqual(M.parse_frame(prefix+raw,NONCE,'after_login'),projection())
  for value in(prefix+b'X'+raw,b'',raw.decode(),bytearray(raw),None):
   with self.assertRaises(ValueError):M.parse_frame(value,NONCE,'after_login')
 def test_missing_duplicate_unknown_or_out_of_order_public_rows_refuse(self):
  lines=frame().split(b'\n');rows=lines[1:-2]
  cases=(rows[:-1],rows+[rows[-1]],rows[1:2]+rows[0:1]+rows[2:],
         [b'PRIVATE_UNKNOWN_PATH|PRIVATE_BODY']+rows[1:],rows[:1]+[rows[0]]+rows[2:])
  for selected in cases:
   with self.assertRaises(ValueError)as caught:M.parse_frame(frame(rows=selected),NONCE,'after_login')
   self.assertNotIn('PRIVATE',str(caught.exception))
 def test_canonical_decimal_permission_field_and_arity_refusals(self):
  first=frame().split(b'\n')[1];fields=first.split(b'|')
  for index,wrong in((1,b'016'),(1,b'-1'),(1,b'0'),(1,b'9'*21),(2,b'0'),(3,b'0755'),(3,b'888'),
                    (3,b'17777'),(4,b'+0'),(5,b'00'),(6,b'1.0'),(6,b'9'*20)):
   altered=list(fields);altered[index]=wrong
   raw=frame().replace(first,b'|'.join(altered),1)
   with self.subTest(index=index,wrong=wrong),self.assertRaises(ValueError):M.parse_frame(raw,NONCE,'after_login')
  for suffix in(b'|PRIVATE_EXTRA',b'\x00'):
   with self.assertRaises(ValueError):M.parse_frame(frame().replace(first,first+suffix,1),NONCE,'after_login')
 def test_timestamp_calendar_timezone_precision_and_internal_cr_refusals(self):
  cases=(b'2026-02-30 10:20:30.123456789 +0000',b'2026-11-16 24:20:30.123456789 +0000',
         b'2026-11-16 10:20:60.123456789 +0000',b'2026-11-16 10:20:30.123456789 -0500',
         b'2026-11-16 10:20:30.12345678 +0000',b'9999-11-16 10:20:30.123456789 +0000',
         b'2026-11-16\r10:20:30.123456789 +0000')
  for wrong in cases:
   with self.assertRaises(ValueError):M.parse_frame(frame().replace(ATIME,wrong),NONCE,'after_login')
 def test_comparison_reports_each_field_and_presence_without_acceptance(self):
  value=phases();value['after_login']['root']['links']+=1
  value['before_logout']['root']['links']+=1;value['before_logout']['etc']['mtime_ns']+=1
  value['offline_after']['var/cache/ldconfig']=None
  observed=M.compare_phases(value)
  self.assertEqual(observed['transitions'][0]['changes'],[dict(path='root',fields={'links':dict(before=2,after=3)})])
  self.assertEqual(observed['transitions'][1]['changes'],[dict(path='etc',fields={'mtime_ns':dict(before=987654321,after=987654322)})])
  endpoint=observed['endpoint']['changes'];self.assertEqual(len(endpoint),1)
  self.assertEqual(endpoint[0]['path'],'var/cache/ldconfig')
  self.assertEqual(endpoint[0]['fields']['present'],dict(before=True,after=False))
  for field in M.FIELDS:self.assertEqual(endpoint[0]['fields'][field]['after'],None)
  for field in('Root_acceptance','VM_acceptance','waiver','restoration'):self.assertIsNone(observed[field])
 def test_observed_atime_change_is_reported_without_restoration_or_waiver(self):
  value=phases();value['after_login']['etc']['atime_ns']+=1
  observed=M.compare_phases(value)
  self.assertEqual(observed['transitions'][0]['changes'],[dict(path='etc',fields={'atime_ns':dict(before=123456789,after=123456790)})])
  self.assertEqual(observed['atime_policy'],'OBSERVED_ONLY_NO_RESTORATION')
  self.assertIsNone(observed['waiver']);self.assertIsNone(observed['restoration'])
 def test_comparison_strict_phase_and_projection_membership(self):
  for changed in('missing-stage','extra-stage','missing-path','extra-path','bad-row'):
   value=phases()
   if changed=='missing-stage':del value['offline_before']
   elif changed=='extra-stage':value['PRIVATE_STAGE']=Poison()
   elif changed=='missing-path':del value['after_login']['root']
   elif changed=='extra-path':value['after_login']['PRIVATE_PATH']=Poison()
   else:value['after_login']['root']['inode']=Poison()
   with self.subTest(changed=changed),self.assertRaises(ValueError)as caught:M.compare_phases(value)
   self.assertNotIn('PRIVATE',str(caught.exception))
 def test_pure_model_functions_never_open_files_directories_or_processes(self):
  value=scan();raw=frame();selected=phases()
  def forbid(*args,**kwargs):raise AssertionError('metadata MODEL attempted resource access')
  with patch.object(builtins,'open',forbid),patch.object(os,'open',forbid),patch.object(os,'scandir',forbid),patch.object(os,'listdir',forbid),patch.object(os,'stat',forbid),patch.object(os,'lstat',forbid),patch.object(os,'readlink',forbid),patch.object(os,'access',forbid):
   self.assertEqual(M.project_scan(value),projection())
   self.assertEqual(M.parse_frame(raw,NONCE,'after_login'),projection())
   self.assertEqual(M.compare_phases(selected)['endpoint']['changes'],[])


if __name__=='__main__':unittest.main(verbosity=2)

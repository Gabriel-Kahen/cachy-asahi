#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Independent observational-timing DATA controls; no Source execution."""
import ast
import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


def fence(event,args):
 if event.startswith(('subprocess.','socket.','ctypes.'))or event in('os.system','os.exec','os.fork','os.posix_spawn','fcntl.flock','resource.setrlimit'):
  raise AssertionError('Reader17 timing controls forbid actor/network/authority: '+event)

sys.addaudithook(fence)
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('reader17_timing',HERE/'reader.py');R=importlib.util.module_from_spec(spec);spec.loader.exec_module(R);S=R.S
ACTUAL_PIN=dict(bytes=28759,sha256='466401585d11e3e74b5ba41c20131f23d65da42108ec374916cb933364412d8f')


def model():
 # MODEL manifest envelope carrying only observed values; never represented as actual manifest.
 actual=S.decode((HERE/'fixtures/source364-manifest-failure.ACTUAL.json').read_bytes())
 return dict(schema=4,source=dict(run='MODEL',job='MODEL'),files={'image.tar':dict(bytes=1,mode=292,sha256='a'*64)},metadata=dict(boot=dict(normal_phase_deadline=actual['actual_normal_image_report_shape']['normal_phase_deadline']['observed_value']),qual=dict(probe_receipts=[dict(lifecycle=copy.deepcopy(row['lifecycle']),returncode=0)for row in actual['probes']]),delivered={}),native_acceptance=False)


def put(value,path,item):
 for key in path[:-1]:
  if type(value)is dict and key not in value:value[key]={}
  value=value[key]
 value[path[-1]]=item


class TimingControls(unittest.TestCase):
 def refuses(self,value,reason='MANIFEST_|NONFINITE_JSON|DUPLICATE_JSON_KEY'):
  with self.assertRaisesRegex(S.Hold,reason):S.manifest_decode(value if type(value)is bytes else S.canonical(value))
 def test_actual_projection_pin_and_partial_negative_are_preserved(self):
  raw=(HERE/'fixtures/source364-manifest-failure.ACTUAL.json').read_bytes();self.assertEqual(S.pin(raw),ACTUAL_PIN);v=S.decode(raw)
  self.assertEqual(v['source'],'3c3e63aae8cc330159197dcd213035c946fdb8ac');self.assertEqual(v['run'],43983488320)
  self.assertEqual((v['bootstrap'],v['build']),('SUCCESS','FAIL'));self.assertEqual(v['build_error'],'ValueError: noninteger/nonfinite transfer JSON')
  self.assertFalse(v['actual_manifest_retained']);self.assertFalse(v['Docker_load_or_create_invoked']);self.assertFalse(v['Root_large_artifact_GET'])
  self.assertEqual(len(v['probes']),9)
  for row,expected in zip(v['probes'],R.E.PROBES):self.assertEqual(row['argv'],expected);R.E.natural(row['lifecycle'])
  self.assertEqual(v['workspace_retirement']['status'],'RETIRED_ABSENT');self.assertEqual(v['image_retirement']['status'],'PASS_RETIRED');self.assertEqual(len(v['image_retirement']['images']),2)
  self.assertEqual(v['full_Rust_build'],'NOT_RUN');self.assertFalse(v['release_acceptance']);self.assertIn('Source-backed inference:',v['cause_evidence'])
  self.assertEqual([r['status']for r in v['phase_requests']],[200,200,200,302,200]);self.assertEqual(v['phase_requests'][-1]['bytes'],7978638630)
 def test_all_observed_floats_roundtrip_unchanged_without_normalization(self):
  value=model();raw=S.canonical(value);decoded=S.manifest_decode(raw);self.assertEqual(decoded,value);self.assertEqual(S.canonical(decoded),raw)
  self.assertTrue(all(type(row['lifecycle']['elapsed_seconds'])is float for row in decoded['metadata']['qual']['probe_receipts']))
 def test_independent_actual_type_shapes_have_only_source_backed_float_paths(self):
  v=S.decode((HERE/'fixtures/source364-manifest-failure.ACTUAL.json').read_bytes());found={}
  def walk(item,path):
   if type(item)is dict:
    if item.get('type')=='float':found[path]=item['observed_value']
    else:
     for key,child in item.items():walk(child,path+(key,))
   elif type(item)is list:
    for index,child in enumerate(item):walk(child,path+(index,))
  walk(v['actual_normal_image_report_shape'],('metadata','boot'));walk(v['actual_qualification_result_shape'],('metadata','qual'))
  self.assertEqual(len(found),10)
  for path,number in found.items():
   value=model();put(value,path,number);self.assertEqual(S.manifest_decode(S.canonical(value)),value)
  projected={tuple(int(part)if part.isdecimal()else part for part in row['path'].split('/')[1:]):row['value']for row in v['actual_qualification_float_fields']}
  self.assertEqual({p:n for p,n in found.items()if p[:2]==('metadata','qual')},projected)
 def test_every_authority_schema_cap_and_pin_float_refuses(self):
  paths=[('schema',),('native_acceptance',),('source','run'),('source','job'),('files','image.tar','bytes'),('files','image.tar','mode'),('metadata','qual','schema'),('metadata','qual','binding','job'),('metadata','qual','readonly_stage0','attempts'),('metadata','qual','probe_receipts',0,'returncode'),('metadata','qual','probe_receipts',0,'lifecycle','pid'),('metadata','qual','probe_receipts',0,'lifecycle','exit'),('metadata','qual','probe_receipts',0,'lifecycle','natural_exit'),('metadata','boot','resources'),('metadata','boot','extraction','files'),('metadata','boot','extraction','logical_bytes')]
  for path in paths:
   value=model();put(value,path,1.0)
   with self.subTest(path=path):self.refuses(value,'MANIFEST_FLOAT_OUTSIDE')
 def test_name_only_and_wrong_parent_timing_bypasses_refuse(self):
  paths=[('elapsed_seconds',),('metadata','elapsed_seconds'),('metadata','boot','elapsed_seconds'),('metadata','qual','elapsed_seconds'),('metadata','delivered','normal_phase_deadline'),('metadata','qual','probe_receipts',0,'elapsed_seconds'),('metadata','qual','probe_receipts',0,'lifecycle','normal_phase_deadline')]
  for path in paths:
   value=model();put(value,path,0.5)
   with self.subTest(path=path):self.refuses(value,'MANIFEST_FLOAT_OUTSIDE')
 def test_tenth_receipt_and_string_index_are_not_probe_observations(self):
  value=model();value['metadata']['qual']['probe_receipts'].append(dict(lifecycle=dict(elapsed_seconds=0.5)));self.refuses(value,'MANIFEST_FLOAT_OUTSIDE')
  value=model();value['metadata']['qual']['probe_receipts']={'0':dict(lifecycle=dict(elapsed_seconds=0.5))};self.refuses(value,'MANIFEST_FLOAT_OUTSIDE')
 def test_nonfinite_tokens_and_overflow_refuse_everywhere(self):
  for token in ('NaN','Infinity','-Infinity','1e999','-1e999'):
   for raw in (b'{"schema":'+token.encode()+b'}',b'{"metadata":{"boot":{"normal_phase_deadline":'+token.encode()+b'}}}',b'{"metadata":{"qual":{"probe_receipts":[{"lifecycle":{"elapsed_seconds":'+token.encode()+b'}}]}}}'):
    with self.subTest(token=token,raw=raw):self.refuses(raw)
 def test_negative_and_boolean_string_null_observations_refuse(self):
  for number in (-0.5,-1,True,False,'0.25',None,[],{}):
   for path in (('metadata','boot','normal_phase_deadline'),('metadata','qual','probe_receipts',0,'lifecycle','elapsed_seconds')):
    value=model();put(value,path,number)
    with self.subTest(path=path,number=number):self.refuses(value,'MANIFEST_FINITE_NONNEGATIVE')
 def test_zero_and_integer_observations_remain_valid(self):
  for number in (0,0.0,1,1.5):
   value=model();value['metadata']['boot']['normal_phase_deadline']=number
   for row in value['metadata']['qual']['probe_receipts']:row['lifecycle']['elapsed_seconds']=number
   self.assertEqual(S.manifest_decode(S.canonical(value)),value)
 def test_duplicates_at_root_and_observed_timing_refuse(self):
  for raw in (b'{"schema":4,"schema":4}',b'{"metadata":{"boot":{"normal_phase_deadline":0.5,"normal_phase_deadline":0.5}}}',b'{"metadata":{"qual":{"probe_receipts":[{"lifecycle":{"elapsed_seconds":0.5,"elapsed_seconds":0.5}}]}}}'):
   self.refuses(raw,'DUPLICATE_JSON_KEY')
 def test_body_bound_and_object_kind_refuse(self):
  for raw in (b'',b'[]',b'1',b'null',b'{}'+b' '*4*S.MIB):self.refuses(raw)
 def test_reader_only_manifest_role_routes_through_new_gate(self):
  tree=ast.parse((HERE/'reader.py').read_text());calls=[n for n in ast.walk(tree)if isinstance(n,ast.Call)and isinstance(n.func,ast.Attribute)and n.func.attr=='manifest_decode']
  self.assertEqual(len(calls),1);self.assertEqual(ast.unparse(calls[0]),'S.manifest_decode(manifest_raw)')
 def test_actual_bootstrap_pass_cannot_hide_build_phase_failure(self):
  value=dict(phase='build',schema=4,dispatch_sha256='a'*64,native_acceptance=False,holds_preserved=True,status='FAIL',error='ValueError: noninteger/nonfinite transfer JSON')
  with self.assertRaisesRegex(S.Hold,'PHASE_HOSTED_REPORT'):R.phase_completion(value,'build','a'*64)
  value.pop('error')
  with self.assertRaisesRegex(S.Hold,'PHASE_COMPLETION_STATUS'):R.phase_completion(value,'build','a'*64)
 def test_no_source_or_authority_execution_during_manifest_admission(self):
  value=model()
  with patch('builtins.exec',side_effect=AssertionError('Source execution forbidden')):self.assertEqual(S.manifest_decode(S.canonical(value)),value)


if __name__=='__main__':unittest.main()

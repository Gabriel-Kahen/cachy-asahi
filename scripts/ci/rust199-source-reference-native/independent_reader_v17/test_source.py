#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Independent Source17 audit and complete Source364 inverse; no Source execution."""
import argparse
import ast
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


def fence(event,args):
 if event.startswith(('subprocess.','socket.','ctypes.'))or event in('os.system','os.exec','os.fork','os.posix_spawn','fcntl.flock','resource.setrlimit'):
  raise AssertionError('Reader17 source controls forbid actor/network/authority: '+event)

sys.addaudithook(fence)
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('reader17_source_data',HERE/'storage.py');S=importlib.util.module_from_spec(spec);spec.loader.exec_module(S)


class SourceControls(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.files={n:(S.read(SOURCE_ROOT/n,64*S.MIB),0o644)for n in S.namespace(SOURCE_ROOT,367)}
  cls.args=[cls.files[n][0]for n in('hosted/phase_transfer.py','previous-v16/hosted/phase_transfer.py','hosted/bootstrap.py','actor/qualify.py','helpers/owned_child.py')]
 def audit(self,current):return S.manifest_source(current,*self.args[1:])
 def test_exact_new_source_profile_and_complete_all_ancestor_inverses(self):
  profile=(HERE/'source-profile.DATA.json').read_bytes();files=S.source(SOURCE_ROOT,profile,S.SOURCE)
  self.assertEqual(S.git_tree(files),S.SOURCE['tree']);self.assertEqual(len(files),367);self.assertEqual(S.source_inverse(files),S.PARENT364)
 def test_observational_emitter_audit_never_executes_source(self):
  with patch('builtins.exec',side_effect=AssertionError('Source execution forbidden')):proof=S.manifest_source(*self.args)
  self.assertFalse(proof['Source_executed']);self.assertTrue(proof['strict_decoder_preserved']);self.assertTrue(proof['all_other_source_AST_preserved'])
 def test_source_gate_is_mandatory_before_data_acceptance(self):
  with patch.object(S,'manifest_source',side_effect=S.Hold('MODEL_REQUIRED_TIMING_SOURCE_GATE')):
   with self.assertRaisesRegex(S.Hold,'MODEL_REQUIRED_TIMING_SOURCE_GATE'):S.source(SOURCE_ROOT,(HERE/'source-profile.DATA.json').read_bytes(),S.SOURCE)
 def test_unbounded_or_untyped_float_path_mutants_refuse(self):
  text=self.args[0].decode();changes=[("path==('metadata','boot','normal_phase_deadline')","True "),("path[:3]==('metadata','qual','probe_receipts')","True "),('type(path[3])is int','True'),('0<=path[3]<9','0<=path[3]<=9'),("path[4:]==('lifecycle','elapsed_seconds')","True"),('type(item)in(int,float)and item>=0','True'),('need(timing,','need(True,'),('math.isfinite(value)','True')]
  for old,new in changes:
   self.assertIn(old,text)
   with self.subTest(mutation=old),self.assertRaisesRegex(S.Hold,'TIMING_MANIFEST_|TIMING_LITERAL_'):self.audit(text.split('def decode_manifest(raw):')[0].encode()+b'def decode_manifest(raw):'+text.split('def decode_manifest(raw):')[1].replace(old,new,1).encode())
 def test_duplicate_nonfinite_parse_and_recursive_bypasses_refuse(self):
  text=self.args[0].decode();changes=[("need(k not in out,'duplicate transfer manifest JSON key')","need(True,'duplicate transfer manifest JSON key')"),('parse_constant=invalid','parse_constant=float'),('parse_float=observed','parse_float=float'),('object_pairs_hook=pairs','object_hook=dict'),('visit(value);return value','return value'),("'finite observed transfer timing'","side_effect()"),('visit(child,path+(key,))','visit(child,path)'),('visit(child,path+(index,))','visit(child,path)'),("need(type(value)is dict,'transfer manifest JSON object')","need(True,'transfer manifest JSON object')")]
  for old,new in changes:
   self.assertIn(old,text)
   with self.subTest(mutation=old),self.assertRaisesRegex(S.Hold,'TIMING_MANIFEST_|TIMING_LITERAL_'):self.audit(text.split('def decode_manifest(raw):')[0].encode()+b'def decode_manifest(raw):'+text.split('def decode_manifest(raw):')[1].replace(old,new,1).encode())
 def test_strict_api_policy_caps_authority_and_load_order_mutants_refuse(self):
  text=self.args[0].decode();changes=[('parse_float=invalid','parse_float=float'),('IMAGE_CAP=12*GIB','IMAGE_CAP=13*GIB'),('REQUEST_CAP=7','REQUEST_CAP=8'),("provider_check(dispatch,provider,'build')","provider_check(dispatch,provider,'bootstrap')"),('manifest=decode_manifest(raw_manifest)','manifest=decode(raw_manifest)'),('manifest=decode_manifest(raw_manifest)','manifest=json.loads(raw_manifest)'),('\n image_binding(manifest,authorization)\n',"\n need(True,'MODEL bypass')\n"),("need(type(manifest['schema'])is int","need(True"),('cap=ARTIFACT_CAP,redirects=3','cap=ARTIFACT_CAP,redirects=4')]
  for old,new in changes:
   self.assertIn(old,text)
   with self.subTest(mutation=old),self.assertRaisesRegex(S.Hold,'TIMING_'):self.audit(text.replace(old,new,1).encode())
 def test_daemon_or_api_cannot_call_manifest_decoder(self):
  text=self.args[0].decode()
  for old,new in (("artifact=decode(raw(out/'artifact.json'))","artifact=decode_manifest(raw(out/'artifact.json'))"),("job=decode(raw(out/'bootstrap-job.json'))","job=decode_manifest(raw(out/'bootstrap-job.json'))"),("run=decode(raw(out/'workflow-run.json'))","run=decode_manifest(raw(out/'workflow-run.json'))")):
   self.assertIn(old,text)
   with self.assertRaisesRegex(S.Hold,'TIMING_ONLY_EXTRACT_MANIFEST_CALLSITE'):self.audit(text.replace(old,new,1).encode())
 def test_boot_deadline_is_report_only_and_not_read_cross_host(self):
  text=self.args[2].decode();args=list(self.args);args[2]=(text+"\nassert report['normal_phase_deadline'] > time.monotonic()\n").encode()
  with self.assertRaisesRegex(S.Hold,'TIMING_BOOT_DEADLINE_REPORT_ASSIGNMENT_ONLY'):S.manifest_source(*args)
  tree=ast.parse((HERE/'storage.py').read_text());decoder=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='manifest_decode')
  self.assertFalse(any(isinstance(n,ast.Attribute)and n.attr in('monotonic','time','deadline')for n in ast.walk(decoder)))
 def test_observation_emitter_and_receipt_schema_changes_refuse(self):
  for index,old,new in ((2,"report['normal_phase_deadline']=phase_deadline","report['normal_phase_deadline']=command.deadline"),(4,"row['elapsed_seconds']=time.monotonic()-started","row['elapsed_seconds']=command.deadline"),(3,"row=dict(argv=argv,returncode=life.get('exit'),lifecycle=life","row=dict(argv=argv,returncode=life.get('exit'),lifecycle={}")):
   text=self.args[index].decode();self.assertIn(old,text);args=list(self.args);args[index]=text.replace(old,new,1).encode()
   with self.subTest(index=index),self.assertRaisesRegex(S.Hold,'TIMING_'):S.manifest_source(*args)
 def remap(self,files):
  mapping=S.decode(files['source-map.json'][0]);mapping['files']={n:dict(S.pin(raw),mode=mode)for n,(raw,mode)in files.items()if n!='source-map.json'};files['source-map.json']=(S.canonical(mapping),0o644);return files
 def marker(self,mutate):
  files=dict(self.files);name='manifest-observed-timings-v17.json';v=S.decode(files[name][0]);mutate(v);files[name]=(S.canonical(v),0o644);return self.remap(files)
 def test_inverse_refuses_issued_claims_wrong_types_and_expanded_scope(self):
  for mutate in (lambda v:v.update(Root_grants=True),lambda v:v.update(schema=17.0),lambda v:v['actual'].update(source='MODEL'),lambda v:v.update(dispatch={}),lambda v:v.update(unadmitted=False),lambda v:v.update(holds_preserved=False)):
   with self.assertRaisesRegex(S.Hold,'SOURCE367_UNISSUED_INVERSE_SCOPE'):S.source_inverse(self.marker(mutate))
  for key in ('manifest_observed_timings','kernel_preentry_required','source_enforced_order','resources_changed','recipe_changed','workflows_changed','carrier_transport_changed','metadata_headers_changed','metadata_normalization_changed','request_bounds_changed'):
   with self.subTest(key=key),self.assertRaisesRegex(S.Hold,'SOURCE367_FINITE_CHANGE_SCOPE'):S.source_inverse(self.marker(lambda v:v.update({key:not v[key]})))
 def test_inverse_preserves_protected_recipes_and_every_ancestor(self):
  for name in ('resource-policy.json','hosted/qualification.py','hosted/bootstrap.py','packages/port/rust199-source-reference/PKGBUILD','previous-v12/actor/entry.py'):
   files=dict(self.files);files[name]=(files[name][0]+b'\n# MODEL drift\n',0o644)
   with self.subTest(name=name),self.assertRaisesRegex(S.Hold,'SOURCE367_FULL_SOURCE364_INVERSE'):S.source_inverse(self.remap(files))
 def test_inverse_requires_exact_archive_bytes_and_namespace(self):
  files=dict(self.files);name='previous-v16/hosted/phase_transfer.py';files[name]=(files[name][0]+b'\n# MODEL drift\n',0o644)
  with self.assertRaisesRegex(S.Hold,'SOURCE367_EXACT_REPLACEMENT_BEFORE'):S.source_inverse(self.remap(files))
  files=dict(self.files);files.pop(name)
  with self.assertRaisesRegex(S.Hold,'SOURCE367_EXACT_ARCHIVED364_NAMESPACE'):S.source_inverse(files)
  with self.assertRaisesRegex(S.Hold,'SOURCE367_EXACT_ARCHIVED364_NAMESPACE'):S.source_inverse(self.marker(lambda v:v['changes'].update({'hosted/bootstrap.py':{}})))


if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source-root',type=Path,required=True);args,rest=p.parse_known_args();SOURCE_ROOT=args.source_root
 unittest.main(argv=[sys.argv[0],*rest])

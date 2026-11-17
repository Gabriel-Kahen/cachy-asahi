#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Exact Reader16 behavior preservation outside Source17/timing seam."""
import ast
import base64
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


def fence(event,args):
 if event.startswith(('subprocess.','socket.','ctypes.'))or event in('os.system','os.exec','os.fork','os.posix_spawn','fcntl.flock','resource.setrlimit'):
  raise AssertionError('Reader17 preservation controls forbid actor/network/authority: '+event)

sys.addaudithook(fence)
HERE=Path(__file__).resolve().parent;OLD=HERE.parent/'independent_reader_v16'
def load(name):
 spec=importlib.util.spec_from_file_location('reader17_preserve_'+name,HERE/(name+'.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
R=load('reader');S=R.S

def functions(path):
 text=path.read_text();return {n.name:ast.get_source_segment(text,n)for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)}


class PreservationControls(unittest.TestCase):
 def unissued(self,value):return all(self.unissued(v)for v in value.values())if type(value)is dict else value is None
 def test_all_provider_evidence_archive_and_elf_predicates_preserved_whole(self):
  for name in ('bindings.py','evidence.py','archives.py','elf.py'):self.assertEqual((HERE/name).read_bytes(),(OLD/name).read_bytes(),name)
 def test_all_parent_storage_guards_and_inverses_preserved(self):
  before,after=functions(OLD/'storage.py'),functions(HERE/'storage.py')
  for name,body in before.items():
   if name=='source':continue
   expected=body.replace('def source_inverse(', 'def source364_inverse(',1)if name=='source_inverse'else body
   self.assertEqual(expected,after['source364_inverse'if name=='source_inverse'else name],name)
 def test_reader_changes_only_version_selectors_and_single_manifest_gate(self):
  old=(OLD/'reader.py').read_text();new=(HERE/'reader.py').read_text()
  restored=new.replace('Rust367','Rust364').replace('rust17_','rust16_').replace('==17 and request','==16 and request').replace('ROOT_SELECTED_RUST367_RETAINED_EVIDENCE_READER_V17','ROOT_SELECTED_RUST364_RETAINED_EVIDENCE_READER_V16').replace('rust199-source367-native-v17-','rust199-source364-native-v16-').replace('ROOT_REVIEWED_EXACT_RUST367_SOURCE_V17','ROOT_REVIEWED_EXACT_RUST364_SOURCE_V16').replace('manifest=S.manifest_decode(manifest_raw)','manifest=S.decode(manifest_raw)').replace('schema=17,status=','schema=16,status=').replace('PASS_RUST367_RETAINED_ARCHIVE_EVIDENCE_DATA_ONLY','PASS_RUST364_RETAINED_ARCHIVE_EVIDENCE_DATA_ONLY')
  self.assertEqual(restored,old)
 def test_all_actual_negative_fixtures_preserved_whole(self):
  for path in (OLD/'fixtures').iterdir():self.assertEqual(path.read_bytes(),(HERE/'fixtures'/path.name).read_bytes(),path.name)
 def test_complete_reader_inverse_reconstructs_all_six_parent_bodies(self):
  v=S.decode((HERE/'inverse.DATA.json').read_bytes());self.assertEqual(v['schema'],17);self.assertIsNone(v['Root_acceptance']);self.assertEqual(v['predecessor_commit'],'04345bbe82fd8e0571bb454589d4dd82b271b8a8')
  for name,row in v['files'].items():
   current=(HERE/name).read_bytes();self.assertEqual(S.pin(current),row['after']);prior=base64.b64decode(row['inverse_body_base64'],validate=True)if row['inverse_body_base64']is not None else current
   self.assertEqual(S.pin(prior),row['before']);self.assertEqual(prior,(OLD/name).read_bytes())
 def test_exact_constructor_reproduces_unissued_template(self):
  P=load('prepare_reader')
  for name,raw in P.render().items():self.assertEqual(raw,(HERE/name).read_bytes())
 def test_unissued_authority_refuses_before_any_source_evidence_or_limits(self):
  request=S.decode((HERE/'request.TEMPLATE.json').read_bytes());self.assertIsNone(request['issuer']);self.assertIsNone(request['approved']);self.assertTrue(all(v is None for v in request['resources'].values()));self.assertTrue(self.unissued(request['selected']))
  self.assertEqual(request['reader_files'],{n:S.pin((HERE/n).read_bytes())for n in R.PROGRAMS})
  with patch.object(R,'Corpus',side_effect=AssertionError('must refuse before DATA')):v=R.evaluate(request,None,None,None)
  self.assertEqual(v['status'],'HOLD');self.assertEqual(v['reason'],'ROOT_READER_SELECTION_UNISSUED');self.assertFalse(v['native_acceptance']);self.assertIsNone(v['Root_acceptance'])

 def test_parent_source_and_old_selector_cannot_receive_new_credit(self):
  old=S.decode((OLD/'request.TEMPLATE.json').read_bytes());old.update(issuer='Root',approved=True)
  with self.assertRaisesRegex(S.Hold,'ROOT_READER_SELECTION_UNISSUED'):R.selector(old)
  with patch.object(S,'namespace',side_effect=AssertionError('must refuse before Source read')):
   with self.assertRaisesRegex(S.Hold,'EXTERNAL_SOURCE_PROFILE_PIN'):S.source(None,(HERE/'source-profile.DATA.json').read_bytes(),dict(S.SOURCE,files=364))


if __name__=='__main__':unittest.main()

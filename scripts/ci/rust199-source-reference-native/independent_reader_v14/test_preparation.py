#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Independent local Reader inverse and unissued selection DATA controls."""
import base64
import ast
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


def fence(event,args):
 if event.startswith(('subprocess.','socket.','ctypes.'))or event in('os.system','os.exec','os.fork','os.posix_spawn','fcntl.flock','resource.setrlimit'):
  raise AssertionError('Reader14 preparation controls forbid actor/network/authority: '+event)


sys.addaudithook(fence)
HERE=Path(__file__).resolve().parent
def load(name):
 spec=importlib.util.spec_from_file_location('reader14_preparation_'+name,HERE/(name+'.py'))
 module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
R=load('reader');P=load('prepare_reader');S=R.S


class PreparationControls(unittest.TestCase):
 def test_full_inverse_reconstructs_all_six_reader13_bodies(self):
  record=S.decode((HERE/'inverse.DATA.json').read_bytes())
  self.assertEqual(record['schema'],14);self.assertIsNone(record['Root_acceptance'])
  self.assertEqual(record['predecessor_commit'],'756422588eb92290fc5c308752612878aafad3be')
  self.assertEqual(set(record['files']),set(R.PROGRAMS))
  for name,row in record['files'].items():
   current=(HERE/name).read_bytes();self.assertEqual(S.pin(current),row['after'])
   before=base64.b64decode(row['inverse_body_base64'],validate=True)if row['inverse_body_base64']is not None else current
   self.assertEqual(S.pin(before),row['before']);self.assertEqual(before,(HERE.parent/'independent_reader_v13'/name).read_bytes())
 def test_local_constructor_reproduces_exact_template_and_inverse(self):
  for name,raw in P.render().items():self.assertEqual((HERE/name).read_bytes(),raw)
 def test_preserved_nonseam_modules_equal_reader13(self):
  for name in('bindings.py','elf.py','archives.py'):
   self.assertEqual((HERE/name).read_bytes(),(HERE.parent/'independent_reader_v13'/name).read_bytes())
 def test_archive_package_and_elf_logic_unchanged_outside_finite_export_allowlist(self):
  def functions(path):
   text=path.read_text();return {node.name:ast.get_source_segment(text,node)for node in ast.parse(text).body if isinstance(node,ast.FunctionDef)}
  before=functions(HERE.parent/'independent_reader_v13/archives.py');after=functions(HERE/'archives.py')
  self.assertEqual(set(before),set(after))
  self.assertTrue(all(before[name]==after[name]for name in before ))
 def test_ordinary_read_hash_path_and_namespace_guards_unchanged(self):
  def functions(path):
   text=path.read_text();return {node.name:ast.get_source_segment(text,node)for node in ast.parse(text).body if isinstance(node,ast.FunctionDef)}
  before=functions(HERE.parent/'independent_reader_v13/storage.py');after=functions(HERE/'storage.py')
  for name in('relative','identity','opened','hashed','read','namespace','git_tree'):
   self.assertEqual(before[name],after[name])
 def test_template_authority_and_future_observations_unissued(self):
  request=S.decode((HERE/'request.TEMPLATE.json').read_bytes())
  self.assertIsNone(request['issuer']);self.assertIsNone(request['approved'])
  self.assertTrue(all(v is None for v in request['resources'].values()))
  self.assertEqual(request['reader_files'],{name:S.pin((HERE/name).read_bytes())for name in R.PROGRAMS})
  with patch.object(R,'Corpus',side_effect=AssertionError('unissued selection must not open DATA')):
   result=R.evaluate(request,None,None,None)
  self.assertEqual(result['status'],'HOLD');self.assertEqual(result['reason'],'ROOT_READER_SELECTION_UNISSUED')
  self.assertFalse(result['native_acceptance']);self.assertIsNone(result['Root_acceptance'])
 def test_source344_actual_projection_has_no_kernel_proof(self):
  raw=(HERE/'fixtures/source344-probe-mount.ACTUAL.json').read_bytes()
  self.assertEqual(S.pin(raw),dict(bytes=6302,sha256='e8cf3b1f7dbefc763f93fc91c501e6d28d9a79e0d83cde6a57e9c180d83edf74'))
  value=S.decode(raw);self.assertFalse(value['acceptance']);self.assertNotIn('mountinfo',value)


if __name__=='__main__':unittest.main()

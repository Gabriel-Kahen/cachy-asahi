#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Canonical DATA controls; inherited syscall fence forbids every actor."""
import argparse
import ast
import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
if not (HERE/'test_data.py').exists():HERE=Path('/home/gabe/Documents/ChatGPT/cachy-asahi-native349-pinned-input-carrier-20261117/scripts/ci/native349-pinned-input-carrier')

def load(path,name):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
D=load(HERE/'test_data.py','carrier_fixture_fence');C=load(HERE/'prepare_canonical.py','carrier_canonical_projection')
PARENT=Path('/home/gabe/Documents/ChatGPT/cachy-asahi-llhttp-native-canonical-successor-v6-20261117/artifacts/development/llhttp95-canonical-v6-20261117-r1/canonical-ONCE-DRAFT')
SOURCE=HERE.parents[2]/'artifacts/development/native349-pinned-input-carrier-20261117-r3/Source-DATA'

class Canonical(unittest.TestCase):
 setUp=D.Controls.setUp
 clean=D.Controls.clean
 def make(self):
  out=self.area/'caller';result=C.construct(PARENT,SOURCE,out);return out,result,C.physical(out,0o600)
 def test_full27_inverse_compact_budget_and_all_root_fields_null(self):
  out,result,bodies=self.make();self.assertEqual(C.inverse(bodies),C.parent_bodies(PARENT));self.assertEqual(result['files'],28);self.assertLess(result['bytes'],2*1024**2)
  binding=result['binding']
  for k in('source_CID','source_ref','workflow_id','delegated_metadata_result','registration_metadata_result','runtime54_profile','Root_authority'):self.assertIsNone(binding[k])
  self.assertEqual(bodies['full-files-inverse.DATA.json'],(PARENT/'full-files-inverse.DATA.json').read_bytes())
  for name in(C.OPERATOR,C.PRIMITIVE,C.PROOF,'packet-seal.DATA.json'):
   with self.assertRaises((ValueError,KeyError,json.JSONDecodeError)):C.inverse(dict(bodies,**{name:bodies[name]+b'\nMODEL-tamper'}))
 def test_unchanged_ten_get_once_main_custody_retirement_and_new_workflow(self):
  out,result,bodies=self.make();old=C.parent_bodies(PARENT)
  for name in(C.OPERATOR,C.PRIMITIVE):
   tree=ast.parse(bodies[name]);prior=ast.parse(old[name]);f=lambda t:{n.name:ast.dump(n,include_attributes=False)for n in t.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}
   now,before=f(tree),f(prior)
   changed={'configure','source'}if name==C.OPERATOR else set()
   for key in before:
    if key not in changed:self.assertEqual(now[key],before[key],key)
   self.assertIn(b'CANDIDATE_WORKFLOW_ID=None',bodies[name]);self.assertIn(C.S.NEW_WF.encode(),bodies[name]);self.assertNotIn(b'==420972285',bodies[name])
   self.assertIn(C.OLD_SOURCE.encode(),bodies[name]);self.assertIn(C.OLD_REF.encode(),bodies[name])
  text=bodies[C.OPERATOR].decode();self.assertIn("GROUP='native-arm-llhttp-reference-source'",text);self.assertIn("OP='llhttp-reference-native349-pinned-input-carrier-v1'",text)
  for token in('same','CLOSE_ONLY','EMPTY','runtime54','16384'):self.assertIn(token,text)
 def test_unissued_cli_refuses_before_role_and_mock_post(self):
  out,result,bodies=self.make();op=load(out/C.OPERATOR,'MODEL_UNISSUED_OPERATOR')
  with patch.object(op,'checked',side_effect=AssertionError('no Root proof read')),patch.object(op.subprocess,'run',side_effect=AssertionError('no POST')):
   with self.assertRaises(ValueError):op.configure(argparse.Namespace())
  self.assertIsNone(op.SOURCE);self.assertIsNone(op.WORKFLOW);self.assertIsNone(op.POST)
 def test_registration_reader_null_refusal_and_exact_frozen_guards(self):
  R=load(HERE/'read_registration.py','MODEL_NEW_READER');config=json.loads((HERE/'registration-config.TEMPLATE.json').read_bytes())
  with self.assertRaises(ValueError):R.render(config)
  publication=self.area/'MODEL_PUBLICATION.json';publication.write_text(json.dumps(dict(issuer='Root',source='1'*40,ref='refs/heads/codex/MODEL-UNISSUED',status='PASS_COMPLETE_PUBLIC_GIT_READBACK_DATA_ONLY')));publication.chmod(0o600)
  config.update(Main='2'*40,source='1'*40,ref='refs/heads/codex/MODEL-UNISSUED',Root_publication=str(publication),Root_publication_pin=R.pin(publication.read_bytes()),public_store=str(self.area/'MODEL-PUBLIC-STORE'),workflow_id=999999999,output=str(self.area/'MODEL-READER-OUTPUT'))
  text=R.render(config);self.assertIn('/actions/workflows/999999999',text);self.assertIn('required_secret_name_count=23',text)
  old=ast.parse(R.FROZEN.read_bytes());new=ast.parse(text)
  functions=lambda tree:{n.name:ast.dump(n,include_attributes=False)for n in tree.body if isinstance(n,ast.FunctionDef)}
  self.assertEqual(functions(old),functions(new));self.assertNotIn('420972285',text)
  self.assertIn('CACHY_NATIVE349_INPUTS_SSH_PRIVATE_KEY',(SOURCE/C.S.NEW_WF).read_text())

 def test_actual_metadata_adapters_refuse_foreign_source_and_old_workflow(self):
  raw=json.loads((SOURCE/'source-map.json').read_bytes());bad=self.area/'foreign-root-metadata.json';bad.write_text(json.dumps(dict(issuer='Root',status='PASS_COMPLETE_PUBLIC_GIT_READBACK_DATA_ONLY',tree='0'*40,source_map=C.P.pin((SOURCE/'source-map.json').read_bytes()),files=95,bytes=sum(p.stat().st_size for p in SOURCE.rglob('*')if p.is_file()),source='1'*40,ref='refs/heads/codex/MODEL-FOREIGN',native='NOT RUN',M2='NOT RUN')));bad.chmod(0o600)
  with self.assertRaises(ValueError):C.source_binding(SOURCE,(bad,C.P.pin(bad.read_bytes())['sha256']))
  bad.write_text(json.dumps(dict(kind='CALLER_WORKFLOW_REGISTRATION_READBACK_DATA_V1',repository='Gabriel-Kahen/cachy-asahi',workflow_id=420972285,workflow_path=C.S.NEW_WF,workflow_sha256=C.P.pin((SOURCE/C.S.NEW_WF).read_bytes())['sha256'],registered_on_default_branch=True,state='active')))
  with self.assertRaises(ValueError):C.source_binding(SOURCE,registration=(bad,C.P.pin(bad.read_bytes())['sha256']))

if __name__=='__main__':
 if not sys.flags.isolated or not sys.flags.dont_write_bytecode or not __debug__:raise SystemExit('Use python -I -B unoptimized')
 unittest.main(verbosity=2)

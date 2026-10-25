# SPDX-License-Identifier: MIT
"""Portable factory controls: genuine public ordinary exports, no source actors."""
import ast
import copy
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('_owned_bound_factory',HERE/'prepare.py')
B=importlib.util.module_from_spec(spec);spec.loader.exec_module(B)

class Factory(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.roots=tuple(B.canonical(os.environ['UPDATER_BOUND_'+k])for k in('PARENT','FRESH','BASELINE','CARRIER'))
  cls.expected=B.canonical(os.environ['UPDATER_BOUND_EXPECTED'])
  cls.values,cls.snapshots,cls.operands=B.render(*cls.roots)
  cls.spec=json.loads(cls.operands['profile.json'][0]);cls.policy=json.loads(cls.values['implementation/profile.json'])
  cls.data=B.helper()
 def refuses(self,fn,*args):
  with self.assertRaises((ValueError,OSError)):fn(*args)
 def test_whole_expected_public357_and_complete_before_inverse(self):
  self.assertEqual(B.tree(self.expected),self.values)
  self.assertEqual(len(self.values),357)
  before=self.snapshots['before'][0]
  self.assertEqual(sum(before[n]==b for n,b in self.values.items()),350)
  self.assertEqual({n for n,b in self.values.items()if before[n]!=b},set(self.spec['changed_names']))
  for n,b in self.values.items():
   if n.endswith('.py'):compile(b,n,'exec')
 def test_complete_role_records_originals_and_null_ownactual(self):
  p=self.policy
  self.assertTrue(all(p[k]is None for k in('actual_source','actual_ref','actual_run')))
  self.assertEqual(p['input_sources']['latest_decisions'],self.spec['inputs']['carrier']['source'])
  self.assertEqual(p['authority_files'],self.spec['inputs']['carrier']['files'])
  for kind in('fresh607','baseline607'):
   r=p['authority_projection_policy']['records'][kind]
   self.assertEqual(B.encoded(r['original']),self.snapshots[kind][0]['decision.json'])
   self.assertEqual(r['files'],self.spec['inputs'][kind]['files'])
   self.assertEqual(r['original']['cleanup'],'PASS_SOURCE_BOUND_RETAINED_RECEIPTS')
   self.assertEqual(self.data.projection(kind,r,p,dict(line.split()for line in self.values['implementation/before607.lock'].decode().splitlines()))['scope'],'ONE_INSTALLED_PREREQUISITE_NOT_UPDATER_ACCEPTANCE')
 def test_original_predicate_exact_and_all_flag_refusals(self):
  def body(raw,name):
   text=raw.decode();node=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)and n.name==name)
   return ast.get_source_segment(text,node)
  self.assertEqual(body(self.operands['data_policy.py'][0],'original_decision'),body(self.values['implementation/authority.py'],'original_decision'))
  for kind,record in self.policy['authority_projection_policy']['records'].items():
   for flag in self.data.FLAGS:
    bad=copy.deepcopy(record['original']);bad['ordinary_and_root_flags'][flag]=False
    self.refuses(self.data.original_decision,kind,bad,self.policy)
   for key,value in(('cleanup','PASS'),('package_count',606),('run_id',True),('limits',[])):
    bad=copy.deepcopy(record['original']);bad[key]=value
    self.refuses(self.data.original_decision,kind,bad,self.policy)
 def test_foreign_member_carrier_and_parent_refusal(self):
  with tempfile.TemporaryDirectory(prefix='portable-bound-drift-')as td:
   root=Path(td)/'carrier';root.mkdir()
   for n,b in self.snapshots['carrier'][0].items():
    p=root/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b)
   (root/'foreign').write_bytes(b'x')
   self.refuses(B.render,*self.roots[:3],root)
   (root/'foreign').unlink();p=root/'baseline607/projection.json';p.write_bytes(p.read_bytes()+b' ')
   self.refuses(B.render,*self.roots[:3],root)
  self.refuses(B.render,self.roots[1],*self.roots[1:])
 def test_paths_alias_links_and_namespace(self):
  with tempfile.TemporaryDirectory(prefix='portable-bound-paths-')as td:
   root=Path(td);out=root/'out';receipt=root/'receipt'
   self.assertEqual(B.paths(*self.roots,out,receipt)[-2:],(out,receipt))
   for p in(HERE/'new',self.roots[0]/'new',root/'native-actual-fixture'/'new'):
    if'native-actual'in str(p):p.parent.mkdir()
    self.refuses(B.paths,*self.roots,p,receipt)
   self.refuses(B.paths,*self.roots,out,out)
   self.refuses(B.canonical,str(out)+'/../alias')
   alias=root/'alias';alias.symlink_to(self.roots[0],target_is_directory=True)
   self.refuses(B.paths,alias,*self.roots[1:],out,receipt)
   p=root/'file';p.write_bytes(b'x');os.link(p,root/'hard');self.refuses(B.read,p)
 def test_late_input_identity_before_any_write(self):
  with tempfile.TemporaryDirectory(prefix='portable-bound-late-')as td:
   out=Path(td)/'out';receipt=Path(td)/'receipt'
   changed=dict(self.snapshots)
   values,state=changed['before'];changed['before']=(values,dict(state,private_test_identity='changed'))
   # A private seam injects only a late identity mismatch; genuine inputs stay read-only.
   with mock.patch.object(B,'render',return_value=(self.values,changed,self.operands)):
    self.refuses(B.build,*self.roots,out,receipt,'known')
   self.assertFalse(out.exists());self.assertFalse(receipt.exists())
 def test_constructor_no_supplied_code_or_process_execution(self):
  with mock.patch.object(subprocess,'Popen',side_effect=AssertionError('constructor actor forbidden')):
   values,_,_=B.render(*self.roots)
  self.assertEqual(values,self.values)
  self.assertNotIn('authority',sys.modules)
 def test_actual_production_cli_known_and_null_same_public_bytes(self):
  with tempfile.TemporaryDirectory(prefix='portable-bound-actual-cli-')as td:
   for context in('known','null'):
    out=Path(td)/context;receipt=Path(td)/(context+'.json')
    argv=[sys.executable,'-I','-B','-Werror',str(HERE/'prepare.py')]
    for name,root in zip(('parent','fresh','baseline','carrier'),self.roots):argv+=['--'+name,str(root)]
    argv+=['--output',str(out),'--receipt',str(receipt),'--context',context]
    p=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,timeout=60)
    self.assertEqual(p.returncode,0,p.stderr.decode());self.assertEqual(p.stderr,b'')
    self.assertEqual(B.tree(out),self.values)
    row=json.loads(B.read(receipt));self.assertFalse(row['actor_authority']);self.assertIsNone(row['actual_run'])
    self.assertEqual(row['publication'],self.spec['sources']['after']if context=='known'else None)
    self.assertTrue(all((p.stat().st_mode&0o777)==0o644 for p in out.rglob('*')if p.is_file()))

if __name__=='__main__':unittest.main()

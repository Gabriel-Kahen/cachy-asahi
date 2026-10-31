# SPDX-License-Identifier: MIT
"""Explicit portable SOURCE fixtures; no installation, native actors or acquisition."""
import ast,contextlib,importlib.util,io,json,os,stat,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('cache_source_factory',HERE/'prepare.py')
F=importlib.util.module_from_spec(spec);spec.loader.exec_module(F)
P=F.ordinary(os.environ['UPDATER_CACHE_PARENT'])
H=F.ordinary(os.environ['UPDATER_CACHE_HELPER'])
E=F.ordinary(os.environ['UPDATER_CACHE_EXPECTED'])

class Controls(unittest.TestCase):
 def test_exact_published_both_receipts_modes_and_current_actual_null(self):
  expected=F.tree(E)
  with tempfile.TemporaryDirectory() as td:
   for mode in ('known','null'):
    output=Path(td)/mode
    with contextlib.ExitStack() as stack:
     previous=os.umask(0o077);stack.callback(os.umask,previous)
     value=F.emit(P,H,output,mode)
    self.assertEqual(F.tree(output),expected);self.assertEqual(len(value['files']),360)
    self.assertEqual(value['source'] is None,mode=='null')
    for key in ('actual_source','actual_ref','actual_run','Root_acceptance'):self.assertIsNone(value[key])
    self.assertTrue(all(stat.S_IMODE((output/n).stat().st_mode)==0o644 for n in expected))
 def test_complete_before_body_profile_workflow_guard_inverses(self):
  values,p,before,helpers,states=F.compose(P,H)
  self.assertEqual(values,F.tree(E));self.assertEqual(len(before[0]),357)
  self.assertEqual(len(p['held']),345);self.assertEqual(len(p['changed']),12);self.assertEqual(len(p['added']),3)
  context=json.loads(values['implementation/parent355.json'])['dependency_cache_context']
  self.assertEqual(context['files'],p['parent']['files'])
  for n,text in context['before_bodies'].items():self.assertEqual(text.encode(),before[0][n])
  for n in ('implementation/runtime.py','implementation/authority.py','implementation/source_guard.py'):
   edits=json.loads(F.read(HERE/'edits.json'))[n]
   self.assertEqual(F.apply(values[n],edits,reverse=True),before[0][n])
 def test_exact_three_helper_copies_no_historical_tree_or_actor_import(self):
  with (patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS')),
        patch('builtins.exec',side_effect=AssertionError('NO_SUPPLIED_CODE_EXECUTION'))):
   values,p,before,helpers,states=F.compose(P,H)
  self.assertEqual(set(values)-set(before[0]),{'implementation/'+n for n in p['helper']['selected']})
  for n,w in p['helper']['selected'].items():
   self.assertEqual(values['implementation/'+n],helpers[0]['implementation/'+n])
  self.assertEqual(len(helpers[0]),1203)
 def test_canonical_double_slash_alias_existing_and_protected_outputs(self):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);alias=root/'alias';alias.symlink_to(P,target_is_directory=True)
   for raw in ('relative','//'+str(P).lstrip('/'),str(alias),str(P)+'/../source'):
    with self.subTest(raw=raw),self.assertRaises(ValueError):F.ordinary(raw)
   for output in (root,P/'BAD',H/'BAD',HERE/'BAD'):
    with self.subTest(output=output),self.assertRaises(ValueError):F.paths(P,H,output)
    if output.name=='BAD':self.assertFalse(output.exists())
   with self.assertRaises(ValueError):F.paths(P,P,root/'out')
 def test_real_fd_mutation_hardlink_symlink_and_namespace_refusal(self):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);leaf=root/'a';leaf.write_bytes(b'original');read=F.os.read;changed=False
   def mutate(fd,count):
    nonlocal changed
    part=read(fd,count)
    if part and not changed:changed=True;leaf.write_bytes(b'mutation')
    return part
   with patch.object(F.os,'read',side_effect=mutate),self.assertRaises(ValueError):F.read_state(leaf)
   second=root/'hard';os.link(leaf,second)
   with self.assertRaises(ValueError):F.read_state(leaf)
   second.unlink();leaf.unlink();leaf.symlink_to(P/'entry.py')
   with self.assertRaises(ValueError):F.scan(root)
   leaf.unlink();(root/'empty').mkdir()
   with self.assertRaises(ValueError):F.scan(root)
 def test_wrong_closed_parent_or_helper_refuses_before_any_write(self):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);wrong=root/'wrong';wrong.mkdir();(wrong/'foreign.py').write_bytes(b'raise AssertionError("NOT_EXECUTED")\n')
   for source,helper in ((wrong,H),(P,wrong)):
    output=root/'out'
    with self.subTest(source=source,helper=helper),self.assertRaises(ValueError):F.emit(source,helper,output,'known')
    self.assertFalse(output.exists())
 def test_fixed_profile_operand_and_late_helper_drift_refuse_before_writes(self):
  read=F.read_state
  def corrupt(path):
   raw,state=read(path)
   return (raw+b'foreign',state) if Path(path).name=='profile.json' else (raw,state)
  with tempfile.TemporaryDirectory() as td:
   output=Path(td)/'out'
   with patch.object(F,'read_state',side_effect=corrupt),self.assertRaisesRegex(ValueError,'pinned'):F.emit(P,H,output,'known')
   self.assertFalse(output.exists());scan=F.scan;calls={}
   def late(root):
    values,state=scan(root);key=str(root);calls[key]=calls.get(key,0)+1
    return (values,dict(state,changed=True)) if Path(root)==H and calls[key]==2 else (values,state)
   with patch.object(F,'scan',side_effect=late),self.assertRaisesRegex(ValueError,'late whole'):F.emit(P,H,output,'known')
   self.assertFalse(output.exists())
 def test_phase240_original180_and_all_other_runtime_clocks_held(self):
  values,p,before,helpers,states=F.compose(P,H);profile=json.loads(values['implementation/profile.json']);original=json.loads(before[0]['implementation/profile.json'])
  self.assertEqual(profile['dependency_cache']['new_phase_seconds'],240)
  self.assertEqual(profile['dependency_cache']['original_acquisition_seconds'],180)
  self.assertEqual(profile['dependency_cache']['prior_files'],1159)
  self.assertEqual(profile['dependency_cache']['new_files'],8)
  self.assertEqual(profile['dependency_cache']['total_dependency_files'],10)
  self.assertEqual(profile['clocks'],original['clocks']);self.assertEqual(profile['before'],original['before']);self.assertEqual(profile['after'],original['after'])
  self.assertEqual(profile['dependency_cache']['outer_fit'],'NOT_ESTABLISHED')
 def test_cache_layer_distinct_from_separate_runtime_argument_repair(self):
  values,p,before,helpers,states=F.compose(P,H);tree=ast.parse(values['implementation/runtime.py']);extras=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='extras')
  self.assertEqual(extras.args.kwonlyargs,[]);self.assertNotIn(b'require_dependency=True',values['implementation/runtime.py'])
  self.assertEqual(p['result']['source'],'764da54af95f91ad7e72059b3c0eea0af0631774')
  self.assertTrue(all(values[n]==before[0][n]for n in p['held']))

if __name__=='__main__':
 suite=unittest.defaultTestLoader.loadTestsFromTestCase(Controls)
 F.need(suite.countTestCases()==9,'nonzero exact9 portable source groups')
 result=unittest.TextTestRunner(verbosity=2).run(suite)
 raise SystemExit(not result.wasSuccessful())

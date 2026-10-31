"""Portable explicit389 generation and source controls; no actors/actual evidence."""
import argparse,ast,contextlib,importlib.util,io,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE));import prepare as P,apps14 as A
PARENT=Path(os.environ['APPS14_CURRENT606_PARENT']).absolute();EXPECTED=Path(os.environ['APPS14_CURRENT606_EXPECTED']).absolute();CARRIER=Path(os.environ['APPS14_CURRENT606_CARRIER']).absolute();FULL=False
LEAF='copyworker/scripts/ci/current606-apps7-copy/lifecycle.py'
def command(args,seconds=60):return subprocess.run([sys.executable,'-I','-B','-Werror',*map(str,args)],capture_output=True,timeout=seconds)
class Controls(unittest.TestCase):
 def test_exact_full389_bound_NULL_and_actual_source_entry(self):
  p,_,_=A.inputs()
  self.assertEqual({n:P.pin(b)for n,b in P.source(EXPECTED,p['after']).items()},p['after'])
  with tempfile.TemporaryDirectory()as td:
   for selected in(False,True):
    out=Path(td)/str(selected)
    with patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTOR_API_GIT')):v=A.emit(PARENT,CARRIER if selected else None,out)
    wanted=p['after']if selected else p['null'];P.source(out,wanted);self.assertEqual((v['files'],v['held'],v['changed'],v['removed'],v['added']),(389,364,16,9,9));self.assertIsNone(v['source']);self.assertIsNone(v['ref']);self.assertIsNone(v['run']);self.assertIsNone(v['current606_acceptance'])
    r=command([out/'apps14/entry.py','--source-only']);self.assertEqual((r.returncode,r.stderr),(0,b''));self.assertIsNone(json.loads(r.stdout)['actual'])
    if not selected:
     r=command([out/'apps14/entry.py','--require-selection']);self.assertNotEqual(r.returncode,0);self.assertIn(b'NULL',r.stderr)
 def test_isolated_actual_cli_and_implicit_foreign_conflicting_options(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);out=root/'source';r=command([HERE/'prepare.py','--apps14','--parent',PARENT,'--apps14-carrier',CARRIER,'--output',out]);self.assertEqual((r.returncode,r.stderr),(0,b''));self.assertEqual(json.loads(r.stdout)['expected_fixture_source'],'97666b742d1b29e469e6de171da6e7a0d15c18c7');P.source(out,A.inputs()[0]['after'])
   common=[HERE/'prepare.py','--parent','/not-read','--output',root/'refused']
   for args in [[],['--apps14','--apps11'],['--apps14','--carrier','/unused'],['--apps14-carrier','/unused'],['--apps14','--apps11-carrier','/unused'],['--apps13']]:
    r=command([*common,*args]);self.assertNotEqual(r.returncode,0);self.assertFalse((root/'refused').exists());self.assertNotIn(b'FileNotFoundError',r.stderr)
 def test_unchanged_original_CLI_dispatch_all_five_modes(self):
  cases=[([], 'emit'),(['--carrier-env-correction'],'emit_carrier_env'),(['--apps9','--apps9-carrier','/candidate'],'emit_apps9'),(['--apps10','--apps10-carrier','/candidate'],'emit_apps10'),(['--apps11','--apps11-carrier','/candidate'],'emit_apps11')]
  for flags,name in cases:
   with self.subTest(name=name),patch.object(sys,'argv',['prepare.py','--parent','/parent','--carrier','/carrier','--output','/output',*flags]),patch.object(P,name,return_value={'route':name})as call,contextlib.redirect_stdout(io.StringIO())as stdout:P.main();self.assertEqual(json.loads(stdout.getvalue()),{'route':name});call.assert_called_once()
 def test_missing_extra_early_and_late_parent_drift_before_output(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);parent=root/'parent';shutil.copytree(PARENT,parent,ignore=shutil.ignore_patterns('.git'));leaf=parent/LEAF;raw=leaf.read_bytes()
   for mode in('bytes','missing','extra','directory'):
    if mode=='bytes':leaf.write_bytes(raw+b'x')
    elif mode=='missing':leaf.unlink()
    elif mode=='extra':(parent/'foreign').write_bytes(b'x')
    else:(parent/'empty-foreign').mkdir()
    with self.assertRaises(ValueError):A.emit(parent,None,root/mode)
    self.assertFalse((root/mode).exists())
    if mode in('bytes','missing'):leaf.write_bytes(raw)
    elif mode=='extra':(parent/'foreign').unlink()
    else:(parent/'empty-foreign').rmdir()
   original=A.F.source;calls=[]
   def drift(path,wanted):
    if path==parent:
     calls.append(True)
     if len(calls)==2:leaf.write_bytes(raw+b'late')
    return original(path,wanted)
   with patch.object(A.F,'source',side_effect=drift),self.assertRaises(ValueError):A.emit(parent,None,root/'late')
   self.assertFalse((root/'late').exists())
 def test_support_profile_and_carrier_drift_before_output(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);factory=root/'factory';shutil.copytree(HERE,factory)
   with patch.object(A,'HERE',factory):
    for dirname,n in [('apps14-payload','apps14/packet.py'),('apps14-null-payload','apps14/packet.py')]:
     leaf=factory/dirname/n;raw=leaf.read_bytes();leaf.write_bytes(raw+b'x')
     with self.assertRaises(ValueError):A.emit(PARENT,None,root/dirname)
     self.assertFalse((root/dirname).exists());leaf.write_bytes(raw)
    (factory/'apps14-profile.json').write_bytes(b'{}')
    with self.assertRaisesRegex(ValueError,'fixed Apps14 profile'):A.emit(PARENT,None,root/'profile')
    self.assertFalse((root/'profile').exists())
   carrier=root/'carrier';shutil.copytree(CARRIER,carrier,ignore=shutil.ignore_patterns('.git'));(carrier/'index.json').write_bytes(b'{}')
   with self.assertRaises(ValueError):A.emit(PARENT,carrier,root/'carrier-out')
   self.assertFalse((root/'carrier-out').exists())
 def test_normalized_inputs_outputs_alias_hardlink_and_overlap_refused(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);(root/'hop').mkdir();alias=root/'alias';alias.symlink_to(PARENT,target_is_directory=True)
   for parent,carrier,out in[(alias,None,root/'out'),(PARENT,None,PARENT/'new'),(PARENT,None,HERE/'new'),(PARENT,CARRIER,CARRIER/'new'),(PARENT,None,root/'hop'/'..'/'noncanonical')]:
    with self.assertRaises(ValueError):A.emit(parent,carrier,out)
   parent=root/'parent';shutil.copytree(PARENT,parent,ignore=shutil.ignore_patterns('.git'));leaf=parent/LEAF;raw=leaf.read_bytes();holder=root/'holder';holder.write_bytes(raw);leaf.unlink();os.link(holder,leaf)
   with self.assertRaises(ValueError):A.emit(parent,None,root/'hardlink')
   self.assertFalse((root/'hardlink').exists());leaf.unlink()
 def test_actual_emitted_focused_or_complete_source_controls(self):
  wanted=['Controls.test_unknown_pair_carrier_refuses_before_external_or_output','Controls.test_both_workflows_explicit_new_env_and_original_clocks','Controls.test_exact13_recipe_carrier_and_issued_decision_no_old13_transfer']
  with tempfile.TemporaryDirectory()as td:
   for selected in(False,True):
    out=Path(td)/str(selected);A.emit(PARENT,CARRIER if selected else None,out);r=command([out/'apps14/test_source.py',*([]if FULL else wanted)],120);self.assertEqual(r.returncode,0,r.stderr.decode(errors='replace'));count=9 if FULL else 3;self.assertRegex(r.stderr,('Ran %d tests in '%count).encode());self.assertNotRegex(r.stderr,rb'\b(?:FAILED|ERROR|skipped)\b');print('complete9'if FULL else'focused3','bound'if selected else'NULL','PASS',file=sys.stderr)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--full-source-controls',action='store_true');a,rest=p.parse_known_args();FULL=a.full_source_controls;unittest.main(argv=[sys.argv[0],*rest],verbosity=2)

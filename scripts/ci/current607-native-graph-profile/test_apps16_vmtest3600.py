# SPDX-License-Identifier: MIT
"""Portable exact public849→853 factory/source-only controls; no artifacts or actors."""
import argparse,ast,copy,importlib.util,json,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
p=argparse.ArgumentParser();p.add_argument('--parent',type=Path,required=True);p.add_argument('--expected',type=Path,required=True);args,rest=p.parse_known_args();sys.argv=[sys.argv[0],*rest]
s=importlib.util.spec_from_file_location('_maintained_vmtest_controls',HERE/'apps16_vmtest3600.py');M=importlib.util.module_from_spec(s);s.loader.exec_module(M);F=M.F;P=args.parent.absolute();EXPECTED=args.expected.absolute()
def functions(raw):return{n.name:F.pin(ast.get_source_segment(raw,n).encode())for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)}
class Controls(unittest.TestCase):
 def test_exact_selected_NULL853_maps_whole_inverses_and_unrelated_versions(self):
  selected,profile,maps=M.render(P);null,_,_=M.render(P,True);self.assertEqual({n:F.pin(b)for n,b in selected.items()},maps['selected']);self.assertEqual(F.files(EXPECTED),maps['selected']);self.assertEqual({n:F.pin(b)for n,b in null.items()},maps['unbound']);self.assertEqual(functions(F.read(HERE/'prepare.py').decode()),profile['held_functions']);self.assertIn(b'hyprland-qt-support 0.1.0-14',selected['latest/implementation/expected606.lock']);self.assertNotIn('artifacts/development',F.read(HERE/'apps16_vmtest3600.py').decode())
  for bodies in(selected,null):
   proof=json.loads(bodies[M.PROOF]);self.assertEqual(len(proof['before_bodies']),7);self.assertEqual(len(proof['added']),4);self.assertTrue(all(proof[k]is None for k in('actual_source','actual_ref','actual_run','Root_acceptance')))
   for n,edits in proof['edits'].items():
    text=bodies[n].decode()
    for a,b in reversed(edits):self.assertEqual(text.count(b),1);text=text.replace(b,a,1)
    self.assertEqual(F.pin(text.encode()),proof['before'][n])
 def test_actual_cli_both_choices_and_source_preflight_NULL_refusal(self):
  with tempfile.TemporaryDirectory()as td:
   t=Path(td)
   for null in(False,True):
    out=t/('null'if null else'known');authorization=t/('null.json'if null else'known.json');r=subprocess.run([sys.executable,'-I','-B','-Werror',str(HERE/'prepare.py'),'--profile','apps16_vmtest3600'+('_unbound'if null else''),'--source',str(P),'--output',str(out),'--authorization',str(authorization)],cwd='/',capture_output=True,timeout=40);self.assertEqual((r.returncode,r.stderr),(0,b''));value=json.loads(authorization.read_bytes());self.assertEqual(len(value['files']),853);self.assertIsNone(value['actual']);self.assertEqual(F.files(out),M.inputs()[1]['unbound'if null else'selected'])
    entry=out/'latest/implementation/latest_run.py';r=subprocess.run([sys.executable,'-I','-B','-Werror',str(entry),'--require-selection'if null else'--source-preflight'],cwd='/',capture_output=True,timeout=60)
    if null:self.assertEqual(r.returncode,1);self.assertIn(b'NULL Apps16',r.stderr)
    else:self.assertEqual((r.returncode,r.stderr),(0,b''));fact=json.loads(r.stdout);self.assertEqual((fact['files'],fact['parent849']['files']),(853,849));self.assertEqual(fact['bounds']['component'],3600);self.assertEqual(fact['outer4200_fit'],'NOT_ESTABLISHED')
 def test_source_profile_payload_and_other_clock_drift_refusals(self):
  real=F.read
  for target in(P/'latest/implementation/latest_component.py',HERE/'apps16-vmtest3600-profile.json',HERE/'apps16-vmtest3600-maps.json',HERE/'apps16-vmtest3600/validation_capacity.py'):
   def drift(path):return real(path)+(b'\n'if Path(path).absolute()==target else b'')
   with patch.object(F,'read',side_effect=drift),self.assertRaises(ValueError):M.render(P)
  profile,maps,payload=M.inputs()
  for name in('consumer','owner','transaction','fixture','real_module_suite','cleanup'):
   bad=copy.deepcopy(profile);bad['clocks'][name]+=1;raw=F.encoded(bad)
   def changed(path):return raw if Path(path)==HERE/'apps16-vmtest3600-profile.json'else real(path)
   with patch.object(F,'read',side_effect=changed),patch.object(M,'PROFILE',F.pin(raw)),self.assertRaises(ValueError):M.inputs()
 def test_alias_overlap_hardlink_emptydir_and_late_source_mutation_prewrite(self):
  with tempfile.TemporaryDirectory()as td:
   t=Path(td);(t/'exists').mkdir();(t/'alias').symlink_to(t,target_is_directory=True)
   for output,authorization in((t/'exists',t/'auth'),(P/'no',t/'auth'),(t/'out',P/'no'),(t/'out',t/'out/auth'),(t/'alias/no',t/'auth'),(t/'exists/../no',t/'auth'),(t/'out',HERE/'no')):
    with self.assertRaises(ValueError):M.emit(P,output,authorization)
   fixture=t/'source';fixture.mkdir();(fixture/'x').write_bytes(b'one');want={'x':F.pin(b'one')};(fixture/'empty').mkdir()
   with self.assertRaises(ValueError):M.closed(fixture,want)
   (fixture/'empty').rmdir();(fixture/'alias').hardlink_to(fixture/'x')
   with self.assertRaises(ValueError):M.closed(fixture,want)
   real=M.closed;count=[0]
   def late(root,wanted):
    if Path(root)==P:
     count[0]+=1
     if count[0]>=2:raise ValueError('late source mutation')
    return real(root,wanted)
   with patch.object(M,'closed',side_effect=late),self.assertRaisesRegex(ValueError,'late source'):M.emit(P,t/'never',t/'never.json')
   self.assertFalse((t/'never').exists());self.assertFalse((t/'never.json').exists())
 def test_main_additive_route_inverse_old_functions_and_all_work_clocks(self):
  profile,maps,payload=M.inputs();raw=F.read(HERE/'prepare.py').decode();choice="'apps16_849_unbound','apps16_vmtest3600','apps16_vmtest3600_unbound'),default=";self.assertEqual(raw.count(choice),1);delta=profile['prepare_delta'];self.assertEqual(F.pin(raw.replace(delta['newchoice'],delta['choice'],1).replace(delta['branch'],delta['anchor'],1).encode()),profile['prepare_before']);self.assertIn("default='fresh_descriptor563'",raw);self.assertEqual(functions(raw),profile['held_functions']);self.assertEqual(profile['passive_caps'],dict(source=300,strict=900,failure=900,collector=900));proof=profile['proof'];self.assertEqual(proof['profile_value']['bounds'],profile['clocks']);self.assertFalse(proof['profile_value']['consumer_difference_is_guaranteed_margin']);self.assertEqual(proof['profile_value']['M2_performance'],'NOT_RUN');self.assertEqual(proof['failure_post']['run'],40177365810);self.assertFalse(proof['failure_diagnosis']['native_acceptance']);self.assertEqual(len(maps['before']),849)
  for n in('latest_component.py','latest_owner.py','latest_setup.py','latest_validate.py','held/package_graph.py'):
   key='latest/implementation/'+n;self.assertEqual(maps['selected'][key],maps['before'][key])
if __name__=='__main__':unittest.main(verbosity=2)

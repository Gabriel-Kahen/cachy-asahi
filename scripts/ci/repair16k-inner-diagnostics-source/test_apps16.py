"""Finite portable Apps16 source generation controls, no original evidence/actors."""
import argparse,ast,importlib.util,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE));import apps16 as A
F=A.F;BASE=Path(os.environ['APPS16_REPAIR_BASE_SOURCE']).absolute();EXPECTED=Path(os.environ['APPS16_REPAIR_EXPECTED_SOURCE']).absolute();CARRIER=Path(os.environ['APPS16_REPAIR_CARRIER']).absolute();
LEAF='scripts/ci/apps7-full574-repair16k/adapter.py'
def command(args,seconds=60):return subprocess.run([sys.executable,'-I','-B','-Werror',*map(str,args)],capture_output=True,timeout=seconds)
class Factory(unittest.TestCase):
 def test_complete_bound_and_NULL235_and_source_gates(self):
  p,_=A.inputs();self.assertEqual((F.files(BASE),F.files(EXPECTED),F.files(CARRIER)),(p['before'],p['after'],p['carrier_files']));self.assertEqual(len(p['held']),197)
  with tempfile.TemporaryDirectory()as td:
   for selected in(False,True):
    root=Path(td)/str(selected)
    with patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS_API_GIT')):v=A.prepare(BASE,root,A.NAME,CARRIER if selected else None)
    self.assertEqual(F.files(root),p['after']if selected else p['null']);self.assertEqual(v['selected'],selected);self.assertIsNone(v['source']);self.assertIsNone(v['ref']);self.assertIsNone(v['repair_acceptance']);self.assertTrue(all(x is None for x in v['run_ids'].values()));self.assertEqual(v['clocks'],'UNCHANGED')
    r=command([root/'apps16-repair/entry.py','--source-only']);self.assertEqual((r.returncode,r.stderr),(0,b''));self.assertIsNone(json.loads(r.stdout)['authority'])
    if not selected:
     r=command([root/'apps16-repair/entry.py','--require-selection']);self.assertNotEqual(r.returncode,0);self.assertIn(b'NULL',r.stderr)
    self.assertEqual(F.files(root),p['after']if selected else p['null'])
 def test_isolated_exact_cli_authorization_help_and_actualsNULL(self):
  with tempfile.TemporaryDirectory()as td:
   out=Path(td)/'source';auth=Path(td)/'authorization.json';r=command([HERE/'apps16.py','--profile',A.NAME,'--base-root',BASE,'--carrier',CARRIER,'--output',out,'--authorization',auth]);self.assertEqual((r.returncode,r.stderr),(0,b''));self.assertEqual(F.files(out),F.files(EXPECTED));v=json.loads(auth.read_bytes());self.assertEqual(v['expected_fixture_source'],'ac1df3c2b1859f97534d1db5064d51472b18567c');self.assertIsNone(v['source']);self.assertIsNone(v['ref']);self.assertEqual(v['files'],A.inputs()[0]['after'])
   r=command([HERE/'apps16.py','--help']);self.assertEqual((r.returncode,r.stderr),(0,b''));self.assertIn(b'--carrier',r.stdout)
 def test_missing_foreign_profile_and_auth_inside_input_refuse_before_output(self):
  with tempfile.TemporaryDirectory()as td:
   out=Path(td)/'source'
   with patch.object(A,'inputs',side_effect=AssertionError('NO_INPUT_READ')):
    for v in(None,'apps14-repair235','apps16','postcopy-cli210'):
     with self.assertRaisesRegex(ValueError,'explicit --profile'):A.prepare(Path('/not-read'),out,v)
   self.assertFalse(out.exists());r=command([HERE/'apps16.py','--profile',A.NAME,'--base-root',BASE,'--output',out,'--authorization',BASE/'never-written-authorization.json']);self.assertNotEqual(r.returncode,0);self.assertIn(b'authorization outside',r.stderr);self.assertFalse(out.exists());self.assertFalse((BASE/'never-written-authorization.json').exists())
 def test_parent_missing_extra_bytes_and_late_drift_refuse_before_output(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);base=root/'base';shutil.copytree(BASE,base,ignore=shutil.ignore_patterns('.git'));leaf=base/LEAF;raw=leaf.read_bytes()
   for mode in('bytes','extra','missing'):
    if mode=='bytes':leaf.write_bytes(raw+b'x')
    elif mode=='extra':(base/'foreign').write_bytes(b'x')
    else:leaf.unlink()
    with self.assertRaises(ValueError):A.prepare(base,root/mode,A.NAME)
    self.assertFalse((root/mode).exists())
    if mode=='extra':(base/'foreign').unlink()
    else:leaf.write_bytes(raw)
   original=F.files;calls=[]
   def changed(path):
    if path==base:
     calls.append(True)
     if len(calls)==2:leaf.write_bytes(raw+b'late')
    return original(path)
   with patch.object(F,'files',side_effect=changed),self.assertRaisesRegex(ValueError,'fresh parent'):A.prepare(base,root/'late',A.NAME)
   self.assertFalse((root/'late').exists())
 def test_payload_profile_carrier_drift_refuse_before_output(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);factory=root/'factory';shutil.copytree(HERE,factory);leaf=factory/'apps16-payload/apps16-repair/selection.py';raw=leaf.read_bytes()
   with patch.object(A,'HERE',factory):
    leaf.write_bytes(raw+b'x')
    with self.assertRaisesRegex(ValueError,'21 used readable'):A.prepare(BASE,root/'payload',A.NAME)
    self.assertFalse((root/'payload').exists());leaf.write_bytes(raw);(factory/'apps16-profile.json').write_bytes(b'{}')
    with self.assertRaisesRegex(ValueError,'fixed Apps16'):A.prepare(BASE,root/'profile',A.NAME)
    self.assertFalse((root/'profile').exists())
   carrier=root/'carrier';shutil.copytree(CARRIER,carrier,ignore=shutil.ignore_patterns('.git'));(carrier/'foreign').write_bytes(b'x')
   with self.assertRaisesRegex(ValueError,'accepted Apps16 carrier94'):A.prepare(BASE,root/'carrier-out',A.NAME,carrier)
   self.assertFalse((root/'carrier-out').exists())
 def test_source_output_and_descriptor_aliases_refuse(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);alias=root/'alias';alias.symlink_to(BASE,target_is_directory=True)
   for base,out in[(alias,root/'alias-out'),(BASE,BASE),(BASE,BASE/'new'),(BASE,HERE/'new'),(BASE,root/'unmade/../escaped'),(BASE/'unmade/..',root/'not-written')]:
    with self.assertRaises(ValueError):A.prepare(base,out,A.NAME)
   base=root/'base';shutil.copytree(BASE,base,ignore=shutil.ignore_patterns('.git'));leaf=base/LEAF;raw=leaf.read_bytes();holder=root/'holder';holder.write_bytes(raw)
   for mode in('symlink','hardlink'):
    leaf.unlink()
    if mode=='symlink':leaf.symlink_to(holder)
    else:os.link(holder,leaf)
    with self.assertRaises(ValueError):A.prepare(base,root/mode,A.NAME)
    self.assertFalse((root/mode).exists());leaf.unlink();leaf.write_bytes(raw)
 def test_old14_whole_function_and_CLI_bound_NULL_parity(self):
  spec=importlib.util.spec_from_file_location('_whole_held_apps14_route',HERE/'apps14.py');old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old);p,_=old.inputs();parent=Path(os.environ['APPS14_REPAIR_BASE_SOURCE']).absolute();carrier=Path(os.environ['APPS14_REPAIR_CARRIER']).absolute()
  with tempfile.TemporaryDirectory()as td:
   root=Path(td)
   for bound in(False,True):
    expected=p['after']if bound else p['null'];out=root/('function-'+str(bound));old.prepare(parent,out,old.NAME,carrier if bound else None);self.assertEqual(F.files(out),expected)
    out=root/('cli-'+str(bound));auth=root/('old-auth-'+str(bound));args=[HERE/'apps14.py','--profile',old.NAME,'--base-root',parent,'--output',out,'--authorization',auth]+(['--carrier',carrier]if bound else[]);r=command(args);self.assertEqual((r.returncode,r.stderr),(0,b''));self.assertEqual(F.files(out),expected);self.assertIsNone(json.loads(auth.read_bytes())['source'])
   self.assertEqual(p['after'],F.files(BASE));self.assertEqual(command([HERE/'apps14.py','--help']).returncode,0)
 def test_focused_emitted_observer_layers_cap_substrate_and_NULL_controls(self):
  with tempfile.TemporaryDirectory()as td:
   for selected in(False,True):
    root=Path(td)/str(selected);A.prepare(BASE,root,A.NAME,CARRIER if selected else None);args=[root/'apps16-repair/test_source.py','ObserverControls','Controls.test_whole14_13_12_210_layers_and_original120_plan_cap','Controls.test_null_profile_known_context_only_and_explicit_apps16_labels'];r=command(args,120);self.assertEqual(r.returncode,0,r.stderr.decode(errors='replace'));self.assertRegex(r.stderr,b'Ran 5 tests in ');self.assertNotRegex(r.stderr,rb'\b(?:FAILED|ERROR|skipped)\b');print('emitted focused5',('bound'if selected else'NULL'),'PASS',file=sys.stderr)
 def test_canonical_recipe17_join_and_early_late_recipe_carrier_drift(self):
  p,payload=A.inputs();self.assertEqual(len(p['recipe_files']),17);self.assertEqual(len(p['payload']),21);self.assertEqual(len(payload),38);self.assertEqual(F.files(A.RECIPE),p['recipe_files']);self.assertEqual({n:w for n,w in p['after'].items()if n.startswith(p['recipe_prefix'])},{p['recipe_prefix']+n:w for n,w in p['recipe_files'].items()})
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);recipe=root/'recipe';shutil.copytree(A.RECIPE,recipe);carrier=root/'carrier';shutil.copytree(CARRIER,carrier,ignore=shutil.ignore_patterns('.git'));leaf=recipe/'apps.py';raw=leaf.read_bytes()
   with patch.object(A,'RECIPE',recipe):
    leaf.write_bytes(raw+b'x')
    with self.assertRaises(ValueError):A.prepare(BASE,root/'early',A.NAME,CARRIER)
    self.assertFalse((root/'early').exists());leaf.write_bytes(raw);original=F.files;seen=[]
    def late(path):
     if path==recipe:
      seen.append(True)
      if len(seen)==2:leaf.write_bytes(raw+b'late')
     return original(path)
    with patch.object(F,'files',side_effect=late),self.assertRaisesRegex(ValueError,'fresh canonical recipe'):A.prepare(BASE,root/'late',A.NAME,CARRIER)
    self.assertFalse((root/'late').exists());leaf.write_bytes(raw)
   original=F.files;seen=[]
   def late(path):
    if path==carrier:
     seen.append(True)
     if len(seen)==2:(carrier/'foreign').write_bytes(b'x')
    return original(path)
   with patch.object(F,'files',side_effect=late),self.assertRaisesRegex(ValueError,'fresh carrier'):A.prepare(BASE,root/'carrier-late',A.NAME,carrier)
   self.assertFalse((root/'carrier-late').exists())
 def test_whole_source_control_custody_and_substrate_version_refusal(self):
  p,_=A.inputs();self.assertEqual(p['source_controls']['source_test_total'],44);self.assertIsNone(p['source_controls']['actual']);self.assertEqual(p['source_controls']['record']['historical_reader_or_actual_replay'],'NOT_RUN')
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);base=root/'base';shutil.copytree(BASE,base,ignore=shutil.ignore_patterns('.git'))
   for n in ['scripts/ci/maintained-desktop574-inputs.json','scripts/ci/apps7-full574-repair16k-ci/retained-cache-profile.json']:
    self.assertEqual(p['before'][n],p['after'][n]);leaf=base/n;raw=leaf.read_bytes();self.assertIn(b'hyprland-qt-support-0.1.0-14',raw);leaf.write_bytes(raw.replace(b'hyprland-qt-support-0.1.0-14',b'hyprland-qt-support-0.1.0-16'))
    with self.assertRaises(ValueError):A.prepare(base,root/'forbidden',A.NAME,CARRIER)
    self.assertFalse((root/'forbidden').exists());leaf.write_bytes(raw)
if __name__=='__main__':unittest.main(verbosity=2)

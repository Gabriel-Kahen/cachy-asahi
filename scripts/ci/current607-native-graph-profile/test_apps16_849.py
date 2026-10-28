# SPDX-License-Identifier: MIT
"""Portable finite849 route, whole source guards and prewrite hostile inputs."""
import argparse,ast,base64,importlib.util,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;p=argparse.ArgumentParser()
for n in('parent','expected','carrier','record','current606-record','codec-parent'):p.add_argument('--'+n,type=Path,required=True)
a,rest=p.parse_known_args();PARENT,EXPECTED,CARRIER,RECORD,CURRENT,CODEC_PARENT=(getattr(a,n).absolute()for n in('parent','expected','carrier','record','current606_record','codec_parent'))
def load(n,p):s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
M=load('_maintained_Apps16_849',HERE/'apps16_849.py');F=M.F;PROFILE,MAPS,_=M.inputs();C=load('_old842_unchanged',HERE/'installed_codec842.py')
def invoke(args):return subprocess.run([sys.executable,'-I','-B','-Werror',*map(str,args)],capture_output=True,cwd='/',timeout=90)
class Controls(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.tmp=tempfile.TemporaryDirectory();cls.root=Path(cls.tmp.name);cls.known=cls.root/'known';cls.null=cls.root/'null';M.emit(PARENT,cls.known,cls.root/'known.json',CARRIER,RECORD,CURRENT);M.emit(PARENT,cls.null,cls.root/'null.json',CARRIER,RECORD,CURRENT,True)
 @classmethod
 def tearDownClass(cls):cls.tmp.cleanup()
 def test_exact849_variants_whole842_inverse_and_ALL_security_clocks(self):
  self.assertEqual(F.files(self.known),F.files(EXPECTED));self.assertEqual(F.files(self.null),MAPS['unbound']);self.assertEqual(len(MAPS['before']),842)
  for root in(self.known,self.null):
   proof=json.loads((root/M.PROOF).read_bytes());self.assertEqual(proof['before'],MAPS['before']);self.assertEqual(len(proof['before_bodies']),10);self.assertEqual(len(proof['added']),7);actual=F.files(root);self.assertEqual(sum(actual.get(n)==w for n,w in MAPS['before'].items()),832)
   for n,b in proof['before_bodies'].items():self.assertEqual(base64.b64decode(b,validate=True),(PARENT/n).read_bytes())
   for n,edits in proof['edits'].items():
    text=(root/n).read_text()
    for before,after in reversed(edits):self.assertEqual(text.count(after),1);text=text.replace(after,before,1)
    self.assertEqual(text.encode(),(PARENT/n).read_bytes())
   self.assertTrue(all(proof[n]is None for n in('actual_source','actual_ref','actual_run','Root_acceptance')))
  self.assertEqual(PROFILE['passive_caps'],dict(source=300,strict=900,collector=900,separate_current606=300));self.assertIn(b'hyprland-qt-support 0.1.0-14',(self.known/M.I/'expected606.lock').read_bytes())
 def test_actual_source_preflight_both_variants_and_NULL_actor_refusal(self):
  for root in(self.known,self.null):
   r=invoke([root/M.I/'latest_run.py','--source-preflight']);self.assertEqual((r.returncode,r.stderr),(0,b''));q=json.loads(r.stdout);self.assertEqual((q['files'],q['transactions'],q['fresh_graphs'],q['auxiliary'],q['whole_real240_suites']),(849,32,65,33,4));self.assertIsNone(q['actual'])
  r=invoke([self.null/M.I/'latest_run.py','--require-selection']);self.assertNotEqual(r.returncode,0);self.assertIn(b'NULL Apps16',r.stderr)
 def test_actual_CLI_known_NULL_authorization_and_old842_route_parity(self):
  for null in(False,True):
   suffix='null'if null else'known';out=self.root/('cli-'+suffix);auth=self.root/('auth-'+suffix);argv=[HERE/'prepare.py','--profile','apps16_849_unbound'if null else'apps16_849','--source',PARENT,'--output',out,'--authorization',auth,'--apps16-carrier',CARRIER,'--apps16-record',RECORD,'--apps16-current606-record',CURRENT];r=invoke(argv);self.assertEqual((r.returncode,r.stderr,r.stdout),(0,b'',b''));q=json.loads(auth.read_bytes());self.assertEqual(q['files'],MAPS['unbound'if null else'selected']);self.assertTrue(all(q[n]is None for n in('source','ref','actual')));r=invoke(argv);self.assertNotEqual(r.returncode,0)
  out=self.root/'old842';auth=self.root/'old842.json';r=invoke([HERE/'prepare.py','--profile','installed_codec842','--source',CODEC_PARENT,'--output',out,'--authorization',auth]);self.assertEqual((r.returncode,r.stderr),(0,b''));self.assertEqual(F.files(out),F.files(PARENT));text=(HERE/'prepare.py').read_text();functions={n.name:F.pin(ast.get_source_segment(text,n).encode())for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)}
  for n,w in PROFILE['held_functions'].items():self.assertEqual(functions[n],w,n)
  self.assertEqual(len(functions),16)
 def test_missing_wrong_input_carrier_record_current606_and_early_drift(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);out=root/'never';auth=root/'receipt';args=[CARRIER,RECORD,CURRENT]
   for index in range(3):
    for bad in(None,PARENT):
     rows=args[:];rows[index]=bad
     with self.assertRaises(ValueError):M.emit(PARENT,out,auth,*rows)
     self.assertFalse(out.exists());self.assertFalse(auth.exists())
   for index,original in enumerate([PARENT,*args]):
    source=root/('input'+str(index));shutil.copytree(original,source,ignore=shutil.ignore_patterns('.git'));leaf=next(p for p in source.rglob('*')if p.is_file());leaf.write_bytes(leaf.read_bytes()+b'drift');values=[PARENT,*args];values[index]=source
    with self.assertRaises(ValueError):M.emit(values[0],out,auth,*values[1:])
    self.assertFalse(out.exists());self.assertFalse(auth.exists())
 def test_normalization_alias_hardlink_empty_directory_and_output_overlap(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);out=root/'never';auth=root/'receipt';alias=root/'alias';alias.symlink_to(CARRIER,target_is_directory=True)
   for source,dest,receipt,carrier in [(PARENT,out,auth,alias),(PARENT,CARRIER/'never',auth,CARRIER),(PARENT,out,RECORD/'never',CARRIER),(PARENT,out,out/'receipt',CARRIER),(PARENT,HERE/'never',auth,CARRIER),(PARENT,root/'missing/../never',auth,CARRIER)]:
    with self.assertRaises(ValueError):M.emit(source,dest,receipt,carrier,RECORD,CURRENT)
   src=root/'parent';shutil.copytree(PARENT,src,ignore=shutil.ignore_patterns('.git'));(src/'foreign-empty').mkdir()
   with self.assertRaises(ValueError):M.emit(src,out,auth,CARRIER,RECORD,CURRENT)
   (src/'foreign-empty').rmdir();leaf=src/M.I/'latest_validate.py';os.link(leaf,root/'hardlink')
   with self.assertRaises(ValueError):M.emit(src,out,auth,CARRIER,RECORD,CURRENT)
   self.assertFalse(out.exists());self.assertFalse(auth.exists())
 def test_readable_profile_payload_and_late_input_drift_before_writes(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);factory=root/'factory';shutil.copytree(HERE,factory);out=root/'never';auth=root/'receipt'
   for name in('apps16-849-profile.json','apps16-849-maps.json','apps16-849/apps16_inputs.py','apps16-849/apps16-null-inputs.json'):
    leaf=factory/name;raw=leaf.read_bytes();leaf.write_bytes(raw+b'drift')
    with patch.object(M,'HERE',factory),self.assertRaises(ValueError):M.emit(PARENT,out,auth,CARRIER,RECORD,CURRENT)
    leaf.write_bytes(raw);self.assertFalse(out.exists())
   src=root/'current606';shutil.copytree(CURRENT,src,ignore=shutil.ignore_patterns('.git'));real=M.closed;calls=0
   def late(path,wanted):
    nonlocal calls
    if path==src:
     calls+=1
     if calls==2:
      leaf=src/'index.json';leaf.write_bytes(leaf.read_bytes()+b'drift')
    return real(path,wanted)
   with patch.object(M,'closed',side_effect=late),self.assertRaises(ValueError):M.emit(PARENT,out,auth,CARRIER,RECORD,src)
   self.assertEqual(calls,2);self.assertFalse(out.exists());self.assertFalse(auth.exists())
if __name__=='__main__':unittest.main(argv=[sys.argv[0],*rest],verbosity=2)

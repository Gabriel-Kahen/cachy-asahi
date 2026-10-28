# SPDX-License-Identifier: MIT
"""Portable exact new outputs, held old route and fail-closed filesystem seams."""
import argparse,ast,base64,importlib.util,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;p=argparse.ArgumentParser()
for n in('parent','expected','cleanup','carrier'):p.add_argument('--'+n,type=Path,required=True)
a,rest=p.parse_known_args();PARENT,EXPECTED,CLEANUP,CARRIER=(getattr(a,n).absolute()for n in('parent','expected','cleanup','carrier'))
def load(n,p):s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
F=load('_maintained_restore_factory',HERE/'prepare.py');M=load('_restore604',HERE/'apps16_restore604.py');PROFILE,MAPS,_=M.inputs(F.__dict__)
class Controls(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.temp=tempfile.TemporaryDirectory();cls.root=Path(cls.temp.name);cls.oldnull=cls.root/'old-null';cls.null=cls.root/'null';cls.bound=cls.root/'bound';F.prepare_apps16(CLEANUP,cls.oldnull,True);F.prepare_apps16_restore604(cls.oldnull,cls.null,True);F.prepare_apps16_restore604(PARENT,cls.bound)
 @classmethod
 def tearDownClass(cls):cls.temp.cleanup()
 def test_exact_selected_NULL_and_unchanged_Apps16_routes(self):
  self.assertEqual(F.files(self.bound),F.files(EXPECTED));self.assertEqual({n:F.pin(b)for n,b in F.files(self.null).items()},MAPS['unbound'])
  out=self.root/'old-bound';F.prepare_apps16(CLEANUP,out,carrier=CARRIER);self.assertEqual(F.files(out),F.files(PARENT));self.assertEqual({n:F.pin(b)for n,b in F.files(self.oldnull).items()},MAPS['null_before'])
 def test_source_entry_and_original_positive_security_bodies(self):
  A=load('_trusted_restore_admission',self.bound/'admission.py');N=load('_trusted_restore_NULL',self.null/'admission.py')
  with patch.object(subprocess,'run',side_effect=AssertionError('NO_ACTORS')),patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS')):
   fact=A.prove(self.bound);self.assertEqual(fact['files'],562);self.assertEqual(fact['native_GUI'],'NOT_RUN')
   with self.assertRaisesRegex(ValueError,'BEFORE ACTORS'):N.prove(self.null)
  before=F.files(PARENT);after=F.files(self.bound);self.assertEqual(sum(after.get(n)==b for n,b in before.items()),558);ctx=json.loads(after['management-restore-parent.json']);self.assertEqual(ctx['files'],MAPS['before'])
  for n,b in ctx['before_bodies'].items():self.assertEqual(base64.b64decode(b,validate=True),before[n])
  self.assertEqual(after['admission.py'][:len(before['admission.py'])],before['admission.py']);self.assertEqual(before['factory/factory.py'].decode().replace(PROFILE['before_seam'],PROFILE['proposed_seam'],1).encode(),after['factory/factory.py'])
 def test_all25_functions_and_source_qualification_reuse(self):
  text=(HERE/'prepare.py').read_text();functions={n.name:F.pin(ast.get_source_segment(text,n).encode())for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)}
  self.assertEqual(len(PROFILE['held_functions']),25)
  for n,w in PROFILE['held_functions'].items():self.assertEqual(functions[n],w,n)
  for key in('source_qualification','reader_qualification'):
   q=PROFILE[key];self.assertEqual(q['exit'],0);self.assertEqual(q['cap'],300);self.assertLess(q['seconds'],300);self.assertFalse(q['retry']);self.assertFalse(q['timeout']);self.assertIsNone(q['actual'])
  self.assertEqual(F.profile()['output']['source'],'bb72a0fc5e84af5621f0b783056137efdd780282')
 def test_actual_isolated_CLI_both_variants_existing_output_and_no_credit(self):
  for flag,parent in [('--apps16-restore604',PARENT),('--apps16-restore604-unbound',self.oldnull)]:
   out=self.root/flag[2:];argv=[sys.executable,'-I','-B','-Werror',str(HERE/'prepare.py'),flag,'--predecessor-root',str(parent),'--output',str(out)];r=subprocess.run(argv,capture_output=True,cwd='/tmp',timeout=30);self.assertEqual(r.returncode,0,r.stderr);q=json.loads(r.stdout);self.assertEqual(q['files'],562);self.assertIsNone(q['actual_run']);self.assertEqual(F.files(out),F.files(self.null if flag.endswith('unbound')else self.bound));r=subprocess.run(argv,capture_output=True,timeout=30);self.assertNotEqual(r.returncode,0)
 def test_path_alias_wrong_variant_source_drift_hardlink_before_output(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);out=root/'never';alias=root/'alias';alias.symlink_to(PARENT,target_is_directory=True)
   for parent,dest,null in[(alias,out,False),(PARENT,PARENT/'never',False),(PARENT,root/'missing/../bad',False),(PARENT,out,True),(self.oldnull,out,False),(PARENT,out,1),(PARENT,HERE/'never',False)]:
    with self.assertRaises((ValueError,OSError)):M.emit(F.__dict__,parent,dest,null)
   src=root/'parent';shutil.copytree(PARENT,src,ignore=shutil.ignore_patterns('.git'));leaf=src/'native.py';raw=leaf.read_bytes();leaf.write_bytes(raw+b'drift')
   with self.assertRaises(ValueError):M.emit(F.__dict__,src,out)
   leaf.write_bytes(raw);os.link(leaf,root/'linked')
   with self.assertRaises(ValueError):M.emit(F.__dict__,src,out)
   self.assertFalse(out.exists());self.assertFalse((PARENT/'never').exists());self.assertFalse((HERE/'never').exists())
 def test_profile_payload_and_late_whole_input_drift(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);factory=root/'factory';shutil.copytree(HERE,factory);out=root/'never'
   for name in('apps16-restore604-profile.json','apps16-restore604-maps.json','apps16-restore604-payload/factory.py','apps16-restore604-payload/admission.fragment'):
    leaf=factory/name;raw=leaf.read_bytes();leaf.write_bytes(raw+b'drift')
    with patch.object(M,'HERE',factory),self.assertRaises(ValueError):M.emit(F.__dict__,PARENT,out)
    self.assertFalse(out.exists());leaf.write_bytes(raw)
   src=root/'parent';shutil.copytree(PARENT,src,ignore=shutil.ignore_patterns('.git'));calls=0;real=F.files
   def late(path):
    nonlocal calls
    if path==src:
     calls+=1
     if calls==2:(src/'native.py').write_bytes((src/'native.py').read_bytes()+b'drift')
    return real(path)
   with patch.dict(F.__dict__,files=late),self.assertRaisesRegex(ValueError,'revalidation'):M.emit(F.__dict__,src,out)
   self.assertEqual(calls,2);self.assertFalse(out.exists())
if __name__=='__main__':unittest.main(argv=[sys.argv[0],*rest],verbosity=2)

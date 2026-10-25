# SPDX-License-Identifier: MIT
"""Focused portable-factory controls; original runtime/source suites remain separate."""
import argparse,copy,importlib.util,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
D=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('_gui682_factory',D/'prepare.py');F=importlib.util.module_from_spec(s);s.loader.exec_module(F)
class Controls(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.q=F.inputs();cls.raw=F.files(ARGS.parent,admin=True);cls.expected=F.files(ARGS.expected,admin=True)
  assert F.table(cls.raw)==cls.q['before']['known']and F.table(cls.expected)==cls.q['after']['known']
 def test_exact_emission_and_finite_null_inverse(self):
  for mode in('known','null'):
   out=ARGS.workdir/('emit-'+mode);F.emit(ARGS.parent,out,mode);self.assertEqual(F.table(F.files(out)),self.q['after'][mode])
  self.assertEqual(F.files(ARGS.workdir/'emit-known'),self.expected)
 def test_canonical_disjoint_before_writes(self):
  for path in (ARGS.parent/'out',D/'out',ARGS.workdir/'a/../out',ARGS.workdir/'foreign-native-actual-1'/'out'):
   with self.assertRaises(ValueError):F.emit(ARGS.parent,path,'known')
   self.assertFalse(path.exists())
  alias=ARGS.workdir/'alias';alias.symlink_to(ARGS.workdir,target_is_directory=True)
  with self.assertRaises(ValueError):F.emit(ARGS.parent,alias/'out','known')
 def test_existing_and_publication_output_refuse(self):
  for path in(ARGS.workdir,ARGS.workdir/'test-trial-root-1'/'out'):
   with self.assertRaises(ValueError):F.emit(ARGS.parent,path,'known')
 def test_foreign_extra_symlink_and_nested_git(self):
  root=ARGS.workdir/'bad';root.mkdir();(root/'foreign').write_text('x')
  with self.assertRaises(ValueError):F.emit(root,ARGS.workdir/'bad-out','known')
  (root/'foreign').unlink();(root/'foreign').symlink_to(D/'prepare.py')
  with self.assertRaises(ValueError):F.files(root,admin=True)
  (root/'foreign').unlink();(root/'nested').mkdir();(root/'nested/.git').mkdir()
  with self.assertRaises(ValueError):F.files(root,admin=True)
 def test_typed_unbinding_drift_and_complete_maps(self):
  bad=dict(self.raw);n='parent574/apps16_common.py';bad[n]+=b'\n'
  with self.assertRaises(ValueError):F.unbind(bad,self.q)
  q=copy.deepcopy(self.q);q['after']['known']['implementation/native.py']['sha256']='0'*64
  with self.assertRaises(ValueError):F.compose(self.raw,'known',q)
  row=next(x for x in json.loads(F.read(D/'unbound.json')).values()if x['patch']['kind']=='json');op=copy.deepcopy(row['patch']);op['body']=dict(kind='value',before=F.pin(b'wrong'),after=None)
  with self.assertRaises(ValueError):F.patch_bytes(b'{}',op)
 def test_late_drift_and_preimport_operand_refusal(self):
  out=ARGS.workdir/'late';calls=0;held=F.files
  def drift(root,admin=False):
   nonlocal calls
   v=held(root,admin);calls+=1
   if calls==2:v['foreign']=b'x'
   return v
  with patch.object(F,'files',side_effect=drift):
   with self.assertRaises(ValueError):F.emit(ARGS.parent,out,'known')
  self.assertFalse(out.exists())
  heldread=F.read
  def changed(p):return heldread(p)+b'x'if Path(p)==D/'payload/observer_apply.py'else heldread(p)
  with patch.object(F,'read',side_effect=changed),patch.object(F.importlib.util,'spec_from_file_location',side_effect=AssertionError('must refuse before import')):
   with self.assertRaises(ValueError):F.emit(ARGS.parent,out,'known')
 def test_pure_current_guard_and_null_refusal(self):
  for mode in('known','null'):
   root=ARGS.workdir/('pure-'+mode);F.emit(ARGS.parent,root,mode)
   code="import sys;sys.path.insert(0,sys.argv[1]);import observer_guard as G;print(G.verify(require_known=True))"
   r=subprocess.run([sys.executable,'-I','-B','-c',code,str(root/'implementation')],capture_output=True,timeout=20)
   if mode=='known':self.assertEqual(r.returncode,0,r.stderr.decode())
   else:self.assertNotEqual(r.returncode,0);self.assertIn(b'UNBOUND NULL',r.stderr)
 def test_original_command_geometry_is_fixed(self):
  import shlex
  raw=self.expected['.github/workflows/native-arm-build.yml'].decode();line=next(x for x in raw.splitlines()if '\"run\":'in x and 'preflight\\n'in x);commands=json.loads(line.strip().split(': ',1)[1]).splitlines()
  self.assertEqual(len(commands),5);self.assertEqual(len(set(commands)),5)
  words=[shlex.split(x)for x in commands];self.assertEqual(words[1],['python3','-I','-B','gui607-source/implementation/presecret_control.py','--control','apps16-common','--apps16-inputs','$GITHUB_WORKSPACE/apps16-inputs']);self.assertEqual(words[2][-1],'gui607-source/parent574/service_controls.py')
 def test_first_read_can_update_access_time(self):
  p=ARGS.workdir/'first-read';p.write_bytes(b'first source read')
  os.utime(p,ns=(0,p.stat().st_mtime_ns));before=p.stat()
  self.assertEqual(F.read(p),b'first source read')
  self.assertEqual(F.identity(before),F.identity(p.stat()))
 def test_descriptor_rejects_real_during_read_mutation(self):
  p=ARGS.workdir/'during-read';p.write_bytes(b'original source')
  original=F.os.fdopen
  class MutatingRead:
   def __init__(self,stream):self.stream=stream
   def __enter__(self):return self
   def __exit__(self,*args):self.stream.close()
   def fileno(self):return self.stream.fileno()
   def read(self,size):
    value=self.stream.read(size);p.write_bytes(b'changed content');return value
  def opened(*args,**kwargs):return MutatingRead(original(*args,**kwargs))
  before=len(list(Path('/proc/self/fd').iterdir()))
  with patch.object(F.os,'fdopen',side_effect=opened):
   with self.assertRaisesRegex(ValueError,'stable source input'):F.read(p)
  self.assertEqual(len(list(Path('/proc/self/fd').iterdir())),before)
 def test_real_isolated_cli_help(self):
  r=subprocess.run([sys.executable,'-I','-B',str(D/'prepare.py'),'--help'],capture_output=True,timeout=10)
  self.assertEqual(r.returncode,0);self.assertIn(b'--context {known,null}',r.stdout)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--parent',type=Path,required=True);p.add_argument('--expected',type=Path,required=True);p.add_argument('--workdir',type=Path,required=True);ARGS=p.parse_args();ARGS.parent=F.canonical(ARGS.parent);ARGS.expected=F.canonical(ARGS.expected);ARGS.workdir=F.canonical(ARGS.workdir);F.need(not ARGS.workdir.exists()and ARGS.workdir.parent.is_dir(),'fresh test workdir');ARGS.workdir.mkdir(mode=0o700);unittest.main(argv=[sys.argv[0]],verbosity=2)

#!/usr/bin/env python3
"""Real private full-graph equality, ancestry/identity/refusal and timing custody."""
import ctypes,hashlib,importlib.util,json,os,stat,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
D=Path(__file__).resolve().parent;SOURCE=D;sys.path.insert(0,str(D/'ancestry'))
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
G=load('whole_original_graph',D/'testdata/package_graph.py');OLD=load('old_descriptor',SOURCE/'latest_descriptor.py');NEW=load('new_descriptor',D/'ancestry/latest_descriptor.py');A=load('fresh_ancestry',D/'ancestry/latest_ancestry.py');T=load('new_timing',D/'ancestry/latest_graph_timing.py');RAW=(D/'testdata/package_graph.py').read_bytes();old=OLD.bind(G,RAW);new=NEW.bind(G,RAW)
FLAGS=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
def fixture(root,count=128):
 for n in('usr/bin','usr/share/doc','usr/share/licenses','var/lib/pacman/local/fixture-1-1','etc','home','root'):(root/n).mkdir(parents=True,exist_ok=True)
 db=root/'var/lib/pacman/local';(db/'ALPM_DB_VERSION').write_bytes(b'9\n')
 for leaf in('desc','files','mtree'):(db/'fixture-1-1'/leaf).write_bytes(('whole '+leaf+'\n').encode())
 files=[]
 for n in range(count):
  name='usr/lib/depth/branch'+str(n%16)+'/layer/tool'+str(n);p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes((str(n)+' whole graph hash\n').encode()*128);files.append(name)
 os.link(root/files[0],root/'usr/bin/hardlink');files.append('usr/bin/hardlink');(root/'etc/sentinel').write_bytes(b'whole configuration\n');(root/'home/alias').symlink_to('../etc/sentinel')
 return [dict(name='fixture',version='1-1',arch='any',depend=[],provides=[],conflict=[],files=files)]
def resolver(root):
 def rootfd():return os.open(root,FLAGS)
 def original(name):
  fd=rootfd()
  try:
   for part in name.split('/')[:-1]:
    child=os.open(part,FLAGS,dir_fd=fd);os.close(fd);fd=child
   return fd
  except BaseException:os.close(fd);raise
 return original,rootfd,A.parent_query(original,rootfd,FLAGS,lambda:None)
class Controls(unittest.TestCase):
 def test_complete_graph_hash_mount_hardlink_alias_equal(self):
  with tempfile.TemporaryDirectory(dir=D)as tmp:
   root=Path(tmp);packages=fixture(root);deadline=time.monotonic()+60;a=old(root,packages,deadline=deadline);b=new(root,packages,deadline=deadline);self.assertEqual(a,b);self.assertEqual(len(b['hardlinks']),1);self.assertIn('parent_mount_id',b['nodes']['home/alias']);self.assertEqual(b['nodes']['etc/sentinel']['sha256'],hashlib.sha256(b'whole configuration\n').hexdigest())
 def test_fresh_edit_and_outside_hardlink_refuse(self):
  with tempfile.TemporaryDirectory(dir=D)as tmp:
   root=Path(tmp);packages=fixture(root);deadline=time.monotonic()+60;a=new(root,packages,deadline=deadline);(root/'etc/sentinel').write_bytes(b'changed\n');b=new(root,packages,deadline=deadline)
   with self.assertRaises(ValueError):G.protected(a,b,lock_witness={})
   os.link(root/'etc/sentinel',root/'outside-observed')
   with self.assertRaisesRegex(ValueError,'hardlink aliases outside'):new(root,packages,deadline=deadline)
 def test_ancestry_no_alias_and_mount_crossing(self):
  with tempfile.TemporaryDirectory(dir=D)as tmp:
   root=Path(tmp);(root/'real').mkdir();(root/'alias').symlink_to('real');original,_,query=resolver(root)
   for f in(original,query):
    with self.assertRaises(OSError):f('alias/leaf')
   original,_,query=resolver(Path('/'));a=original('proc/version');b=query('proc/version')
   try:self.assertEqual(G.key(os.fstat(a)),G.key(os.fstat(b)))
   finally:os.close(a);os.close(b)
 def test_private_body_fallback_deadline_and_unknown_capability(self):
  with self.assertRaises(ValueError):NEW.bind(G,RAW+b'\n')
  self.assertIsNot(new.__globals__,vars(G));self.assertIs(new.__globals__['selected'],G.selected)
  with tempfile.TemporaryDirectory(dir=D)as tmp:
   root=Path(tmp);packages=fixture(root);original,rootfd,_=resolver(root)
   with patch.object(ctypes,'CDLL',return_value=object()):fallback=A.parent_query(original,rootfd,FLAGS,lambda:None)
   a=fallback('usr/lib/x');b=original('usr/lib/x')
   try:self.assertEqual(G.key(os.fstat(a)),G.key(os.fstat(b)))
   finally:os.close(a);os.close(b)
   with self.assertRaisesRegex(ValueError,'deadline'):new(root,packages,deadline=time.monotonic()-1)
   with patch.object(os,'getxattr',side_effect=PermissionError(13,'unknown capability')):
    with self.assertRaises(PermissionError):new(root,packages,deadline=time.monotonic()+60)
 def test_rebinding_during_fresh_hash_refused_and_descriptors_retired(self):
  with tempfile.TemporaryDirectory(dir=D)as tmp:
   root=Path(tmp);packages=fixture(root);read=os.read;changed=[];before=len(list(Path('/proc/self/fd').iterdir()))
   def mutate(fd,n):
    raw=read(fd,n)
    if raw and not changed:(root/'etc/sentinel').write_bytes(b'rebound during hash\n');changed.append(True)
    return raw
   with patch.object(os,'read',side_effect=mutate):
    with self.assertRaises(ValueError):new(root,packages,deadline=time.monotonic()+60)
   self.assertTrue(changed);self.assertEqual(len(list(Path('/proc/self/fd').iterdir())),before)
 def test_public_timing_inode_projection_under_private_umask(self):
  with tempfile.TemporaryDirectory(dir=D)as tmp:
   p=Path(tmp)/'latest607-graph-timing.json';before=os.umask(0o077)
   try:t=T.GraphTiming(p,'a'*32,time.monotonic()+60,lambda:'baseline606')
   finally:os.umask(before)
   self.assertEqual(stat.S_IMODE(p.stat().st_mode),0o644);before=G.key(p.stat());t.wrap(lambda *a,**kw:dict(nodes={},bytes_read=0))('/',[],deadline=t.deadline);self.assertEqual(p.stat().st_ino,before[1]);v=json.loads(p.read_bytes());self.assertFalse(v['actual_authority']);self.assertEqual(v['observations'][0]['state'],'COMPLETE')
if __name__=='__main__':unittest.main(verbosity=2)

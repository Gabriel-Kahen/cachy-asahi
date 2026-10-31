# SPDX-License-Identifier: MIT
"""Maintained cache-join controls. Package authentication stays with original code."""
import importlib.util,json,os,tempfile,time,unittest
from pathlib import Path
D=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('retained_seed',D/'seed.py');S=importlib.util.module_from_spec(spec);spec.loader.exec_module(S)
class Controls(unittest.TestCase):
 def test_full_original_lock_profiles(self):
  native=json.loads((D/'native-inputs.lock.json').read_bytes());desktop=json.loads((D/'desktop574-inputs.lock.json').read_bytes());n,_=S.rows(native);d,_=S.rows(desktop);index=json.loads((D/'index.json').read_bytes());self.assertEqual(len(n),496);self.assertEqual(len(d),1148);self.assertEqual(d,index['files']);self.assertTrue(all(d.get(k)==v for k,v in n.items()))
 def test_join_preserves_previous_inodes_metadata_and_bytes(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);cache=root/'cache';cache.mkdir(mode=0o700);packages=root/'packages';packages.mkdir();(cache/'old').write_bytes(b'old');(packages/'new').write_bytes(b'new');before=S.exact(cache/'old',S.pin(b'old'),time.monotonic()+30,True)
   result=S.join(cache,packages,{'new':S.pin(b'new')},{'new':S.pin(b'new'),'old':S.pin(b'old')},time.monotonic()+30);self.assertEqual(result['added'],1);self.assertEqual(S.exact(cache/'old',S.pin(b'old'),time.monotonic()+30,True),before);self.assertTrue(result['all_previous_inode_metadata_bytes_unchanged'])
 def test_foreign_links_and_deadline_refuse_before_copy(self):
  for kind in('foreign','symlink','hardlink','deadline'):
   with tempfile.TemporaryDirectory()as td:
    root=Path(td);cache=root/'cache';cache.mkdir(mode=0o700);packages=root/'packages';packages.mkdir();(cache/'old').write_bytes(b'old');(packages/'new').write_bytes(b'new')
    if kind=='foreign':(cache/'foreign').write_bytes(b'x')
    if kind=='symlink':(cache/'old').unlink();(cache/'old').symlink_to(packages/'new')
    if kind=='hardlink':os.link(cache/'old',root/'link')
    with self.assertRaises(ValueError):S.join(cache,packages,{'new':S.pin(b'new')},{'old':S.pin(b'old'),'new':S.pin(b'new')},time.monotonic()-1 if kind=='deadline'else time.monotonic()+30)
    self.assertFalse((cache/'new').exists())
 def test_real_relatime_updates_only_atime(self):
  with tempfile.TemporaryDirectory(dir='/dev/shm')as td:
   p=Path(td)/'read';p.write_bytes(b'exact');os.utime(p,ns=(1,2));a=p.stat();S.exact(p,S.pin(b'exact'),time.monotonic()+30,True);b=p.stat();self.assertGreater(b.st_atime_ns,a.st_atime_ns);self.assertEqual(S.IDENTITY(a),S.IDENTITY(b))
if __name__=='__main__':unittest.main(verbosity=2)

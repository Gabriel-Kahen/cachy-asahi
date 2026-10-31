"""Real private graph equivalence/security controls, x86 diagnostics only."""
from pathlib import Path
import hashlib,importlib.util,json,os,stat,tempfile,time,unittest
from unittest.mock import patch
D=Path(__file__).resolve().parent;SRC=D/'testdata/package_graph.py'
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
Q=load('latest_descriptor',D/'latest_descriptor.py');T=load('latest_graph_timing',D/'latest_graph_timing.py');G=load('_held_complete_graph',SRC);RAW=SRC.read_bytes();fresh=Q.bind(G,RAW)
def fixture(root):
 for n in('usr/bin','usr/share/doc','usr/share/licenses','var/lib/pacman/local/fixture-1-1','etc','home','root'): (root/n).mkdir(parents=True,exist_ok=True)
 db=root/'var/lib/pacman/local';(db/'ALPM_DB_VERSION').write_bytes(b'9\n')
 for leaf in('desc','files','mtree'):(db/'fixture-1-1'/leaf).write_bytes(('full '+leaf+'\n').encode())
 files=[]
 for n in range(128):
  name='usr/bin/tool'+str(n);(root/name).write_bytes((str(n)+' whole hash payload\n').encode());files.append(name)
 os.link(root/files[0],root/'usr/bin/hardlink');files.append('usr/bin/hardlink');(root/'etc/sentinel').write_bytes(b'whole config\n');(root/'home/alias').symlink_to('../etc/sentinel')
 return [dict(name='fixture',version='1-1',arch='any',depend=[],provides=[],conflict=[],files=files)]
class Controls(unittest.TestCase):
 def test_real_complete_graph_equal_all_hash_mount_identity_alias_hardlinks(self):
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);packages=fixture(root);deadline=time.monotonic()+30;old=G.capture(root,packages,deadline=deadline);new=fresh(root,packages,deadline=deadline);self.assertEqual(old,new);self.assertEqual(len(new['hardlinks']),1);self.assertIn('parent_mount_id',new['nodes']['home/alias']);self.assertEqual(new['nodes']['etc/sentinel']['sha256'],hashlib.sha256(b'whole config\n').hexdigest())
 def test_real_changed_protected_payload_and_capability_error_not_hidden(self):
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);packages=fixture(root);deadline=time.monotonic()+30;before=fresh(root,packages,deadline=deadline);(root/'etc/sentinel').write_bytes(b'drift\n');after=fresh(root,packages,deadline=deadline)
   with self.assertRaises(ValueError):G.protected(before,after,lock_witness={})
   with patch.object(os,'getxattr',side_effect=PermissionError(13,'forbidden')):
    with self.assertRaises(PermissionError):fresh(root,packages,deadline=deadline)
 def test_fresh_descriptor_queries_fallback_and_expired_budget(self):
  import ctypes
  with tempfile.TemporaryDirectory()as tmp:
   p=Path(tmp)/'file';p.write_bytes(b'x');fd=os.open(p,os.O_RDONLY);calls=[]
   def old(descriptor):
    calls.append(descriptor);rows=[r.split(b':')[1].strip()for r in Path('/proc/self/fdinfo/'+str(descriptor)).read_bytes().splitlines()if r.startswith(b'mnt_id:')];return int(rows[0])
   try:
    ticks=[];query=Q.mount_query(old,lambda:ticks.append(1));want=old(fd);self.assertEqual(query(fd),want);self.assertEqual(query(fd),want);self.assertEqual(len(ticks),2)
    with patch.object(ctypes,'CDLL',return_value=object()):fallback=Q.mount_query(old,lambda:None);self.assertEqual(fallback(fd),want)
    def expired():raise TimeoutError('original deadline')
    with self.assertRaises(TimeoutError):Q.mount_query(old,expired)(fd)
   finally:os.close(fd)
 def test_complete_graph_body_pin_and_current_call_selected_globals(self):
  with self.assertRaises(ValueError):Q.bind(G,RAW+b'\n')
  # One selected scope update must be inherited when the private capture binds.
  saved=G.SELECTED_FILES
  try:
   G.SELECTED_FILES=frozenset({'etc/sentinel'});private=Q.bind(G,RAW)
   self.assertEqual(private.__globals__['SELECTED_FILES'],G.SELECTED_FILES);self.assertIs(private.__globals__['selected'],G.selected)
  finally:G.SELECTED_FILES=saved
 def test_bounded_timing_same_deadline_complete_and_exception_data(self):
  with tempfile.TemporaryDirectory()as tmp:
   path=Path(tmp)/'latest607-graph-timing.json';deadline=time.monotonic()+30;phase=['baseline606'];timing=T.GraphTiming(path,'a'*32,deadline,lambda:phase[0]);capture=timing.wrap(lambda root,packages,**kw:dict(nodes={'x':{}},bytes_read=1));self.assertEqual(capture('/',[],deadline=deadline)['bytes_read'],1);v=json.loads(path.read_bytes());self.assertEqual(v['observations'][0]['state'],'COMPLETE');self.assertEqual(v['original_deadline'],deadline);self.assertFalse(v['actual_authority'])
   with self.assertRaises(ValueError):capture('/',[],deadline=deadline+1)
   def failed(*a,**kw):raise RuntimeError('sentinel')
   with self.assertRaisesRegex(RuntimeError,'sentinel'):timing.wrap(failed)('/',[],deadline=deadline)
   self.assertEqual(json.loads(path.read_bytes())['observations'][-1]['state'],'FAILED')
if __name__=='__main__':unittest.main(verbosity=2)

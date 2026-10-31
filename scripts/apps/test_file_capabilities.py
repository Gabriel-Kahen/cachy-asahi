#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded format, graph and actual tempfile controls; never execute capped files."""
import errno,hashlib,importlib.util,os,struct,sys,tempfile,time,unittest
from pathlib import Path
from types import SimpleNamespace
sys.dont_write_bytecode=True
spec=importlib.util.spec_from_file_location('apps_file_capabilities',Path(__file__).with_name('file_capabilities.py'))
C=importlib.util.module_from_spec(spec);sys.modules[spec.name]=C;spec.loader.exec_module(C)
RAW=bytes.fromhex('0100000240000000000000000000000000000000')
def limits(**changes):
 values=dict(max_nodes=100,max_depth=8,max_bytes=1024**2,max_file_bytes=65536,max_hardlink_groups=8,max_hardlink_aliases=16,max_hardlink_members=8)
 values.update(changes);until=time.monotonic()+5
 def tick():
  if time.monotonic()>until:raise ValueError('test deadline')
 return SimpleNamespace(tick=tick,**values)
def row(path):
 info=path.lstat();value=dict(mode=info.st_mode&0o7777,uid=info.st_uid,gid=info.st_gid)
 if path.is_symlink():value.update(type='symlink',target=os.readlink(path))
 elif path.is_dir():value.update(type='directory')
 else:
  raw=path.read_bytes();value.update(type='file',bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
 return value
def graph(root):return {str(p.relative_to(root)):row(p) for p in sorted(root.rglob('*'))}
def user_xattr(test,path):
 try:os.setxattr(path,'user.fixture',b'bounded test',follow_symlinks=False)
 except OSError as error:
  if error.errno in (errno.ENOTSUP,errno.EOPNOTSUPP):test.skipTest('filesystem lacks user xattrs')
  raise

class Format(unittest.TestCase):
 def test_known_newgidmap_revision2(self):
  self.assertEqual(C.validate(RAW),dict(revision=2,effective=True,permitted=64,inheritable=0,rootid=None))
 def test_revision3_rootid_and_high_words(self):
  raw=struct.pack('<6I',0x03000000,1,2,4,8,1000)
  self.assertEqual(C.validate(raw),dict(revision=3,effective=False,permitted=1+(4<<32),inheritable=2+(8<<32),rootid=1000))
 def test_revision3_rootid_zero_is_valid(self):
  self.assertEqual(C.validate(struct.pack('<I',0x03000001)+RAW[4:]+struct.pack('<I',0))['rootid'],0)
 def test_bad_lengths_revisions_reserved_flags_and_rootid_refuse(self):
  bad=[b'',RAW[:-1],RAW+b'\0',RAW+b'\0'*4,struct.pack('<I',0x01000001)+RAW[4:],struct.pack('<I',0x02000003)+RAW[4:],struct.pack('<I',0x03000001)+RAW[4:]+b'\xff'*4,struct.pack('<I',0x04000001)+RAW[4:]]
  for raw in bad:
   with self.subTest(raw=raw.hex()),self.assertRaises((ValueError,TypeError)):C.validate(raw)
 def test_nonbytes_refuse(self):
  for raw in (None,RAW.hex(),list(RAW),20):
   with self.subTest(raw=raw),self.assertRaises((ValueError,TypeError)):C.validate(raw)
 def test_pax_roundtrip_preserves_binary_surrogates(self):
  raw=struct.pack('<I',0x03000001)+RAW[4:]+struct.pack('<I',0xfffffffe)
  self.assertEqual(C.pax_value(raw.decode('utf8','surrogateescape')),raw)
 def test_pax_invalid_capability_or_unicode_refuses(self):
  for text in ('not capability bytes','\ud800',RAW.hex()):
   with self.subTest(text=text),self.assertRaises((ValueError,TypeError)):C.pax_value(text)

class TempGraphs(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(prefix='apps-cap-data-');self.root=Path(self.temp.name);(self.root/'dir').mkdir();(self.root/'dir/file').write_bytes(b'inert capability test; never execute\n')
 def tearDown(self):self.temp.cleanup()
 def test_map_requires_canonical_lowercase_hex(self):
  nodes=graph(self.root);raw=struct.pack('<I',0x03000001)+RAW[4:]+struct.pack('<I',0xfffffffe)
  self.assertEqual(C.validate_map(nodes,{'dir/file':raw.hex()},limits()),{'dir/file':raw.hex()})
  with self.assertRaises(ValueError):C.validate_map(nodes,{'dir/file':raw.hex().upper()},limits())
 def test_caps_only_regular_known_files(self):
  nodes=graph(self.root);(self.root/'link').symlink_to('dir/file');nodes=graph(self.root)
  for name in ('dir','link','missing','../escape','/absolute'):
   with self.subTest(name=name),self.assertRaises((ValueError,TypeError)):C.validate_map(nodes,{name:RAW.hex()},limits())
 def test_map_rejects_malformed_hex_and_caps(self):
  for value in ('xyz',RAW.hex()+'00','',None,RAW.hex()+'\n',' '.join(f'{b:02x}' for b in RAW)):
   with self.subTest(value=value),self.assertRaises((ValueError,TypeError)):C.validate_map(graph(self.root),{'dir/file':value},limits())
 def test_graph_and_map_bounds(self):
  nodes=graph(self.root)
  for bound in (dict(max_nodes=1),dict(max_depth=0),dict(max_bytes=1),dict(max_file_bytes=1)):
   with self.subTest(bound=bound),self.assertRaises(ValueError):C.validate_map(nodes,{'dir/file':RAW.hex()},limits(**bound))
 def test_hardlink_aliases_require_identical_complete_capabilities(self):
  os.link(self.root/'dir/file',self.root/'dir/alias');nodes=graph(self.root)
  for name in ('dir/file','dir/alias'):nodes[name]['hardlink_group']='dir/alias'
  good={'dir/file':RAW.hex(),'dir/alias':RAW.hex()};self.assertEqual(C.validate_map(nodes,good,limits()),good)
  other=struct.pack('<I',0x02000000)+RAW[4:]
  for mapping in ({'dir/file':RAW.hex()},{'dir/file':RAW.hex(),'dir/alias':other.hex()}):
   with self.subTest(mapping=mapping),self.assertRaises(ValueError):C.validate_map(nodes,mapping,limits())
 def test_observe_complete_empty_map_and_restore_empty(self):
  nodes=graph(self.root);self.assertEqual(C.observe(self.root,nodes,limits()),{});self.assertEqual(C.restore(self.root,nodes,{},limits()),{})
 def test_metadata_drift_refuses(self):
  nodes=graph(self.root);(self.root/'dir/file').chmod(0o600)
  with self.assertRaises(ValueError):C.observe(self.root,nodes,limits())
 def test_unknown_xattrs_on_file_directory_and_root_refuse(self):
  for relative in ('dir/file','dir',''):
   target=self.root/relative;user_xattr(self,target)
   with self.subTest(relative=relative),self.assertRaises(ValueError):C.observe(self.root,graph(self.root),limits())
   os.removexattr(target,'user.fixture',follow_symlinks=False)
 def test_restore_refuses_unexpected_existing_attribute(self):
  user_xattr(self,self.root/'dir/file')
  with self.assertRaises(ValueError):C.restore(self.root,graph(self.root),{},limits())
  self.assertEqual(os.getxattr(self.root/'dir/file','user.fixture'),b'bounded test')
 def test_external_symlink_target_is_never_followed(self):
  with tempfile.TemporaryDirectory(prefix='apps-cap-victim-') as temp:
   victim=Path(temp)/'file';victim.write_bytes(b'untouched');user_xattr(self,victim)
   (self.root/'escape').symlink_to(victim)
   self.assertEqual(C.observe(self.root,graph(self.root),limits()),{})
   self.assertEqual(victim.read_bytes(),b'untouched');self.assertEqual(os.getxattr(victim,'user.fixture'),b'bounded test')
 def test_directory_replaced_by_symlink_refuses(self):
  nodes=graph(self.root)
  with tempfile.TemporaryDirectory(prefix='apps-cap-victim-') as temp:
   victim=Path(temp);(victim/'file').write_bytes((self.root/'dir/file').read_bytes());(self.root/'dir/file').unlink();(self.root/'dir').rmdir();(self.root/'dir').symlink_to(victim,target_is_directory=True)
   with self.assertRaises((ValueError,OSError)):C.observe(self.root,nodes,limits())
   self.assertEqual(os.listxattr(victim/'file'),[])
 def test_closed_graph_refuses_unlisted_files(self):
  nodes=graph(self.root);(self.root/'unlisted').write_bytes(b'not in owner graph')
  with self.assertRaises(ValueError):C.observe(self.root,nodes,limits())
 def test_unclosed_or_forged_hardlinks_refuse(self):
  os.link(self.root/'dir/file',self.root/'dir/alias');nodes=graph(self.root)
  with self.assertRaises(ValueError):C.observe(self.root,nodes,limits())
  for name in ('dir/file','dir/alias'):nodes[name]['hardlink_group']='dir/alias'
  self.assertEqual(C.observe(self.root,nodes,limits()),{})
  del nodes['dir/alias']
  with self.assertRaises(ValueError):C.observe(self.root,nodes,limits())
 def test_deadline_failure_precedes_writes(self):
  budget=limits();budget.tick=lambda:(_ for _ in ()).throw(ValueError('expired'))
  with self.assertRaises(ValueError):C.restore(self.root,graph(self.root),{'dir/file':RAW.hex()},budget)
  self.assertEqual(os.listxattr(self.root/'dir/file'),[])
 def test_restore_live_root_refused(self):
  with self.assertRaises(ValueError):C.restore(Path('/'),{}, {},limits())

if __name__=='__main__':unittest.main(verbosity=2)

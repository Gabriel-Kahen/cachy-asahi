#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Unprivileged rootfs DATA models and complete337 Source inverse; no actor."""
import ast,copy,hashlib,importlib.util,io,json,os,shutil,stat,sys,tarfile,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent

def module(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
P=module('v11_source_constructor_DATA',HERE/'prepare.py');N=module('v11_bootstrap_FENCED',HERE/'payload/hosted/bootstrap.py');OLD=module('held_old_bootstrap_FENCED',HERE.parent/'successor_v5/payload/hosted/bootstrap.py');V10=module('v10_test_support_FENCED',HERE.parent/'successor_v10/test_data.py')

def fence(event,args):
 if event.startswith(('socket.','subprocess.'))or event in('os.system','os.exec','os.fork','os.posix_spawn','fcntl.flock'):raise AssertionError('FENCED no actor/network/lease '+event)
sys.addaudithook(fence)
BODY=b'FENCED execute-only DATA; never executed\n'

def tar_model(path,rows):
 with tarfile.open(path,'w',format=tarfile.USTAR_FORMAT)as archive:
  for kind,name,mode,body in rows:
   item=tarfile.TarInfo(name);item.uid=item.gid=0;item.mode=mode
   if kind=='dir':item.type=tarfile.DIRTYPE;archive.addfile(item)
   elif kind in('link','hard'):item.type=tarfile.SYMTYPE if kind=='link'else tarfile.LNKTYPE;item.linkname=body;archive.addfile(item)
   elif kind=='fifo':item.type=tarfile.FIFOTYPE;archive.addfile(item)
   else:item.size=len(body);archive.addfile(item,io.BytesIO(body))

def basic(mode=0o644,dir_mode=0o755):return [('dir','usr',0o755,b''),('dir','usr/lib',dir_mode,b''),('file','usr/lib/dbus-daemon-launch-helper',mode,BODY)]
def expected_basic(mode,dir_mode=0o755):
 rows=[['usr','dir',0o755,''],['usr/lib','dir',dir_mode,''],['usr/lib/dbus-daemon-launch-helper','file',mode,hashlib.sha256(BODY).hexdigest()]]
 return hashlib.sha256(b''.join((json.dumps(r,separators=(',',':'))+'\n').encode()for r in rows)).hexdigest()
def parent_model():
 before=V10.parent_model()
 with patch.object(V10.P,'PARENT',V10.P.identity(before)):return V10.P.render(before)

class RootfsControls(unittest.TestCase):
 def test_old_failure_class_reproduced_unprivileged_after_complete_extraction(self):
  self.assertNotEqual(os.getuid(),0,'MODEL must run unprivileged')
  with tempfile.TemporaryDirectory(prefix='FENCED-v11-old-')as temp:
   root=Path(temp);tar_model(root/'rootfs.tar',basic(0o111));result=OLD.extract_rootfs(root/'rootfs.tar',root/'rootfs',time.monotonic()+10);self.assertEqual(result['files'],3);p=root/'rootfs/usr/lib/dbus-daemon-launch-helper';self.assertEqual(p.stat().st_uid,os.getuid());self.assertEqual(stat.S_IMODE(p.stat().st_mode),0o111)
   with self.assertRaises(PermissionError)as error:OLD.tree_digest(root/'rootfs')
   self.assertEqual(error.exception.errno,13)
 def test_same_canonical_digest_byte_parity_for_readable_files_dirs_and_links(self):
  with tempfile.TemporaryDirectory(prefix='FENCED-v11-parity-')as temp:
   root=Path(temp);rows=basic(0o4755)+[('hard','usr/lib/copy',0o644,'usr/lib/dbus-daemon-launch-helper'),('link','usr/link',0o777,'lib/dbus-daemon-launch-helper')];tar_model(root/'rootfs.tar',rows);old=OLD.extract_rootfs(root/'rootfs.tar',root/'old',time.monotonic()+10);new=N.extract_rootfs(root/'rootfs.tar',root/'new',time.monotonic()+10)
   self.assertEqual({k:new[k]for k in('files','logical_bytes')},old);self.assertEqual(new['rootfs_tree_sha256'],OLD.tree_digest(root/'old'));self.assertEqual(OLD.tree_digest(root/'new'),OLD.tree_digest(root/'old'));self.assertTrue(new['final_modes_verified']);self.assertEqual(new['digest_timing'],'PRIVATE_READABLE_STAGING_BEFORE_EXACT_MODE_FINALIZATION')
 def test_execute_only_and_zero_mode_files_hash_before_exact_final_mode(self):
  for mode in(0o111,0o4111,0o000):
   with self.subTest(mode=oct(mode)),tempfile.TemporaryDirectory(prefix='FENCED-v11-mode-')as temp:
    root=Path(temp);tar_model(root/'rootfs.tar',basic(mode));result=N.extract_rootfs(root/'rootfs.tar',root/'rootfs',time.monotonic()+10);p=root/'rootfs/usr/lib/dbus-daemon-launch-helper';self.assertEqual(stat.S_IMODE(p.stat().st_mode),mode);self.assertEqual(result['rootfs_tree_sha256'],expected_basic(mode))
    with self.assertRaises(PermissionError):OLD.tree_digest(root/'rootfs')
 def test_unreadable_directory_preserved_and_hash_is_not_postmode_rehash(self):
  with tempfile.TemporaryDirectory(prefix='FENCED-v11-dir-')as temp:
   root=Path(temp);tar_model(root/'rootfs.tar',basic(0o111,0));result=N.extract_rootfs(root/'rootfs.tar',root/'rootfs',time.monotonic()+10);p=root/'rootfs/usr/lib'
   try:self.assertEqual(stat.S_IMODE(p.stat().st_mode),0);self.assertEqual(result['rootfs_tree_sha256'],expected_basic(0o111,0));self.assertTrue(result['final_modes_verified'])
   finally:p.chmod(0o700) # Only this known, self-owned MODEL directory for cleanup.
 def test_hardlink_of_execute_only_source_copies_before_original_modes(self):
  with tempfile.TemporaryDirectory(prefix='FENCED-v11-hard-')as temp:
   root=Path(temp);rows=basic(0o111)+[('hard','usr/lib/copy',0o000,'usr/lib/dbus-daemon-launch-helper')];tar_model(root/'rootfs.tar',rows);result=N.extract_rootfs(root/'rootfs.tar',root/'rootfs',time.monotonic()+10);one=root/'rootfs/usr/lib/dbus-daemon-launch-helper';two=root/'rootfs/usr/lib/copy';self.assertEqual(stat.S_IMODE(one.stat().st_mode),0o111);self.assertEqual(stat.S_IMODE(two.stat().st_mode),0);self.assertNotEqual(one.stat().st_ino,two.stat().st_ino);self.assertEqual(one.stat().st_nlink,two.stat().st_nlink,1);self.assertEqual(result['logical_bytes'],2*len(BODY))
 def test_each_original_mode_is_applied_once_via_owned_descriptor(self):
  with tempfile.TemporaryDirectory(prefix='FENCED-v11-once-')as temp:
   root=Path(temp);tar_model(root/'rootfs.tar',basic(0o111));real=os.fchmod;calls=[]
   def record(fd,mode):calls.append((os.fstat(fd).st_ino,mode));return real(fd,mode)
   with patch.object(N.os,'fchmod',side_effect=record):N.extract_rootfs(root/'rootfs.tar',root/'rootfs',time.monotonic()+10)
   self.assertEqual(len(calls),3);self.assertEqual(len({ino for ino,mode in calls}),3);self.assertEqual(sorted(mode for ino,mode in calls),[0o111,0o755,0o755])
 def test_mutation_during_hash_or_before_final_modes_refuses(self):
  for when in('during','after','extra','inode'):
   with self.subTest(when=when),tempfile.TemporaryDirectory(prefix='FENCED-v11-mutate-')as temp:
    root=Path(temp);tar_model(root/'rootfs.tar',basic(0o111));real_sha=N.sha;real_tree=N.tree_digest
    def changed_sha(path,tick=lambda:None):
     result=real_sha(path,tick);path.write_bytes(b'FENCED changed');return result
    def changed_tree(path,*args):
     result=real_tree(path,*args)
     if when=='extra':(path/'extra').write_bytes(b'FENCED')
     elif when=='inode':
      replacement=path/'replacement';replacement.write_bytes(BODY);os.replace(replacement,path/'usr/lib/dbus-daemon-launch-helper')
     else:(path/'usr/lib/dbus-daemon-launch-helper').write_bytes(b'FENCED changed')
     return result
    with patch.object(N,'sha',side_effect=changed_sha)if when=='during'else patch.object(N,'tree_digest',side_effect=changed_tree):
     with self.assertRaises(ValueError):N.extract_rootfs(root/'rootfs.tar',root/'rootfs',time.monotonic()+10)
 def test_wrong_final_mode_or_changed_inode_refuses(self):
  with tempfile.TemporaryDirectory(prefix='FENCED-v11-final-')as temp:
   root=Path(temp);tar_model(root/'rootfs.tar',basic(0o111))
   with patch.object(N.os,'fchmod',return_value=None),self.assertRaises(ValueError):N.extract_rootfs(root/'rootfs.tar',root/'rootfs',time.monotonic()+10)
 def test_cancellation_deadline_and_truncated_tar_refuse(self):
  for kind in('cancel','deadline','truncated','tail'):
   with self.subTest(kind=kind),tempfile.TemporaryDirectory(prefix='FENCED-v11-refuse-')as temp:
    root=Path(temp);tar_model(root/'rootfs.tar',basic());tick=lambda:None;deadline=time.monotonic()+10
    if kind=='cancel':
     def tick():raise ValueError('FENCED cancellation')
    elif kind=='deadline':deadline=time.monotonic()-1
    elif kind=='truncated':(root/'rootfs.tar').write_bytes((root/'rootfs.tar').read_bytes()[:1600])
    else:(root/'rootfs.tar').write_bytes((root/'rootfs.tar').read_bytes()+b'FENCED nonzero tail')
    with self.assertRaises((ValueError,tarfile.TarError,EOFError)):N.extract_rootfs(root/'rootfs.tar',root/'rootfs',deadline,tick)
 def test_alias_escape_and_special_nodes_refuse(self):
  for row in(('file','../escape',0o644,BODY),('hard','escape',0o644,'../outside'),('fifo','special',0o644,b'')):
   with tempfile.TemporaryDirectory(prefix='FENCED-v11-alias-')as temp:
    root=Path(temp);tar_model(root/'rootfs.tar',[row])
    with self.assertRaises((ValueError,OSError)):N.extract_rootfs(root/'rootfs.tar',root/'rootfs',time.monotonic()+10)

class SourceControls(unittest.TestCase):
 def test_complete337_inverse_and_all_outside_bootstrap_unchanged(self):
  before=parent_model();parent=P.identity(before)
  with patch.object(P,'PARENT',parent):
   after=P.render(before);self.assertEqual(P.undo(after),before)
   for name,row in before.items():
    if name not in P.REPLACED|{'source-map.json'}:self.assertEqual(after[name],row,name)
   self.assertEqual(set(after)-set(before),{P.MARKER}|{P.ARCHIVE+n for n in P.REPLACED|{'source-map.json'}})
 def test_install_image_actor_http_budget_and_canonical_hash_format_preserved(self):
  before=parent_model();P.check_delta(before,P.fs.snapshot(HERE/'payload'));old,new=Path(OLD.__file__).read_text(),Path(N.__file__).read_text()
  for name in('normal_dockerfile','build_base','bounded_info','end_tar','inspect_image','retire','copy_data'):
   fn=lambda text:ast.get_source_segment(text,next(n for n in ast.parse(text).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))and n.name==name));self.assertEqual(fn(old),fn(new),name)
  self.assertIn("rootfs_tree_sha256=report['extraction']['rootfs_tree_sha256']",new);self.assertNotIn('sudo',new)
 def test_parent_tamper_and_profile_fresh_output_refuse(self):
  before=parent_model();parent=P.identity(before)
  with tempfile.TemporaryDirectory(prefix='FENCED-v11-constructor-')as temp:
   root=Path(temp);base=root/'parent';V10.V9.write(before,base);constructor=root/'constructor';constructor.mkdir();shutil.copytree(HERE/'payload',constructor/'payload')
   with patch.object(P,'PARENT',parent),patch.object(P,'HERE',constructor):
    files=P.render(before);profile=dict(schema=11,scope=P.SCOPE,parent=parent,actual=P.ACTUAL,Root_review=None,accepted=None,unadmitted=True,constructor_files=P.inputs(),**P.identity(files));raw=P.encode(profile);(constructor/'constructor-profile.json').write_bytes(raw);sha=P.fs.pin(raw)['sha256']
    with self.assertRaises(ValueError):P.construct(base,root/'bad','0'*64)
    self.assertTrue(P.construct(base,root/'output',sha)['unadmitted']);self.assertEqual(P.fs.snapshot(root/'output'),files)
    with self.assertRaises((ValueError,OSError)):P.construct(base,root/'output',sha)
    after=P.render(before);after['resource-policy.json']=(after['resource-policy.json'][0]+b'\n',0o644)
    with self.assertRaises(ValueError):P.undo(after)

 def test_current_complete_source_gate_and_unissued_profile(self):
  before=parent_model();parent=P.identity(before)
  with tempfile.TemporaryDirectory(prefix='FENCED-v11-map-gate-')as temp,patch.object(P,'PARENT',parent):
   files=P.render(before);root=Path(temp)/'source';V10.V9.write(files,root);entry=module('v11_current_source_gate_FENCED',root/'hosted/entry.py');entry.source_gate(root,P.identity(files)['map_sha256']);(root/'hosted/bootstrap.py').write_bytes(files['hosted/bootstrap.py'][0]+b'\n')
   with self.assertRaises(ValueError):entry.source_gate(root,P.identity(files)['map_sha256'])
  v=json.loads((HERE/'constructor-profile.json').read_bytes());self.assertEqual(v['schema'],11);self.assertEqual(v['files'],340);self.assertEqual(v['actual'],P.ACTUAL);self.assertIsNone(v['Root_review']);self.assertIsNone(v['accepted']);self.assertEqual(v['constructor_files'],P.inputs())

if __name__=='__main__':unittest.main(verbosity=2)

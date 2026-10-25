# SPDX-License-Identifier: MIT
"""Private plain-tree/refusal controls; never fabricate accepted606 actors."""
import copy,json,os,struct,subprocess,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
import bridge as B
ROOT=next(p for p in Path(__file__).resolve().parents if (p/'scripts/update/full_root.py').is_file())
OWNER=ROOT/'scripts/ci/current606-welcome5-closed-owner/selection.py'
if not OWNER.is_file():OWNER=next(p/'trusted-owner/selection.py' for p in Path(__file__).resolve().parents if (p/'trusted-owner/selection.py').is_file())

class Controls(unittest.TestCase):
 @classmethod
 def setUpClass(cls):cls.api=B.load_apis(ROOT)
 def setUp(self):
  p=patch.object(subprocess,'Popen',side_effect=AssertionError('no actors/network/Git'));p.start();self.addCleanup(p.stop)
 def limits(self):return self.api.roots.Limits(deadline=time.monotonic()+30,max_packages=2,max_nodes=200,max_bytes=1024**2,max_file_bytes=512*1024,max_package_files=20)
 def fixture(self,base):
  base.chmod(0o700);source=base/'source';source.mkdir();(source/'usr/bin').mkdir(parents=True);(source/'etc').mkdir()
  (source/'usr/bin/private').write_bytes(b'PRIVATE_INERT_SOURCE_NEVER_EXECUTED');os.link(source/'usr/bin/private',source/'usr/bin/alias');(source/'literal').symlink_to('usr/bin/private')
  for n in self.api.scope.RUNTIME:(source/n).mkdir()
  (source/'tmp/ephemeral').write_bytes(b'NOT_PACKAGE_OWNED_RUNTIME_CONTENT')
  db=source/'var/lib/pacman/local';(db/'fixture-1-1').mkdir(parents=True);(db/'ALPM_DB_VERSION').write_bytes(b'9\n')
  (db/'fixture-1-1/desc').write_bytes(b'%NAME%\nfixture\n\n%VERSION%\n1-1\n\n%ARCH%\nany\n')
  (db/'fixture-1-1/files').write_bytes(b'%FILES%\nusr/bin/private\nusr/bin/alias\nliteral\n')
  root=self.api.roots._open_root(source)
  try:mount=self.api.roots._mount_id(root,self.limits())
  finally:os.close(root)
  policy=dict(source_mount=mount,target_mount=mount,observed_mounts=[])
  return source,base/'stage',policy
 def capture(self,base):
  source,target,policy=self.fixture(base);r=B._materialize(source,target,self.api,self.limits(),{'fixture':'1-1'},policy,self.api.scope._mount_table());return source,target,r
 def test_real_private_tree_raw_database_hardlinks_symlinks_and_source_identity(self):
  with tempfile.TemporaryDirectory(dir='/tmp')as td:
   source,target,r=self.capture(Path(td));self.assertTrue(r['projection']['source_preserved']);self.assertFalse(r['projection']['capabilities_restored'])
   self.assertEqual(r['observation']['nodes']['usr/bin/alias']['hardlink_group'],'usr/bin/alias');self.assertEqual((target/'usr/bin/alias').stat().st_ino,(target/'usr/bin/private').stat().st_ino)
   self.assertNotEqual((source/'usr/bin/private').stat().st_ino,(target/'usr/bin/private').stat().st_ino);self.assertEqual(os.readlink(target/'literal'),'usr/bin/private')
   self.assertEqual(list((target/'tmp').iterdir()),[]);self.assertEqual((source/'tmp/ephemeral').read_bytes(),b'NOT_PACKAGE_OWNED_RUNTIME_CONTENT')
   self.assertEqual((source/'var/lib/pacman/local/fixture-1-1/desc').read_bytes(),(target/'var/lib/pacman/local/fixture-1-1/desc').read_bytes())
   actual,caps=B._restore_and_observe(target,r,self.api,self.limits());self.assertEqual(actual['nodes'],r['observation']['nodes']);self.assertEqual(caps,{})
 def test_unknown_user_xattr_refuses_before_copy(self):
  with tempfile.TemporaryDirectory(dir='/tmp')as td:
   source,target,policy=self.fixture(Path(td));os.setxattr(source/'usr/bin/private','user.unreviewed',b'NOT_DROPPED')
   with self.assertRaisesRegex(ValueError,'unknown xattr'):B._materialize(source,target,self.api,self.limits(),{'fixture':'1-1'},policy,self.api.scope._mount_table())
   self.assertFalse(target.exists());self.assertEqual(os.getxattr(source/'usr/bin/private','user.unreviewed'),b'NOT_DROPPED')
 def test_external_hardlink_and_owned_omitted_payload_refuse(self):
  for mode in ('external-link','runtime-owned'):
   with self.subTest(mode=mode),tempfile.TemporaryDirectory(dir='/tmp')as td:
    base=Path(td);source,target,policy=self.fixture(base)
    if mode=='external-link':os.link(source/'usr/bin/private',base/'external')
    else:(source/'var/lib/pacman/local/fixture-1-1/files').write_bytes(b'%FILES%\ntmp/ephemeral\n')
    with self.assertRaises(ValueError):B._materialize(source,target,self.api,self.limits(),{'fixture':'1-1'},policy,self.api.scope._mount_table())
    self.assertFalse(target.exists())
 def test_changed_inventory_and_actual_mount_table_refuse(self):
  for mode in ('inventory','mount-table'):
   with self.subTest(mode=mode),tempfile.TemporaryDirectory(dir='/tmp')as td:
    source,target,policy=self.fixture(Path(td));expected={'fixture':'wrong'}if mode=='inventory'else{'fixture':'1-1'};raw='WRONG_MOUNT_TABLE'if mode=='mount-table'else self.api.scope._mount_table()
    with self.assertRaises(ValueError):B._materialize(source,target,self.api,self.limits(),expected,policy,raw)
 def test_stage_rebind_and_payload_tampering_refuse(self):
  for mode in ('inode','payload'):
   with self.subTest(mode=mode),tempfile.TemporaryDirectory(dir='/tmp')as td:
    source,target,r=self.capture(Path(td))
    if mode=='inode':r['projection']['root_identity'][1]+=1
    else:(target/'usr/bin/private').write_bytes(b'CHANGED')
    with self.assertRaises(ValueError):B._restore_and_observe(target,r,self.api,self.limits())
 def test_nonempty_capability_restore_requires_real_missing_privilege(self):
  # This ordinary process is deliberately incapable of claiming the native
  # five-cap profile. The actual kernel, not a mocked setter, must refuse.
  status=Path('/proc/self/status').read_text();self.assertIn('CapEff:\t0000000000000000',status)
  with tempfile.TemporaryDirectory(dir='/tmp')as td:
   source,target,r=self.capture(Path(td));value=struct.pack('<5I',0x02000001,1<<10,0,0,0);r['capabilities']={n:value.hex() for n in ('usr/bin/alias','usr/bin/private')}
   with self.assertRaises(PermissionError):B._restore_and_observe(target,r,self.api,self.limits())
   self.assertNotIn('security.capability',os.listxattr(target/'usr/bin/private'));self.assertTrue(target.exists())
 def test_default_gate_refuses_all_actual_routes_before_mutation(self):
  selection=B.decode(B.read(B.HERE/'selection.json'));self.assertTrue(all(v is None for v in selection['current606'].values()));self.assertTrue(all(selection[k]is None for k in ('actual_source','actual_ref','actual_run','capture_receipt','nonce')))
  for call in (B.capture,B.finalize,B.dispose):
   with patch.object(B,'actor_guard',side_effect=AssertionError('must not reach actors')),self.assertRaisesRegex(ValueError,'UNBOUND606'):call(selection,'a'*32,ROOT,self.limits())
  fake=dict(selection,status='ROOT_BOUND_CURRENT606_APPS7_INPUTS',purpose='CURRENT606_APPS7_CLOSED_NATIVE');original=B.read;code=OWNER.read_bytes()
  def fixed(path,*args):return code if Path(path)==Path('/runner/owner/selection.py')else original(path,*args)
  with patch.object(B,'read',side_effect=fixed),self.assertRaisesRegex(ValueError,'NULL/UNBOUND'):B.authority(fake,'capture','a'*32)
  with patch.object(B,'read',side_effect=lambda path,*args:code+b' 'if Path(path)==Path('/runner/owner/selection.py')else original(path,*args)),self.assertRaisesRegex(ValueError,'owner API differs'):B.authority(fake,'capture','a'*32)
 def test_unknown_mount_and_tmpfs_stage_refuse(self):
  rows=[dict(id=1,path='/',fs='overlay'),dict(id=2,path='/measurement',fs='ext4'),dict(id=3,path='/unreviewed',fs='ext4')]
  with self.assertRaisesRegex(ValueError,'unrecognized source mount'):self.api.scope.mount_policy(Path('/'),B.STAGE,rows)
  rows=[dict(id=1,path='/',fs='overlay'),dict(id=2,path='/measurement',fs='tmpfs')]
  with self.assertRaisesRegex(ValueError,'disk-backed'):self.api.scope.mount_policy(Path('/'),B.STAGE,rows)
 def test_helper_source_tamper_and_duplicate_json_refuse(self):
  import shutil
  with self.assertRaisesRegex(ValueError,'duplicate'):B.decode(b'{"nonce":1,"nonce":2}')
  with tempfile.TemporaryDirectory(dir='/tmp')as td:
   root=Path(td)
   with self.assertRaises(FileNotFoundError):B.load_apis(root)
  with tempfile.TemporaryDirectory(dir='/tmp')as td:
   root=Path(td)/'changed'
   for name in B.decode(B.read(B.HERE/'source-pins.json'))['files']:
    path=root/name;path.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/name,path)
   path=root/'scripts/update/full_root.py';path.write_bytes(path.read_bytes()+b'\n# changed source\n')
   with self.assertRaisesRegex(ValueError,'whole source differs'):B.load_apis(root)
 def test_actor_profile_values_exclude_admin_ptrace_and_old_six_held(self):
  self.assertEqual(B.MASKS,dict(capture=0xdb,bridge=0x8000001b,worker=0x800400db))
  for mask in B.MASKS.values():self.assertFalse(mask&(1<<21|1<<19))
  self.assertEqual(B.MASKS['worker']^B.MASKS['capture'],1<<18|1<<31)
  with self.assertRaisesRegex(ValueError,'dedicated native root PID1'):B.actor_guard('bridge','a'*32)
 def test_created_stage_marker_runs_before_any_payload_write(self):
  with tempfile.TemporaryDirectory(dir='/tmp')as td:
   base=Path(td);source,target,policy=self.fixture(base);seen=[]
   def created(path):
    self.assertEqual(path,target);self.assertEqual(list(path.iterdir()),[]);seen.append([path.stat().st_dev,path.stat().st_ino]);raise RuntimeError('inert copy failure after stage identity reserved')
   with self.assertRaisesRegex(RuntimeError,'identity reserved'):B._materialize(source,target,self.api,self.limits(),{'fixture':'1-1'},policy,self.api.scope._mount_table(),created=created)
   self.assertEqual(len(seen),1);self.assertTrue(target.is_dir());B.remove_owned_tree(target,seen[0],self.api,self.limits());self.assertFalse(target.exists());self.assertTrue((source/'usr/bin/private').exists())
 def test_original_fd_cleanup_unlinks_literal_symlink_without_following(self):
  with tempfile.TemporaryDirectory(dir='/tmp')as td:
   source,target,r=self.capture(Path(td));outside=Path(td)/'outside';outside.write_bytes(b'UNTOUCHED_EXTERNAL');(target/'outside-alias').symlink_to(outside)
   B.remove_owned_tree(target,[target.stat().st_dev,target.stat().st_ino],self.api,self.limits());self.assertFalse(target.exists());self.assertEqual(outside.read_bytes(),b'UNTOUCHED_EXTERNAL')
 def test_cleanup_identity_and_special_nodes_refuse_before_deletion(self):
  for mode in ('identity','fifo'):
   with self.subTest(mode=mode),tempfile.TemporaryDirectory(dir='/tmp')as td:
    source,target,r=self.capture(Path(td));identity=[target.stat().st_dev,target.stat().st_ino]
    if mode=='identity':identity[1]+=1
    else:os.mkfifo(target/'unexpected')
    with self.assertRaises(ValueError):B.remove_owned_tree(target,identity,self.api,self.limits())
    self.assertEqual((target/'usr/bin/private').read_bytes(),b'PRIVATE_INERT_SOURCE_NEVER_EXECUTED')
 def test_missing_lease_cannot_chown_or_create_measurement(self):
  with patch.object(os,'chown',side_effect=AssertionError('no mutation before lease')),self.assertRaisesRegex(ValueError,'lease UNSUPPLIED'):B.owned_measurement({},'a'*32)
  for record in (None,{},dict(nonce='b'*32,prior_consumers_absent=True),dict(nonce='a'*32,prior_consumers_absent=False)):
   with self.assertRaisesRegex(ValueError,'retirement UNSUPPLIED'):B.prior_retirement(dict(retirement=record),'a'*32)
 def test_real_bounded_small_receipt_export_has_no_maps_and_refuses_alias_overwrite(self):
  # Writer-only inert private fixture; this context is never actor admission.
  with tempfile.TemporaryDirectory(dir='/tmp')as td:
   root=Path(td);root.chmod(0o700);info=root.stat();context=dict(nonce='a'*32,source_native='UNIT_NOT_A_NATIVE_SOURCE',source_run=0,output=dict(identity=[info.st_dev,info.st_ino],uid=info.st_uid,gid=info.st_gid,mode=0o700))
   value=dict(status='CAPTURED_NOT_FINALIZED',nonce=context['nonce'],source_native=context['source_native'],source_run=0,stage_identity=[0]*9,native_acceptance='NOT_GRANTED',maps={n:dict(bytes=1,sha256='b'*64)for n in('observation','packages','capabilities','projection')})
   with patch.object(B,'OUTPUT',root):
    row=B.export_small_receipt('bridge-capture.json',value,context);path=root/'bridge-capture.json';self.assertEqual(B.pin(path.read_bytes()),row);self.assertEqual(path.stat().st_mode&0o7777,0o644);self.assertEqual(root.stat().st_mode&0o7777,0o700);self.assertNotIn('PRIVATE_INERT_SOURCE',path.read_text())
    with self.assertRaises(FileExistsError):B.export_small_receipt('bridge-capture.json',value,context)
    with self.assertRaisesRegex(ValueError,'small receipt schema'):B.export_small_receipt('arbitrary-user-file',value,context)
    changed=copy.deepcopy(value);changed['maps']['observation']['raw_private_data']='MUST_NOT_EXPORT'
    with self.assertRaisesRegex(ValueError,'map pins only'):B.export_small_receipt('bridge-capture.json',changed,context)
    path.unlink();outside=root/'outside';outside.write_bytes(b'NOT_OVERWRITTEN');path.symlink_to(outside)
    with self.assertRaises(FileExistsError):B.export_small_receipt('bridge-capture.json',value,context)
    self.assertEqual(outside.read_bytes(),b'NOT_OVERWRITTEN')

class MountBoundaryControls(unittest.TestCase):
 @classmethod
 def setUpClass(cls):cls.api=B.load_apis(ROOT)
 limits=Controls.limits
 fixture=Controls.fixture
 def test_original_mount_policy_to_scoped_caps_projects_runtime_descendants_only(self):
  rows=[dict(id=1,path='/',fs='overlay')]+[dict(id=i+2,path='/'+n,fs='ext4')for i,n in enumerate(sorted(B.INFRA))]+[dict(id=50,path='/dev/pts',fs='devpts'),dict(id=51,path='/proc/sys',fs='proc'),dict(id=52,path='/sys/fs/cgroup',fs='cgroup2')]
  policy=self.api.scope.mount_policy(Path('/'),B.STAGE,rows)
  self.assertIn('dev/pts',policy['observed_mounts']);omitted=set(policy['observed_mounts'])|self.api.scope.RUNTIME
  # This is precisely the original failing predicate; no fabricated native data.
  self.assertFalse(omitted<=B.INFRA|self.api.scope.RUNTIME|self.api.scope.MOUNT_FILES)
  result=B.scoped_caps(self.api,omitted,self.limits())
  self.assertEqual(result.OMITTED,B.INFRA|self.api.scope.RUNTIME)
  self.assertEqual(result.MOUNT_FILES,self.api.scope.MOUNT_FILES)
 def test_real_small_tree_runtime_projection_preserves_complete_data_db_caps_identities(self):
  with patch.object(subprocess,'Popen',side_effect=AssertionError('no actors/network/Git')),tempfile.TemporaryDirectory(dir='/tmp')as td:
   base=Path(td);source,target,policy=self.fixture(base);raw=self.api.scope._mount_table()
   old=B._materialize(source,target,self.api,self.limits(),{'fixture':'1-1'},policy,raw)
   policy=dict(policy,observed_mounts=['dev/pts','proc/sys','sys/fs/cgroup','tmp/nested'])
   new=B._materialize(source,base/'stage-nested',self.api,self.limits(),{'fixture':'1-1'},policy,raw)
   for key in('packages','capabilities'):self.assertEqual(old[key],new[key])
   for key in('nodes','complete','eligible','unsupported_counts'):self.assertEqual(old['observation'][key],new['observation'][key])
   for key in('source_node_identities','excluded','owned_paths','source_preserved'):self.assertEqual(old['projection'][key],new['projection'][key])
   self.assertEqual((source/'tmp/ephemeral').read_bytes(),b'NOT_PACKAGE_OWNED_RUNTIME_CONTENT');self.assertEqual(list((base/'stage-nested/tmp').iterdir()),[])
 def test_unknown_persistent_and_infrastructure_descendant_alias_control_depth_refuse(self):
  for name in('etc/private','measurement/nested','runner/hidden','dev/../escape','dev//pts','dev/./pts','/dev/pts','dev/pts/','dev/\x00bad','dev/\nname','dev/\x7fname','dev/back\\slash','dev/'+'x/'*129+'leaf'):
   with self.subTest(name=name),self.assertRaises(ValueError):B.scoped_caps(self.api,{name},self.limits())
  rows=[dict(id=1,path='/',fs='overlay'),dict(id=2,path='/measurement',fs='ext4'),dict(id=3,path='/etc/private',fs='ext4')]
  with self.assertRaisesRegex(ValueError,'unrecognized source mount'):self.api.scope.mount_policy(Path('/'),B.STAGE,rows)
  files=self.api.scope.MOUNT_FILES;result=B.scoped_caps(self.api,set(files),self.limits());self.assertEqual(result.OMITTED,set());self.assertEqual(result.MOUNT_FILES,files)

if __name__=='__main__':unittest.main(verbosity=2)

#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Data/control tests. Never invoke Docker, QEMU or guest executables."""
import base64,contextlib,copy,hashlib,importlib.util,io,json,os,signal,socket,subprocess,sys,tarfile,tempfile,time,unittest
from pathlib import Path
from unittest.mock import Mock,patch
HERE=Path(__file__).resolve().parent


def load(name):
 spec=importlib.util.spec_from_file_location('arm16k_test_'+name,HERE/(name+'.py'))
 module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


b=load('boot');a=load('assemble');d=load('inspect_inputs');s=load('select_guest');p=load('prepare')
NONCE='1'*32;CID='a'*64;IMAGE='sha256:'+'b'*64
FRAME=('TCG_LOGIN_BEGIN '+NONCE+'\nUID=1000\nUSERNAME=builder\nPID1=systemd\nARCH=aarch64\nPAGESIZE=16384\nXDG_SESSION_ID=1\nId=1\nName=builder\nUser=1000\nClass=user\nType=tty\nService=login\nRemote=no\nLeader=55\nActive=yes\nState=active\nLOGIND=active\nDBUS=active\nTCG_LOGIN_END '+NONCE+'\n').encode()


class Data(unittest.TestCase):
 def test_frozen_primitives_exact(self):
  for name,ref in json.loads((HERE/'frozen/origin.json').read_text()).items():
   file=HERE/'frozen'/name;self.assertEqual(file.stat().st_size,ref['bytes']);self.assertEqual(p.sha(file),ref['sha256'])
 def test_kernel_rejects_changed_config_or_image(self):
  with tempfile.TemporaryDirectory()as tmp:
   image=Path(tmp)/'Image';image.write_bytes(b'not a kernel');config=Path(tmp)/'config';config.write_text('CONFIG_ARM64_16K_PAGES=y\n')
   with self.assertRaisesRegex(ValueError,'pin differs'):d.kernel(image,config)
 def test_symlink_material_refused(self):
  with tempfile.TemporaryDirectory()as tmp:
   x=Path(tmp)/'x';x.write_text('data');y=Path(tmp)/'y';y.symlink_to(x)
   with self.assertRaisesRegex(ValueError,'ordinary material'):d.pin(y)
 def test_rootfs_wrong_archive_refused_before_parse(self):
  with tempfile.NamedTemporaryFile()as f:
   with self.assertRaisesRegex(ValueError,'exact ALARM'):d.rootfs(Path(f.name))
 def test_required_kernel_features_include_console_disk_and_systemd(self):
  self.assertTrue({'ARM64_16K_PAGES','CGROUPS','FHANDLE','VIRTIO_MMIO','VIRTIO_BLK','EXT4_FS','SERIAL_AMBA_PL011_CONSOLE'}<=set(d.REQUIRED))
 def test_derived_symlink_ancestor_never_followed(self):
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp)/'root';root.mkdir();outside=Path(tmp)/'outside';outside.mkdir();(root/'escape').symlink_to(outside)
   with patch.object(a,'R',root),self.assertRaisesRegex(ValueError,'symlink ancestor'):a.parents('escape/data')
   self.assertEqual(list(outside.iterdir()),[])
 def test_exact_original_duplicate_capability_formats(self):
  item=tarfile.TarInfo('usr/bin/newuidmap');raw=bytes.fromhex(a.CAPABILITIES[item.name])
  item.pax_headers={'SCHILY.xattr.security.capability':raw.decode('utf-8','surrogateescape'),'LIBARCHIVE.xattr.security.capability':base64.b64encode(raw).decode().rstrip('=')}
  self.assertEqual(a.capability(item,item.name),raw)
  for mutation in ('different','missing','unknown','symlink'):
   test=copy.deepcopy(item)
   if mutation=='different':test.pax_headers['LIBARCHIVE.xattr.security.capability']='eA'
   if mutation=='missing':del test.pax_headers['LIBARCHIVE.xattr.security.capability']
   if mutation=='unknown':test.pax_headers['SCHILY.xattr.user.extra']='x'
   if mutation=='symlink':test.type=tarfile.SYMTYPE
   with self.subTest(mutation=mutation),self.assertRaises(ValueError):a.capability(test,test.name)
 def test_journal_acl_is_numeric_exact_and_never_host_name_resolved(self):
  item=tarfile.TarInfo('var/log/journal');item.type=tarfile.DIRTYPE;item.pax_headers=dict(a.JOURNAL_ACLS)
  values=a.extended_metadata(item,item.name);self.assertEqual(set(values),{'system.posix_acl_access','system.posix_acl_default'})
  self.assertEqual(values['system.posix_acl_access'].hex(),'0200000001000700ffffffff04000500ffffffff08000500e603000008000500e703000010000500ffffffff20000500ffffffff')
  item.pax_headers['SCHILY.acl.access']=a.JOURNAL_ACLS['SCHILY.acl.access'].replace('998','1000')
  with self.assertRaisesRegex(ValueError,'ACL differs'):a.extended_metadata(item,item.name)
 def test_ext4_ignored_ids_can_change_but_named_groups_permissions_cannot(self):
  raw=bytearray(a.JOURNAL_ACL_BYTES)
  for offset in (8,16,40,48):raw[offset:offset+4]=b'\0'*4
  self.assertEqual(a.acl_entries(bytes(raw)),a.acl_entries(a.JOURNAL_ACL_BYTES))
  raw[24:28]=(1000).to_bytes(4,'little');self.assertNotEqual(a.acl_entries(bytes(raw)),a.acl_entries(a.JOURNAL_ACL_BYTES))
  with self.assertRaisesRegex(ValueError,'layout'):a.acl_entries(b'bad')
 def test_declared_whole_package_closure_requires_payload(self):
  index={'nodes':{},'packages':{'demo-1':{'desc':{'NAME':['demo'],'VERSION':['1'],'DEPENDS':[]},'files':{'FILES':['usr/bin/demo']}}}}
  with patch.object(s,'TARGETS',('demo',)),self.assertRaisesRegex(ValueError,'payload absent'):s.select(index)
 def test_missing_provider_never_invented(self):
  with patch.object(s,'TARGETS',('absent>=1',)),self.assertRaisesRegex(ValueError,'missing/ambiguous'):s.select({'nodes':{},'packages':{}})
 def test_versioned_provides_forward_versions_to_alpm(self):
  # Modeled ABI result only; actual ALPM16 selection was exercised in assembly.
  with patch.object(s,'version_compare',return_value=1)as compare:
   self.assertTrue(s.satisfies('1:1.0-1','>=','9.0-1'))
   compare.assert_called_once_with('1:1.0-1','9.0-1')
  with patch.object(s,'version_compare',side_effect=AssertionError('no version comparison')):
   self.assertFalse(s.satisfies(None,'=','1'));self.assertTrue(s.satisfies('1',None,None))
  with self.assertRaisesRegex(ValueError,'unsupported dependency'):s.atom('bad dependency || foo')
 def test_data_import_does_not_load_host_alpm(self):
  with patch.object(s.ctypes,'CDLL',side_effect=AssertionError('DATA import cannot require Arch library')):
   self.assertIsNone(load('select_guest').ALPM)
 def test_real_selection_requires_exact_alpm16_without_fallback(self):
  library=Mock();library.alpm_pkg_vercmp.side_effect=[1,-1]
  with patch.object(s,'ALPM',None),patch.object(s.ctypes,'CDLL',return_value=library)as load_library:
   self.assertEqual(s.version_compare('1:1.0-1','9.0-1'),1)
   self.assertEqual(s.version_compare('2','3'),-1)
   load_library.assert_called_once_with('libalpm.so.16')
   self.assertEqual(library.alpm_pkg_vercmp.call_args_list[0].args,(b'1:1.0-1',b'9.0-1'))
   self.assertEqual(library.alpm_pkg_vercmp.argtypes,[s.ctypes.c_char_p,s.ctypes.c_char_p])
   self.assertIs(library.alpm_pkg_vercmp.restype,s.ctypes.c_int)
  with patch.object(s,'ALPM',None),patch.object(s.ctypes,'CDLL',side_effect=OSError('missing ALPM16')):
   with self.assertRaisesRegex(OSError,'missing ALPM16'):s.version_compare('1','2')
 def test_budget_includes_input_checkout_output_scratch_and_new_image(self):
  fake=type('Usage',(),{'free':8*p.LIMIT})()
  with patch.object(p,'allocated',return_value=1),patch.object(p.shutil,'disk_usage',return_value=fake):
   self.assertEqual(p.assert_budget(Path('/input'),Path('/output'),100,110,20),43)
   with self.assertRaisesRegex(AssertionError,'disk cap'):p.assert_budget(Path('/input'),Path('/output'),0,p.LIMIT,1)
 def test_boot_requires_explicit_opt_in_before_docker(self):
  with patch.object(sys,'argv',['boot.py','--prepared','/absent','--prepared-sha256','a'*64,'--tool-image','unused','--tool-image-id',IMAGE,'--output','/absent']),patch.object(b.subprocess,'check_output',side_effect=AssertionError('must not execute')),contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):b.main()
 def test_actor_import_never_launches_qemu(self):
  with patch.object(subprocess,'Popen',side_effect=AssertionError('must not launch')):load('vm_actor')
 def test_actor_fixed_no_network_tcg_profile(self):
  text=(HERE/'vm_actor.py').read_text()
  for value in ("'/usr/bin/qemu-system-aarch64'","'tcg,thread=multi'","'1536'","'virtio-blk-device,drive=refdisk'","'none'","'2'","'root=/dev/vda rootfstype=ext4 rw console=ttyAMA0"):
   self.assertIn(value,text)
  self.assertNotIn("'-enable-kvm'",text);self.assertNotIn("'-netdev'",text);self.assertNotIn("'-initrd'",text)


class Session(unittest.TestCase):
 def test_real_session_architecture_and_page_size_required(self):self.assertEqual(b.parse_session(FRAME,NONCE)['PAGESIZE'],'16384')
 def test_wrong_architecture_pages_or_pam_fields_refuse(self):
  for data,nonce in ((FRAME,'2'*32),(FRAME.replace(b'PAGESIZE=16384',b'PAGESIZE=4096'),NONCE),(FRAME.replace(b'ARCH=aarch64',b'ARCH=x86_64'),NONCE),(FRAME.replace(b'UID=1000',b'UID=0'),NONCE),(FRAME.replace(b'Type=tty',b'Type=unspecified'),NONCE),(FRAME+FRAME,NONCE)):
   with self.subTest(data=data[:60]),self.assertRaises(AssertionError):b.parse_session(data,nonce)
 def test_fragmented_serial_and_bound(self):
  left,right=socket.socketpair();self.addCleanup(left.close);self.addCleanup(right.close);serial=b.Serial(left,time.monotonic()+1)
  right.sendall(b'boot\r\nlog');right.sendall(b'in: ');serial.until(rb'login:');self.assertLessEqual(len(serial.data),b.B.MAX_SERIAL)
  serial.data=bytearray(b.B.MAX_SERIAL+1);right.sendall(b'x')
  with self.assertRaises(ValueError):serial.until(rb'never')


class FakeDocker:
 def __init__(self,scope,foreign=False):self.scope=scope;self.present=True;self.removed=False;self.foreign=foreign
 def __call__(self,argv,**kw):
  if argv[1:3]==['container','ls']:return subprocess.CompletedProcess(argv,0,(CID+' '+self.scope.name+'\n').encode()if self.present else b'',b'')
  if argv[1:3]==['container','inspect']:
   row={'Id':CID,'Name':'/'+self.scope.name,'Image':IMAGE,'Config':{'Labels':dict(self.scope.labels),'Entrypoint':['/usr/bin/python3'],'Cmd':['-I','-B','/opt/vm_actor.py']},'Mounts':[{'Type':'bind','Source':self.scope.source,'Destination':'/inputs','RW':False},{'Type':'bind','Source':self.scope.out,'Destination':'/work','RW':True}],'HostConfig':{'ReadonlyRootfs':True,'NetworkMode':'none','CapDrop':['ALL'],'CapAdd':[],'Privileged':False,'Devices':[],'Init':False,'Memory':3*1024**3,'NanoCpus':2_000_000_000,'PidsLimit':256}}
   if self.foreign:row['Config']['Labels']['owner']='foreign'
   return subprocess.CompletedProcess(argv,0,json.dumps([row]).encode(),b'')
  if argv[1]=='wait':raise subprocess.TimeoutExpired(argv,kw.get('timeout',0))
  if argv[1:4]==['container','rm','--force']:self.present=False;self.removed=True;return subprocess.CompletedProcess(argv,0,b'',b'')
  raise AssertionError(argv)


class Cleanup(unittest.TestCase):
 def make_scope(self,root):
  source=root/'input';source.mkdir();out=root/'output';out.mkdir()
  return b.OwnedContainer('cachy-arm16k-systemd-test',out/'container.cid',IMAGE,{'owner':'test'},source,out)
 def test_ambiguous_create_wait_timeout_still_removes_exact_owned_container(self):
  with tempfile.TemporaryDirectory()as tmp:
   scope=self.make_scope(Path(tmp));scope.submitted=True;fake=FakeDocker(scope);original={'category':'TimeoutExpired','message':'original create failure'};report={'failure':dict(original)}
   with patch.object(b.subprocess,'run',fake):scope.cleanup(report)
   self.assertTrue(fake.removed);self.assertEqual(report['failure'],original);self.assertTrue(report['owned_container_absence_verified'])
 def test_foreign_same_name_is_never_removed(self):
  with tempfile.TemporaryDirectory()as tmp:
   scope=self.make_scope(Path(tmp));scope.submitted=True;fake=FakeDocker(scope,True);report={}
   with patch.object(b.subprocess,'run',fake):scope.cleanup(report)
   self.assertFalse(fake.removed);self.assertEqual(report['cleanup_errors'][0]['step'],'ownership-recovery')
 def test_private_cid_name_mismatch_never_removed(self):
  with tempfile.TemporaryDirectory()as tmp:
   scope=self.make_scope(Path(tmp));scope.submitted=True;scope.cidfile.write_text('c'*64+'\n');fake=FakeDocker(scope);report={}
   with patch.object(b.subprocess,'run',fake):scope.cleanup(report)
   self.assertFalse(fake.removed);self.assertIn('differ',report['cleanup_errors'][0]['message'])
 def test_cancellation_defers_during_owned_cleanup(self):
  old={number:signal.getsignal(number)for number in (signal.SIGINT,signal.SIGTERM)}
  with b.Cancellation()as state:
   with self.assertRaises(b.B.Cancelled):os.kill(os.getpid(),signal.SIGTERM)
   state.cleaning=True;os.kill(os.getpid(),signal.SIGINT);self.assertEqual(state.pending,[signal.SIGTERM,signal.SIGINT])
  self.assertEqual({number:signal.getsignal(number)for number in old},old)
 def test_main_sigterm_during_ambiguous_create_retains_failure_and_removes(self):
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);source=root/'input';source.mkdir();out=root/'output';refs={}
   for name in ('guest.raw','Image','kernel.config'):
    f=source/name;f.write_bytes(b'SYNTHETIC never booted');refs[name]={'bytes':f.stat().st_size,'sha256':b.sha(f)}
   manifest=source/'prepared.json';manifest.write_text(json.dumps({'status':'PREPARED_NOT_BOOTED','scope':'emulated aarch64/16K stock systemd login reference only','nonce':NONCE,'files':refs,'provenance':{'tool_image_id':IMAGE}}))
   (source/'credentials.json').write_text(json.dumps({'username':'builder','password':'X'*32}));(source/'credentials.json').chmod(0o600)
   holder={};created=False
   def output(argv,**kw):return json.dumps([{'Id':IMAGE,'Config':{'Labels':{}}}]).encode()if argv[1:3]==['image','inspect']else b'["name=rootless"]'
   def run(argv,**kw):
    nonlocal created
    if argv[1]=='create':
     created=True;name=argv[argv.index('--name')+1];labels={argv[i+1].split('=',1)[0]:argv[i+1].split('=',1)[1]for i,v in enumerate(argv)if v=='--label'}
     holder['fake']=FakeDocker(b.OwnedContainer(name,Path(argv[argv.index('--cidfile')+1]),IMAGE,labels,source,out));os.kill(os.getpid(),signal.SIGTERM)
    if not created:return subprocess.CompletedProcess(argv,0,b'',b'')
    return holder['fake'](argv,**kw)
   argv=['boot.py','--allow-first-arm16k-systemd-boot','--prepared',str(source),'--prepared-sha256',b.sha(manifest),'--tool-image','fixture','--tool-image-id',IMAGE,'--output',str(out)]
   with patch.object(sys,'argv',argv),patch.object(b.subprocess,'check_output',output),patch.object(b.subprocess,'run',run),contextlib.redirect_stdout(io.StringIO()):self.assertEqual(b.main(),1)
   report=json.loads((out/'report.json').read_text());self.assertEqual(report['failure']['category'],'Cancelled');self.assertTrue(report['owned_container_removed']);self.assertTrue(holder['fake'].removed)


if __name__=='__main__':unittest.main(verbosity=2)

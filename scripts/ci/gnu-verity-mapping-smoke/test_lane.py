# SPDX-License-Identifier: MIT
"""Pure source/UAPI/refusal controls. No native kernel/QEMU/DM actors or VM fixture."""
import json,os,re,stat,struct,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import contract as C,fixture as F,lane as L,protocol as P,supervise as S,layout as V
HERE=Path(__file__).resolve().parent

def header(size=312):
 b=bytearray(size);struct.pack_into('<6Ii3I',b,0,4,50,0,size,312,0,0,0,0,0);return b

def single_list():
 # Inert ABI parser unit only; no UART trace, guest, syscall, or VM credit.
 b=header(342);struct.pack_into('<4I',b,312,0,1,13,0);b[328:335]=b'verity\0';return b

def frames(rows,nonce='1'*32):return b''.join(P.PREFIX+nonce.encode()+b' '+json.dumps(v,separators=(',',':')).encode()+b'\n'for v in rows)

class SourceControls(unittest.TestCase):
 def test_default_boot_selectors_are_null(self):
  p=C.obj(C.read(HERE/'input-policy.json'));self.assertTrue(all(p[k]is None for k in('actual_source','actual_ref','actual_run')));self.assertEqual(p['scope'],P.SCOPE)
 def test_null_refuses_before_actors_or_mkdir(self):
  with tempfile.TemporaryDirectory(dir=HERE)as tmp:
   t=Path(tmp);(t/'input-policy.json').write_bytes(C.read(HERE/'input-policy.json'))
   for n in('kernel-descriptor.json','Root-build-decision.json','kernel-build-result.json'):(t/n).write_bytes(b'null\n')
   with patch.object(C,'HERE',t),patch.object(C,'source',return_value={}),patch.object(L,'fresh',side_effect=AssertionError('NO_MKDIR')),patch.object(S,'run',side_effect=AssertionError('NO_ACTORS')),patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS')):
    with self.assertRaisesRegex(ValueError,'NULL kernel'):L.probe(t,t/'input',t/'work',t/'out')
   self.assertFalse((t/'work').exists());self.assertFalse((t/'out').exists())
 def test_guest_only_nonce_owned_finite_mutation_surface(self):
  c=C.read(HERE/'init.c').decode();self.assertIn('DM_DEV_CREATE_CMD',c);self.assertIn('DM_TABLE_LOAD_CMD',c);self.assertIn('DM_DEV_REMOVE_CMD',c);self.assertIn('"gv-good-"',c);self.assertIn('"gv-bad-"',c)
  for name in('DM_REMOVE_ALL','DM_DEV_RENAME','DM_DEFERRED_REMOVE','execve','/sys/'):
   self.assertNotIn(name,c)
 def test_whole_upstream_uapi_witness(self):
  v=C.obj(C.read(HERE/'uapi-source-proof.json'));self.assertEqual(v['archive'],dict(bytes=262965559,sha256='874ef68d04ac8c831b90bb01a387cfabb58fceb60842c49a0d0e58bcd6c146ad'))
  for n,row in v['files'].items():self.assertEqual(P.pin(row['text'].encode()),{k:row[k]for k in('bytes','sha256')})
  self.assertIn('#define DM_VERSION_MAJOR\t4',v['files']['include/uapi/linux/dm-ioctl.h']['text']);self.assertIn('#define DM_VERSION_MINOR\t50',v['files']['include/uapi/linux/dm-ioctl.h']['text']);self.assertRegex(v['files']['drivers/md/dm-verity-target.c']['text'],r'\.version\s*= \{1, 13, 0\}')
 def test_kernel_reader_custody_self_support_present(self):
  self.assertTrue((HERE/'kernel-reader/calibrate_run.py').is_file());self.assertTrue((HERE/'kernel-reader/custody.py').is_file());self.assertTrue((HERE/'kernel-reader/source-authorization.json').is_file())
 def test_default_or_exact_accepted_build_authority_only(self):
  if C.read(HERE/'kernel-descriptor.json')==b'null\n':
   with self.assertRaisesRegex(ValueError,'NULL kernel'):C.bound()
  else:
   p,d,decision,result=C.bound();self.assertEqual(len(d['members']),30);self.assertEqual(d['artifact']['id'],12147995917);self.assertEqual(decision['configuration']['active_changes'],14);self.assertEqual(decision['configuration']['inactive_domain'],189)
 def test_qemu_readonly_tcg_bounds(self):
  args=L.qemu(Path('/owned/work'));self.assertIn('64M',args);self.assertEqual(args[args.index('-smp')+1],'1');self.assertEqual(args[args.index('-accel')+1],'tcg');self.assertEqual(args[args.index('-net')+1],'none');self.assertIn('-no-reboot',args)
  for option in('-drive','-enable-kvm','-pidfile'):self.assertNotIn(option,args)
 def test_pinned_native_static_compiler_surface(self):
  self.assertIn('-nostdinc',L.FLAGS);self.assertIn('-nostdlib',L.FLAGS);self.assertIn('-static',L.FLAGS);self.assertIn('-Wl,-z,max-page-size=16384',L.FLAGS);self.assertIn('-mgeneral-regs-only',L.FLAGS)
 def test_owned_cleanup_refuses_unknown_content(self):
  with tempfile.TemporaryDirectory(dir=HERE)as tmp:
   work=Path(tmp)/'work';owner=L.fresh(work);(work/'foreign').write_bytes(b'held')
   with self.assertRaisesRegex(ValueError,'top-level'):L.remove(work,owner)
   self.assertTrue((work/'foreign').exists())
 def test_owned_cleanup_known_private_files(self):
  with tempfile.TemporaryDirectory(dir=HERE)as tmp:
   work=Path(tmp)/'work';owner=L.fresh(work);(work/'owner.json').write_bytes(b'{}');r=L.remove(work,owner);self.assertTrue(r['absence_verified']);self.assertFalse(work.exists())
 def test_elf_requires_real_static_aarch64_structure(self):
  for b in(b'',b'\x7fELF'+bytes(100),b'x'*512):
   with self.assertRaises(ValueError):F.elf(b)
 def test_cpio_refuses_invalid_elf_even_with_owner_nonce(self):
  with self.assertRaises(ValueError):F.cpio(b'no executable','1'*32)
 def test_supervision_unreaped_anchor_and_failure_only_force(self):
  text=C.read(HERE/'supervise.py').decode();self.assertIn('os.WNOWAIT',text);self.assertIn('start_new_session=True',text);self.assertIn('if failure is not None:',text);self.assertLess(text.index('os.killpg(child.pid,sig)'),text.index('child.wait(timeout=5)'));self.assertIn('signal.pthread_sigmask',text);self.assertIn('UNREAPED_CHILD_UNTIL_RETIREMENT',text)
 def test_signal_cleanup_handlers_present(self):
  text=C.read(HERE/'lane.py').decode();self.assertIn('signal.signal(s,interrupted)',text);self.assertIn('finally:',text);self.assertIn('signal.signal(sig,handler)',text)

class ABIControls(unittest.TestCase):
 def test_inert_version_parser_unit_not_VM(self):self.assertEqual(P.dm(bytes(header()))['version'],[4,50,0])
 def test_inert_target_parser_unit_not_VM(self):self.assertEqual(P.dm(bytes(single_list()),True)['targets'],{'verity':[1,13,0]})
 def test_header_mutations_refuse(self):
  for offset,value in((0,5),(4,49),(8,1),(12,999),(16,304),(20,1),(24,1),(28,256),(28,1),(32,1),(36,1),(40,1),(48,1)):
   with self.subTest(offset=offset,value=value):
    b=header();struct.pack_into('<I',b,offset,value)
    with self.assertRaises(ValueError):P.dm(bytes(b))
 def test_target_next_outside_refuses(self):
  b=single_list();struct.pack_into('<I',b,312,9992)
  with self.assertRaises(ValueError):P.dm(bytes(b),True)
 def test_target_next_unaligned_refuses(self):
  b=single_list();struct.pack_into('<I',b,312,23)
  with self.assertRaises(ValueError):P.dm(bytes(b),True)
 def test_target_wrong_verity_version_refuses(self):
  b=single_list();struct.pack_into('<I',b,320,12)
  with self.assertRaisesRegex(ValueError,'verity'):P.dm(bytes(b),True)
 def test_target_unterminated_refuses(self):
  b=single_list();b[328:]=b'x'*14
  with self.assertRaisesRegex(ValueError,'terminated'):P.dm(bytes(b),True)
 def test_target_nonzero_padding_refuses(self):
  b=single_list();b[-1]=1
  with self.assertRaises(ValueError):P.dm(bytes(b),True)
 def test_truncated_ioctl_refuses(self):
  for n in(0,16,304,311):
   with self.assertRaises(ValueError):P.dm(bytes(n))
 def test_unknown_target_name_refuses(self):
  b=single_list();b[328]=ord('/')
  with self.assertRaises(ValueError):P.dm(bytes(b),True)

class UARTControls(unittest.TestCase):
 def test_no_uart_refuses(self):
  with self.assertRaises(ValueError):P.uart(b'', '1'*32)
 def test_kernel_log_without_guest_refuses(self):
  with self.assertRaisesRegex(ValueError,'exact27'):P.uart(b'Linux version\nreboot: Power down\n','1'*32)
 def test_foreign_nonce_refuses(self):
  with self.assertRaisesRegex(ValueError,'nonce'):P.uart(frames([dict(event='boot')],'2'*32),'1'*32)
 def test_malformed_owner_frame_refuses(self):
  with self.assertRaisesRegex(ValueError,'prefix'):P.uart(b'GNU_VERITY_SMOKE-forged\n','1'*32)
 def test_failure_frame_cannot_be_positive(self):
  with self.assertRaisesRegex(ValueError,'exact27'):P.uart(frames([dict(event='fail',stage=11,rc=-2)]),'1'*32)
 def test_duplicate_frame_cannot_be_positive(self):
  with self.assertRaisesRegex(ValueError,'exact27'):P.uart(frames([dict(event='boot')]*4),'1'*32)
 def test_bad_pid_pages_machine_release_refuse_before_dm(self):
  boot=dict(event='boot',pid=1,page_size=16384,machine='aarch64',kernel=P.RELEASE)
  # Incomplete frames exercise refusal branches; no accepting UART fixture exists.
  for key,value in(('pid',2),('pid',True),('page_size',4096),('page_size',True),('machine','x86_64'),('kernel','oldKSM')):
   with self.subTest(key=key,value=value):
    rows=[dict(boot,**{key:value})]+[dict(event='unreachable')]*26
    with self.assertRaisesRegex(ValueError,'real PID1'):P.uart(frames(rows),'1'*32)
 def test_json_duplicates_refuse(self):
  with self.assertRaisesRegex(ValueError,'duplicate'):P.uart(b'GNU_VERITY_SMOKE '+b'1'*32+b' {"event":"boot","event":"boot"}\n','1'*32)
 def test_owner_nonce_shape_refuses(self):
  with self.assertRaises(ValueError):P.uart(b'x','a'*31)
 def test_oversize_uart_refuses(self):
  with self.assertRaises(ValueError):P.uart(b'x'*(P.CAP+1),'1'*32)



class MappingControls(unittest.TestCase):
 def test_exact_primary_layout_and_independent_corruption(self):
  assets=V.assets();self.assertEqual({k:len(b)for k,b in assets.items()},{'data.raw':8192,'hash.raw':4096,'corrupt.raw':8192});self.assertEqual([i for i,(a,b)in enumerate(zip(assets['data.raw'],assets['corrupt.raw']))if a!=b],[4133]);self.assertEqual(V.ROOT,'6e7fd501909cf93260b86733d85027ec40fbc8200dc5907bd8c77eeacd7123ec')
  import hashlib
  self.assertEqual(hashlib.sha256(V.SALT+assets['hash.raw']).hexdigest(),V.ROOT)
  for i in range(2):self.assertEqual(hashlib.sha256(V.SALT+assets['data.raw'][4096*i:4096*(i+1)]).digest(),assets['hash.raw'][32*i:32*(i+1)])
  self.assertNotEqual(hashlib.sha256(V.SALT+assets['corrupt.raw'][4096:]).digest(),assets['hash.raw'][32:64]);self.assertEqual(assets['hash.raw'][64:],bytes(4032))
 def test_primary_verity_docs_and_driver_status_semantics(self):
  v=C.obj(C.read(HERE/'uapi-source-proof.json'));docs=v['files']['Documentation/admin-guide/device-mapper/verity.rst']['text'];self.assertIn('salt is prepended',docs);self.assertIn('power of two',docs);self.assertIn('PART_BITS 4',v['files']['drivers/block/virtio_blk.c']['text']);self.assertIn("v->hash_failed ? 'C' : 'V'",v['files']['drivers/md/dm-verity-target.c']['text']);self.assertIn('format_dev_t(td->dm_dev.name, dev)',v['files']['drivers/md/dm.c']['text'])
 def test_fixture_header_whole_generator_equality(self):self.assertEqual(C.read(HERE/'fixture-data.h'),V.header())
 def test_exact_table_request_root_salt_readonly_and_sector_length(self):
  paths={'good':'/dev/vda','hash':'/dev/vdb','bad':'/dev/vdc'};r=V.request('good','load','1'*32,paths);self.assertEqual(len(r),1024);self.assertEqual(struct.unpack_from('<I',r,28)[0],1);self.assertEqual(struct.unpack_from('<QQiI16s',r,312),(0,16,0,0,b'verity'+bytes(10)));self.assertEqual(r[352:].split(b'\0',1)[0].decode(),V.parameters(paths['good'],paths['hash']));self.assertNotIn(b'ignore_corruption',r)
 def test_exact_three_ordinary_readonly_raw_qemu_inputs(self):
  args=L.qemu(Path('/private/work'));rows=[json.loads(args[i+1])for i,x in enumerate(args)if x=='-blockdev'];self.assertEqual(len(rows),6);self.assertTrue(all(r['read-only']is True for r in rows));self.assertEqual({r['filename']for r in rows if r['driver']=='file'},{'/private/work/data.raw','/private/work/hash.raw','/private/work/corrupt.raw'});self.assertEqual(sum(x=='-device'for x in args),3)
 def test_previous_genuine_availability_uart_cannot_grant_mapping_credit(self):
  # Whole genuine historical output is read-only DATA, never new guest execution.
  import zipfile
  a=HERE.parents[0]/'gnu-verity-kernel-boot-probe-native-actual-20261018/originals/artifact.zip'
  if a.is_file():
   with zipfile.ZipFile(a)as z:raw=z.read('qemu.stdout')
   with self.assertRaisesRegex(ValueError,'exact27'):P.uart(raw,'1'*32)
  else:
   with self.assertRaisesRegex(ValueError,'exact27'):P.uart(b'GNU_BOOT_DM old availability only\n','1'*32)
 def test_eio_and_remove_are_actual_guest_syscall_checks(self):
  c=C.read(HERE/'init.c').decode();self.assertIn('if(rc!=-5)',c);self.assertIn('"gone",DM_DEV_STATUS_CMD,0,312,-6',c);self.assertIn('NR_UMOUNT2',c);self.assertLess(c.index('begin("mappings_closed")'),c.index('command(fd,0,"remove"'))



def inert_call(role,phase):
 nonce='1'*32;paths={'good':'/dev/vda','hash':'/dev/vdb','bad':'/dev/vdc'};physical={'good':252<<8,'hash':(252<<8)|16,'bad':(252<<8)|32};mapped={'good':253<<8,'bad':(253<<8)|1};request=V.request(role,phase,nonce,paths)
 if phase=='gone':raw=request;rc=-6
 else:
  tail=(V.parameters(V.devname(physical[role]),V.devname(physical['hash'])).encode()+b'\0')if phase=='table'else((b'V -\0'if role=='good'else b'C -\0')if phase=='info'else b'');size=352+len(tail)if tail else 305;raw=bytearray(size);flags={'create':8,'load':64,'resume':8225,'table':49,'info':33,'remove':8192}[phase];struct.pack_into('<6Ii3IQ',raw,0,4,50,0,size,312,int(phase in('resume','table','info')),int(phase=='info'),flags,0,0,0 if phase=='remove'else mapped[role]);n=V.name(role,nonce).encode();raw[48:48+len(n)]=n
  if tail:struct.pack_into('<QQiI16s',raw,312,0,16,0,(40+len(tail)+7)//8*8,b'verity');raw[352:]=tail
  raw=bytes(raw);rc=0
 row=dict(event='dm_ioctl',role=role,phase=phase,command=0xc138fd00+V.PHASE[phase],request_bytes=len(request),request_hex=request.hex(),rc=rc,bytes=len(raw),raw_hex=raw.hex());return row,nonce,paths,physical,mapped

class MappingProtocolControls(unittest.TestCase):
 def test_inert_single_ioctl_units_are_not_VM_traces(self):
  for role in('good','bad'):
   for phase in V.PHASE:
    with self.subTest(role=role,phase=phase):
     row,nonce,paths,physical,mapped=inert_call(role,phase)
     if phase=='create':mapped.pop(role)
     P.io_record(row,role,phase,nonce,paths,mapped,physical)
 def test_wrong_trusted_root_readback_refuses(self):
  row,nonce,paths,physical,mapped=inert_call('good','table');raw=bytes.fromhex(row['raw_hex']).replace(V.ROOT.encode(),b'0'*64);row['raw_hex']=raw.hex()
  with self.assertRaisesRegex(ValueError,'trusted-root'):P.io_record(row,'good','table',nonce,paths,mapped,physical)
 def test_optional_ignore_corruption_request_refuses(self):
  row,nonce,paths,physical,mapped=inert_call('bad','load');raw=bytearray.fromhex(row['request_hex']);raw[-20:]=b'ignore_corruption'+bytes(3);row['request_hex']=raw.hex()
  with self.assertRaisesRegex(ValueError,'exact full source-owned'):P.io_record(row,'bad','load',nonce,paths,mapped,physical)
 def test_non_readonly_or_deferred_state_refuses(self):
  for phase,flags in(('resume',32),('load',64|131072),('remove',131072),('info',1)):
   row,nonce,paths,physical,mapped=inert_call('good',phase);raw=bytearray.fromhex(row['raw_hex']);struct.pack_into('<I',raw,28,flags);row['raw_hex']=raw.hex()
   with self.assertRaisesRegex(ValueError,'mapping state'):P.io_record(row,'good',phase,nonce,paths,mapped,physical)
 def test_bad_eio_is_exact_errno_not_any_failure(self):
  good=dict(event='bad_read',offset=4096,bytes=4096,rc=-5);self.assertEqual(P.bad_read(good)['rc'],-5)
  for key,value in(('rc',0),('rc',4096),('rc',-12),('offset',0),('bytes',8192)):
   with self.assertRaisesRegex(ValueError,'kernel EIO'):P.bad_read(dict(good,**{key:value}))
 def test_full_good_data_read_is_exact(self):
  row=dict(event='good_read',offset=0,bytes=8192,block_returns=[4096,4096],raw_hex=V.assets()['data.raw'].hex());self.assertEqual(P.good_read(row)['bytes'],8192)
  row['raw_hex']=V.assets()['corrupt.raw'].hex()
  with self.assertRaises(ValueError):P.good_read(row)
 def test_verity_info_must_distinguish_v_from_c(self):
  for role,wrong in(('good',b'C -'),('bad',b'V -')):
   row,nonce,paths,physical,mapped=inert_call(role,'info');raw=bytearray.fromhex(row['raw_hex']);raw[352:355]=wrong;row['raw_hex']=raw.hex()
   with self.assertRaisesRegex(ValueError,'kernel verity'):P.io_record(row,role,'info',nonce,paths,mapped,physical)
 def test_remove_requires_immediate_enxio_confirmation(self):
  row,nonce,paths,physical,mapped=inert_call('bad','gone');row['rc']=0
  with self.assertRaisesRegex(ValueError,'ENXIO'):P.io_record(row,'bad','gone',nonce,paths,mapped,physical)

if __name__=='__main__':unittest.main(verbosity=2)

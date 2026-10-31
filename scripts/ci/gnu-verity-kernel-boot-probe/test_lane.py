# SPDX-License-Identifier: MIT
"""Pure source/UAPI/refusal controls. No native kernel/QEMU/DM actors or VM fixture."""
import json,os,re,stat,struct,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import contract as C,fixture as F,lane as L,protocol as P,supervise as S
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
 def test_finite_read_only_guest_ioctl_surface(self):
  c=C.read(HERE/'init.c').decode();h=C.read(HERE/'probe-uapi.h').decode();self.assertEqual(c.count('syscall6(NR_IOCTL,'),2);self.assertIn('DM_VERSION_CMD',h);self.assertIn('DM_LIST_VERSIONS_CMD',h)
  for name in('DM_DEV_CREATE','DM_TABLE_LOAD','DM_DEV_REMOVE','execve','mount('):self.assertNotIn(name,c+h)
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
 def test_qemu_diskless_tcg_bounds(self):
  args=L.qemu(Path('/owned/work'));self.assertIn('64M',args);self.assertEqual(args[args.index('-smp')+1],'1');self.assertEqual(args[args.index('-accel')+1],'tcg');self.assertEqual(args[args.index('-net')+1],'none');self.assertIn('-no-reboot',args)
  for option in('-drive','-blockdev','-device','-enable-kvm','-pidfile'):self.assertNotIn(option,args)
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
  with self.assertRaisesRegex(ValueError,'four exact'):P.uart(b'Linux version\nreboot: Power down\n','1'*32)
 def test_foreign_nonce_refuses(self):
  with self.assertRaisesRegex(ValueError,'nonce'):P.uart(frames([dict(event='boot')],'2'*32),'1'*32)
 def test_malformed_owner_frame_refuses(self):
  with self.assertRaisesRegex(ValueError,'prefix'):P.uart(b'GNU_BOOT_DM-forged\n','1'*32)
 def test_failure_frame_cannot_be_positive(self):
  with self.assertRaisesRegex(ValueError,'four exact'):P.uart(frames([dict(event='fail',stage=11,rc=-2)]),'1'*32)
 def test_duplicate_frame_cannot_be_positive(self):
  with self.assertRaisesRegex(ValueError,'four exact'):P.uart(frames([dict(event='boot')]*4),'1'*32)
 def test_bad_pid_pages_machine_release_refuse_before_dm(self):
  boot=dict(event='boot',pid=1,page_size=16384,machine='aarch64',kernel=P.RELEASE)
  # Incomplete frames exercise refusal branches; no accepting UART fixture exists.
  for key,value in(('pid',2),('pid',True),('page_size',4096),('page_size',True),('machine','x86_64'),('kernel','oldKSM')):
   with self.subTest(key=key,value=value):
    rows=[dict(boot,**{key:value}),dict(event='dm_version'),dict(event='dm_targets'),dict(event='poweroff')]
    with self.assertRaisesRegex(ValueError,'actual PID1'):P.uart(frames(rows),'1'*32)
 def test_json_duplicates_refuse(self):
  with self.assertRaisesRegex(ValueError,'duplicate'):P.uart(b'GNU_BOOT_DM '+b'1'*32+b' {"event":"boot","event":"boot"}\n','1'*32)
 def test_owner_nonce_shape_refuses(self):
  with self.assertRaises(ValueError):P.uart(b'x','a'*31)
 def test_oversize_uart_refuses(self):
  with self.assertRaises(ValueError):P.uart(b'x'*(P.CAP+1),'1'*32)

if __name__=='__main__':unittest.main(verbosity=2)

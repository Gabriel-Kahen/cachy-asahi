#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pure/refusal controls only. Never manufacture a positive sharing receipt."""
import hashlib,os,select,sys,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent));import sharing as S
class Controls(unittest.TestCase):
 def test_unique_nonzero_nonce_bound_private_page_pattern(self):
  nonce='0'*32;pages=[S.page(nonce,i)for i in range(S.PAGES)]
  self.assertEqual(len(set(pages)),128);self.assertTrue(all(len(p)==16384 and p!=bytes(16384)for p in pages))
  self.assertEqual(S.expected_hash(nonce),hashlib.sha256(b''.join(pages)).hexdigest());self.assertNotEqual(S.page('1'*32,0),pages[0])
 def test_missing_disabled_or_conflicting_kernel_advice_is_refused(self):
  for raw in(b'',b'CONFIG_KSM=y\n',b'CONFIG_KSM=y\n# CONFIG_ADVISE_SYSCALLS is not set\n',b'CONFIG_KSM=y\nCONFIG_ADVISE_SYSCALLS=y\n# CONFIG_ADVISE_SYSCALLS is not set\n'):
   with self.assertRaisesRegex(ValueError,'requires genuine'):S.require_kernel_config(raw)
 def test_invalid_nonce_or_page_never_allocates(self):
  for nonce,index in [('x'*32,0),('0'*32,-1),('0'*32,128),('0'*32,True)]:
   with self.assertRaises(ValueError):S.page(nonce,index)
 def test_strict_decimal_parser(self):
  self.assertEqual(S.number(b'16384\n'),16384)
  for raw in (b'1',b'01\n',b'-1\n',b'1\n2\n',b' 1\n',b'9223372036854775808\n',b'1'*65):
   with self.assertRaises(ValueError):S.number(raw)
 def test_outside_owned_guest_refused_before_sysfs_or_fork(self):
  with patch.object(S,'Scalars',side_effect=AssertionError('NO_SYSFS')),patch.object(S.os,'fork',side_effect=AssertionError('NO_ACTOR')):
   with self.assertRaises(ValueError):S.experiment({},-1)
 def test_no_model_sysfs_authority(self):
  import tempfile
  with tempfile.TemporaryDirectory()as d:
   p=Path(d)
   for name in('run',*S.CONFIG,*S.COUNTERS):(p/name).write_bytes(b'0\n')
   with patch.object(S,'SYSFS',p):
    with self.assertRaisesRegex(ValueError,'real sysfs'):S.Scalars()
   self.assertTrue(all(f.read_bytes()==b'0\n'for f in p.iterdir()))
 def test_foreign_edit_refuses_before_write(self):
  value=S.Scalars.__new__(S.Scalars);value.owned={'run':1}
  with patch.object(value,'read',return_value=0),patch.object(S.os,'write',side_effect=AssertionError('NO_OVERWRITE')):
   with self.assertRaisesRegex(ValueError,'foreign edit'):value.write('run',0)
 def test_original_config_restore_uses_compare_and_swap_writes(self):
  value=S.Scalars.__new__(S.Scalars);value.original={'run':0,'pages_to_scan':100,'sleep_millisecs':10};value.owned={'run':2,**S.CONFIG};writes=[]
  def write(name,n):writes.append((name,n));value.owned[name]=n
  with patch.object(value,'write',side_effect=write),patch.object(value,'read',side_effect=lambda n:value.owned[n]):value.restore()
  self.assertEqual(writes,[('run',0),('sleep_millisecs',10),('pages_to_scan',100)])
 def test_missing_unknown_or_scalar_only_never_pass_sharing(self):
  for value in ({},{'profile':S.PROFILE},{'status':'PASS_REAL_SYSFS_SCALAR_RESTORE_AND_FOREIGN_EDIT_REFUSAL'},{'profile':S.PROFILE,'unmerge':'NOT_RUN_NEVER2'}):
   with self.assertRaises(ValueError):S.validate(value,'0'*32)
 def test_missing_duplicate_or_changed_capture_is_not_authority(self):
  value={'parent':123};argv=['/usr/bin/python3','-I','-B','/source/sharing.py','--owned-parent','123']
  with self.assertRaises(ValueError):S.command_join(value,[])
  with self.assertRaises(ValueError):S.command_join(value,[{'argv':argv},{'argv':argv}])
 def test_bounded_real_owned_pipe_protocol_no_child_or_sysfs(self):
  read,write=os.pipe()
  try:
   os.write(write,b'{"scalar":1}\n');self.assertEqual(S.read_line(read,S.time.monotonic()+1),{'scalar':1})
   os.write(write,b'{}\n{}\n')
   with self.assertRaises(ValueError):S.read_line(read,S.time.monotonic()+1)
  finally:os.close(read);os.close(write)
 def test_failed_fork_retires_all_new_pipe_descriptors(self):
  real_pipe=S.os.pipe2;made=[]
  def pipe(flags):
   pair=real_pipe(flags);made.extend(pair);return pair
  with patch.object(S.os,'pipe2',side_effect=pipe),patch.object(S.os,'fork',side_effect=OSError('CONTROL_NO_CHILD')):
   with self.assertRaises(OSError):S.spawn('0'*32,S.time.monotonic()+1,[])
  self.assertEqual(len(made),4)
  for fd in made:
   with self.assertRaises(OSError):os.fstat(fd)
 def test_failed_second_pipe_closes_first_pair_without_fork(self):
  real_pipe=S.os.pipe2;made=[]
  def pipe(flags):
   if made:raise OSError('CONTROL_NO_PIPE')
   pair=real_pipe(flags);made.extend(pair);return pair
  with patch.object(S.os,'pipe2',side_effect=pipe),patch.object(S.os,'fork',side_effect=AssertionError('NO_CHILD')):
   with self.assertRaises(OSError):S.spawn('0'*32,S.time.monotonic()+1,[])
  for fd in made:
   with self.assertRaises(OSError):os.fstat(fd)
 def test_expired_pipe_deadline_refuses_without_wait(self):
  with patch.object(S.select,'select',side_effect=AssertionError('NO_WAIT')):
   with self.assertRaisesRegex(ValueError,'deadline'):S.read_line(-1,S.time.monotonic()-1)
if __name__=='__main__':unittest.main()

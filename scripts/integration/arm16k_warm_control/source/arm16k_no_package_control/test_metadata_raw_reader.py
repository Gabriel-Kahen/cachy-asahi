# SPDX-License-Identifier: MIT
"""Fenced raw-reader controls: synthetic stat frames only, no image/tool actors."""
from contextlib import contextmanager
from datetime import datetime,timezone
import copy
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import stat
import struct
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent

def module(name,path):
 spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

R=module('fixed_metadata_raw_reader',HERE/'metadata_raw_reader.py')
M=module('actual_no_package_metadata',HERE/'metadata.py')
F=module('actual_Source65_ext4_fields',HERE.parent/'arm16k_perl5423_vm/frozen/independent_readback.py')
L=module('actual_Source65_runtime',HERE.parent/'arm16k_perl5423_vm/runtime.py')


def fence(event,args):
 if event.startswith(('subprocess.','socket.','ctypes.','os.exec','os.spawn','os.fork','os.posix_spawn'))or event in ('os.system','os.kill','os.killpg','os.setuid','os.setgid','fcntl.flock'):
  raise AssertionError('FENCED public metadata models only: '+event)
sys.addaudithook(fence)


def timestamp(seconds=1700000000,ns=123456789):
 low=seconds&0xffffffff;signed=struct.unpack('<i',struct.pack('<I',low))[0];extra=ns*4+((seconds-signed)>>32)
 d=datetime.fromtimestamp(seconds,timezone.utc);days=('Mon','Tue','Wed','Thu','Fri','Sat','Sun');months=('Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec')
 comment=f'{days[d.weekday()]} {months[d.month-1]} {d.day:2d} {d.hour:02d}:{d.minute:02d}:{d.second:02d} {d.year:04d}'
 return f'0x{low:08x}:{extra:08x} -- {comment}'


def frame(inode=20,kind='directory',seconds=1700000000,ns=123456789):
 return ('debugfs 1.47.4 (29-Mar-2025)\n'
  f'Inode: {inode}   Type: {kind}    Mode:  0755   Flags: 0x80000\n'
  'Generation: 0    Version: 0x00000000:00000001\n'
  'User:     0   Group:     0   Project:     0   Size: 4096\n'
  'File ACL: 0\nLinks: 2   Blockcount: 8\n'
  'Fragment:  Address: 0    Number: 0    Size: 0\n'
  f' ctime: {timestamp(seconds,ns)}\n atime: {timestamp(seconds,ns)}\n mtime: {timestamp(seconds,ns)}\ncrtime: {timestamp(seconds,ns)}\n'
  'Size of extra inode fields: 32\nInode checksum: 0x01234567\nEXTENTS:\n(0):1234\n').encode()


def missing(path):return ('debugfs 1.47.4 (29-Mar-2025)\n/'+path+': File not found by ext2_lookup \n').encode()
def outcome(code=0):return dict(passed=code==0,reaped=True,ownership='REAPED',exit=code,group_census='EMPTY_TWICE',output_complete=True,signals=[],timeout=False,error=None)


class Controls(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='MODEL-metadata-raw-');self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
 def budget(self):return R.Budget(time.monotonic()+60,lambda:None)

 def test_exact_fixed_scope_and_fields_match_actual_comparison_module(self):
  self.assertEqual(R.PATHS,M.PATHS);self.assertEqual(R.FIELDS,M.FIELDS);self.assertEqual(R.BOUNDS,M.BOUNDS)
  for path in R.PATHS:self.assertEqual(R.request(path),'stat /'+path)
  for path in ('/etc','root/.ssh','etc/shadow','var/lib/pacman/local/pkg/desc','../etc','etc;cat /etc/shadow','',None):
   with self.subTest(path=path),self.assertRaises(ValueError):R.request(path)

 def test_metadata_and_absence_are_exact_and_no_extra_field_is_projected(self):
  row=R.parse_stat(frame(),'root');self.assertEqual(tuple(row),R.FIELDS)
  self.assertEqual((row['type'],row['atime'],row['atime_ns']),('directory',1700000000,123456789))
  self.assertIsNone(R.parse_stat(missing('etc/audit'),'etc/audit'))
  self.assertNotIn('ctime',row);self.assertNotIn('xattrs',row);self.assertNotIn('sha256',row)

 def test_signed_epoch_and_nanoseconds_match_exact_Source65_inode_decoder(self):
  for seconds,ns in ((-1,0),(0,999999999),(1700000000,123456789),(2**31+1234,999999999),(2**32+30,1)):
   raw=bytearray(256);struct.pack_into('<H',raw,0,stat.S_IFDIR|0o755);struct.pack_into('<H',raw,26,2);struct.pack_into('<H',raw,128,32)
   low=seconds&0xffffffff;signed=struct.unpack('<i',struct.pack('<I',low))[0];extra=ns*4+((seconds-signed)>>32)
   for at,ex in ((8,140),(12,132),(16,136)):
    struct.pack_into('<I',raw,at,low);struct.pack_into('<I',raw,ex,extra)
   reader=object.__new__(F.Ext4Reader);reader.inodes=100;reader.ipg=100;reader.inode_size=256;reader.desc_size=32;reader.max_file_bytes=2**40
   desc=bytearray(32);struct.pack_into('<I',desc,8,1)
   reader.read=lambda off,length:bytes(desc)if length==32 else bytes(raw);reader.xattrs=lambda a,b:{}
   before,_=reader.inode(20);observed=R.parse_stat(frame(seconds=seconds,ns=ns),'etc')
   with self.subTest(seconds=seconds,ns=ns):
    self.assertEqual((observed['atime'],observed['atime_ns'],observed['mtime'],observed['mtime_ns']),tuple(before[k]for k in ('atime','atime_ns','mtime','mtime_ns')))

 def test_unknown_frames_xattrs_private_text_duplicate_fields_and_partial_frames_refuse(self):
  raw=frame()
  invalid=(raw+raw,raw[:-1],b'PRIVATE\n'+raw,raw+b'Extended attributes:\n  user.secret = "PRIVATE"\n',
   raw+b'Fast link dest: "PRIVATE"\n',raw+b'cat /root/.ssh/id_ed25519\n',raw+b'Links: 2   Blockcount: 8\n',raw.replace(b'Links: 2',b'Links: 0'),
   raw.replace(b'Type: directory',b'Type: symlink'),raw.replace(b'0755',b'0999'),raw.replace(b'User:     0',b'User:     -1'),raw+b'\x00',raw+b'\x1b[31m',raw+b'X'*R.STAT_CAP)
  for index,value in enumerate(invalid):
   with self.subTest(index=index),self.assertRaises(ValueError)as error:R.parse_stat(value,'root')
   self.assertNotIn('PRIVATE',str(error.exception));self.assertNotIn('id_ed25519',str(error.exception))

 def test_absence_requires_matching_literal_path_and_no_other_diagnostics(self):
  for raw in (missing('etc/udev'),missing('etc/audit')+b'Filesystem not open\n',missing('etc/audit').replace(b'ext2_lookup',b'permission denied'),missing('etc/audit').replace(b' \n',b'   \n')):
   with self.assertRaises(ValueError):R.parse_stat(raw,'etc/audit')

 def test_bad_calendar_extra_ns_and_out_of_range_values_refuse(self):
  raw=frame()
  for value in (raw.replace(b'Tue Nov 14',b'Mon Nov 14'),raw.replace(b':1d6f3454',b':ffffffff'),raw.replace(b'Inode: 20',b'Inode: 0'),raw.replace(b'Size: 4096',b'Size: 1099511627776')):
   with self.assertRaises(ValueError):R.parse_stat(value,'etc')

 def test_exact_fifteen_lookups_project_and_compare_without_acceptance(self):
  calls=[]
  def call(path):calls.append(path);return missing(path)if path=='etc/audit'else frame(20+R.PATHS.index(path))
  scan=R.observe_with(call,self.budget());projected=M.project_scan(scan)
  self.assertEqual(calls,list(R.PATHS));self.assertEqual(len(projected),15);self.assertIsNone(projected['etc/audit'])
  phases={stage:copy.deepcopy(projected)for stage in M.PHASES};phases['offline_after']['var']['atime_ns']+=1
  comparison=M.compare_phases(phases);self.assertEqual(comparison['endpoint']['changes'][0]['path'],'var')
  self.assertIsNone(comparison['Root_acceptance']);self.assertEqual(comparison['atime_policy'],'OBSERVED_ONLY_NO_RESTORATION')

 def test_missing_parent_alias_cycle_wrong_type_or_guard_failure_never_becomes_absence(self):
  calls=[]
  def call(path):calls.append(path);return missing(path)if path=='etc'else frame(20+R.PATHS.index(path))
  with self.assertRaises(ValueError):R.observe_with(call,self.budget())
  self.assertNotIn('etc/audit',calls)
  with self.assertRaises(ValueError):R.observe_with(lambda path:frame(20),self.budget())
  with self.assertRaises(ValueError):R.observe_with(lambda path:frame(20,'regular'),self.budget())
  budget=R.Budget(time.monotonic()+10,lambda:(_ for _ in ()).throw(ValueError('MODEL guard hold')))
  with self.assertRaises(ValueError):R.observe_with(lambda p:frame(),budget)

 def test_deadline_and_output_caps_precede_any_image_or_process(self):
  for deadline in (time.monotonic()-1,time.monotonic()+1000,float('nan'),True):
   with self.assertRaises(ValueError):R.Budget(deadline,lambda:None)
  budget=self.budget()
  with self.assertRaises(ValueError):budget.charge(b'X'*(R.STAT_CAP+1))
  budget.bytes=R.TOTAL_CAP
  with self.assertRaises(ValueError):budget.charge(b'X')

 def test_actual_Source65_helpers_load_whole_pinned_bytes_without_image_read(self):
  with R.ExitStack()as stack:
   runtime,owned=R.dependencies(HERE.parent/'arm16k_perl5423_vm',self.budget(),stack)
   self.assertTrue(callable(owned.prepare));self.assertTrue(callable(owned.supervise));self.assertTrue(runtime.natural(outcome()))
   self.assertFalse(runtime.natural(dict(outcome(),signals=['SIGTERM'])))

 def test_readonly_binding_refuses_alias_hardlink_special_and_mutation(self):
  path=self.root/'MODEL-ordinary';path.write_bytes(b'INERT')
  with R.held_regular(path,self.budget(),100)as(fd,info):
   self.assertEqual(os.fstat(fd).st_ino,info.st_ino)
   with self.assertRaises(OSError):os.write(fd,b'NO')
  alias=self.root/'alias';alias.symlink_to(path)
  with self.assertRaises(ValueError):
   with R.held_regular(alias,self.budget(),100):pass
  linked=self.root/'linked';os.link(path,linked)
  with self.assertRaises(ValueError):
   with R.held_regular(path,self.budget(),100):pass
  linked.unlink()
  with self.assertRaises(ValueError):
   with R.held_regular(path,self.budget(),100):path.write_bytes(b'CHANGED')

 def run_observer(self,mutate=None,model_result=None):
  image=self.root/'MODEL-NOT-A-FILESYSTEM';image.write_bytes(b'MODEL'+bytes(4096-5));tool=self.root/'MODEL-NOT-AN-EXECUTABLE';tool.write_bytes(b'INERT_TOOL')
  pin=dict(bytes=10,sha256=hashlib.sha256(b'INERT_TOOL').hexdigest());original=R.held_regular;calls=[]
  @contextmanager
  def held(path,budget,maximum):
   actual=tool if str(path)=='/usr/bin/debugfs'else path
   with original(actual,budget,maximum)as value:yield value
  def spawn(argv,**kwargs):
   self.assertEqual(argv[0],'/usr/bin/debugfs');self.assertEqual(argv[1],'-R');self.assertTrue(argv[2].startswith('stat /'))
   self.assertEqual(kwargs['stderr'],R.subprocess.STDOUT);self.assertEqual(kwargs['stdin'],R.subprocess.DEVNULL)
   self.assertEqual(kwargs['env'],{'PATH':'/usr/bin:/bin','LC_ALL':'C','TZ':'UTC'})
   self.assertEqual(len(kwargs['pass_fds']),2);self.assertEqual(argv[-1],'/proc/self/fd/'+str(kwargs['pass_fds'][0]))
   self.assertEqual(kwargs['executable'],'/proc/self/fd/'+str(kwargs['pass_fds'][1]));calls.append(argv[2][6:])
   return SimpleNamespace(path=calls[-1])
  def supervise(child,**kwargs):
   if mutate:mutate(image,tool)
   value=dict(outcome(),output=frame(20+R.PATHS.index(child.path)))if model_result is None else copy.deepcopy(model_result)
   return value
  owned=SimpleNamespace(prepare=lambda:None,supervise=supervise)
  runtime=SimpleNamespace(image_tool_metadata=lambda p,i:None,natural=L.natural)
  with patch.object(R,'fixed_tool_path',return_value=Path('/usr/bin/debugfs')),patch.object(R,'dependencies',return_value=(runtime,owned)),patch.object(R,'held_regular',side_effect=held),patch.object(R.subprocess,'Popen',side_effect=spawn):
   result=R.observe(image,pin,time.monotonic()+60,legacy_root=self.root,guard=lambda:None)
  return result,calls

 def test_outer_observer_uses_only_fixed_stats_pinned_fds_and_minimal_environment(self):
  result,calls=self.run_observer();self.assertEqual(calls,list(R.PATHS));self.assertEqual(result['observed_paths'],list(R.PATHS))
  self.assertFalse(any('.ssh' in name or 'shadow' in name for name in calls))

 def test_forced_nonzero_incomplete_or_mutated_input_never_returns_observation(self):
  for mutation in (dict(exit=2,passed=False),dict(signals=['SIGTERM']),dict(output_complete=False),dict(timeout=True)):
   with self.subTest(mutation=mutation),self.assertRaises(ValueError):self.run_observer(model_result=dict(outcome(),output=frame(),**mutation))
  with self.assertRaises(ValueError):self.run_observer(mutate=lambda image,tool:image.write_bytes(b'ALTERED'))

 def test_cli_has_only_explicit_readonly_operands_and_no_partial_JSON_on_refusal(self):
  args=['reader','--raw','/MODEL/image.raw','--legacy-root','/MODEL/legacy','--debugfs-pin-json','{"bytes":1,"sha256":"'+'a'*64+'"}','--deadline-monotonic',str(time.monotonic()+30)]
  output=SimpleNamespace(buffer=io.BytesIO())
  with patch.object(R.sys,'argv',args),patch.object(R.sys,'stdout',output),patch.object(R,'observe',side_effect=ValueError('MODEL invalid frame')):
   with self.assertRaises(SystemExit)as error:R.main()
  self.assertEqual(error.exception.code,2);self.assertEqual(output.buffer.getvalue(),b'')
  scope=dict(observed_paths=list(R.PATHS),nodes={})
  with patch.object(R.sys,'argv',args),patch.object(R.sys,'stdout',output),patch.object(R,'observe',return_value=scope)as observe:R.main()
  self.assertEqual(output.buffer.getvalue(),R.encoded(scope));self.assertEqual(observe.call_args.args[0],Path('/MODEL/image.raw'))
  self.assertEqual(observe.call_args.kwargs['legacy_root'],Path('/MODEL/legacy'))

 def test_tool_pin_shape_duplicate_JSON_and_unissued_selection_refuse(self):
  for value in (None,{},dict(bytes=True,sha256='a'*64),dict(bytes=1,sha256='a'*64,path='/unreviewed')):
   with self.assertRaises(ValueError):R.pin_shape(value)
  with self.assertRaises(ValueError):R.decoded('{"bytes":1,"bytes":2}')


if __name__=='__main__':unittest.main()

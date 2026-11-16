#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Poisoned MODEL directory-reader controls; no image or SSH body is opened."""
import importlib.util
from pathlib import Path
import struct
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('ssh_privacy_source',HERE/'ssh_privacy.py')
P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)


def need(ok,message):
 if not ok:raise ValueError(message)

class K:
 need=staticmethod(need)


def directory(entries):
 """Construct only MODEL directory-entry bytes, never any child payload."""
 blocks=[];block=[];used=0
 for inode,name,kind in entries:
  minimum=(8+len(name)+3)&~3
  if minimum>P.BLOCK_BYTES:raise AssertionError('MODEL entry must fit one block')
  if used+minimum>P.BLOCK_BYTES:
   block[-1][1]+=P.BLOCK_BYTES-used;blocks.append(block);block=[];used=0
  block.append([inode,minimum,name,kind]);used+=minimum
 if not block:raise AssertionError('MODEL directory must not be empty')
 block[-1][1]+=P.BLOCK_BYTES-used;blocks.append(block)
 return b''.join(struct.pack('<IHBB',inode,length,len(name),kind)+name+bytes(length-8-len(name))for rows in blocks for inode,length,name,kind in rows)


class Reader:
 def __init__(self,root_entries=(),fs_entries=()):
  self.data={2:directory([(2,b'.',2),(2,b'..',2),(16,b'root',2),*fs_entries]),
             16:directory([(16,b'.',2),(2,b'..',2),*root_entries])}
  self.fields={n:dict(inode=n,type='directory',size=len(raw))for n,raw in self.data.items()}
  self.inode_calls=[];self.chunk_calls=[];self.override_chunks={}
 def inode(self,number):
  self.inode_calls.append(number)
  if number not in(2,16):raise AssertionError('MODEL private/other inode must never be requested')
  return dict(self.fields[number]),number
 def chunks(self,fields,raw):
  number=fields['inode'];self.chunk_calls.append(number)
  if number not in(2,16):raise AssertionError('MODEL private/other body must never be requested')
  if number in self.override_chunks:yield from self.override_chunks[number];return
  data=self.data[number]
  for offset in range(0,len(data),P.BLOCK_BYTES):yield data[offset:offset+P.BLOCK_BYTES]


def fence(event,args):
 if event.startswith(('subprocess.','socket.','ctypes.','os.exec','os.fork','os.posix_spawn'))or event in('os.system','fcntl.flock'):
  raise AssertionError('SSH privacy MODEL-only fence: '+event)
sys.addaudithook(fence)


class Controls(unittest.TestCase):
 def assert_refuses_without_private_access(self,reader):
  with self.assertRaises(ValueError):P.guard_root_ssh_absence(K,reader)
  self.assertTrue(set(reader.inode_calls)<={2,16})
  self.assertTrue(set(reader.chunk_calls)<={2,16})

 def test_absence_passes_using_only_the_two_fixed_directory_metadata_streams(self):
  reader=Reader(root_entries=[(77,b'ordinary-MODEL-file',1),(78,b'non-UTF8-\xff',1)],fs_entries=[(90,b'other',2)])
  P.guard_root_ssh_absence(K,reader)
  self.assertEqual(reader.inode_calls,[2,16]);self.assertEqual(reader.chunk_calls,[2,16])

 def test_every_existing_ssh_node_kind_refuses_before_its_inode_or_body(self):
  for kind in range(8):
   with self.subTest(kind=kind):
    reader=Reader(root_entries=[(77,b'.ssh',kind)])
    self.assert_refuses_without_private_access(reader)
    self.assertEqual(reader.inode_calls,[2,16]);self.assertEqual(reader.chunk_calls,[2,16])

 def test_unrelated_names_and_nested_names_do_not_trigger_recursion(self):
  reader=Reader(root_entries=[(77,b'.ssh-other',2),(78,b'ordinary-directory',2)],fs_entries=[(80,b'.ssh',2)])
  P.guard_root_ssh_absence(K,reader)
  self.assertEqual(reader.inode_calls,[2,16]);self.assertEqual(reader.chunk_calls,[2,16])

 def test_root_alias_or_cycle_refuses_without_following_target(self):
  for inode,kind in ((77,7),(77,1),(2,2)):
   with self.subTest(inode=inode,kind=kind):
    reader=Reader();reader.data[2]=directory([(2,b'.',2),(2,b'..',2),(inode,b'root',kind)])
    self.assert_refuses_without_private_access(reader)
    self.assertEqual(reader.inode_calls,[2]);self.assertEqual(reader.chunk_calls,[2])

 def test_missing_root_and_wrong_parent_inode_type_refuse_before_private_data(self):
  reader=Reader(fs_entries=[(16,b'root-hardlink-MODEL',2)])
  self.assert_refuses_without_private_access(reader)
  self.assertEqual(reader.inode_calls,[2]);self.assertEqual(reader.chunk_calls,[2])
  reader=Reader();reader.data[2]=directory([(2,b'.',2),(2,b'..',2)])
  self.assert_refuses_without_private_access(reader)
  self.assertEqual(reader.inode_calls,[2])
  for number in(2,16):
   with self.subTest(number=number):
    reader=Reader();reader.fields[number]['type']='symlink'
    self.assert_refuses_without_private_access(reader)
    self.assertNotIn(number,reader.chunk_calls)

 def test_dot_parent_and_duplicate_entry_shapes_refuse(self):
  cases=[[(17,b'.',2),(2,b'..',2)],[(16,b'.',2),(3,b'..',2)],[(16,b'.',1),(2,b'..',2)],
         [(16,b'.',2),(2,b'..',2),(77,b'one',1),(78,b'one',1)],
         [(16,b'.',2),(2,b'..',2),(77,b'bad/name',1)],[(16,b'.',2),(2,b'..',2),(77,b'bad\0name',1)],
         [(16,b'.',2),(2,b'..',2),(77,b'',1)],[(16,b'.',2),(2,b'..',2),(77,b'bad-type',8)]]
  for rows in cases:
   with self.subTest(rows=rows):
    reader=Reader();reader.data[16]=directory(rows);self.assert_refuses_without_private_access(reader)

 def test_malformed_record_alignment_bounds_names_and_block_crossing_refuse(self):
  for field,value in(('length',0),('length',4),('length',10),('length',4097),('name',255)):
   with self.subTest(field=field,value=value):
    reader=Reader();raw=bytearray(reader.data[16])
    if field=='length':struct.pack_into('<H',raw,4,value)
    else:raw[6]=value
    reader.data[16]=bytes(raw);self.assert_refuses_without_private_access(reader)
  reader=Reader();raw=bytearray(directory([(16,b'.',2),(2,b'..',2)]+[(77+i,f'n{i}'.encode(),1)for i in range(500)]))
  # A length may remain within total data yet cross the first4096-byte block.
  struct.pack_into('<H',raw,4,4100);reader.data[16]=bytes(raw);reader.fields[16]['size']=len(raw)
  self.assert_refuses_without_private_access(reader)

 def test_directory_size_identity_and_metadata_stream_bounds_refuse(self):
  for size in(0,-1,True,4095,P.MAX_DIRECTORY_BYTES+4096):
   with self.subTest(size=size):
    reader=Reader();reader.fields[16]['size']=size;self.assert_refuses_without_private_access(reader)
    self.assertNotIn(16,reader.chunk_calls)
  reader=Reader();reader.fields[16]['inode']=77;self.assert_refuses_without_private_access(reader)
  self.assertNotIn(16,reader.chunk_calls)
  for chunks in((b'',),(b'X'*4097,),(b'X'*4096,b'EXTRA'),(b'X'*4095,),('TEXT_NOT_BYTES',)):
   with self.subTest(chunks=tuple(type(x).__name__+':'+str(len(x))for x in chunks)):
    reader=Reader();reader.override_chunks[16]=chunks;self.assert_refuses_without_private_access(reader)

 def test_total_directory_record_budget_is_finite(self):
  reader=Reader(root_entries=[(77+i,f'MODEL-{i}'.encode(),1)for i in range(P.MAX_ENTRIES)])
  self.assertLessEqual(reader.fields[16]['size'],P.MAX_DIRECTORY_BYTES)
  self.assert_refuses_without_private_access(reader)
  self.assertEqual(reader.inode_calls,[2,16]);self.assertEqual(reader.chunk_calls,[2,16])

 def test_unused_ext4_directory_tail_is_allowed_without_following_any_inode(self):
  reader=Reader()
  # Rebuild ordinary entries leaving an inactive metadata-checksum style tail.
  raw=bytearray(struct.pack('<IHBB',16,12,1,2)+b'.'+bytes(3)+struct.pack('<IHBB',2,4072,2,2)+b'..'+bytes(4062)+struct.pack('<IHBB',0,12,0,222)+bytes(4))
  self.assertEqual(len(raw),4096);reader.data[16]=bytes(raw)
  P.guard_root_ssh_absence(K,reader)
  self.assertEqual(reader.inode_calls,[2,16])
 def test_actual_image_scan_guards_before_base_inventory_or_body_hashing(self):
  spec=importlib.util.spec_from_file_location('ssh_privacy_actual_image_scan',HERE/'image.py')
  image=importlib.util.module_from_spec(spec);spec.loader.exec_module(image)
  for present in(False,True):
   with self.subTest(present=present):
    opened=[];markers=[];reads=[];closed=[];guards=[];operand=object()
    class FakeBase(Reader):
     def __init__(self,path,**limits):
      if path is not operand:raise AssertionError('only the opaque MODEL operand is allowed')
      if limits!={'max_nodes':150000,'max_file_bytes':256*1024**2}:raise AssertionError('actual scan bounds must remain exact')
      super().__init__(root_entries=[(77,b'.ssh',2)]if present else[])
      self.incompat=0;opened.append(self)
     def __enter__(self):return self
     def __exit__(self,kind,value,traceback):closed.append(kind)
     def read(self,offset,length):
      if(offset,length)!=(1024,1024):raise AssertionError('only MODEL superblock metadata may be read')
      reads.append((offset,length));return bytes(1024)
     def inventory(self):
      markers.append('BASE_INVENTORY_BODY_HASHING')
      if present:raise AssertionError('private body-hashing inventory must not be reached')
      return {'nodes':{}}
    frozen=SimpleNamespace(Ext4Reader=FakeBase,u32=lambda raw,offset:struct.unpack_from('<I',raw,offset)[0])
    def helper(name):
     if name!='independent_readback.py':raise AssertionError('fixed public reader helper only')
     return frozen
    contracts=SimpleNamespace(ordinary=lambda value:value,helper=helper,need=need)
    def modules(name):
     if name=='contracts':return contracts
     if name=='ssh_privacy':return P
     raise AssertionError('unexpected source module request')
    with patch.object(image,'module',side_effect=modules):
     if present:
      with self.assertRaisesRegex(ValueError,'protected target must be absent before inventory'):
       image.scan(operand,image.time.monotonic()+10,lambda:guards.append('READ_GUARD'))
     else:
      result=image.scan(operand,image.time.monotonic()+10,lambda:guards.append('READ_GUARD'))
      self.assertEqual(result,dict(nodes={},records={},filesystem_free_bytes=0,log_data_b64=None,retained_log_data_b64=None))
    self.assertEqual(len(opened),1)
    self.assertEqual(opened[0].inode_calls,[2,16]);self.assertEqual(opened[0].chunk_calls,[2,16])
    self.assertEqual(markers,[]if present else['BASE_INVENTORY_BODY_HASHING'])
    self.assertEqual(reads,[(1024,1024)]);self.assertEqual(guards,['READ_GUARD'])
    self.assertEqual(closed,[ValueError]if present else[None])


if __name__=='__main__':unittest.main(verbosity=2)

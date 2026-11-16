# SPDX-License-Identifier: MIT
"""Exact /root/.ssh absence guard before whole-inventory body hashing.

Reads only filesystem-root and literal-root directory inode/entry metadata.
Names stay bytes; no target inode, target body or recursive traversal is used.
"""
import struct

BLOCK_BYTES=4096
MAX_DIRECTORY_BYTES=16*1024**2
MAX_ENTRIES=150000


def _directory(K,reader,number,parent,budget):
 K.need(type(number)is int and 1<=number<=2**32-1,'SSH privacy ordinary directory inode number')
 fields,raw=reader.inode(number)
 K.need(type(fields)is dict and fields.get('type')=='directory'and type(fields.get('inode'))is int and fields['inode']==number,'SSH privacy fixed parent must be an ordinary directory')
 size=fields.get('size')
 K.need(type(size)is int and BLOCK_BYTES<=size<=MAX_DIRECTORY_BYTES and size%BLOCK_BYTES==0,'SSH privacy bounded complete directory blocks')
 blocks=[];total=0
 for block in reader.chunks(fields,raw):
  K.need(type(block)is bytes and 0<len(block)<=BLOCK_BYTES and total+len(block)<=size,'SSH privacy bounded directory metadata stream')
  blocks.append(block);total+=len(block)
 K.need(total==size,'SSH privacy exact directory metadata length')
 data=b''.join(blocks);entries={};offset=0
 while offset<size:
  budget[0]+=1;K.need(budget[0]<=MAX_ENTRIES,'SSH privacy finite directory entry count')
  K.need(offset+8<=size,'SSH privacy complete directory entry header')
  inode,length,name_bytes,kind=struct.unpack_from('<IHBB',data,offset)
  K.need(length>=8 and length%4==0 and offset+length<=size and offset%BLOCK_BYTES+length<=BLOCK_BYTES and name_bytes<=length-8,'SSH privacy valid directory entry bounds')
  if inode:
   name=data[offset+8:offset+8+name_bytes]
   K.need(name and b'/'not in name and b'\0'not in name and name not in entries,'SSH privacy unique literal directory names')
   K.need(0<=kind<=7,'SSH privacy valid directory entry type')
   entries[name]=(inode,kind)
  offset+=length
 K.need(entries.get(b'.')==(number,2)and entries.get(b'..')==(parent,2),'SSH privacy exact directory dot and parent entries')
 return entries


def guard_root_ssh_absence(K,reader):
 """Refuse any /root/.ssh entry before inventory may hash private bodies."""
 budget=[0]
 entries=_directory(K,reader,2,2,budget)
 root=entries.get(b'root')
 K.need(root is not None and root[1]==2 and root[0]!=2 and sum(row[0]==root[0]for row in entries.values())==1,'SSH privacy literal root parent without aliases')
 entries=_directory(K,reader,root[0],2,budget)
 K.need(b'.ssh'not in entries,'SSH privacy protected target must be absent before inventory')

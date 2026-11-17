# SPDX-License-Identifier: MIT
"""Fixed /root/.ssh directory-entry aggregate; never retains non-dot names."""
import struct
BLOCK_BYTES=4096
MAX_DIRECTORY_BYTES=65536
MAX_HEADERS=8192
FIELDS=('inode','type','mode','uid','gid','size','links','mtime','mtime_ns')

def need(ok,why):
 if not ok:raise ValueError(why)

def metadata(row):
 need(type(row)is dict and all(type(row.get(k))is int for k in FIELDS if k!='type'),'fixed ordinary directory inode metadata')
 need(row['type']=='directory' and row['mode']==0o700 and row['uid']==row['gid']==0,'fixed root SSH target must be an ordinary root-owned0700 directory')
 need(1<=row['inode']<=2**32-1 and row['links']>=2 and BLOCK_BYTES<=row['size']<=MAX_DIRECTORY_BYTES and row['size']%BLOCK_BYTES==0,'bounded fixed root SSH directory metadata')
 return {k:row[k]for k in FIELDS}

def aggregate(reader,number,parent):
 """Read only selected directory chunks; no child inode, names, values or recursion."""
 need(type(number)is type(parent)is int and number!=parent,'literal selected root SSH and parent inode')
 first,raw=reader.inode(number);bound=metadata(first);need(bound['inode']==number,'same selected SSH inode')
 seen_dot=seen_parent=False;live=other=headers=total=0
 def result(empty,complete,state):
  return dict(kind='FIXED_ROOT_SSH_EMPTY_AGGREGATE_V1',state=state,empty=empty,complete=complete,
   inode_metadata=bound,parent_inode=parent,live_entries_seen=live,non_dot_entries_seen=other,
   directory_bytes_read=total,headers_seen=headers,names_retained=False,child_inodes_visited=0,
   file_payload_chunks_read=False,xattr_values_read=False,symlink_targets_decoded=False)
 for block in reader.chunks(first,raw):
  need(type(block)is bytes and len(block)==BLOCK_BYTES and total+len(block)<=bound['size'],'bounded selected directory metadata block')
  total+=len(block);offset=0
  while offset<len(block):
   headers+=1;need(headers<=MAX_HEADERS and offset+8<=len(block),'bounded directory entry headers')
   inode,length,name_bytes,kind=struct.unpack_from('<IHBB',block,offset)
   need(length>=8 and length%4==0 and offset+length<=len(block) and name_bytes<=length-8 and name_bytes<=255,'valid complete directory entry header')
   if inode:
    live+=1;need(0<=kind<=7 and name_bytes>0,'valid live directory entry header')
    if name_bytes==1 and block[offset+8:offset+9]==b'.':
     need(not seen_dot and inode==number and kind==2,'unique exact directory dot entry');seen_dot=True
    elif name_bytes==2 and block[offset+8:offset+10]==b'..':
     need(not seen_parent and inode==parent and kind==2,'unique exact directory parent entry');seen_parent=True
    else:
     other+=1;return result(False,False,'NONEMPTY_REFUSED_WITHOUT_NAMES')
   offset+=length
 need(total==bound['size'] and seen_dot and seen_parent and live==2 and other==0,'complete selected directory contains only exact dot and parent entries')
 after,_=reader.inode(number);need(metadata(after)==bound,'same selected directory metadata before and after emptiness proof')
 need(bound['links']==2,'empty ordinary directory link count must be exactly two')
 return result(True,True,'EMPTY_DIRECTORY_METADATA_ONLY')

def require_empty(proof):
 expected={'kind','state','empty','complete','inode_metadata','parent_inode','live_entries_seen','non_dot_entries_seen','directory_bytes_read','headers_seen','names_retained','child_inodes_visited','file_payload_chunks_read','xattr_values_read','symlink_targets_decoded'}
 need(type(proof)is dict and set(proof)==expected,'closed fixed SSH aggregate proof')
 bound=metadata(proof['inode_metadata'])
 need(proof['kind']=='FIXED_ROOT_SSH_EMPTY_AGGREGATE_V1' and proof['state']=='EMPTY_DIRECTORY_METADATA_ONLY' and proof['empty']is proof['complete']is True,'actual complete empty-directory aggregate required')
 need(type(proof['live_entries_seen'])is type(proof['non_dot_entries_seen'])is int and proof['live_entries_seen']==2 and proof['non_dot_entries_seen']==0 and bound['links']==2,'only two live dot entries')
 need(type(proof['directory_bytes_read'])is int and proof['directory_bytes_read']==bound['size'] and type(proof['headers_seen'])is int and 2<=proof['headers_seen']<=MAX_HEADERS,'complete bounded header coverage')
 need(type(proof['parent_inode'])is int and 1<=proof['parent_inode']<=2**32-1 and proof['parent_inode']!=bound['inode'],'fixed distinct ordinary parent inode')
 need(proof['names_retained']is proof['file_payload_chunks_read']is proof['xattr_values_read']is proof['symlink_targets_decoded']is False and type(proof['child_inodes_visited'])is int and proof['child_inodes_visited']==0,'no names, child inodes, private body, xattrs or symlink values')
 return bound

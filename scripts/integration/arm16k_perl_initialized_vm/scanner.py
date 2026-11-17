# SPDX-License-Identifier: MIT
"""Opt-in readonly Source65 scan with verified empty SSH metadata, never children."""
import base64,hashlib,importlib.util,time
from pathlib import Path
HERE=Path(__file__).resolve().parent

def module(n):
 s=importlib.util.spec_from_file_location('initialized_scanner_'+n,HERE/(n+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

def scan(path,authority,empty_document,empty_closure,guard,*,now=None,clock=time.monotonic):
 Q,E=module('qualification'),module('ssh_empty');L=Q.authorize_scan(authority,empty_document,empty_closure,int(time.time())if now is None else now);K=L.contracts;F=K.helper('independent_readback.py')
 K.need(callable(guard),'existing actual Root whole-operation guard callback');deadline=clock()+authority['scan_seconds'];K.END=deadline
 original=E.require_empty(empty_document['root_ssh_emptiness']);identity=lambda s:tuple(getattr(s,k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
 p=K.ordinary(path);first=identity(p.lstat());K.need(K.pin(p)==Q.RAW,'exact initialized raw full pin before scan')
 class Reader(F.Ext4Reader):
  _metadata_only=True
  _ssh_inode=None
  _verified_blocks=None
  def read(self,offset,length):
   guard();K.need(clock()<deadline,'finite initialized readonly scan');return super().read(offset,length)
  def xattrs(self,raw,extra):
   # Before proving emptiness, no selected or parent xattr value is consumed.
   return {}if self._metadata_only else super().xattrs(raw,extra)
  def chunks(self,fields,raw):
   if fields['inode']==self._ssh_inode:
    if self._metadata_only:
     for block in super().chunks(fields,raw):
      self._verified_blocks.append(block);yield block
    else:
     # Use only the exact directory-entry bytes already checked empty. Even a
     # concurrent malformed input cannot enqueue an uninspected private child.
     K.need(E.metadata(fields)==self._empty['inode_metadata'],'same verified empty inode at inventory boundary')
     yield from self._verified_blocks
   else:yield from super().chunks(fields,raw)
  def inventory(self):
   budget=[0];entries=L.privacy._directory(K,self,2,2,budget);root=entries.get(b'root')
   K.need(root is not None and root[1]==2 and root[0]!=2 and sum(v[0]==root[0]for v in entries.values())==1,'literal root without aliases')
   entries=L.privacy._directory(K,self,root[0],2,budget);target=entries.get(b'.ssh')
   K.need(target is not None and target[1]==2 and target[0]not in(2,root[0]) and sum(v[0]==target[0]for v in entries.values())==1,'literal selected ordinary SSH without aliases')
   self._ssh_inode=target[0];self._verified_blocks=[];self._empty=E.aggregate(self,target[0],root[0]);E.require_empty(self._empty)
   K.need(self._empty==empty_document['root_ssh_emptiness'] and self._empty['inode_metadata']==original,'exact fresh proof matches live initialized raw metadata')
   self._metadata_only=False;return super().inventory()
 with Reader(p,max_nodes=150000,max_file_bytes=256*1024**2)as r:
  sb=r.read(1024,1024);free=F.u32(sb,12)|(F.u32(sb,344)<<32 if r.incompat&0x80 else 0)
  nodes=r.inventory()['nodes'];records={};log=None;retained=None
  for name,row in nodes.items():
   if name in('var/log/pacman.log','var/lib/arm16k-perl5423-vm/receipts/pacman-log-after'):
    K.need(row['type']=='file' and row['size']<=(8 if name=='var/log/pacman.log'else 24)*1024**2,'bounded ordinary ALPM transaction log')
    fields,data=r.inode(row['inode']);body=b''.join(r.chunks(fields,data));K.need(hashlib.sha256(body).hexdigest()==row['sha256'],'actual transaction log hash')
    if name=='var/log/pacman.log':log=base64.b64encode(body).decode()
    else:retained=base64.b64encode(body).decode()
   if name.startswith('var/lib/pacman/local/')and name.rsplit('/',1)[-1]in('desc','files'):
    K.need(row['type']=='file' and row['size']<=4*1024**2,'bounded ordinary ALPM metadata');fields,data=r.inode(row['inode']);body=b''.join(r.chunks(fields,data));K.need(hashlib.sha256(body).hexdigest()==row['sha256'],'actual paired ALPM text hash');records[name]=body.decode()
  proof=r._empty
 K.need(K.pin(p)==Q.RAW and identity(p.lstat())==first,'same original raw full hash and stat after initialized scan')
 result=dict(nodes=nodes,records=records,filesystem_free_bytes=free*4096,log_data_b64=log,retained_log_data_b64=retained,root_ssh_empty_proof=proof)
 module('policy').snapshot(result);K.need(len(Q.canonical(result))<=authority['output_cap_bytes'],'bounded complete initialized scan DATA');return result

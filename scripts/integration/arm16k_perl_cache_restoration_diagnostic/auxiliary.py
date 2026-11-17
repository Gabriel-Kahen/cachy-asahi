# SPDX-License-Identifier: MIT
"""Passive narrow ELF64LE/AArch64 glibc auxcache2.0 facts, never acceptance."""
import hashlib,json,re,struct
MAGIC=b'glibc-ld.so.auxcache-2.0';CAP=1048576

def need(v,why):
 if not v:raise ValueError(why)
def pin(body):return dict(bytes=len(body),sha256=hashlib.sha256(body).hexdigest())
def decode(body):
 need(type(body)is bytes and 33<=len(body)<=CAP,'bounded auxiliary cache bytes');magic,n,s=struct.unpack_from('<24sII',body)
 need(magic==MAGIC and 0<n<=4096 and 0<s<=CAP and 32+48*n+s==len(body),'exact2.0 header/count/table geometry')
 table=32+48*n;need(body[table]==0,'special NULL SONAME string');cursor=1;rows=[];ids=set();padding=bytearray()
 for i in range(n):
  ino,ctime,size,dev,flags,offset,isa,pad=struct.unpack_from('<QQQQiII4s',body,32+48*i)
  need(ino>0 and ctime<=2**63-1 and size>=64 and dev>0,'typed positive cached stat identity')
  need(flags==0x0a03 and isa==0,'finite AArch64 libc6/no-ISA auxiliary profile; unsupported flags refuse')
  identity=(ino,ctime,size,dev);need(identity not in ids,'no duplicate cached stat identities');ids.add(identity);padding.extend(pad)
  if offset==0:name=None
  else:
   need(offset==cursor and offset<s,'exact sequential in-table SONAME offset');end=body.find(b'\0',table+offset,len(body));need(end>=table+offset and end-table-offset<=255,'bounded terminated auxiliary SONAME');name=body[table+offset:end].decode('ascii');need(re.fullmatch(r'[A-Za-z0-9_+.-]+\.so(?:\.[A-Za-z0-9_+.-]+)?',name)is not None,'literal public shared-library SONAME');cursor=end-table+1
  rows.append(dict(inode=ino,ctime=ctime,bytes=size,device=dev,flags=flags,isa_level=isa,soname=name))
 need(cursor==s,'complete auxiliary string table accounted for')
 canonical=sorted(rows,key=lambda r:(r['device'],r['inode'],r['ctime'],r['bytes'],r['flags'],r['isa_level'],r['soname']or''));semantic=(json.dumps(canonical,sort_keys=True,separators=(',',':'))+'\n').encode()
 return dict(kind='DECODED_GLIBC_AUXCACHE_2_0_FACTS_ONLY_V1',body=pin(body),entries=n,rows=rows,unordered_defined_fields=pin(semantic),abi_padding=pin(bytes(padding)),abi_padding_semantics='OPAQUE_NOT_INITIALIZED_BY_PINNED_WRITER_NOT_ACCEPTANCE',provider_qualification='PENDING_BASELINE_AFTER_BODY_AND_PROVIDER_IDENTITY_JOIN',Root_acceptance=None,lifecycle_acceptance=None,actual_cause=None)

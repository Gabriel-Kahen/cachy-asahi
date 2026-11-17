# SPDX-License-Identifier: MIT
"""Bounded source-only ELF64LE AArch64 DT_SONAME decoder for pinned db5.3 members."""
import struct,re

def need(ok,why):
 if not ok:raise ValueError(why)
def soname(b):
 need(type(b)is bytes and 64<=len(b)<=4194304 and b[:7]==b'\x7fELF\x02\x01\x01','bounded ELF64LE provider')
 kind,machine,version,_,phoff,_,_,ehsize,phsize,phnum,*_=struct.unpack_from('<HHIQQQIHHHHHH',b,16)
 need(kind==3 and machine==183 and version==1 and ehsize==64 and phsize==56 and 0<phnum<=128 and 64<=phoff and phoff+phsize*phnum<=len(b),'exact bounded AArch64 shared-object program headers')
 loads=[];dynamic=[]
 for i in range(phnum):
  p,_,offset,vaddr,_,filesz,memsz,_=struct.unpack_from('<IIQQQQQQ',b,phoff+i*56)
  need(offset+filesz<=len(b)and filesz<=memsz,'program segment range')
  if p==1:loads.append((vaddr,offset,filesz))
  if p==2:dynamic.append((offset,filesz))
 need(len(dynamic)==1,'one dynamic table');offset,size=dynamic[0];need(size%16==0 and 0<size<=65536,'bounded dynamic entries');tags={};ended=False
 for i in range(size//16):
  key,value=struct.unpack_from('<qQ',b,offset+i*16)
  if key==0:ended=True;break
  if key in(5,10,14):need(key not in tags,'unique SONAME/string table metadata');tags[key]=value
 need(ended and set(tags)=={5,10,14},'complete dynamic SONAME/string table')
 matches=[o+tags[5]-v for v,o,n in loads if v<=tags[5]and tags[5]+tags[10]<=v+n];need(len(matches)==1 and 0<tags[10]<=4194304 and tags[14]<tags[10],'mapped bounded dynamic string table')
 begin=matches[0]+tags[14];end=b.find(b'\0',begin,matches[0]+tags[10]);need(begin<end<=begin+255,'bounded terminated ELF SONAME');name=b[begin:end].decode('ascii');need(re.fullmatch(r'[A-Za-z0-9_+.-]+\.so(?:\.[A-Za-z0-9_+.-]+)?',name)is not None,'literal public ELF SONAME');return name

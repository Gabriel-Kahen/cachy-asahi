# SPDX-License-Identifier: MIT
"""Deterministic six-node diskless newc and bounded static AArch64 ELF check."""
import re,stat,struct
from protocol import need,pin

def elf(raw):
 need(64<=len(raw)<=512*1024 and raw[:7]==b'\x7fELF\x02\x01\x01'and struct.unpack_from('<HH',raw,16)==(2,183),'static ELF64 AArch64 executable')
 entry,phoff=struct.unpack_from('<QQ',raw,24);size,count=struct.unpack_from('<HH',raw,54);need(size==56 and 1<=count<=16 and phoff+count*size<=len(raw),'finite ELF headers');loads=[];executable=False
 for i in range(count):
  typ,flags,off,va,pa,fs,ms,align=struct.unpack_from('<IIQQQQQQ',raw,phoff+56*i);need(off+fs<=len(raw)and ms>=fs,'ELF segment bounds');need(typ not in(2,3),'no dynamic loader/interpreter or runtime libraries')
  if typ==1:
   need(align>=16384 and align&(align-1)==0 and off%16384==va%16384 and flags&3!=3 and ms<=128*1024,'16K-aligned bounded non-WX load');loads.append(dict(offset=off,virtual=va,file_bytes=fs,memory_bytes=ms,flags=flags,alignment=align));executable|=bool(flags&1 and va<=entry<va+fs)
 need(loads and executable,'entry inside executable load');return dict(status='SOURCE_STATIC_AARCH64_ELF_STRUCTURE_ONLY',ELF=pin(raw),entry=entry,loads=loads,executed=False)

def cpio(init,nonce):
 elf(init);need(type(nonce)is str and re.fullmatch('[0-9a-f]{32}',nonce),'unique owner nonce')
 nodes={'init':(stat.S_IFREG|0o755,init,0,0),'nonce':(stat.S_IFREG|0o400,nonce.encode(),0,0),'dev':(stat.S_IFDIR|0o755,b'',0,0),'dev/console':(stat.S_IFCHR|0o600,b'',5,1),'dev/mapper':(stat.S_IFDIR|0o755,b'',0,0),'dev/mapper/control':(stat.S_IFCHR|0o600,b'',10,236)};out=bytearray()
 for ino,(name,(mode,data,major,minor))in enumerate([*sorted(nodes.items()),('TRAILER!!!',(0,b'',0,0))],1):
  name=name.encode()+b'\0';fields=(ino,mode,0,0,1,0,len(data),0,0,major,minor,len(name),0);out+=b'070701'+''.join('%08x'%v for v in fields).encode()+name;out+=b'\0'*(-len(out)%4);out+=data;out+=b'\0'*(-len(out)%4)
 need(len(out)<=1024**2,'fixed minimal initramfs bound');return bytes(out)

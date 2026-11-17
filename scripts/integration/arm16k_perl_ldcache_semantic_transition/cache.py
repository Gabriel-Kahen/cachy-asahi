# SPDX-License-Identifier: MIT
"""Bounded little-endian AArch64 cache1.1 profile from exact glibc8362 source.

Unsupported hwcaps/extensions/architectures refuse. This is not libc's permissive
reader: production qualification requires canonical output of its pinned writer.
"""
import functools,hashlib,re,struct
MAGIC=b'glibc-ld.so.cache1.1';GENERATOR=b'ldconfig (GNU libc) stable release version 2.43';FLAG=0x0a03;CAP=1048576

def need(ok,why):
 if not ok:raise ValueError(why)
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def soname(s):return type(s)is str and len(s)<=255 and re.fullmatch(r'[A-Za-z0-9_+.-]+\.so(?:\.[A-Za-z0-9_+.-]+)?',s)is not None and all(len(n)<=9 and int(n)<=2147483647 for n in re.findall('[0-9]+',s))

def libcmp(a,b):
 """Numeric-aware ordering from glibc elf/dl-cache.c, restricted bounded digits."""
 i=j=0
 while i<len(a):
  x=a[i];y=b[j]if j<len(b)else '\0'
  if '0'<=x<='9':
   if '0'<=y<='9':
    p=i;q=j
    while i<len(a)and a[i].isdigit():i+=1
    while j<len(b)and b[j].isdigit():j+=1
    need(i-p<=9 and j-q<=9,'bounded libc signed-int numeric segment');u=int(a[p:i]);v=int(b[q:j]);need(u<=2147483647 and v<=2147483647,'libc comparator integer range')
    if u!=v:return u-v
   else:return 1
  elif '0'<=y<='9':return -1
  elif x!=y:return ord(x)-ord(y)
  else:i+=1;j+=1
 return -(ord(b[j])if j<len(b)else 0)

def row(name,path):
 need(soname(name),'bounded public shared-library key')
 need(type(path)is str and len(path)<=4096 and re.fullmatch(r'/(?:usr/)?lib(?:64)?/[A-Za-z0-9_+./-]+',path)is not None,'literal public library target')
 need(all(p not in('','..','.')for p in path[1:].split('/')),'unaliased lexical public target')
 return dict(name=name,path=path,flags=FLAG,osversion=0,hwcap=0)

def encode(entries):
 need(type(entries)is list and 0<len(entries)<=4096,'bounded nonempty entry list')
 entries=[row(r['name'],r['path'])if type(r)is dict and set(r)=={'name','path','flags','osversion','hwcap'}and type(r['flags'])is int and r['flags']==FLAG and type(r['osversion'])is int and r['osversion']==0 and type(r['hwcap'])is int and r['hwcap']==0 else need(False,'exact supported entry schema')for r in entries]
 need(len({(r['name'],r['path'])for r in entries})==len(entries),'no duplicate entry mappings')
 names=[r['name']for r in entries];need(len(set(names))==len(names),'this finite provider profile has unique SONAME lookup keys')
 ordered=sorted(entries,key=functools.cmp_to_key(lambda a,b:-libcmp(a['name'],b['name'])))
 strings=sorted({r[n].encode()for r in entries for n in('name','path')},key=lambda s:s[::-1],reverse=True)
 # Exact stringtable_finalize suffix merge; strings may intentionally share tails.
 offsets={};table=bytearray();previous=None
 for s in strings:
  if previous is not None and previous.endswith(s):offsets[s]=offsets[previous]+len(previous)-len(s)
  else:offsets[s]=len(table);table.extend(s+b'\0')
  previous=s
 start=48+24*len(ordered);end=start+len(table);ext=(end+3)&~3
 header=struct.pack('<20sIIB3xI3I',MAGIC,len(ordered),len(table),2,ext,0,0,0)
 body=b''.join(struct.pack('<iIIIQ',FLAG,start+offsets[r['name'].encode()],start+offsets[r['path'].encode()],0,0)for r in ordered)
 extension=struct.pack('<6I',0xeaa42174,1,0,0,ext+24,len(GENERATOR))+GENERATOR
 result=header+body+table+b'\0'*(ext-end)+extension;need(len(result)<=CAP,'canonical bounded cache');return result

def decode(body):
 need(type(body)is bytes and 48<=len(body)<=CAP,'bounded cache bytes')
 magic,n,size,flags,ext,*unused=struct.unpack_from('<20sIIB3xI3I',body)
 need(magic==MAGIC and flags==2 and body[29:32]==b'\0'*3 and unused==[0,0,0],'exact1.1 little-endian header/reserved fields')
 need(0<n<=4096 and 0<size<=CAP,'bounded cache entry/string counts');start=48+n*24;end=start+size
 need(end<=len(body)and ext==(end+3)&~3 and ext+24<=len(body)and body[end:ext]==b'\0'*(ext-end),'disjoint complete tables and aligned zero extension padding')
 magic,count,tag,eflags,offset,length=struct.unpack_from('<6I',body,ext)
 need(magic==0xeaa42174 and count==1 and tag==eflags==0 and offset==ext+24 and length==len(GENERATOR)and offset+length==len(body)and body[offset:]==GENERATOR,'exact pinned generator extension; no unknown/hwcaps/overlap/trailing data')
 coverage=set();entries=[]
 def string(offset):
  need(type(offset)is int and start<=offset<end,'string offset inside declared table')
  stop=body.find(b'\0',offset,end);need(stop>=offset and stop-offset<=4096,'bounded in-table NUL termination')
  raw=body[offset:stop];need(raw and all(32<=x<127 for x in raw),'nonempty printable ASCII string');coverage.update(range(offset,stop+1));return raw.decode('ascii')
 for i in range(n):
  f,k,v,o,h=struct.unpack_from('<iIIIQ',body,48+i*24);need(f==FLAG and o==h==0,'exactAArch64 libc6 flags; no obsolete OS/hwcap entries');entries.append(row(string(k),string(v)))
 need(coverage==set(range(start,end)),'every string table byte accounted for by entries including suffix sharing')
 need(encode(entries)==body,'exact canonical pinned glibc writer layout/order/string sharing')
 return dict(kind='DECODED_PINNED_AARCH64_GLIBC_1_1_V1',cache=pin(body),entries=entries,generator=GENERATOR.decode(),architecture='AARCH64_LITTLE_ENDIAN',hwcaps='UNSUPPORTED_REFUSED',Root_acceptance=None,lifecycle_acceptance=None)

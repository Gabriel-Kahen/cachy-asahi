# SPDX-License-Identifier: MIT
"""Finite exact-package DATA contract; importing it performs no operation."""
import base64,datetime,hashlib,io,json,os,stat,struct,tarfile
from pathlib import Path
HERE=Path(__file__).resolve().parent


def need(ok,message):
 if not ok:raise ValueError(message)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def read(path,cap=64*1024**2):
 p=Path(path);need(p.is_absolute() and p==p.resolve() and not any(n.is_symlink()for n in(p,*p.parents)),'canonical ordinary input')
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  s=os.fstat(fd);need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size<=cap,'bounded single-link regular input')
  with os.fdopen(os.dup(fd),'rb')as f:b=f.read(cap+1)
  key=lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
  need(len(b)==s.st_size and key(s)==key(os.fstat(fd))==key(p.lstat()),'stable whole input');return b
 finally:os.close(fd)
def checked(path,row,cap=64*1024**2):
 b=read(Path(path).resolve(),cap);need(pin(b)=={k:row[k]for k in('bytes','sha256')},'whole input pin differs');return b
def lock():
 v=json.loads((HERE/'inputs.lock.json').read_bytes())
 for n,row in v['data'].items():checked(HERE/n,row)
 return v
def info(raw):
 rows={}
 for line in raw.decode().splitlines():
  if ' = 'in line:
   k,v=line.split(' = ',1);rows.setdefault(k,[]).append(v)
 return rows
def local(root):
 rows={}
 for p in Path(root).glob('*/desc'):
  b=read(p.resolve(),131072);v={s.splitlines()[0].strip('%'):s.splitlines()[1:]for s in b.decode().split('\n\n')if s.startswith('%')};n=v['NAME'][0];need(n not in rows,'unique local package');rows[n]=dict(version=v['VERSION'][0],desc=pin(b))
 return rows
def parent(rows):need(rows==json.loads((HERE/'data/parent-packages.json').read_bytes()),'exact unchanged 178-package parent ALPM')
def successor(rows):
 n=lock()['package']['name'];need(n in rows and rows[n]['version']==lock()['package']['version'],'exact added package version');parent({k:v for k,v in rows.items()if k!=n})
def elf(raw):
 need(len(raw)>=64 and raw[:6]==b'\x7fELF\x02\x01' and struct.unpack_from('<H',raw,18)[0]==62,'ELF64 little-endian x86_64 module')
 off=struct.unpack_from('<Q',raw,40)[0];size,count=struct.unpack_from('<HH',raw,58);need(size==64 and 0<count<4096 and off+size*count<=len(raw),'bounded section table')
 sections=[struct.unpack_from('<IIQQQQIIQQ',raw,off+i*size)for i in range(count)]
 def body(i):
  s=sections[i];need(s[4]+s[5]<=len(raw),'whole ELF section');return raw[s[4]:s[4]+s[5]]
 def text(table,offset):
  need(offset<len(table),'string index');end=table.find(b'\0',offset);need(end>=offset,'terminated string');return table[offset:end].decode()
 needed=[];stamps=[]
 for s in sections:
  if s[1]==6:
   data=raw[s[4]:s[4]+s[5]];strings=body(s[6]);need(len(data)%16==0,'whole dynamic table')
   for i in range(0,len(data),16):
    tag,value=struct.unpack_from('<QQ',data,i)
    if tag==1:needed.append(text(strings,value))
  if s[1]==11:
   need(s[9]==24 and s[5]%24==0,'whole dynamic symbols');strings=body(s[6])
   for i in range(s[4],s[4]+s[5],24):
    name,kind,other,index,value,length=struct.unpack_from('<IBBHQQ',raw,i);n=text(strings,name)
    if n.startswith('qemu_stamp_') and index:stamps.append(n)
 return dict(needed=sorted(needed),stamps=stamps)
def archive(path):
 v=lock();raw=checked(path,v['package']['archive']);found={};selected={};total=0
 with tarfile.open(fileobj=io.BytesIO(raw),mode='r|*')as t:
  for m in t:
   n=m.name;need(n in v['members'] and n not in found and (m.isfile()or m.isdir())and not n.startswith('/')and '..'not in Path(n).parts,'exact ordinary package member');total+=m.size;need(total<1024**2,'finite one-package payload')
   row=dict(bytes=m.size,mode=m.mode,kind='file'if m.isfile()else'directory')
   if m.isfile():
    b=t.extractfile(m).read(m.size+1);row['sha256']=hashlib.sha256(b).hexdigest()
    if n in('.PKGINFO',v['module']['path']):selected[n]=b
   need(row==v['members'][n],'exact member metadata/body');found[n]=row
 need(found==v['members'],'whole package membership');i=info(selected['.PKGINFO']);need(i['pkgname']==[v['package']['name']]and i['pkgver']==[v['package']['version']]and i['arch']==['x86_64']and i['depend']==['glibc','pixman','libpixman-1.so=0-64','qemu-common=11.1.3-1'],'exact package/dependency closure')
 module=selected[v['module']['path']];need(pin(module)=={k:v['module'][k]for k in('bytes','sha256')}and elf(module)==dict(needed=v['module']['needed'],stamps=[v['module']['stamp']]),'exact module ABI and NEEDED');return dict(package=v['package'],module=v['module'],ordinary_members=len(found),payload_execution=False)
def signed(status):
 rows=[s.split()[1:]for s in status.decode().splitlines()if s.startswith('[GNUPG:] ')];need(not any(r[0]in('EXPKEYSIG','EXPSIG','REVKEYSIG','BADSIG','ERRSIG','NO_PUBKEY','ERROR','FAILURE')for r in rows),'current valid signature status');valid=[r for r in rows if r[0]=='VALIDSIG'];v=lock()['package'];need(len(valid)==1 and len(valid[0])==11 and valid[0][1]==v['signing_key']and valid[0][-1]==v['primary_signer'],'exact official signer');return valid[0]
def devices(raw):
 need(len(raw)<=1024**2,'bounded device-help DATA');names=lock()['required_devices'];r={n:('name "'+n+'"').encode()in raw for n in names};need(all(r.values()),'all three real virtio devices required');return r
def qualified(v):
 need(v['kind']=='ARM16K_VIRTIO_TOOL_IMAGE_V1'and v['status']=='TOOL_IMAGE_DEVICES_QUALIFIED_NO_GUEST'and v['parent_image_id']==lock()['parent_image_id']and isinstance(v['image_id'],str)and len(v['image_id'])==71 and v['image_id'].startswith('sha256:')and all(c in'0123456789abcdef'for c in v['image_id'][7:])and v['image_id']!=v['parent_image_id']and v['required_devices']==dict.fromkeys(lock()['required_devices'],True)and v['owned_containers_absent']is True and v['guest_boot']=='NOT RUN','actual distinct image and real qualification required');need(all(v[n]==lock()[n]for n in('package','module','qemu','providers'))and 0<v['image_delta_bytes']<=lock()['resources']['image_delta_bytes'],'exact installed package/module/provider and finite image closure')

def confinement(row,name,image,labels,stage,mounts):
 need(row['Name']=='/'+name and len(row['Id'])==64 and all(c in'0123456789abcdef'for c in row['Id'])and row['Image']==image and row['Config']['Labels']==labels,'exact owned image/name/labels')
 need(row['Config']['Entrypoint']==['/usr/bin/python3']and row['Config']['Cmd']==['-I','-B','/recipe/actor.py',stage],'exact actor entry')
 h=row['HostConfig'];need(h['NetworkMode']=='none'and h['CapDrop']==['ALL']and not h['CapAdd']and not h['Privileged']and not h['Devices']and not h.get('DeviceRequests')and h.get('PidMode','')==''and h.get('IpcMode','private')=='private'and h.get('UTSMode','')==''and h.get('Init')is False and h['ReadonlyRootfs']==(stage=='probe')and h['Memory']==536870912 and h['MemorySwap']==536870912 and h['NanoCpus']==1000000000 and h['PidsLimit']==64 and h['SecurityOpt']==['no-new-privileges'],'exact offline bounded container')
 need(len(row['Mounts'])==len(mounts)and{(m['Source'],m['Destination'],m['RW'])for m in row['Mounts']}==mounts and all(m['Type']=='bind'for m in row['Mounts']),'exact finite mounts')


def tool_metadata(report):
 qualified(report);stamp=report['actual_observed_utc'];when=datetime.datetime.fromisoformat(stamp);need(when.utcoffset()is not None,'real timezone-aware observation timestamp')
 return dict(kind='ROOT_OBSERVED_ARM_QEMU_DEVICE_HELP_V1',issued_by='Root',status='OBSERVED_DEVICE_HELP_ONLY',image_id=report['image_id'],qemu_path='/usr/bin/qemu-system-aarch64',devices=lock()['required_devices'],actual_tool_pin={k:report['qemu'][k]for k in('bytes','sha256')},actual_help_pin=report['device_help'],actual_observed_utc=stamp)

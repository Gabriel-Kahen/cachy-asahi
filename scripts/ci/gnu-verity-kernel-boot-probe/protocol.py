# SPDX-License-Identifier: MIT
"""Strict retained raw syscall/UAPI DATA, no actors or accepting fixture."""
import hashlib,json,re,struct
SCOPE='BOOT_AND_DM_TARGET_AVAILABILITY_ONLY'
PREFIX=b'GNU_BOOT_DM '
RELEASE='7.1.13-generic16k-managed-gui'
VERSION=0xc138fd00
LIST=0xc138fd0d
CAP=4*1024**2

def need(ok,why):
 if not ok:raise ValueError(why)
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def obj(raw):
 def pairs(rows):
  out={}
  for k,v in rows:need(k not in out,'duplicate protocol JSON');out[k]=v
  return out
 v=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'finite protocol JSON'));need(type(v)is dict,'protocol object');return v

def dm(raw,targets=False):
 need(type(raw)is bytes and 312<=len(raw)<=16384,'bounded complete real DM ioctl bytes')
 major,minor,patch,size,start,count,opened,flags,event,padding=struct.unpack_from('<6Ii3I',raw)
 dev=struct.unpack_from('<Q',raw,40)[0]
 need((major,minor,patch,size,start,count,opened,event,padding,dev)==(4,50,0,len(raw),312,0,0,0,0,0)and flags&~65536==0 and raw[48:312]==bytes(264),'whole source-shaped DM header/version/size/no truncation')
 if not targets:need(len(raw)==312,'complete DM_VERSION header only');return dict(version=[major,minor,patch],raw=pin(raw))
 result={};pos=start
 while True:
  need(len(result)<64 and pos+17<=len(raw),'finite complete DM target records');nxt,a,b,c=struct.unpack_from('<4I',raw,pos);end=pos+nxt if nxt else len(raw)
  need(pos+16<end<=len(raw)and nxt%8==0,'monotone aligned DM target next offset');tail=raw[pos+16:end];zero=tail.find(b'\0');need(1<=zero<=63 and tail[zero:]==bytes(len(tail)-zero),'terminated bounded target name and zero padding');name=tail[:zero].decode('ascii');need(re.fullmatch('[A-Za-z0-9_-]+',name)and name not in result,'unique actual DM target name');result[name]=[a,b,c]
  if not nxt:break
  pos=end
 need(result.get('verity')==[1,13,0],'actual pinned verity target1.13.0 required')
 return dict(version=[major,minor,patch],targets=result,raw=pin(raw))

def uart(raw,nonce):
 need(type(raw)is bytes and 0<len(raw)<=CAP and type(nonce)is str and re.fullmatch('[0-9a-f]{32}',nonce),'bounded original UART and owner nonce')
 records=[]
 for line in raw.splitlines():
  line=line.rstrip(b'\r')
  if not line.startswith(b'GNU_BOOT_DM'):continue
  need(line.startswith(PREFIX)and len(line)<=65536,'complete source protocol prefix/line cap');parts=line.split(b' ',2);need(len(parts)==3 and parts[1]==nonce.encode(),'every frame joins the unique host owner nonce');records.append(obj(parts[2]))
 need([v.get('event')for v in records]==['boot','dm_version','dm_targets','poweroff'],'four exact ordered single boot/DM/poweroff frames; no failure/replay credit')
 boot,version,targets,power=records
 need(boot==dict(event='boot',pid=1,page_size=16384,machine='aarch64',kernel=RELEASE)and type(boot['pid'])is int and type(boot['page_size'])is int,'actual PID1/AT_PAGESZ/uname join')
 parsed=[]
 for row,command,is_targets in((version,VERSION,False),(targets,LIST,True)):
  fields={'event','command','rc','bytes','raw_hex'}|({'count','verity_version'}if is_targets else set());need(set(row)==fields and type(row['command'])is int and row['command']==command and type(row['rc'])is int and row['rc']==0 and type(row['bytes'])is int and 312<=row['bytes']<=16384 and type(row['raw_hex'])is str and len(row['raw_hex'])==2*row['bytes']and re.fullmatch('[0-9a-f]+',row['raw_hex']),'exact successful source syscall/raw-byte fields');data=bytes.fromhex(row['raw_hex']);value=dm(data,is_targets)
  if is_targets:need(type(row['count'])is int and row['count']==len(value['targets'])and row['verity_version']==[1,13,0]and all(type(x)is int for x in row['verity_version']),'actual DM list count/version joins')
  parsed.append(value)
 need(power==dict(event='poweroff',pid=1,method='LINUX_REBOOT_CMD_POWER_OFF',dm_closed=True)and type(power['pid'])is int and power['dm_closed']is True,'source-owned DM close before poweroff request')
 powerline=raw.rfind(PREFIX+nonce.encode()+b' {"event":"poweroff"')
 need(powerline>=0 and re.search(rb'(?:^|\n)(?:\[[^\]\r\n]{1,32}\]\s*)?reboot: Power down\r?(?:\n|$)',raw[powerline:])is not None,'real kernel power-down console after PID1 close/poweroff request')
 return dict(status='PASS_RETAINED_BOOT_AND_DM_TARGET_DATA_ONLY',nonce=nonce,boot=boot,dm_version=parsed[0],dm_targets=parsed[1],poweroff_request=power,UART=pin(raw),scope=SCOPE,verity_mapping='NOT_TESTED',integrity='NOT_TESTED',lifecycle='NOT_TESTED',hardware='NOT_RUN',performance='NOT_MEASURED',acceptance='NOT_GRANTED')

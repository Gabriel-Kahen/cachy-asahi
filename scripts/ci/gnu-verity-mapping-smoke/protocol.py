# SPDX-License-Identifier: MIT
"""Strict retained raw syscall/UAPI DATA, no actors or accepting fixture."""
import hashlib,json,re,struct,stat
import layout as V
SCOPE='STANDALONE_DM_VERITY_MAPPING_AND_INTEGRITY_SMOKE_ONLY'
PREFIX=b'GNU_VERITY_SMOKE '
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

def stat_block(row,size,expected_dev=None):
 need(row['bytes']==size and type(row['bytes'])is int and type(row['readonly'])is int and row['readonly']==1 and type(row['rdev'])is int and 0<row['rdev']<=0xffffffff and type(row['stat_hex'])is str and re.fullmatch('[0-9a-f]{256}',row['stat_hex']),'actual read-only block size/rdev/full stat bytes');raw=bytes.fromhex(row['stat_hex']);mode=struct.unpack_from('<I',raw,16)[0];rdev=struct.unpack_from('<Q',raw,32)[0];uid,gid=struct.unpack_from('<II',raw,24)
 need(stat.S_IFMT(mode)==stat.S_IFBLK and rdev==row['rdev']and uid==gid==0 and V.dev(rdev)[0]>0,'actual guest devtmpfs block node rdev/owner/mode')
 if expected_dev is not None:need(rdev==expected_dev,'mapped block node equals ioctl-created device')
 return rdev

def io_record(row,role,phase,nonce,paths,mapped,rdev):
 expected=V.request(role,phase,nonce,paths);fields={'event','role','phase','command','request_bytes','request_hex','rc','bytes','raw_hex'}
 need(set(row)==fields and row['event']=='dm_ioctl'and row['role']==role and row['phase']==phase and type(row['command'])is int and row['command']==0xc138fd00+V.PHASE[phase]and type(row['request_bytes'])is int and row['request_bytes']==len(expected)and row['request_hex']==expected.hex(),'exact full source-owned ioctl request and nonce/table/root/salt/readonly operands')
 need(type(row['bytes'])is int and 305<=row['bytes']<=1024 and type(row['raw_hex'])is str and len(row['raw_hex'])==2*row['bytes']and re.fullmatch('[0-9a-f]+',row['raw_hex'])and type(row['rc'])is int,'complete bounded actual ioctl return bytes');raw=bytes.fromhex(row['raw_hex'])
 if phase=='gone':need(row['rc']==-6 and raw==expected,'removed nonce-owned name must return kernel ENXIO');return None
 need(row['rc']==0,'real successful mapping ioctl');major,minor,patch,size,start,count,opened,flags,event,padding=struct.unpack_from('<6Ii3I',raw);dev=struct.unpack_from('<Q',raw,40)[0];name=V.name(role,nonce).encode();need((major,minor,patch,size,start,padding)==(4,50,0,len(raw),312,0)and raw[48:176]==name+bytes(128-len(name))and raw[176:305]==bytes(129),'whole actual header/source nonce-owned mapping name/version/UUID')
 allowed={'create':{8},'load':{64},'resume':{33,8225},'table':{49},'info':{33},'remove':{0,8192}};need(flags in allowed[phase]and opened==int(phase=='info')and count==int(phase in('resume','table','info')),'source-derived mapping state/readonly/active/closed and no deferred cleanup flags')
 if phase=='create':need(V.dev(dev)[0]>0 and V.dev(dev)[1]==(0 if role=='good'else 1)and role not in mapped,'fresh exact persistent minor from kernel');mapped[role]=dev
 elif phase=='remove':need(dev==0,'remove returns the source zero selector device')
 else:need(dev==mapped[role],'same actual created mapped device throughout')
 if phase in('table','info'):
  need(len(raw)>352,'complete real target status');sector,length,status,nxt,typ=struct.unpack_from('<QQiI16s',raw,312);tail=raw[352:];need(tail[-1:]==b'\0'and b'\0'not in tail[:-1]and(sector,length,status,typ)==(0,16,0,b'verity'+bytes(10))and nxt==(40+len(tail)+7)//8*8,'complete singleton verity status/sector length/aligned ABI')
  text=tail[:-1].decode('ascii');want=V.parameters(V.devname(rdev[role]),V.devname(rdev['hash']))if phase=='table'else('V -'if role=='good'else'C -');need(text==want,'actual trusted-root table readback or kernel verity verified/corrupted status')
 else:need(len(raw)==305,'source NO_PARAMS minimum305 output bytes')
 return dict(dev=dev,flags=flags,event_nr=event,raw=pin(raw))

def good_read(row):
 expected=V.assets()['data.raw'];need(set(row)=={'event','offset','bytes','block_returns','raw_hex'}and row['event']=='good_read'and type(row['offset'])is int and row['offset']==0 and type(row['bytes'])is int and row['bytes']==8192 and row['block_returns']==[4096,4096]and all(type(x)is int for x in row['block_returns'])and row['raw_hex']==expected.hex(),'full verified expected data returned through active readonly verity mapping');return pin(expected)
def bad_read(row):
 need(row==dict(event='bad_read',offset=4096,bytes=4096,rc=-5)and all(type(row[k])is int for k in('offset','bytes','rc')),'deliberate bad-block read requires real kernel EIO');return dict(offset=4096,bytes=4096,rc=-5)

def uart(raw,nonce):
 need(type(raw)is bytes and 0<len(raw)<=CAP and type(nonce)is str and re.fullmatch('[0-9a-f]{32}',nonce),'bounded original UART owner nonce');records=[]
 for line in raw.splitlines():
  line=line.rstrip(b'\r')
  if not line.startswith(b'GNU_VERITY_SMOKE'):continue
  need(line.startswith(PREFIX)and len(line)<=65536,'source protocol prefix/cap');parts=line.split(b' ',2);need(len(parts)==3 and parts[1]==nonce.encode(),'every record joins host owner nonce');records.append(obj(parts[2]))
 need(len(records)==27,'exact27 original mapping/read/corruption/cleanup frames; no fixture/failure/replay credit');i=0
 def take(event):
  nonlocal i
  row=records[i];i+=1;need(row.get('event')==event,'exact ordered original guest sequence: '+event);return row
 boot=take('boot');need(boot==dict(event='boot',pid=1,page_size=16384,machine='aarch64',kernel=RELEASE)and type(boot['pid'])is int and type(boot['page_size'])is int,'real PID1/16K/kernel release');mounted=take('devtmpfs');need(mounted==dict(event='devtmpfs',rc=0,flags=10)and type(mounted['rc'])is int,'guest-only devtmpfs mount')
 availability=[]
 for event,code,targets in(('dm_version',VERSION,False),('dm_targets',LIST,True)):
  row=take(event);fields={'event','command','rc','bytes','raw_hex'}|({'count','verity_version'}if targets else set());need(set(row)==fields and type(row['command'])is int and row['command']==code and type(row['rc'])is int and row['rc']==0 and type(row['bytes'])is int and 312<=row['bytes']<=16384 and type(row['raw_hex'])is str and len(row['raw_hex'])==2*row['bytes']and re.fullmatch('[0-9a-f]+',row['raw_hex']),'actual availability syscall bytes');parsed=dm(bytes.fromhex(row['raw_hex']),targets)
  if targets:need(type(row['count'])is int and row['count']==len(parsed['targets'])and row['verity_version']==[1,13,0]and all(type(x)is int for x in row['verity_version']),'actual complete target count/version')
  availability.append(parsed)
 paths={};rdev={};fixtures=V.assets();key={'good':'data.raw','hash':'hash.raw','bad':'corrupt.raw'}
 for _ in range(3):
  row=take('device');role=row.get('role');need(set(row)=={'event','role','path','bytes','readonly','rdev','stat_hex','raw_hex'}and role in key and role not in paths and row['path']in('/dev/vda','/dev/vdb','/dev/vdc')and row['path']not in paths.values(),'three independent source-enumerated raw devices');expected=fixtures[key[role]];rdev[role]=stat_block(row,len(expected));need(V.dev(rdev[role])[1]=={'/dev/vda':0,'/dev/vdb':16,'/dev/vdc':32}[row['path']]and row['raw_hex']==expected.hex(),'full physical input bytes/size and actual distinct virtio minor');paths[role]=row['path']
 need(len(set(rdev.values()))==3,'good/hash/corrupt are independent physical devices');mapped={};calls=[]
 for role in('good','bad'):
  for phase in('create','load','resume','table'):calls.append(io_record(take('dm_ioctl'),role,phase,nonce,paths,mapped,rdev))
  node=take('mapped_device');need(set(node)=={'event','role','path','bytes','readonly','rdev','stat_hex'}and node['role']==role and node['path']==('/dev/dm-0'if role=='good'else'/dev/dm-1'),'source-owned mapped node');stat_block(node,8192,mapped[role])
  if role=='good':
   read=take('good_read');good_read(read)
  else:
   read=take('bad_read');bad_read(read)
  calls.append(io_record(take('dm_ioctl'),role,'info',nonce,paths,mapped,rdev))
 need(mapped['good']!=mapped['bad']and V.dev(mapped['good'])[0]==V.dev(mapped['bad'])[0]and all(V.dev(d)[0]!=V.dev(mapped['good'])[0]for d in rdev.values()),'independent good/bad verity mappings distinct from physical devices');closed=take('mappings_closed');need(closed==dict(event='mappings_closed',good=True,bad=True)and closed['good']is True and closed['bad']is True,'both mapped FDs closed before removal')
 for role in('good','bad'):
  for phase in('remove','gone'):calls.append(io_record(take('dm_ioctl'),role,phase,nonce,paths,mapped,rdev))
 power=take('poweroff');need(power==dict(event='poweroff',pid=1,method='LINUX_REBOOT_CMD_POWER_OFF',dm_closed=True,mappings_removed=True,devtmpfs_unmounted=True)and type(power['pid'])is int and all(power[k]is True for k in('dm_closed','mappings_removed','devtmpfs_unmounted')),'control/guest devtmpfs closed after both confirmed mapping removals')
 marker=PREFIX+nonce.encode()+b' {"event":"poweroff"';pos=raw.rfind(marker);need(pos>=0 and re.search(rb'(?:^|\n)(?:\[[^\]\r\n]{1,32}\]\s*)?reboot: Power down\r?(?:\n|$)',raw[pos:])is not None,'real later kernel power down')
 return dict(status='PASS_RETAINED_STANDALONE_DM_VERITY_MAPPING_INTEGRITY_DATA_ONLY',nonce=nonce,boot=boot,dm_version=availability[0],dm_targets=availability[1],physical_paths=paths,physical_devices=rdev,mapped_devices=mapped,root_digest=V.ROOT,salt=V.SALT.hex(),good_read=pin(fixtures['data.raw']),bad_read=dict(offset=4096,bytes=4096,rc=-5,verity_status='C -'),guest_cleanup='BOTH_NONCE_OWNED_MAPPINGS_CLOSED_REMOVED_ENXIO_AND_DEVTMPFS_UNMOUNTED',ioctl_returns=calls,poweroff_request=power,UART=pin(raw),scope=SCOPE,lifecycle='NOT_TESTED',hardware='NOT_RUN',performance='NOT_MEASURED',acceptance='NOT_GRANTED')

# SPDX-License-Identifier: MIT
"""Two fresh boots of one owned generic16K root. No hardware acceptance."""
import base64,hashlib,importlib.util,json,math,os,re,stat,sys,time,zlib
from pathlib import Path
HERE=Path(__file__).resolve().parent
BUDGET=dict(owner=21600,producer=2300,assembly=1070,media=1900,vm_shared=14400,boot=3600,transaction=90,cleanup=60)
PREFIX=b'CORE7_SYSTEMD_VM '
RETIRED=b'CORE7_SYSTEMD_VM_RETIRE '

def need(value,message):
 if not value:raise ValueError(message)
def disk_serial(nonce,role):
 """20 ASCII bytes encoding128 digest bits, bound to role and the full128-bit nonce."""
 need(type(nonce)is str and re.fullmatch('[a-f0-9]{32}',nonce)and role in('boot','data'),'exact full nonce and block role')
 raw=hashlib.sha256(b'cachy-asahi/core7/virtio-blk/serial-v1\0'+role.encode('ascii')+b'\0'+bytes.fromhex(nonce)).digest()[:16]
 value=base64.b85encode(raw).decode('ascii')
 need(len(value)==20 and all(33<=ord(c)<=126 and c not in ',\0'for c in value),'literal20-byte virtio block property')
 return value

def encoded(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def decode(raw):
 def pairs(rows):
  result={}
  for k,v in rows:need(k not in result,'duplicate JSON field');result[k]=v
  return result
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def identity(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def read(path,cap=2*1024**2):
 path=Path(path);need(not any(p.is_symlink()for p in(path,*path.parents)),'ordinary input ancestors')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
 try:
  st=os.fstat(fd);need(stat.S_ISREG(st.st_mode)and st.st_nlink==1 and st.st_size<=cap,'bounded single-link ordinary input')
  data=bytearray()
  while len(data)<=st.st_size:
   v=os.read(fd,min(1024**2,st.st_size-len(data)+1))
   if not v:break
   data.extend(v)
  need(len(data)==st.st_size and identity(st)==identity(os.fstat(fd))==identity(path.lstat()),'whole stable descriptor/path read');return bytes(data)
 finally:os.close(fd)
def inflate(raw,cap=256*1024**2):
 need(type(raw)is bytes and 0<len(raw)<=64*1024**2,'bounded complete compressed graph');d=zlib.decompressobj(16+zlib.MAX_WBITS);value=d.decompress(raw,cap+1);need(len(value)<=cap and d.eof and not d.unused_data and not d.unconsumed_tail,'one bounded complete gzip graph');return value
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
def selection(value):
 need(type(value)is dict and set(value)=={'schema','scope','actual','nonce','kernel','source_profiles','budgets'},'closed two-boot selector')
 need(value['schema']==1 and value['scope']=='CORE7_AUTOMATIC_HOOKS_ROLLBACK_FOUR_BOOT_GENERIC16K'and value['budgets']==BUDGET,'explicit new case; old budgets not rebound')
 need(type(value['nonce'])is str and re.fullmatch('[0-9a-f]{32}',value['nonce']),'fresh owned nonce')
 need(type(value['actual'])is dict and set(value['actual'])=={'source','ref','run','attempt'}and re.fullmatch('[a-f0-9]{40}',value['actual']['source']or'')and re.fullmatch('codex/[a-z0-9-]+',value['actual']['ref']or'')and str(value['actual']['run']).isdigit()and type(value['actual']['attempt'])is int and value['actual']['attempt']==1,'genuine actual binding required before actors')
 need(type(value['kernel'])is dict and value['kernel'].get('kernel_authority')is not None and value['kernel'].get('kernel_source')is not None,'whole accepted generic16K kernel authority required')
 need(set(value['source_profiles'])=={'core800','ksm637','core7_carrier'},'all three whole immutable source profiles');return value

def command(row,seconds=90):
 need(type(row)is dict and type(row['exit_code'])is int and row['exit_code']==0 and row['group_absence_verified']is True,'natural actual foreground exit/group retirement')
 need(type(row['time_limit'])in(int,float)and 0<row['time_limit']<=seconds and type(row['seconds'])in(int,float)and math.isfinite(row['seconds'])and 0<=row['seconds']<=row['time_limit']+6,'actual finite command clock')
 need(row['output_limit']==1024**2 and row['stdout_bytes']+row['stderr_bytes']<=1024**2,'whole command stream caps');return row

def process(value,expected,state='running'):
 need(set(value)=={'pid','exe_link','exe','version','manager','root','boot_id','package_version','architecture','page_size','kernel','capabilities'},'complete actual PID1 projection')
 need(value['architecture']=='aarch64'and value['page_size']==16384 and value['kernel']==expected['kernel'],'actual generic16K kernel/architecture/page readback');caps=value['capabilities'];need(set(caps)=={'CapEff','CapPrm','CapBnd','CapInh','CapAmb','NoNewPrivs','Seccomp','last'}and type(caps['last'])is int and 0<caps['last']<64,'whole actual PID1 capability readback');mask=(1<<(caps['last']+1))-1;need(all(caps[k]==mask for k in('CapEff','CapPrm','CapBnd'))and caps['CapInh']==caps['CapAmb']==caps['NoNewPrivs']==caps['Seccomp']==0,'explicit full owned VM init authority; old copied-root profile unchanged')
 need(type(value['pid'])is int and value['pid']==1 and value['exe_link']=='/usr/lib/systemd/systemd'and value['exe']==expected['exe']and value['version']==expected['version']and value['package_version']==expected['package_version'],'actual full executable/version and installed package match')
 need(value['manager']==dict(Version=expected['manager_version'],Virtualization='qemu',SystemState=state),'source-defined custom target manager readback')
 need(re.fullmatch('[a-f0-9-]{36}',value['boot_id'])and set(value['root'])=={'device','inode','serial','machine_id'}and type(value['root']['device'])is int and value['root']['device']>0 and type(value['root']['inode'])is int and value['root']['inode']==2 and value['root']['serial']==expected['serial']==disk_serial(expected['nonce'],'boot')and value['root']['machine_id']==expected['nonce'],'owned persistent root identity and nonce');return value

def protocol(raw,selected,phase,expected):
 selection(selected);need(type(phase)is int and phase in(1,2,3,4)and type(raw)is bytes and len(raw)<=1024**2,'bounded finite actual UART')
 need(b'Kernel panic - not syncing:'not in raw and b'CORE7_BOOTSTRAP_FAILURE_DATA 'not in raw,'panic or bootstrap failure cannot be positive')
 lines=[v for v in raw.splitlines()if v.startswith(PREFIX)];need(len(lines)==1,'one actual final observer frame')
 value=decode(lines[0][len(PREFIX):]);need(set(value)=={'schema','nonce','phase','status','pid1','worker','probe','custody','previous','observer_commands','hardware','release'},'closed actual VM observer result')
 need(value['schema']==1 and value['nonce']==selected['nonce']and type(value['phase'])is int and value['phase']==phase and value['status']=='PASS_ACTUAL_SYSTEMD_PID1_AND_OWNED_STAGE'and value['hardware']=='NOT_RUN'and value['release']=='NOT_ADMITTED','nonce and explicit finite VM scope')
 process(value['pid1'],expected)
 for role in('worker','probe'):
  need(value[role]==dict(ActiveState='inactive',SubState='dead',Result='success',ExecMainCode='1',ExecMainStatus='0',MainPID='0',ControlGroup=''),'natural oneshot exit and empty unit group '+role)
 need(value['custody']['status']=='PASS_FULL_GRAPH_SIGNATURE_ACCOUNT_CACHE_AND_USER_PRESERVATION'and type(value['custody']['phase'])is int and value['custody']['phase']==phase and value['custody']['public_home_retired']is True,'source-owned complete guest custody validation required')
 need(len(value['observer_commands'])==6,'all real PID1/manager and two unit query commands')
 for row in value['observer_commands']:command(row)
 wait=value['observer_commands'][0];need(wait['argv']==['/usr/bin/systemctl','--system','is-system-running','--wait']and wait['stdout_bytes']==8 and wait['stdout_sha256']==pin(b'running\n')['sha256']and wait['stderr_bytes']==0,'actual manager startup completion wait and exact running response')
 retired=[v for v in raw.splitlines()if v.startswith(RETIRED)];need(len(retired)==1,'one actual natural observer retirement marker');need(decode(retired[0][len(RETIRED):])==dict(schema=1,nonce=selected['nonce'],phase=phase,event='observer-retired',status='NATURAL_OBSERVER_EXIT_BEFORE_OWNED_MANAGER_POWEROFF',observer=pin(encoded(value)),service_result='success',exit_code='exited',exit_status='0'),'actual ExecStopPost after natural observer exit and before owned manager poweroff')
 return value

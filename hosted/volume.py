# SPDX-License-Identifier: MIT
"""One source/token-owned work volume and bounded initialization; no import actions."""
import hashlib,json,re
DOCKER=['/usr/bin/docker','--host=unix:///var/run/docker.sock']
OP='llvm23-source-reference-native-v2'
INNER='llvm23-source-reference-native-v1'
INIT_CODE=r'''import json,os,stat,sys
from pathlib import Path
b=json.loads(sys.argv[1]);p=Path('/work')
def need(v,s):
 if not v:raise ValueError(s)
def node(s):return dict(device=s.st_dev,inode=s.st_ino,uid=s.st_uid,gid=s.st_gid,mode=stat.S_IMODE(s.st_mode))
need(os.getuid()==os.geteuid()==os.getgid()==os.getegid()==0,'initializer root only')
status=dict(l.split(':',1)for l in Path('/proc/self/status').read_text().splitlines()if ':'in l)
need(all(int(status[k].strip(),16)==1 for k in('CapPrm','CapEff','CapBnd'))and all(int(status[k].strip(),16)==0 for k in('CapInh','CapAmb'))and status['NoNewPrivs'].strip()=='1','CHOWN only; no FOWNER or DAC capability')
need(os.uname().machine=='aarch64'and set(x.name for x in Path('/sys/class/net').iterdir())=={'lo'},'native isolated initializer')
need(os.statvfs('/').f_flag&os.ST_RDONLY and not os.statvfs(p).f_flag&os.ST_RDONLY,'readonly root and writable volume')
limits={n:(Path('/sys/fs/cgroup')/n).read_text().strip()for n in('cpu.max','memory.max','memory.swap.max','pids.max')}
need(limits=={'cpu.max':'100000 100000','memory.max':'536870912','memory.swap.max':'0','pids.max':'64'},'bounded initializer cgroup')
fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
try:
 before=os.fstat(fd);need(stat.S_ISDIR(before.st_mode)and before.st_uid==before.st_gid==0 and not os.listdir(fd),'fresh empty root-owned volume')
 os.fchmod(fd,0o700);os.fchown(fd,1001,1001)
 after=os.fstat(fd);need(stat.S_IMODE(after.st_mode)==0o700 and after.st_uid==after.st_gid==1001 and not os.listdir(fd),'exact initialized empty volume')
 need((before.st_dev,before.st_ino)==(after.st_dev,after.st_ino)==(p.lstat().st_dev,p.lstat().st_ino),'same ordinary directory')
 print(json.dumps(dict(schema=1,status='INITIALIZED_EMPTY_WORK_VOLUME',binding=b,before=node(before),after=node(after),limits=limits,capabilities='CHOWN_ONLY_CHMOD_BEFORE_CHOWN',recursive=False),sort_keys=True))
finally:os.close(fd)
'''


def need(v,s):
 if not v:raise ValueError(s)
def encode(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def owner(binding):
 need(binding['operation']==OP,'new outer operation required')
 token=hashlib.sha256((binding['source']+':'+binding['run']+':'+binding['job']).encode()).hexdigest()[:24]
 name='llvm23v2-'+token
 return dict(source=binding['source'],run=binding['run'],job=binding['job'],operation=OP,token=token,actor=name,init=name+'-init',volume=name+'-work')
def labels(b,role):return{'cachy-asahi.operation':OP,'cachy-asahi.llvm-work.source':b['source'],'cachy-asahi.llvm-work.token':b['token'],'cachy-asahi.llvm-work.role':role}
def volume_identity(row,b):
 need(row['Name']==b['volume']and row['Driver']=='local'and row.get('Scope')=='local'and not row.get('Options')and row['Labels']==labels(b,'work'),'exact owned local volume; no foreign cleanup')
def container_identity(row,name,image,b,role):
 need(row['Name']=='/'+name and re.fullmatch('[0-9a-f]{64}',row['Id'])and row['Image']==image and all(row['Config']['Labels'].get(k)==v for k,v in labels(b,role).items()),'exact source/token/role-owned container')
def init_options(b,image):
 return DOCKER+['create','--name',b['init'],*[x for k,v in labels(b,'initializer').items()for x in('--label',k+'='+v)],'--user=0:0','--init=false','--workdir=/','--cpus=1','--memory=512m','--memory-swap=512m','--pids-limit=64','--network=none','--read-only','--cap-drop=ALL','--cap-add=CHOWN','--security-opt=no-new-privileges','--mount',f"type=volume,src={b['volume']},dst=/work,volume-nocopy",'--entrypoint=/usr/bin/python3',image,'-I','-B','-c',INIT_CODE,encode(b).decode()]
def inspect_init(row,b,image):
 container_identity(row,b['init'],image,b,'initializer');h,c=row['HostConfig'],row['Config'];need(c['User']=='0:0'and c['Entrypoint']==['/usr/bin/python3']and c['Cmd']==['-I','-B','-c',INIT_CODE,encode(b).decode()],'exact initializer code/binding')
 need(h['ReadonlyRootfs']and h['NetworkMode']=='none'and h['CapDrop']==['ALL']and h['CapAdd']in(['CHOWN'],['CAP_CHOWN'])and h['SecurityOpt']==['no-new-privileges']and not h['Privileged']and not h['Devices']and not h.get('Init')and h['Memory']==h['MemorySwap']==512*1024**2 and h['NanoCpus']==10**9 and h['PidsLimit']==64 and h.get('UsernsMode','')=='','exact minimal initializer domain')
 mounts=row['Mounts'];need(len(mounts)==1 and mounts[0]['Type']=='volume'and mounts[0]['Name']==b['volume']and mounts[0]['Destination']=='/work'and mounts[0]['RW'],'initializer has only owned volume')
 declared=h['Mounts'];need(len(declared)==1 and declared[0]['Type']=='volume'and declared[0]['Source']==b['volume']and declared[0]['Target']=='/work'and declared[0]['VolumeOptions']['NoCopy']is True,'explicit initializer nocopy')
def receipt(value,b):
 need(value['schema']==1 and value['status']=='INITIALIZED_EMPTY_WORK_VOLUME'and value['binding']==b and value['recursive']is False and value['capabilities']=='CHOWN_ONLY_CHMOD_BEFORE_CHOWN','actual finite initializer receipt')
 before,after=value['before'],value['after'];need(before['uid']==before['gid']==0 and after['uid']==after['gid']==1001 and after['mode']==0o700 and (before['device'],before['inode'])==(after['device'],after['inode']),'same actual work volume initialized to1001:1001/0700')
 need(value['limits']=={'cpu.max':'100000 100000','memory.max':'536870912','memory.swap.max':'0','pids.max':'64'},'actual initializer limits')
def admission(b):
 return dict(schema=1,outer_operation=OP,inner_operation=INNER,binding=b,expected_owner=dict(uid=1001,gid=1001,mode=0o700),native_acceptance=False)

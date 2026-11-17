# SPDX-License-Identifier: MIT
"""Exact work-volume binding and finite owner initialization; no import actions.

Copy-up is an unproven explanation for the earlier LLVM ownership failure.
"""
import hashlib
import json
import re

OPERATION='rust199-source-reference-native-v1'
LIMITS={'cpu.max':'200000 100000','memory.max':'134217728','memory.swap.max':'0','pids.max':'32'}
INIT_CODE=r'''import json,os,stat,sys
from pathlib import Path
b=json.loads(sys.argv[1]);p=Path('/work')
def need(v,s):
 if not v:raise ValueError(s)
def node(s):return dict(device=s.st_dev,inode=s.st_ino,uid=s.st_uid,gid=s.st_gid,mode=stat.S_IMODE(s.st_mode))
print(json.dumps(dict(status='INITIALIZER_WORK_ROOT_OBSERVED',binding=b,actual=node(p.lstat())),sort_keys=True),file=sys.stderr,flush=True)
need(os.getuid()==os.geteuid()==os.getgid()==os.getegid()==0,'initializer root only')
status=dict(l.split(':',1)for l in Path('/proc/self/status').read_text().splitlines()if ':'in l)
need(all(int(status[k].strip(),16)==1 for k in('CapPrm','CapEff','CapBnd'))and all(int(status[k].strip(),16)==0 for k in('CapInh','CapAmb'))and status['NoNewPrivs'].strip()=='1','CHOWN only; no FOWNER or DAC capability')
need(os.uname().machine=='aarch64'and set(x.name for x in Path('/sys/class/net').iterdir())=={'lo'},'native isolated initializer')
need(os.statvfs('/').f_flag&os.ST_RDONLY and not os.statvfs(p).f_flag&os.ST_RDONLY,'readonly root and writable volume')
limits={n:(Path('/sys/fs/cgroup')/n).read_text().strip()for n in('cpu.max','memory.max','memory.swap.max','pids.max')}
need(limits=={'cpu.max':'200000 100000','memory.max':'134217728','memory.swap.max':'0','pids.max':'32'},'bounded initializer cgroup')
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


def encode(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def binding(source,image,root_admission_sha256):
    need(type(source)is dict and type(image)is str and re.fullmatch('sha256:[0-9a-f]{64}',image) and
         type(root_admission_sha256)is str and re.fullmatch('[0-9a-f]{64}',root_admission_sha256),'exact image and Root admission pins')
    token=hashlib.sha256(encode(source)).hexdigest()[:24];base='rust199-'+token
    return dict(source=source,image=image,root_admission_sha256=root_admission_sha256,token=token,
                init=base+'-init',prepare=base+'-prepare',makepkg=base+'-makepkg',volume=base+'-work',operation=OPERATION)


def admission(b):
    return dict(schema=1,operation=OPERATION,binding=b,expected_owner=dict(uid=1001,gid=1001,mode=0o700),native_acceptance=False)


def node(row):
    need(type(row)is dict and set(row)=={'device','inode','uid','gid','mode'} and all(type(v)is int for v in row.values()) and
         row['device']>=0 and row['inode']>0 and 0<=row['mode']<=0o7777,'actual finite directory stat row')


def verify_receipt(value,b):
    need(type(value)is dict and set(value)=={'schema','status','binding','before','after','limits','capabilities','recursive'} and
         value['schema']==1 and value['status']=='INITIALIZED_EMPTY_WORK_VOLUME' and value['binding']==b and
         value['recursive']is False and value['capabilities']=='CHOWN_ONLY_CHMOD_BEFORE_CHOWN' and value['limits']==LIMITS,
         'exact source/image/Root-bound finite initializer receipt')
    before,after=value['before'],value['after'];node(before);node(after)
    need(before['uid']==before['gid']==0 and after['uid']==after['gid']==1001 and after['mode']==0o700 and
         (before['device'],before['inode'])==(after['device'],after['inode']),'same actual work volume initialized1001:1001/0700')
    return value


def verify_work(value,initialized,actual,uid,gid,writable,empty,phase):
    need(phase in ('prepare','makepkg'),'only outer workload pre-entry checks')
    need(value==admission(value['binding']),'whole exact work-volume admission')
    verify_receipt(initialized,value['binding']);node(actual)
    need(uid==gid==1001 and actual==initialized['after'] and writable is True and
         type(empty)is bool and empty is (phase=='prepare'),'same initialized native1001 work root and phase emptiness')
    return dict(status='NONROOT_WORK_VOLUME_VERIFIED',binding=value['binding'],actual=actual,phase=phase,empty=empty,write_probe=False)

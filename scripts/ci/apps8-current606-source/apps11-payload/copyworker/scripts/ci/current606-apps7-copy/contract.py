# SPDX-License-Identifier: MIT
"""New copy-only actor contract; original six-capability actor is not modified."""
import hashlib,json,os,re,stat
from pathlib import Path
PURPOSE='CURRENT606_APPS7_OWNED_ORDINARY_SOURCE'
LOCK='3a586c1e3400391f56bd281ac9c16aba85d94d0fca002770e77ee1802c5d9fd1'
WORKER_CAPS=('CHOWN','DAC_OVERRIDE','FOWNER','FSETID','SETUID','SETGID','SYS_CHROOT','SETFCAP')
WORKER_MASK=0x800400db
BRIDGE_CAPS=('CHOWN','DAC_OVERRIDE','FOWNER','FSETID','SETFCAP');BRIDGE_MASK=0x8000001b
MAPS=('ordinary_observation','packages','capabilities','bridge_proof')
SOURCE_ROOT=Path('/seed');WORK_ROOT=Path('/work');PROOF_ROOT=Path('/bridge-proof')
BOUNDS=dict(max_packages=606,max_nodes=200000,max_bytes=6*1024**3,max_file_bytes=1024**3,max_depth=128)
COPY_SECONDS=600;WORKER_SECONDS=1800;CLEANUP_SECONDS=60;MAP_BYTES=64*1024**2;ALL_MAP_BYTES=128*1024**2

def need(ok,why):
 if not ok:raise ValueError(why)
def encoded(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def decode(raw):
 def pairs(rows):
  result={}
  for k,v in rows:need(k not in result,'duplicate JSON key');result[k]=v
  return result
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))
def ordinary(path,maximum=MAP_BYTES):
 path=Path(path);need(path.is_absolute()and '..'not in path.parts,'absolute contained input')
 parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  for part in path.parts[1:-1]:
   child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent);os.close(parent);parent=child
  fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
  try:
   before=os.fstat(fd);need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<before.st_size<=maximum,'bounded single-link ordinary input')
   raw=bytearray()
   while len(raw)<=before.st_size:
    block=os.read(fd,min(65536,before.st_size-len(raw)+1))
    if not block:break
    raw.extend(block)
   key=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
   need(len(raw)==before.st_size and key(before)==key(os.fstat(fd))==key(os.stat(path.name,dir_fd=parent,follow_symlinks=False)),'input identity drift')
   return bytes(raw)
  finally:os.close(fd)
 finally:os.close(parent)

def authority(selection,role,nonce):
 """Delegate only to the closed owner's exact source-pinned finite gate."""
 need(type(selection)is dict and selection.get('status')=='ROOT_BOUND_CURRENT606_APPS7_INPUTS'and type(selection.get('current606'))is dict and selection['current606'].get('source')is not None and selection['current606'].get('run')is not None,'current606 authority NULL/UNSUPPLIED; refuse before actors/copy')
 api=decode(ordinary(Path(__file__).resolve().with_name('owner-api.json'),1024**2))
 need(type(api)is dict and set(api)=={'path','bytes','sha256'},'owner API schema')
 need(all(api[k]is not None for k in api),'closed owner API UNSUPPLIED; refuse before actors/copy')
 need(api['path']=='/runner/owner/selection.py','fixed source-owned owner API')
 raw=ordinary(Path(api['path']),128*1024);need(pin(raw)=={k:api[k]for k in('bytes','sha256')},'whole owner API source pin')
 import types
 module=types.ModuleType('_current606_closed_owner_selection');module.__file__=api['path']
 exec(compile(raw,api['path'],'exec'),module.__dict__)
 context=module.verify_actor(selection,role,nonce)
 need(type(context)is dict and type(context.get('source_native'))is str and re.fullmatch('[0-9a-f]{40}',context['source_native'])and type(context.get('source_run'))is int and context['source_run']>0 and context.get('expected606_sha256')==LOCK,'owner-gated actual606 source/run/lock')
 return context

def capability_profile(status,ordinary_child=False):
 need(type(status)is dict,'complete process status')
 expected=0 if ordinary_child else WORKER_MASK
 for key in('CapEff','CapPrm'):need(status.get(key)==expected,'exact new worker capability profile')
 need(status.get('CapInh')==status.get('CapAmb')==0,'inherited/ambient capabilities refused')
 need(status.get('CapBnd')==WORKER_MASK,'exact worker bounding set')
 need(status.get('NoNewPrivs')==1,'NNP required')
 if ordinary_child:need(status.get('uid',0)>0 and status.get('gid',0)>0,'ordinary child identity')
 else:need(status.get('uid')==status.get('gid')==0,'owned root copy worker')
 return True


def bindings(rows):
 need(type(rows)is list and len(rows)==5,'five exact worker bind mounts')
 expected={'/runner':True,'/seed':True,'/bridge-proof':True,'/work':False,'/out':False}
 actual={}
 for row in rows:
  need(type(row)is dict and set(row)=={'source','target','readonly'},'typed worker bind row')
  src=Path(row['source']);need(src.is_absolute()and '..'not in src.parts and type(row['readonly'])is bool,'absolute explicit worker bind')
  need(row['target']not in actual,'duplicate worker mount');actual[row['target']]=row['readonly']
 need(actual==expected,'exact source/proof/runner readonly and work/output writable binds')
 return True

def actor_guard(nonce):
 need(type(nonce)is str and re.fullmatch('[0-9a-f]{32}',nonce),'owner nonce required')
 need(os.getuid()==os.geteuid()==0 and os.getpid()==1 and os.uname().machine=='aarch64'and Path('/.dockerenv').is_file(),'dedicated native root copy worker PID1')
 need(os.environ.get('CAA_CURRENT606_APPS7_COPY')==nonce and {p.name for p in Path('/sys/class/net').iterdir()}=={'lo'},'network-none owner-bound copy worker')
 raw=Path('/proc/self/status').read_text();need(len(raw)<=65536,'bounded worker status')
 fields=dict(line.split(':',1)for line in raw.splitlines()if ':'in line)
 status={k:int(fields[k],16)for k in('CapEff','CapPrm','CapBnd','CapInh','CapAmb')}
 status.update(NoNewPrivs=int(fields['NoNewPrivs']),uid=os.geteuid(),gid=os.getegid());capability_profile(status)
 return status


APPS_DIRS=('usr/lib/cachy-asahi-apps','usr/share/doc/cachy-asahi-apps','usr/share/licenses/cachy-asahi-apps')
APPS_FILES=frozenset(('usr/bin/cachy-asahi-apps',*(APPS_DIRS[0]+'/'+n for n in('apps.py','inventory.py','helper-pins.json')),*(APPS_DIRS[1]+'/'+n for n in('README.md','source-provenance.json')),*(APPS_DIRS[2]+'/'+n for n in('LICENSE','NOTICE'))))

# NULL until the genuinely accepted Apps11 pair is bound into this source.
APPS11_PAIR={'bytes': 26716, 'sha256': '80fe5fd4117c5b994e724ba29bb60473da86d829af757c8c62bea1164758901a'}

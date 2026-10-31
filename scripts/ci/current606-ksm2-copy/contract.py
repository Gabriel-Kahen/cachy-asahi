# SPDX-License-Identifier: MIT
"""New copy-only actor contract; original six-capability actor is not modified."""
import contextlib
import hashlib,json,os,re,stat
from pathlib import Path
PURPOSE='CURRENT606_KSM2_OWNED_ORDINARY_SOURCE'
LOCK='3a586c1e3400391f56bd281ac9c16aba85d94d0fca002770e77ee1802c5d9fd1'
WORKER_CAPS=('CHOWN','DAC_OVERRIDE','FOWNER','FSETID','SETUID','SETGID','SYS_CHROOT','SETFCAP')
WORKER_MASK=0x800400db
BRIDGE_CAPS=('CHOWN','DAC_OVERRIDE','FOWNER','FSETID','SETFCAP');BRIDGE_MASK=0x8000001b
MAPS=('ordinary_observation','packages','capabilities','bridge_proof')
SOURCE_ROOT=Path('/seed');WORK_ROOT=Path('/work');PROOF_ROOT=Path('/bridge-proof')
BOUNDS=dict(max_packages=606,max_nodes=200000,max_bytes=6*1024**3,max_file_bytes=1024**3,max_depth=128)
COPY_SECONDS=600;WORKER_SECONDS=1800;CLEANUP_SECONDS=60;MAP_BYTES=64*1024**2;ALL_MAP_BYTES=128*1024**2

# Diagnostic-only fixed vocabulary: no paths, contents, nonce, timing or authority.
PHASE_LABELS=frozenset(('startup', 'authority', 'sealed-maps', 'mount-proof', 'plan-load', 'source-observe', 'source-database', 'source-capabilities', 'copy-context', 'copy-observe', 'copy-hardlinks-root', 'copy-capabilities', 'copy-retire', 'lifecycle', 'driver-plan', 'driver-baseline', 'exclusive-ownership', 'keyring', 'private-fixtures', 'graph', 'fixture-preservation', 'database', 'capabilities', 'physical', 'home-preservation', 'selected-database', 'transaction-plan', 'transaction-child', 'transaction-receipt', 'installed-fixture', 'source-proof', 'source-proof-capabilities', 'baseline-capture', 'result-publish', 'baseline1.transaction', 'baseline1.readback', 'baseline1.fixtures', 'baseline1.post-fixture-readback', 'baseline1.source-proof', 'upgrade2.transaction', 'upgrade2.readback', 'upgrade2.fixtures', 'upgrade2.post-fixture-readback', 'upgrade2.source-proof', 'same-version2.transaction', 'same-version2.readback', 'same-version2.fixtures', 'same-version2.post-fixture-readback', 'same-version2.source-proof', 'remove2.transaction', 'remove2.readback', 'remove2.fixtures', 'remove2.post-fixture-readback', 'remove2.source-proof', 'reinstall2.transaction', 'reinstall2.readback', 'reinstall2.fixtures', 'reinstall2.post-fixture-readback', 'reinstall2.source-proof', 'restore-original1.transaction', 'restore-original1.readback', 'restore-original1.fixtures', 'restore-original1.post-fixture-readback', 'restore-original1.source-proof'))
PHASE_LINE_CAP=512;PHASE_BYTE_CAP=32768
_phase_counts=[0,0]
def phase_marker(event,label):
 if event not in('BEGIN','END','FAIL')or label not in PHASE_LABELS:return
 raw=('KSM361_PHASE '+event+' '+label+'\n').encode('ascii')
 if len(raw)>96 or _phase_counts[0]>=PHASE_LINE_CAP or _phase_counts[1]+len(raw)>PHASE_BYTE_CAP:return
 _phase_counts[0]+=1;_phase_counts[1]+=len(raw)
 try:os.write(2,raw)
 except OSError:pass

@contextlib.contextmanager
def phase(label):
 phase_marker('BEGIN',label)
 try:yield
 except BaseException:
  phase_marker('FAIL',label)
  raise
 else:phase_marker('END',label)

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
 need(type(selection)is dict and selection.get('status')=='ROOT_BOUND_CURRENT606_KSM2_INPUTS'and type(selection.get('current606'))is dict and selection['current606'].get('source')is not None and selection['current606'].get('run')is not None,'current606 authority NULL/UNSUPPLIED; refuse before actors/copy')
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
 need(os.environ.get('CAA_CURRENT606_KSM2_COPY')==nonce and {p.name for p in Path('/sys/class/net').iterdir()}=={'lo'},'network-none owner-bound copy worker')
 raw=Path('/proc/self/status').read_text();need(len(raw)<=65536,'bounded worker status')
 fields=dict(line.split(':',1)for line in raw.splitlines()if ':'in line)
 status={k:int(fields[k],16)for k in('CapEff','CapPrm','CapBnd','CapInh','CapAmb')}
 status.update(NoNewPrivs=int(fields['NoNewPrivs']),uid=os.geteuid(),gid=os.getegid());capability_profile(status)
 return status


KSM_DIRS=('usr/share/doc/cachy-asahi-ksmctl','usr/share/licenses/cachy-asahi-ksmctl')
KSM_FILES=frozenset(('usr/bin/cachy-asahi-ksmctl','usr/bin/cachy-asahi-ksm-experiment',*(KSM_DIRS[0]+'/'+n for n in('README.md','source-provenance.json','experiment-provenance.json')),*(KSM_DIRS[1]+'/'+n for n in('LICENSE','NOTICE'))))
OLD_FILES=KSM_FILES-{'usr/bin/cachy-asahi-ksm-experiment',KSM_DIRS[0]+'/experiment-provenance.json'}

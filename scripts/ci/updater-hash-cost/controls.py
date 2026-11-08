#!/usr/bin/env python3
"""New combined cache+v2 DATA controls and explicit legacy39 compatibility view.

Only pinned AST fragments and private ordinary fixtures execute. No lifecycle,
Source constructor, reader, compiler, subprocess, package or native actor.
"""
import argparse,ast,hashlib,json,os,sys,tempfile,time,types
from pathlib import Path
D=Path(__file__).resolve().parent
pin=lambda b:dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def need(v,why):
 if not v:raise ValueError(why)
def extract(raw,names,env):
 nodes=[]
 for n in ast.parse(raw).body:
  if isinstance(n,(ast.FunctionDef,ast.ClassDef))and n.name in names:nodes.append(n)
  elif isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id in names for t in n.targets):nodes.append(n)
 exec(compile(ast.Module(nodes,type_ignores=[]),'<pinned-combined-DATA-fragments>','exec'),env);return env
NAMES={'_initializer_clone','_initializer_hash_api','_initializer_valid','_initializer_capture','_INITIALIZER_PROFILE','_INITIALIZER_PREFIX','_INITIALIZER_MAX','_INITIALIZER_PHASES'}
class Clock:
 def __init__(self):self.n=0
 def __call__(self):self.n+=1;return self.n
class Limits:
 def __init__(self,fail=False):self.calls=0;self.fail=fail
 def tick(self):
  self.calls+=1
  if self.fail and self.calls==2:raise ValueError('root observation deadline')
class State:
 def __init__(self):self.ops=[0]*10
 def add(self,index,value=1):self.ops[index]+=value
 def progress(self,end):pass

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,required=True);parser.add_argument('--support-root',type=Path);parser.add_argument('--v1-view',type=Path);args=parser.parse_args();support=args.support_root or args.root
 operands=json.loads((D/'operands.json').read_bytes());raws={};assets={}
 for name,row in operands['canonical'].items():
  raw=(args.root/name).read_bytes();need(pin(raw)==row,'exact composed canonical '+name);raws[name]=raw
 for name,row in operands['assets'].items():
  raw=(D/row['file']).read_bytes();need(pin(raw)=={k:row[k]for k in('bytes','sha256')},'exact compatibility/frozen operand '+name);assets[name]=raw
 checkpoint=(support/'scripts/update/aux_checkpoint.py').read_bytes();need(pin(checkpoint)==operands['aux_checkpoint'],'held checkpoint')
 need(pin((support/'scripts/ci/initializer_mount_query_controls.py').read_bytes())==operands['legacy_control'],'unchanged strict legacy39 control')
 def fence(event,values):
  if event.startswith(('subprocess.','socket.'))or event in('os.system','os.fork','os.posix_spawn','ctypes.dlopen','os.kill','os.killpg'):raise RuntimeError('combined DATA actor denied '+event)
 sys.addaudithook(fence)
 rows=[];nonce='a'*32
 with tempfile.TemporaryDirectory(prefix='combined-data-')as temporary:
  leaf=Path(temporary)/'owned'
  for scope in ('maintained','frozen'):
   oldroot=assets['legacy/scripts/update/full_root.py']if scope=='maintained'else assets['frozen-before/full_root.py']
   newroot=raws['scripts/update/full_root.py']if scope=='maintained'else assets['frozen/full_root.py']
   producer=raws['scripts/update/aux_initialize.py']if scope=='maintained'else assets['frozen/aux_initialize.py']
   caller=raws['scripts/ci/full-root-upgrade-caller/upgrade_hook.py']if scope=='maintained'else assets['frozen/upgrade_hook.py']
   for case in ('combined-two-chunks','combined-deadline','combined-entry-change'):
    outcomes=[]
    for measured in (False,True):
     leaf.write_bytes(b'K'*(1024**2+17));fd=os.open(leaf,os.O_RDONLY);expected=os.fstat(fd)
     if case=='combined-entry-change':
      with leaf.open('ab')as f:f.write(b'x')
     trace={'read_sizes':[],'read_bytes':0,'updates':[],'fstats':0};clock=Clock();state=State();proxy=types.SimpleNamespace(**vars(os))
     def read(fd,size):trace['read_sizes'].append(size);value=os.read(fd,size);trace['read_bytes']+=len(value);return value
     def fstat(fd):trace['fstats']+=1;return os.fstat(fd)
     proxy.read=read;proxy.fstat=fstat
     class Digest:
      def __init__(self,*a,**k):self.value=hashlib.sha256(*a,**k)
      def update(self,b):trace['updates'].append(len(b));return self.value.update(b)
      def hexdigest(self):return self.value.hexdigest()
     backend=types.SimpleNamespace(**vars(hashlib));backend.sha256=Digest
     roots=extract(newroot if measured else oldroot,{'_identity','_file_hash'},dict(os=proxy,hashlib=backend,need=need))
     api=extract(producer,NAMES,dict(os=proxy,hashlib=backend,json=json,sys=sys,time=types.SimpleNamespace(monotonic_ns=clock)))
     fn=api['_initializer_hash_api'](types.SimpleNamespace(_file_hash=roots['_file_hash']),state,clock=clock)if measured else roots['_file_hash']
     limits=Limits(case=='combined-deadline')
     try:outcome=('digest',fn(fd,expected,limits))
     except ValueError as error:outcome=('refusal',str(error))
     finally:os.close(fd)
     outcomes.append((outcome,trace,limits.calls))
     if measured:
      need(state.ops[4]==1 and state.ops[5]==trace['read_bytes'],'combined count/read bytes')
      need(state.ops[8]==len(trace['read_sizes'])and state.ops[9]==len(trace['updates'])and state.ops[7]>=state.ops[8]+state.ops[9],'combined exact delegated-call split timers')
    need(outcomes[0]==outcomes[1],'combined cache+telemetry changed digest/reads/fstat/ticks/refusal')
    rows.append(dict(scope=scope,case=case,status='PASS_COMBINED_EQUIVALENCE',outcome=outcomes[1][0],ops=state.ops))
   new=extract(producer,NAMES,dict(json=json));consumer=extract(caller,NAMES,dict(json=json));old=extract(assets['legacy/scripts/update/aux_initialize.py'],NAMES-{'_initializer_hash_api'},dict(json=json))
   v2=dict(v=2,profile='I16K_STATX_HASH_SPLIT_V2',nonce=nonce,lane='WORKER',seq=0,phase='WORKER_OBSERVE',state='REFUSED',elapsed_ns=0,remaining_ns=-1,ops=[0]*10,saturated=False)
   v1=dict(v2,v=1,profile='I16K_STATX_V1',ops=[0]*8)
   need(old['_initializer_valid'](v1,nonce)and not old['_initializer_valid'](v2,nonce),'strict historical v1 route')
   need(new['_initializer_valid'](v2,nonce)and consumer['_initializer_valid'](v2,nonce)and not new['_initializer_valid'](v1,nonce)and not consumer['_initializer_valid'](v1,nonce),'strict v2 producer/caller route')
   wire=lambda v:new['_INITIALIZER_PREFIX']+json.dumps(v,sort_keys=True,separators=(',',':')).encode()+b'\n'
   need(new['_initializer_capture'](wire(v2),nonce)==(v2,1)and new['_initializer_capture'](wire(v1)+wire(dict(v2,seq=1)),nonce)==(None,0),'framed v2 route refuses mixed profile')
   rows.append(dict(scope=scope,case='strict-v1-v2-source-routes-and-mixed-frame-refusal',status='PASS_NO_MIXED_ADMISSION'))
  bridge=extract(assets['frozen/aux_copy.py'],{'_descriptor_root_bytes','_DESCRIPTOR_ROOT_PROFILE','_DESCRIPTOR_ROOT_INVERSE','_DESCRIPTOR_PINS'},dict(_descriptor_hashlib=hashlib))
  def baseline(raw):
   raw=bridge['_descriptor_root_bytes'](raw,need)
   if b'max_packages: int = 607'in raw:raw=raw.replace(b'max_packages: int = 607',b'max_packages: int = 587',1)
   need((len(raw),hashlib.sha256(raw).hexdigest())==bridge['_DESCRIPTOR_PINS']['full_root'],'whole descriptor baseline')
   return raw
  need(baseline(assets['frozen/full_root.py'])==baseline(assets['frozen-before/full_root.py']),'whole frozen cache inverse')
  rows.append(dict(case='combined-source-cache-whole-descriptor-bridge',status='PASS_EXACT_BASELINE'))
 if args.v1_view:
  need(not os.path.lexists(args.v1_view),'fresh explicit compatibility view')
  for name in operands['canonical']:
   target=args.v1_view/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(assets['legacy/'+name]);target.chmod(0o644)
  target=args.v1_view/'scripts/update/aux_checkpoint.py';target.write_bytes(checkpoint);target.chmod(0o644)
  need({f.relative_to(args.v1_view).as_posix()for f in args.v1_view.rglob('*')if f.is_file()}==set(operands['canonical'])|{'scripts/update/aux_checkpoint.py'},'exact four-leaf legacy view')
 need(len(rows)==9,'exact nine NEW combined controls; no skipped case')
 print(json.dumps(dict(status='PASS_NEW_COMBINED_CANONICAL_DATA_ONLY',new_controls=len(rows),rows=rows,canonical_v2_covered=True,legacy39='UNCHANGED_OLD_V1_VIEW_ONLY_NOT_V2_COVERAGE',legacy39_executed=False,performance_claim=False,source_constructor_calls=0,reader_calls=0,native=0,Root_acceptance=None),sort_keys=True))
if __name__=='__main__':main()

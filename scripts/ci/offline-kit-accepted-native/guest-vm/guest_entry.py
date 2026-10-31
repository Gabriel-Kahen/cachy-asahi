#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Owned ARM guest PID1 orchestrates byte-held original Kit phases."""
import ast,base64,ctypes,hashlib,importlib.util,json,os,re,stat,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import guest_phase as G
BASE=Path('/kit77');ROOT=BASE/'source';WORK=BASE/'work';PUBLIC=BASE/'public';RUNTIME=BASE/'runtime';LANE='scripts/ci/offline-kit-accepted-native'
LOCK='cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac'
BUDGET=dict(overall=15840,prepare=2400,qemu=10380,export=1200,cleanup=300,kit=4500,produce=300,receive=300,candidate=1500)

need,read,sha,encoded=G.need,G.read,G.sha,G.encoded

def pin(raw):return dict(bytes=len(raw),sha256=sha(raw))
def selection(v):
 keys={'schema','purpose','identity','nonce','image','kernel','launcher_epoch_s','source_map_sha256','uid','gid','source_manifest','accepted_manifest','runtime_manifest','budgets'}
 need(type(v)is dict and set(v)==keys and type(v['schema'])is int and v['schema']==1 and v['purpose']=='KIT77_SOFTWARE_ARM_GUEST_FULL_LIFECYCLE_V1','closed selection')
 need(type(v['nonce'])is str and re.fullmatch('[a-f0-9]{32}',v['nonce'])and type(v['image'])is str and re.fullmatch('sha256:[a-f0-9]{64}',v['image']),'nonce/image origin')
 i=v['identity'];need(type(i)is dict and set(i)=={'source_sha','feature_code_sha','run_id','token','consumer'},'whole original identity')
 need(type(i['source_sha'])is str and re.fullmatch('[a-f0-9]{40}',i['source_sha'])and i['feature_code_sha']==i['source_sha']and type(i['run_id'])is str and re.fullmatch('[1-9][0-9]*',i['run_id']),'source/run')
 token=sha((i['source_sha']+':'+i['run_id']+':1:accepted-tools').encode())[:16];need(i['token']==token and i['consumer']=='offline-kit-accepted-'+token,'original token')
 need(type(v['uid'])is type(v['gid'])is int and v['uid']==v['gid']==1001 and v['budgets']==BUDGET and all(type(x)is int for x in v['budgets'].values()),'fixed UID/GID/budgets')
 need(type(v['launcher_epoch_s'])is int and 946684800<=v['launcher_epoch_s']<4102444800,'actual launch UTC; PREPARE None refuses')
 need(type(v['source_map_sha256'])is str and re.fullmatch('[a-f0-9]{64}',v['source_map_sha256'])and type(v['kernel'])is dict and type(v['kernel'].get('profile'))is dict and type(v['kernel']['profile'].get('release'))is str,'kernel/map')
 for key in('source_manifest','accepted_manifest','runtime_manifest'):
  need(type(v[key])is dict and v[key],'complete source/input/runtime map')
  for n,r in v[key].items():
   need(type(n)is str and n and not n.startswith('/')and '..'not in n.split('/')and '\\'not in n,'safe source name')
   need(type(r)is dict and set(r)=={'bytes','sha256','mode'}and type(r['bytes'])is int and 0<=r['bytes']<=16*1024**2 and type(r['mode'])is int and r['mode']in(420,493)and re.fullmatch('[a-f0-9]{64}',r['sha256']or''),'numeric source pin')
 need(len(v['source_manifest'])>=77 and len(v['accepted_manifest'])==23 and all('/'not in n for n in v['runtime_manifest']),'whole source/carrier/runtime');return v

def disk_serial(nonce,role):return base64.b85encode(hashlib.sha256(b'cachy-asahi/core7/virtio-blk/serial-v1\0'+role.encode()+b'\0'+bytes.fromhex(nonce)).digest()[:16]).decode()

def vm_guard(s):
 need(os.getpid()==1 and os.getuid()==os.geteuid()==0 and os.uname().machine=='aarch64'and os.sysconf('SC_PAGE_SIZE')==16384,'actual ARM16K guest Python PID1')
 need(not os.path.lexists('/.dockerenv')and os.uname().release==s['kernel']['profile']['release'],'exact guest kernel');words=Path('/proc/cmdline').read_text().split()
 for x in('kit77_vm='+s['nonce'],'caa_core_vm='+s['nonce'],'caa_core_phase=1','caa_core_realtime='+str(s['launcher_epoch_s'])):need([w for w in words if w.startswith(x.split('=')[0]+'=')]==[x],'one exact kernel selector '+x.split('=')[0])
 need(not any(x in words for x in('apparmor=0','selinux=0','enforcing=0','security=none','lsm=none')),'no LSM-disable selector');need({p.name for p in Path('/sys/class/net').iterdir()}=={'lo'},'offline guest')
 root=Path('/').stat();need(root.st_ino==2 and os.major(root.st_dev)>0,'actual ext4 root')
 for role,dev in [('boot','vda'),('data','vdb')]:need(Path('/sys/class/block/'+dev+'/serial').read_text().strip()==disk_serial(s['nonce'],role),'whole nonce disk serial')
 return dict(pid=1,uid=0,architecture=os.uname().machine,page_size=16384,kernel=os.uname().release,boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),serials={r:disk_serial(s['nonce'],r)for r in('boot','data')})
def save(path,value,uid=0):
 path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
 with path.open('xb')as stream:stream.write(encoded(value))
 path.chmod(0o600);os.chown(path,uid,uid)
def emit(s,event,**fields):
 v=dict(schema=1,event=event,nonce=s['nonce'],selection_sha256=s['_selection_sha256'],acceptance=False,**fields);wire=json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False);need(len(wire.encode())<=65536,'bounded frame');print('KIT77_VM '+s['nonce']+' '+wire,flush=True)
def module(path,name):
 spec=importlib.util.spec_from_file_location(name,path);v=importlib.util.module_from_spec(spec);sys.modules[name]=v;spec.loader.exec_module(v);return v

class NativeOps:
 def __init__(self,s):
  need(Path(__file__).resolve()==Path('/kit77/runtime/guest_entry.py'),'fixed canonical guest entry path');self.s=s;self.root=vm_guard(s);self.actor=None;self.created=[];self.mounts_retired=True;self.kit_start=None;self.cgroup_base=None;self.cgroups=[]
 def initial(self):
  s=self.s;need(not any(WORK.iterdir())and not any(PUBLIC.iterdir()),'fresh owned work/public')
  for key,root in [('source_manifest',ROOT),('accepted_manifest',BASE/'accepted'),('runtime_manifest',RUNTIME)]:
   rows=s[key];need({p.relative_to(root).as_posix()for p in root.rglob('*')if p.is_file()}==set(rows)and not any(p.is_symlink()for p in root.rglob('*')),'whole '+key)
   for n,r in rows.items():need(dict(pin(read(root/n)),mode=stat.S_IMODE((root/n).stat().st_mode))==r,'input pin '+n)
  need(sha(read(ROOT/LANE/'source-map.json'))==s['source_map_sha256'],'whole source map')
  need(sha(read(RUNTIME/'owner_common.py'))=='dbb12f84b78a1b4c2d4916bcd82f0993f83765f09105de638c17ebafd4ce8ecd','held original Actors')
  self.C=module(RUNTIME/'owner_common.py','_kit77_actors');self.owner=module(ROOT/LANE/'owner.py','_kit77_public');self.V=module(ROOT/LANE/'guest-vm/vm_contract.py','_kit77_authority');self.M=module(ROOT/LANE/'guest-vm/media_helper.py','_kit77_media')
  epoch=s['launcher_epoch_s'];before=time.time_ns();mono=time.monotonic_ns();time.clock_settime(time.CLOCK_REALTIME,epoch);after=time.time_ns();end=time.monotonic_ns();need(epoch*10**9<=after<=epoch*10**9+(end-mono)+10**9 and 0<=end-mono<=5*10**9,'launch UTC readback')
  clock=dict(source='ROOT_BOUND_CURRENT_QEMU_LAUNCH_UTC',epoch_seconds=epoch,previous_realtime_ns=before,initialized_realtime_ns=after,monotonic_before_ns=mono,monotonic_after_ns=end)
  need(s['kernel']==G.SC.decode(read(ROOT/LANE/'guest-vm/kernel-policy.json'))['kernel'],'exact Core kernel policy')
  self.current_keys=self.V.key_preflight(BASE/'accepted',int(time.time()),18610)
  save(WORK/'vm/source-proof.json',dict(schema_version=1,status='WHOLE_GUEST_SOURCE_INPUT_RUNTIME_PIN_JOIN_ONLY',nonce=s['nonce'],source_map_sha256=s['source_map_sha256'],source_files=len(s['source_manifest']),accepted_files=23,runtime_files=len(s['runtime_manifest']),acceptance=False))
  save(WORK/'vm/clock.json',clock);save(WORK/'vm/root.json',self.root);return dict(self.root,clock=clock)
 def preflight(self):
  s=self.s;policy=self.V.accepted_policy();need(policy['files']==s['accepted_manifest'],'current public carrier authority');facts=self.V.key_preflight(BASE/'accepted',int(time.time()),18610)
  for n in s['accepted_manifest']:
   if n not in('maintenance.TEST-public.asc','diagnostics.TEST-public.asc','FILES.json'):need(read(BASE/'accepted'/n)==read(ROOT/LANE/'accepted'/n),'original archive/signature/provenance held')
  accepted=WORK/'accepted-carrier';accepted.mkdir(mode=0o755)
  for n in s['accepted_manifest']:(accepted/n).write_bytes(read(BASE/'accepted'/n));(accepted/n).chmod(0o644)
  self.carrier=dict(source=policy['source'],tree=policy['tree'],ref=policy['ref'],files=23,bytes=sum(r['bytes']for r in s['accepted_manifest'].values()),inventory_sha256=sha(read(accepted/'FILES.json')),actual_authority=False,current_public_certificates=facts);save(WORK/'accepted-carrier.json',self.carrier);return facts
 def start(self):
  root=Path('/sys/fs/cgroup');need({'memory','pids'}<=set((root/'cgroup.controllers').read_text().split()),'guest memory+pids controllers')
  with(root/'cgroup.subtree_control').open('w')as f:f.write('+memory +pids')
  base=root/('kit77-'+self.s['nonce']);need(not base.exists(),'fresh nonce-owned resource parent');base.mkdir();st=base.stat();self.cgroup_base=(base,st.st_dev,st.st_ino)
  with(base/'cgroup.subtree_control').open('w')as f:f.write('+memory +pids')
  self.kit_start=time.monotonic();self.actor=self.C.Actors(WORK/'vm-actors',4500)
 def begin_tool(self,tool):
  current=WORK/tool;current.mkdir(mode=0o755);trial=current/'trial';trial.mkdir(mode=0o700);os.chown(trial,1001,1001);save(trial/'identity.json',dict(identity=self.s['identity'],image=self.s['image'],packages_sha256=LOCK,accepted_carrier=self.carrier),1001)
  raw=read(ROOT/LANE/'expected-packages.lock');need(sha(raw)==LOCK,'original574 lock');(trial/'packages.lock').write_bytes(raw);(trial/'packages.lock').chmod(0o644)
 def select_candidate(self,tool):
  current=WORK/tool;inputs=current/'candidate-inputs';inputs.mkdir(mode=0o555);out=current/'candidate-output';out.mkdir(mode=0o700);os.chown(out,1001,1001);(out/'client-state').mkdir(mode=0o700);os.chown(out/'client-state',1001,1001)
  selected=module(ROOT/LANE/'select_candidate.py','_kit77_selector').make(ROOT/LANE/'candidate-source',current/'trial/public/transport',current/'trial/public/trust',self.s['identity'],self.s['image']);save(inputs/'candidate-selection.json',selected,1001);return selected
 def targets(self,rows):
  self.created=[];self.mounts_retired=False
  for r in rows:
   p=Path(r['target']);existed=os.path.lexists(p)
   if existed:need(p.is_dir()and not p.is_symlink()and not any(p.iterdir()),'empty baseline role directory')
   elif r['type']=='directory':p.mkdir(mode=0o755)
   else:p.touch(mode=0o644)
   st=p.lstat();self.created.append((p,existed,(st.st_dev,st.st_ino,st.st_mode,st.st_uid,st.st_gid)))
 def retire_targets(self):
  for p,existed,key in reversed(self.created):
   st=p.lstat();need((st.st_dev,st.st_ino,st.st_mode,st.st_uid,st.st_gid)==key and not p.is_symlink()and not os.path.ismount(p),'same unmounted role inode');need(not any(p.iterdir())if p.is_dir()else st.st_size==0,'empty placeholder')
   if not existed:
    if p.is_dir():p.rmdir()
    else:p.unlink()
  self.created=[];self.mounts_retired=True
 def resource_leaf(self,tool,phase):
  p=self.cgroup_base[0]/(tool+'-'+phase);need(not p.exists(),'fresh owned phase cgroup');p.mkdir();st=p.stat();need(st.st_uid==st.st_gid==0,'owned cgroup root');self.cgroups.append((p,st.st_dev,st.st_ino))
  for n,v in [('memory.max','1073741824'),('pids.max','128')]:
   with(p/n).open('w')as f:f.write(v)
   need((p/n).read_text().strip()==v,'exact resource limit readback')
  return p
 def resource_retire(self,p):
  held=next(r for r in self.cgroups if r[0]==p);st=p.stat();need((st.st_dev,st.st_ino)==held[1:]and st.st_uid==st.st_gid==0,'same owned resource inode')
  events=dict(x.split()for x in(p/'cgroup.events').read_text().splitlines());need(events.get('populated')=='0'and not(p/'cgroup.procs').read_text().strip(),'actual phase cgroup empty')
  memory={k:int(v)for k,v in(x.split()for x in(p/'memory.events').read_text().splitlines())}
  again=p.stat();need((again.st_dev,again.st_ino)==held[1:]and again.st_uid==again.st_gid==0 and not p.is_symlink(),'same resource inode immediately before removal')
  p.rmdir();need(not p.exists(),'owned phase cgroup removed');self.cgroups.remove(held)
  return dict(path=str(p),device=st.st_dev,inode=st.st_ino,uid=0,gid=0,populated=0,procs_empty=True,memory_events=memory,same_inode=True,removed=True)
 def phase(self,tool,phase):
  rows=G.mount_rows(tool,phase);current=WORK/tool;resource=self.resource_leaf(tool,phase)
  if phase=='receive':p=current/'receiver';p.mkdir(mode=0o700);os.chown(p,1001,1001)
  raw=read(current/'candidate-inputs/candidate-selection.json',1024**2)if phase=='candidate'else None
  v=dict(schema_version=1,cgroup_path=str(resource),identity=self.s['identity'],nonce=self.s['nonce'],image_origin=self.s['image'],tool=tool,phase=phase,source_map_sha256=self.s['source_map_sha256'],kernel_release=self.s['kernel']['profile']['release'],mounts=rows,env=G.environment(self.s['identity'],tool,phase,raw),argv=['/usr/bin/python','-I','-B','/trial-code/trial.py',phase],seconds=BUDGET[phase],receipt_path='/kit77/work/vm/phases/'+tool+'-'+phase+'-boundary.json');G.descriptor(v)
  path=WORK/'vm/phases'/(tool+'-'+phase+'.descriptor.json');save(path,v);self.targets(rows)
  command=['/usr/bin/unshare','--mount','--pid','--net','--mount-proc','--fork','--kill-child=SIGKILL','--','/usr/bin/python3','-I','-B','/kit77/runtime/guest_phase.py','--descriptor',str(path),'--sha256',sha(read(path))]
  primary=None
  try:self.actor.run(command,timeout=BUDGET[phase])
  except BaseException as error:primary=error;raise
  finally:
   try:self.retire_targets()
   except BaseException as error:
    if primary is None:raise
    primary.add_note('phase target retirement failed: '+str(error)[:512])
  resource_record=self.resource_retire(resource);need(resource_record['memory_events'].get('oom_kill')==0,'no phase OOM kill')
  row=self.actor.rows[-1];need(row['status']=='PASS'and type(row['exit'])is int and row['exit']==0 and all(row[k]is True for k in('natural_exit','group_absent','leader_reaped','leader_held_until_group_inspection'))and row['forced_retirement']is False and row['reservation']=='REAPED','natural original actor retirement')
  log=read(row['log']);prefix=('KIT77_PHASE_BOUNDARY '+self.s['nonce']+' ').encode();lines=[x for x in log.splitlines()if x.startswith(prefix)];need(len(lines)==1 and len(lines[0])<=65536,'one original boundary stdout frame');body=lines[0][len(prefix):];boundary=G.SC.decode(body)
  need(boundary['descriptor_sha256']==sha(read(path))and boundary['phase']==phase and boundary['tool']==tool and boundary['nonce']==self.s['nonce'],'source/context boundary')
  target=Path(v['receipt_path']);target.write_bytes(body+b'\n');target.chmod(0o600)
  record=dict(schema_version=1,resource_retirement=resource_record,status='COMPLETED_VM_PHASE_ORIGINAL_TRIAL_NO_OUTER_CLEANUP_CREDIT',identity=self.s['identity'],nonce=self.s['nonce'],tool=tool,phase=phase,actor_index=len(self.actor.rows)-1,actor_row=row,descriptor=pin(read(path)),boundary=pin(read(target)),actor_log=pin(log),boundary_frame=dict(offset=log.index(lines[0]),bytes=len(lines[0]),sha256=sha(lines[0])),acceptance=False);save(WORK/'vm/phases'/(tool+'-'+phase+'.json'),record);return record
 def original_result(self,tool,phase):
  p=WORK/tool
  if phase=='produce':
   need(not (p/'trial/producer').exists()and not(p/'trial/signing').exists(),'original producer/private signing removal');return G.SC.decode(read(p/'trial/public/producer.json'))
  if phase=='receive':
   value=G.SC.decode(read(p/'receiver/receiver.json'));need(value['status']=='PASS_RELOCATED_NATIVE_DEVELOPMENT_VERIFY_AND_PROPOSED_PLAN'and value['packages_installed']is False,'original receiver checks');return value
  value=G.SC.decode(read(p/'candidate-output/candidate-lifecycle.json'));need(value['status']=='PASS_FINITE_REAL_CANDIDATE_DISPOSABLE_ALPM_LIFECYCLE'and value['original574_database_restored']is True and len(value['events'])==5 and len(value['offline_authentication_refusal_recovery'])==3,'original five-phase lifecycle/recovery gates');return value
 def observe(self):
  for key,root in [('source_manifest',ROOT),('accepted_manifest',BASE/'accepted'),('runtime_manifest',RUNTIME)]:
   for n,r in self.s[key].items():need(dict(pin(read(root/n)),mode=stat.S_IMODE((root/n).stat().st_mode))==r,'input preservation '+n)
  import guest_observer as O
  return O.observe(self.s,self.M)
 def retired(self):
  if self.created:self.retire_targets()
  for p,_,_ in tuple(self.cgroups):self.resource_retire(p)
  if self.cgroup_base:
   p,dev,ino=self.cgroup_base;st=p.stat();need((st.st_dev,st.st_ino)==(dev,ino)and st.st_uid==st.st_gid==0 and not(p/'cgroup.procs').read_text().strip(),'same empty owned resource parent');need(dict(x.split()for x in(p/'cgroup.events').read_text().splitlines()).get('populated')=='0','no live phase resource descendants');p.rmdir();self.cgroup_base=None
  rows=self.actor.rows if self.actor else[]
  good=bool(rows)and all(r.get('natural_exit')is True and r.get('group_absent')is True and r.get('leader_reaped')is True and r.get('forced_retirement')is False and r.get('reservation')=='REAPED'for r in rows)
  return dict(status='PASS_GUEST_PHASES_RETIRED'if good and self.mounts_retired else'FAILED_OR_UNKNOWN_RETIREMENT',phase_processes='ABSENT_NATURALLY_REAPED'if good else'UNKNOWN',phase_mount_targets='RETIRED_SAME_OWNED_NODES'if self.mounts_retired else'UNKNOWN')
 def export(self,result):
  allowed=self.owner.public_names({'files':self.s['source_manifest']})|{'vm/'+n+'.json'for n in('result','root','clock','source-proof')}
  for tool in('maintenance','diagnostics'):
   for phase in('produce','receive','candidate'):
    stem='vm/phases/'+tool+'-'+phase;allowed.update((stem+'.json',stem+'-boundary.json',stem+'.descriptor.json'))
  allowed.add('vm-actors/actors.json');allowed.update('vm-actors/'+str(i).zfill(4)+'.log'for i in range(6));files={};total=0
  quarantined=set();partial_expected={}
  for tool in('maintenance','diagnostics'):
   pair={tool+'/candidate-output/'+n for n in('candidate-partial.json','candidate-partial.tar.gz')}
   if os.path.lexists(WORK/tool/'candidate-output'):
    try:
     verified=self.owner.partial_retention(WORK/tool,self.s['identity'])
     if verified is not None:
      need(verified['status']=='VERIFIED_PARTIAL_DATA_ONLY','verified original partial DATA pair only')
      for name in pair:
       kind='capsule'if name.endswith('.tar.gz')else'manifest';partial_expected[name]=dict(bytes=verified[kind+'_bytes'],sha256=verified[kind+'_sha256'])
     else:need(not any(os.path.lexists(WORK/n)for n in pair),'partial pair requires original verification')
    except BaseException as error:
     quarantined.update(pair|{tool+'/candidate-output/candidate-exports.tar.gz'});result['status']='FAILED_OR_INCOMPLETE_NO_ADMISSION';result.setdefault('retention_errors',[]).append(dict(tool=tool,type=type(error).__name__,reason=str(error)[:1024]))
  allowed-=quarantined
  save(WORK/'vm/result.json',result)
  def emit_file(path,name):
   nonlocal total
   need(self.owner.portable_public(name)and not self.owner.private_retention(tuple(name.split('/'))),'original public/private retention boundary');raw=read(path)
   if name in partial_expected:need(pin(raw)==partial_expected[name],'same verified partial body before public copy')
   total+=len(raw);need(len(files)<2047 and total<=126*1024**2,'public file/byte caps');target=PUBLIC/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw);target.chmod(0o600);files[name]=pin(raw)
  for name in sorted(allowed):
   if os.path.lexists(WORK/name):emit_file(WORK/name,name)
  for name in sorted(self.s['source_manifest']):emit_file(ROOT/name,'source/'+name)
  index=dict(schema=1,purpose='KIT77_GUEST_PUBLIC_INDEX_V1',identity=self.s['identity'],nonce=self.s['nonce'],status='KIT77_GUEST_PUBLIC_DATA_ONLY',result_status=result['status'],files=files,bytes=total,acceptance=False);body=encoded(index);need(len(body)<=2*1024**2 and total+len(body)<=126*1024**2,'whole indexed public cap');(PUBLIC/'index.json').write_bytes(body);(PUBLIC/'index.json').chmod(0o600);return pin(body)

def original_gate(phase,value):
 need(type(value)is dict,'original phase result object')
 if phase=='produce':need(value['status']=='PASS_ACCEPTED_NATIVE_DATA_ORIGINAL_SIGNATURE_AND_TEST_KIT_ASSEMBLY','original producer full result')
 elif phase=='receive':need(value['status']=='PASS_RELOCATED_NATIVE_DEVELOPMENT_VERIFY_AND_PROPOSED_PLAN'and value['packages_installed']is False,'original receiver full result')
 else:need(value['status']=='PASS_FINITE_REAL_CANDIDATE_DISPOSABLE_ALPM_LIFECYCLE'and value['original574_database_restored']is True and len(value['events'])==5 and len(value['offline_authentication_refusal_recovery'])==3,'original candidate lifecycle/recovery full result')
 return value

def run(s,ops,writer=emit):
 boot=ops.initial();writer(s,'boot',**boot);failure=None;before=after=None;phases=[];tools={};index=None;retired=dict(status='FAILED_OR_UNKNOWN_RETIREMENT',phase_processes='UNKNOWN',phase_mount_targets='UNKNOWN')
 result=dict(schema_version=1,status='FAILED_OR_INCOMPLETE_NO_ADMISSION',identity=s['identity'],nonce=s['nonce'],image_origin=s['image'],operation='kit-vm-lifecycle',phases=phases,tools=tools,preservation=dict(source_nodes='UNKNOWN',source_capabilities='UNKNOWN',inventory='UNKNOWN'),software_vm=True,hardware='NOT_RUN',release='NOT_ADMITTED',outer_cleanup='PENDING_PARENT_OWNERSHIP_PROOF',acceptance=False)
 try:
  result['certificate_preflight']=ops.preflight();before=ops.observe();ops.start()
  for tool in('maintenance','diagnostics'):
   ops.begin_tool(tool);reports={}
   for phase in('produce','receive','candidate'):
    if phase=='candidate':ops.select_candidate(tool)
    phases.append(ops.phase(tool,phase));reports[phase]=original_gate(phase,ops.original_result(tool,phase))
   tools[tool]=reports
  after=ops.observe();need(before==after,'whole original574/source/capability/inventory preserved before and after all Kit phases')
  result.update(status='PASS_SOFTWARE_ARM_VM_ORIGINAL_TWO_KIT_LIFECYCLES_PENDING_OUTER_CLEANUP',preservation=dict(source_nodes='PASS',source_capabilities='PASS',inventory='PASS'),before=before,after=after)
 except BaseException as error:failure=error;result['error']=dict(type=type(error).__name__,reason=str(error)[:2048])
 finally:
  try:
   retired=ops.retired();need(retired['status']=='PASS_GUEST_PHASES_RETIRED','guest phase retirement incomplete')
  except BaseException as error:
   result['status']='FAILED_OR_INCOMPLETE_NO_ADMISSION';result['retirement_error']=dict(type=type(error).__name__,reason=str(error)[:1024])
   if failure is None:failure=error
   else:failure.add_note('guest retirement failed: '+str(error)[:512])
  result['guest_retirement']=retired
  try:index=ops.export(result)
  except BaseException as error:
   result['status']='FAILED_OR_INCOMPLETE_NO_ADMISSION'
   if failure is None:failure=error
   else:failure.add_note('public export failed: '+str(error)[:512])
  writer(s,'result',status=result['status'],index=index,preservation=result['preservation'],kit_lifecycle='PASS_TWO_ORIGINAL_KITS_VM_ONLY'if result['status'].startswith('PASS_')else'NOT_ADMITTED',software_vm=True,hardware='NOT_RUN',release='NOT_ADMITTED',outer_cleanup='PENDING_PARENT_OWNERSHIP_PROOF')
  writer(s,'exit',**retired)
 return result,failure

def main():
 raw=read(BASE/'selection.json',4*1024**2);s=selection(G.SC.decode(raw));s['_selection_sha256']=sha(raw);ops=NativeOps(s)
 try:
  result,error=run(s,ops)
  if error is not None:print('KIT77_GUEST_ERROR '+type(error).__name__+': '+str(error)[:2048],flush=True)
 except BaseException as error:print('KIT77_GUEST_PREEXEC_REFUSAL '+type(error).__name__+': '+str(error)[:1024],flush=True)
 finally:
  sys.stdout.flush();sys.stderr.flush();os.sync();ctypes.CDLL(None).reboot(0x4321fedc)
if __name__=='__main__':main()

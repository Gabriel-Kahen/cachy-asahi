#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Separate owned ARM software-VM Kit route. Native owner/transactions are held."""
import argparse,errno,fcntl,hashlib,os,re,shutil,signal,stat,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import vm_contract as V
HERE=V.HERE;ROOT=V.ROOT;NATIVE=V.LANE;LABEL='org.cachy-asahi.kit138-fresh-test-vm-owner'
def load_proof(a,execute=True):
 V.selected();O=V.original();manifest,own,tmp=O.binding(a,execute);p=V.decode(V.read(Path(a.work)/'source-proof.json'))
 V.need(p['status']=='PASS_PRESECRET_COMPLETE_FRESH_ROOT_TEST_KIT_VM_SOURCE'and p['identity']==own and p['operation']==V.OPERATION and p['map_sha256']==a.manifest_sha256,'same explicit VM source/operation proof')
 V.need(p['scope']=='SOFTWARE_ARM_VM_ONLY'and p['acceptance']is False,'VM-only execution authority');return O,manifest,own,tmp

def native_primitives(a):
 O,manifest,own,tmp=load_proof(a)
 # Private verified module: only admission for the NEW operation is adapted.
 # Original transport/bootstrap/retirement function bodies and native file held.
 O.admitted=lambda args:load_proof(args)[1:]
 return O,manifest,own,tmp

def proof(a):
 V.selected();O=V.original();manifest,own,tmp=O.binding(a);keys=V.key_preflight(HERE/'accepted-public');work=V.fresh(Path(a.work))
 V.save(work/'source-proof.json',dict(status='PASS_PRESECRET_COMPLETE_FRESH_ROOT_TEST_KIT_VM_SOURCE',identity=own,operation=V.OPERATION,map_sha256=a.manifest_sha256,files=len(manifest['files'])+3,scope='SOFTWARE_ARM_VM_ONLY',accepted_files=47,current_files=23,history_files=23,key_preflight=keys,acceptance=False,native='NOT_RUN'))
 with open(os.environ['GITHUB_OUTPUT'],'a')as f:f.write('job_token='+own['token']+'\n')
def transport(a):
 O,*_=native_primitives(a);return O.transport(a)
def bootstrap(a):
 O,*_=native_primitives(a);return O.bootstrap(a)
def object_id(kind,raw):return hashlib.sha1(kind.encode()+b' '+str(len(raw)).encode()+b'\0'+raw).digest()
def tree_id(rows,bodies):
 def descend(prefix):
  body=b'';names={n[len(prefix):].split('/')[0]for n in rows if n.startswith(prefix)}
  for name in sorted(names,key=lambda n:(n+('/'if prefix+n not in rows else'')).encode()):
   path=prefix+name
   if path in rows:mode=b'100755'if rows[path]['mode']==493 else b'100644';oid=object_id('blob',bodies[path])
   else:mode=b'40000';oid=descend(path+'/')
   body+=mode+b' '+name.encode()+b'\0'+oid
  return object_id('tree',body)
 return descend('').hex()
def kernel_inputs(work):
 p=V.decode(V.read(HERE/'kernel-policy.json'));carrier=ROOT/'retained-native-tools/kernel';rows=p['carrier_files'];contents={};actual=set()
 for folder,dirs,files in os.walk(carrier):
  if Path(folder)==carrier and '.git'in dirs:dirs.remove('.git')
  V.need(not any((Path(folder)/n).is_symlink()for n in(*dirs,*files)),'ordinary kernel DATA');actual.update((Path(folder)/n).relative_to(carrier).as_posix()for n in files)
 V.need(actual==set(rows),'all28 immutable Core kernel leaves')
 for n,r in rows.items():
  b=V.read(carrier/n,r['bytes']);V.need(V.pin(b)=={k:r[k]for k in('bytes','sha256')}and stat.S_IMODE((carrier/n).stat().st_mode)==r['mode'],'exact Core kernel bytes/modes');contents[n]=b
 V.need(tree_id(rows,contents)==p['carrier_tree'],'whole Core kernel carrier tree');target=V.fresh(work/'kernel-inputs');payload=V.fresh(target/'kernel')
 for n,b in contents.items():
  V.need(n.startswith('payload/')and '/'not in n[8:],'flat kernel DATA');(payload/n[8:]).write_bytes(b)
 provider=HERE/'providers';saved=sys.path[:]
 try:
  V.need('contract'not in sys.modules,'no foreign kernel contract cache');sys.path.insert(0,str(provider));K=V.load('held_kernel_input',provider/'kernel_input.py')
  V.need(Path(K.C.__file__).resolve()==provider/'contract.py','original kernel verifier closure');profile,receipt,image,config=K.imported(p['kernel'],target,provider)
 finally:sys.path[:]=saved;sys.modules.pop('contract',None)
 V.need(profile==p['kernel']['profile']and V.row(image)==profile['Image']and V.row(config)==profile['config'],'original kernel build authority, not new build')
 V.save(work/'kernel.json',dict(status='PINNED_CORE_GENERIC16K_KERNEL_IMPORTED_BUILD_DATA_ONLY',carrier_source=p['carrier_source'],carrier_tree=p['carrier_tree'],profile=profile,import_receipt=receipt,Image=V.row(image),config=V.row(config),boot='NOT_RUN',acceptance=False));shutil.copyfile(image,work/'Image');return p['kernel']
def accepted(work):
 p=V.accepted_policy();src=ROOT/'retained-native-tools/accepted';V.carrier_namespace(src,p['files']);keys=V.key_preflight(src);dst=V.fresh(work/'accepted')
 for n,r in p['files'].items():
  b=V.read(src/n,r['bytes']);V.need(V.pin(b)=={k:r[k]for k in('bytes','sha256')}and stat.S_IMODE((src/n).stat().st_mode)==r['mode'],'exact reviewed fresh TEST carrier DATA');target=dst/n;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(b);target.chmod(r['mode'])
 return V.key_preflight(dst),p

def helper_mounts(vm,disks):return [(str(vm),'/workspace',True),(str(ROOT),'/source',True),(str(disks),'/measurement',False)]
def media_command(own,image,vm,disks,role):
 name='kit77-vm-'+own['nonce']+'-'+role;cmd=['create','--name',name,'--label',LABEL+'='+own['nonce'],'--label',LABEL+'.role='+role,'--pull=never','--platform=linux/arm64','--user=0:0','--cap-drop=ALL','--security-opt=no-new-privileges','--read-only','--network=none','--pids-limit=256','--memory=2g','--cpus=2','--tmpfs=/tmp:rw,nosuid,nodev,size=512m']
 for cap in('CHOWN','DAC_OVERRIDE','FOWNER','FSETID','SETFCAP'):cmd+=['--cap-add='+cap]
 for src,dst,ro in helper_mounts(vm,disks):cmd+=['--mount','type=bind,src='+src+',dst='+dst+(',readonly'if ro else'')]
 return name,[*cmd,'--env','KIT77_VM_MEDIA_NONCE='+own['nonce'],'--env','KIT77_VM_MEDIA_IMAGE='+image,'--entrypoint=/usr/bin/python3',image,'-I','-B','/source/scripts/ci/offline-kit-accepted-native/guest-vm/fresh-test/media_helper.py',role]
def media_inspection(row,own,image,vm,disks,role):
 V.need(role in('prepare','export','scrub','bind-launch'),'finite inspected helper role');bind=role=='bind-launch';h=row['HostConfig'];c=row['Config'];name='kit77-vm-'+own['nonce']+'-'+role
 V.need(row['Name']=='/'+name and row['Image']==image and re.fullmatch('[a-f0-9]{64}',row['Id']or'')and c['Labels'].get(LABEL)==own['nonce']and c['Labels'].get(LABEL+'.role')==role,'same owned helper ID/image/nonce/role')
 expected={'CHOWN','DAC_OVERRIDE','FOWNER','FSETID','SETFCAP'};caps=h.get('CapAdd')or[]
 V.need((not caps if bind else len(caps)==5 and(set(caps)==expected or set(caps)=={'CAP_'+n for n in expected}))and h['CapDrop']==['ALL']and h['SecurityOpt']==['no-new-privileges']and c['User']=='0:0'and h['Privileged']is False and h['ReadonlyRootfs']is True and h['AutoRemove']is False and h['NetworkMode']=='none'and h.get('PidMode','')==''and h.get('IpcMode','private')in('','private')and h.get('UTSMode','')==''and not h.get('Devices')and not h.get('DeviceRequests')and not h.get('VolumesFrom'),'exact isolated helper capabilities/namespaces')
 V.need(h['PidsLimit']==(64 if bind else 256)and h['Memory']==(256*1024**2 if bind else 2*1024**3)and h['NanoCpus']==(1000000000 if bind else 2000000000),'exact helper resources')
 mounts=row['Mounts'];actual=[(m['Source'],m['Destination'],not m['RW'])for m in mounts if m['Type']=='bind'];V.need(len(actual)==3 and set(actual)==set(helper_mounts(vm,disks))and all(m['Type']=='bind'or(m['Type']=='tmpfs'and m['Destination']=='/tmp')for m in mounts)and set(h['Tmpfs'])=={'/tmp'}and set(h['Tmpfs']['/tmp'].split(','))=={'rw','nosuid','nodev','size=8m'if bind else'size=512m'},'exact helper mounts/tmpfs')
 expected_env=dict(x.split('=',1)for x in own.get('image_env',[]))
 if not bind:expected_env.update(KIT77_VM_MEDIA_NONCE=own['nonce'],KIT77_VM_MEDIA_IMAGE=image)
 observed=c.get('Env')or[];V.need(all(type(x)is str and'='in x for x in observed)and len({x.split('=',1)[0]for x in observed})==len(observed)and dict(x.split('=',1)for x in observed)==expected_env,'exact image/helper environment')
 cmd=['-I','-B','-c',BIND_CODE]if bind else['-I','-B','/source/scripts/ci/offline-kit-accepted-native/guest-vm/fresh-test/media_helper.py',role]
 V.need(c['Entrypoint']==['/usr/bin/python3']and c['Cmd']==cmd,'exact source-owned helper entrypoint');return row['Id']

def remaining(deadline,nominal,reserve=300):
 value=min(nominal,deadline-time.monotonic()-reserve);V.need(value>1,'VM deadline/reserved cleanup exhausted');return value

def state_save(vm,state):V.update(vm/'host-state.json',state)
def runtime_actor(O,directory,seconds):return V.load('vm_runtime',HERE/'vm_runtime.py').derive(O.C)(directory,seconds)
def disk_identity(path,size):
 p=Path(path);s=p.lstat();V.need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_uid==os.getuid()and not s.st_mode&0o022 and s.st_size==size and not any(q.is_symlink()for q in(p,*p.parents)),'owned fixed VM disk');return dict(device=s.st_dev,inode=s.st_ino,uid=s.st_uid,bytes=s.st_size)
def checked_image(actor,O,base,own):
 V.need(base['status']=='PASS_ACTUAL_FRESH_ACCEPTED574_PRODUCER'and base['identity']==own and re.fullmatch('sha256:[a-f0-9]{64}',base['image']or''),'same fresh574 bootstrap');core=O.C.module(ROOT/'scripts/ci/maintained_desktop574.py','vm_existing574_image');core.docker=actor.docker;r=core.inspect_image(base['image'],own['token']);V.need(r['Id']==base['image'],'owned immutable574 image');return r

def media_actor(actor,context,image,vm,disks,role,deadline,state):
 V.need(role in('prepare','export','scrub'),'finite media role');reserve=0 if role=='scrub'else 300;left=lambda n:remaining(deadline,n,reserve);name,command=media_command(context,image,vm,disks,role);V.need(not actor.docker('ps','-aq','--no-trunc','--filter','name=^/'+name+'$',timeout=left(30)),'fresh owned helper')
 cid=actor.docker(*command,timeout=left(30));V.need(re.fullmatch('[a-f0-9]{64}',cid or''),'created helper CID');entry=dict(cid=cid,name=name,role=role,retired=False);state['helpers'].append(entry);state_save(vm,state)
 rows=V.decode(actor.docker('inspect',cid,timeout=left(30)));V.need(len(rows)==1 and media_inspection(rows[0],context,image,vm,disks,role)==cid,'same helper inspect');V.save(vm/('media-'+role+'-inspection.json'),rows[0]);actor.docker('start','--attach',cid,timeout=left(V.BUDGET[role if role!='scrub'else'cleanup']))
 stopped=V.decode(actor.docker('inspect',cid,timeout=left(30)))[0];media_inspection(stopped,context,image,vm,disks,role);V.need(stopped['State']['Status']=='exited'and stopped['State']['ExitCode']==0 and stopped['State']['OOMKilled']is False,'natural media completion');V.save(vm/('media-'+role+'-stopped.json'),stopped);actor.docker('rm',cid,timeout=left(30));V.need(not actor.docker('ps','-aq','--no-trunc','--filter','id='+cid,timeout=left(30)),'owned helper absent');entry['retired']=True;state_save(vm,state)

def input_data():
 p=V.decode(V.read(HERE/'kernel-policy.json'));carrier=ROOT/'retained-native-tools/kernel';rows=p['carrier_files'];bodies={};actual=set()
 for folder,dirs,files in os.walk(carrier,followlinks=False):
  if Path(folder)==carrier and '.git'in dirs:dirs.remove('.git')
  V.need(not any((Path(folder)/n).is_symlink()for n in(*dirs,*files)),'ordinary kernel DATA');actual.update((Path(folder)/n).relative_to(carrier).as_posix()for n in files)
 V.need(actual==set(rows),'whole28 Core kernel leaves')
 for n,w in rows.items():
  b=V.read(carrier/n,w['bytes']);V.need(V.pin(b)=={k:w[k]for k in('bytes','sha256')}and stat.S_IMODE((carrier/n).stat().st_mode)==w['mode'],'exact kernel DATA');bodies[n]=b
 V.need(tree_id(rows,bodies)==p['carrier_tree'],'whole immutable kernel tree');policy=V.accepted_policy();accepted_root=ROOT/'retained-native-tools/accepted';V.carrier_namespace(accepted_root,policy['files'])
 for n,w in policy['files'].items():V.need(V.pin(V.read(accepted_root/n,w['bytes']))=={k:w[k]for k in('bytes','sha256')}and stat.S_IMODE((accepted_root/n).stat().st_mode)==w['mode'],'exact accepted DATA')
 return dict(status='EXACT_PUBLIC_VM_INPUTS_TIME_WINDOW_CHECKED_NO_ACTORS',kernel_source=p['carrier_source'],kernel_tree=p['carrier_tree'],keys=V.key_preflight(accepted_root),acceptance=False)
def check_inputs(a):
 load_proof(a,False);host_tools();return input_data()

BIND_CODE="""import hashlib,json,os,stat,subprocess
from pathlib import Path
p=Path('/measurement/data.raw');s=p.lstat();assert stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_size==24*1024**3
raw=Path('/workspace/launch-selection.json').read_bytes();assert len(raw)<=2*1024**2
for q in ('rm /kit77/selection.json','write /workspace/launch-selection.json /kit77/selection.json','set_inode_field /kit77/selection.json mode 0100600','set_inode_field /kit77/selection.json uid 0','set_inode_field /kit77/selection.json gid 0','dump /kit77/selection.json /tmp/readback.json'):
 r=subprocess.run(['/usr/bin/debugfs','-w','-R',q,str(p)],capture_output=True,timeout=15);assert r.returncode==0 and len(r.stdout)+len(r.stderr)<=65536
assert Path('/tmp/readback.json').read_bytes()==raw
r=subprocess.run(['/usr/bin/debugfs','-R','ls -p /kit77',str(p)],capture_output=True,timeout=15);assert r.returncode==0 and len(r.stdout)+len(r.stderr)<=65536
rows=[x.split(b'/')for x in r.stdout.splitlines()if x.startswith(b'/')];rows=[x for x in rows if len(x)==8 and x[5]==b'selection.json'];assert len(rows)==1
x=rows[0];assert x[1].isdigit()and int(x[1])>0 and int(x[2],8)==0o100600 and x[3]==x[4]==b'0'and x[6].isdigit()and int(x[6])==len(raw)
z=p.lstat();assert(s.st_dev,s.st_ino,s.st_size)==(z.st_dev,z.st_ino,z.st_size)
print(json.dumps({'status':'EXACT_CURRENT_LAUNCH_SELECTION_BOUND','bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}))
"""
def bind_command(context,image,vm,disks):
 name='kit77-vm-'+context['nonce']+'-bind-launch';command=['create','--name',name,'--label',LABEL+'='+context['nonce'],'--label',LABEL+'.role=bind-launch','--pull=never','--platform=linux/arm64','--user=0:0','--cap-drop=ALL','--security-opt=no-new-privileges','--read-only','--network=none','--pids-limit=64','--memory=256m','--cpus=1','--tmpfs=/tmp:rw,nosuid,nodev,size=8m']
 for src,dst,ro in helper_mounts(vm,disks):command+=['--mount','type=bind,src='+src+',dst='+dst+(',readonly'if ro else'')]
 return name,command+['--entrypoint=/usr/bin/python3',image,'-I','-B','-c',BIND_CODE]

def bind_launch(actor,context,image,vm,disks,selection,deadline,state):
 epoch=int(time.time());V.need(1700000000<=epoch<2**32,'current launcher UTC');bound=dict(selection,launcher_epoch_s=epoch);raw=V.encoded(bound);V.need(len(raw)<=2*1024**2,'bounded selection');V.save(vm/'launch-selection.json',bound);before=disk_identity(disks/'data.raw',24*1024**3);name,command=bind_command(context,image,vm,disks)
 V.need(not actor.docker('ps','-aq','--no-trunc','--filter','name=^/'+name+'$',timeout=remaining(deadline,15)),'fresh binding helper');cid=actor.docker(*command,timeout=remaining(deadline,15));V.need(re.fullmatch('[a-f0-9]{64}',cid or''),'binding CID');entry=dict(cid=cid,name=name,role='bind-launch',retired=False);state['helpers'].append(entry);state_save(vm,state)
 row=V.decode(actor.docker('inspect',cid,timeout=remaining(deadline,15)))[0];media_inspection(row,context,image,vm,disks,'bind-launch');V.save(vm/'media-bind-launch-inspection.json',row);result=V.decode(actor.docker('start','--attach',cid,timeout=remaining(deadline,120)));r=V.decode(actor.docker('inspect',cid,timeout=remaining(deadline,15)))[0];media_inspection(r,context,image,vm,disks,'bind-launch');V.need(r['State']['Status']=='exited'and r['State']['ExitCode']==0 and r['State']['OOMKilled']is False and result==dict(status='EXACT_CURRENT_LAUNCH_SELECTION_BOUND',**V.pin(raw)),'exact UTC selection/readback');actor.docker('rm',cid,timeout=remaining(deadline,15));V.need(not actor.docker('ps','-aq','--no-trunc','--filter','id='+cid,timeout=remaining(deadline,15)),'binding helper absent');entry['retired']=True;state_save(vm,state)
 V.need(disk_identity(disks/'data.raw',24*1024**3)==before and 0<=time.time()-epoch<=120,'same owned disk/current context');V.save(vm/'launch-context.json',dict(status='CURRENT_UTC_GUEST_SELECTION_BOUND_AND_READ_BACK',epoch=epoch,selection=V.pin(raw),disk=before,acceptance=False));return bound

def uart(raw,selection):
 V.need(type(raw)is bytes and len(raw)<=16*1024**2 and b'Kernel panic - not syncing:'not in raw,'bounded complete nonpanic UART');prefix=('KIT77_VM '+selection['nonce']+' ').encode();lines=[x.rstrip(b'\r')for x in raw.splitlines()if x.startswith(b'KIT77_VM ')];V.need(len(lines)==3 and all(x.startswith(prefix)for x in lines),'three same-nonce frames');frames=[V.decode(x[len(prefix):])for x in lines];common={'schema','event','nonce','selection_sha256','acceptance'};extra=[{'pid','uid','architecture','page_size','kernel','boot_id','serials','clock'},{'status','index','preservation','kit_lifecycle','software_vm','hardware','release','outer_cleanup'},{'status','phase_processes','phase_mount_targets'}]
 for f,event,fields in zip(frames,('boot','result','exit'),extra):V.need(type(f)is dict and set(f)==common|fields and type(f['schema'])is int and f['schema']==1 and f['event']==event and f['nonce']==selection['nonce']and f['selection_sha256']==V.pin(V.encoded(selection))['sha256']and f['acceptance']is False,'closed UART frame')
 b,r,e=frames;V.need(type(b['pid'])is int and b['pid']==1 and type(b['uid'])is int and b['uid']==0 and b['architecture']=='aarch64'and type(b['page_size'])is int and b['page_size']==16384 and b['kernel']==selection['kernel']['profile']['release']and re.fullmatch('[a-f0-9-]{36}',b['boot_id']or'')and b['serials']=={n:V.disk_serial(selection['nonce'],n)for n in('boot','data')},'actual owned16K PID1/serials')
 c=b['clock'];V.need(type(c)is dict and set(c)=={'source','epoch_seconds','previous_realtime_ns','initialized_realtime_ns','monotonic_before_ns','monotonic_after_ns'}and c['source']=='ROOT_BOUND_CURRENT_QEMU_LAUNCH_UTC'and type(c['epoch_seconds'])is int and c['epoch_seconds']==selection['launcher_epoch_s']and all(type(c[k])is int and c[k]>=0 for k in c if k not in('source','epoch_seconds'))and c['monotonic_after_ns']>=c['monotonic_before_ns']and abs(c['initialized_realtime_ns']-c['epoch_seconds']*10**9)<=2*10**9,'actual current guest clock')
 V.need(r['software_vm']is True and r['hardware']=='NOT_RUN'and r['release']=='NOT_ADMITTED'and r['outer_cleanup']=='PENDING_PARENT_OWNERSHIP_PROOF'and r['status']in('PASS_SOFTWARE_ARM_VM_FRESH_ROOT_TEST_TWO_KIT_LIFECYCLES_PENDING_OUTER_CLEANUP','FAILED_OR_INCOMPLETE_NO_ADMISSION')and r['kit_lifecycle']in('PASS_TWO_FRESH_ROOT_TEST_KITS_VM_ONLY','NOT_ADMITTED')and type(r['preservation'])is dict and set(r['preservation'])=={'inventory','source_nodes','source_capabilities'}and all(x in('PASS','UNKNOWN')for x in r['preservation'].values()),'software-only result');V.need(e['status']in('PASS_GUEST_PHASES_RETIRED','FAILED_OR_UNKNOWN_RETIREMENT')and e['phase_processes']in('ABSENT_NATURALLY_REAPED','UNKNOWN')and e['phase_mount_targets']in('RETIRED_SAME_OWNED_NODES','UNKNOWN'),'guest retirement');return dict(boot=b,result=r,exit=e)

def export_join(vm,disks,selection,frames):
 receipt=V.decode(V.read(disks/'guest-export.json'));V.need(receipt['status']=='EXACT_KIT77_PUBLIC_FILES_DATA_ONLY'and receipt['nonce']==selection['nonce']and receipt['acceptance']is False,'same media export');files=receipt['files'];V.need(type(files)is dict and 0<len(files)<=2048 and 'index.json'in files,'bounded exported namespace');root=disks/'guest-export';paths=list(root.rglob('*'));V.need(not any(p.is_symlink()for p in paths)and {p.relative_to(root).as_posix()for p in paths if p.is_file()}==set(files),'closed ordinary public export');M=V.load('media_public_helpers',HERE/'media_helper.py');allowed,portable,private=M.public_allowlist(selection,ROOT);total=0
 for name,pin in files.items():
  V.need(name=='index.json'or(name in allowed and portable(name)and not private(tuple(name.split('/')))),'exact public privacy allowlist');V.need(type(pin)is dict and set(pin)=={'bytes','sha256'}and type(pin['bytes'])is int and 0<=pin['bytes']<=16*1024**2 and V.row(root/name)==pin,'guest original body pin');total+=pin['bytes']
 V.need(total==receipt['bytes']and total<=126*1024**2 and files['index.json']['bytes']<=2*1024**2 ,'bounded export aggregate');uart_join=frames is not None and frames['result']['index']is not None
 if uart_join:V.need(frames['result']['index']==files['index.json'],'original UART/index body join')
 index=V.decode(V.read(root/'index.json',2*1024**2));V.need(index['identity']==selection['identity']and index['nonce']==selection['nonce']and index['files']=={n:p for n,p in files.items()if n!='index.json'}and index['bytes']==sum(p['bytes']for n,p in files.items()if n!='index.json')and index['acceptance']is False,'exact original public index');V.need(not os.path.lexists(vm/'public'),'fresh promoted public output');root.rename(vm/'public');V.save(vm/'export.json',dict(status='PINNED_GUEST_PUBLIC_DATA_ONLY',files=files,bytes=total,identity=selection['identity'],nonce=selection['nonce'],uart_index_join=uart_join,acceptance=False));return receipt

def inspect_or_absent(actor,cid,deadline):
 raw=actor.docker('inspect',cid,timeout=remaining(deadline,30,0),allowed=(0,1));row=actor.rows[-1]
 if row['exit']==1:V.need(cid in raw and 'No such'in raw,'unambiguous exact helper absence');return None
 values=V.decode(raw);V.need(len(values)==1,'one exact helper inspect');return values[0]

def same_helper_config(before,after):
 if before['Id']!=after['Id']or before['Config']!=after['Config']:return False
 values=[]
 for r in(before,after):
  h=dict(r['HostConfig'])
  if 'OomKillDisable'not in h or not(h['OomKillDisable']is False or h['OomKillDisable']is None):return False
  h['OomKillDisable']=False;values.append(h)
 return values[0]==values[1]

def cleanup_helpers(actor,context,image,vm,disks,deadline,state):
 for entry in reversed(state['helpers']):
  V.need(type(entry['cid'])is str and re.fullmatch('[a-f0-9]{64}',entry['cid'])and entry['name']=='kit77-vm-'+context['nonce']+'-'+entry['role'],'known exact owned helper');row=inspect_or_absent(actor,entry['cid'],deadline)
  if row is not None:
   V.need(media_inspection(row,context,image,vm,disks,entry['role'])==entry['cid'],'owned helper before retirement');saved=vm/('media-'+entry['role']+'-inspection.json')
   if saved.exists():
    before=V.decode(V.read(saved));V.need(before['Id']==row['Id']and same_helper_config(before,row),'same original helper immutable configuration')
   actor.docker('rm','--force',entry['cid'],timeout=remaining(deadline,30,0));V.need(inspect_or_absent(actor,entry['cid'],deadline)is None,'helper absent after owned retirement')
  entry['retired']=True;state_save(vm,state)
 state['helpers_absent']=True;state_save(vm,state)
def retire_media(actor,context,image,vm,disks,deadline,state):
 V.need(state['helpers_absent']is True and(not state['qemu_started']or state['qemu_group_absent']is True),'unknown QEMU group retains backing media')
 if (disks/'stage').exists():media_actor(actor,context,image,vm,disks,'scrub',deadline,state)
 V.need(not(disks/'stage').exists(),'no original stage remains');i=disks.lstat();V.need([i.st_dev,i.st_ino]==state['disks_identity']and i.st_uid==os.getuid()and not disks.is_symlink()and not disks.is_mount()and shutil.rmtree.avoids_symlink_attacks,'only recorded owned backing directory');shutil.rmtree(disks);state['media_retired']=True;state_save(vm,state)

def execute(a):
 O,manifest,own,tmp=native_primitives(a);work=Path(a.work);V.need(not any(os.path.lexists(work/n)for n in('guest-vm','kit-actors','kit-results.json','maintenance','diagnostics','ordered-cleanup.json')),'fresh VM-only operation namespace');input_data();vm=V.fresh(work/'guest-vm');disks=V.fresh(vm/'disks');i=disks.stat();nonce=os.urandom(16).hex();state=dict(identity=own,nonce=nonce,helpers=[],helpers_absent=False,qemu_started=False,qemu_group_absent=None,media_retired=False,disks_identity=[i.st_dev,i.st_ino],acceptance=False);state_save(vm,state);deadline=time.monotonic()+V.BUDGET['overall'];state['deadline_monotonic']=deadline;state_save(vm,state);actor=runtime_actor(O,vm/'actors',V.BUDGET['overall']);failure=None;frames=None;fds=[]
 report=dict(status='FAILED_OR_INCOMPLETE_SOFTWARE_VM_ONLY',identity=own,nonce=nonce,software_vm=True,acceptance=False,native_admission=False,hardware='NOT_RUN',release='NOT_ADMITTED',outer_cleanup='PENDING')
 try:
  base=V.decode(V.read(work/'bootstrap.json'));image=base['image'];inspection=checked_image(actor,O,base,own);V.save(vm/'image-inspection.json',inspection);context=dict(own,nonce=nonce,image_env=inspection['Config'].get('Env')or[]);state['context']=context;state['image']=image;state_save(vm,state);tools_before=host_tools(actor);V.save(vm/'tools.json',dict(status='HOST_TOOLS_OBSERVED_BEFORE_ONLY',before=tools_before,after=None,image_tools=dict(image=image,installed574_lock=V.LOCK,package='e2fsprogs 1.47.4-1',authority='SOURCE_PINNED_MEDIA_COMMANDS_PLUS_FULL_ROOT_ELF_AND_NODE_OBSERVATIONS'),acceptance=False));kernel=kernel_inputs(vm);keys,policy=accepted(vm);V.save(vm/'key-preflight.json',keys)
  runtime=V.fresh(vm/'runtime');runtime_rows={}
  for name in('guest_entry.py','guest_phase.py','guest_seccomp.py','guest_observer.py'):
   b=V.read(HERE/name);(runtime/name).write_bytes(b);(runtime/name).chmod(0o644);runtime_rows[name]=dict(V.pin(b),mode=0o644)
  b=V.read(NATIVE/'owner_common.py');(runtime/'owner_common.py').write_bytes(b);(runtime/'owner_common.py').chmod(0o644);runtime_rows['owner_common.py']=dict(V.pin(b),mode=0o644)
  selection=dict(schema=1,purpose=V.PURPOSE,identity=own,nonce=nonce,image=image,kernel=kernel,uid=1001,gid=1001,source_map_sha256=a.manifest_sha256,source_manifest=V.source_rows(manifest,a.manifest_sha256),accepted_manifest=policy['files'],runtime_manifest=runtime_rows,budgets=V.BUDGET,launcher_epoch_s=None);V.save(vm/'selection.json',selection);media_actor(actor,context,image,vm,disks,'prepare',deadline,state)
  prepared=V.decode(V.read(disks/'prepared.json'));V.need(prepared['status']=='PREPARED_KIT77_MEDIA_NOT_BOOTED'and prepared['nonce']==nonce and prepared['image']==image and prepared['launcher_epoch_s']is None and prepared['serials']=={n:V.disk_serial(nonce,n)for n in('boot','data')},'same-nonce prepared media');V.save(vm/'prepared.json',prepared)
  for name,size in(('boot',16*1024**3),('data',24*1024**3)):
   path=disks/(name+'.raw');disk_identity(path,size);fd=os.open(path,os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC);fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);fds.append(fd)
  V.key_preflight(vm/'accepted');selection=bind_launch(actor,context,image,vm,disks,selection,deadline,state);V.save(vm/'sealed-disks.json',{name:dict(identity=disk_identity(disks/(name+'.raw'),size),**V.row(disks/(name+'.raw')))for name,size in(('boot',16*1024**3),('data',24*1024**3))});V.need(0<=time.time()-selection['launcher_epoch_s']<=120,'current launch clock after disk sealing')
  argv=V.qemu(vm/'Image',disks/'boot.raw',disks/'data.raw',nonce,selection['launcher_epoch_s']);V.save(vm/'qemu-argv.json',argv);state['qemu_started']=True;state_save(vm,state)
  try:actor.run(argv,log=vm/'uart.log',timeout=remaining(deadline,V.BUDGET['qemu']))
  finally:
   qrow=actor.rows[-1]if actor.rows and actor.rows[-1]['argv']==list(map(str,argv))else None;state['qemu_group_absent']=None if qrow is None else qrow.get('group_absent');state['qemu_record']=qrow;state_save(vm,state)
   if qrow is not None:V.save(vm/'qemu-process.json',qrow)
  tools_after=host_tools(actor);V.need({n:{k:v for k,v in r.items()if k!='process'}for n,r in tools_before.items()}=={n:{k:v for k,v in r.items()if k!='process'}for n,r in tools_after.items()},'same actual host tools before/after QEMU');V.update(vm/'tools.json',dict(status='SAME_HOST_TOOLS_OBSERVED_BEFORE_AFTER_QEMU',before=tools_before,after=tools_after,image_tools=dict(image=image,installed574_lock=V.LOCK,package='e2fsprogs 1.47.4-1',authority='SOURCE_PINNED_MEDIA_COMMANDS_PLUS_FULL_ROOT_ELF_AND_NODE_OBSERVATIONS'),acceptance=False));frames=uart(V.read(vm/'uart.log'),selection);V.save(vm/'uart-frames.json',frames);media_actor(actor,context,image,vm,disks,'export',deadline,state);export_join(vm,disks,selection,frames)
  V.need(frames['result']['status']=='PASS_SOFTWARE_ARM_VM_FRESH_ROOT_TEST_TWO_KIT_LIFECYCLES_PENDING_OUTER_CLEANUP'and frames['result']['kit_lifecycle']=='PASS_TWO_FRESH_ROOT_TEST_KITS_VM_ONLY'and all(x=='PASS'for x in frames['result']['preservation'].values())and frames['exit']==dict(schema=1,event='exit',nonce=nonce,selection_sha256=V.pin(V.encoded(selection))['sha256'],acceptance=False,status='PASS_GUEST_PHASES_RETIRED',phase_processes='ABSENT_NATURALLY_REAPED',phase_mount_targets='RETIRED_SAME_OWNED_NODES'),'complete original lifecycles/preservation/retirement');report.update(status='PASS_SOFTWARE_ARM_VM_FRESH_ROOT_TEST_KITS_PENDING_OUTER_CLEANUP',guest=frames['result'])
 except BaseException as error:
  failure=error;report['error']=dict(type=type(error).__name__,message=str(error)[:2048])
  if state['qemu_started']and state['qemu_group_absent']is True and not any(h['role']=='export'for h in state['helpers']):
   try:media_actor(actor,context,image,vm,disks,'export',deadline,state);export_join(vm,disks,selection,frames)
   except BaseException as secondary:report['diagnostic_export_error']=dict(type=type(secondary).__name__,message=str(secondary)[:1024])
 finally:
  for fd in reversed(fds):os.close(fd)
  report['host_state']=state;V.update(vm/'result.json',report)
 if failure is not None:raise failure
 return report


def cleanup_call(function,args,deadline):
 seconds=min(V.BUDGET['cleanup'],deadline-time.monotonic());V.need(seconds>0 and signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0),'finite original-cleanup window and no foreign timer');old=signal.getsignal(signal.SIGALRM)
 def expired(*unused):raise TimeoutError('shared VM original-cleanup deadline')
 signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,seconds)
 try:
  result=function(args);V.need(time.monotonic()<=deadline,'shared VM original cleanup exceeded deadline');return result
 finally:signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,old)

def cleanup(a):
 O,manifest,own,tmp=native_primitives(a);work=Path(a.work);vm=work/'guest-vm';record=dict(status='INCOMPLETE_OR_UNKNOWN_VM_CLEANUP',identity=own,acceptance=False,native_admission=False,backing_media='RETAINED_OR_UNKNOWN',producer_cleanup='NOT_RUN');failure=None
 try:
  if vm.exists():
   state=V.decode(V.read(vm/'host-state.json'));V.need(state['identity']==own and re.fullmatch('[a-f0-9]{32}',state['nonce']or'')and vm.stat().st_uid==os.getuid()and stat.S_IMODE(vm.stat().st_mode)==0o700,'same private VM work owner');disks=vm/'disks';end=min(time.monotonic()+V.BUDGET['cleanup'],state['deadline_monotonic']);V.need(end>time.monotonic()+1,'shared VM cleanup deadline exhausted');actor=runtime_actor(O,vm/'cleanup-actors',end-time.monotonic())
   if 'context'in state:cleanup_helpers(actor,state['context'],state['image'],vm,disks,end,state)
   else:V.need(not state['helpers']and state['qemu_started']is False,'no unbound helper or QEMU');state['helpers_absent']=True
   if disks.exists():retire_media(actor,state.get('context'),state.get('image'),vm,disks,end,state)
   V.need(state['media_retired']is True and state['helpers_absent']is True and(not state['qemu_started']or state['qemu_group_absent']is True),'all VM helpers/media retired before producer cleanup');record['backing_media']='RETIRED_AFTER_VERIFIED_QEMU_GROUP_ABSENCE'
  else:record['backing_media']='NO_VM_WORK_CREATED'
  cleanup_call(O.cleanup,a,end if vm.exists()else time.monotonic()+V.BUDGET['cleanup']);held=V.decode(V.read(work/'ordered-cleanup.json'));V.need(held['identity']==own and held['status']in('PASS_CONSUMERS_ABSENT_THEN_ORIGINAL574_RETIRED','INPUT_TRANSPORT_NOT_ESTABLISHED_BEFORE_NATIVE_ACTORS_DIAGNOSTIC_ONLY','INPUT_TRANSPORT_COMPLETED_BEFORE_NATIVE_ACTORS_DIAGNOSTIC_ONLY','INPUT_TRANSPORT_FAILED_BEFORE_NATIVE_ACTORS_DIAGNOSTIC_ONLY'),'original ordered producer cleanup');record.update(status='PASS_VM_MEDIA_RETIRED_THEN_ORIGINAL_PRODUCER_CLEANUP',producer_cleanup=held['status'])
 except BaseException as error:failure=error;record['error']=dict(type=type(error).__name__,message=str(error)[:2048])
 finally:V.update(work/'vm-cleanup.json',record)
 if failure is not None:raise failure
 return record

HOST_FILES={'host-state.json','result.json','image-inspection.json','kernel.json','selection.json','launch-selection.json','launch-context.json','key-preflight.json','prepared.json','sealed-disks.json','qemu-argv.json','qemu-process.json','uart.log','uart-frames.json','export.json','tools.json'}|{'media-'+r+'-'+s+'.json'for r in('prepare','export','scrub','bind-launch')for s in('inspection','stopped')}
RETENTION_CAP=126*1024**2;RESULT_RESERVE=2*1024**2
def retain(a):
 O,manifest,own,tmp=load_proof(a,False);work=Path(a.work);out=V.fresh(tmp/'offline-kit-fresh-test-vm-public');files={};errors=[];total=0;count=0
 def emit(path,name,pin=None):
  nonlocal total,count
  target=None
  try:
   V.need(O.portable_public(name)and not O.private_retention(tuple(name.split('/'))),'finite portable public path');raw=V.read(path);V.need(count<2047 and total+len(raw)<=RETENTION_CAP-RESULT_RESERVE,'bounded reserved VM public envelope')
   if pin is not None:V.need(V.pin(raw)=={k:pin[k]for k in('bytes','sha256')},'exact retained source/export body')
   V.need(name not in files,'unique retained public path');target=out/name;target.parent.mkdir(parents=True,exist_ok=True)
   with target.open('xb')as f:f.write(raw)
   target.chmod(0o644);files[name]=V.pin(raw);count+=1;total+=len(raw)
  except Exception as error:
   if target is not None:target.unlink(missing_ok=True)
   if len(errors)<64:errors.append(dict(path=name,error=type(error).__name__+': '+str(error)[:384]))
 rows=V.source_rows(manifest,a.manifest_sha256)
 for name,pin in rows.items():emit(ROOT/name,'source/'+name,pin)
 # Critical raw actor evidence first; no recursive fallback or raw VM disk/stage roots.
 vm=work/'guest-vm'
 for directory in('actors','cleanup-actors'):
  root=vm/directory
  for name in ['actors.json',*(f'{i:04d}.log'for i in range(128))]:
   if os.path.lexists(root/name):emit(root/name,'host-vm/'+directory+'/'+name)
 for name in sorted(HOST_FILES):
  if os.path.lexists(vm/name):emit(vm/name,'host-vm/'+name)
 for name in('source-proof.json','bootstrap.json','input-transport-owner.json','ordered-cleanup.json','vm-cleanup.json'):
  if os.path.lexists(work/name):emit(work/name,name)
 for directory in('bootstrap-actors','cleanup-actors','input-transport-actors'):
  for name in ['actors.json',*(f'{i:04d}.log'for i in range(100))]:
   if os.path.lexists(work/directory/name):emit(work/directory/name,directory+'/'+name)
 for phase in('transport','bootstrap','execute-selected','cleanup'):
  for suffix in('stdout','stderr','exit-code'):
   path=work/'phase-logs'/(phase+'.'+suffix)
   if os.path.lexists(path):emit(path,'phase-logs/'+path.name)
 for name in('report.json','installed-packages.lock','offline-kit-retained574-inputs.json'):
  path=tmp/'desktop574'/name
  if os.path.lexists(path):emit(path,'producer574/'+name)
 export=vm/'export.json'
 if export.exists():
  try:
   exported=V.decode(V.read(export));M=V.load('retention_media_privacy',HERE/'media_helper.py');s=V.decode(V.read(vm/'launch-selection.json'));allowed,portable,private=M.public_allowlist(s,ROOT);V.need(exported['identity']==own and exported['nonce']==s['nonce']and exported['status']=='PINNED_GUEST_PUBLIC_DATA_ONLY','same qualified public export')
   for name,pin in exported['files'].items():
    V.need(name=='index.json'or(name in allowed and portable(name)and not private(tuple(name.split('/')))),'exact indexed guest privacy');emit(vm/'public'/name,'guest/'+name,pin)
  except Exception as error:errors.append(dict(path='guest-export',error=type(error).__name__+': '+str(error)[:384]))
 result=V.decode(V.read(vm/'result.json'))if(vm/'result.json').exists()else{};clean=V.decode(V.read(work/'vm-cleanup.json'))if(work/'vm-cleanup.json').exists()else{}
 passed=not errors and result.get('status')=='PASS_SOFTWARE_ARM_VM_FRESH_ROOT_TEST_KITS_PENDING_OUTER_CLEANUP'and clean.get('status')=='PASS_VM_MEDIA_RETIRED_THEN_ORIGINAL_PRODUCER_CLEANUP'and clean.get('producer_cleanup')=='PASS_CONSUMERS_ABSENT_THEN_ORIGINAL574_RETIRED'and export.exists()
 record=dict(status='PASS_SOFTWARE_ARM_VM_TWO_FRESH_ROOT_TEST_KIT_LIFECYCLES'if passed else'INCOMPLETE_OR_FAILED_SOFTWARE_VM_ONLY',operation=V.OPERATION,identity=own,files=files,bytes=total,retention_complete=not errors,retention_errors=errors,software_vm=True,native_admission=False,acceptance=False,hardware='NOT_RUN',release='NOT_ADMITTED',raw_disks_or_keys='NEVER_RETAINED',scope='GENERIC16K_SOFTWARE_VM_NOT_NATIVE_CONTAINER_OR_HARDWARE_ADMISSION')
 V.need(len(V.encoded(record))<=RESULT_RESERVE,'reserved result cap');V.save(out/'result.json',record);V.need(not errors,'VM public retention incomplete; result retained');return record


def host_tools(actor=None):
 paths={'qemu':'/usr/bin/qemu-system-aarch64','debugfs':'/usr/sbin/debugfs'if Path('/usr/sbin/debugfs').exists()else'/usr/bin/debugfs'};result={}
 for name,text in paths.items():
  path=Path(text);info=path.lstat();V.need(stat.S_ISREG(info.st_mode)and info.st_nlink==1 and info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o755 and 0<info.st_size<=256*1024**2 and not any(p.is_symlink()for p in(path,*path.parents)),'pre-provisioned ordinary root-owned host tool required; no installer fallback');value=dict(path=text,**V.row(path),mode=stat.S_IMODE(info.st_mode),uid=info.st_uid)
  try:os.getxattr(path,'security.capability',follow_symlinks=False)
  except OSError as error:
   V.need(error.errno in(errno.ENODATA,errno.ENOTSUP),'host tool capability absence UNKNOWN or denied');value['file_capabilities']=dict(status='ABSENT',observation='ENODATA'if error.errno==errno.ENODATA else'ENOTSUP')
  else:V.need(False,'host tool executable file capabilities refused')
  if actor is not None:
   argv=[text,'--version'if name=='qemu'else'-V'];version=actor.run(argv,timeout=remaining(actor.deadline,15));V.need(0<len(version.encode())<=8192,'bounded actual tool version');value.update(version=version,version_argv=argv,process=actor.rows[-1])
  result[name]=value
 return result

def check_host(a):
 V.selected();V.original().binding(a);return dict(status='PREPROVISIONED_HOST_TOOL_METADATA_NO_ACTORS',tools=host_tools(),installation='NOT_REQUESTED_NO_APT_SUDO_OR_ROOT',acceptance=False)

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('command',choices=('proof','check-host','check-inputs','transport','bootstrap','execute','execute-selected','cleanup','retain'));p.add_argument('--manifest-sha256',required=True);p.add_argument('--work',required=True);p.add_argument('--execute',action='store_true');a=p.parse_args();command={'execute-selected':'execute','check-inputs':'check_inputs','check-host':'check_host'}.get(a.command,a.command);result=globals()[command](a)
 if command in('check_inputs','check_host'):print(V.encoded(result).decode(),end='')
if __name__=='__main__':main()

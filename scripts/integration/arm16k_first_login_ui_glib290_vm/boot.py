#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Separate Root-only first ARM virtio seat boot; preparation never calls this."""
import argparse,copy,importlib.util,json,os,re,resource,secrets,shutil,socket,stat,subprocess,sys,tempfile,time
from contextlib import ExitStack
from pathlib import Path
HERE=Path(__file__).resolve().parent
PASS='PASS_EMULATED_ARM16K_GLIB290_REAL_SEAT_UI_LIFECYCLE_ONLY'

def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
K=load('arm_seat_vm_contracts',HERE/'contracts.py')
def custody_class(B):
 class OwnedContainer(B.OwnedContainer):
  def validate(self,row):
   assert row['Config']['Cmd']==['-I','-B','/inputs/ui_glib_actor.py']and row['HostConfig']['SecurityOpt']==['no-new-privileges']and row['HostConfig']['Memory']==row['HostConfig']['MemorySwap']==K.BOOT_RESOURCES['memory_bytes'] and not row['HostConfig'].get('DeviceRequests')and row['HostConfig'].get('PidMode','')==''and row['HostConfig'].get('IpcMode','private')=='private'and row['HostConfig'].get('UTSMode','')==''
   original=copy.deepcopy(row);original['Config']['Cmd']=['-I','-B','/opt/vm_actor.py'];original['HostConfig']['Memory']=original['HostConfig']['MemorySwap']=3*1024**3;super().validate(original)
 return OwnedContainer

def limit_command_log():
 hard=resource.getrlimit(resource.RLIMIT_FSIZE)[1];bound=1024**2 if hard==resource.RLIM_INFINITY else min(1024**2,hard)
 resource.setrlimit(resource.RLIMIT_FSIZE,(bound,bound))

def memory_evidence(out,nonce):
 result={}
 for stage in ['before-vm','at-qemu-exit','final']:
  path=out/('memory-'+stage+'.json')
  if not path.exists():continue
  info=path.lstat();assert stat.S_ISREG(info.st_mode)and info.st_uid==os.getuid()and stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1 and info.st_size<=16384
  value=K.read(path,16384);assert value['nonce']==nonce and value['stage']==stage and type(value['schema_version'])is int and value['schema_version']==1 and type(value['utc_ns'])is int and 0<value['utc_ns']<=2**64-1 and value['source']=='fixed cgroup-v2 numeric DATA'and value['status']in ['OBSERVED','REFUSED']
  counters={'memory.peak','memory.current','memory.max','memory.swap.current','memory.swap.max'}
  assert set(value)<={'schema_version','nonce','stage','utc_ns','source','status','memory.events','error_category'}|counters
  assert all(type(value[k])is int and 0<=value[k]<=2**64-1 for k in counters&value.keys())
  events=value.get('memory.events',{});assert isinstance(events,dict)and set(events)<={'low','high','max','oom','oom_kill','oom_group_kill','sock_throttled'}and all(type(v)is int and 0<=v<=2**64-1 for v in events.values())
  if value['status']=='OBSERVED':assert counters<=value.keys()and value['memory.max']==K.BOOT_RESOURCES['memory_bytes']and value['memory.swap.max']==0 and {'low','high','max','oom','oom_kill'}<=events.keys()
  else:assert value.get('error_category')in ['OSError','FileNotFoundError','PermissionError','UnicodeDecodeError','ValueError','AssertionError']
  result[stage]={'pin':K.pin(path),'actual_numeric_cgroup':value}
 return result

def disk_evidence(out,nonce):
 result={}
 for name in ['actor-file-limits.json','qemu-file-limits.json','overlay-at-qemu-exit.json']:
  path=out/name
  if not path.exists():continue
  info=path.lstat();assert stat.S_ISREG(info.st_mode)and info.st_uid==os.getuid()and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o600 and info.st_size<=16384
  value=K.read(path,16384);assert value['nonce']==nonce and type(value['schema_version'])is int and value['schema_version']==1
  if name=='qemu-file-limits.json':
   assert set(value)=={'schema_version','nonce','pid','start_ticks','actual_RLIMIT_FSIZE','actual_SigIgn_hex'}
   assert type(value['pid'])is int and value['pid']>0 and type(value['start_ticks'])is int and value['start_ticks']>=0 and re.fullmatch('[0-9a-fA-F]{1,16}',value['actual_SigIgn_hex'])
   assert value['actual_RLIMIT_FSIZE']==[K.BOOT_RESOURCES['overlay_bytes']]*2
  else:
   assert set(value)=={'schema_version','nonce','overlay'}|({'actor_RLIMIT_FSIZE'}if name=='actor-file-limits.json'else set())
   if name=='actor-file-limits.json':assert value['actor_RLIMIT_FSIZE']==[K.BOOT_RESOURCES['overlay_bytes']]*2
   row=value['overlay'];assert set(row)=={'file_bytes','allocated_bytes','file_limit_bytes','allocated_cap_bytes','within_budget'}
   assert all(type(row[k])is int for k in row if k!='within_budget')and type(row['within_budget'])is bool
   assert row['file_limit_bytes']==row['allocated_cap_bytes']==K.BOOT_RESOURCES['overlay_bytes']
   assert row['within_budget']==(0<row['file_bytes']<=row['file_limit_bytes']and 0<row['allocated_bytes']<=row['allocated_cap_bytes'])
  result[name]={'pin':K.pin(path),'actual':value}
 return result

def final_evidence(out,report,nonce):
 report['memory_receipts']=memory_evidence(out,nonce)
 report['disk_receipts']=disk_evidence(out,nonce)
 report['allocated_nonoverlay_output_bytes']=sum(p.stat().st_blocks*512 for p in out.rglob('*')if p.is_file()and p.name!='overlay.qcow2')
 assert report['allocated_nonoverlay_output_bytes']<=K.DISK_BUDGETS['boot_nonoverlay_bytes']-512*1024,'non-overlay output budget exceeded (final report reserve512KiB)'
 if (out/'qemu-retirement.json').exists():report['QEMU_retirement']=K.read(out/'qemu-retirement.json')
 report['QEMU_natural_without_actor_signal']=report.get('QEMU_retirement',{}).get('natural_without_actor_signal',False)
 if report['status']==PASS:
  assert report.get('owned_container_absence_verified') is True,'verified owned container absence required'
  assert set(report['disk_receipts'])=={'actor-file-limits.json','qemu-file-limits.json','overlay-at-qemu-exit.json'}
  assert all(row['actual']['overlay']['within_budget'] is True for row in report['disk_receipts'].values() if 'overlay' in row['actual'])
  assert set(report['memory_receipts'])=={'before-vm','at-qemu-exit','final'} and all(r['actual_numeric_cgroup']['status']=='OBSERVED' for r in report['memory_receipts'].values())

def publish_report(out,report,state,nonce):
 def write_report(path):
  raw=(json.dumps(report,indent=2,sort_keys=True)+'\n').encode()
  assert len(raw)<=512*1024,'bounded final report required'
  path.write_bytes(raw)

 with ExitStack() as files:
  try:
   stage=Path(files.enter_context(tempfile.TemporaryDirectory(dir=out)))
   if report['status']==PASS and not report.get('cleanup_errors'):
    try:
     journey={'foundation':report['seat'],'ui_journey':report['ui_journey'],'status':PASS}
     (stage/'journey.json').write_text(json.dumps(journey,indent=2,sort_keys=True)+'\n')
    except OSError as e:
     report.setdefault('cleanup_errors',[]).append({'step':'journey-receipt','category':type(e).__name__})
   # Include the staged journey allocation in the existing non-overlay census.
   try:final_evidence(out,report,nonce)
   except BaseException as e:report.setdefault('cleanup_errors',[]).append({'step':'final-evidence','category':type(e).__name__})
   if report.get('cleanup_errors'):report['status']='HOLD_CLEANUP'
   if report['status']!=PASS:report.pop('ui_status',None)
   write_report(stage/'report.json')
  finally:state.__exit__()
  if state.pending:
   report['cancelled_signals']=list(state.pending)
   if report['status']!='HOLD_CLEANUP':report['status']='HOLD_CANCELLED'
   report.pop('ui_status',None)
   write_report(stage/'report.json')
  # The report is the terminal receipt. A failed report publication retires its companion.
  journey_path=out/'journey.json'
  journey_stage=stage/'journey.json'
  try:
   if report['status']==PASS:journey_stage.replace(journey_path)
   (stage/'report.json').replace(out/'report.json')
  except BaseException:
   if report['status']==PASS and not journey_stage.exists():journey_path.unlink(missing_ok=True)
   raise

def installed(proof,prepared,epoch,now):
 d=proof['installed_gate'];adds=prepared['lineage']['additions'];clock=d['clock']
 # Explicit comparisons avoid treating mere nonempty strings as actual success.
 assert d['status']=='PASS' and d['nonce']==prepared['nonce'] and d['baseline_count']==111 and d['installed_count']==283 and len(adds['archives'])==173
 assert d['trusted_ALPM_completed'] is True and d['ordinary_hooks_scriptlets'] is True and d['policy_owner']=='networkmanager' and d['additions_sha256']==prepared['lineage']['additions_pin']['sha256']
 expected=''.join(n+' '+v+'\n' for n,v in sorted({**{r['name']:r['version'] for r in prepared['base_packages']},**{n:r['version'] for n,r in adds['archives'].items()}}.items())).encode()
 import hashlib
 assert d['actual_inventory_sha256']==hashlib.sha256(expected).hexdigest() and d['durability']=='successful install service after sync-f boundary'
 assert clock['RTC_PRESENT']=='yes' and clock['RTC_DRIVER']=='pl031' and clock['RTC_HCTOSYS']=='1' and clock['RTC_CLOCK_ADVANCED']=='yes' and clock['CLOCK_SETTING']=='none'
 h,g,t=(int(clock[k]) for k in ('HOST_BOOT_UTC','GUEST_BEFORE_CRYPTO_UTC','RTC_BEFORE_CRYPTO_UTC'))
 assert h==epoch and h-5<=g<=min(h+605,now+5) and abs(g-t)<=2
 return d

def checked_prepared(a):
 K.checked(a.authority,{'bytes':a.authority.stat().st_size,'sha256':a.authority_sha256});approval=K.admission(K.read(a.authority),'boot');assert approval['source_lock']==K.source();refs,arm,x86,lower=K.references();bundle=lower.kernel(a.kernel_bundle,approval);K.checked(a.qemu_metadata,approval['qemu_metadata']);tool=K.read(a.qemu_metadata);K.checked(a.tool_qualification,approval['tool_qualification']);qualification=K.read(a.tool_qualification);K.qualified_tool(tool,approval['tool_image_id'],qualification,K.ROOT/refs['tool_producer']['path']);assert qualification['Root_device_help_metadata']==K.pin(a.qemu_metadata)
 source=a.prepared.resolve(strict=True);K.checked(source/'prepared.json',{'bytes':(source/'prepared.json').stat().st_size,'sha256':a.prepared_sha256});m=K.read(source/'prepared.json');assert m['status']=='PREPARED_NOT_BOOTED'and m['operation']==K.OP and re.fullmatch('[0-9a-f]{32}',m['nonce'])
 assert m['lineage']['source_lock']==K.source()and m['kernel']==bundle and m['lineage']['tool_metadata']==tool and m['lineage']['additions_pin']==approval['additions_manifest']
 for key in ['kind','issued_by','operation','tool_image_id','source_lock','source_public','kernel_bundle','additions_manifest','qemu_metadata','tool_qualification','minimal155_report','minimal155_prepared']:assert m['authority'][key]==approval[key]
 assert set(m['files'])=={'guest.raw','Image','kernel.config','ui_glib_actor.py'}and m['files']['Image']==bundle['files']['Image']and m['files']['kernel.config']==bundle['files']['config']and m['files']['ui_glib_actor.py']==K.pin(HERE/'ui_glib_actor.py')and m['files']['guest.raw']['bytes']==3*1024**3
 for name,ref in m['files'].items():K.checked(source/name,ref)
 cred=source/'credentials.json';info=cred.lstat();assert stat.S_ISREG(info.st_mode)and stat.S_IMODE(info.st_mode)==0o600 and info.st_uid==os.getuid()and info.st_size<=4096;login=K.read(cred,4096);assert login['username']=='builder'and re.fullmatch('[0-9a-f]{32}',login['password'])
 return source,m,approval,login,arm

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--allow-first-arm16k-ui-glib290-boot',action='store_true')
 for n in ('prepared','authority','kernel-bundle','qemu-metadata','tool-qualification','output'):p.add_argument('--'+n,type=Path,required=True)
 p.add_argument('--prepared-sha256',required=True);p.add_argument('--authority-sha256',required=True);a=p.parse_args()
 if not(a.allow_first_arm16k_ui_glib290_boot and __debug__ and sys.flags.isolated and os.geteuid()!=0):p.error('Root-only explicit isolated ordinary-user admission required')
 source,m,approval,login,arm=checked_prepared(a);B=load('UI_ARM_lower_custody',arm/'frozen/reference_controller.py');OwnedContainer=custody_class(B);P=load('UI_ARM_protocol_adapter',HERE/'protocol.py').bind(arm)
 # Path check is shared; boot reserves the same stricter output budget.
 out=K.output_path(a.output,'boot');assert int(next(v.split()[1]for v in Path('/proc/meminfo').read_text().splitlines()if v.startswith('MemAvailable:')))*1024>=7*1024**3;os.umask(0o077)
 image=json.loads(subprocess.check_output(['docker','image','inspect',approval['tool_image_id']]))[0];assert image['Id']==approval['tool_image_id']
 assert 'name=rootless' in json.loads(subprocess.check_output(['docker','info','--format','{{json .SecurityOptions}}']))
 with (source/'ui-glib290-attempt.json').open('x') as f:json.dump({'nonce':m['nonce'],'operation':K.OP,'scope':'one emulated ARM16K virtio seat first boot only'},f)
 out.mkdir(mode=0o700);token=secrets.token_hex(16);name='cachy-arm16k-ui-glib290-'+token;labels=dict(image['Config'].get('Labels') or {});labels.update({'org.cachy-asahi.arm-seat-owner':str(os.getuid()),'org.cachy-asahi.arm-seat-nonce':token,'org.cachy-asahi.arm-seat-input':a.prepared_sha256})
 scope=OwnedContainer(name,out/'container.cid',approval['tool_image_id'],labels,source,out);state=B.Cancellation();serial=qmp=qfile=None
 report={'schema_version':1,'status':'HOLD','operation':K.OP,'scope':'emulated ARM16K real-seat GTK/ALPM software only','native16K':'NOT RUN','M2':'NOT RUN','performance':'NOT MEASURED','release':'NOT RUN','guest_shutdown':'NOT ESTABLISHED'}
 def command(label,argv,timeout=20):
  with (out/(label+'.log')).open('wb') as f:r=subprocess.run(argv,stdout=f,stderr=subprocess.STDOUT,timeout=timeout,preexec_fn=limit_command_log)
  assert r.returncode==0,(label,r.returncode)
 state.__enter__()
 try:
  assert scope.listing(time.monotonic()+8) is None
  (out/'host-admission.json').write_text(json.dumps({'nonce':m['nonce'],'utc_ns':time.time_ns(),'monotonic_ns':time.monotonic_ns()}))
  scope.submitted=True
  command('create',['docker','create','--cidfile',str(scope.cidfile),'--name',name,'--init=false',*[x for k,v in labels.items() for x in ('--label',k+'='+v)],'--read-only','--network=none','--cap-drop=ALL','--security-opt=no-new-privileges','--cpus=2','--memory=5g','--memory-swap=5g','--pids-limit=256','--tmpfs','/tmp:rw,nodev,nosuid,noexec,size=32m','--mount','type=bind,source='+str(source)+',target=/inputs,readonly','--mount','type=bind,source='+str(out)+',target=/work','--env','CACHY_ASAHI_ALLOW_ARM16K_UI_GLIB290_BOOT=1','--entrypoint','/usr/bin/python3',approval['tool_image_id'],'-I','-B','/inputs/ui_glib_actor.py'])
  row=scope.recover(time.monotonic()+8);assert row is not None;report['container_id']=row['Id'];report['image_id']=row['Image'];report['boot_resources']=K.BOOT_RESOURCES;report['runtime']={k:row['HostConfig'][k] for k in ('NetworkMode','ReadonlyRootfs','CapDrop','CapAdd','Privileged','Devices','Memory','MemorySwap','NanoCpus','PidsLimit','Init')}
  command('start',['docker','start',name]);deadline=time.monotonic()+540
  with tempfile.TemporaryDirectory(prefix='arm-seat-sockets-') as short:
   link=Path(short)/'out';link.symlink_to(out,target_is_directory=True)
   for node in ('serial.sock','qmp.sock'):
    until=time.monotonic()+15
    while not (out/node).exists() and time.monotonic()<until:time.sleep(.05)
    st=(out/node).lstat();assert stat.S_ISSOCK(st.st_mode) and st.st_uid==os.getuid()
   qmp=socket.socket(socket.AF_UNIX);qmp.settimeout(5);qmp.connect(str(link/'qmp.sock'));qfile=qmp.makefile('rwb',buffering=0)
   def reply():
    line=qfile.readline(65537);assert 0<len(line)<=65536;return json.loads(line)
   assert 'QMP' in reply();count=0
   def rpc(method,args=None):
    nonlocal count
    assert method in ('qmp_capabilities','input-send-event','quit');count+=1;ident='arm-seat-'+str(count);qfile.write(json.dumps({'execute':method,'arguments':args or {},'id':ident}).encode()+b'\n')
    for _ in range(64):
     row=reply()
     if row.get('id')==ident:assert 'error' not in row;return row.get('return')
    raise ValueError('bounded fixed QMP reply refused')
   rpc('qmp_capabilities');stream=socket.socket(socket.AF_UNIX);stream.connect(str(link/'serial.sock'));serial=P.Serial(stream,deadline,m['nonce'])
   result=P.journey(serial,rpc,login['password']);report.update(result);assert result['ui_status']==PASS
   actual=K.read(out/'host-qemu-start.json');assert actual['nonce']==m['nonce'];report['installed_gate']=installed(report['seat'],m,actual['utc_ns']//1000000000,int(time.time()))
   rpc('quit');report['QMP_quit_requested']=True;report['guest_shutdown']='QMP quit requested after proved normal PAM logout; not guest poweroff'
  command('normal-container-wait',['docker','wait',name],20);terminal=scope.recover(time.monotonic()+8);assert terminal['State']['ExitCode']==0 and not terminal['State']['OOMKilled']
  retirement=K.read(out/'qemu-retirement.json');assert retirement['passed'] and retirement['natural_without_actor_signal']is True and retirement['actor_signals']==[] and retirement['actor_error']is None and not retirement.get('actor_cancelled') and retirement['reaped'] and retirement['group_census']=='EMPTY_TWICE';report.update(status=PASS,QEMU_retirement=retirement)
 except BaseException as e:report['failure']={'category':type(e).__name__,'message':str(e)[:2048]}
 finally:
  state.cleaning=True
  try:
   if serial is not None:
    try:(out/'serial.redacted.log').write_bytes(P.redact_serial(bytes(serial.data),login['password']));serial.stream.close()
    except BaseException as e:report.setdefault('cleanup_errors',[]).append({'step':'serial-report','category':type(e).__name__})
   for name,item in (('qmp-file',qfile),('qmp-socket',qmp)):
    if item is not None:
     try:item.close()
     except BaseException as e:report.setdefault('cleanup_errors',[]).append({'step':name,'category':type(e).__name__})
   scope.cleanup(report)
  except BaseException as e:report.setdefault('cleanup_errors',[]).append({'step':'cleanup','category':type(e).__name__})
  finally:
   publish_report(out,report,state,m['nonce'])
 print(json.dumps({'status':report['status'],'report':str(out/'report.json')}));return 0 if report['status']==PASS else 1
if __name__=='__main__':raise SystemExit(main())

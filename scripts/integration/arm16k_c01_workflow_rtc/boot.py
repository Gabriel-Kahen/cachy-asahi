#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Separate Root-admitted RTC/time actor; no preparation or implicit boot."""
import argparse,copy,importlib.util,json,os,re,secrets,socket,stat,subprocess,shutil,sys,tempfile,time
from pathlib import Path
HERE=Path(__file__).resolve().parent

def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

I=load('rtc_lifecycle_inputs',HERE/'inputs.py')
LOCK,REFERENCE,B=I.reference()
K=load('rtc_lifecycle_contracts',HERE/'contracts.py')
LEGACY=load('c01_rtc_legacy_result_parser',HERE/'frozen/c01/boot.py')
Cancellation,Serial,parse_session,sha=B.Cancellation,B.Serial,B.parse_session,B.sha

class OwnedContainer(B.OwnedContainer):
 def validate(self,row):
  assert row['Config']['Cmd']==['-I','-B','/inputs/rtc_actor.py'],'explicit new RTC actor required'
  original=copy.deepcopy(row);original['Config']['Cmd']=['-I','-B','/opt/vm_actor.py']
  # Only the separately pinned actor entry changes; all custody/resource checks remain.
  super().validate(original)

def parse_lifecycle(data,nonce,host_epoch,end_epoch):
 text=data.decode('utf-8',errors='replace').replace('\r','');start='ARM16K_C01_RTC_BEGIN '+nonce+'\n';end='ARM16K_C01_RTC_END '+nonce
 if text.count(start)!=1 or text.count(end)!=1:raise ValueError('missing/duplicate RTC result frame')
 fields={}
 for line in text.split(start,1)[1].split(end,1)[0].splitlines():
  if '='not in line:raise ValueError('malformed RTC result')
  key,value=line.split('=',1)
  if key in fields or not re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,63}',key)or len(value)>256:raise ValueError('duplicate/invalid RTC result')
  fields[key]=value
 if fields.get('STATUS')=='HOLD':return fields
 fixed={'RTC_PRESENT':'yes','RTC_DRIVER':'pl031','RTC_HCTOSYS':'1','RTC_CLOCK_ADVANCED':'yes','CLOCK_SETTING':'none','DURABLE_RECEIPTS':'sync_f_completed'}
 for key,value in fixed.items():
  if fields.pop(key,None)!=value:raise ValueError('RTC/durability invariant differs: '+key)
 times={}
 for key in ('HOST_BOOT_UTC','GUEST_BEFORE_CRYPTO_UTC','RTC_BEFORE_CRYPTO_UTC'):
  value=fields.pop(key,'')
  if not re.fullmatch('[1-9][0-9]{8,11}',value):raise ValueError('invalid actual UTC field')
  times[key]=int(value)
 h,g,t=times.values()
 if h!=host_epoch or not h-5<=g<=min(h+485,end_epoch+5)or abs(g-t)>2:raise ValueError('real host/RTC/guest UTC comparison differs')
 old=('ARM16K_PROJECT_BEGIN '+nonce+'\n'+''.join(k+'='+v+'\n'for k,v in fields.items())+'ARM16K_PROJECT_END '+nonce).encode()
 validated=LEGACY.parse_lifecycle(old,nonce)
 return {**validated,**fixed,**times}

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--allow-first-arm16k-c01-rtc-workflow',action='store_true');p.add_argument('--prepared',type=Path,required=True);p.add_argument('--prepared-sha256',required=True);p.add_argument('--authority',type=Path,required=True);p.add_argument('--authority-sha256',required=True);p.add_argument('--kernel-bundle',type=Path,required=True);p.add_argument('--baseline-config',type=Path,required=True);p.add_argument('--signing-receipt',type=Path,required=True);p.add_argument('--trust-prerequisite',type=Path,required=True);p.add_argument('--trust-prerequisite-sha256',required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 if not(a.allow_first_arm16k_c01_rtc_workflow and __debug__ and sys.flags.isolated and os.geteuid()!=0):p.error('explicit Root-authorized first boot/isolated ordinary host user required')
 os.umask(0o077)
 source=a.prepared.resolve(strict=True);manifest=source/'prepared.json';assert sha(manifest)==a.prepared_sha256
 approval=K.authority(a.authority,a.authority_sha256,HERE/'rtc_actor.py');assert approval.get('allow_boot')is True,'fresh Root boot authority required'
 trust=I.trust_prerequisite(a.trust_prerequisite,a.trust_prerequisite_sha256,approval)
 bundle=K.kernel(a.kernel_bundle,approval,a.baseline_config);fresh=K.signing(a.signing_receipt,LOCK)
 I.checked(a.baseline_config,LOCK['base_files']['kernel.config'])
 assert shutil.disk_usage(a.output.parent).free>=2*1024**3+256*1024**2,'2GiB free reserve required'
 prepared=json.loads(manifest.read_text());assert prepared['status']=='PREPARED_NOT_BOOTED'and prepared['scope']=='emulated aarch64/16K stock systemd login reference only'
 assert prepared['provenance']['project_lifecycle']['added_packages']==LOCK['added_packages']
 assert prepared['operation']=='arm16k-c01-baseline-lto-rtc-v1'and all(prepared['rtc_authority'].get(k)==approval.get(k)for k in ('kind','issued_by','tool_image_id','rtc_actor','kernel_bundle','approved_compiler_facts','clock_policy','ksm_pass_receipt')) and prepared['rtc_bundle']==bundle and prepared['fresh_signing']==fresh
 lineage=prepared['provenance']['project_lifecycle'];assert lineage['trust_prerequisite']==trust
 for name,ref in lineage['source_pins'].items():I.checked(HERE/name,ref)
 assert prepared['files']['Image']==bundle['files']['Image']and prepared['files']['kernel.config']==bundle['files']['config']and prepared['files']['rtc_actor.py']==approval['rtc_actor']
 assert set(prepared['files'])=={'guest.raw','Image','kernel.config','rtc_actor.py'}and re.fullmatch('[0-9a-f]{32}',prepared['nonce'])
 assert prepared['provenance']['tool_image_id']==LOCK['tool_image_id'],'prepared tool image differs'
 for n,ref in prepared['files'].items():
  path=source/n;assert path.is_file()and not path.is_symlink()and path.stat().st_size==ref['bytes']and sha(path)==ref['sha256']
 credentials=source/'credentials.json';assert not credentials.is_symlink();info=credentials.stat();assert info.st_uid==os.getuid()and stat.S_IMODE(info.st_mode)==0o600 and info.st_size<=4096
 login=json.loads(credentials.read_text());assert login['username']=='builder'
 secret=login['password'].encode();assert 24<=len(secret)<=128
 image=json.loads(subprocess.check_output(['docker','image','inspect',LOCK['tool_image_id']],text=True))[0];assert image['Id']==LOCK['tool_image_id']
 security=json.loads(subprocess.check_output(['docker','info','--format','{{json .SecurityOptions}}'],text=True));assert 'name=rootless'in security,'rootless Docker required'
 # Explicit unique attempt before launch; the constructor never consumes it.
 attempt=source/'arm16k-c01-rtc-attempt.json'
 with attempt.open('x')as f:json.dump({'nonce':prepared['nonce'],'scope':'first emulated ARM16K systemd boot only'},f)
 out=a.output.resolve();out.mkdir(mode=0o700,parents=True,exist_ok=False)
 token=secrets.token_hex(16);name='cachy-arm16k-c01-rtc-'+token;serial=None;qmp=None;report={'schema_version':1,'status':'HOLD','scope':'emulated ARM16K systemd software only','M2':'NOT RUN','native_ARM':'NOT RUN','release':'NOT RUN','guest_shutdown':'NOT QUALIFIED; QMP emulator quit after logout'}
 labels=dict(image.get('Config',{}).get('Labels')or{});labels.update({'org.cachy-asahi.arm16k-c01-rtc-owner':str(os.getuid()),'org.cachy-asahi.arm16k-c01-rtc-nonce':token,'org.cachy-asahi.arm16k-c01-rtc-input':a.prepared_sha256})
 scope=OwnedContainer(name,out/'container.cid',LOCK['tool_image_id'],labels,source,out)
 def cmd(label,argv,timeout=20):
  with (out/(label+'.log')).open('wb')as f:r=subprocess.run(argv,stdout=f,stderr=subprocess.STDOUT,timeout=timeout)
  assert r.returncode==0,(label,r.returncode)
 state=Cancellation();state.__enter__()
 try:
  assert scope.listing(time.monotonic()+8)is None,'unique reference name already exists'
  K.signing(a.signing_receipt,LOCK)
  I.trust_prerequisite(a.trust_prerequisite,a.trust_prerequisite_sha256,approval)
  (out/'host-admission.json').write_text(json.dumps({'nonce':prepared['nonce'],'utc_ns':time.time_ns(),'monotonic_ns':time.monotonic_ns()}))
  scope.submitted=True
  cmd('create',['docker','create','--cidfile',str(scope.cidfile),'--name',name,'--init=false',*[x for k,v in labels.items()for x in ['--label',k+'='+v]],'--read-only','--network=none','--cap-drop=ALL','--security-opt=no-new-privileges','--cpus=2','--memory=3g','--pids-limit=256','--tmpfs','/tmp:rw,nodev,nosuid,noexec,size=32m','--mount','type=bind,source='+str(source)+',target=/inputs,readonly','--mount','type=bind,source='+str(out)+',target=/work','--env','CACHY_ASAHI_ALLOW_ARM16K_C01_RTC_BOOT=1','--entrypoint','/usr/bin/python3',LOCK['tool_image_id'],'-I','-B','/inputs/rtc_actor.py'])
  observed=scope.recover(time.monotonic()+8);assert observed is not None;hc=observed['HostConfig'];assert hc['ReadonlyRootfs']and hc['NetworkMode']=='none'and hc['CapDrop']==['ALL']and not hc['CapAdd']and not hc['Privileged']and not hc['Devices']
  assert hc['Memory']==3*1024**3 and hc['NanoCpus']==2_000_000_000 and hc['PidsLimit']==256
  assert {(m['Destination'],m['RW'])for m in observed['Mounts']}=={('/inputs',False),('/work',True)}
  report['runtime']={k:hc[k]for k in ['NetworkMode','ReadonlyRootfs','CapDrop','CapAdd','Privileged','Devices','Memory','NanoCpus','PidsLimit']};report['container_id']=observed['Id'];report['image_id']=observed['Image']
  cmd('start',['docker','start',name]);deadline=time.monotonic()+420
  with tempfile.TemporaryDirectory(prefix='tcg-sockets-')as short:
   link=Path(short)/'out';link.symlink_to(out,target_is_directory=True)
   for n in ['serial.sock','qmp.sock']:
    until=time.monotonic()+15
    while not(out/n).exists()and time.monotonic()<until:time.sleep(.05)
    node=(out/n).lstat();assert stat.S_ISSOCK(node.st_mode)and node.st_uid==os.getuid()
   qmp=socket.socket(socket.AF_UNIX);qmp.settimeout(5);qmp.connect(str(link/'qmp.sock'));qfile=qmp.makefile('rwb',buffering=0)
   def reply():
    line=qfile.readline(65537);assert 0<len(line)<=65536;return json.loads(line)
   assert 'QMP'in reply();qfile.write(b'{"execute":"qmp_capabilities","id":"cap"}\n')
   while reply().get('id')!='cap':pass
   stream=socket.socket(socket.AF_UNIX);stream.connect(str(link/'serial.sock'));serial=Serial(stream,deadline)
   serial.until(rb'login:\s*');serial.send(b'builder\n');serial.until(rb'Password:\s*');serial.send(secret+b'\n')
   nonce=prepared['nonce'];serial.until(('ARM16K_SHELL_READY '+nonce).encode());serial.send(b'/usr/local/libexec/arm16k-login-proof\n');serial.until(('TCG_LOGIN_END '+nonce).encode())
   report['session']=parse_session(bytes(serial.data),nonce)
   actual=json.loads((out/'host-qemu-start.json').read_text());assert actual['nonce']==nonce
   report['project']=parse_lifecycle(bytes(serial.data),nonce,actual['utc_ns']//1000000000,int(time.time()))
   serial.send(b'exit\n');serial.until(rb'login:\s*');report['normal_PAM_logout_observed']=True
   qfile.write(b'{"execute":"quit","id":"quit"}\n');report['QMP_quit_requested']=True
  cmd('normal-container-wait',['docker','wait',name],20)
  terminal=scope.recover(time.monotonic()+8);assert terminal['State']['ExitCode']==0 and not terminal['State']['OOMKilled']
  retirement=json.loads((out/'qemu-retirement.json').read_text());assert retirement['passed']and not retirement.get('actor_cancelled'),retirement
  report['QEMU_retirement']=retirement
  if report['project'].get('STATUS')=='PASS':report['status']='PASS_EMULATED_ARM16K_C01_RTC_CORRECTNESS_INSTALL_REMOVE_ONLY'
 except BaseException as e:report['failure']={'category':type(e).__name__,'message':str(e)[:2048]}
 finally:
  state.cleaning=True
  try:
   if serial is not None:
    try:
     (out/'serial.redacted.log').write_bytes(bytes(serial.data).replace(secret,b'[REDACTED TEST PASSWORD]'));serial.stream.close()
    except BaseException as e:report.setdefault('cleanup_errors',[]).append({'step':'serial-report','category':type(e).__name__,'message':str(e)[:1024]})
   if qmp is not None:
    try:qmp.close()
    except OSError:pass
   scope.cleanup(report)
  except BaseException as e:report.setdefault('cleanup_errors',[]).append({'step':'cleanup','category':type(e).__name__,'message':str(e)[:1024]})
  finally:
   if state.pending:report['cancelled_signals']=state.pending;report['status']='HOLD_CANCELLED'
   if report.get('cleanup_errors')and report['status']=='PASS_EMULATED_ARM16K_C01_RTC_CORRECTNESS_INSTALL_REMOVE_ONLY':report['status']='HOLD_CLEANUP'
   try:(out/'report.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
   finally:state.__exit__()
 print(json.dumps({'status':report['status'],'report':str(out/'report.json'),'failure':report.get('failure')}))
 return 0 if report['status']=='PASS_EMULATED_ARM16K_C01_RTC_CORRECTNESS_INSTALL_REMOVE_ONLY'else 1


if __name__=='__main__':raise SystemExit(main())

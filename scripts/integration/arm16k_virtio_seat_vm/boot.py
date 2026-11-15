#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Separate Root-only first ARM virtio seat boot; preparation never calls this."""
import argparse,copy,importlib.util,json,os,re,secrets,shutil,socket,stat,subprocess,sys,tempfile,time
from pathlib import Path
HERE=Path(__file__).resolve().parent

def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
K=load('arm_seat_vm_contracts',HERE/'contracts.py')
B=load('arm_seat_original_custody',HERE/'frozen/reference_controller.py')
P=load('arm_seat_protocol',HERE/'frozen/arm16k_virtio_seat/protocol.py')
class OwnedContainer(B.OwnedContainer):
 def validate(self,row):
  assert row['Config']['Cmd']==['-I','-B','/inputs/seat_actor.py'],'new ARM virtio actor identity required'
  assert row['HostConfig']['SecurityOpt']==['no-new-privileges']
  original=copy.deepcopy(row);original['Config']['Cmd']=['-I','-B','/opt/vm_actor.py'];super().validate(original)

def installed(proof,prepared,epoch,now):
 d=proof['installed_gate'];adds=prepared['lineage']['additions'];clock=d['clock']
 # Explicit comparisons avoid treating mere nonempty strings as actual success.
 assert d['status']=='PASS' and d['nonce']==prepared['nonce'] and d['baseline_count']==111 and d['installed_count']==111+len(adds['archives'])
 assert d['trusted_ALPM_completed'] is True and d['ordinary_hooks_scriptlets'] is True and d['policy_owner']=='networkmanager' and d['additions_sha256']==prepared['lineage']['additions_pin']['sha256']
 expected=''.join(n+' '+v+'\n' for n,v in sorted({**{r['name']:r['version'] for r in prepared['base_packages']},**{n:r['version'] for n,r in adds['archives'].items()}}.items())).encode()
 import hashlib
 assert d['actual_inventory_sha256']==hashlib.sha256(expected).hexdigest() and d['durability']=='successful install service after sync-f boundary'
 assert clock['RTC_PRESENT']=='yes' and clock['RTC_DRIVER']=='pl031' and clock['RTC_HCTOSYS']=='1' and clock['RTC_CLOCK_ADVANCED']=='yes' and clock['CLOCK_SETTING']=='none'
 h,g,t=(int(clock[k]) for k in ('HOST_BOOT_UTC','GUEST_BEFORE_CRYPTO_UTC','RTC_BEFORE_CRYPTO_UTC'))
 assert h==epoch and h-5<=g<=min(h+485,now+5) and abs(g-t)<=2
 return d

def checked_prepared(a):
 approval=K.authority(a.authority,a.authority_sha256,'boot');bundle=K.kernel(a.kernel_bundle,approval);tool=K.tool_metadata(a.qemu_metadata,approval)
 source=a.prepared.resolve(strict=True);K.checked(source/'prepared.json',{'bytes':(source/'prepared.json').stat().st_size,'sha256':a.prepared_sha256});m=K.read_json(source/'prepared.json')
 assert m['status']=='PREPARED_NOT_BOOTED' and m['operation']==K.OP and re.fullmatch('[0-9a-f]{32}',m['nonce'])
 assert m['lineage']['source_lock']==K.source() and m['kernel']==bundle and m['lineage']['tool_metadata']==tool and m['lineage']['additions_pin']==approval['additions_manifest']
 assert all(m['authority'][k]==approval[k] for k in ('kind','issued_by','operation','tool_image_id','source_lock','actor','kernel_bundle','additions_manifest','qemu_metadata'))
 assert set(m['files'])=={'guest.raw','Image','kernel.config','seat_actor.py'} and m['files']['Image']==bundle['files']['Image'] and m['files']['kernel.config']==bundle['files']['config'] and m['files']['seat_actor.py']==K.pin(HERE/'seat_actor.py')
 for n,r in m['files'].items():K.checked(source/n,r)
 cred=source/'credentials.json';info=cred.lstat();assert stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode)==0o600 and info.st_uid==os.getuid() and info.st_size<=4096
 login=K.read_json(cred,4096);assert login['username']=='builder' and re.fullmatch('[0-9a-f]{32}',login['password'])
 return source,m,approval,login

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--allow-first-arm16k-virtio-seat-boot',action='store_true')
 for n in ('prepared','authority','kernel-bundle','qemu-metadata','output'):p.add_argument('--'+n,type=Path,required=True)
 p.add_argument('--prepared-sha256',required=True);p.add_argument('--authority-sha256',required=True);a=p.parse_args()
 if not(a.allow_first_arm16k_virtio_seat_boot and __debug__ and sys.flags.isolated and os.geteuid()!=0):p.error('Root-only explicit isolated ordinary-user admission required')
 source,m,approval,login=checked_prepared(a)
 # Path check is shared; boot reserves the same stricter output budget.
 out=K.output_path(a.output);os.umask(0o077)
 image=json.loads(subprocess.check_output(['docker','image','inspect',K.IMAGE]))[0];assert image['Id']==K.IMAGE
 assert 'name=rootless' in json.loads(subprocess.check_output(['docker','info','--format','{{json .SecurityOptions}}']))
 with (source/'virtio-seat-attempt.json').open('x') as f:json.dump({'nonce':m['nonce'],'operation':K.OP,'scope':'one emulated ARM16K virtio seat first boot only'},f)
 out.mkdir(mode=0o700);token=secrets.token_hex(16);name='cachy-arm16k-virtio-seat-'+token;labels=dict(image['Config'].get('Labels') or {});labels.update({'org.cachy-asahi.arm-seat-owner':str(os.getuid()),'org.cachy-asahi.arm-seat-nonce':token,'org.cachy-asahi.arm-seat-input':a.prepared_sha256})
 scope=OwnedContainer(name,out/'container.cid',K.IMAGE,labels,source,out);state=B.Cancellation();serial=qmp=qfile=None
 report={'schema_version':1,'status':'HOLD','scope':'emulated ARM16K real virtio seat software only','native16K':'NOT RUN','M2':'NOT RUN','performance':'NOT MEASURED','release':'NOT RUN','guest_shutdown':'NOT QUALIFIED; QMP quit after normal PAM logout'}
 def command(label,argv,timeout=20):
  with (out/(label+'.log')).open('wb') as f:r=subprocess.run(argv,stdout=f,stderr=subprocess.STDOUT,timeout=timeout)
  assert r.returncode==0,(label,r.returncode)
 state.__enter__()
 try:
  assert scope.listing(time.monotonic()+8) is None
  (out/'host-admission.json').write_text(json.dumps({'nonce':m['nonce'],'utc_ns':time.time_ns(),'monotonic_ns':time.monotonic_ns()}))
  scope.submitted=True
  command('create',['docker','create','--cidfile',str(scope.cidfile),'--name',name,'--init=false',*[x for k,v in labels.items() for x in ('--label',k+'='+v)],'--read-only','--network=none','--cap-drop=ALL','--security-opt=no-new-privileges','--cpus=2','--memory=3g','--pids-limit=256','--tmpfs','/tmp:rw,nodev,nosuid,noexec,size=32m','--mount','type=bind,source='+str(source)+',target=/inputs,readonly','--mount','type=bind,source='+str(out)+',target=/work','--env','CACHY_ASAHI_ALLOW_ARM16K_VIRTIO_SEAT_BOOT=1','--entrypoint','/usr/bin/python3',K.IMAGE,'-I','-B','/inputs/seat_actor.py'])
  row=scope.recover(time.monotonic()+8);assert row is not None;report['container_id']=row['Id'];report['image_id']=row['Image'];report['runtime']={k:row['HostConfig'][k] for k in ('NetworkMode','ReadonlyRootfs','CapDrop','CapAdd','Privileged','Devices','Memory','NanoCpus','PidsLimit','Init')}
  command('start',['docker','start',name]);deadline=time.monotonic()+420
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
   result=P.journey(serial,rpc,login['password']);report.update(result)
   actual=K.read_json(out/'host-qemu-start.json');assert actual['nonce']==m['nonce'];report['installed_gate']=installed(report['seat'],m,actual['utc_ns']//1000000000,int(time.time()))
   rpc('quit');report['QMP_quit_requested']=True
  command('normal-container-wait',['docker','wait',name],20);terminal=scope.recover(time.monotonic()+8);assert terminal['State']['ExitCode']==0 and not terminal['State']['OOMKilled']
  retirement=K.read_json(out/'qemu-retirement.json');assert retirement['passed'] and not retirement.get('actor_cancelled') and retirement['reaped'] and retirement['group_census']=='EMPTY_TWICE';report.update(status='PASS_EMULATED_ARM16K_VIRTIO_SEAT_PAM_POLICY_ONLY',QEMU_retirement=retirement)
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
   if state.pending:report.update(status='HOLD_CANCELLED',cancelled_signals=state.pending)
   if report.get('cleanup_errors'):report['status']='HOLD_CLEANUP'
   try:(out/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
   finally:state.__exit__()
 print(json.dumps({'status':report['status'],'report':str(out/'report.json')}));return 0 if report['status']=='PASS_EMULATED_ARM16K_VIRTIO_SEAT_PAM_POLICY_ONLY' else 1
if __name__=='__main__':raise SystemExit(main())

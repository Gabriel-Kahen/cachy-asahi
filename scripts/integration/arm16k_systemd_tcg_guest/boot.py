#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit Root-admitted ARM16K first boot; never called by preparation."""
import argparse,hashlib,importlib.util,json,os,re,secrets,shutil,signal,socket,stat,subprocess,sys,tempfile,time
from pathlib import Path
F=Path(__file__).with_name('frozen')/'reference_controller.py'
assert hashlib.sha256(F.read_bytes()).hexdigest()=='e7c8935f342d4b36bb6f8f24c0b48c3b8aa04be9807f62c3f8141aeaf26819fc'
spec=importlib.util.spec_from_file_location('fixed_x86_primitives',F)
B=importlib.util.module_from_spec(spec);spec.loader.exec_module(B)
Cancellation,OwnedContainer,Serial,parse_frame,sha=B.Cancellation,B.OwnedContainer,B.Serial,B.parse_frame,B.sha


def parse_session(data,nonce):
 fields=parse_frame(data,nonce)
 assert fields.get('ARCH')=='aarch64'and fields.get('PAGESIZE')=='16384','runtime architecture/page-size proof differs'
 return fields

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--allow-first-arm16k-systemd-boot',action='store_true');p.add_argument('--prepared',type=Path,required=True);p.add_argument('--prepared-sha256',required=True);p.add_argument('--tool-image',required=True);p.add_argument('--tool-image-id',required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 if not(a.allow_first_arm16k_systemd_boot and __debug__ and sys.flags.isolated and os.geteuid()!=0):p.error('explicit Root-authorized first boot/isolated ordinary host user required')
 source=a.prepared.resolve(strict=True);manifest=source/'prepared.json';assert sha(manifest)==a.prepared_sha256
 prepared=json.loads(manifest.read_text());assert prepared['status']=='PREPARED_NOT_BOOTED'and prepared['scope']=='emulated aarch64/16K stock systemd login reference only'
 assert set(prepared['files'])=={'guest.raw','Image','kernel.config'}and re.fullmatch('[0-9a-f]{32}',prepared['nonce'])
 assert prepared['provenance']['tool_image_id']==a.tool_image_id,'prepared tool image differs'
 for n,ref in prepared['files'].items():
  path=source/n;assert path.is_file()and not path.is_symlink()and path.stat().st_size==ref['bytes']and sha(path)==ref['sha256']
 credentials=source/'credentials.json';info=credentials.stat();assert info.st_uid==os.getuid()and stat.S_IMODE(info.st_mode)==0o600
 login=json.loads(credentials.read_text());assert login['username']=='builder'
 secret=login['password'].encode();assert 24<=len(secret)<=128
 image=json.loads(subprocess.check_output(['docker','image','inspect',a.tool_image],text=True))[0];assert image['Id']==a.tool_image_id
 security=json.loads(subprocess.check_output(['docker','info','--format','{{json .SecurityOptions}}'],text=True));assert 'name=rootless'in security,'rootless Docker required'
 # Explicit unique attempt before launch; the constructor never consumes it.
 attempt=source/'arm16k-first-boot-attempt.json'
 with attempt.open('x')as f:json.dump({'nonce':prepared['nonce'],'scope':'first emulated ARM16K systemd boot only'},f)
 out=a.output.resolve();out.mkdir(mode=0o700,parents=True,exist_ok=False)
 token=secrets.token_hex(16);name='cachy-arm16k-systemd-'+token;serial=None;qmp=None;report={'schema_version':1,'status':'HOLD','scope':'emulated ARM16K systemd software only','M2':'NOT RUN','native_ARM':'NOT RUN','release':'NOT RUN','guest_shutdown':'NOT QUALIFIED; QMP emulator quit after logout'}
 labels=dict(image.get('Config',{}).get('Labels')or{});labels.update({'org.cachy-asahi.arm16k-systemd-owner':str(os.getuid()),'org.cachy-asahi.arm16k-systemd-nonce':token,'org.cachy-asahi.arm16k-systemd-input':a.prepared_sha256})
 scope=OwnedContainer(name,out/'container.cid',a.tool_image_id,labels,source,out)
 def cmd(label,argv,timeout=20):
  with (out/(label+'.log')).open('wb')as f:r=subprocess.run(argv,stdout=f,stderr=subprocess.STDOUT,timeout=timeout)
  assert r.returncode==0,(label,r.returncode)
 state=Cancellation();state.__enter__()
 try:
  assert scope.listing(time.monotonic()+8)is None,'unique reference name already exists'
  scope.submitted=True
  cmd('create',['docker','create','--cidfile',str(scope.cidfile),'--name',name,'--init=false',*[x for k,v in labels.items()for x in ['--label',k+'='+v]],'--read-only','--network=none','--cap-drop=ALL','--security-opt=no-new-privileges','--cpus=2','--memory=3g','--pids-limit=256','--tmpfs','/tmp:rw,nodev,nosuid,noexec,size=32m','--mount','type=bind,source='+str(source)+',target=/inputs,readonly','--mount','type=bind,source='+str(out)+',target=/work','--env','CACHY_ASAHI_ALLOW_ARM16K_SYSTEMD_BOOT=1','--entrypoint','/usr/bin/python3',a.tool_image,'-I','-B','/opt/vm_actor.py'])
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
   serial.send(b'exit\n');serial.until(rb'login:\s*');report['normal_PAM_logout_observed']=True
   qfile.write(b'{"execute":"quit","id":"quit"}\n');report['QMP_quit_requested']=True
  cmd('normal-container-wait',['docker','wait',name],20)
  terminal=scope.recover(time.monotonic()+8);assert terminal['State']['ExitCode']==0 and not terminal['State']['OOMKilled']
  retirement=json.loads((out/'qemu-retirement.json').read_text());assert retirement['passed']and not retirement.get('actor_cancelled'),retirement
  report['QEMU_retirement']=retirement;report['status']='PASS_EMULATED_ARM16K_SYSTEMD_SERIAL_PAM_SESSION_ONLY'
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
   if report.get('cleanup_errors')and report['status']=='PASS_EMULATED_ARM16K_SYSTEMD_SERIAL_PAM_SESSION_ONLY':report['status']='HOLD_CLEANUP'
   try:(out/'report.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
   finally:state.__exit__()
 print(json.dumps({'status':report['status'],'report':str(out/'report.json'),'failure':report.get('failure')}))
 return 0 if report['status']=='PASS_EMULATED_ARM16K_SYSTEMD_SERIAL_PAM_SESSION_ONLY'else 1


if __name__=='__main__':raise SystemExit(main())

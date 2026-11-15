#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit first-boot controller. Preparation never calls this module."""
import argparse,hashlib,json,os,re,secrets,shutil,signal,socket,stat,subprocess,tempfile,time
from pathlib import Path
MAX_SERIAL=1024**2


class Cancelled(KeyboardInterrupt):
 def __init__(self,number):super().__init__('signal '+str(number));self.number=number


class Cancellation:
 """Handle INT/TERM; defer further cancellation until owned cleanup/report ends."""
 def __init__(self):self.pending=[];self.cleaning=False;self.previous={}
 def handler(self,number,frame):
  self.pending.append(number)
  if not self.cleaning:raise Cancelled(number)
 def __enter__(self):
  for number in [signal.SIGINT,signal.SIGTERM]:self.previous[number]=signal.getsignal(number);signal.signal(number,self.handler)
  return self
 def __exit__(self,*_):
  for number,handler in self.previous.items():signal.signal(number,handler)


class OwnedContainer:
 """Only this fixed reference container; recover ambiguous create before disposal."""
 def __init__(self,name,cidfile,image,labels,source,out):
  self.name,self.cidfile,self.image,self.labels=name,cidfile,image,labels
  self.source,self.out=str(source),str(out);self.submitted=False;self.cid=None
 def call(self,argv,deadline):
  remaining=deadline-time.monotonic()
  if remaining<=0:raise TimeoutError('independent container cleanup deadline')
  return subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=min(8,remaining))
 def listing(self,deadline):
  r=self.call(['docker','container','ls','-a','--no-trunc','--filter','name=^/'+self.name+'$','--format','{{.ID}} {{.Names}}'],deadline)
  assert r.returncode==0,'owned-name query failed'
  rows=r.stdout.decode().splitlines();assert len(rows)<=1
  if not rows:return None
  pair=rows[0].split();assert len(pair)==2 and pair[1]==self.name and re.fullmatch('[0-9a-f]{64}',pair[0])
  return pair[0]
 def validate(self,row):
  assert re.fullmatch('[0-9a-f]{64}',row.get('Id',''))and row['Name']=='/'+self.name
  assert row['Image']==self.image and row['Config']['Labels']==self.labels,'owned image/labels mismatch'
  assert row['Config']['Entrypoint']==['/usr/bin/python3']and row['Config']['Cmd']==['-I','-B','/opt/vm_actor.py']
  mounts={(m['Type'],m['Source'],m['Destination'],m['RW'])for m in row['Mounts']}
  assert len(row['Mounts'])==2 and mounts=={('bind',self.source,'/inputs',False),('bind',self.out,'/work',True)},'owned mounts mismatch'
  hc=row['HostConfig'];assert hc['ReadonlyRootfs']and hc['NetworkMode']=='none'and hc['CapDrop']==['ALL']and not hc['CapAdd']and not hc['Privileged']and not hc['Devices']and hc.get('Init')is False
  assert hc['Memory']==3*1024**3 and hc['NanoCpus']==2_000_000_000 and hc['PidsLimit']==256
 def recover(self,deadline):
  from_file=None
  try:
   fd=os.open(self.cidfile,os.O_RDONLY|os.O_NOFOLLOW)
   with os.fdopen(fd,'rb')as f:
    st=os.fstat(f.fileno());assert stat.S_ISREG(st.st_mode)and st.st_uid==os.getuid()and st.st_size<=128 and not st.st_mode&0o022
    raw=f.read(129).decode().strip()
   if raw:
    assert re.fullmatch('[0-9a-f]{64}',raw),'invalid private CID receipt';from_file=raw
  except FileNotFoundError:pass
  listed=self.listing(deadline)
  if from_file and listed:assert from_file==listed,'private CID/name differ'
  candidate=self.cid or from_file or listed
  if candidate is None:return None
  if self.cid and from_file:assert self.cid==from_file
  r=self.call(['docker','container','inspect',candidate],deadline);assert r.returncode==0,'owned CID inspection failed'
  rows=json.loads(r.stdout);assert len(rows)==1;self.validate(rows[0]);assert rows[0]['Id']==candidate
  self.cid=candidate
  return rows[0]
 def cleanup(self,report):
  if not self.submitted:return
  deadline=time.monotonic()+35;errors=report.setdefault('cleanup_errors',[])
  try:row=self.recover(deadline)
  except BaseException as e:
   errors.append({'step':'ownership-recovery','category':type(e).__name__,'message':str(e)[:1024]});return
  if row is None:report['owned_container_absence_verified']=True;return
  report['container_id']=self.cid;report['cleanup_ownership_verified']=True
  try:(Path(self.out)/'STOP').touch()
  except BaseException as e:errors.append({'step':'request-stop','category':type(e).__name__,'message':str(e)[:1024]})
  try:
   r=self.call(['docker','wait',self.cid],min(deadline-15,time.monotonic()+8))
   if r.returncode:raise RuntimeError('owned wait command failed')
  except BaseException as e:errors.append({'step':'bounded-wait','category':type(e).__name__,'message':str(e)[:1024]})
  # A wait timeout/error cannot skip removal or the final report.
  try:
   r=self.call(['docker','container','rm','--force',self.cid],deadline-5);assert r.returncode==0,'owned forced removal failed'
   report['owned_container_removed']=True
  except BaseException as e:errors.append({'step':'forced-removal','category':type(e).__name__,'message':str(e)[:1024]})
  try:
   report['owned_container_absence_verified']=self.listing(deadline)is None
   assert report['owned_container_absence_verified'],'owned name remains after removal'
  except BaseException as e:errors.append({'step':'absence-check','category':type(e).__name__,'message':str(e)[:1024]})


def sha(path):
 with path.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()


def parse_frame(data,nonce):
 text=data.decode('utf-8',errors='replace').replace('\r','')
 start='TCG_LOGIN_BEGIN '+nonce+'\n';end='TCG_LOGIN_END '+nonce
 assert text.count(start)==1 and text.count(end)==1,'missing/duplicate exact login frame'
 body=text.split(start,1)[1].split(end,1)[0];fields={}
 for line in body.splitlines():
  assert '='in line,line
  k,v=line.split('=',1);assert k not in fields and len(v)<1024
  fields[k]=v
 for k,v in {'UID':'1000','USERNAME':'builder','PID1':'systemd','Name':'builder','User':'1000','Class':'user','Type':'tty','Service':'login','Remote':'no','LOGIND':'active','DBUS':'active'}.items():assert fields.get(k)==v,(k,fields.get(k),v)
 assert fields['XDG_SESSION_ID']==fields['Id']and re.fullmatch('[A-Za-z0-9_-]{1,64}',fields['Id'])
 assert fields['Leader'].isdigit()and fields['State']in {'active','online'}
 return fields


class Serial:
 def __init__(self,stream,deadline):self.stream=stream;self.deadline=deadline;self.data=bytearray();self.offset=0
 def until(self,pattern):
  regex=re.compile(pattern)
  while True:
   match=regex.search(bytes(self.data),self.offset)
   if match:self.offset=match.end();return match
   remaining=self.deadline-time.monotonic()
   if remaining<=0:raise TimeoutError('bounded reference serial deadline')
   self.stream.settimeout(min(.5,remaining))
   try:chunk=self.stream.recv(65536)
   except socket.timeout:continue
   if not chunk:raise EOFError('reference serial closed before expected frame')
   self.data.extend(chunk)
   if len(self.data)>MAX_SERIAL:raise ValueError('reference serial byte limit')
 def send(self,data):self.stream.sendall(data)


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--allow-first-x86-reference-boot',action='store_true');p.add_argument('--prepared',type=Path,required=True);p.add_argument('--prepared-sha256',required=True);p.add_argument('--tool-image',required=True);p.add_argument('--tool-image-id',required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 if not(a.allow_first_x86_reference_boot and __debug__ and os.geteuid()!=0):p.error('explicit Root-authorized first boot/ordinary host user required')
 source=a.prepared.resolve(strict=True);manifest=source/'prepared.json';assert sha(manifest)==a.prepared_sha256
 prepared=json.loads(manifest.read_text());assert prepared['status']=='PREPARED_NOT_BOOTED'
 for n,ref in prepared['files'].items():
  path=source/n;assert path.is_file()and not path.is_symlink()and path.stat().st_size==ref['bytes']and sha(path)==ref['sha256']
 credentials=source/'credentials.json';info=credentials.stat();assert info.st_uid==os.getuid()and stat.S_IMODE(info.st_mode)==0o600
 login=json.loads(credentials.read_text());assert login['username']=='builder'
 secret=login['password'].encode();assert 24<=len(secret)<=128
 image=json.loads(subprocess.check_output(['docker','image','inspect',a.tool_image],text=True))[0];assert image['Id']==a.tool_image_id
 security=json.loads(subprocess.check_output(['docker','info','--format','{{json .SecurityOptions}}'],text=True));assert 'name=rootless'in security,'rootless Docker required'
 # Explicit unique attempt before launch; the constructor never consumes it.
 attempt=source/'first-boot-attempt.json'
 with attempt.open('x')as f:json.dump({'nonce':prepared['nonce'],'scope':'first x86 reference boot only'},f)
 out=a.output.resolve();out.mkdir(mode=0o700,parents=True,exist_ok=False)
 token=secrets.token_hex(16);name='cachy-tcg-reference-'+token;serial=None;qmp=None;report={'schema_version':1,'status':'HOLD','scope':'x86 TCG reference software only','M2':'NOT RUN','ARM':'NOT RUN','release':'NOT RUN','guest_shutdown':'NOT QUALIFIED; QMP emulator quit after logout'}
 labels=dict(image.get('Config',{}).get('Labels')or{});labels.update({'org.cachy-asahi.reference-owner':str(os.getuid()),'org.cachy-asahi.reference-nonce':token,'org.cachy-asahi.reference-input':a.prepared_sha256})
 scope=OwnedContainer(name,out/'container.cid',a.tool_image_id,labels,source,out)
 def cmd(label,argv,timeout=20):
  with (out/(label+'.log')).open('wb')as f:r=subprocess.run(argv,stdout=f,stderr=subprocess.STDOUT,timeout=timeout)
  assert r.returncode==0,(label,r.returncode)
 state=Cancellation();state.__enter__()
 try:
  assert scope.listing(time.monotonic()+8)is None,'unique reference name already exists'
  scope.submitted=True
  cmd('create',['docker','create','--cidfile',str(scope.cidfile),'--name',name,'--init=false',*[x for k,v in labels.items()for x in ['--label',k+'='+v]],'--read-only','--network=none','--cap-drop=ALL','--security-opt=no-new-privileges','--cpus=2','--memory=3g','--pids-limit=256','--tmpfs','/tmp:rw,nodev,nosuid,noexec,size=32m','--mount','type=bind,source='+str(source)+',target=/inputs,readonly','--mount','type=bind,source='+str(out)+',target=/work','--env','CACHY_ASAHI_ALLOW_REFERENCE_BOOT=1','--entrypoint','/usr/bin/python3',a.tool_image,'-I','-B','/opt/vm_actor.py'])
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
   nonce=prepared['nonce'];serial.until(('TCG_SHELL_READY '+nonce).encode());serial.send(b'/usr/local/libexec/tcg-login-proof\n');serial.until(('TCG_LOGIN_END '+nonce).encode())
   report['session']=parse_frame(bytes(serial.data),nonce)
   serial.send(b'exit\n');serial.until(rb'login:\s*');report['normal_PAM_logout_observed']=True
   qfile.write(b'{"execute":"quit","id":"quit"}\n');report['QMP_quit_requested']=True
  cmd('normal-container-wait',['docker','wait',name],20)
  terminal=scope.recover(time.monotonic()+8);assert terminal['State']['ExitCode']==0 and not terminal['State']['OOMKilled']
  retirement=json.loads((out/'qemu-retirement.json').read_text());assert retirement['passed']and not retirement.get('actor_cancelled'),retirement
  report['QEMU_retirement']=retirement;report['status']='PASS_X86_REFERENCE_SERIAL_PAM_SESSION_ONLY'
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
   if report.get('cleanup_errors')and report['status']=='PASS_X86_REFERENCE_SERIAL_PAM_SESSION_ONLY':report['status']='HOLD_CLEANUP'
   try:(out/'report.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
   finally:state.__exit__()
 print(json.dumps({'status':report['status'],'report':str(out/'report.json'),'failure':report.get('failure')}))
 return 0 if report['status']=='PASS_X86_REFERENCE_SERIAL_PAM_SESSION_ONLY'else 1


if __name__=='__main__':raise SystemExit(main())

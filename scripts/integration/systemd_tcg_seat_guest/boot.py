#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Root-reviewed finite VGA/PS2/VT PAM journey; no autologin/session fabrication."""
import argparse,hashlib,importlib.util,json,os,re,secrets,signal,socket,stat,subprocess,tempfile,time
from pathlib import Path
HERE=Path(__file__).resolve().parent;FROZEN=HERE.parent/'systemd_tcg_guest/boot.py';PIN='e7c8935f342d4b36bb6f8f24c0b48c3b8aa04be9807f62c3f8141aeaf26819fc'
def sha(p):
 with p.open('rb')as s:return hashlib.file_digest(s,'sha256').hexdigest()
assert sha(FROZEN)==PIN
spec=importlib.util.spec_from_file_location('seat_fixed_custody',FROZEN);B=importlib.util.module_from_spec(spec);spec.loader.exec_module(B)
seat_spec=importlib.util.spec_from_file_location('seat_input_corroboration',HERE/'input_seat.py');INPUT=importlib.util.module_from_spec(seat_spec);seat_spec.loader.exec_module(INPUT)
keyboard_spec=importlib.util.spec_from_file_location('seat_explicit_keyboard',HERE/'keyboard.py');KEYBOARD=importlib.util.module_from_spec(keyboard_spec);keyboard_spec.loader.exec_module(KEYBOARD)
class SeatHold(RuntimeError):pass
class Serial(B.Serial):
 def __init__(self,stream,deadline,nonce):super().__init__(stream,deadline);self.nonce=nonce
 def release(self,expected):
  old=self.deadline;self.deadline=min(old,time.monotonic()+5)
  try:
   match=self.until(rb'SEAT_KEY_ACK ([0-9a-f]+) ([1-9][0-9]*)\r?\n');assert match.group(1).decode()==self.nonce and int(match.group(2))==expected,'nonce/release order mismatch'
  finally:self.deadline=old
 def until(self,pattern):
  regex=re.compile(pattern)
  while True:
   hold=re.search(rb'(?m)^SEAT_HOLD '+self.nonce.encode()+rb' (\{[^\r\n]*\})\r?\n',bytes(self.data).replace(b'\r',b''))
   if hold:raise SeatHold(str(json.loads(hold.group(1)).get('failure',{}))[:2048])
   match=regex.search(bytes(self.data),self.offset)
   if match:self.offset=match.end();return match
   remaining=self.deadline-time.monotonic()
   if remaining<=0:raise TimeoutError('real-seat serial deadline')
   self.stream.settimeout(min(.5,remaining))
   try:chunk=self.stream.recv(65536)
   except socket.timeout:continue
   if not chunk:raise EOFError('real-seat observer closed')
   self.data.extend(chunk)
   if len(self.data)>1024**2:raise ValueError('real-seat serial byte bound')
def parse(data,nonce):
 text=data.decode(errors='replace').replace('\r','');begin='SEAT_SESSION_BEGIN '+nonce+'\n';end='SEAT_SESSION_END '+nonce
 assert text.count(begin)==text.count(end)==1,'missing/duplicate seat frame'
 body=text.split(begin,1)[1].split(end,1)[0].strip();assert len(body)<128*1024
 value=json.loads(body);assert value['status']=='PASS_X86_REAL_SEAT_REFERENCE_ONLY'and value['nonce']==nonce
 user=value['user'];assert user['status']=='PASS_X86_REAL_SEAT_USER_PROOF_ONLY'and user['uid']==user['gid']==1000 and user['tty']=='/dev/tty1'and user['foreground_VT']=='tty1'
 assert user['sd_session_get_seat']=={'return':0,'seat':'seat0'}
 for props in [user['logind'],value['real_session_corroborated']]:
  for k,v in {'Name':'builder','Active':True,'Class':'user','Type':'tty','Remote':False,'Service':'login','TTY':'tty1'}.items():assert props[k]==v,(k,props[k])
  assert props['Seat'][0]=='seat0'and props['User'][0]==1000
 assert user['logind']['Id']==value['real_session_corroborated']['Id']
 for credentials in [user['bus_credentials'],value['user_bus_credentials_corroborated']]:assert credentials['UnixUserID']==1000 and credentials['ProcessID']==user['pid']
 assert user['authorization']['allow_user_interaction']is False and user['authorization']['result'][0]is True and user['authorization']['result'][1]is False
 assert user['original_policy_sha256']=='6002ee5e8fcf3cfdd25fa5425c5dfa879dc293f8b1c69f14b4a8f9259be0b446'
 assert value['stock_udev_seat_rule_sha256']==INPUT.RULE_SHA256
 assert value['DRM_cards']and any(INPUT.is_seat_keyboard(p)for p in value['kernel_input_devices'].values())
 assert value['keyboard_delivery']=={'release_count':41,'raw_events_or_keycodes_exported':False,'event_grab':False}
 assert value['observed_stages']['password_ready_echo_off']is True and value['observed_stages']['profile_entered']is True and value['observed_stages']['PAM_authentication_denied']is False
 assert len(value['VT_screen_pins'])==2
 return value
def key_codes(text):
 if not re.fullmatch('[a-z0-9]+',text):raise ValueError('only fixed lowercase/hex keyboard text admitted')
 return list(text)+['ret']
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--allow-first-real-seat-reference-boot',action='store_true');p.add_argument('--prepared',type=Path,required=True);p.add_argument('--prepared-sha256',required=True);p.add_argument('--tool-image',required=True);p.add_argument('--tool-image-id',required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 if not(a.allow_first_real_seat_reference_boot and __debug__ and os.geteuid()!=0):p.error('explicit Root-reviewed real-seat experiment/ordinary host user required')
 source=a.prepared.resolve(strict=True);assert sha(source/'prepared.json')==a.prepared_sha256;manifest=json.loads((source/'prepared.json').read_text());assert manifest['status']=='PREPARED_NOT_BOOTED'
 for name,ref in manifest['files'].items():
  path=source/name;assert path.is_file()and not path.is_symlink()and path.stat().st_size==ref['bytes']and sha(path)==ref['sha256']
 credential=source/'credentials.json';assert credential.stat().st_uid==os.getuid()and credential.stat().st_mode&0o777==0o600 and not credential.is_symlink();login=json.loads(credential.read_text());assert login['username']=='builder'and re.fullmatch('[0-9a-f]{32}',login['password']);secret=login['password'].encode()
 image=json.loads(subprocess.check_output(['docker','image','inspect',a.tool_image]))[0];assert image['Id']==a.tool_image_id
 assert 'name=rootless'in json.loads(subprocess.check_output(['docker','info','--format','{{json .SecurityOptions}}']))
 out=a.output.resolve();out.mkdir(mode=0o700,parents=True,exist_ok=False)
 with(source/'first-boot-attempt.json').open('x')as f:json.dump({'nonce':manifest['nonce'],'scope':'one real x86 VT/seat reference attempt'},f)
 token=secrets.token_hex(16);name='cachy-tcg-seat-'+token;nonce=manifest['nonce'];labels=dict(image.get('Config',{}).get('Labels')or{});labels.update({'org.cachy-asahi.reference-owner':str(os.getuid()),'org.cachy-asahi.reference-nonce':token,'org.cachy-asahi.reference-input':a.prepared_sha256})
 scope=B.OwnedContainer(name,out/'container.cid',a.tool_image_id,labels,source,out);serial=None;qmp=None;qfile=None;state=B.Cancellation();report={'schema_version':1,'status':'HOLD','scope':'x86 real VT/PAM/logind/seat/Polkit reference only','ARM_M2_release':'NOT RUN','guest_shutdown':'NOT QUALIFIED; planned logout then QMP emulator quit'}
 def command(label,args,timeout=20):
  with(out/(label+'.log')).open('wb')as f:r=subprocess.run(args,stdout=f,stderr=subprocess.STDOUT,timeout=timeout)
  assert r.returncode==0,(label,r.returncode)
 state.__enter__()
 try:
  assert scope.listing(time.monotonic()+8)is None
  scope.submitted=True
  command('create',['docker','create','--cidfile',str(scope.cidfile),'--name',name,'--init=false',*[x for k,v in labels.items()for x in ['--label',k+'='+v]],'--read-only','--network=none','--cap-drop=ALL','--security-opt=no-new-privileges','--cpus=2','--memory=3g','--pids-limit=256','--tmpfs','/tmp:rw,nodev,nosuid,noexec,size=32m','--mount','type=bind,source='+str(source)+',target=/inputs,readonly','--mount','type=bind,source='+str(out)+',target=/work','--env','CACHY_ASAHI_ALLOW_REFERENCE_BOOT=1','--entrypoint=/usr/bin/python3',a.tool_image,'-I','-B','/opt/vm_actor.py'])
  observed=scope.recover(time.monotonic()+8);assert observed;report['container_id']=observed['Id'];report['tool_image_id']=observed['Image'];report['runtime']={k:observed['HostConfig'][k]for k in ['NetworkMode','ReadonlyRootfs','CapDrop','CapAdd','Privileged','Devices','Memory','NanoCpus','PidsLimit','Init']}
  command('start',['docker','start',name]);deadline=time.monotonic()+420
  with tempfile.TemporaryDirectory(prefix='tcg-seat-sockets-')as short:
   link=Path(short)/'out';link.symlink_to(out,target_is_directory=True)
   for node in ['serial.sock','qmp.sock']:
    until=time.monotonic()+15
    while not(out/node).exists()and time.monotonic()<until:time.sleep(.05)
    st=(out/node).lstat();assert stat.S_ISSOCK(st.st_mode)and st.st_uid==os.getuid()
   qmp=socket.socket(socket.AF_UNIX);qmp.settimeout(5);qmp.connect(str(link/'qmp.sock'));qfile=qmp.makefile('rwb',buffering=0)
   def reply():
    line=qfile.readline(65537);assert 0<len(line)<=65536;return json.loads(line)
   assert 'QMP'in reply();rpc_count=0
   def rpc(method,args=None):
    nonlocal rpc_count
    rpc_count+=1;ident='seat-'+str(rpc_count);qfile.write(json.dumps({'execute':method,'arguments':args or{},'id':ident}).encode()+b'\n')
    for _ in range(64):
     row=reply()
     if row.get('id')==ident:assert 'error'not in row,('QMP refusal',row.get('error'));return row.get('return')
    raise ValueError('QMP event reply bound')
   rpc('qmp_capabilities');stream=socket.socket(socket.AF_UNIX);stream.connect(str(link/'serial.sock'));serial=Serial(stream,deadline,nonce)
   released=0
   def keys(codes):
    nonlocal released
    for key in codes:
     rpc('input-send-event',{'events':KEYBOARD.key_events(key)});released+=1;serial.release(released)
   # Explicit make/break, then real per-character ATkbd release acknowledgements.
   chord=[{'type':'key','data':{'down':True,'key':{'type':'qcode','data':k}}}for k in ['ctrl','alt','f1']]
   chord +=[{'type':'key','data':{'down':False,'key':{'type':'qcode','data':k}}}for k in ['f1','alt','ctrl']]
   rpc('input-send-event',{'events':chord})
   ready=serial.until(('SEAT_LOGIN_READY '+nonce+r' (\{[^\r\n]*\})\r?\n').encode());assert json.loads(ready.group(1))=={'release_count':0}
   keys(key_codes('builder'))
   ready=serial.until(('SEAT_PASSWORD_READY '+nonce+r' (\{[^\r\n]*\})\r?\n').encode());assert json.loads(ready.group(1))=={'echo_disabled':True,'release_count':8}
   keys(key_codes(login['password']))
   report['keyboard']={'method':'QMP explicit down/up; real ATkbd release acknowledgement per character','VT_selection':'Ctrl+Alt+F1','username_releases':8,'credential_releases':33,'credential_values_logged':False,'raw_keycodes_exported':False,'password_ready_echo_off_observed':True}
   serial.until(('SEAT_SESSION_END '+nonce).encode());report['seat']=parse(bytes(serial.data),nonce)
   serial.until(('SEAT_SHELL_RETURNED '+nonce).encode());keys(key_codes('exit'));logout=serial.until(('SEAT_LOGOUT_COMPLETE '+nonce+r' (\{[^\r\n]*\})\r?\n').encode());assert json.loads(logout.group(1))=={'login1_session_removed':True,'new_getty_prompt':True,'release_count':46};report['normal_VT_PAM_logout_observed']=True
   rpc('quit');report['QMP_quit_requested']=True
  command('normal-container-wait',['docker','wait',name],20);terminal=scope.recover(time.monotonic()+8);assert terminal['State']['ExitCode']==0 and not terminal['State']['OOMKilled']
  retirement=json.loads((out/'qemu-retirement.json').read_text());assert retirement['passed']and not retirement.get('actor_cancelled');report.update(status='PASS_X86_REAL_SEAT_REFERENCE_ONLY',QEMU_retirement=retirement)
 except BaseException as e:report['failure']={'category':type(e).__name__,'message':str(e)[:2048]}
 finally:
  state.cleaning=True
  try:
   if serial is not None:
    try:(out/'serial.redacted.log').write_bytes(bytes(serial.data).replace(secret,b'[REDACTED TEST PASSWORD]'));serial.stream.close()
    except BaseException as e:report.setdefault('cleanup_errors',[]).append({'step':'serial-report','category':type(e).__name__,'message':str(e)[:1024]})
   for label,resource in [('qmp-file',qfile),('qmp-socket',qmp)]:
    if resource is not None:
     try:resource.close()
     except BaseException as e:report.setdefault('cleanup_errors',[]).append({'step':label,'category':type(e).__name__,'message':str(e)[:1024]})
   scope.cleanup(report)
  except BaseException as e:report.setdefault('cleanup_errors',[]).append({'step':'cleanup','category':type(e).__name__,'message':str(e)[:1024]})
  finally:
   if state.pending:report['cancelled_signals']=state.pending;report['status']='HOLD_CANCELLED'
   if report.get('cleanup_errors')and report['status'].startswith('PASS_'):report['status']='HOLD_CLEANUP'
   try:(out/'report.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
   finally:state.__exit__()
 print(json.dumps({'status':report['status'],'report':str(out/'report.json'),'failure':report.get('failure')}));return 0 if report['status'].startswith('PASS_')else 1
if __name__=='__main__':raise SystemExit(main())

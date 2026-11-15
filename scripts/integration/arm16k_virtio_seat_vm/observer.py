#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only root observation of real VT pixels/session/device custody."""
import ctypes,hashlib,importlib.util,json,os,socket,subprocess,termios,time,traceback
from pathlib import Path
H=Path('/home/builder');R=Path('/run/arm16k-virtio-seat');nonce=Path('/etc/arm16k-virtio-seat-nonce').read_text().strip()

def main():
 assert os.uname().machine=='aarch64' and os.sysconf('SC_PAGE_SIZE')==16384 and os.uname().release=='7.1.13-generic16k-managed-gui-rtc-uiseat1'
 assert len(nonce)==32 and all(c in '0123456789abcdef' for c in nonce)
 assert __debug__ and os.geteuid()==0 and not Path('/.dockerenv').exists()and Path('/proc/1/comm').read_text().strip()=='systemd'
 assert 'arm16k_virtio_seat_nonce='+nonce in Path('/proc/cmdline').read_text()
 D=Path('/var/lib/arm16k-virtio-seat')
 def envfile(path,cap):
  assert path.is_file() and not path.is_symlink() and path.stat().st_uid==0 and path.stat().st_size<=cap
  result={}
  for line in path.read_text().splitlines():
   key,value=line.split('=',1);assert key not in result;result[key]=value
  return result
 install=envfile(D/'summary.env',4096);assert install['STATUS']=='PASS' and install['NONCE']==nonce and install['BASELINE_PACKAGES']=='111' and install['TRUSTED_ALPM']=='Required_TrustedOnly' and install['HOOKS_SCRIPTLETS']=='unsuppressed' and install['POLICY_OWNER']=='networkmanager' and install['CLOCK_SETTING']=='none'
 assert set(install)=={'STATUS','NONCE','BASELINE_PACKAGES','INSTALLED_PACKAGES','TRUSTED_ALPM','HOOKS_SCRIPTLETS','POLICY_OWNER','CLOCK_SETTING'}
 actual=subprocess.run(['/usr/bin/pacman','-Q'],capture_output=True,timeout=10);assert actual.returncode==0 and len(actual.stdout)<=65536
 expected=(D/'expected-after.lock').read_bytes();assert len(expected)<=65536 and b''.join(sorted(actual.stdout.splitlines(keepends=True)))==expected
 assert len(actual.stdout.splitlines())==int(install['INSTALLED_PACKAGES'])
 unit=subprocess.run(['/usr/bin/systemctl','show','arm16k-seat-install.service','--property=Result','--property=ExecMainStatus','--property=ActiveState'],capture_output=True,timeout=5);assert unit.returncode==0 and set(unit.stdout.splitlines())=={b'Result=success',b'ExecMainStatus=0',b'ActiveState=active'}
 clock=envfile(D/'rtc-clock.env',2048)
 assert clock['RTC_PRESENT']=='yes' and clock['RTC_DRIVER']=='pl031' and clock['RTC_HCTOSYS']=='1' and clock['RTC_CLOCK_ADVANCED']=='yes' and clock['CLOCK_SETTING']=='none'
 input_hash=(D/'addition-manifest.sha256').read_text().strip();assert len(input_hash)==64 and all(c in '0123456789abcdef' for c in input_hash)
 installed_gate={'status':'PASS','nonce':nonce,'baseline_count':111,'installed_count':int(install['INSTALLED_PACKAGES']),'trusted_ALPM_completed':True,'ordinary_hooks_scriptlets':True,'policy_owner':'networkmanager','additions_sha256':input_hash,'actual_inventory_sha256':hashlib.sha256(expected).hexdigest(),'clock':clock,'durability':'successful install service after sync-f boundary'}
 with open('/dev/ttyAMA0','w',buffering=1)as serial:
  def frame(label,value=None):serial.write('\n'+label+' '+nonce+(' '+json.dumps(value,sort_keys=True)if value is not None else'')+'\n')
  deadline=time.monotonic()+210;report={'schema_version':1,'status':'HOLD','installed_gate':installed_gate};screens=[];keyboard_fd=None;counter=None;password_observed=False;logout_keys_allowed=False;last_journal=0;stages={'login_ready':False,'password_ready_echo_off':False,'profile_entered':False,'PAM_authentication_denied':False}
  def wait(check,label):
   while time.monotonic()<deadline:
    observe_progress()
    value=check()
    if value:return value
    time.sleep(.1)
   raise TimeoutError(label)
  def screen():
   p=Path('/dev/vcs1')
   if not p.exists():return ''
   data=p.read_bytes();assert len(data)<16384
   return data.decode(errors='replace')
  def observe_progress():
   nonlocal last_journal
   if keyboard_fd is not None:
    while True:
     try:data=os.read(keyboard_fd,4096)
     except BlockingIOError:break
     if not data:raise EOFError('real keyboard event stream ended')
     for count in counter.consume(data):
      if(not password_observed and count>8)or(not logout_keys_allowed and count>41):raise RuntimeError('unexpected keyboard release outside admitted phase')
      frame('SEAT_KEY_ACK',count)
   profile=H/'PROFILE_ENTERED';stages['profile_entered']=profile.exists()
   error=H/'SEAT_ERROR'
   if error.exists():
    assert error.is_file()and not error.is_symlink()and error.stat().st_uid==1000 and error.stat().st_size<=65536
    stages['profile_error_bytes']=error.stat().st_size
    if error.stat().st_size:
     data=error.read_bytes();stages['profile_stderr_sha256']=hashlib.sha256(data).hexdigest()
     if any(token in data for token in [b'Traceback (most recent call last)',b'SyntaxError:',b'Fatal Python error:',b"can't open file"]):raise RuntimeError('profile proof startup error; contents private')
   status=H/'PROOF_EXIT_STATUS'
   if status.exists():
    assert status.is_file()and not status.is_symlink()and status.stat().st_uid==1000 and status.stat().st_size<8
    stages['profile_proof_exit']=int(status.read_text())
    if stages['profile_proof_exit']!=0:raise RuntimeError('profile proof exited nonzero')
   if password_observed and not stages['profile_entered']and counter.count>=41:
    if'Login incorrect'in screen():stages['PAM_authentication_denied']=True;raise PermissionError('stock VT login denied; no authentication retry')
    if time.monotonic()-last_journal>=1:
     last_journal=time.monotonic();r=subprocess.run(['journalctl','--boot','--unit=getty@tty1.service','--output=json','--no-pager','--quiet','-n','40'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=5)
     assert len(r.stdout)<256*1024
     for line in r.stdout.splitlines():
      message=json.loads(line).get('MESSAGE','');message=message if isinstance(message,str)else''
      if'authentication failure'in message:stages['PAM_authentication_denied']=True;raise PermissionError('journal confirms PAM authentication failure; no authentication retry')
  def independent(name,passed,evidence):
   report['last_attempted_independent_check']=name
   checks.publish(D/'receipts',nonce,name,passed,evidence,report.setdefault('independent_checks',{}))
  def persist_census(stage):
   value={'schema_version':1,'nonce':nonce,'stage':stage,'diagnostics':input_parent.census()}
   raw=(json.dumps(value,sort_keys=True)+'\n').encode();assert len(raw)<=65536
   destination=D/'receipts'/('device-census-'+stage+'.json')
   fd=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
   with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
   result=subprocess.run(['/usr/bin/sync','-f',str(destination.parent)],capture_output=True,timeout=5);assert result.returncode==0
   report['device_diagnostics']=value['diagnostics']
  try:
   spec=importlib.util.spec_from_file_location('real_input_parent','/usr/local/libexec/seat-input.py');input_parent=importlib.util.module_from_spec(spec);spec.loader.exec_module(input_parent)
   kspec=importlib.util.spec_from_file_location('passive_keyboard','/usr/local/libexec/seat-keyboard.py');keyboard=importlib.util.module_from_spec(kspec);kspec.loader.exec_module(keyboard)
   check_spec=importlib.util.spec_from_file_location('arm_seat_independent_checks',D/'observer-checks.py');checks=importlib.util.module_from_spec(check_spec);check_spec.loader.exec_module(checks)
   rule=Path('/usr/lib/udev/rules.d/71-seat.rules');assert hashlib.sha256(rule.read_bytes()).hexdigest()==input_parent.RULE_SHA256
   # Observe the kernel VT text cells, not a synthetic login/prompt/session.
   persist_census('pre-device')
   gpu=wait(input_parent.choose_gpu,'actual virtio-MMIO GPU with stock seat tag')
   wait(lambda:subprocess.run(['loginctl','show-seat','seat0','--property=CanTTY','--value'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=5).stdout.strip()==b'yes','real seat0 VT capability')
   persist_census('initial')
   event,input_record=wait(input_parent.choose_keyboard,'actual virtio-MMIO keyboard identity/capabilities/seat parent')
   keyboard_fd=input_parent.open_verified_keyboard(event,input_record)
   # No grab/ioctl: drain pre-protocol input without retaining/exporting values.
   while True:
    try:old=os.read(keyboard_fd,4096)
    except BlockingIOError:break
    if not old:raise EOFError('keyboard stream closed before protocol')
   counter=keyboard.Releases()
   text=wait(lambda:(s if'login:'in(s:=screen())else''),'actual tty1 getty prompt');assert counter.count==0;screens.append({'stage':'login','sha256':hashlib.sha256(text.encode()).hexdigest()});stages['login_ready']=True;frame('SEAT_LOGIN_READY',{'release_count':0})
   def password_state():
    text=screen()
    if counter.count!=8 or'login: builder'not in text or'Password:'not in text:return ''
    # getty/login may vhangup and reopen the VT: never retain a stale fd.
    attributes,transient=keyboard.tty_attributes()
    if transient is not None:
     counts=stages.setdefault('tty_transient_errno_counts',{});key=str(transient);counts[key]=counts.get(key,0)+1
     return ''
    return text if keyboard.password_ready(text,attributes,counter.count)else''
   text=wait(password_state,'actual PAM prompt with successful live tty ECHO-off read')
   password_observed=True;stages['password_ready_echo_off']=True;screens.append({'stage':'password','sha256':hashlib.sha256(text.encode()).hexdigest()});frame('SEAT_PASSWORD_READY',{'echo_disabled':True,'release_count':counter.count})
   f=H/'SEAT_REPORT.json';wait(lambda:f.exists()and counter.count==41,'ordinary user proof')
   assert f.is_file()and not f.is_symlink()and f.stat().st_uid==1000 and f.stat().st_size<65536
   user=json.loads(f.read_text());report['user']=user;assert user['status']=='PASS_ARM16K_VIRTIO_SEAT_USER_PROOF_ONLY',user.get('failure')
   import gi
   from gi.repository import Gio,GLib
   bus=Gio.bus_get_sync(Gio.BusType.SYSTEM,None)
   def call(dest,path,interface,method,args,out):return bus.call_sync(dest,path,interface,method,args,GLib.VariantType(out),Gio.DBusCallFlags.NONE,5000,None).unpack()
   cred=call('org.freedesktop.DBus','/org/freedesktop/DBus','org.freedesktop.DBus','GetConnectionCredentials',GLib.Variant('(s)',(user['bus_unique_name'],)),'(a{sv})')[0]
   independent('bus-credentials',*checks.bus(user,cred))
   session=call('org.freedesktop.login1','/org/freedesktop/login1','org.freedesktop.login1.Manager','GetSessionByPID',GLib.Variant('(u)',(user['pid'],)),'(o)')[0]
   props=call('org.freedesktop.login1',session,'org.freedesktop.DBus.Properties','GetAll',GLib.Variant('(s)',('org.freedesktop.login1.Session',)),'(a{sv})')[0]
   independent('logind-session',*checks.session(props))
   independent('process-vt',*checks.process(user,os.getsid(user['pid']),Path('/sys/class/tty/tty0/active').read_text().strip()))
   # Recollect the SAME actual descriptor identity after authentication.
   final_input=input_parent.keyboard_record(event)
   independent('keyboard-record',*checks.record(input_record,final_input,input_parent.is_seat_keyboard(final_input)))
   final_gpu=input_parent.choose_gpu()
   independent('gpu-record',*checks.record(gpu,final_gpu or {},input_parent.is_seat_gpu(final_gpu or {})))
   inputs={event.name:final_input};cards=[final_gpu['sysfs_path']]
   status=subprocess.check_output(['loginctl','seat-status','seat0','--no-pager'],timeout=10).decode()
   independent('seat-status','seat0' in status,{'contains_seat0':'seat0' in status,'bytes':len(status.encode()),'sha256':hashlib.sha256(status.encode()).hexdigest()})
   report.update(installed_gate=installed_gate,architecture='aarch64',pagesize=16384,virtio_GPU=final_gpu,status='PASS_ARM16K_VIRTIO_SEAT_REFERENCE_ONLY',nonce=nonce,user_bus_credentials_corroborated=cred,real_session_corroborated={k:props[k]for k in ['Id','Name','User','Active','Class','Type','Remote','Service','TTY','Seat','Leader']},kernel_input_devices=inputs,stock_udev_seat_rule_sha256=input_parent.RULE_SHA256,DRM_cards=cards,seat_status=status,VT_screen_pins=screens,keyboard_delivery=counter.report(),observed_stages=stages)
   (R/'REPORT_VERIFIED').touch();frame('SEAT_SESSION_BEGIN');serial.write(json.dumps(report,sort_keys=True)+'\n');frame('SEAT_SESSION_END')
   wait(lambda:(H/'SHELL_RETURNED').exists(),'proof return to real interactive shell');logout_keys_allowed=True;frame('SEAT_SHELL_RETURNED')
   def gone():
    r=subprocess.run(['loginctl','show-session',user['logind']['Id'],'--no-pager'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
    return r.returncode!=0
   wait(lambda:counter.count==46 and gone(),'normal VT PAM logout/session removal');text=wait(lambda:(s if'login:'in(s:=screen())else''),'getty after logout');frame('SEAT_LOGOUT_COMPLETE',{'login1_session_removed':True,'new_getty_prompt':True,'release_count':counter.count})
  except BaseException as e:
   try:persist_census('terminal')
   except BaseException as diagnostic_error:report['device_diagnostic_failure']={'category':type(diagnostic_error).__name__}
   trace=traceback.extract_tb(e.__traceback__)[-1]
   report['failed_source']={'label':'observer.py' if Path(trace.filename).name=='seat-observer.py' else 'observer_checks.py' if Path(trace.filename).name=='observer-checks.py' else 'input_seat.py' if Path(trace.filename).name=='seat-input.py' else 'other','line':trace.lineno}
   report.update(status='HOLD',observed_stages=stages,keyboard_delivery=counter.report()if counter else None,failure={'category':type(e).__name__,'message':str(e)[:2048]});frame('SEAT_HOLD',report)
  finally:
   if keyboard_fd is not None:os.close(keyboard_fd)
  (R/'observer.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
 return 0 if report['status'].startswith('PASS_')else 1
if __name__=='__main__':raise SystemExit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only root observation of real VT pixels/session/device custody."""
import ctypes,hashlib,importlib.util,json,os,socket,subprocess,termios,time
from pathlib import Path
H=Path('/home/builder');R=Path('/run/tcg-seat');nonce=Path('/etc/tcg-reference-nonce').read_text().strip()

def main():
 assert __debug__ and os.geteuid()==0 and not Path('/.dockerenv').exists()and Path('/proc/1/comm').read_text().strip()=='systemd'
 assert 'tcg_reference_nonce='+nonce in Path('/proc/cmdline').read_text()
 with open('/dev/ttyS0','w',buffering=1)as serial:
  def frame(label,value=None):serial.write('\n'+label+' '+nonce+(' '+json.dumps(value,sort_keys=True)if value is not None else'')+'\n')
  deadline=time.monotonic()+210;report={'schema_version':1,'status':'HOLD'};screens=[];keyboard_fd=None;counter=None;password_observed=False;logout_keys_allowed=False;last_journal=0;stages={'login_ready':False,'password_ready_echo_off':False,'profile_entered':False,'PAM_authentication_denied':False}
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
  try:
   spec=importlib.util.spec_from_file_location('real_input_parent','/usr/local/libexec/seat-input.py');input_parent=importlib.util.module_from_spec(spec);spec.loader.exec_module(input_parent)
   kspec=importlib.util.spec_from_file_location('passive_keyboard','/usr/local/libexec/seat-keyboard.py');keyboard=importlib.util.module_from_spec(kspec);kspec.loader.exec_module(keyboard)
   rule=Path('/usr/lib/udev/rules.d/71-seat.rules');assert hashlib.sha256(rule.read_bytes()).hexdigest()==input_parent.RULE_SHA256
   # Observe the kernel VT text cells, not a synthetic login/prompt/session.
   wait(lambda:list(Path('/sys/class/drm').glob('card[0-9]')),'virtual DRM device')
   wait(lambda:subprocess.run(['loginctl','show-seat','seat0','--property=CanTTY','--value'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=5).stdout.strip()==b'yes','real seat0 VT capability')
   def at_keyboard():
    return next((p for p in Path('/sys/class/input').glob('event*')if(p/'device/name').read_text().strip()=='AT Translated Set 2 keyboard'),None)
   event=wait(at_keyboard,'real AT keyboard event device');keyboard_fd=os.open('/dev/input/'+event.name,os.O_RDONLY|os.O_NONBLOCK|os.O_CLOEXEC)
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
   user=json.loads(f.read_text());report['user']=user;assert user['status']=='PASS_X86_REAL_SEAT_USER_PROOF_ONLY',user.get('failure')
   import gi
   from gi.repository import Gio,GLib
   bus=Gio.bus_get_sync(Gio.BusType.SYSTEM,None)
   def call(dest,path,interface,method,args,out):return bus.call_sync(dest,path,interface,method,args,GLib.VariantType(out),Gio.DBusCallFlags.NONE,5000,None).unpack()
   cred=call('org.freedesktop.DBus','/org/freedesktop/DBus','org.freedesktop.DBus','GetConnectionCredentials',GLib.Variant('(s)',(user['bus_unique_name'],)),'(a{sv})')[0];assert cred['UnixUserID']==1000 and cred['ProcessID']==user['pid']
   session=call('org.freedesktop.login1','/org/freedesktop/login1','org.freedesktop.login1.Manager','GetSessionByPID',GLib.Variant('(u)',(user['pid'],)),'(o)')[0]
   props=call('org.freedesktop.login1',session,'org.freedesktop.DBus.Properties','GetAll',GLib.Variant('(s)',('org.freedesktop.login1.Session',)),'(a{sv})')[0]
   assert props['Seat'][0]=='seat0'and props['Active']is True and props['Name']=='builder'and props['TTY']=='tty1'and props['User'][0]==1000
   assert os.getsid(user['pid'])==user['process_session']and Path('/sys/class/tty/tty0/active').read_text().strip()=='tty1'
   inputs={}
   for p in Path('/sys/class/input').glob('event*'):
    facts=subprocess.check_output(['udevadm','info','--query=property','--path',str(p)],timeout=5).decode();parent=(p/'device').resolve(strict=True);parent_facts=subprocess.check_output(['udevadm','info','--query=property','--path',str(parent)],timeout=5).decode();inputs[p.name]={'name':(parent/'name').read_text().strip(),'properties':facts,'sysfs_path':str(p.resolve(strict=True)),'parent_sysfs_path':str(parent),'parent_properties':parent_facts}
   assert any(input_parent.is_seat_keyboard(v)for v in inputs.values()),inputs
   cards=[str(p.resolve())for p in Path('/sys/class/drm').glob('card[0-9]')];assert cards,'real virtual DRM card not present'
   status=subprocess.check_output(['loginctl','seat-status','seat0','--no-pager'],timeout=10).decode();assert 'seat0'in status
   report.update(status='PASS_X86_REAL_SEAT_REFERENCE_ONLY',nonce=nonce,user_bus_credentials_corroborated=cred,real_session_corroborated={k:props[k]for k in ['Id','Name','User','Active','Class','Type','Remote','Service','TTY','Seat','Leader']},kernel_input_devices=inputs,stock_udev_seat_rule_sha256=input_parent.RULE_SHA256,DRM_cards=cards,seat_status=status,VT_screen_pins=screens,keyboard_delivery=counter.report(),observed_stages=stages)
   (R/'REPORT_VERIFIED').touch();frame('SEAT_SESSION_BEGIN');serial.write(json.dumps(report,sort_keys=True)+'\n');frame('SEAT_SESSION_END')
   wait(lambda:(H/'SHELL_RETURNED').exists(),'proof return to real interactive shell');logout_keys_allowed=True;frame('SEAT_SHELL_RETURNED')
   def gone():
    r=subprocess.run(['loginctl','show-session',user['logind']['Id'],'--no-pager'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
    return r.returncode!=0
   wait(lambda:counter.count==46 and gone(),'normal VT PAM logout/session removal');text=wait(lambda:(s if'login:'in(s:=screen())else''),'getty after logout');frame('SEAT_LOGOUT_COMPLETE',{'login1_session_removed':True,'new_getty_prompt':True,'release_count':counter.count})
  except BaseException as e:
   report.update(status='HOLD',observed_stages=stages,keyboard_delivery=counter.report()if counter else None,failure={'category':type(e).__name__,'message':str(e)[:2048]});frame('SEAT_HOLD',report)
  finally:
   if keyboard_fd is not None:os.close(keyboard_fd)
  (R/'observer.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
 return 0 if report['status'].startswith('PASS_')else 1
if __name__=='__main__':raise SystemExit(main())

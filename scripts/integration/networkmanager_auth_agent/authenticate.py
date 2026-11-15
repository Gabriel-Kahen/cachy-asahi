#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One ordinary-process real agent/PAM own-write attempt, then denied deletes."""
import fcntl,importlib.util,json,os,pty,pwd,re,resource,select,signal,subprocess,termios,threading,time,traceback
from pathlib import Path
I=Path('/opt/nm-private-bus');HOME=Path('/home/UID1000')


def load(n,f):
 s=importlib.util.spec_from_file_location(n,I/f);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m


def main():
 if not(__debug__ and os.geteuid()==os.getegid()==1000 and os.environ.get('CACHY_ASAHI_PAM_ACTOR')=='1'and Path('/.dockerenv').is_file()):raise RuntimeError('owned ordinary PAM actor only')
 assert pwd.getpwuid(1000).pw_name=='builder'
 caps=dict(l.split(':',1)for l in Path('/proc/self/status').read_text().splitlines()if ':'in l)
 assert all(int(caps[k].strip(),16)==0 for k in ['CapEff','CapPrm','CapBnd','CapInh','CapAmb'])and caps['NoNewPrivs'].strip()=='1'
 paths={k:os.environ['NM_AUTH_'+k.upper()+'_PATH']for k in ['system','foreign']};assert all(re.fullmatch(r'/org/freedesktop/NetworkManager/Settings/[0-9]+',v)for v in paths.values())
 O=load('pam_agent_owner','owned_process.py');G=load('pam_agent_env','previous_guest.py');env=G.clean_env(os.environ);env.update(HOME=str(HOME),XDG_CONFIG_HOME=str(HOME/'config'),XDG_CACHE_HOME=str(HOME/'cache'),XDG_DATA_HOME=str(HOME/'data'),XDG_RUNTIME_DIR=str(HOME/'runtime'),TERM='dumb')
 os.environ.clear();os.environ.update(env)
 import gi
 gi.require_version('NM','1.0')
 from gi.repository import Gio,GLib,NM
 bus=Gio.bus_get_sync(Gio.BusType.SYSTEM,None)
 identity=bus.call_sync('org.freedesktop.DBus','/org/freedesktop/DBus','org.freedesktop.DBus','GetConnectionCredentials',GLib.Variant('(s)',(bus.get_unique_name(),)),GLib.VariantType('(a{sv})'),Gio.DBusCallFlags.NONE,3000,None).unpack()[0]
 assert identity['UnixUserID']==1000 and identity['ProcessID']==os.getpid()
 secret=(HOME/'TEST-password').read_bytes();(HOME/'TEST-password').unlink();resource.setrlimit(resource.RLIMIT_CORE,(0,0))
 start=Path('/proc/self/stat').read_text().rpartition(')')[2].split()[19];subject=str(os.getpid())+','+start
 master,slave=pty.openpty();rfd,wfd=os.pipe();flags=termios.tcgetattr(slave);flags[3]&=~termios.ECHO;termios.tcsetattr(slave,termios.TCSANOW,flags)
 def session():os.setsid();fcntl.ioctl(slave,termios.TIOCSCTTY,0)
 logpath=HOME/'agent-program.log';log=logpath.open('wb');O.prepare();child=subprocess.Popen(['/usr/bin/pkttyagent','--process',subject,'--notify-fd',str(wfd),'--fallback'],env=env,stdin=slave,stdout=log,stderr=subprocess.STDOUT,pass_fds=(wfd,),preexec_fn=session)
 os.close(slave);os.close(wfd);report={'uid':1000,'gid':1000,'bus_identity':identity,'real_process_subject':subject,'capabilities':'ALL zero; no-new-privileges remains1','agent_registered':False,'password_exported':False,'PAM_credential':'private TEST builder credential only','requests':[]};tty=bytearray();sent=False
 try:
  until=time.monotonic()+5
  while time.monotonic()<until:
   if os.waitid(os.P_PID,child.pid,os.WEXITED|os.WNOWAIT|os.WNOHANG)is not None:break
   if select.select([rfd],[],[],.05)[0]:
    assert os.read(rfd,1)==b'';report['agent_registered']=True;break
  assert report['agent_registered'],'real pkttyagent did not register'
  def request(label,path,method,args,outtype,allow_password,authority=False):
   nonlocal sent
   result={'name':label};done=threading.Event()
   def worker():
    try:
     value=bus.call_sync('org.freedesktop.PolicyKit1'if authority else'org.freedesktop.NetworkManager',path,'org.freedesktop.PolicyKit1.Authority'if authority else('org.freedesktop.NetworkManager.Settings'if method=='AddConnection2'else'org.freedesktop.NetworkManager.Settings.Connection'),method,args,GLib.VariantType(outtype),Gio.DBusCallFlags.NONE,20000,None)
     result.update(success=True,reply=str(value),unpacked=value.unpack())
    except BaseException as e:result.update(success=False,error=str(e),remote_error=Gio.DBusError.get_remote_error(e)if isinstance(e,GLib.Error)else type(e).__name__)
    finally:done.set()
   thread=threading.Thread(target=worker,daemon=True);thread.start();until=time.monotonic()+23
   while not done.is_set()and time.monotonic()<until:
    if select.select([master],[],[],.05)[0]:
     try:data=os.read(master,65536)
     except OSError:break
     tty.extend(data);assert len(tty)<=1024**2
     if allow_password and not sent and re.search(rb'password\s*:',tty,re.I):os.write(master,secret+b'\n');sent=True
   thread.join(timeout=1);assert done.is_set(),'bounded authorization request did not finish'
   report['requests'].append(result);return result
  authargs=GLib.Variant('((sa{sv})sa{ss}us)',(('unix-process',{'pid':GLib.Variant('u',os.getpid()),'start-time':GLib.Variant('t',int(start)),'uid':GLib.Variant('i',1000)}),'org.freedesktop.NetworkManager.settings.modify.own',{},1,'TEST-private-PAM-own'))
  report['direct_Polkit_PAM']=request('real-PAM-process-authentication','/org/freedesktop/PolicyKit1/Authority','CheckAuthorization',authargs,'((bba{ss}))',True,authority=True)
  c=NM.SimpleConnection.new();setting=NM.SettingConnection.new()
  for key,value in [('id','TEST-authenticated-user-own'),('uuid','e3140000-0000-4000-8000-000000000013'),('type','802-3-ethernet'),('interface-name','cachy-test0'),('autoconnect',False)]:setting.set_property(key,value)
  assert setting.add_permission('user','builder',None);c.add_setting(setting);c.add_setting(NM.SettingWired.new())
  for kind in [NM.SettingIP4Config,NM.SettingIP6Config]:s=kind.new();s.set_property('method','disabled');c.add_setting(s)
  params=GLib.Variant.new_tuple(c.to_dbus(NM.ConnectionSerializationFlags.ALL),GLib.Variant('u',int(NM.SettingsAddConnection2Flags.TO_DISK)),GLib.Variant('a{sv}',{}))
  own=request('authorized-own-create','/org/freedesktop/NetworkManager/Settings','AddConnection2',params,'(oa{sv})',True)
  report['password_sent_once_to_real_private_TTY']=sent
  (HOME/'OWN_RESULT.json').write_text(json.dumps(own));(HOME/'OWN_DONE').touch()
  until=time.monotonic()+15
  while not Path('/run/auth-control/CONTINUE_DENIALS').exists()and time.monotonic()<until:time.sleep(.05)
  assert Path('/run/auth-control/CONTINUE_DENIALS').exists(),'root snapshot boundary deadline'
  if own['success']:
   for kind in ['system','foreign']:request('denied-'+kind+'-delete',paths[kind],'Delete',None,'()',False)
  report['status']='PASS_AUTHENTICATED_OWN_WRITE_AND_DENIALS'if own['success']and len(report['requests'])==4 and all(not x['success']for x in report['requests'][2:])else'HOLD_REAL_PAM_OR_AUTHORIZATION'
 except BaseException as e:report['status']='HOLD_REAL_PAM_OR_AUTHORIZATION';report['failure']={'category':type(e).__name__,'message':str(e)[:2048]}
 finally:
  row=os.waitid(os.P_PID,child.pid,os.WEXITED|os.WNOWAIT|os.WNOHANG)
  if row is None:os.kill(child.pid,signal.SIGTERM)
  result=O.supervise(child,cap=8,retirement=2,grace=.2);result.pop('output');report['agent_retirement']=result;log.close();os.close(rfd);os.close(master)
  text=(bytes(tty)+logpath.read_bytes()).replace(secret,b'[REDACTED TEST CREDENTIAL]').decode(errors='replace');report['redacted_agent_output']=text
  assert secret.decode()not in json.dumps(report)
  (HOME/'AUTH_REPORT.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n');(HOME/'AUTH_DONE').touch();print(json.dumps(report),flush=True)
 return 0


if __name__=='__main__':raise SystemExit(main())

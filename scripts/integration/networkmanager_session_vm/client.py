#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Genuine logged-in ordinary user's fixed own-write/denial journey."""
import ctypes,grp,hashlib,json,os,pwd,re,select,signal,subprocess,sys,time
from pathlib import Path
H=Path('/home/builder');I=Path('/run/nm-session-fixture');NONCE=Path('/etc/tcg-reference-nonce').read_text().strip()
def wait(name,seconds=20):
 until=time.monotonic()+seconds
 while time.monotonic()<until:
  p=I/(name+'.json')
  if p.exists():assert p.is_file()and not p.is_symlink()and p.stat().st_uid==0;return json.loads(p.read_text())
  if (I/'final.json').exists():raise RuntimeError((I/'final.json').read_text()[:4096])
  time.sleep(.1)
 raise TimeoutError('root observer '+name)
def main():
 report={'schema_version':1,'status':'HOLD','scope':'ordinary real-login x86 guest NM/Polkit only','password_challenge_for_own_write':'not required by unchanged active-session upstream policy','native_ARM_M2_release':'NOT RUN'};child=None;notify=None;log=None
 try:
  assert __debug__ and os.geteuid()==os.getegid()==1000 and pwd.getpwuid(1000).pw_name=='builder'
  assert Path('/proc/1/comm').read_text().strip()=='systemd'and not Path('/.dockerenv').exists()
  assert 'tcg_reference_nonce='+NONCE in Path('/proc/cmdline').read_text()
  tty=os.ttyname(sys.stdin.fileno());libc=ctypes.CDLL(None);libc.tcgetsid.argtypes=[ctypes.c_int];libc.tcgetsid.restype=ctypes.c_int;assert tty=='/dev/ttyS0'and libc.tcgetsid(sys.stdin.fileno())==os.getsid(0)
  assert not any(g.gr_name in {'root','wheel','sudo','admin','empower'}and(g.gr_gid in os.getgroups()or'builder'in g.gr_mem)for g in grp.getgrall())
  report['account']={'uid':os.geteuid(),'gid':os.getegid(),'groups':os.getgroups(),'tty':tty,'process_session':os.getsid(0),'pid':os.getpid()}
  # Never inherit caller-provided bus addresses. Use the stock guest system bus.
  for k in list(os.environ):
   if k.startswith(('DBUS_','G_BUS_')):del os.environ[k]
  os.environ['DBUS_SYSTEM_BUS_ADDRESS']='unix:path=/run/dbus/system_bus_socket'
  import gi
  gi.require_version('NM','1.0')
  from gi.repository import Gio,GLib,NM
  bus=Gio.bus_get_sync(Gio.BusType.SYSTEM,None)
  def call(destination,path,interface,method,args=None,out=None,timeout=12000):
   return bus.call_sync(destination,path,interface,method,args,GLib.VariantType(out)if out else None,Gio.DBusCallFlags.NONE,timeout,None)
  identity=call('org.freedesktop.DBus','/org/freedesktop/DBus','org.freedesktop.DBus','GetConnectionCredentials',GLib.Variant('(s)',(bus.get_unique_name(),)),'(a{sv})').unpack()[0];assert identity['UnixUserID']==1000 and identity['ProcessID']==os.getpid();report['bus_identity']=identity
  report['service_bus_identities']={}
  for service,uid in [('org.freedesktop.NetworkManager',0),('org.freedesktop.PolicyKit1',102),('org.freedesktop.login1',0)]:
   owner=call('org.freedesktop.DBus','/org/freedesktop/DBus','org.freedesktop.DBus','GetNameOwner',GLib.Variant('(s)',(service,)),'(s)').unpack()[0]
   credential=call('org.freedesktop.DBus','/org/freedesktop/DBus','org.freedesktop.DBus','GetConnectionCredentials',GLib.Variant('(s)',(owner,)),'(a{sv})').unpack()[0]
   assert credential['UnixUserID']==uid and credential['ProcessID']>1
   report['service_bus_identities'][service]={'owner':owner,'credentials':credential}
  report['stock_service_states']=subprocess.check_output(['systemctl','is-active','NetworkManager.service','polkit.service','systemd-logind.service','dbus.service'],timeout=10).decode().splitlines();assert report['stock_service_states']==['active']*4
  session=call('org.freedesktop.login1','/org/freedesktop/login1','org.freedesktop.login1.Manager','GetSessionByPID',GLib.Variant('(u)',(os.getpid(),)),'(o)').unpack()[0]
  properties=call('org.freedesktop.login1',session,'org.freedesktop.DBus.Properties','GetAll',GLib.Variant('(s)',('org.freedesktop.login1.Session',)),'(a{sv})').unpack()[0]
  for k,v in {'Name':'builder','Active':True,'Class':'user','Type':'tty','Remote':False,'Service':'login'}.items():assert properties[k]==v,(k,properties[k])
  assert properties['Id']==os.environ['XDG_SESSION_ID'];report['logind']={k:properties[k]for k in ['Id','Name','User','Active','Class','Type','Remote','Service']}
  ready=wait('ready');assert ready['nonce']==NONCE
  # This agent shares the genuine login's controlling TTY/session; no fake PTY,
  # setsid, session claims, allow rules or alternative helper are introduced.
  start=int(Path('/proc/self/stat').read_text().rpartition(')')[2].split()[19]);rfd,wfd=os.pipe();notify=rfd
  log=(H/'agent.log').open('wb')
  child=subprocess.Popen(['/usr/bin/pkttyagent','--process',str(os.getpid())+','+str(start),'--notify-fd',str(wfd)],stdin=sys.stdin,stdout=log,stderr=subprocess.STDOUT,pass_fds=(wfd,))
  os.close(wfd);assert select.select([rfd],[],[],8)[0]and os.read(rfd,1)==b''and child.poll()is None,'real TTY agent registration failed'
  assert os.getsid(child.pid)==os.getsid(0);report['agent']={'registered':True,'pid':child.pid,'process_subject_pid':os.getpid(),'start_time':start,'same_real_login_session':True,'program_sha256':hashlib.sha256(Path('/usr/bin/pkttyagent').read_bytes()).hexdigest()}
  client=NM.Client.new(None);assert client.get_nm_running();report['NM_version']=client.get_version()
  own=NM.SimpleConnection.new();setting=NM.SettingConnection.new()
  for k,v in [('id','TEST-session-own'),('uuid','e3140000-0000-4000-8000-000000000023'),('type','802-3-ethernet'),('interface-name','cachy-absent0'),('autoconnect',False)]:setting.set_property(k,v)
  assert setting.add_permission('user','builder',None);own.add_setting(setting);own.add_setting(NM.SettingWired.new())
  for cls in [NM.SettingIP4Config,NM.SettingIP6Config]:s=cls.new();s.set_property('method','disabled');own.add_setting(s)
  params=GLib.Variant.new_tuple(own.to_dbus(NM.ConnectionSerializationFlags.ALL),GLib.Variant('u',int(NM.SettingsAddConnection2Flags.TO_DISK)),GLib.Variant('a{sv}',{}))
  result=call('org.freedesktop.NetworkManager','/org/freedesktop/NetworkManager/Settings','org.freedesktop.NetworkManager.Settings','AddConnection2',params,'(oa{sv})');path=result.unpack()[0];report['own_create']={'success':True,'path':path}
  setting.set_property('id','TEST-session-own-edited')
  call('org.freedesktop.NetworkManager',path,'org.freedesktop.NetworkManager.Settings.Connection','Update2',GLib.Variant.new_tuple(own.to_dbus(NM.ConnectionSerializationFlags.ALL),GLib.Variant('u',int(NM.SettingsUpdate2Flags.TO_DISK)),GLib.Variant('a{sv}',{})),'(a{sv})');report['own_edit']={'success':True}
  (H/'PERSISTENCE_READY').touch();report['persistence']=wait('persisted');assert report['persistence']['passed']
  # No user-interaction flag is added to Update2/Delete. If NM/Polkit initiates
  # a standard admin challenge anyway, cancel the real agent normally at4s.
  denials=[]
  for label in ['foreign','system']:
   import threading
   done=threading.Event();row={'name':label+'-delete'}
   def request():
    try:call('org.freedesktop.NetworkManager',ready['paths'][label],'org.freedesktop.NetworkManager.Settings.Connection','Delete',None,'()',15000);row['success']=True
    except GLib.Error as e:row.update(success=False,error=str(e),remote_error=Gio.DBusError.get_remote_error(e))
    finally:done.set()
   thread=threading.Thread(target=request,daemon=True);thread.start();done.wait(4)
   if not done.is_set()and child.poll()is None:
    child.terminate();report['agent_cancelled_for_pending_admin_action']=True
   assert done.wait(13),'admin denial did not finish in bounded window';thread.join(1)
   assert not row['success'],'ordinary builder unexpectedly deleted '+label
   assert row.get('remote_error')in {'org.freedesktop.NetworkManager.Settings.PermissionDenied','org.freedesktop.NetworkManager.Settings.InvalidConnection','org.freedesktop.DBus.Error.AccessDenied'},row
   denials.append(row)
  report['denials']=denials;(H/'DENIALS_DONE').touch();report['denied_state']=wait('denials');assert report['denied_state']['passed']
  call('org.freedesktop.NetworkManager',path,'org.freedesktop.NetworkManager.Settings.Connection','Delete',None,'()');report['own_cleanup']={'success':True};(H/'SESSION_DONE').touch()
  report['root_observer']=wait('final');assert report['root_observer']['status']=='PASS_X86_ROOT_OBSERVATION_ONLY'
  report['status']='PASS_X86_REAL_LOGIN_OWN_PROFILE_AND_DENIALS_ONLY'
 except BaseException as e:report['failure']={'category':type(e).__name__,'message':str(e)[:2048]}
 finally:
  if child is not None:
   if child.poll()is None:child.terminate()
   try:report['agent_exit']=child.wait(timeout=5)
   except subprocess.TimeoutExpired:report['agent_cleanup']='HOLD; normal TERM retirement deadline';report['status']='HOLD'
  if notify is not None:os.close(notify)
  if log is not None:log.close()
  if (H/'agent.log').exists():
   raw=(H/'agent.log').read_bytes();assert len(raw)<=65536;report['agent_output']=raw.decode(errors='replace')
  (H/'SESSION_REPORT.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
  print('\nNM_SESSION_BEGIN '+NONCE+'\n'+json.dumps(report,sort_keys=True)+'\nNM_SESSION_END '+NONCE,flush=True)
 return 0 if report['status'].startswith('PASS_')else 1
if __name__=='__main__':raise SystemExit(main())

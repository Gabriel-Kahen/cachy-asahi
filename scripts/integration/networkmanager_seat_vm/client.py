#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One genuine active tty1 user's NM own-profile/denial lifecycle; no agent."""
import ctypes,grp,hashlib,json,os,pwd,subprocess,time
from pathlib import Path
H=Path('/home/builder');R=Path('/run/nm-session-fixture');nonce=Path('/etc/tcg-reference-nonce').read_text().strip()
def wait(name,seconds=15):
 until=time.monotonic()+seconds
 while time.monotonic()<until:
  p=R/(name+'.json')
  if p.exists():assert p.is_file()and not p.is_symlink()and p.stat().st_uid==0 and p.stat().st_size<128*1024;return json.loads(p.read_text())
  if(R/'final.json').exists():raise RuntimeError('root snapshot observer finished without required phase')
  time.sleep(.1)
 raise TimeoutError('root NM phase '+name)
def main():
 report={'schema_version':1,'status':'HOLD','scope':'x86 real-seat ordinary NM profile lifecycle only','additional_credential_sent':False,'authentication_agent_started':False,'ARM_M2_release':'NOT RUN'}
 try:
  assert __debug__ and os.geteuid()==os.getegid()==1000 and pwd.getpwuid(1000).pw_name=='builder'
  assert not Path('/.dockerenv').exists()and Path('/proc/1/comm').read_text().strip()=='systemd'and 'tcg_reference_nonce='+nonce in Path('/proc/cmdline').read_text()
  assert os.ttyname(0)=='/dev/tty1'and Path('/sys/class/tty/tty0/active').read_text().strip()=='tty1'
  assert not any(g.gr_name in {'root','wheel','sudo','admin','empower'}and(g.gr_gid in os.getgroups()or'builder'in g.gr_mem)for g in grp.getgrall())
  for key in list(os.environ):
   if key.startswith(('DBUS_','G_BUS_')):del os.environ[key]
  os.environ['DBUS_SYSTEM_BUS_ADDRESS']='unix:path=/run/dbus/system_bus_socket'
  import gi
  gi.require_version('NM','1.0')
  from gi.repository import Gio,GLib,NM
  bus=Gio.bus_get_sync(Gio.BusType.SYSTEM,None)
  def call(dest,path,interface,method,args=None,out=None):return bus.call_sync(dest,path,interface,method,args,GLib.VariantType(out)if out else None,Gio.DBusCallFlags.NONE,15000,None).unpack()
  cred=call('org.freedesktop.DBus','/org/freedesktop/DBus','org.freedesktop.DBus','GetConnectionCredentials',GLib.Variant('(s)',(bus.get_unique_name(),)),'(a{sv})')[0];assert cred['UnixUserID']==1000 and cred['ProcessID']==os.getpid()
  report['identity']={'uid':1000,'gid':1000,'pid':os.getpid(),'groups':os.getgroups(),'tty':'/dev/tty1','bus_credentials':cred}
  path=call('org.freedesktop.login1','/org/freedesktop/login1','org.freedesktop.login1.Manager','GetSessionByPID',GLib.Variant('(u)',(os.getpid(),)),'(o)')[0]
  props=call('org.freedesktop.login1',path,'org.freedesktop.DBus.Properties','GetAll',GLib.Variant('(s)',('org.freedesktop.login1.Session',)),'(a{sv})')[0]
  for k,v in {'Name':'builder','Active':True,'Class':'user','Type':'tty','Remote':False,'Service':'login','TTY':'tty1'}.items():assert props[k]==v,(k,props[k])
  assert props['Seat'][0]=='seat0'and props['User'][0]==1000 and props['Id']==os.environ['XDG_SESSION_ID'];report['logind']={k:props[k]for k in ['Id','Name','User','Active','Class','Type','Remote','Service','TTY','Seat']}
  sd=ctypes.CDLL('libsystemd.so.0');sd.sd_session_get_seat.argtypes=[ctypes.c_char_p,ctypes.POINTER(ctypes.c_void_p)];sd.sd_session_get_seat.restype=ctypes.c_int;seat=ctypes.c_void_p();rc=sd.sd_session_get_seat(props['Id'].encode(),ctypes.byref(seat));value=ctypes.string_at(seat).decode()if rc>=0 else None
  if seat.value:libc=ctypes.CDLL(None);libc.free.argtypes=[ctypes.c_void_p];libc.free(seat)
  assert rc==0 and value=='seat0';report['sd_session_get_seat']={'return':rc,'seat':value}
  report['service_bus_identities']={}
  for service,uid in [('org.freedesktop.NetworkManager',0),('org.freedesktop.PolicyKit1',102)]:
   owner=call('org.freedesktop.DBus','/org/freedesktop/DBus','org.freedesktop.DBus','GetNameOwner',GLib.Variant('(s)',(service,)),'(s)')[0];identity=call('org.freedesktop.DBus','/org/freedesktop/DBus','org.freedesktop.DBus','GetConnectionCredentials',GLib.Variant('(s)',(owner,)),'(a{sv})')[0];assert identity['UnixUserID']==uid and identity['ProcessID']>1;report['service_bus_identities'][service]=identity
  args=GLib.Variant('((sa{sv})sa{ss}us)',(('system-bus-name',{'name':GLib.Variant('s',bus.get_unique_name())}),'org.freedesktop.NetworkManager.settings.modify.own',{},0,''))
  auth=call('org.freedesktop.PolicyKit1','/org/freedesktop/PolicyKit1/Authority','org.freedesktop.PolicyKit1.Authority','CheckAuthorization',args,'((bba{ss}))')[0];assert auth[0]is True and auth[1]is False;report['own_authorization_no_interaction']=auth
  report['policy_sha256']=hashlib.sha256(Path('/usr/share/polkit-1/actions/org.freedesktop.NetworkManager.policy').read_bytes()).hexdigest();assert report['policy_sha256']=='6002ee5e8fcf3cfdd25fa5425c5dfa879dc293f8b1c69f14b4a8f9259be0b446'
  ready=wait('ready');assert ready['nonce']==nonce and ready['version']=='1.58.1';client=NM.Client.new(None);assert client.get_nm_running()and client.get_version()=='1.58.1';report['NM_version']=client.get_version()
  connection=NM.SimpleConnection.new();setting=NM.SettingConnection.new()
  for k,v in [('id','TEST-session-own'),('uuid','e3140000-0000-4000-8000-000000000023'),('type','802-3-ethernet'),('interface-name','cachy-absent0'),('autoconnect',False)]:setting.set_property(k,v)
  assert setting.add_permission('user','builder',None);connection.add_setting(setting);connection.add_setting(NM.SettingWired.new())
  for cls in [NM.SettingIP4Config,NM.SettingIP6Config]:s=cls.new();s.set_property('method','disabled');connection.add_setting(s)
  args=GLib.Variant.new_tuple(connection.to_dbus(NM.ConnectionSerializationFlags.ALL),GLib.Variant('u',int(NM.SettingsAddConnection2Flags.TO_DISK)),GLib.Variant('a{sv}',{}))
  path=call('org.freedesktop.NetworkManager','/org/freedesktop/NetworkManager/Settings','org.freedesktop.NetworkManager.Settings','AddConnection2',args,'(oa{sv})')[0];report['own_create']={'success':True,'path':path}
  setting.set_property('id','TEST-session-own-edited');args=GLib.Variant.new_tuple(connection.to_dbus(NM.ConnectionSerializationFlags.ALL),GLib.Variant('u',int(NM.SettingsUpdate2Flags.TO_DISK)),GLib.Variant('a{sv}',{}));call('org.freedesktop.NetworkManager',path,'org.freedesktop.NetworkManager.Settings.Connection','Update2',args,'(a{sv})');report['own_edit']={'success':True}
  (H/'PERSISTENCE_READY').touch();report['persistence']=wait('persisted');assert report['persistence']['passed']
  denials=[]
  for name in ['foreign','system']:
   row={'name':name+'-delete'}
   try:call('org.freedesktop.NetworkManager',ready['paths'][name],'org.freedesktop.NetworkManager.Settings.Connection','Delete',None,'()');row['success']=True
   except GLib.Error as e:row.update(success=False,error=str(e),remote_error=Gio.DBusError.get_remote_error(e))
   assert row['success']is False and row.get('remote_error')in {'org.freedesktop.NetworkManager.Settings.PermissionDenied','org.freedesktop.NetworkManager.Settings.InvalidConnection','org.freedesktop.DBus.Error.AccessDenied'},row
   denials.append(row)
  report['denials']=denials;(H/'DENIALS_DONE').touch();report['denied_state']=wait('denials');assert report['denied_state']['passed']
  call('org.freedesktop.NetworkManager',path,'org.freedesktop.NetworkManager.Settings.Connection','Delete',None,'()');report['own_cleanup']={'success':True};(H/'SESSION_DONE').touch();report['root_observer']=wait('final');assert report['root_observer']['status']=='PASS_X86_ROOT_OBSERVATION_ONLY'
  report['status']='PASS_X86_REAL_SEAT_NM_PROFILE_LIFECYCLE_ONLY'
 except BaseException as e:report['failure']={'category':type(e).__name__,'message':str(e)[:2048]}
 temporary=H/'NM_SEAT_REPORT.tmp';temporary.write_text(json.dumps(report,sort_keys=True,indent=2)+'\n');temporary.replace(H/'NM_SEAT_REPORT.json')
 return 0 if report['status'].startswith('PASS_')else 1
if __name__=='__main__':raise SystemExit(main())

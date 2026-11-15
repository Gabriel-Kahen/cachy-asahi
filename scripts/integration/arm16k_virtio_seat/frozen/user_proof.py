#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Ordinary real VT login proof; no authorization policy/session mutation."""
import ctypes,grp,hashlib,json,os,pwd,subprocess,sys,time
from pathlib import Path
H=Path('/home/builder');R=Path('/run/tcg-seat');nonce=Path('/etc/tcg-reference-nonce').read_text().strip()
def main():
 report={'schema_version':1,'status':'HOLD','scope':'generic x86 real VT/PAM/seat/Polkit reference only','ARM_M2_release':'NOT RUN'}
 try:
  assert __debug__ and os.geteuid()==os.getegid()==1000 and pwd.getpwuid(1000).pw_name=='builder'
  assert not Path('/.dockerenv').exists()and Path('/proc/1/comm').read_text().strip()=='systemd'
  assert 'tcg_reference_nonce='+nonce in Path('/proc/cmdline').read_text()
  assert os.ttyname(0)=='/dev/tty1'and Path('/sys/class/tty/tty0/active').read_text().strip()=='tty1'
  libc=ctypes.CDLL(None);libc.tcgetsid.argtypes=[ctypes.c_int];libc.tcgetsid.restype=ctypes.c_int;assert libc.tcgetsid(0)==os.getsid(0)
  assert not any(g.gr_name in {'root','wheel','sudo','admin','empower'}and(g.gr_gid in os.getgroups()or'builder'in g.gr_mem)for g in grp.getgrall())
  import gi
  from gi.repository import Gio,GLib
  for key in list(os.environ):
   if key.startswith(('DBUS_','G_BUS_')):del os.environ[key]
  os.environ['DBUS_SYSTEM_BUS_ADDRESS']='unix:path=/run/dbus/system_bus_socket';bus=Gio.bus_get_sync(Gio.BusType.SYSTEM,None)
  def call(dest,path,interface,method,args,out):return bus.call_sync(dest,path,interface,method,args,GLib.VariantType(out),Gio.DBusCallFlags.NONE,12000,None).unpack()
  credentials=call('org.freedesktop.DBus','/org/freedesktop/DBus','org.freedesktop.DBus','GetConnectionCredentials',GLib.Variant('(s)',(bus.get_unique_name(),)),'(a{sv})')[0];assert credentials['UnixUserID']==1000 and credentials['ProcessID']==os.getpid()
  session=call('org.freedesktop.login1','/org/freedesktop/login1','org.freedesktop.login1.Manager','GetSessionByPID',GLib.Variant('(u)',(os.getpid(),)),'(o)')[0]
  props=call('org.freedesktop.login1',session,'org.freedesktop.DBus.Properties','GetAll',GLib.Variant('(s)',('org.freedesktop.login1.Session',)),'(a{sv})')[0]
  for key,value in {'Name':'builder','Active':True,'Class':'user','Type':'tty','Remote':False,'Service':'login','TTY':'tty1'}.items():assert props[key]==value,(key,props[key])
  assert props['Seat'][0]=='seat0'and props['User'][0]==1000 and props['Id']==os.environ['XDG_SESSION_ID']
  sd=ctypes.CDLL('libsystemd.so.0');sd.sd_session_get_seat.argtypes=[ctypes.c_char_p,ctypes.POINTER(ctypes.c_void_p)];sd.sd_session_get_seat.restype=ctypes.c_int;seat=ctypes.c_void_p();rc=sd.sd_session_get_seat(props['Id'].encode(),ctypes.byref(seat));actual=ctypes.string_at(seat).decode()if rc>=0 else None
  if seat.value:libc.free.argtypes=[ctypes.c_void_p];libc.free(seat)
  assert rc==0 and actual=='seat0',(rc,actual)
  # Existing original NM action is used as a stock installed Polkit reference;
  # no NM daemon or connection modification is needed by this generic test.
  subject=('system-bus-name',{'name':GLib.Variant('s',bus.get_unique_name())})
  auth=call('org.freedesktop.PolicyKit1','/org/freedesktop/PolicyKit1/Authority','org.freedesktop.PolicyKit1.Authority','CheckAuthorization',GLib.Variant('((sa{sv})sa{ss}us)',(subject,'org.freedesktop.NetworkManager.settings.modify.own',{},0,'')),'((bba{ss}))')[0]
  assert auth[0]is True and auth[1]is False,auth
  report.update(status='PASS_X86_REAL_SEAT_USER_PROOF_ONLY',nonce=nonce,uid=1000,gid=1000,groups=os.getgroups(),pid=os.getpid(),process_session=os.getsid(0),tty='/dev/tty1',foreground_VT='tty1',bus_unique_name=bus.get_unique_name(),bus_credentials=credentials,logind={k:props[k]for k in ['Id','Name','User','Active','Class','Type','Remote','Service','TTY','Seat','Leader']},sd_session_get_seat={'return':rc,'seat':actual},original_policy_sha256=hashlib.sha256(Path('/usr/share/polkit-1/actions/org.freedesktop.NetworkManager.policy').read_bytes()).hexdigest(),loaded_action=subprocess.check_output(['pkaction','--action-id','org.freedesktop.NetworkManager.settings.modify.own','--verbose'],timeout=10).decode(),authorization={'action':'org.freedesktop.NetworkManager.settings.modify.own','allow_user_interaction':False,'result':auth})
 except BaseException as e:report['failure']={'category':type(e).__name__,'message':str(e)[:2048]}
 temporary=H/'seat-report.tmp';temporary.write_text(json.dumps(report,sort_keys=True,indent=2)+'\n');temporary.replace(H/'SEAT_REPORT.json')
 until=time.monotonic()+30
 while time.monotonic()<until:
  if(R/'REPORT_VERIFIED').exists():break
  time.sleep(.1)
 return 0 if report['status'].startswith('PASS_')else 1
if __name__=='__main__':raise SystemExit(main())

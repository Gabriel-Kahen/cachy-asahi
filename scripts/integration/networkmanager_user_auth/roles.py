#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Only fixed Polkit UID102 owner, UID1000 probes and root DATA snapshots."""
import argparse,grp,hashlib,importlib.util,json,os,pwd,resource,signal,stat,subprocess,time,traceback
from pathlib import Path
I=Path('/opt/nm-private-bus')


def module(name,file):
 s=importlib.util.spec_from_file_location(name,I/file);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m


def main():
 p=argparse.ArgumentParser();p.add_argument('role',choices=['polkit','identity','modify-system','modify-restricted','create-own','read-restricted','snapshot','authority']);a=p.parse_args()
 if not(__debug__ and os.environ.get('CACHY_ASAHI_USER_AUTH_TEST')=='1'and Path('/.dockerenv').is_file()):p.error('owned container only')
 O=module('auth_role_owned','owned_process.py');G=module('auth_role_previous','previous_guest.py');F=module('auth_role_fixture','fixture.py');env=G.clean_env(os.environ)
 resource.setrlimit(resource.RLIMIT_CORE,(0,0))
 def call(argv):
  O.prepare();c=subprocess.Popen(argv,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
  r=O.supervise(c,cap=8,retirement=1,grace=.2,max_output=1024**2);out=r.pop('output').decode(errors='replace');assert r['reaped']and not r['timeout']and r['error']is None,r
  return {'argv':argv,'result':r,'output':out}
 caps=dict(l.split(':',1)for l in Path('/proc/self/status').read_text().splitlines()if ':'in l)
 assert all(int(caps[k].strip(),16)==0 for k in ['CapEff','CapPrm','CapBnd','CapInh','CapAmb'])and caps['NoNewPrivs'].strip()=='1'
 if a.role=='snapshot':
  assert os.geteuid()==0
  inventory=call(['pacman','-Q']);assert inventory['result']['passed']
  files={}
  for pth in sorted(Path('/etc/NetworkManager').rglob('*')):
   if pth.is_file()and not pth.is_symlink():
    s=pth.stat();files[str(pth)]={'sha256':hashlib.sha256(pth.read_bytes()).hexdigest(),'mode':stat.S_IMODE(s.st_mode),'uid':s.st_uid,'gid':s.st_gid}
  policies={str(pth):hashlib.sha256(pth.read_bytes()).hexdigest()for directory in ['/usr/share/polkit-1/rules.d','/etc/polkit-1/rules.d','/usr/share/dbus-1/system.d','/usr/share/polkit-1/actions']for pth in Path(directory).glob('*')if pth.is_file()}
  print(json.dumps({'files':files,'inventory':inventory['output'],'policy_pins':policies}));return 0
 if a.role=='polkit':
  assert os.geteuid()==os.getegid()==102 and pwd.getpwuid(102).pw_name=='polkitd'
  env.update(HOME='/polkit',XDG_CACHE_HOME='/polkit/cache',XDG_CONFIG_HOME='/polkit/config',XDG_DATA_HOME='/polkit/data',XDG_RUNTIME_DIR='/polkit/runtime')
  Path('/polkit/runtime').mkdir(mode=0o700)
  f=Path('/polkit/polkit.log').open('wb');O.prepare();child=subprocess.Popen(['/usr/lib/polkit-1/polkitd','--log-level=debug'],env=env,stdin=subprocess.DEVNULL,stdout=f,stderr=subprocess.STDOUT,start_new_session=True)
  report={'uid':os.geteuid(),'gid':os.getegid(),'child_pid':child.pid,'capabilities':'ALL zero'};Path('/polkit/STARTED').write_text(json.dumps(report))
  until=time.monotonic()+120
  while not Path('/run/auth-control/STOP_POLKIT').exists()and time.monotonic()<until:
   if os.waitid(os.P_PID,child.pid,os.WEXITED|os.WNOWAIT|os.WNOHANG)is not None:break
   time.sleep(.1)
  row=os.waitid(os.P_PID,child.pid,os.WEXITED|os.WNOWAIT|os.WNOHANG)
  if row is None:os.kill(child.pid,signal.SIGTERM)
  result=O.supervise(child,cap=8,retirement=2,grace=.2);result.pop('output');f.close();report['retirement']=result
  Path('/polkit/report.json').write_text(json.dumps(report,indent=2)+'\n');Path('/polkit/DONE').touch();return 0 if result['passed']else 1
 import gi
 from gi.repository import Gio,GLib
 if a.role=='authority':assert os.geteuid()==0
 else:
  assert os.geteuid()==os.getegid()==1000 and pwd.getpwuid(1000).pw_name=='builder'
  assert not {'wheel','empower'}&{grp.getgrgid(x).gr_name for x in os.getgroups()}
  env.update(HOME='/home/UID1000',XDG_CONFIG_HOME='/home/UID1000/config',XDG_CACHE_HOME='/home/UID1000/cache',XDG_DATA_HOME='/home/UID1000/data',XDG_RUNTIME_DIR='/home/UID1000/runtime')
 # Set only this process's owned socket before GLib opens any connection.
 os.environ.clear();os.environ.update(env)
 bus=Gio.bus_get_sync(Gio.BusType.SYSTEM,None)
 def dbus(method,args,out):return bus.call_sync('org.freedesktop.DBus','/org/freedesktop/DBus','org.freedesktop.DBus',method,args,GLib.VariantType(out),Gio.DBusCallFlags.NONE,3000,None).unpack()
 identity=dbus('GetConnectionCredentials',GLib.Variant('(s)',(bus.get_unique_name(),)),'(a{sv})')[0]
 assert identity['UnixUserID']==os.geteuid()and identity['ProcessID']==os.getpid(),identity
 owners={}
 for name in ['org.freedesktop.NetworkManager','org.freedesktop.PolicyKit1']:
  unique=dbus('GetNameOwner',GLib.Variant('(s)',(name,)),'(s)')[0];owners[name]=dbus('GetConnectionCredentials',GLib.Variant('(s)',(unique,)),'(a{sv})')[0]
 assert owners['org.freedesktop.NetworkManager']['UnixUserID']==0 and owners['org.freedesktop.PolicyKit1']['UnixUserID']==102
 result={'uid':os.geteuid(),'gid':os.getegid(),'groups':os.getgroups(),'bus_identity':identity,'owners':owners,'role':a.role}
 if a.role in ['identity','authority']:
  result['bus_id']=dbus('GetId',None,'(s)')[0]
  if a.role=='identity':
   checks={}
   for action in ['org.freedesktop.NetworkManager.settings.modify.own','org.freedesktop.NetworkManager.settings.modify.system']:
    args=GLib.Variant('((sa{sv})sa{ss}us)',(('system-bus-name',{'name':GLib.Variant('s',bus.get_unique_name())}),action,{},0,''))
    checks[action]=bus.call_sync('org.freedesktop.PolicyKit1','/org/freedesktop/PolicyKit1/Authority','org.freedesktop.PolicyKit1.Authority','CheckAuthorization',args,GLib.VariantType('((bba{ss}))'),Gio.DBusCallFlags.NONE,5000,None).unpack()[0]
   result['genuine_polkit_checks_no_interaction']=checks
  print(json.dumps(result));return 0
 commands={
 'modify-system':['nmcli','--wait','5','connection','modify','uuid',F.SYSTEM,'connection.id','TEST-UNEXPECTED-system-edit'],
 'modify-restricted':['nmcli','--wait','5','connection','modify','uuid',F.RESTRICTED,'connection.id','TEST-user-edit'],
 'read-restricted':['nmcli','--wait','5','-g','connection.id,connection.permissions,connection.autoconnect','connection','show','uuid',F.RESTRICTED],
 'create-own':['nmcli','--wait','5','connection','add','type','ethernet','ifname','cachy-test0','con-name','TEST-user-created','connection.uuid',F.CREATED,'connection.permissions','user:builder','connection.autoconnect','no','ipv4.method','disabled','ipv6.method','disabled'],
 }
 result['command']=call(commands[a.role]);print(json.dumps(result));return 0


if __name__=='__main__':raise SystemExit(main())

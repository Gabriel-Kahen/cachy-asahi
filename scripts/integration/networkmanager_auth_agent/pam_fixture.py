#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fixed root NM/private-bus fixture, preserving image authorization policy."""
import xml.etree.ElementTree as E
import hashlib,importlib.util,json,os,resource,signal,socket,stat,subprocess,time,traceback
from pathlib import Path
INPUT=Path('/opt/nm-private-bus');OUT=Path('/out')
SYSTEM='e3140000-0000-4000-8000-000000000011'
RESTRICTED='e3140000-0000-4000-8000-000000000012'
CREATED='e3140000-0000-4000-8000-000000000013'
FOREIGN='e3140000-0000-4000-8000-000000000014'


def module(name,file):
 s=importlib.util.spec_from_file_location(name,INPUT/file);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m


def main():
 if not(__debug__ and os.geteuid()==0 and os.environ.get('CACHY_ASAHI_USER_AUTH_TEST')=='1'and Path('/.dockerenv').exists()):raise RuntimeError('owned container only')
 O=module('auth_owned','owned_process.py');G=module('auth_previous_bus','previous_guest.py');R=module('auth_repository','repository.py')
 resource.setrlimit(resource.RLIMIT_CORE,(0,0));resource.setrlimit(resource.RLIMIT_FSIZE,(2*1024**2,2*1024**2))
 report={'status':'HOLD','commands':[],'retirement':[]};children={};files=[];env=G.clean_env(os.environ)
 def call(argv):
  O.prepare();c=subprocess.Popen(argv,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
  r=O.supervise(c,cap=8,retirement=1,grace=.2);data=r.pop('output').decode(errors='replace');report['commands'].append({'argv':argv,'result':r,'output':data});return r['exit'],data
 def start(role,argv):
  f=(OUT/(role+'.log')).open('wb');files.append(f);O.prepare();children[role]=subprocess.Popen(argv,env=env,stdin=subprocess.DEVNULL,stdout=f,stderr=subprocess.STDOUT,start_new_session=True)
 def retire(role):
  c=children.pop(role);row=os.waitid(os.P_PID,c.pid,os.WEXITED|os.WNOWAIT|os.WNOHANG)
  if row is None:os.kill(c.pid,signal.SIGTERM)
  r=O.supervise(c,cap=8,retirement=2,grace=.2);r.pop('output');report['retirement'].append({'role':role,'result':r});assert r['passed']or(role=='pam-helper'and r['exit']==-signal.SIGTERM and r['reaped']and r['group_census']=='EMPTY_TWICE'and not r['signals']and r['error']is None),r
 try:
  caps=dict(l.split(':',1)for l in Path('/proc/self/status').read_text().splitlines()if ':'in l)
  assert all(int(caps[k].strip(),16)==0 for k in R.CAP_FIELDS)and caps['NoNewPrivs'].strip()=='1'
  mounts=R.mounts(Path('/proc/self/mountinfo').read_text());assert 'ro'in mounts['/']['options']
  writable=G.WRITABLE|{'/polkit','/home/UID1000'}
  allowed={'/'}|set(R.STANDARD_MOUNTS)|R.RUNTIME_FILES|set(R.STANDARD_DEVICES)|{'/usr/bin/docker-init'}|writable
  assert set(mounts)<=allowed
  for p in writable:assert mounts[p]['fs']=='tmpfs'and {'rw','nodev','nosuid','noexec'}<=mounts[p]['options']
  for p in ['/sys','/sys/fs/cgroup','/proc/sys']:assert 'ro'in mounts[p]['options']
  assert {x[1]for x in socket.if_nameindex()}=={'lo'}
  assert not any(Path(p).exists()for p in ['/run/dbus/system_bus_socket','/run/docker.sock','/dev/net','/dev/dri','/dev/snd'])
  for p in ['/run/dbus','/run/NetworkManager','/run/auth-control','/run/user-TEST','/etc/NetworkManager/conf.d','/etc/NetworkManager/system-connections']:Path(p).mkdir(parents=True,exist_ok=True)
  Path('/run/dbus').chmod(0o755);Path('/run/auth-control').chmod(0o755)
  Path('/etc/NetworkManager/NetworkManager.conf').write_bytes(G.CONFIG.replace(b'level=INFO',b'level=TRACE\ndomains=AUTH,SETTINGS'))
  Path('/etc/NetworkManager/conf.d/70-TEST-user.conf').write_bytes(G.USER)
  standard=Path('/usr/share/dbus-1/system.conf').read_bytes()
  transport=''.join(E.tostring(x,encoding='unicode')for x in E.fromstring(standard).findall('policy'))
  report['bus_transport_source_sha256']=hashlib.sha256(standard).hexdigest()
  xml='<busconfig><type>system</type><listen>'+G.BUS+'</listen><auth>EXTERNAL</auth>'+transport+'<include>/usr/share/dbus-1/system.d/org.freedesktop.NetworkManager.conf</include><include>/usr/share/dbus-1/system.d/org.freedesktop.PolicyKit1.conf</include></busconfig>\n'
  Path('/run/dbus/TEST-auth.conf').write_text(xml)
  start('bus',['/usr/bin/dbus-daemon','--nofork','--nopidfile','--config-file=/run/dbus/TEST-auth.conf'])
  until=time.monotonic()+5
  while not Path('/run/dbus/system_bus_socket').exists()and time.monotonic()<until:time.sleep(.02)
  Path('/run/polkit').mkdir(mode=0o755,exist_ok=True)
  start('pam-helper',['/usr/bin/systemd-socket-activate','--accept','--inetd','--listen=/run/polkit/agent-helper.socket','--setenv=DBUS_SYSTEM_BUS_ADDRESS='+G.BUS,'/usr/lib/polkit-1/polkit-agent-helper-1','--socket-activated'])
  until=time.monotonic()+5
  while not Path('/run/polkit/agent-helper.socket').exists()and time.monotonic()<until:time.sleep(.02)
  Path('/run/polkit/agent-helper.socket').chmod(0o666)
  start('nm',['/usr/bin/NetworkManager','--debug','--no-daemon','--config','/etc/NetworkManager/NetworkManager.conf','--pid-file','/run/NetworkManager/TEST.pid'])
  until=time.monotonic()+12
  while time.monotonic()<until:
   code,text=call(['nmcli','-g','RUNNING','general'])
   if code==0 and text.strip()=='running':break
   time.sleep(.1)
  else:raise RuntimeError('private daemon readiness')
  for uuid,name,permission in [(SYSTEM,'TEST-root-system',''),(RESTRICTED,'TEST-root-seeded-user-restricted','user:builder'),(FOREIGN,'TEST-root-seeded-foreign','user:nobody')]:
   argv=['nmcli','connection','add','type','ethernet','ifname','cachy-test0','con-name',name,'connection.uuid',uuid,'connection.autoconnect','no','ipv4.method','disabled','ipv6.method','disabled']
   if permission:argv+=['connection.permissions',permission]
   code,text=call(argv);assert code==0,text
  report['status']='READY_ROOT_FIXTURE';(OUT/'fixture-ready.json').write_text(json.dumps(report,indent=2)+'\n');(OUT/'READY').touch()
  until=time.monotonic()+150
  while not Path('/run/auth-control/STOP_ROOT').exists()and time.monotonic()<until:time.sleep(.1)
  assert Path('/run/auth-control/STOP_ROOT').exists(),'root fixture deadline'
  # Explicit fixture cleanup only; a denied ordinary client never gains root cleanup credit.
  for uuid in [SYSTEM,RESTRICTED,CREATED,FOREIGN]:
   code,text=call(['nmcli','-g','UUID','connection','show'])
   if uuid in text:
    code,text=call(['nmcli','connection','delete','uuid',uuid]);assert code==0,text
  assert not list(Path('/etc/NetworkManager/system-connections').glob('*.nmconnection'))
  retire('nm');retire('pam-helper');retire('bus');assert not Path('/run/dbus/system_bus_socket').exists()
  report.update(status='PASS_ROOT_FIXTURE_CLEANUP_ONLY',owned_profiles_removed=True,owned_socket_removed=True)
 except BaseException as e:report['failure']={'category':type(e).__name__,'message':str(e)[:2048],'traceback':traceback.format_exc(limit=6)[-4096:]}
 finally:
  for role in reversed(list(children)):
   try:retire(role)
   except BaseException as e:report.setdefault('cleanup_failure',[]).append(str(e)[:2048]);report['status']='HOLD_CLEANUP'
  for f in files:f.close()
  (OUT/'report.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n');(OUT/'DONE').touch();print(json.dumps({'status':report['status'],'failure':report.get('failure')}),flush=True)
  until=time.monotonic()+45
  while not Path('/run/auth-control/ALLOW_EXIT').exists()and time.monotonic()<until:time.sleep(.1)
 return 0 if report['status']=='PASS_ROOT_FIXTURE_CLEANUP_ONLY'else 1


if __name__=='__main__':raise SystemExit(main())

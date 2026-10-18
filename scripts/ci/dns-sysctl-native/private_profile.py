#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real stored-profile integration on a container-private system bus; never activation."""
import hashlib,json,os,resource,shutil,signal,stat,subprocess,time
from pathlib import Path
from profile_actor import process_frame,namespace_frame,worker_guard,zero_frame

UUID='5f7d4f36-a20e-4bd8-9f15-4e6e68731410'
BUS='unix:path=/run/dbus/system_bus_socket'
PROGRAM=Path('/usr/bin/cachy-asahi-dns')
LIMIT=1024**2

def need(ok,message):
 if not ok:raise ValueError(message)

def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def save(path,value):path.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')

def command(argv,*,expected=0):
 process=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,env=dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',DBUS_SYSTEM_BUS_ADDRESS=BUS,DBUS_SESSION_BUS_ADDRESS='unix:path=/nonexistent'))
 try:
  stdout,stderr=process.communicate(timeout=15)
  need(len(stdout)+len(stderr)<=65536,'private profile command output cap')
  need(process.returncode==expected,'private profile command failed: '+str(argv[0])+': '+stderr.decode(errors='replace')[-1024:])
  return stdout.decode()
 finally:
  if process.poll()is None:os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=2)
  process.stdout.close();process.stderr.close()

def nm(*args):return command(['/usr/bin/nmcli','--wait','10','--colors','no',*args])

def snapshot(path):
 result={}
 if not path.exists():return result
 for item in(path,*sorted(path.rglob('*'))):
  need(len(result)<128,'bounded private NM state tree')
  info=item.lstat();need(stat.S_ISDIR(info.st_mode)or stat.S_ISREG(info.st_mode)or stat.S_ISSOCK(info.st_mode),'ordinary daemon state tree')
  need(not stat.S_ISREG(info.st_mode)or info.st_size<=LIMIT,'daemon state file cap')
  result[str(item)]=dict(kind=stat.S_IFMT(info.st_mode),mode=stat.S_IMODE(info.st_mode),uid=info.st_uid,gid=info.st_gid,dev=info.st_dev,ino=info.st_ino,sha256=digest(item)if stat.S_ISREG(info.st_mode)else None)
 return result

def remove_new(path,before):
 after=snapshot(path)
 for name,row in before.items():need(after.get(name)==row,'preexisting NM state changed: '+name)
 for name in sorted(set(after)-set(before),key=lambda n:len(Path(n).parts),reverse=True):
  item=Path(name);need(snapshot(path).get(name)==after[name],'daemon state changed during retirement')
  item.rmdir()if stat.S_ISDIR(after[name]['kind'])else item.unlink()
 need(snapshot(path)==before,'private NM state retirement differs')

def run(out,*,nonce=None):
 binding=worker_guard(nonce)
 status=dict(line.split(':',1)for line in Path('/proc/self/status').read_text().splitlines()if':'in line)
 need(int(status['CapEff'].strip(),16)==0 and set(p.name for p in Path('/sys/class/net').iterdir())=={'lo'},'zero-cap/network-none worker required')
 need(os.environ.get('DBUS_SYSTEM_BUS_ADDRESS')==BUS and not out.exists()and out.is_absolute()and out.parent.is_dir(),'fixed private bus/fresh owned output required')
 socket=Path('/run/dbus/system_bus_socket');need(not os.path.lexists(socket),'preexisting system socket refused')
 roots=[Path('/run/dbus'),Path('/run/NetworkManager'),Path('/var/lib/NetworkManager')];before={p:snapshot(p)for p in roots}
 resolver=Path('/etc/resolv.conf');resolver_pin=resolver.read_bytes();out.mkdir(mode=0o700)
 work=Path('/tmp/dns-private-profile');work.mkdir(mode=0o700)
 for name in('conf','profiles','state','logs'):(work/name).mkdir(mode=0o700)
 Path('/run/dbus').mkdir(parents=True,exist_ok=True)
 dbus_config=work/'dbus.conf';dbus_config.write_text('<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN" "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">\n<busconfig><type>system</type><listen>'+BUS+'</listen><auth>EXTERNAL</auth><policy user="root"><allow own="*"/><allow send_destination="*"/><allow receive_sender="*"/></policy></busconfig>\n')
 config=work/'NetworkManager.conf';config.write_text('[main]\nplugins=keyfile\nauth-polkit=false\ndns=none\nrc-manager=unmanaged\nno-auto-default=*\n[connectivity]\nenabled=false\n[keyfile]\npath='+str(work/'profiles')+'\nunmanaged-devices=*\n[device-all]\nmatch-device=*\nmanaged=0\n')
 children=[];logs=[];events=[];failure=None;retirement=[]
 result=dict(worker_binding=binding,status='FAIL_PRIVATE_PROFILE_INTEGRATION',architecture=os.uname().machine,source_program_sha256=digest(PROGRAM),fixture_uuid=UUID,PolicyKit='NOT_TESTED_PRIVATE_AUTH_POLKIT_FALSE',live_DNS='NOT_RUN',interface_activation='NOT_RUN',host_mutation='NOT_RUN',cap_eff=status['CapEff'].strip(),interfaces=sorted(p.name for p in Path('/sys/class/net').iterdir()),events=events)
 def bounded_log():resource.setrlimit(resource.RLIMIT_FSIZE,(LIMIT,LIMIT))
 def start(role,argv):
  log=(out/(role+'.log')).open('xb');logs.append(log);process=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,start_new_session=True,preexec_fn=bounded_log,env=dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',DBUS_SYSTEM_BUS_ADDRESS=BUS,DBUS_SESSION_BUS_ADDRESS='unix:path=/nonexistent'))
  children.append((role,process));deadline=time.monotonic()+2
  while True:
   try:
    if os.readlink('/proc/'+str(process.pid)+'/exe')==argv[0]:break
   except FileNotFoundError:pass
   need(process.poll()is None and time.monotonic()<deadline,'exact private daemon exec absent');time.sleep(.01)
  observed=process_frame(process.pid);namespace=namespace_frame(process.pid)
  need(zero_frame(observed)and observed['PPid']==str(os.getpid())and namespace==binding['namespaces'],'NM/dbus exec privilege or namespace changed')
  events.append(dict(kind='daemon-start',role=role,pid=process.pid,pgid=process.pid,argv=argv,observed_after_exec=observed,namespaces=namespace));return process
 previous=signal.signal(signal.SIGALRM,lambda *_:(_ for _ in()).throw(TimeoutError('private profile overall90s deadline')));signal.setitimer(signal.ITIMER_REAL,90)
 try:
  bus=start('dbus',['/usr/bin/dbus-daemon','--nofork','--nopidfile','--config-file='+str(dbus_config)])
  deadline=time.monotonic()+5
  while not socket.exists():
   need(bus.poll()is None and time.monotonic()<deadline,'private DBus startup failed');time.sleep(.05)
  daemon=start('NetworkManager',['/usr/bin/NetworkManager','--no-daemon','--debug','--config='+str(config),'--config-dir='+str(work/'conf'),'--system-config-dir='+str(work/'conf'),'--intern-config='+str(work/'state/intern.conf'),'--state-file='+str(work/'state/NetworkManager.state'),'--pid-file='+str(work/'state/NetworkManager.pid')])
  deadline=time.monotonic()+8
  while True:
   need(daemon.poll()is None,'NetworkManager startup failed under unchanged caps')
   try:
    nm('--get-values','UUID','connection','show');version=command(['/usr/bin/NetworkManager','--version']);break
   except ValueError:
    need(time.monotonic()<deadline,'private NM startup deadline');time.sleep(.05)
  need(nm('--get-values','UUID','connection','show').strip()=='','private NM must begin with no profiles')
  need(nm('--get-values','UUID','connection','show','--active').strip()=='','no active connection allowed')
  nm('connection','add','type','ethernet','ifname','dns-fixture0','con-name','owned-dns-fixture','connection.uuid',UUID,'connection.autoconnect','no','ipv4.method','manual','ipv4.addresses','192.0.2.2/24','ipv4.dns','192.0.2.53','ipv4.ignore-auto-dns','no','ipv6.method','manual','ipv6.addresses','2001:db8::2/64','ipv6.dns','2001:db8::53','ipv6.ignore-auto-dns','no')
  fields=['ipv4.dns','ipv4.ignore-auto-dns','ipv6.dns','ipv6.ignore-auto-dns'];query=['--escape','no','--get-values',','.join(['connection.uuid',*fields]),'connection','show','uuid',UUID]
  before_fields=nm(*query);held=nm('--get-values','connection.uuid,connection.autoconnect,ipv4.method,ipv4.addresses,ipv6.method,ipv6.addresses','connection','show','uuid',UUID)
  for label,v4,v6 in [('nonempty','1.1.1.1,9.9.9.9','2001:4860:4860::8888'),('empty','','')]:
   state=work/('receipt-'+label)
   planned=json.loads(command([str(PROGRAM),'--json','preview','--uuid',UUID,'--state-dir',str(state),'--ipv4-dns',v4,'--ipv6-dns',v6,'--ipv4-ignore-auto-dns','yes','--ipv6-ignore-auto-dns','yes']))
   need(planned['status']=='PREVIEW_ONLY'and nm(*query)==before_fields,'real profile preview must not modify')
   applied=json.loads(command([str(PROGRAM),'--json','apply',str(state),'--receipt-sha256',planned['receipt_sha256'],'--confirm','APPLY_CONNECTION_DNS']))
   current=json.loads(command([str(PROGRAM),'--json','status',str(state)]));need(applied['phase']=='APPLIED'and current['matches_after']is True,'real stored profile readback absent')
   undone=json.loads(command([str(PROGRAM),'--json','undo',str(state),'--receipt-sha256',applied['receipt_sha256'],'--confirm','RESTORE_CONNECTION_DNS']))
   need(undone['phase']=='UNDONE'and nm(*query)==before_fields,'exact real prior fields not restored')
   events.append(dict(kind='stored-profile-roundtrip',case=label,status='PASS',receipt_sha256=undone['receipt_sha256'],before={field:row['before']for field,row in planned['changes'].items()},applied=current['current'],restored_raw_sha256=hashlib.sha256(nm(*query).encode()).hexdigest()))
  state=work/'receipt-conflict';plan=json.loads(command([str(PROGRAM),'--json','preview','--uuid',UUID,'--state-dir',str(state),'--ipv4-dns','1.1.1.1']))
  applied=json.loads(command([str(PROGRAM),'--json','apply',str(state),'--receipt-sha256',plan['receipt_sha256'],'--confirm','APPLY_CONNECTION_DNS']))
  nm('connection','modify','uuid',UUID,'ipv4.dns','8.8.8.8');foreign=nm(*query)
  command([str(PROGRAM),'--json','undo',str(state),'--receipt-sha256',applied['receipt_sha256'],'--confirm','RESTORE_CONNECTION_DNS'],expected=1)
  need(nm(*query)==foreign,'foreign edit was overwritten');events.append(dict(kind='foreign-edit-refused',status='PASS',preserved_raw_sha256=hashlib.sha256(foreign.encode()).hexdigest()))
  need(nm('--get-values','connection.uuid,connection.autoconnect,ipv4.method,ipv4.addresses,ipv6.method,ipv6.addresses','connection','show','uuid',UUID)==held,'unowned profile fields changed')
  need(nm('--get-values','UUID','connection','show','--active').strip()=='','profile activated unexpectedly')
  nm('connection','delete','uuid',UUID);need(nm('--get-values','UUID','connection','show').strip()=='','fixture profile retirement failed')
  result.update(status='PASS_REAL_PRIVATE_STORED_PROFILE_INTEGRATION',NetworkManager_version=version.strip(),stored_profiles_deleted=True)
 except BaseException as error:failure=error;result.update(error_type=type(error).__name__,error=str(error)[:2048])
 finally:
  signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,previous)
  for role,process in reversed(children):
   initial=process.poll()
   if initial is None:
    os.killpg(process.pid,signal.SIGTERM)
    try:process.wait(timeout=3)
    except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=2)
   absent=False
   try:os.killpg(process.pid,0)
   except ProcessLookupError:absent=True
   retirement.append(dict(role=role,pid=process.pid,returncode=process.returncode,group_absent=absent))
  for log in logs:log.close()
  try:
   need(all(row['group_absent']for row in retirement),'daemon child group remains')
   try:
    pid,_=os.waitpid(-1,os.WNOHANG);need(pid==0,'unexpected adopted child receipt; child state unknown')
    raise ValueError('unreaped child still exists')
   except ChildProcessError:pass
   for path in reversed(roots):remove_new(path,before[path])
   need(resolver.read_bytes()==resolver_pin,'container resolver bytes changed')
   need(work.is_dir()and not work.is_symlink()and work.stat().st_uid==0 and stat.S_IMODE(work.stat().st_mode)==0o700,'owned work retirement identity')
   work_files=snapshot(work);shutil.rmtree(work);need(not work.exists(),'owned work remains')
   result['retirement']=dict(status='PASS_DAEMONS_REAPED_OWN_STATE_REMOVED',groups=retirement,resolver_preserved=True,private_work_removed=True,work_nodes=len(work_files))
  except BaseException as error:result.update(status='FAIL_PRIVATE_PROFILE_INTEGRATION',retirement_error=str(error)[:1024]);failure=error
  save(out/'receipt.json',result)
 return int(failure is not None)

if __name__=='__main__':raise SystemExit(run(Path('/out/private-profile')))

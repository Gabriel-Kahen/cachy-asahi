# SPDX-License-Identifier: MIT
"""Original-six-cap read supervisor with a bound zero-cap private NM worker."""
import hashlib,json,os,re,select,shutil,signal,stat,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))

def need(ok,message):
 if not ok:raise ValueError(message)

def network_state():
 root=Path('/sys/class/net');need({p.name for p in root.iterdir()}=={'lo'},'only private loopback allowed')
 paths=['/sys/class/net/lo/flags','/sys/class/net/lo/mtu','/proc/net/if_inet6','/proc/sys/net/ipv6/conf/lo/temp_valid_lft','/proc/sys/net/ipv6/conf/lo/temp_prefered_lft']
 result={name:Path(name).read_text()for name in paths}
 # Exclude only read-side kernel use/reference counters, not route identity/flags/metrics.
 result['ipv4_routes']=[row[:4]+row[6:]for row in(line.split()for line in Path('/proc/net/route').read_text().splitlines()[1:])]
 result['ipv6_routes']=[row[:6]+row[8:]for row in(line.split()for line in Path('/proc/net/ipv6_route').read_text().splitlines())]
 return result

def launch(C,source,out,image,products,docker,command,containers):
 inputs=out/'profile-inputs';inputs.mkdir();runner=inputs/'runner';runner.mkdir();accepted=runner/'accepted';accepted.mkdir()
 for target,path in [('profile_actor.py',C.HERE/'profile_actor.py'),('private_profile.py',C.HERE/'private_profile.py'),('installed.py',source/'scripts/ci/apps-cache-native/installed.py'),('accepted/lifecycle.py',source/'scripts/ci/welcome-native/lifecycle.py'),('accepted/root_upgrade.py',source/'scripts/ci/full-root-upgrade/root_upgrade.py')]:shutil.copyfile(path,runner/target)
 base=dict(line.split()for line in(out/'base-inventory.log').read_text().splitlines())
 (inputs/'base.json').write_text(json.dumps(base))
 product=products['cachy-asahi-dns2'];program=source/'packages/tools/cachy-asahi-dns2/cachy-asahi-dns';payload=product['payload']['usr/bin/cachy-asahi-dns']
 C.need(C.digest(program)==payload['sha256']and payload['mode']==0o755,'validated build-A/source program byte join required')
 (inputs/'control.json').write_text(json.dumps(dict(source_program_sha256=payload['sha256'],native_archive_sha256=product['sha256'],version=product['version'])))
 for path in(inputs,*inputs.rglob('*')):path.chmod(0o755 if path.is_dir()else 0o644)
 staged=inputs/'dns-command';shutil.copyfile(program,staged);staged.chmod(0o755);C.need(C.digest(staged)==payload['sha256'],'staged native-payload bytes differ')
 output=out/'private-profile-actor';output.mkdir(mode=0o700);output.chmod(0o703);actor='cachy-asahi-product-'+os.urandom(16).hex();containers.append(actor)
 argv=docker(image,actor,output,root=True);caps=['--cap-add='+c for c in('CHOWN','DAC_OVERRIDE','FOWNER','FSETID','SETUID','SETGID')]
 C.need([a for a in argv if a.startswith('--cap-add=')]==caps,'original ALPM root capset changed; no silent privilege adaptation')
 # The supervisor retains exactly the original ALPM capset; only its NM worker drops all E/P/I/A.
 command(argv+['--env=CACHY_ASAHI_DNS_PRIVATE_PROFILE=1','--env=DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/dbus/system_bus_socket','--mount',f'type=bind,src={inputs},dst=/inputs,readonly','--mount',f'type=bind,src={runner},dst=/runner,readonly','--mount',f'type=bind,src={staged},dst=/usr/bin/cachy-asahi-dns,readonly','--entrypoint=/usr/bin/python3',image,'-I','-B','/runner/profile_actor.py'],out/'private-profile.log',600)
 receipt=output/'receipt.json';C.need(receipt.is_file()and not receipt.is_symlink()and receipt.stat().st_size<=1024**2,'bounded private NM receipt required')
 value=json.loads(receipt.read_bytes())
 from rules import validate_profile
 validate_profile(value,payload['sha256']);return value

def export_results(directory,output):
 # The runner owns0703 /out; cap0 UID0 owns only newly created fixed0644 files.
 need(directory.is_dir()and not directory.is_symlink()and directory.stat().st_uid==0,'owned private result directory required')
 for name in ('receipt.json','NetworkManager.log','dbus.log'):
  path=directory/name;fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
  try:
   before=os.fstat(fd);need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and before.st_uid==0 and before.st_size<=1024**2,'bounded owned ordinary result required')
   with os.fdopen(os.dup(fd),'rb')as stream:raw=stream.read(1024**2+1)
   identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
   need(len(raw)==before.st_size and identity(before)==identity(os.fstat(fd))==identity(path.lstat()),'private result changed during export')
  finally:os.close(fd)
  target=output/name;fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  try:
   with os.fdopen(os.dup(fd),'wb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
   os.fchmod(fd,0o644);after=os.fstat(fd);need(after.st_uid==0 and after.st_nlink==1 and stat.S_IMODE(after.st_mode)==0o644,'owned readable handoff required')
  finally:os.close(fd)
 shutil.rmtree(directory);need(not directory.exists(),'private result work remains')

def process_frame(pid):
 fields=dict(line.split(':',1)for line in Path('/proc/'+str(pid)+'/status').read_text().splitlines()if':'in line)
 return {k:fields[k].strip()for k in('Pid','PPid','CapInh','CapPrm','CapEff','CapAmb','CapBnd','NoNewPrivs')}

def namespace_frame(pid):return {name:os.readlink('/proc/'+str(pid)+'/ns/'+name)for name in('pid','mnt','net','user')}

def zero_frame(frame):
 return all(int(frame[k],16)==0 for k in('CapInh','CapPrm','CapEff','CapAmb'))and int(frame['CapBnd'],16)==0xdb and frame['NoNewPrivs']=='1'

def worker_guard(nonce):
 need(os.getuid()==os.geteuid()==0 and os.getpid()>1 and os.getppid()==1 and Path('/.dockerenv').is_file()and os.environ.get('CACHY_ASAHI_DNS_PRIVATE_PROFILE')=='1','dedicated root worker of container PID1 required')
 need(type(nonce)is str and re.fullmatch('[0-9a-f]{32}',nonce)and nonce==os.environ.get('CACHY_ASAHI_DNS_PROFILE_NONCE'),'exact supervisor worker nonce required')
 frame=process_frame('self');need(zero_frame(frame),'zero E/P/I/A and NoNewPrivs1 required; bounding set remains original six')
 return dict(pid=os.getpid(),ppid=os.getppid(),nonce=nonce,frame=frame,namespaces=namespace_frame('self'))

def drop_capabilities():
 import ctypes
 libc=ctypes.CDLL(None,use_errno=True)
 class Header(ctypes.Structure):_fields_=[('version',ctypes.c_uint32),('pid',ctypes.c_int)]
 class Data(ctypes.Structure):_fields_=[('effective',ctypes.c_uint32),('permitted',ctypes.c_uint32),('inheritable',ctypes.c_uint32)]
 need(libc.prctl(38,1,0,0,0)==0,'worker NoNewPrivs set failed')
 need(libc.prctl(47,4,0,0,0)==0,'worker ambient clear failed')
 header=Header(0x20080522,0);data=(Data*2)()
 need(libc.capset(ctypes.byref(header),ctypes.byref(data))==0,'worker own capability reduction failed')
 need(zero_frame(process_frame('self')),'worker privilege reduction readback failed')

def worker(nonce,fd):
 import private_profile as F
 binding=worker_guard(nonce);raw=(json.dumps(binding,sort_keys=True)+'\n').encode();need(len(raw)<=4096 and os.write(fd,raw)==len(raw),'bounded atomic worker handshake required');os.close(fd)
 return F.run(Path('/tmp/private-profile-result'),nonce=nonce)

def supervise():
 frame=process_frame('self');namespace=namespace_frame('self')
 need(os.getuid()==os.geteuid()==0 and os.getpid()==1 and frame['Pid']=='1'and frame['PPid']=='0'and all(int(frame[k],16)==0xdb for k in('CapPrm','CapEff','CapBnd'))and all(int(frame[k],16)==0 for k in('CapInh','CapAmb'))and frame['NoNewPrivs']=='1','supervisor must have only original six ALPM capabilities and NoNewPrivs1')
 nonce=os.urandom(16).hex();read_fd,write_fd=os.pipe2(os.O_CLOEXEC);pid=os.fork();waited=False;binding=None;error=None;code=None
 if pid==0:
  try:
   os.close(read_fd);os.setsid();os.set_inheritable(write_fd,True);drop_capabilities()
   os.execve('/usr/bin/python3',['/usr/bin/python3','-I','-B','/runner/profile_actor.py','worker',nonce,str(write_fd)],dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',CACHY_ASAHI_DNS_PRIVATE_PROFILE='1',CACHY_ASAHI_DNS_PROFILE_NONCE=nonce,DBUS_SYSTEM_BUS_ADDRESS='unix:path=/run/dbus/system_bus_socket'))
  except BaseException:
   import traceback
   traceback.print_exc();os._exit(1)
 os.close(write_fd)
 try:
  need(select.select([read_fd],[],[],5)[0],'worker after-exec handshake absent');raw=os.read(read_fd,4097);need(0<len(raw)<=4096 and raw.endswith(b'\n'),'bounded worker handshake')
  binding=json.loads(raw);observed=process_frame(pid)
  need(binding['pid']==pid and binding['ppid']==1 and binding['nonce']==nonce and binding['frame']==observed and zero_frame(observed)and binding['namespaces']==namespace==namespace_frame(pid),'exact child PID/PPID/capability/namespace binding required')
  returned,status=os.waitpid(pid,0);waited=True;code=os.waitstatus_to_exitcode(status);need(returned==pid,'wrong direct child wait receipt')
 finally:
  os.close(read_fd)
  if not waited:
   try:os.killpg(pid,signal.SIGKILL)
   except ProcessLookupError:pass
   os.waitpid(pid,0)
 absent=False
 try:os.killpg(pid,0)
 except ProcessLookupError:absent=True
 need(absent and process_frame('self')==frame and namespace_frame('self')==namespace,'worker group remains or supervisor identity changed')
 try:os.waitpid(-1,os.WNOHANG)
 except ChildProcessError:pass
 else:raise ValueError('supervisor has unretired adopted child')
 return dict(route='ORIGINAL_SIX_CAP_SUPERVISOR_ZERO_CAP_NM_WORKER',supervisor=frame,namespaces=namespace,worker=binding,worker_exit=code,worker_group_absent=absent),code

def inside():
 import installed as I
 import private_profile as F
 L,driver=I.apis()
 L.need(os.getuid()==os.geteuid()==0 and os.getpid()==1 and os.uname().machine=='aarch64','dedicated native ARM PID1 required')
 base=json.loads(Path('/inputs/base.json').read_bytes());control=json.loads(Path('/inputs/control.json').read_bytes())
 L.need(len(base)==574 and L.inventory()==base and L.sha(F.PROGRAM)==control['source_program_sha256']and stat.S_IMODE(F.PROGRAM.stat().st_mode)==0o755 and control['version']=='0.1.0-2','exact574/native-build source program required')
 state=I.base_state(L,driver);before=I.preserve_base(L,state);network=network_state();directory=Path('/tmp/private-profile-result');supervision,result=supervise()
 receipt=directory/'receipt.json';value=json.loads(receipt.read_bytes());value['supervision']=supervision
 try:
  L.need(I.preserve_base(L,state)==before,'original574 payload/raw DB changed during real private NM integration')
  after=network_state();L.need(after==network,'private namespace loopback/routes/lifetimes changed')
  L.need(supervision['worker_exit']==0 and value.get('worker_binding')==supervision['worker'],'worker failed or standalone binding differs')
  value.update(supervision=supervision,base574_preserved=True,base_manifest_sha256=before,base_count=574,network_before=network,network_after=after,network_state_preserved=True,program_delivery='SOURCE_BYTES_EQUAL_VERIFIED_NATIVE_BUILD_A_PAYLOAD_READONLY_MOUNT',native_archive_sha256=control['native_archive_sha256'])
 except BaseException as error:value.update(status='FAIL_PRIVATE_PROFILE_INTEGRATION',preservation_error=str(error)[:1024]);result=1
 receipt.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n');export_results(directory,Path('/out'));return result

if __name__=='__main__':
 if len(sys.argv)==4 and sys.argv[1]=='worker':raise SystemExit(worker(sys.argv[2],int(sys.argv[3])))
 need(len(sys.argv)==1,'fixed supervisor/worker entry only');raise SystemExit(inside())

#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Root-bound image preparation or separate boot; no operation on import."""
import argparse,importlib.util,json,os,re,secrets,select,socket,stat,struct,sys,tempfile,time
from pathlib import Path
HERE=Path(__file__).resolve().parent

def module(n):
 s=importlib.util.spec_from_file_location('perl_controller_'+n,HERE/(n+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m


def attempt_marker(phase,output,prepared,authority_sha256,nonce):
 K=module('contracts');K.need(phase in('prepare','boot'),'exact marker phase')
 root=K.ordinary(prepared if phase=='boot'else output)
 name='perl5423-boot-attempt.json'if phase=='boot'else'perl5423-attempt.json'
 path=root/name
 with path.open('x')as stream:stream.write(K.canonical(dict(authority=authority_sha256,nonce=nonce)).decode())
 return path


def proc_identity(pid):
 K=module('contracts');K.need(type(pid)is int and pid>1,'positive selected process')
 def read(name,cap):
  fd=os.open('/proc/'+str(pid)+'/'+name,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
  try:body=os.read(fd,cap+1)
  finally:os.close(fd)
  K.need(len(body)<=cap,'bounded selected proc identity');return body
 raw=read('stat',4096);head,sep,tail=raw.rpartition(b')');fields=tail.split()
 K.need(sep and b'('in head and len(fields)>=20 and int(head.split(b'(',1)[0])==pid and fields[0]not in(b'Z',b'X'),'same live selected process')
 argv=read('cmdline',65536);K.need(argv.endswith(b'\0'),'complete selected process argv')
 return dict(pid=pid,parent=int(fields[1]),start=int(fields[19]),argv=argv[:-1].split(b'\0'))


class QMPPeer:
 """Pin the original connected QEMU and its exact authenticated actor parent."""
 def __init__(self,stream,row,argv):
  self.stream,self.fd,self.argv=stream,stream.fileno(),list(argv);self.fds=[]
  try:
   self.credentials=struct.unpack('3i',stream.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12));pid,uid,gid=self.credentials
   module('contracts').need(uid==os.getuid()and gid==os.getgid()and pid>1,'own-UID original QMP peer')
   self.actor_pid=row['State']['Pid'];self.fds=[os.pidfd_open(pid,0)]
   self.fds.append(os.pidfd_open(self.actor_pid,0));self.qemu=proc_identity(pid);self.actor=proc_identity(self.actor_pid)
   self.check(row)
  except BaseException:self.close();raise
 def check(self,row):
  K=module('contracts');K.need(row['State']['Running']is True and not row['State']['OOMKilled']and row['State']['Pid']==self.actor_pid,'same running authenticated actor')
  K.need(self.stream.fileno()==self.fd and struct.unpack('3i',self.stream.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))==self.credentials,'same original QMP connection')
  for fd in self.fds:
   poll=select.poll();poll.register(fd,select.POLLIN);K.need(not poll.poll(0),'original QMP/actor pidfd still live')
  qemu=proc_identity(self.credentials[0]);actor=proc_identity(self.actor_pid)
  K.need(qemu==self.qemu and actor==self.actor and qemu['parent']==self.actor_pid and qemu['argv']==[x.encode()for x in self.argv],'same QEMU argv/start and authenticated actor parent/start')
 def close(self):
  for fd in self.fds:os.close(fd)
  self.fds=[]
 def evidence(self):
  return dict(qemu_pid=self.qemu['pid'],qemu_start=self.qemu['start'],actor_pid=self.actor_pid,actor_start=self.actor['start'],peer_uid=self.credentials[1],peer_gid=self.credentials[2],argv=module('contracts').json_pin(self.argv),original_connection=True,pidfds_live_checked=True)


def quit_hold_qmp(peer,qfile,guard,end,progress=None):
 K=module('contracts');K.need(qfile.fileno()==peer.fd,'original QMP stream descriptor')
 if progress is None:progress={}
 progress.update(stage='VALIDATING',request_bytes=0,reply_attempts=0,reply_bytes=0)
 guard();K.need(time.monotonic()<end,'bounded HOLD quit deadline')
 peer.stream.settimeout(min(2,end-time.monotonic()));request=b'{"execute":"quit","id":"guest-HOLD-retire"}\n'
 progress['stage']='WRITE_ENTERED'
 try:written=qfile.write(request)
 except OSError as error:
  progress.update(stage='WRITE_FAILED',io_error=type(error).__name__,errno=error.errno);raise
 progress.update(stage='WRITE_RETURNED',request_bytes=written)
 K.need(written==len(request),'complete fixed HOLD quit request')
 total=0
 for attempt in range(16):
  guard();K.need(time.monotonic()<end,'bounded HOLD quit reply deadline');peer.stream.settimeout(min(2,end-time.monotonic()))
  progress.update(stage='READ_ENTERED',reply_attempts=attempt+1)
  try:line=qfile.readline(65537)
  except OSError as error:
   progress.update(stage='READ_FAILED',io_error=type(error).__name__,errno=error.errno);raise
  total+=len(line);progress.update(stage='READ_RETURNED',reply_bytes=total)
  K.need(0<len(line)<=65536 and total<=65536,'bounded HOLD QMP reply')
  row=json.loads(line)
  if row.get('id')=='guest-HOLD-retire':
   K.need('return'in row and 'error'not in row,'QMP HOLD quit acknowledged');progress['stage']='ACKNOWLEDGED';return
 raise ValueError('QMP HOLD quit acknowledgement absent')


def normal_hold_cleanup(scope,peer,qfile,failure,nonce,authority_sha256,out,end,guard,record):
 K,P,R=module('contracts'),module('protocol'),module('runtime');P._nonce(nonce);P.hold_failure(failure);out=K.ordinary(out)
 K.need(end-time.monotonic()>12,'reserved normal HOLD retirement budget')
 K.need(scope.labels['org.cachy-asahi.perl5423-nonce']==nonce and scope.labels['org.cachy-asahi.perl5423-authority']==authority_sha256,'same case/authority owned actor')
 row=scope.recover(min(end,time.monotonic()+8));K.need(row is not None and row['Id']==scope.cid,'exact owned CID before HOLD retirement');scope.validate(row);peer.check(row)
 record.update(stage='AUTHENTICATED',nonce=nonce,authority=authority_sha256,container_id=scope.cid,name=scope.name,image=scope.image,peer=peer.evidence())
 marker=out/P.HOLD_MARKER
 fd=os.open(marker,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 with os.fdopen(fd,'wb')as stream:os.fchmod(stream.fileno(),0o600);stream.write(K.canonical(dict(nonce=nonce,failure=failure)))
 marker_pin=K.pin(marker,4096)
 record.update(stage='MARKER_WRITTEN',marker=marker_pin)
 # Recheck the pinned peer and authenticated container before control traffic.
 peer.check(row);quit_hold_qmp(peer,qfile,guard,min(end,time.monotonic()+5),record.setdefault('qmp_quit_progress',{}))
 record.update(stage='QMP_QUIT_ACKNOWLEDGED',QMP_quit_acknowledged=True)
 wait=scope.call(['docker','wait',scope.cid],min(end,time.monotonic()+8))
 K.need(wait.returncode==0 and wait.stdout.strip()==b'1','natural stopped failure actor wait')
 row=scope.recover(min(end,time.monotonic()+8));K.need(row is not None and row['Id']==scope.cid,'same stopped failure actor');scope.validate(row)
 K.need(row['State']['Running']is False and row['State']['ExitCode']==1 and row['State']['OOMKilled']is False,'ordinary nonzero HOLD actor exit')
 retired=K.load(out/P.HOLD_RETIRED,16384);K.keys(retired,('status','nonce','failure','marker','qemu','VM_acceptance','Root_acceptance'),'HOLD retirement receipt')
 K.need(retired==dict(status='HOLD_GUEST_FAILURE_QEMU_NATURALLY_RETIRED',nonce=nonce,failure=failure,marker=marker_pin,qemu=K.pin(out/'qemu.json'),VM_acceptance=None,Root_acceptance=None)and K.pin(marker,4096)==marker_pin,'same nonce/failure/marker/QEMU retirement joins')
 qemu=R.receipt(out/'qemu.json');K.need(R.natural(qemu)and qemu['argv']==peer.argv,'natural same QEMU reap/group absence')
 record.update(stage='ACTOR_RETIRED',retirement=K.pin(out/P.HOLD_RETIRED))
 removed=scope.call(['docker','container','rm',scope.cid],min(end,time.monotonic()+8));K.need(removed.returncode==0,'normal stopped HOLD actor removal')
 K.need(scope.listing(min(end,time.monotonic()+8))is None,'owned HOLD container absent after normal removal')
 record.update(stage='ABSENCE_VERIFIED',status='HOLD_FAILURE_NATURALLY_RETIRED',forced=False);return record


def cleanup_scope(scope,peer,qfile,failure,nonce,authority_sha256,out,cleanup_end,guard,report):
 if scope is None:return
 if failure is not None:
  record=report.setdefault('guest_HOLD_cleanup',dict(status='HOLD_RETIREMENT_ATTEMPT',stage='AUTHENTICATING'))
  try:
   module('contracts').need(peer is not None and qfile is not None,'original authenticated HOLD QMP binding available')
   normal_hold_cleanup(scope,peer,qfile,failure,nonce,authority_sha256,out,min(cleanup_end-40,time.monotonic()+25),guard,record)
   report.update(container_id=scope.cid,cleanup_ownership_verified=True,owned_container_removed=True,owned_container_absence_verified=True);return
  except BaseException as error:
   report.setdefault('cleanup_errors',[]).append(dict(step='normal-guest-HOLD-retirement',category=type(error).__name__,message=str(error)[:1024]));report['forced_owned_cleanup_fallback']=True
 scope.cleanup(report)


def authority(value,phase,packet,source,output,K,resources=None):
 K.keys(value,('kind','issued_by','accepted','operation','phase','packet','source_lock','output','uid','created_utc','expires_utc','image','docker_endpoint','docker_cli','quota_device','actor_tools','kernel','credentials','prepared'),'controller authority')
 K.root_cert(value,'ROOT_PERL5423_VM_ACTOR_AUTHORITY_V1')
 K.need(value['phase']==phase and value['operation']==K.OP and value['packet']==packet and value['source_lock']==source and value['output']==str(output) and value['uid']==os.getuid()!=0,'exact Root phase/packet/Source/output/UID')
 now=int(time.time());K.need(type(value['created_utc'])is type(value['expires_utc'])is int and 0<=now-value['created_utc']<=3600 and now<value['expires_utc']<=value['created_utc']+3600,'fresh finite authority')
 K.need(re.fullmatch('sha256:[0-9a-f]{64}',value['image']or'') and re.fullmatch('unix:///run/user/'+str(os.getuid())+'/[A-Za-z0-9_./-]+',value['docker_endpoint']or'') and '..'not in value['docker_endpoint'],'exact local own-UID rootless endpoint/image')
 module('runtime').docker_cli_shape(value['docker_cli'])
 if resources is not None and resources['quota_guard']['method']=='READ_ONLY_HOME_BTRFS_ENOSYS_FSTATVFS':
  module('home_btrfs').profile(resources['quota_guard'],resources,source,phase,output,now)
  K.need(value['quota_device']is None,'HOME FD syscall mode has no quota device path')
 else:K.need(type(value['quota_device'])is str and re.fullmatch('/dev/[A-Za-z0-9_/-]+',value['quota_device']),'explicit readonly quota device')
 K.need(set(value['actor_tools'])=={'/usr/bin/python3','/usr/bin/cp','/usr/bin/debugfs','/usr/bin/e2fsck','/usr/bin/qemu-img','/usr/bin/qemu-system-aarch64'},'complete fixed tool image pins')
 for pin in list(value['actor_tools'].values())+list(value['kernel'].values()):K.pin_shape(pin)
 K.keys(value['kernel'],('Image','config'),'RTC 16K kernel pins')
 if phase=='boot':K.pin_shape(value['credentials']);K.pin_shape(value['prepared'])
 else:K.need(value['credentials']is value['prepared']is None,'preparation has no PAM secret or boot binding')


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('phase',choices=['prepare','boot']);p.add_argument('--execute-root-bound-actor',action='store_true')
 for n in('packet','baseline','kernel','authority','output'):p.add_argument('--'+n,type=Path,required=True)
 for n in('authority-sha256','source-lock-sha256'):p.add_argument('--'+n,required=True)
 p.add_argument('--prepared',type=Path);p.add_argument('--credentials',type=Path);p.add_argument('--baseline-ownership',type=Path);a=p.parse_args()
 K,A,R,B,P,Q=module('contracts'),module('adapter'),module('runtime'),None,module('protocol'),module('budget')
 K.need(a.execute_root_bound_actor and sys.flags.isolated and sys.dont_write_bytecode and __debug__ and os.getuid()==os.geteuid()!=0,'explicit isolated ordinary-user Root actor entry')
 source=A.source(a.source_lock_sha256);packet_dir=K.ordinary(a.packet);packet=K.load(packet_dir/'case-packet.json');case=K.load(packet_dir/'case-inputs.json')
 K.need(packet['Source_lock']==source and packet['operation']==K.OP and re.fullmatch('[0-9a-f]{32}',packet['nonce']or''),'exact packet Source/nonce')
 for name,row in packet['files'].items():K.need(K.pin(packet_dir/name)=={n:row[n]for n in('bytes','sha256')},'packet complete file pins')
 cert={n:K.load(packet_dir/(n+'.json'))for n in K.EVIDENCE};observed={}
 started=time.monotonic();K.END=started+cert['resource_certificate'][a.phase+'_seconds']
 for name,row in packet['materials'].items():observed[name]=K.pin(Path(row['path']))
 K.validate(case,observed,**cert)
 baseline=K.ordinary(a.baseline);kernel=K.ordinary(a.kernel);out=K.ordinary(a.output)
 K.need(not out.exists() and out.parent.is_dir() and out.parent.stat().st_uid==os.getuid() and not out.parent.stat().st_mode&0o022,'fresh private owned output')
 K.need(all(out!=q and q not in out.parents and out not in q.parents for q in (HERE,packet_dir,baseline,kernel)),'disjoint Source/packet/baseline/kernel/output')
 authpath=K.ordinary(a.authority);K.need(K.pin(authpath)['sha256']==a.authority_sha256,'external Root exact authority bytes');auth=K.load(authpath)
 authority(auth,a.phase,K.pin(packet_dir/'case-packet.json'),source,out,K,cert['resource_certificate'])
 R.checked_docker_cli(auth['docker_cli'])
 base=cert['baseline_certificate'];r=cert['resource_certificate']
 baseline_paths=A.baseline_inputs(baseline,base,a.baseline_ownership)
 K.need(all(path!=out and out not in path.parents for path in baseline_paths.values()),'baseline operands outside actor output')
 for name,pin in auth['kernel'].items():K.need(K.pin(kernel/name)==pin,'actual qualified RTC kernel')
 cfg=K.helper('rtc_contract.py').values((kernel/'config').read_bytes())
 required={'CONFIG_ARM64':'y','CONFIG_ARM64_16K_PAGES':'y','CONFIG_RTC_CLASS':'y','CONFIG_RTC_DRV_PL031':'y','CONFIG_RTC_HCTOSYS':'y','CONFIG_RTC_HCTOSYS_DEVICE':'"rtc0"','CONFIG_RTC_SYSTOHC':'n','CONFIG_VIRTIO_BLK':'y','CONFIG_EXT4_FS':'y'}
 K.need(all(cfg.get(n,'n')==v for n,v in required.items()),'exact builtin 16K/PL031/RTC boot kernel configuration')
 retained=[]
 for group in ('materials','rollback_materials','dependency_materials'):
  for name,row in packet[group].items():
   if group=='materials'and name not in K.MATERIALS:continue
   K.need(re.fullmatch('[A-Za-z0-9._+-]+',row['guest_name'])is not None,'fixed guest retained material name')
   K.need(K.pin(Path(row['path']))=={n:row[n]for n in('bytes','sha256')},'exact retained material before actor')
   retained.append((str(K.ordinary(row['path'])),'/materials/'+row['guest_name']))
 K.need(len({dst for _,dst in retained})==len(retained),'unique exact retained file bind destinations')
 prepared=None;secret=None
 if a.phase=='boot':
  K.need(a.prepared is not None and a.credentials is not None,'exact boot prepared input/private PAM credentials')
  prepared=K.ordinary(a.prepared);credentials=K.ordinary(a.credentials)
  K.need(K.pin(prepared/'prepared.json')==auth['prepared'] and K.pin(credentials)==auth['credentials'] and stat.S_IMODE(credentials.stat().st_mode)==0o600 and credentials.stat().st_uid==os.getuid(),'exact private original PAM credential/prepared pins')
  secret=K.load(credentials);K.need(secret.get('username')=='builder' and type(secret.get('password'))is str and re.fullmatch('[A-Za-z0-9_-]{24,128}',secret['password']),'original finite PAM secret')
  m=K.load(prepared/'prepared.json');K.need(m['status']=='PREPARED_NOT_BOOTED' and m['packet']==K.pin(packet_dir/'case-packet.json') and K.pin(prepared/'guest.raw')==m['raw'],'exact prepared raw lineage')
 else:K.need(a.prepared is a.credentials is None,'prepare does not consume boot operands')
 # The readonly whole-owner guard begins before Docker, runs throughout serial
 # waits, and remains active until owned retirement is recorded.
 os.umask(0o077);out.mkdir(mode=0o700);deadline=started+r[a.phase+'_seconds'];cleanup_end=deadline+r['cleanup_seconds']
 guard=Q.Guard(out,r,auth['quota_device'],cleanup_end,R.allocated,initial=True,source=source,phase=a.phase);R.GUARD=guard;guard(True)
 B=K.helper('reference_controller.py');state=B.Cancellation();scope=serial=qmp=qfile=peer=None;hold_failure=None
 report=dict(status='HOLD',docker_cli=auth['docker_cli'],operation=K.OP,phase=a.phase,cleanup_errors=[],VM_acceptance=None,Root_acceptance=None,native16K='NOT_RUN',M2='NOT_RUN',performance='NOT_MEASURED',release='NOT_ADMITTED')
 (out/'actor-envelope.json').write_bytes(K.canonical(dict(deadline_monotonic_ns=int(deadline*10**9))))
 (out/'actor-tools.json').write_bytes(K.canonical(dict(files=auth['actor_tools'])))
 (out/'host-epoch.json').write_bytes(K.canonical(dict(nonce=packet['nonce'],utc_ns=time.time_ns())))
 def cmd(label,argv,seconds=15):return R.command(argv,out,label,seconds,cleanup_end if state.cleaning else deadline)
 state.__enter__();route=R.transport(auth);entered=False
 try:
  route.__enter__();entered=True
  K.need('name=rootless'in json.loads(cmd('rootless',['docker','info','--format','{{json .SecurityOptions}}'])),'actual local rootless daemon')
  image=json.loads(cmd('image',['docker','image','inspect',auth['image']]))[0];K.need(image['Id']==auth['image'],'exact tool image ID')
  labels=dict(image['Config'].get('Labels')or{});labels.update({'org.cachy-asahi.perl5423-owner':str(os.getuid()),'org.cachy-asahi.perl5423-nonce':packet['nonce'],'org.cachy-asahi.perl5423-authority':a.authority_sha256})
  mounts={('bind',str(HERE),'/code',False),('bind',str(packet_dir),'/packet',False),('bind',str(baseline),'/base',False),('bind',str(kernel),'/kernel',False),('bind',str(out),'/work',True)}
  mounts.update(('bind',src,dst,False)for src,dst in retained)
  if prepared is not None:mounts.add(('bind',str(prepared),'/prepared',False))
  name='cachy-perl5423-'+secrets.token_hex(12)
  class Scope(B.OwnedContainer):
   def call(self,argv,limit):return R.docker_call(argv,out,limit,shared_deadline=cleanup_end if state.cleaning else deadline,defer_cancel=state.cleaning)
   def validate(self,row,expected_name=name):
    # Capture this immutable string now; later material loops reuse "name".
    K.need(row['Name']=='/'+expected_name and row['Image']==auth['image'] and row['Config']['Labels']==labels and row['Config']['Entrypoint']==['/usr/bin/python3'] and row['Config']['Cmd']==['-I','-B','/code/actor.py',a.phase],'exact owned actor identity')
    K.need(len(row['Mounts'])==len(mounts) and {(x['Type'],x['Source'],x['Destination'],x['RW'])for x in row['Mounts']}==mounts,'exact readonly inputs/single writable output')
    h=row['HostConfig'];K.need(h['ReadonlyRootfs']is True and h['NetworkMode']=='none' and h['CapDrop']==['ALL'] and not h.get('CapAdd') and not h['Privileged'] and not h['Devices'] and h['Init']is False and h['SecurityOpt']==['no-new-privileges'] and h['Memory']==h['MemorySwap']==r['owner_memory_bytes'] and h['NanoCpus']==r['cpus']*10**9 and h['PidsLimit']==r['pids'],'finite cap0 NNP no-network no-device actor')
  scope=Scope(name,out/'container.cid',auth['image'],labels,baseline,out);K.need(scope.listing(time.monotonic()+8)is None,'fresh owned name')
  argv=['docker','create','--cidfile',str(scope.cidfile),'--name',name,'--init=false','--pull=never','--read-only','--network=none','--cap-drop=ALL','--security-opt=no-new-privileges','--cpus='+str(r['cpus']),'--memory='+str(r['owner_memory_bytes']),'--memory-swap='+str(r['owner_memory_bytes']),'--pids-limit='+str(r['pids']),'--tmpfs','/tmp:rw,nodev,nosuid,noexec,size=32m']
  for key,value in labels.items():argv+=['--label',key+'='+value]
  for _,src,dst,rw in sorted(mounts):argv+=['--mount','type=bind,source='+src+',target='+dst+(''if rw else',readonly')]
  argv+=['--env','CACHY_PERL5423_ACTOR=1','--entrypoint','/usr/bin/python3',auth['image'],'-I','-B','/code/actor.py',a.phase]
  attempt_marker(a.phase,out,prepared,a.authority_sha256,packet['nonce'])
  scope.submitted=True;cmd('create',argv);scope.recover(time.monotonic()+8);cmd('start',['docker','start',name])
  if a.phase=='boot':
   with tempfile.TemporaryDirectory(prefix='perl5423-sockets-')as short:
    link=Path(short)/'out';link.symlink_to(out,target_is_directory=True)
    for node in ('serial.sock','qmp.sock'):
     until=min(deadline,time.monotonic()+20)
     while not(out/node).exists() and time.monotonic()<until:guard();time.sleep(.05)
     st=(out/node).lstat();K.need(stat.S_ISSOCK(st.st_mode) and st.st_uid==os.getuid(),'actual owned VM socket')
    qmp=socket.socket(socket.AF_UNIX);qmp.settimeout(2);qmp.connect(str(link/'qmp.sock'));qfile=qmp.makefile('rwb',buffering=0)
    def reply():
     guard();line=qfile.readline(65537);K.need(0<len(line)<=65536,'bounded QMP reply');return json.loads(line)
    K.need('QMP'in reply(),'actual QMP greeting')
    def rpc(method):
     qfile.write(json.dumps(dict(execute=method,id=method)).encode()+b'\n')
     for _ in range(64):
      row=reply()
      if row.get('id')==method:K.need('error'not in row,'QMP error');return
     raise ValueError('QMP finite matching reply absent')
    rpc('qmp_capabilities')
    try:
     peer=QMPPeer(qmp,scope.recover(min(deadline,time.monotonic()+8)),module('actor').qemu_argv(m,r,K.load(out/'host-epoch.json')['utc_ns']//10**9))
    except Exception as error:report['guest_HOLD_binding_unavailable']=dict(category=type(error).__name__,message=str(error)[:1024])
    stream=socket.socket(socket.AF_UNIX);stream.connect(str(link/'serial.sock'))
    class Serial(B.Serial):
     def until(self,pattern):
      # Frozen Serial's bounded recv also calls guard via this socket wrapper.
      guard();return super().until(pattern)
    class Watched:
     def __getattr__(self,n):return getattr(stream,n)
     def recv(self,n):guard();return stream.recv(n)
    serial=Serial(Watched(),deadline-r['cleanup_seconds'])
    report.update(P.journey(serial,secret['password'],m['baseline_nonce'],packet['nonce'],B.parse_frame));rpc('quit');report['QMP_quit_requested']=True
  cmd('wait',['docker','wait',name],max(5,deadline-time.monotonic()));finished=scope.recover(time.monotonic()+8)
  K.need(finished['State']['ExitCode']==0 and not finished['State']['Running'] and not finished['State']['OOMKilled'],'natural actor completion')
  if a.phase=='boot':
   K.need(R.natural(R.receipt(out/'qemu.json')),'natural QEMU group reap')
   P.validate(report['restored'],module('proof').inventory_hash(base['inventory']),K.load(out/'host-epoch.json')['utc_ns']//10**9,int(time.time()),cert['runtime_certificate']['rollback']['local_database_policy'])
   report['outputs']=module('proof').outputs(out/'results',report['restored'],base['inventory'],cert['runtime_certificate'],packet['nonce'],K.load(out/'host-epoch.json')['utc_ns']//10**9,int(time.time()),r['guest_output_cap_bytes'])
   report['preservation']=K.load(out/'preservation.json');K.need(report['preservation']['status']=='PASS_COMPLETE_BASELINE_AND_USER_PRESERVATION','postboot complete preservation')
   module('retention').verify(out,report['preservation']['retained_DATA'],cert['runtime_certificate'],packet,K.pin(packet_dir/'case-packet.json'),r)
  K.need(K.pin(authpath)['sha256']==a.authority_sha256 and A.source(a.source_lock_sha256)==source,'Source/authority stable throughout actor')
  A.baseline_inputs(baseline,base,a.baseline_ownership)
  for name,row in packet['materials'].items():K.need(K.pin(Path(row['path']))=={n:row[n]for n in('bytes','sha256')},'retained original material stable')
  if prepared is not None:K.need(K.pin(prepared/'prepared.json')==auth['prepared'] and K.pin(prepared/'guest.raw')==m['raw'],'prepared original remains unchanged')
  report['status']='PREPARED_NOT_BOOTED'if a.phase=='prepare'else'PASS_EMULATED_ARM16K_PERL5423_DATA_ONLY'
 except BaseException as error:
  report['failure']=dict(category=type(error).__name__,message=str(error)[:1024])
  if isinstance(error,P.GuestHold):hold_failure=error.failure
 finally:
  state.cleaning=True;K.END=cleanup_end
  # Quota failure must never prevent owned-container recovery/removal. The
  # read-only guard remains sampled separately; cleanup has its reserved tail.
  def cleanup_guard():
   try:guard(True)
   except BaseException as e:
    report['budget_failure']=str(e)[:1024];report['status']='HOLD';R.GUARD=None
  R.GUARD=cleanup_guard;cleanup_guard()
  try:
   try:
    if serial is not None:(out/'serial.redacted.log').write_bytes(bytes(serial.data).replace(secret['password'].encode(),b'[REDACTED]'))
   except BaseException as error:report.setdefault('cleanup_errors',[]).append('serial-report: '+str(error)[:1024])
  finally:
   try:
    cleanup_scope(scope,peer,qfile,hold_failure,packet['nonce'],a.authority_sha256,out,cleanup_end,cleanup_guard,report)
   except BaseException as error:report.setdefault('cleanup_errors',[]).append('owned-cleanup: '+str(error)[:1024])
   finally:
    for handle in (serial.stream if serial is not None else None,qfile,qmp,peer):
     try:
      if handle is not None:handle.close()
     except BaseException as error:report.setdefault('cleanup_errors',[]).append('close-handle: '+str(error)[:1024])
    if state.pending or report.get('cleanup_errors') or not report.get('owned_container_absence_verified'):report['status']='HOLD_CLEANUP_OR_CANCELLED'
    if guard.home is None:report['quota_guard_samples']=guard.samples
    else:report['storage_guard']=dict(mode='HOME_BTRFS_ENOSYS',samples=guard.samples,last_snapshot=guard.last_snapshot,own_uid_quota='UNSUPPORTED_NOT_UNLIMITED',other_quota_availability='UNCLAIMED',capacity_reservation=False)
    try:(out/'report.json').write_bytes(K.canonical(report))
    finally:
     try:
      if entered:route.__exit__(None,None,None)
     finally:state.__exit__()
 return 0 if report['status']in('PREPARED_NOT_BOOTED','PASS_EMULATED_ARM16K_PERL5423_DATA_ONLY')else 1
if __name__=='__main__':raise SystemExit(main())

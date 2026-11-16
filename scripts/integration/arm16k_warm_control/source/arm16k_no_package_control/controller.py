#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Explicit Root-bound no-package control. No transport or private reads on import."""
import argparse,importlib.util,json,os,re,secrets,socket,stat,sys,tempfile,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('control_support',HERE/'support.py');S=importlib.util.module_from_spec(spec);spec.loader.exec_module(S)


def login_fields(raw,nonce):
 fields=S.legacy('contracts').helper('reference_controller.py').parse_frame(raw,nonce)
 expected={'UID','USERNAME','PID1','ARCH','PAGESIZE','XDG_SESSION_ID','Id','Name','User','Active','State','Class','Remote','Type','Service','Leader','LOGIND','DBUS'}
 K=S.local('contracts');K.need(set(fields)==expected and fields['ARCH']=='aarch64'and fields['PAGESIZE']=='16384'and fields['Active']=='yes','exact ordinary ARM16K PAM proof')
 return fields


def journey(serial,password,packet,guard,clock=time.monotonic,sleep=time.sleep):
 """One ordinary PAM session, two fixed probes and the Root-selected idle."""
 K,M,P=S.local('contracts'),S.local('metadata'),S.local('plan');t=packet['timing'];nonce=packet['nonce'];base=packet['baseline_nonce'];overall=serial.deadline
 def until(pattern,seconds):
  guard();serial.deadline=min(overall,clock()+seconds);return serial.until(pattern)
 until(rb'login:\s*',t['login_seconds']);serial.send(b'builder\n');until(rb'Password:\s*',t['login_seconds']);serial.send(password.encode()+b'\n')
 until(('ARM16K_SHELL_READY '+base).encode(),t['login_seconds'])
 serial.send(b'/usr/local/libexec/arm16k-login-proof\n');until(('TCG_LOGIN_END '+base).encode()+rb'\r?\n',t['proof_seconds'])
 proof=login_fields(bytes(serial.data),base);rows={}
 def probe(stage):
  start=len(serial.data);serial.send(P.guest_command(stage,nonce).encode('ascii'))
  until(('ARM16K_NO_PACKAGE_META_END '+nonce+' '+stage).encode()+rb'\r?\n',t['probe_seconds'])
  rows[stage]=M.parse_frame(bytes(serial.data[start:]),nonce,stage)
 probe('after_login');start=clock();end=start+packet['idle_seconds']
 while clock()<end:guard();K.need(clock()<overall,'control idle deadline');sleep(max(0,min(.05,end-clock())))
 idle_ns=int((clock()-start)*10**9);probe('before_logout')
 serial.send(b'exit\n');until(rb'login:\s*',t['logout_seconds']);serial.deadline=overall
 return dict(session=proof,metadata=rows,normal_PAM_logout_observed=True,selected_idle_seconds=packet['idle_seconds'],observed_idle_ns=idle_ns)


def validate_container(row,name,image,labels,mounts,r):
 K=S.local('contracts')
 K.need(re.fullmatch('[0-9a-f]{64}',row['Id'])is not None and row['Name']=='/'+name and row['Image']==image and row['Config']['Labels']==labels and row['Config']['Entrypoint']==['/usr/bin/python3']and row['Config']['Cmd']==['-I','-B','/code/actor.py','--execute-root-bound-actor'],'exact owned control identity')
 K.need(len(row['Mounts'])==len(mounts)and {(m['Type'],m['Source'],m['Destination'],m['RW'])for m in row['Mounts']}==mounts,'exact readonly control inputs and one writable output')
 h=row['HostConfig'];K.need(h['ReadonlyRootfs']is True and h['NetworkMode']=='none'and h['CapDrop']==['ALL']and not h.get('CapAdd')and not h['Privileged']and not h['Devices']and h['Init']is False and h['SecurityOpt']==['no-new-privileges']and h['Memory']==h['MemorySwap']==r['owner_memory_bytes']and h['NanoCpus']==r['cpus']*10**9 and h['PidsLimit']==r['pids'],'finite rootless cap0 NNP control confinement')


def normal_remove(scope,report,deadline):
 K=S.local('contracts');row=scope.recover(min(deadline,time.monotonic()+8))
 if row is None:report['owned_container_absence_verified']=True;return
 K.need(row['State']['Running']is False,'stopped owned control before normal removal')
 result=scope.call(['docker','container','rm',scope.cid],min(deadline,time.monotonic()+8));K.need(result.returncode==0,'normal stopped control removal')
 K.need(scope.listing(min(deadline,time.monotonic()+8))is None,'owned control absent after normal removal')
 report.update(container_id=scope.cid,cleanup_ownership_verified=True,owned_container_removed=True,owned_container_absence_verified=True,normal_owned_cleanup=True)


def validate_observations(data,packet,source,out,expected_argv):
 K,R=S.local('contracts'),S.legacy('runtime')
 K.keys(data,('schema','status','operation','nonce','baseline_nonce','source_lock','baseline','kernel','reader','metadata','qemu_receipt','qemu_argv','qemu_epoch','qemu_naturally_retired','original_raw_identity_unchanged','VM_acceptance','Root_acceptance','preservation','ALPM'),'control actor observations')
 K.need(type(data['schema'])is int and data['schema']==1 and data['status']=='PASS_NO_PACKAGE_ACTOR_OFFLINE_METADATA_ONLY'and data['operation']==K.OP and data['nonce']==packet['nonce']and data['baseline_nonce']==packet['baseline_nonce']and data['source_lock']==source,'exact actor operation and nonce bindings')
 K.need(data['baseline']=={n:packet['baseline'][n]for n in ('raw','prepared','certificate')}and data['kernel']=={n:packet['kernel'][n]for n in ('Image','config')}and data['reader']==packet['reader'],'exact actor input pins')
 K.keys(data['metadata'],('offline_before','offline_after'),'two offline metadata phases')
 K.need(data['qemu_naturally_retired']is data['original_raw_identity_unchanged']is True and all(data[n]is None for n in ('VM_acceptance','Root_acceptance','preservation','ALPM')),'observation only without acceptance or preservation claim')
 K.need(data['qemu_receipt']==K.pin(out/'qemu.json',4*1024**2)and data['qemu_argv']==K.pin(out/'qemu-argv.json',65536)and data['qemu_epoch']==K.pin(out/'qemu-epoch.json',4096),'exact actor QEMU receipt pins')
 receipt=R.receipt(out/'qemu.json');K.need(R.natural(receipt)and receipt['argv']==expected_argv and K.load(out/'qemu-argv.json',65536)==dict(argv=expected_argv),'same naturally reaped authenticated QEMU vector')
 return data['metadata']


def launch_epoch(value,nonce,admission_ns,now_ns):
 K=S.local('contracts');K.keys(value,('nonce','utc_ns'),'actual QEMU launch epoch')
 K.need(value['nonce']==nonce and type(value['utc_ns'])is int and type(admission_ns)is type(now_ns)is int and admission_ns<=value['utc_ns']<=now_ns and now_ns-value['utc_ns']<=30*10**9,'fresh same-case post-metadata QEMU launch epoch')
 return value['utc_ns']//10**9


def execute(a):
 K,R,L,M=S.local('contracts'),S.legacy('runtime'),S.legacy('controller'),S.local('metadata')
 source=S.source(a.source_lock_sha256);packet_dir=K.ordinary(a.packet);packet_path=packet_dir/'control-packet.json';packet=K.load(packet_path);K.inputs(packet,source)
 K.need({p.name for p in packet_dir.iterdir()}=={'control-packet.json','raw_metadata.py'},'exact constructed control packet membership')
 K.need(K.pin(packet_dir/'raw_metadata.py',1024**2)==packet['reader'],'exact pinned metadata reader source')
 out=K.ordinary(a.output);authpath=K.ordinary(a.authority);K.need(K.pin(authpath,1024**2)['sha256']==a.authority_sha256,'exact external control authority bytes');auth=K.load(authpath);packet_pin=K.pin(packet_path,1024**2)
 K.authority(auth,packet_pin,packet,source,out,int(time.time()),os.getuid())
 admission_path=K.ordinary(a.external_admission);K.need(K.pin(admission_path,1024**2)==auth['external_admission'],'exact external Root admission bytes');admission=K.load(admission_path);K.admission(admission,packet_pin,packet,source,out,int(time.time()),os.getuid())
 K.need(callable(getattr(os,'pidfd_open',None)),'native Linux pidfd_open required')
 base=K.ordinary(a.baseline);kernel=K.ordinary(a.kernel);credentials=K.ordinary(a.credentials)
 inputs=(HERE,S.LEGACY,packet_dir,base,kernel,credentials,authpath,admission_path)
 K.need(not out.exists()and out.parent.is_dir()and out.parent.stat().st_uid==os.getuid()and not out.parent.stat().st_mode&0o022,'fresh private owned control output')
 K.need(all(out!=p and out not in p.parents and p not in out.parents for p in inputs),'disjoint control output and immutable inputs')
 K.need(all(','not in str(p)and '\n'not in str(p)for p in (*inputs,out)),'literal bind mount operands')
 r=packet['resources'];started=time.monotonic();deadline=started+r['boot_seconds'];cleanup_end=deadline+r['cleanup_seconds'];K.END=deadline;S.legacy('contracts').END=deadline;os.umask(0o077);out.mkdir(mode=0o700)
 guard=S.legacy('budget').Guard(out,r,auth['quota_device'],cleanup_end,R.allocated,initial=True,source=source,phase='boot');R.GUARD=guard
 B=S.legacy('contracts').helper('reference_controller.py');state=B.Cancellation();scope=serial=stream=qmp=qfile=peer=None;entered=False;route=R.transport(auth)
 report=dict(operation=K.OP,status='HOLD_NO_PACKAGE_CONTROL',nonce=packet['nonce'],source_lock=source,cleanup_errors=[],Root_acceptance=None,VM_acceptance=None,preservation=None,ALPM=None)
 def cmd(label,argv,seconds=15):return R.command(argv,out,label,seconds,cleanup_end if state.cleaning else deadline)
 def unchanged():
  guard();K.need(K.pin(base/'guest.raw',4*1024**3)==packet['baseline']['raw']and K.pin(base/'prepared.json')==packet['baseline']['prepared'],'exact original baseline raw and prepared pins')
  K.need(K.pin(credentials,4096)==auth['credentials'],'original private PAM credential pin')
  K.need(all(K.pin(kernel/n,128*1024**2)==packet['kernel'][n]for n in ('Image','config')),'exact admitted case14 kernel pins')
  K.need(K.pin(packet_path,1024**2)==packet_pin and K.pin(packet_dir/'raw_metadata.py',1024**2)==packet['reader']and K.pin(authpath,1024**2)['sha256']==a.authority_sha256 and K.pin(admission_path,1024**2)==auth['external_admission']and S.source(source)==source,'control Source, packet, reader and grant stable')
 def rpc(method,limit=None):
  until=min(cleanup_end if state.cleaning else deadline,time.monotonic()+5,limit if limit is not None else cleanup_end)
  guard();K.need(time.monotonic()<until,'finite control QMP request deadline');qmp.settimeout(min(2,until-time.monotonic()));request=json.dumps(dict(execute=method,id=method)).encode()+b'\n';K.need(qfile.write(request)==len(request),'complete control QMP request')
  for _ in range(64):
   guard();K.need(time.monotonic()<until,'finite control QMP reply deadline');qmp.settimeout(min(2,until-time.monotonic()));line=qfile.readline(65537);K.need(0<len(line)<=65536,'bounded control QMP reply');row=json.loads(line)
   if row.get('id')==method:K.need('return'in row and 'error'not in row,'control QMP acknowledgement');return
  raise ValueError('finite control QMP reply count')
 state.__enter__()
 try:
  guard(True);route.__enter__();entered=True;unchanged();prepared=K.load(base/'prepared.json');K.need(prepared['nonce']==packet['baseline_nonce']and prepared['files']['guest.raw']==packet['baseline']['raw'],'original baseline nonce/raw lineage')
  info=credentials.lstat();K.need(stat.S_ISREG(info.st_mode)and info.st_nlink==1 and info.st_uid==os.getuid()and stat.S_IMODE(info.st_mode)==0o600,'original private own-UID PAM credentials')
  secret=K.load(credentials,4096);K.need(set(secret)=={'username','password'}and secret['username']=='builder'and type(secret['password'])is str and re.fullmatch('[A-Za-z0-9_-]{24,128}',secret['password'])is not None,'finite original builder PAM secret')
  cfg=S.legacy('contracts').helper('rtc_contract.py').values((kernel/'config').read_bytes());required={'CONFIG_ARM64':'y','CONFIG_ARM64_16K_PAGES':'y','CONFIG_RTC_CLASS':'y','CONFIG_RTC_DRV_PL031':'y','CONFIG_RTC_HCTOSYS':'y','CONFIG_RTC_HCTOSYS_DEVICE':'"rtc0"','CONFIG_RTC_SYSTOHC':'n','CONFIG_VIRTIO_BLK':'y','CONFIG_EXT4_FS':'y'};K.need(all(cfg.get(n,'n')==v for n,v in required.items()),'admitted builtin ARM16K RTC kernel configuration')
  K.need('name=rootless'in json.loads(cmd('rootless',['docker','info','--format','{{json .SecurityOptions}}'])),'actual rootless Docker endpoint')
  image=json.loads(cmd('image',['docker','image','inspect',packet['tool_image']]))[0];K.need(image['Id']==packet['tool_image'],'exact admitted tool image')
  labels=dict(image['Config'].get('Labels')or{});labels.update({'org.cachy-asahi.no-package-owner':str(os.getuid()),'org.cachy-asahi.no-package-nonce':packet['nonce'],'org.cachy-asahi.no-package-authority':a.authority_sha256});name='cachy-no-package-'+secrets.token_hex(12)
  mounts={('bind',str(HERE),'/code',False),('bind',str(S.LEGACY),'/legacy',False),('bind',str(packet_dir),'/packet',False),('bind',str(packet_dir/'raw_metadata.py'),'/reader/raw_metadata.py',False),('bind',str(base/'guest.raw'),'/base/guest.raw',False),('bind',str(kernel/'Image'),'/kernel/Image',False),('bind',str(kernel/'config'),'/kernel/config',False),('bind',str(out),'/work',True)}
  class Scope(B.OwnedContainer):
   def call(self,argv,limit):return R.docker_call(argv,out,limit,shared_deadline=cleanup_end if state.cleaning else deadline,defer_cancel=state.cleaning)
   def validate(self,row,expected_name=name):validate_container(row,expected_name,packet['tool_image'],labels,mounts,r)
  scope=Scope(name,out/'container.cid',packet['tool_image'],labels,base,out);K.need(scope.listing(time.monotonic()+8)is None,'fresh owned control name')
  (out/'control-attempt.json').write_bytes(K.canonical(dict(operation=K.OP,nonce=packet['nonce'],authority=a.authority_sha256)))
  (out/'actor-envelope.json').write_bytes(K.canonical(dict(deadline_monotonic_ns=int(deadline*10**9))))
  epoch=dict(nonce=packet['nonce'],utc_ns=time.time_ns());(out/'host-epoch.json').write_bytes(K.canonical(epoch))
  argv=['docker','create','--cidfile',str(scope.cidfile),'--name',name,'--init=false','--pull=never','--read-only','--network=none','--cap-drop=ALL','--security-opt=no-new-privileges','--cpus='+str(r['cpus']),'--memory='+str(r['owner_memory_bytes']),'--memory-swap='+str(r['owner_memory_bytes']),'--pids-limit='+str(r['pids']),'--tmpfs','/tmp:rw,nodev,nosuid,noexec,size=32m']
  for key,value in labels.items():argv+=['--label',key+'='+value]
  for _,src,dst,_ in sorted(mounts):argv+=['--mount','type=bind,source='+src+',target='+dst+(''if dst=='/work'else',readonly')]
  argv+=['--env','CACHY_NO_PACKAGE_ACTOR=1','--entrypoint','/usr/bin/python3',packet['tool_image'],'-I','-B','/code/actor.py','--execute-root-bound-actor']
  scope.submitted=True;cmd('create',argv);scope.recover(time.monotonic()+8);cmd('start',['docker','start',name])
  with tempfile.TemporaryDirectory(prefix='no-package-sockets-')as short:
   link=Path(short)/'out';link.symlink_to(out,target_is_directory=True)
   for node in ('serial.sock','qmp.sock'):
    until=min(deadline,time.monotonic()+140)
    while not(out/node).exists()and time.monotonic()<until:guard();time.sleep(.05)
    info=(out/node).lstat();K.need(stat.S_ISSOCK(info.st_mode)and info.st_uid==os.getuid(),'owned control VM socket')
   qmp=socket.socket(socket.AF_UNIX);qmp.settimeout(2);qmp.connect(str(link/'qmp.sock'));qfile=qmp.makefile('rwb',buffering=0);greeting=qfile.readline(65537);K.need(0<len(greeting)<=65536 and 'QMP'in json.loads(greeting),'control QMP greeting');rpc('qmp_capabilities')
   actual_epoch=launch_epoch(K.load(out/'qemu-epoch.json',4096),packet['nonce'],epoch['utc_ns'],time.time_ns())
   peer=L.QMPPeer(qmp,scope.recover(time.monotonic()+8),S.local('actor').qemu_argv(packet,actual_epoch));report['QMP_peer']=peer.evidence()
   stream=socket.socket(socket.AF_UNIX);stream.connect(str(link/'serial.sock'))
   class Watched:
    def __getattr__(self,n):return getattr(stream,n)
    def recv(self,n):guard();return stream.recv(n)
   serial=B.Serial(Watched(),deadline-r['cleanup_seconds']);observed=journey(serial,secret['password'],packet,guard);report.update(observed)
   peer.check(scope.recover(time.monotonic()+8));rpc('quit');report['QMP_quit_requested']=True
  cmd('wait',['docker','wait',scope.cid],max(5,deadline-time.monotonic()));row=scope.recover(time.monotonic()+8);K.need(row['State']['Running']is False and row['State']['ExitCode']==0 and not row['State']['OOMKilled'],'naturally completed control actor')
  data=K.load(out/'observations.json',65536);offline=validate_observations(data,packet,source,out,peer.argv)
  phases=dict(offline,**observed['metadata']);report['comparison']=M.compare_phases(phases);report['actor_observations']=K.pin(out/'observations.json',65536);unchanged();K.authority(auth,packet_pin,packet,source,out,int(time.time()),os.getuid(),starting=False);K.admission(admission,packet_pin,packet,source,out,int(time.time()),os.getuid(),starting=False);report['status']='COMPLETE_NO_PACKAGE_METADATA_OBSERVATION_ONLY'
 except BaseException as error:
  report['failure_category']=type(error).__name__ if type(error).__name__ in ('ValueError','AssertionError','TimeoutError','OSError','FileNotFoundError','KeyboardInterrupt','Cancelled')else'Exception'
 finally:
  state.cleaning=True;K.END=cleanup_end;S.legacy('contracts').END=cleanup_end
  def cleanup_guard():
   try:guard(True)
   except BaseException:report['budget_failure']=True;report['status']='HOLD_NO_PACKAGE_CONTROL';R.GUARD=None
  R.GUARD=cleanup_guard;cleanup_guard()
  try:
   if scope is not None and scope.submitted:
    try:
     normal_end=min(cleanup_end-35,time.monotonic()+25);K.need(normal_end-time.monotonic()>8,'reserved normal and fallback cleanup budgets');row=scope.recover(min(normal_end,time.monotonic()+8))
     if row is not None and row['State']['Running']:
      K.need(peer is not None,'original control QMP peer for normal failure retirement');peer.check(row);rpc('quit',normal_end);result=scope.call(['docker','wait',scope.cid],min(normal_end,time.monotonic()+8));K.need(result.returncode==0,'normal control failure actor wait')
     normal_remove(scope,report,normal_end)
    except BaseException:
     report['forced_owned_cleanup_fallback']=True;report['status']='HOLD_NO_PACKAGE_CONTROL';scope.cleanup(report)
  except BaseException:report['cleanup_errors'].append('owned_cleanup_failed')
  finally:
   for handle in (stream,qfile,qmp,peer):
    if handle is not None:
     try:handle.close()
     except BaseException:report['cleanup_errors'].append('handle_close_failed')
   if state.pending or report['cleanup_errors']or not report.get('owned_container_absence_verified'):report['status']='HOLD_NO_PACKAGE_CONTROL'
   report['guard_samples']=guard.samples
   # Legacy owned cleanup may collect exception strings. Retain fixed categories
   # only; the raw serial stream and arbitrary diagnostic text are never retained.
   allowed_steps={'ownership-recovery','request-stop','bounded-wait','forced-removal','absence-check'}
   report['cleanup_errors']=[dict(step=e.get('step')if e.get('step')in allowed_steps else'owned_cleanup',category=e.get('category')if e.get('category')in ('OSError','ValueError','AssertionError','TimeoutError')else'Exception')if type(e)is dict else'cleanup_failed'for e in report['cleanup_errors']]
   try:(out/'report.json').write_bytes(K.canonical(report))
   finally:
    try:
     if entered:route.__exit__(None,None,None)
    finally:
     try:state.__exit__()
     finally:R.GUARD=None;K.END=None;S.legacy('contracts').END=None
 return 0 if report['status']=='COMPLETE_NO_PACKAGE_METADATA_OBSERVATION_ONLY'else 1


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--execute-root-bound-control',action='store_true')
 for name in ('packet','baseline','kernel','credentials','authority','external-admission','output'):p.add_argument('--'+name,type=Path,required=True)
 for name in ('authority-sha256','source-lock-sha256'):p.add_argument('--'+name,required=True)
 a=p.parse_args()
 if not(a.execute_root_bound_control and sys.flags.isolated and sys.dont_write_bytecode and __debug__ and os.getuid()==os.geteuid()!=0):p.error('explicit isolated ordinary-user Root control required')
 return execute(a)
if __name__=='__main__':raise SystemExit(main())

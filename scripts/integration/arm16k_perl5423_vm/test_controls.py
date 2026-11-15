# SPDX-License-Identifier: MIT
"""Fenced synthetic DATA only. Never Docker, VM, GPG, ALPM, compiler or network."""
import ast,copy,hashlib,importlib.util,json,os,struct,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent

def module(n):
 s=importlib.util.spec_from_file_location('perl_controls_'+n,HERE/(n+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
K,A,P,F,I,C,Q=tuple(module(n)for n in('contracts','adapter','protocol','proof','image','controller','budget'))

def fence(event,args):
 if event.startswith(('subprocess.','socket.','ctypes.'))or event in('os.system','os.exec','os.fork','os.posix_spawn','fcntl.flock'):raise RuntimeError('fenced synthetic control: '+event)
sys.addaudithook(fence)

def pin(label,bytes=32):return dict(bytes=bytes,sha256=hashlib.sha256(('MODEL_ONLY_'+label).encode()).hexdigest())

def seal(c,b,rt,r,d,reader,installed):
 c['evidence']['baseline_certificate']=K.json_pin(b)
 for v in(rt,r):v.update(baseline_certificate=c['evidence']['baseline_certificate'],package=c['package']['archive'])
 for n,v in [('runtime_certificate',rt),('resource_certificate',r),('installed_Reader',reader),('installed_component_decision',installed)]:c['evidence'][n]=K.json_pin(v)
 d.update(source=c['source'],native=c['native'],package=c['package'],trust=c['trust'],evidence={n:c['evidence'][n]for n in K.EVIDENCE if n!='Root_decision'})
 c['evidence']['Root_decision']=K.json_pin(d)
 obs={n:c['package'][n]if n in K.MATERIALS else c['evidence'][n]for n in K.MATERIALS+K.EVIDENCE}
 return c,obs,b,rt,r,d,reader,installed

def modeled(rollback=False, dependency=False):
 c=K.load(HERE/'case.TEMPLATE.json');c['native']=dict(run='43692477455',job='132745843566',artifact='14153417247')
 for n in K.MATERIALS:c['package'][n]=pin(n)
 c['package']['archive']=copy.deepcopy(K.NATIVE_ARCHIVE)
 now=int(time.time());c['trust']=dict(fingerprint='A'*40,created_utc=now-1,expires_utc=now+3500,evaluated_utc=now,public_only=True,signature_valid=True,revoked=False)
 inv={n:'MODEL-1'for n in ('glibc','gdbm','db5.3','libxcrypt','bzip2','zlib','base-tools')}
 if dependency:inv.pop('db5.3')
 if rollback:inv['perl']='5.42.3-1'
 b=dict(kind='ROOT_ACCEPTED_ARM16K_PAM_BASELINE_V1',issued_by='Root',accepted=True,architecture='aarch64',page_bytes=16384,raw=pin('raw',1024**3),prepared=pin('prepared'),inventory=inv,ownership=pin('ownership'),report=pin('PAM'),normal_PAM_logout_observed=True,owned_container_absence_verified=True,baseline_count=len(inv))
 ns={};files={};baseline_files={};tools=['/usr/bin/'+n for n in K.TOOLS]
 def entry(path,owner='base-tools',mode=0o755):return dict(**pin(path),mode=mode,owner=owner,version=K.PACKAGE['version']if owner=='perl'else K.DB53['version']if owner=='db5.3'and dependency else inv[owner],resolved=path)
 for p in tools+['/etc/pacman.conf']:files[p]=entry(p);baseline_files[p]=copy.deepcopy(files[p])
 def candidate(path,mode=0o755):
  for parent in reversed(Path(path).parents):
   if str(parent)=='/':continue
   ns[str(parent)]=dict(kind='d',mode=0o755,uid=0,gid=0)
  row=entry(path,'perl',mode);files[path]=row;ns[path]=dict(kind='f',mode=mode,uid=0,gid=0,bytes=row['bytes'],sha256=row['sha256'])
 for p in list(K.PERL_ELFS)+['/usr/bin/core_perl/'+n for n in K.COMMANDS]:candidate(p)
 for hard,target in K.HARDLINKS.items():
  candidate(target,0o644 if '/man/'in target else 0o755);candidate(hard,0o644 if '/man/'in hard else 0o755);ns[hard]=copy.deepcopy(ns[target]);files[hard]=dict(files[target],resolved=hard)
 for n in K.COMMANDS:
  p='/usr/bin/'+n;ns[p]=dict(kind='l',mode=0o777,uid=0,gid=0,link_target='core_perl/'+n)
  files[p]=dict(files['/usr/bin/core_perl/'+n],resolved='/usr/bin/core_perl/'+n)
 loader='/usr/lib/ld-linux-aarch64.so.1';files[loader]=entry(loader,'glibc');baseline_files[loader]=copy.deepcopy(files[loader])
 elfs={}
 def elf(path,needed):
  elfs[path]=dict(sha256=files[path]['sha256'],**{'class':64},byte_order='little',machine=183,interpreter=loader if path=='/usr/bin/perl'else None,needed=list(needed),version_needs={n:['MODEL_V1']for n in needed},providers={n:dict(path=p,version_definitions=['MODEL_V1'])for n,p in needed.items()},static_16k_geometry=True)
 for path in K.PERL_ELFS:elf(path,{})
 providers={}
 for soname,owner in [('libc.so.6','glibc'),('libdb-5.3.so','db5.3'),('libgdbm.so.6','gdbm'),('libz.so.1','zlib'),('libbz2.so.1.0','bzip2'),('libcrypt.so.2','libxcrypt')]:
  p='/usr/lib/'+soname;files[p]=entry(p,owner,0o755);baseline_files[p]=copy.deepcopy(files[p]);elf(p,{});providers[owner]=p
  if dependency and owner=='db5.3':del baseline_files[p]
 for path,soname in [(K.PERL_ELFS[0],'libperl.so'),(K.PERL_ELFS[2],'libdb-5.3.so'),(K.PERL_ELFS[3],'libgdbm.so.6'),(K.PERL_ELFS[4],'libz.so.1'),(K.PERL_ELFS[5],'libbz2.so.1.0')]:elf(path,{soname:K.PERL_ELFS[1]if soname=='libperl.so'else'/usr/lib/'+soname})
 requires=[n if n!='libcrypt.so'else'libcrypt.so=2-64'for n in K.PACKAGE['depends']]
 deps={n:dict(owner=owner,version=K.DB53['version']if owner=='db5.3'and dependency else inv[owner],satisfied=True,providers=[providers[owner]])for n,owner in zip(requires,('glibc','gdbm','db5.3','libxcrypt','libxcrypt','bzip2','zlib'))}
 old=copy.deepcopy(ns)if rollback else{}
 recovery=dict(mode='SIGNED_EXACT_OLD_PACKAGE'if rollback else'REMOVE',version=inv.get('perl'),archive=pin('old')if rollback else None,signature=pin('old-sig')if rollback else None,reason='explicit'if rollback else None,exact_payload_verified=True,local_database_policy='NORMAL_INSTALLDATE_AND_TRANSACTION_TIMESTAMPS'if rollback else'EXACT')
 rt=dict(kind='ROOT_REVIEWED_PERL5423_VM_RUNTIME_V1',issued_by='Root',accepted=True,baseline_certificate=None,package=None,namespace_coverage='ALL_PACKAGE_OWNED_PATHS',candidate_namespace=ns,baseline_namespace=old,baseline_files=baseline_files,hardlinks=K.HARDLINKS,dependency_transaction={},elf_inventory=pin('elf-inventory'),full_payload_elf_coverage=True,elfs=elfs,files=files,tools=tools,loader=loader,alpm_dependencies=requires,PKGINFO=dict(bytes=4483,sha256='31461fa035ad9f3761775dc412f3966c1c451c817e51eb5a2412808027133edc'),effective_hook_policy=dict(baseline_configuration='/etc/pacman.conf',transaction_same_effective_policy=True,hook_directories=['/usr/share/libalpm/hooks','/etc/pacman.d/hooks'],namespace_pin=pin('actual-complete-hooks'),scriptlets_enabled=True,suppression_added=False),dependency_resolution=deps,reverse_dependencies=[],rollback=recovery,probe_qualification=dict(commands=['/usr/bin/'+n for n in K.COMMANDS],modules=['Config','JSON::PP','Digest::SHA','DB_File','GDBM_File','Compress::Raw::Zlib','Compress::Raw::Bzip2','threads'],network=False,CPAN=False,compiler=False,actual_paths_verified=True),baseline_namespace_pin=pin('complete-baseline-namespace'),restoration_allowances=dict(install_date_path='/var/lib/pacman/local/perl-'+inv['perl']+'/desc'if rollback else None,database_timestamp_paths=['/var/lib/pacman/local']+(['/var/lib/pacman/local/perl-'+inv['perl'], '/var/lib/pacman/local/perl-'+inv['perl']+'/desc','/var/lib/pacman/local/perl-'+inv['perl']+'/files']if rollback else[]),payload_directory_timestamps=True,normal_pacman_log='/var/log/pacman.log',pacman_log_before=pin('MODEL_original_pacman_log'),cache_directory_timestamps=['/var/cache','/var/cache/ldconfig']))
 if dependency:
  db=providers['db5.3'];row=files[db];nsdep={'/usr':dict(kind='d',mode=0o755,uid=0,gid=0),'/usr/lib':dict(kind='d',mode=0o755,uid=0,gid=0),db:dict(kind='f',mode=row['mode'],uid=0,gid=0,bytes=row['bytes'],sha256=row['sha256'])}
  rt['dependency_transaction']=dict(K.DB53,namespace=nsdep,files={db:row},elf_paths=[db],full_ELF_coverage=True,requires=['libgcc','libstdc++','sh'],resolution={n:dict(owner='base-tools',version=inv['base-tools'],satisfied=True,providers=['/usr/bin/bash'])for n in('libgcc','libstdc++','sh')},baseline_public_trust=pin('actual-public-official-trust-namespace'),signature_authenticated=True,current_trust_reviewed=True,recovery='NORMAL_REMOVE_AFTER_PERL_RECOVERY')
 r={n:1 for n in K.LIMITS};r.update(kind='ROOT_REVIEWED_PERL5423_VM_RESOURCES_V1',issued_by='Root',accepted=True,baseline_certificate=None,package=None,package_expanded_bytes=sum(v.get('bytes',0)for v in ns.values())+(sum(v.get('bytes',0)for v in rt['dependency_transaction']['namespace'].values())if dependency else 0),fixture_source_bytes=1024**2,case_staging_bytes=24*1024**2,baseline_raw_bytes=1024**3,prepared_raw_bytes=1024**3,baseline_allocated_bytes=1024**2,guest_filesystem_free_bytes=100*1024**2,guest_output_cap_bytes=1024**2,clone_allocated_cap_bytes=40*1024**2,readback_allocated_cap_bytes=40*1024**2,overlay_cap_bytes=10*1024**2,logs_cap_bytes=10*1024**2,reserve_bytes=1024**2,physical_free_bytes=200*1024**2,quota_initial_headroom_bytes=200*1024**2,quota_live_reserve_bytes=1024**2,guest_memory_bytes=128*1024**2,owner_memory_bytes=256*1024**2,host_reserve_bytes=1024**2,host_MemAvailable_bytes=512*1024**2,cpus=2,pids=128,prepare_seconds=120,boot_seconds=600,cleanup_seconds=60,boot_overhead_seconds=30,output_device=1,host_uid=os.getuid(),gpg_seconds=5,install_seconds=20,probe_wait_seconds=180,remove_seconds=20,run_seconds=10,sync_seconds=5,log_bytes=1024**2)
 # Resources require a positive ordinary UID; synthetic host may be root, never actor.
 r['host_uid']=1000
 r['quota_guard']=dict(issued_by='Root',method='READ_ONLY_Q_GETQUOTA',whole_actor=True,read_only=True,uid=1000,device=1,initial_headroom_bytes=r['quota_initial_headroom_bytes'],live_reserve_bytes=r['quota_live_reserve_bytes'],on_unknown_or_exhausted='HOLD_AND_OWNED_CLEANUP')
 d=dict(kind='ROOT_ACCEPTED_PERL5423_INPUT_FOR_VM_V1',issued_by='Root',accepted=True,operation=K.OP,accepted_for_vm_input=True,package_signature_authenticated=True)
 reader=K.load(HERE/'known/installed-Reader.json');installed=K.load(HERE/'known/installed-decision.json')
 return seal(c,b,rt,r,d,reader,installed)

def reseal(a):return seal(a[0],*a[2:])

class Controls(unittest.TestCase):
 def test_null_template_refuses(self):
  with self.assertRaises(ValueError):K.validate(K.load(HERE/'case.TEMPLATE.json'),{},None,None,None,None,None,None)
 def test_modeled_remove_and_rollback(self):
  for old in(False,True):self.assertEqual(K.validate(*modeled(old))['operation'],K.OP)
 def test_all_input_pins_are_required(self):
  for n in K.MATERIALS+K.EVIDENCE:
   a=modeled();(a[0]['package']if n in K.MATERIALS else a[0]['evidence'])[n]=None
   with self.subTest(n=n),self.assertRaises(ValueError):K.validate(*a)
 def test_producer_success_is_not_reader_or_root_acceptance(self):
  for n in('reader','Root','native','source'):
   a=modeled()
   if n=='reader':a[6]['status']='producerSUCCESS'
   if n=='Root':a[5]['accepted']=False
   if n=='native':a[0]['native']['run']='1'
   if n=='source':a[0]['source']['sha']='f'*40
   with self.subTest(n=n),self.assertRaises(ValueError):K.validate(*reseal(a))
 def test_dependency_and_recursive_elf_provider_refusals(self):
  for n in('dependency','soname','GNU','missing-provider','geometry','compiler','expanded-dep','hook-policy'):
   a=modeled();rt=a[3]
   if n=='dependency':rt['dependency_resolution']['gdbm>=1.17']['satisfied']=False
   if n=='soname':rt['elfs'][K.PERL_ELFS[4]]['needed']=[];rt['elfs'][K.PERL_ELFS[4]]['providers']={};rt['elfs'][K.PERL_ELFS[4]]['version_needs']={}
   if n=='GNU':rt['elfs'][K.PERL_ELFS[4]]['providers']['libz.so.1']['version_definitions']=[]
   if n=='missing-provider':del rt['elfs']['/usr/lib/libz.so.1']
   if n=='geometry':rt['elfs'][K.PERL_ELFS[0]]['static_16k_geometry']=False
   if n=='compiler':rt['probe_qualification']['compiler']=True
   if n=='expanded-dep':rt['alpm_dependencies'].remove('libcrypt.so=2-64')
   if n=='hook-policy':rt['effective_hook_policy']['transaction_same_effective_policy']=False
   with self.subTest(n=n),self.assertRaises(ValueError):K.validate(*reseal(a))
 def test_baseline_and_recovery_must_match(self):
  for n in('present','old-archive','db-policy','reasons','reverse'):
   a=modeled(n!='reverse');rt=a[3]
   if n=='present':rt['baseline_namespace']={}
   if n=='old-archive':rt['rollback']['archive']=None
   if n=='db-policy':rt['rollback']['local_database_policy']='IGNORE_ALL_DATABASE_CHANGES'
   if n=='reasons':rt['rollback']['reason']='guess'
   if n=='reverse':rt['reverse_dependencies']=['glibc']
   with self.subTest(n=n),self.assertRaises(ValueError):K.validate(*reseal(a))
 def test_namespace_escape_link_cycle_permissions_and_owner(self):
  for n in('escape','cycle','SUID','worldwrite','owner'):
   a=modeled();rt=a[3];ns=rt['candidate_namespace']
   if n=='escape':ns['/etc/passwd']=ns['/usr/bin/perl']
   if n=='cycle':ns['/usr/bin/json_pp']['link_target']='json_pp'
   if n=='SUID':ns['/usr/bin/perl']['mode']=0o4755
   if n=='worldwrite':ns['/usr/bin/perl']['mode']=0o777
   if n=='owner':rt['files']['/usr/bin/perl']['owner']='missing'
   with self.subTest(n=n),self.assertRaises(ValueError):K.validate(*reseal(a))
 def test_resource_sparse_peak_quota_ram_and_finite_envelopes(self):
  for n in('physical_free_bytes','quota_initial_headroom_bytes','guest_filesystem_free_bytes','host_MemAvailable_bytes','probe_wait_seconds','boot_seconds','clone_allocated_cap_bytes','case_staging_bytes'):
   a=modeled();a[4][n]=1
   with self.subTest(n=n),self.assertRaises(ValueError):K.validate(*reseal(a))
  a=modeled();a[4]['quota_guard']['whole_actor']=False
  with self.assertRaises(ValueError):K.validate(*reseal(a))
 def test_packet_is_strict_alpm_and_no_archive_copy(self):
  a=modeled();rows=A.contents(a[0],dict(zip(K.EVIDENCE,a[2:])),pin('source'), 'a'*32)
  self.assertNotIn(A.PKG,rows);self.assertIn(b'LocalFileSigLevel = Required TrustedOnly',rows['pacman.conf'][0]);self.assertNotIn(b'[core]',rows['pacman.conf'][0]);self.assertIn(b'recovery_mode=REMOVE',rows['case.env'][0]);self.assertEqual(len(rows['case.env'][0].splitlines()),15)
  self.assertIn(b'/usr/bin/perl',rows['elf-paths.tsv'][0]);self.assertNotIn(b'111',rows['expected-base.lock'][0])
 def test_static_elf_geometry(self):
  raw=bytearray(120);raw[:6]=b'\x7fELF\x02\x01';struct.pack_into('<HH',raw,16,2,183);struct.pack_into('<Q',raw,32,64);struct.pack_into('<HH',raw,54,56,1);struct.pack_into('<IIQQQQQQ',raw,64,1,5,0,0x400000,0,120,120,16384)
  self.assertEqual(F.elf(raw)['minimum_alignment'],16384)
  for offset,value in((112,4096),(80,0x400001)):
   bad=bytearray(raw);struct.pack_into('<Q',bad,offset,value)
   with self.assertRaises(ValueError):F.elf(bad)
 def test_duplicate_frame_and_hold_refuse(self):
  raw=('PERL5423_PROBE_BEGIN '+'a'*32+'\n'+''.join(k+'='+v+'\n'for k,v in P.PROBE.items())+'PERL5423_PROBE_END '+'a'*32+'\n').encode();self.assertEqual(P.validate_probe(P.frame(raw,'a'*32)),P.PROBE)
  with self.assertRaises(ValueError):P.frame(raw+raw,'a'*32)
  with self.assertRaises(ValueError):P.validate_probe(dict(P.PROBE,STATUS='HOLD'))
 def test_ownership_census_and_preservation_do_not_assume111(self):
  h=lambda b:hashlib.sha256(b.encode()).hexdigest()
  desc='%NAME%\nx\n\n%VERSION%\n1\n';files='%FILES%\nusr/bin/x\n';nodes={p:dict(type='file',mode=0o644,uid=0,gid=0,size=len(t),sha256=h(t))for p,t in [('var/lib/pacman/local/x-1/desc',desc),('var/lib/pacman/local/x-1/files',files)]};nodes['usr/bin/x']=dict(type='file',mode=0o755,uid=0,gid=0,sha256='a'*64)
  scan=dict(nodes=nodes,records={'var/lib/pacman/local/x-1/desc':desc,'var/lib/pacman/local/x-1/files':files});self.assertEqual(len(I.owners(scan,{'x':'1'})),1)
  after=copy.deepcopy(scan);after['nodes']['usr/bin/x']['sha256']='b'*64
  with self.assertRaises(ValueError):I.preserve(scan,after,{'x':'1'},modeled()[3])
 def test_no_actions_on_import_and_operational_fence(self):
  for n in('actor','runtime','controller','budget','image'):module(n)
  for event in('subprocess.Popen','socket.__new__','ctypes.dlopen','fcntl.flock'):
   with self.assertRaises(RuntimeError):sys.audit(event)
 def test_durable_actual_ELF_bytes_and_functional_receipt_joins(self):
  raw=bytearray(120);raw[:6]=b'\x7fELF\x02\x01';struct.pack_into('<HH',raw,16,2,183);struct.pack_into('<Q',raw,32,64);struct.pack_into('<HH',raw,54,56,1);struct.pack_into('<IIQQQQQQ',raw,64,1,5,0,0x400000,0,120,120,16384);raw=bytes(raw)
  for kind in('valid','functional','ELF','receipt','extra'):
   a=modeled();rt=a[3];inv=a[2]['inventory'];paths=[p for p in sorted(rt['elfs'])if rt['files'][p]['owner']=='perl']
   data={str(i)+'.elf':raw for i,p in enumerate(paths)}
   for p in paths:rt['files'][p]['sha256']=hashlib.sha256(raw).hexdigest()
   data.update({n:b'MODELED_COMMAND_OUTPUT\n'for n in F.LOGS});data['version.log']=b'v5.42.3\n';data['paths.log']=b'/usr/lib/perl5/5.42/core_perl/CORE/libperl.so\n';data['functional.log']=F.FUNCTIONAL
   manifest=''.join(str(i)+'.elf\t'+p+'\t'+rt['files'][p]['sha256']+'\n'for i,p in enumerate(paths)).encode()
   fields=dict(P.RESTORED,DB_POLICY='EXACT',BASE_SHA256=F.inventory_hash(inv),FINAL_SHA256=F.inventory_hash(inv),FUNCTIONAL_SHA256=hashlib.sha256(F.FUNCTIONAL).hexdigest(),ELF_MANIFEST_SHA256=hashlib.sha256(manifest).hexdigest(),HOST_BOOT_UTC='1794750000',GUEST_BEFORE_CRYPTO_UTC='1794750001',RTC_BEFORE_CRYPTO_UTC='1794750001')
   data['outputs.sha256']=''.join(hashlib.sha256(data[n]).hexdigest()+'  '+n+'\n'for n in sorted(n for n in data if n.endswith('.elf'))+sorted(F.LOGS)).encode()
   data['summary.env']=('PERL5423_RESTORED_BEGIN '+'a'*32+'\n'+''.join(k+'='+v+'\n'for k,v in fields.items())+'PERL5423_RESTORED_END '+'a'*32+'\n').encode()
   if kind=='functional':data['functional.log']=b'PASS_FAKE\n'
   if kind=='ELF':data['0.elf']=b'not an ELF'
   if kind=='receipt':data['summary.env']=data['summary.env'].replace(b'STATUS=PASS',b'STATUS=HOLD')
   if kind=='extra':data['unknown']=b'unreviewed'
   with tempfile.TemporaryDirectory()as tmp:
    root=Path(tmp)
    for n,body in data.items():(root/n).write_bytes(body);(root/n).chmod(0o600)
    if kind=='valid':
     result=F.outputs(root,fields,inv,rt,'a'*32,1794750000,1794750002,65536);self.assertIsNone(result['VM_acceptance']);self.assertIsNone(result['Root_acceptance'])
    else:
     with self.subTest(kind=kind),self.assertRaises(ValueError):F.outputs(root,fields,inv,rt,'a'*32,1794750000,1794750002,65536)
 def test_whole_actor_readonly_quota_guard_exhaustion_unknown_and_deadline(self):
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);r=modeled()[4];r.update(host_uid=os.getuid(),output_device=root.stat().st_dev,physical_free_bytes=1,host_reserve_bytes=1,host_MemAvailable_bytes=1,owner_memory_bytes=1)
   seen=[]
   def query(device,uid):seen.append((device,uid));return 10**12
   guard=Q.Guard(root,r,'/dev/MODELED',time.monotonic()+60,lambda *args,**kw:0,initial=True,query=query);guard(True);self.assertEqual(seen,[('/dev/MODELED',os.getuid())]);self.assertEqual(guard.samples,1)
   guard.query=lambda d,u:0
   with self.assertRaises(ValueError):guard(True)
   guard.query=lambda d,u:(_ for _ in ()).throw(OSError('MODELED quota unknown'))
   with self.assertRaises(OSError):guard(True)
   guard.deadline=time.monotonic()-1
   with self.assertRaises(TimeoutError):guard(True)
 def test_closed_fresh_root_authority_and_no_network_QEMU(self):
  now=int(time.time());sp=pin('Source');pp=pin('packet');out=Path('/PRIVATE/MODELED/output')
  auth=dict(kind='ROOT_PERL5423_VM_ACTOR_AUTHORITY_V1',issued_by='Root',accepted=True,operation=K.OP,phase='prepare',packet=pp,source_lock=sp,output=str(out),uid=1000,created_utc=now,expires_utc=now+100,image='sha256:'+'a'*64,docker_endpoint='unix:///run/user/1000/docker.sock',quota_device='/dev/MODELED',actor_tools={p:pin(p)for p in('/usr/bin/python3','/usr/bin/cp','/usr/bin/debugfs','/usr/bin/e2fsck','/usr/bin/qemu-img','/usr/bin/qemu-system-aarch64')},kernel={n:pin(n)for n in('Image','config')},credentials=None,prepared=None)
  with patch.object(C.os,'getuid',return_value=1000):
   C.authority(auth,'prepare',pp,sp,out,K)
   for n,value in [('accepted',False),('phase','boot'),('expires_utc',now-1),('docker_endpoint','tcp://remote:2375'),('uid',1001)]:
    bad=copy.deepcopy(auth);bad[n]=value
    with self.subTest(n=n),self.assertRaises(ValueError):C.authority(bad,'prepare',pp,sp,out,K)
  actor=module('actor');argv=actor.qemu_argv(dict(nonce='a'*32,baseline_nonce='b'*32),modeled()[4],now)
  self.assertEqual(argv[argv.index('-nic')+1],'none');self.assertEqual(argv[argv.index('-accel')+1],'tcg,thread=multi');self.assertNotIn('-enable-kvm',argv)
 def test_explicit_db53_dependency_addition_and_no_other_packages(self):
  a=modeled(dependency=True);K.validate(*a)
  rows=A.contents(a[0],dict(zip(K.EVIDENCE,a[2:])),pin('source'),'a'*32)
  self.assertIn(b'dependency_mode=DB53',rows['case.env'][0]);self.assertIn(b'db5.3 5.3.28-7',rows['expected-dependencies.lock'][0]);self.assertNotIn(b'db5.3',rows['expected-base.lock'][0])
  for kind in('archive','signature','provider','admission','unbounded-extra'):
   b=modeled(dependency=True);dep=b[3]['dependency_transaction']
   if kind=='archive':dep['archive']=pin('wrong')
   if kind=='signature':dep['signature']=None
   if kind=='provider':dep['resolution']['libgcc']['providers']=[]
   if kind=='admission':dep['current_trust_reviewed']=False
   if kind=='unbounded-extra':dep['name']='other'
   with self.subTest(kind=kind),self.assertRaises(ValueError):K.validate(*reseal(b))
 def test_normal_rollback_timestamp_allowance_and_unrelated_drift_refusals(self):
  def fixture():
   old='5.42.3-1';desc='%NAME%\nperl\n\n%VERSION%\n'+old+'\n\n%INSTALLDATE%\n1794759672\n\n%REASON%\n0\n';files='%FILES%\nusr/bin/perl\n'
   db='var/lib/pacman/local/perl-'+old
   def file(raw):return dict(type='file',mode=0o644,uid=0,gid=0,mtime=1,mtime_ns=0,size=len(raw),sha256=hashlib.sha256(raw.encode()).hexdigest())
   nodes={p:dict(type='directory',mode=0o755,uid=0,gid=0,mtime=1,mtime_ns=0)for p in('usr','usr/bin','etc','root','home/builder','var/lib/pacman/local',db)}
   nodes.update({'usr/bin/perl':file('MODEL_PERL'),'etc/passwd':file('MODEL_ACCOUNT'),'home/builder/custom':file('MODEL_USER'),db+'/desc':file(desc),db+'/files':file(files),'var/lib/pacman/local/ALPM_DB_VERSION':file('9\n'),'var/log/pacman.log':file('original\n')})
   import base64
   before=dict(nodes=nodes,records={db+'/desc':desc,db+'/files':files},log_data_b64=base64.b64encode(b'original\n').decode());after=copy.deepcopy(before)
   after['records'][db+'/desc']=desc.replace('1794759672','1794759724');after['nodes'][db+'/desc']=file(after['records'][db+'/desc'])
   for p in('usr','usr/bin','var/lib/pacman/local',db,db+'/desc',db+'/files'):after['nodes'][p]['mtime']=2
   after['nodes']['var/log/pacman.log']=file('original\nappend\n');after['log_data_b64']=base64.b64encode(b'original\nappend\n').decode()
   return before,after,db
  for kind in('valid','payload','database','user','account','log','file-time','unrelated-db-time','extra-db-node'):
   before,after,db=fixture();rt=modeled(True)[3];rt['restoration_allowances']['pacman_log_before']=dict(bytes=9,sha256=hashlib.sha256(b'original\n').hexdigest())
   if kind=='payload':after['nodes']['usr/bin/perl']['sha256']='a'*64
   if kind=='database':after['records'][db+'/desc']=after['records'][db+'/desc'].replace('%REASON%\n0','%REASON%\n1');after['nodes'][db+'/desc']['sha256']=hashlib.sha256(after['records'][db+'/desc'].encode()).hexdigest()
   if kind=='user':after['nodes']['home/builder/custom']['sha256']='a'*64
   if kind=='account':after['nodes']['etc/passwd']['sha256']='a'*64
   if kind=='log':after['log_data_b64']='dHJ1bmNhdGVk'
   if kind=='file-time':after['nodes']['usr/bin/perl']['mtime']=99
   if kind=='unrelated-db-time':after['nodes']['var/lib/pacman/local/ALPM_DB_VERSION']['mtime']=99
   if kind=='extra-db-node':after['nodes'][db+'/unreviewed']=copy.deepcopy(after['nodes'][db+'/files'])
   if kind=='valid':
    result=I.preserve(before,after,{'perl':'5.42.3-1'},rt);self.assertEqual(result['normal_install_date']['original_install_date'],'1794759672');self.assertEqual(result['normal_install_date']['final_install_date'],'1794759724');self.assertEqual(result['account_user_residuals'],[])
   else:
    with self.subTest(kind=kind),self.assertRaises(ValueError):I.preserve(before,after,{'perl':'5.42.3-1'},rt)
 def test_exact_hardlink_contract_and_nondecimal_install_dates_refuse(self):
  a=modeled();a[3]['hardlinks']={}
  with self.assertRaises(ValueError):K.validate(*reseal(a))
  n=module('restoration')
  for raw in(b'%INSTALLDATE%\nNOT_A_DATE\n',b'%INSTALLDATE%\n123\n%INSTALLDATE%\n456\n'):
   with self.assertRaises(ValueError):n.normalize_desc(raw)
 def test_material_reference_map_uses_individual_original_paths(self):
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);mapping={n:str(root/('separate-'+n)/name)for n,name in A.NAMES.items()}
   path=root/'material-paths.json';path.write_bytes(K.canonical(mapping))
   self.assertEqual({n:str(p)for n,p in A.material_paths(path).items()},mapping)
   mapping['unapproved']='https://network.invalid/archive';path.write_bytes(K.canonical(mapping))
   with self.assertRaises(ValueError):A.material_paths(path)
 def test_source_syntax(self):
  for p in HERE.rglob('*.py'):ast.parse(p.read_bytes())
 def test_closed_source_lock(self):
  digest=K.pin(HERE/'source.lock.json')['sha256'];self.assertEqual(A.source(digest)['sha256'],digest)
  with self.assertRaises(ValueError):A.source('0'*64)
if __name__=='__main__':unittest.main(verbosity=2)

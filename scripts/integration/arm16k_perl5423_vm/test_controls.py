# SPDX-License-Identifier: MIT
"""Fenced synthetic DATA only. Never Docker, VM, GPG, ALPM, compiler or network."""
import ast,copy,ctypes,hashlib,importlib.util,json,os,struct,sys,tempfile,time,unittest
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
 d.update(input_kind=rt['kind'],source=c['source'],native=c['native'],package=c['package'],trust=c['trust'],evidence={n:c['evidence'][n]for n in K.EVIDENCE if n!='Root_decision'})
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
 if dependency:inv['archlinuxarm-keyring']='MODEL-1'
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
  public_files={p:entry(p,'archlinuxarm-keyring',0o644)for p in K.ALARM_FILES};files.update(public_files);baseline_files.update(copy.deepcopy(public_files))
  official=dict(kind='ROOT_REVIEWED_SCRATCH_ALARM_PUBLIC_TRUST_V1',signer=K.ALARM_SIGNER,files=public_files,trusted_policy_reviewed=True,revoked_signer_absent=True,ownertrust_policy='ROOT_ADMITTED_SIGNER_ONLY_NO_BULK_OWNERTRUST_IMPORT',scratch_home='/run/arm16k-perl5423-vm/official-trust',baseline_global_gpgdir='ABSENT')
  db=providers['db5.3'];row=files[db];nsdep={'/usr':dict(kind='d',mode=0o755,uid=0,gid=0),'/usr/lib':dict(kind='d',mode=0o755,uid=0,gid=0),db:dict(kind='f',mode=row['mode'],uid=0,gid=0,bytes=row['bytes'],sha256=row['sha256'])}
  rt['dependency_transaction']=dict(K.DB53,namespace=nsdep,files={db:row},elf_paths=[db],full_ELF_coverage=True,requires=['libgcc','libstdc++','sh'],resolution={n:dict(owner='base-tools',version=inv['base-tools'],satisfied=True,providers=['/usr/bin/bash'])for n in('libgcc','libstdc++','sh')},baseline_public_trust=pin('actual-public-official-trust-namespace'),official_trust=official,signature_authenticated=True,current_trust_reviewed=True,recovery='NORMAL_REMOVE_AFTER_PERL_RECOVERY')
 r={n:1 for n in K.LIMITS};r.update(kind='ROOT_REVIEWED_PERL5423_VM_RESOURCES_V1',issued_by='Root',accepted=True,baseline_certificate=None,package=None,package_expanded_bytes=sum(v.get('bytes',0)for v in ns.values())+(sum(v.get('bytes',0)for v in rt['dependency_transaction']['namespace'].values())if dependency else 0),fixture_source_bytes=1024**2,case_staging_bytes=24*1024**2,baseline_raw_bytes=1024**3,prepared_raw_bytes=1024**3,baseline_allocated_bytes=1024**2,guest_filesystem_free_bytes=100*1024**2,guest_output_cap_bytes=1024**2,clone_allocated_cap_bytes=40*1024**2,readback_allocated_cap_bytes=40*1024**2,overlay_cap_bytes=10*1024**2,logs_cap_bytes=10*1024**2,reserve_bytes=1024**2,physical_free_bytes=200*1024**2,quota_initial_headroom_bytes=200*1024**2,quota_live_reserve_bytes=1024**2,guest_memory_bytes=128*1024**2,owner_memory_bytes=256*1024**2,host_reserve_bytes=1024**2,host_MemAvailable_bytes=512*1024**2,cpus=2,pids=128,prepare_seconds=120,boot_seconds=600,cleanup_seconds=60,boot_overhead_seconds=30,output_device=1,host_uid=os.getuid(),gpg_seconds=5,install_seconds=20,probe_wait_seconds=180,remove_seconds=20,run_seconds=10,sync_seconds=5,log_bytes=1024**2)
 # Resources require a positive ordinary UID; synthetic host may be root, never actor.
 r['host_uid']=1000
 r['quota_guard']=dict(issued_by='Root',method='READ_ONLY_Q_GETQUOTA',whole_actor=True,read_only=True,uid=1000,device=1,initial_headroom_bytes=r['quota_initial_headroom_bytes'],live_reserve_bytes=r['quota_live_reserve_bytes'],on_unknown_or_exhausted='HOLD_AND_OWNED_CLEANUP')
 d=dict(kind='ROOT_ACCEPTED_PERL5423_INPUT_FOR_VM_V1',issued_by='Root',accepted=True,operation=K.OP,accepted_for_vm_input=True,package_signature_authenticated=True)
 reader=K.load(HERE/'known/installed-Reader.json');installed=K.load(HERE/'known/installed-decision.json')
 return seal(c,b,rt,r,d,reader,installed)

def reseal(a):return seal(a[0],*a[2:])

def modeled_home():
 a=modeled();r=a[4];q=K.load(HERE/'home-storage-guard.TEMPLATE.json');now=int(time.time())
 q.update(outputs=dict(prepare='/home/gabe/MODEL/prepare',boot='/home/gabe/MODEL/boot'),source_lock=pin('modeled-controller-source'),created_utc=now-1,expires_utc=now+300)
 r.update(host_uid=1000,output_device=54,quota_initial_headroom_bytes=None,quota_live_reserve_bytes=None,quota_guard=q)
 return reseal(a)

class Controls(unittest.TestCase):
 def test_actual_scope_name_capture_survives_material_loop_name_rebinding(self):
  import types
  source=ast.parse((HERE/'controller.py').read_bytes());node=next(n for n in ast.walk(source)if isinstance(n,ast.ClassDef)and n.name=='Scope');name='cachy-perl5423-a9b3e6c2974deadcf05ed9a5';labels={'MODEL':'LABEL'};mounts={('bind','/MODEL','/work',True)};r=modeled()[4]
  ns=dict(B=types.SimpleNamespace(OwnedContainer=object),K=K,name=name,auth=dict(image='sha256:'+'a'*64),labels=labels,mounts=mounts,r=r,a=types.SimpleNamespace(phase='prepare'))
  exec(compile(ast.Module(body=[node],type_ignores=[]),'<actual-Scope-source>','exec'),ns);scope=ns['Scope']()
  row=dict(Name='/'+name,Image=ns['auth']['image'],Config=dict(Labels=labels,Entrypoint=['/usr/bin/python3'],Cmd=['-I','-B','/code/actor.py','prepare']),Mounts=[dict(Type='bind',Source='/MODEL',Destination='/work',RW=True)],HostConfig=dict(ReadonlyRootfs=True,NetworkMode='none',CapDrop=['ALL'],CapAdd=[],Privileged=False,Devices=[],Init=False,SecurityOpt=['no-new-privileges'],Memory=r['owner_memory_bytes'],MemorySwap=r['owner_memory_bytes'],NanoCpus=r['cpus']*10**9,PidsLimit=r['pids']))
  scope.validate(row);ns['name']='signing_receipt';scope.validate(row)
  for bad in(dict(row,Name='/signing_receipt'),dict(row,Name='/cachy-perl5423-WRONG'),dict(row,Image='sha256:'+'b'*64)):
   with self.assertRaises(ValueError):scope.validate(bad)
 def test_actual_PT_INTERP_alias_pair_requires_same_loader_and_observed_alias(self):
  canonical='/usr/lib/ld-linux-aarch64.so.1';alias='/lib/ld-linux-aarch64.so.1';baseline={'glibc':'ACTUAL-VERSION-MODEL','filesystem':'ACTUAL-FS-MODEL'};row=dict(bytes=201832,sha256='a'*64,mode=0o755,owner='glibc',version=baseline['glibc'],resolved=canonical)
  value=dict(loader=alias,files={alias:copy.deepcopy(row),canonical:copy.deepcopy(row)},baseline_files={alias:copy.deepcopy(row),canonical:copy.deepcopy(row)},expected_payload=dict(aliases={'/lib':dict(target='usr/lib',owner='filesystem',version=baseline['filesystem'],mode=0o777,uid=0,gid=0)}))
  self.assertTrue(K.interpreter_matches(value,canonical,baseline));self.assertTrue(K.interpreter_matches(value,alias,baseline));self.assertTrue(K.interpreter_matches(value,None,baseline))
  reverse=copy.deepcopy(value);reverse['loader']=canonical;self.assertTrue(K.interpreter_matches(reverse,alias,baseline))
  for kind in('target','hash','bytes','mode','owner','version','missing-alias','wrong-alias','alias-owner','alias-version','missing-file','missing-baseline','arbitrary','double-slash'):
   bad=copy.deepcopy(value);interpreter=canonical
   if kind in('target','hash','bytes','mode','owner','version'):
    key={'target':'resolved','hash':'sha256'}.get(kind,kind);bad['files'][canonical][key]={'target':'/usr/lib/wrong.so','hash':'b'*64,'bytes':1,'mode':0o644,'owner':'filesystem','version':'OTHER'}[kind]
   if kind=='missing-alias':bad['expected_payload']['aliases']={}
   if kind=='wrong-alias':bad['expected_payload']['aliases']['/lib']['target']='usr/other'
   if kind=='alias-owner':bad['expected_payload']['aliases']['/lib']['owner']='glibc'
   if kind=='alias-version':bad['expected_payload']['aliases']['/lib']['version']='OTHER'
   if kind=='missing-file':del bad['files'][canonical]
   if kind=='missing-baseline':del bad['baseline_files'][canonical]
   if kind=='arbitrary':interpreter='/tmp/ld-linux-aarch64.so.1'
   if kind=='double-slash':interpreter='//usr/lib/ld-linux-aarch64.so.1'
   with self.subTest(kind=kind),self.assertRaises(ValueError):K.interpreter_matches(bad,interpreter,baseline)
 def test_official_scratch_trust_certificate_packet_and_finite_gpg_envelope(self):
  a=modeled(dependency=True);K.validate(*a);rows=A.contents(a[0],dict(zip(K.EVIDENCE,a[2:])),pin('source'),'a'*32)
  conf=rows['dependency-pacman.conf'][0];self.assertIn(b'GPGDir = /run/arm16k-perl5423-vm/official-trust',conf);self.assertNotIn(b'GPGDir = /etc/pacman.d/gnupg',conf);self.assertIn(b'Required TrustedOnly',conf);self.assertEqual(len(rows['official-public-files.tsv'][0].splitlines()),3);self.assertEqual(rows['official-signer'][0],(K.ALARM_SIGNER+'\n').encode());self.assertIn('official-trust.sh',rows)
  for kind in('signer','review','revoked','bulk','global','home','missing-file','file-mode'):
   b=modeled(dependency=True);trust=b[3]['dependency_transaction']['official_trust']
   if kind=='signer':trust['signer']='A'*40
   if kind=='review':trust['trusted_policy_reviewed']=False
   if kind=='revoked':trust['revoked_signer_absent']=False
   if kind=='bulk':trust['ownertrust_policy']='IMPORT_ALL_TRUSTED'
   if kind=='global':trust['baseline_global_gpgdir']='PRESENT'
   if kind=='home':trust['scratch_home']='/etc/pacman.d/gnupg'
   if kind=='missing-file':del trust['files'][K.ALARM_FILES[-1]]
   if kind=='file-mode':trust['files'][K.ALARM_FILES[0]]['mode']=0o600
   with self.subTest(kind=kind),self.assertRaises(ValueError):K.validate(*reseal(b))
  a[4].update(gpg_seconds=15,install_seconds=60,remove_seconds=60,run_seconds=10,sync_seconds=10,cleanup_seconds=90,boot_overhead_seconds=120,probe_wait_seconds=240,boot_seconds=900)
  with self.assertRaises(ValueError):K.validate(*reseal(a))
  a[4]['boot_seconds']=1200;K.validate(*reseal(a))
  self.assertNotIn('cmp',K.TOOLS)
  for p in(HERE/'guest').glob('*.sh'):self.assertNotIn('cmp --',p.read_text())
 def test_absent_pacman_log_restored_with_retained_transaction_log_only(self):
  import base64
  rt=modeled()[3];rt['restoration_allowances']['pacman_log_before']=None
  desc='%NAME%\nx\n\n%VERSION%\n1\n';files='%FILES%\nusr/bin/x\nvar/log/\n';h=lambda b:hashlib.sha256(b).hexdigest();data=b'normal ALPM transaction log\n';receipt='var/lib/arm16k-perl5423-vm/receipts/pacman-log-after'
  nodes={'usr/bin/x':dict(type='file',mode=0o755,uid=0,gid=0,sha256='a'*64),'var/log':dict(type='directory',mode=0o755,uid=0,gid=0,mtime=1,mtime_ns=0)};records={'var/lib/pacman/local/x-1/desc':desc,'var/lib/pacman/local/x-1/files':files}
  for p,text in records.items():nodes[p]=dict(type='file',mode=0o644,uid=0,gid=0,sha256=h(text.encode()))
  before=dict(nodes=nodes,records=records,log_data_b64=None);valid=copy.deepcopy(before);valid['nodes']['var/log']['mtime']=2;valid['nodes'][receipt]=dict(type='file',mode=0o600,uid=0,gid=0,size=len(data),sha256=h(data));valid['retained_log_data_b64']=base64.b64encode(data).decode()
  for kind in('valid','left-log','missing-receipt','owner','mode','hash','extra-log'):
   after=copy.deepcopy(valid)
   if kind=='left-log':after['nodes']['var/log/pacman.log']=after['nodes'][receipt]
   if kind=='missing-receipt':after['retained_log_data_b64']=None
   if kind=='owner':after['nodes'][receipt]['uid']=1000
   if kind=='mode':after['nodes'][receipt]['mode']=0o644
   if kind=='hash':after['nodes'][receipt]['sha256']='b'*64
   if kind=='extra-log':after['nodes']['var/log/unrelated']=after['nodes'][receipt]
   if kind=='valid':self.assertEqual(I.preserve(before,after,{'x':'1'},rt)['pacman_log'],'ABSENCE_RESTORED_WITH_RETAINED_NORMAL_TRANSACTION_LOG')
   else:
    with self.subTest(kind=kind),self.assertRaises(ValueError):I.preserve(before,after,{'x':'1'},rt)
 def test_Tool529_e2fsck_four_links_only_and_generic_DATA_stays_single_link(self):
  import types
  R=module('runtime')
  with tempfile.TemporaryDirectory()as tmp:
   p=Path(tmp)/'synthetic-tool';p.write_bytes(b'MODELED_TOOL_BYTES_NOT_EXECUTED');actual=p.lstat();base={n:getattr(actual,n)for n in('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')};base.update(st_mode=0o100755,st_uid=0,st_gid=0,st_nlink=4);fakeK=types.SimpleNamespace(ordinary=lambda p:p,need=K.need,END=None)
   for kind in('e2fsck-four','e2fsck-one','python-one','other-four','wrong-owner','wrong-mode','wrong-type','changed'):
    values=dict(base);name='/usr/bin/e2fsck'
    if kind in('e2fsck-one','python-one'):values['st_nlink']=1
    if kind=='python-one':name='/usr/bin/python3'
    if kind=='other-four':name='/usr/bin/cp'
    if kind=='wrong-owner':values['st_uid']=1000
    if kind=='wrong-mode':values['st_mode']=0o100777
    if kind=='wrong-type':values['st_mode']=0o120755
    first=types.SimpleNamespace(**values);last=types.SimpleNamespace(**dict(values,st_ino=values['st_ino']+1))if kind=='changed'else first
    with patch.object(R,'module',return_value=fakeK),patch.object(R.Path,'resolve',return_value=p),patch.object(R.Path,'lstat',return_value=first),patch.object(R.os,'fstat',side_effect=[first,last]):
     if kind in('e2fsck-four','e2fsck-one','python-one'):self.assertEqual(R.image_tool_pin(name),dict(bytes=len(b'MODELED_TOOL_BYTES_NOT_EXECUTED'),sha256=hashlib.sha256(b'MODELED_TOOL_BYTES_NOT_EXECUTED').hexdigest()))
     else:
      with self.subTest(kind=kind),self.assertRaises(ValueError):R.image_tool_pin(name)
   link=p.with_name('hardlink');os.link(p,link)
   with self.assertRaises(ValueError):K.pin(p)
  self.assertNotIn('--sig-proxy=false',(HERE/'controller.py').read_text())
 def test_strict_SHM_syscall443_FD_backend_and_unchanged_headroom_policy(self):
  import types
  for kind in('valid','hard-only','soft-only','exhausted','no-limits','invalid-mask','ENOSYS','EPERM','ENOTBLK'):
   calls=[];number={'ENOSYS':38,'EPERM':1,'ENOTBLK':15}.get(kind,0);saved_errno={}
   def syscall(*args):
    calls.append(tuple(v.value for v in args[:4]));q=args[4]._obj;self.assertEqual(ctypes.sizeof(q),72);self.assertEqual(type(q).valid.offset,64)
    q.bhard=0 if kind in('soft-only','no-limits')else 100;q.bsoft=0 if kind in('hard-only','no-limits')else 80;q.curspace=90*1024 if kind=='exhausted'else 1024;q.valid=1 if kind=='invalid-mask'else 63
    ctypes.set_errno(number);return -1 if number else 0
   class Fake:
    def __call__(self,*args):return syscall(*args)
   native=types.SimpleNamespace(syscall=Fake())
   with patch.object(ctypes,'CDLL',return_value=native)as loader,patch.object(ctypes,'set_errno',side_effect=lambda n:saved_errno.update(value=n)),patch.object(ctypes,'get_errno',side_effect=lambda:saved_errno['value']),patch.object(Q.os,'fstat',return_value=types.SimpleNamespace(st_mode=0o40700)),patch.object(Q.os,'getuid',return_value=1000),patch.object(Q.platform,'system',return_value='Linux'),patch.object(Q.platform,'machine',return_value='x86_64'):
    if number:
     with self.assertRaises(OSError)as error:Q.quota_fd(23,1000)
     self.assertEqual(error.exception.errno,number)
    elif kind in('no-limits','invalid-mask'):
     with self.assertRaises(ValueError):Q.quota_fd(23,1000)
    else:self.assertEqual(Q.quota_fd(23,1000),0 if kind=='exhausted'else (100 if kind=='hard-only'else 80)*1024-1024)
    loader.assert_called_once_with(None,use_errno=True)
   self.assertEqual(calls,[(443,23,0x80000700,1000)])
  with patch.object(ctypes,'CDLL')as loader,patch.object(Q.os,'getuid',return_value=1000),patch.object(Q.os,'fstat',return_value=types.SimpleNamespace(st_mode=0o40700)),patch.object(Q.platform,'machine',return_value='aarch64'):
   with self.assertRaises(ValueError):Q.quota_fd(23,1000)
   with self.assertRaises(ValueError):Q.quota_fd(23,1001)
   loader.assert_not_called()
 def test_strict_SHM_mount_directory_FD_walk_close_and_no_legacy_query(self):
  opened=[];closed=[]
  def open_fd(path,flags,**kw):opened.append((path,flags,kw));return 10+len(opened)
  with patch.object(Q.os,'open',side_effect=open_fd),patch.object(Q.os,'close',side_effect=closed.append),patch.object(Q,'quota_fd',return_value=12345)as query:
   self.assertEqual(Q.quota('/dev/shm',1000),12345);query.assert_called_once_with(13,1000)
  flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC;self.assertEqual(opened,[('/',flags,{}),('dev',flags,dict(dir_fd=11)),('shm',flags,dict(dir_fd=12))]);self.assertEqual(closed,[11,12,13])
  for number in(1,15,38):
   closed=[]
   with patch.object(Q.os,'open',side_effect=[11,12,13]),patch.object(Q.os,'close',side_effect=closed.append),patch.object(Q,'quota_fd',side_effect=OSError(number,'MODELED backend HOLD')):
    with self.assertRaises(OSError):Q.quota('/dev/shm',1000)
   self.assertEqual(closed,[11,12,13])
  for path in('/dev/../shm','/dev//shm','/dev/shm/','relative','/dev/shm\0'):
   with patch.object(Q.os,'open')as opening:
    with self.assertRaises(ValueError):Q.quota(path,1000)
    opening.assert_not_called()
  self.assertNotIn('.quotactl(', (HERE/'budget.py').read_text());self.assertIn('ctypes.c_long(443)',(HERE/'home_btrfs.py').read_text());self.assertNotIn('.quotactl(', (HERE/'home_btrfs.py').read_text())
 def test_HOME_explicit_profile_acceptance_and_SHM_branch_unchanged(self):
  H=module('home_btrfs');a=modeled_home();self.assertEqual(K.validate(*a)['operation'],K.OP)
  for old in(False,True):self.assertEqual(K.validate(*modeled(old))['operation'],K.OP)
  for kind in('numeric-quota','EPERM','other-fs','other-device','other-uid','unlimited','reservation','source','expired','mode','inode-model','node-cap','physical','RAM'):
   b=modeled_home();r=b[4];q=r['quota_guard']
   if kind=='numeric-quota':r['quota_initial_headroom_bytes']=1
   if kind=='EPERM':q['quota_query']['errno']=1
   if kind=='other-fs':q['filesystem']['fstype']='tmpfs'
   if kind=='other-device':q['device']=55
   if kind=='other-uid':q['uid']=1001
   if kind=='unlimited':q['quota_query']['status']='UNLIMITED'
   if kind=='reservation':q['capacity_reservation']=True
   if kind=='source':q['source_lock']=None
   if kind=='expired':q['created_utc']=1;q['expires_utc']=2
   if kind=='mode':q['method']='UNKNOWN'
   if kind=='inode-model':q['inode_counters']='UNLIMITED'
   if kind=='node-cap':q['output_node_cap']=150001
   if kind=='physical':r['physical_free_bytes']=1
   if kind=='RAM':r['host_MemAvailable_bytes']=1
   with self.subTest(kind=kind),self.assertRaises(ValueError):K.validate(*reseal(b))
  strict=modeled();strict[4]['quota_initial_headroom_bytes']=strict[4]['quota_live_reserve_bytes']=None
  with self.assertRaises(ValueError):K.validate(*reseal(strict))
 def test_HOME_capacity_ENOSYS_inode_and_mount_semantics_pure(self):
  H=module('home_btrfs');r=modeled_home()[4];fs=dict(blocks=1000000,bfree=900000,bavail=800000,frsize=4096,files=0,ffree=0,favail=0)
  self.assertEqual(H.capacity(fs,r,True),'UNREPORTED');reported=dict(fs,files=100000,ffree=50000,favail=40000);self.assertEqual(H.capacity(reported,r,True),'REPORTED')
  for bad in(dict(fs,files=100),dict(fs,frsize=0),dict(fs,bavail=1),dict(fs,bfree=0),dict(reported,favail=1),dict(reported,favail=50001)):
   with self.assertRaises(ValueError):H.capacity(bad,r,True)
  row='42 1 0:33 /@home /home rw - btrfs /dev/MODELED rw,subvolid=257,subvol=/@home\n';self.assertEqual(H.mountinfo(row,42)['subvolume'],'/@home')
  for bad in(row.replace('btrfs','tmpfs'),row.replace('0:33','0:54'),row.replace('0:33','0:34'),row.replace('/@home','/@root'),row.replace('257','258'),row+row):
   with self.assertRaises(ValueError):H.mountinfo(bad,42)
  with self.assertRaises(ValueError):H.mountinfo(row,43)
 def test_HOME_retained_kernel_mount_and_userspace_fstat_domains_separate(self):
  H=module('home_btrfs');row='62 40 0:33 /@home /home rw,noatime shared:169 - btrfs /dev/nvme0n1p6 rw,compress=zstd:1,ssd,discard=async,space_cache=v2,subvolid=257,subvol=/@home'
  with patch.object(H.os,'major',side_effect=AssertionError('must not derive kernel identity')),patch.object(H.os,'minor',side_effect=AssertionError('must not derive kernel identity')):
   observed=H.mountinfo(row,62);self.assertEqual(observed['device'],54);self.assertEqual(observed['kernel_mount_device'],'0:33')
  a=modeled_home();self.assertEqual(K.validate(*a)['operation'],K.OP)
  for key,value in(('device',33),('kernel_mount_device','0:54')):
   bad=modeled_home();bad[4]['quota_guard']['filesystem'][key]=value
   with self.subTest(key=key),self.assertRaises(ValueError):K.validate(*reseal(bad))
  with patch.object(H,'proc_read',side_effect=['pos:\t0\nmnt_id:\t62\nino:\t59258250\n',row]):self.assertEqual(H.mounted(17)['mount_id'],62)
 def test_HOME_sample_brackets_capacity_and_holds_every_other_error(self):
  import types
  H=module('home_btrfs');r=modeled_home()[4];q=r['quota_guard'];root=Path(q['outputs']['prepare']);st=types.SimpleNamespace(st_dev=54,st_ino=7,st_mode=0o40700,st_uid=1000,st_gid=1000);fs=dict(blocks=1000000,bfree=900000,bavail=800000,frsize=4096,files=0,ffree=0,favail=0);mount=dict(mount_id=42)
  for kind in('valid','EPERM','EIO','supported','late-error','low-bytes','changed-inodes','unknown-fs','wrong-fstat','allocation','node-limit','expired','wrong-Source','wrong-output'):
   seen=[];closed=[];r=modeled_home()[4];q=r['quota_guard'];source=q['source_lock'];phase='prepare';end=time.monotonic()+60
   def query(fd):
    seen.append(fd)
    if kind=='EPERM':return -1,1
    if kind=='EIO':raise OSError(5,'MODELED unknown query')
    if kind=='supported':return 0,0
    if kind=='late-error'and len(seen)>1:return -1,1
    return -1,38
   samples=[]
   def filesystem(fd):
    samples.append(fd)
    if kind=='low-bytes':return dict(fs,bavail=1)
    if kind=='changed-inodes'and len(samples)>1:return dict(fs,files=100000,ffree=50000,favail=40000)
    return dict(fs)
   def allocation(*args,**kw):
    if kind=='node-limit':raise ValueError('MODELED actual runtime census node bound')
    return 2**63 if kind=='allocation'else 1234
   def mounted(fd):
    if kind=='unknown-fs':raise ValueError('MODELED unknown mount')
    return mount
   if kind=='expired':q['created_utc']=1;q['expires_utc']=2
   if kind=='wrong-Source':source=pin('wrong-Source')
   if kind=='wrong-output':phase='boot'
   with patch.object(H.os,'fstat',return_value=types.SimpleNamespace(**dict(st.__dict__,st_dev=33))if kind=='wrong-fstat'else st),patch.object(H.os,'getuid',return_value=1000),patch.object(H.os,'geteuid',return_value=1000),patch.object(H.os,'close',side_effect=closed.append),patch.object(H.Path,'lstat',return_value=st):
    args=(root,r,source,phase,True,end,allocation);kwargs=dict(query=query,fs_query=filesystem,mount_query=mounted,opener=lambda path:10 if path=='/home/gabe'else 11)
    if kind=='valid':
     result=H.sample(*args,**kwargs);self.assertEqual(seen,[10,10]);self.assertEqual(len(samples),2);self.assertEqual(result['own_uid_quota'],'UNSUPPORTED_NOT_UNLIMITED');self.assertEqual(result['filesystem_inode_counters'],'UNREPORTED');self.assertFalse(result['capacity_reservation']);self.assertEqual(result['allocated_bytes'],1234)
    else:
     with self.subTest(kind=kind),self.assertRaises((ValueError,OSError)):H.sample(*args,**kwargs)
   if seen:self.assertEqual(closed,[11,10])
 def test_HOME_guard_preserves_memory_deadline_and_prepare_boot_bindings(self):
  r=modeled_home()[4];q=r['quota_guard'];root=Path(q['outputs']['prepare']);source=q['source_lock'];st=type('S',(),dict(st_dev=54))
  guard=Q.Guard(root,r,None,time.monotonic()+60,lambda *a,**k:0,initial=True,source=source,phase='prepare');guard.home.sample=lambda *a,**k:dict(status='PASS_FILESYSTEM_CAPACITY_ONLY')
  with patch.object(Q.os,'getuid',return_value=1000),patch.object(Q.Path,'stat',return_value=st),patch.object(Q.Path,'read_text',return_value='MemAvailable: 100000000 kB\n'):
   guard(True);self.assertEqual(guard.samples,1)
  with patch.object(Q.os,'getuid',return_value=1000),patch.object(Q.Path,'stat',return_value=st),patch.object(Q.Path,'read_text',return_value='MemAvailable: 1 kB\n'):
   with self.assertRaisesRegex(ValueError,'host RAM reserve exhausted'):guard(True)
  for uid,device in((1001,54),(1000,55)):
   with patch.object(Q.os,'getuid',return_value=uid),patch.object(Q.Path,'stat',return_value=type('S',(),dict(st_dev=device))),patch.object(guard.home,'sample')as sample:
    with self.subTest(uid=uid,device=device),self.assertRaisesRegex(ValueError,'actual quota UID/device differs'):guard(True)
    sample.assert_not_called()
  guard.deadline=time.monotonic()-1
  with self.assertRaises(TimeoutError):guard(True)
  for phase in('prepare','boot'):Q.Guard(Path(q['outputs'][phase]),r,None,time.monotonic()+60,lambda *a,**k:0,source=source,phase=phase)
  with self.assertRaises(ValueError):Q.Guard(root,r,'/dev/MODELED',time.monotonic()+60,lambda *a,**k:0,source=source,phase='prepare')
  with self.assertRaises(ValueError):Q.Guard(root,r,None,time.monotonic()+60,lambda *a,**k:0,source=source,phase='boot')
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
  for n in('actor','runtime','controller','budget','image','baseline_observer','home_btrfs'):module(n)
  for event in('subprocess.Popen','socket.__new__','ctypes.dlopen','fcntl.flock'):
   with self.assertRaises(RuntimeError):sys.audit(event)
 def test_retained_alpm_literal_ownership_keys_and_exact_empty_records(self):
  cases=K.load(HERE/'known/alpm-ownership-cases.json')['cases'];records={};nodes={};inventory={}
  for row in cases:
   inventory[row['name']]=row['version'];base='var/lib/pacman/local/'+row['name']+'-'+row['version']+'/'
   records[base+'desc']='%NAME%\n'+row['name']+'\n\n%VERSION%\n'+row['version']+'\n';records[base+'files']=row['files']
   self.assertEqual(I.owned_paths(row['files']),row['selected_keys'])
   for p in row['selected_keys']:nodes[p]=dict(type='file',mode=0o644,uid=0,gid=0,sha256='a'*64)
  scan=dict(nodes=nodes,records=records);owned=I.owners(scan,inventory);self.assertEqual(set(owned),set(nodes))
  self.assertIn('usr/bin/[',owned);self.assertIn('usr/lib/systemd/system/system-systemd\\x2dcryptsetup.slice',owned)
  self.assertEqual(I.owned_paths(''),[])
  for raw in(' ','\n','%FILES%\n','%OTHER%\nx\n','%FILES%\nusr/bin/x\r\n','%FILES%\nusr/bin/x\nusr/bin/x/\n'):
   with self.subTest(raw=raw),self.assertRaises(ValueError):I.owned_paths(raw)
  for key in('/usr/bin/x','../x','usr/../x','usr//x','usr/./x','usr/bin/x//','usr/bin/x\t','usr/bin/x\0'):
   with self.subTest(key=key),self.assertRaises(ValueError):I.ownership_key(key)
  for kind in('missing','alias','empty-desc','orphan'):
   bad=copy.deepcopy(scan)
   if kind in('missing','alias'):
    del bad['nodes']['usr/bin/[']
    if kind=='alias':bad['nodes']['usr/bin/alias']=nodes['usr/bin/[']
   elif kind=='empty-desc':bad['records'][next(p for p in records if p.endswith('/desc'))]=''
   else:bad['records']['var/lib/pacman/local/orphan/files']=''
   with self.subTest(kind=kind),self.assertRaises(ValueError):I.owners(bad,inventory)
  # Command/runtime operands retain their stricter grammar.
  with self.assertRaises(ValueError):K.guest_path('/usr/bin/[')
 def test_readonly_observer_renders_only_synthetic_data_and_refuses_unissued_authority(self):
  O=module('baseline_observer');scan=dict(nodes={'usr/bin/x':dict(type='file',mode=0o755,uid=0,gid=0,sha256='a'*64)},records={'var/lib/pacman/local/x-1/desc':'%NAME%\nx\n\n%VERSION%\n1\n','var/lib/pacman/local/x-1/files':'%FILES%\nusr/bin/x\n'})
  rows=O.render(scan,{'x':'1'});self.assertEqual(set(rows),{'ownership.json','namespace.json','alpm-records.json'});self.assertEqual(json.loads(rows['ownership.json'])['usr/bin/x']['owners'],['x'])
  with self.assertRaises(ValueError):O.authority(K.load(HERE/'baseline-observer-authority.TEMPLATE.json'),pin('Source'),Path('/MODEL'),K)
  for event in('subprocess.Popen','socket.__new__','ctypes.dlopen','fcntl.flock'):
   with self.assertRaises(RuntimeError):O.fence(event,())
 def test_explicit_separate_baseline_ownership_pin_without_image_copy(self):
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);base=root/'original';base.mkdir();(base/'guest.raw').write_bytes(b'MODEL_RAW');(base/'prepared.json').write_bytes(b'MODEL_PREPARED');ownership=root/'ownership.json';ownership.write_bytes(b'MODEL_OWNERS')
   expected=dict(raw=K.pin(base/'guest.raw'),prepared=K.pin(base/'prepared.json'),ownership=K.pin(ownership))
   self.assertEqual(A.baseline_inputs(base,expected,ownership)['ownership'],ownership);self.assertFalse((base/'ownership.json').exists())
   with self.assertRaises(FileNotFoundError):A.baseline_inputs(base,expected)
   ownership.write_bytes(b'WRONG')
   with self.assertRaises(ValueError):A.baseline_inputs(base,expected,ownership)
 def test_readonly_observer_synthetic_scan_joins_pins_and_bounds_output(self):
  O=module('baseline_observer');scan=dict(nodes={'usr/bin/x':dict(type='file',mode=0o755,uid=0,gid=0,sha256='a'*64)},records={'var/lib/pacman/local/x-1/desc':'%NAME%\nx\n\n%VERSION%\n1\n','var/lib/pacman/local/x-1/files':'%FILES%\nusr/bin/x\n'},filesystem_free_bytes=4096,log_data_b64=None)
  for kind in('valid','wrong-raw','output-cap'):
   with tempfile.TemporaryDirectory()as tmp:
    root=Path(tmp);raw=root/'raw';raw.write_bytes(b'SYNTHETIC_NOT_EXT4');prep=root/'prepared';prep.write_bytes(K.canonical(dict(base_packages=[dict(name='x',version='1')],files={'guest.raw':K.pin(raw)})));out=root/'fresh';now=int(time.time());source=pin('synthetic-source')
    auth=dict(kind='ROOT_PERL5423_READONLY_BASELINE_AUTHORITY_V1',issued_by='Root',accepted=True,operation=K.OP,source_lock=source,raw=dict(path=str(raw),**K.pin(raw)),prepared=dict(path=str(prep),**K.pin(prep)),output=str(out),uid=os.getuid(),created_utc=now-1,expires_utc=now+60,scan_seconds=10,output_cap_bytes=1 if kind=='output-cap'else 1024**2,external_resource_enforcement='ROOT_CUSLS_WHOLE_PROCESS_MEMORY_CPU_PID_QUOTA_AND_OUTPUT_GUARD')
    authpath=root/'authority';authpath.write_bytes(K.canonical(auth))
    if kind=='wrong-raw':raw.write_bytes(b'WRONG')
    modules=dict(contracts=O.module('contracts'),adapter=type('A',(),{'source':staticmethod(lambda sha:source)}),image=type('I',(),{'scan':staticmethod(lambda *args:copy.deepcopy(scan)),'owners':staticmethod(I.owners)}))
    with patch.object(O,'module',side_effect=lambda n:modules[n]):
     if kind=='valid':
      result=O.observe(authpath,K.pin(authpath)['sha256'],'MODEL_SHA',out);self.assertEqual(set(result),{'ownership.json','namespace.json','alpm-records.json','observation.json'});obs=K.load(out/'observation.json');self.assertIsNone(obs['Root_baseline_certificate']);self.assertTrue(obs['original_raw_and_prepared_unchanged'])
     else:
      with self.assertRaises(ValueError):O.observe(authpath,K.pin(authpath)['sha256'],'MODEL_SHA',out)
      self.assertFalse(out.exists())
 def test_durable_actual_ELF_bytes_and_functional_receipt_joins(self):
  raw=bytearray(120);raw[:6]=b'\x7fELF\x02\x01';struct.pack_into('<HH',raw,16,2,183);struct.pack_into('<Q',raw,32,64);struct.pack_into('<HH',raw,54,56,1);struct.pack_into('<IIQQQQQQ',raw,64,1,5,0,0x400000,0,120,120,16384);raw=bytes(raw)
  for kind in('valid','functional','ELF','receipt','extra'):
   a=modeled();rt=a[3];inv=a[2]['inventory'];paths=[p for p in sorted(rt['elfs'])if rt['files'][p]['owner']=='perl']
   data={str(i)+'.elf':raw for i,p in enumerate(paths)}
   for p in paths:rt['files'][p]['sha256']=hashlib.sha256(raw).hexdigest()
   data.update({n:b'MODELED_COMMAND_OUTPUT\n'for n in F.LOGS});data['version.log']=b'v5.42.3\n';data['paths.log']=b'/usr/lib/perl5/5.42/core_perl/CORE/libperl.so\n';data['functional.log']=F.FUNCTIONAL
   manifest=''.join(str(i)+'.elf\t'+p+'\t'+rt['files'][p]['sha256']+'\n'for i,p in enumerate(paths)).encode()
   fields=dict(P.RESTORED,DB_POLICY='EXACT',BASE_SHA256=F.inventory_hash(inv),FINAL_SHA256=F.inventory_hash(inv),FUNCTIONAL_SHA256=hashlib.sha256(F.FUNCTIONAL).hexdigest(),ELF_MANIFEST_SHA256=hashlib.sha256(manifest).hexdigest(),HOST_BOOT_UTC='1794750000',GUEST_BEFORE_CRYPTO_UTC='1794750001',RTC_BEFORE_CRYPTO_UTC='1794750001')
   data['before-alpm-provider-observation.tsv']=b''
   data['outputs.sha256']=''.join(hashlib.sha256(data[n]).hexdigest()+'  '+n+'\n'for n in sorted(n for n in data if n.endswith('.elf'))+sorted(F.LOGS)+['before-alpm-provider-observation.tsv']).encode()
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
   guard=Q.Guard(root,r,'/dev/MODELED',time.monotonic()+60,lambda *args,**kw:0,initial=True,query=query)
   with patch.object(Q.shutil,'disk_usage',return_value=type('D',(),dict(free=2**40))),patch.object(Q.Path,'read_text',return_value='MemAvailable: 100000000 kB\n'):guard(True)
   self.assertEqual(seen,[('/dev/MODELED',os.getuid())]);self.assertEqual(guard.samples,1)
   guard.query=lambda d,u:0
   with self.assertRaises(ValueError):guard(True)
   guard.query=lambda d,u:(_ for _ in ()).throw(OSError('MODELED quota unknown'))
   with self.assertRaises(OSError):guard(True)
   guard.deadline=time.monotonic()-1
   with self.assertRaises(TimeoutError):guard(True)
 def test_closed_fresh_root_authority_and_no_network_QEMU(self):
  now=int(time.time());sp=pin('Source');pp=pin('packet');out=Path('/PRIVATE/MODELED/output')
  auth=dict(kind='ROOT_PERL5423_VM_ACTOR_AUTHORITY_V1',issued_by='Root',accepted=True,operation=K.OP,phase='prepare',packet=pp,source_lock=sp,output=str(out),uid=1000,created_utc=now,expires_utc=now+100,image='sha256:'+'a'*64,docker_endpoint='unix:///run/user/1000/docker.sock',docker_cli=dict(path='/MODEL/Root-selected/docker',bytes=44217952,sha256='e966e0e6ea215b74fdbee17fbe7ed8bff15b65930bfc8e131652ceae4ed0210e',uid=1000,gid=1000,mode=0o755,device=1,inode=1,nlink=1),quota_device='/dev/MODELED',actor_tools={p:pin(p)for p in('/usr/bin/python3','/usr/bin/cp','/usr/bin/debugfs','/usr/bin/e2fsck','/usr/bin/qemu-img','/usr/bin/qemu-system-aarch64')},kernel={n:pin(n)for n in('Image','config')},credentials=None,prepared=None)
  with patch.object(C.os,'getuid',return_value=1000):
   C.authority(auth,'prepare',pp,sp,out,K)
   home=modeled_home()[4];home['quota_guard']['source_lock']=sp
   for phase in('prepare','boot'):
    target=Path(home['quota_guard']['outputs'][phase]);trial=dict(auth,phase=phase,output=str(target),quota_device=None,prepared=pin('prepared')if phase=='boot'else None,credentials=pin('credentials')if phase=='boot'else None)
    C.authority(trial,phase,pp,sp,target,K,home)
    for bad in(dict(trial,quota_device='/dev/MODELED'),dict(trial,output=str(target)+'-wrong')):
     with self.assertRaises(ValueError):C.authority(bad,phase,pp,sp,target,K,home)
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
 def test_expected_payload_plan_keeps_actual_fields_null_and_exact81rows(self):
  E=module('expected_payload');v=K.load(HERE/'known/expected-payload-inputs.json');E.validate(v);self.assertEqual(len(v['rows']),81);self.assertIsNone(v['Root_runtime_certificate']);self.assertFalse(v['runtime_acceptance'])
  for kind in('guest','row-hash','alias','runtime'):
   bad=copy.deepcopy(v)
   if kind=='guest':bad['actual_guest_hashes']={}
   if kind=='row-hash':bad['rows'][0]['expected_member_sha256']='0'*64
   if kind=='alias':bad['aliases']['/lib']['target']='usr/lib/escape'
   if kind=='runtime':bad['runtime_acceptance']=True
   with self.subTest(kind=kind),self.assertRaises(ValueError):E.validate(bad)
 def test_expected_provider_actual_raw_observation_refuses_hash_owner_alias_drift(self):
  import base64,types
  E=module('expected_payload');v=K.load(HERE/'known/expected-payload-inputs.json');nodes={};inventory={};owned={}
  for row in v['rows']:
   if row['expected_package']in('perl','db5.3'):continue
   p=row['expected_path'].lstrip('/');owner=row['expected_package'];inventory[owner]=row['expected_package_version'];owned[p]=dict(owners=[owner]);nodes[p]=dict(type='file',size=row['expected_member_bytes'],sha256=row['expected_member_sha256'],mode=0o755,uid=0,gid=0)
  for path,row in v['aliases'].items():
   if row['owner']in('perl','db5.3'):continue
   p=path.lstrip('/');inventory[row['owner']]=row['version'];owned[p]=dict(owners=[row['owner']]);nodes[p]=dict(type='symlink',target_b64=base64.b64encode(row['target'].encode()).decode(),mode=row['mode'],uid=0,gid=0)
  original=E.module
  for kind in('valid','hash','owner','alias'):
   actual=copy.deepcopy(nodes);ownership=copy.deepcopy(owned)
   if kind=='hash':next(n for n in actual.values()if n['type']=='file')['sha256']='0'*64
   if kind=='owner':next(iter(ownership.values()))['owners']=[]
   if kind=='alias':actual['lib']['target_b64']=base64.b64encode(b'usr/elsewhere').decode()
   fake=types.SimpleNamespace(owners=lambda scan,inv:ownership)
   with patch.object(E,'module',side_effect=lambda n:fake if n=='image'else original(n)):
    if kind=='valid':
     report=E.observe(v,dict(nodes=actual),inventory);self.assertFalse(report['runtime_acceptance']);self.assertIsNone(report['Root_runtime_certificate']);self.assertIsNone(report['VM'])
    else:
     with self.subTest(kind=kind),self.assertRaises(ValueError):E.observe(v,dict(nodes=actual),inventory)
 def test_expected_certificate_cannot_relabel_actual_or_bypass_explicit_admission(self):
  a=modeled();a[3]['kind']='ROOT_REVIEWED_PERL5423_VM_EXPECTED_PAYLOAD_INPUTS_V1';a[3]['actual_guest_hashes']={}
  with self.assertRaises(ValueError):K.validate(*reseal(a))
  a=modeled();a[5]['input_kind']='ROOT_REVIEWED_PERL5423_VM_EXPECTED_PAYLOAD_INPUTS_V1';a[0]['evidence']['Root_decision']=K.json_pin(a[5]);a[1]['Root_decision']=a[0]['evidence']['Root_decision']
  with self.assertRaises(ValueError):K.validate(*a)
 def test_modeled_expected_input_kind_requires_own_Root_admission_and_emits_preALPM_vectors(self):
  # Shape/phase control only: synthetic certificates remain operation-fenced.
  E=module('expected_payload');a=modeled(dependency=True);rt=a[3];base=a[2];v=K.load(HERE/'known/expected-payload-inputs.json')
  rt.update(kind=E.KIND,expected_payload=v,actual_guest_hashes=None,actual_guest_ALPM_ownership=None,actual_guest_namespace=None,Root_runtime_certificate=None,runtime_acceptance=False)
  rt['probe_qualification'].pop('actual_paths_verified');rt['probe_qualification']['expected_paths_source_verified']=True
  dep=rt['dependency_transaction'];dep['elf_paths']=[]
  for row in v['rows']:
   p=row['expected_path'];owner=row['expected_package'];version=row['expected_package_version']
   f=dict(bytes=row['expected_member_bytes'],sha256=row['expected_member_sha256'],mode=0o755,owner=owner,version=version,resolved=p);rt['files'][p]=f
   if owner not in('perl','db5.3'):base['inventory'][owner]=version;rt['baseline_files'][p]=copy.deepcopy(f)
   else:
    ns=rt['candidate_namespace']if owner=='perl'else dep['namespace']
    for parent in reversed(Path(p).parents):
     if str(parent)!='/':ns[str(parent)]=dict(kind='d',mode=0o755,uid=0,gid=0)
    ns[p]=dict(kind='f',mode=0o755,uid=0,gid=0,bytes=f['bytes'],sha256=f['sha256'])
    if owner=='db5.3':dep['files'][p]=f;dep['elf_paths'].append(p)
   if p in rt['elfs']:rt['elfs'][p]['sha256']=f['sha256']
   else:rt['elfs'][p]=dict(sha256=f['sha256'],**{'class':64},byte_order='little',machine=183,interpreter=None,needed=[],version_needs={},providers={},static_16k_geometry=True)
  for alias in v['aliases'].values():base['inventory'][alias['owner']]=alias['version']
  for fs in(rt['baseline_files'],rt['files']):
   for row in fs.values():
    if row['owner']in base['inventory']:row['version']=base['inventory'][row['owner']]
  for row in rt['dependency_resolution'].values():
   if row['owner']in base['inventory']:row['version']=base['inventory'][row['owner']]
  base['baseline_count']=len(base['inventory']);a[4]['package_expanded_bytes']=sum(r.get('bytes',0)for ns in(rt['candidate_namespace'],dep['namespace'])for r in ns.values())
  a[4].update(clone_allocated_cap_bytes=128*1024**2,readback_allocated_cap_bytes=128*1024**2,physical_free_bytes=512*1024**2,quota_initial_headroom_bytes=512*1024**2,guest_filesystem_free_bytes=256*1024**2);a[4]['quota_guard']['initial_headroom_bytes']=a[4]['quota_initial_headroom_bytes']
  a=reseal(a);K.validate(*a);rows=A.contents(a[0],dict(zip(K.EVIDENCE,a[2:])),pin('source'),'a'*32)
  self.assertEqual(len(rows['expected-before-alpm-providers.tsv'][0].splitlines()),10);self.assertIn(b'/lib\tusr/lib',rows['expected-before-alpm-aliases.tsv'][0]);self.assertEqual(a[5]['input_kind'],E.KIND)
 def test_expected_db_already_in_baseline_is_checked_before_ALPM(self):
  import base64,types
  E=module('expected_payload');v=K.load(HERE/'known/expected-payload-inputs.json');nodes={};inventory={};owned={}
  for r in v['rows']:
   if r['expected_package']=='perl':continue
   p=r['expected_path'].lstrip('/');owner=r['expected_package'];inventory[owner]=r['expected_package_version'];owned[p]=dict(owners=[owner]);nodes[p]=dict(type='file',size=r['expected_member_bytes'],sha256=r['expected_member_sha256'],mode=0o755,uid=0,gid=0)
  for p,r in v['aliases'].items():
   if r['owner']=='perl':continue
   inventory[r['owner']]=r['version'];owned[p.lstrip('/')]=dict(owners=[r['owner']]);nodes[p.lstrip('/')]=dict(type='symlink',target_b64=base64.b64encode(r['target'].encode()).decode(),mode=r['mode'],uid=0,gid=0)
  original=E.module;fake=types.SimpleNamespace(owners=lambda scan,inv:owned)
  with patch.object(E,'module',side_effect=lambda n:fake if n=='image'else original(n)):
   result=E.observe(v,dict(nodes=nodes),inventory);self.assertEqual(len(result['files']),27)
   nodes['usr/lib/libdb-5.3.so']['sha256']='0'*64
   with self.assertRaises(ValueError):E.observe(v,dict(nodes=nodes),inventory)
 def test_explicit_Docker_binding_shape_and_no_missing_or_unbound_fallback(self):
  R=module('runtime');known=dict(path='/home/gabe/bin/docker',bytes=44217952,sha256='e966e0e6ea215b74fdbee17fbe7ed8bff15b65930bfc8e131652ceae4ed0210e',uid=os.getuid(),gid=os.getgid(),mode=0o755,device=1,inode=1,nlink=1)
  self.assertEqual(R.docker_cli_shape(known),known)
  for bad in(None,dict(known,path='docker'),dict(known,mode=0o777),dict(known,nlink=2),dict(known,sha256=None)):
   with self.subTest(value=bad),self.assertRaises(ValueError):R.docker_cli_shape(bad)
  for argv in(['docker','info'],['/usr/bin/docker','info']):
   with self.assertRaises(ValueError):R.bound_command(argv)
 def test_Docker_binding_positive_metadata_and_tamper_alias_identity_refusals(self):
  R=module('runtime')
  with tempfile.TemporaryDirectory()as tmp:
   p=Path(tmp)/'owned-cli';p.write_bytes(b'MODELED_NOT_EXECUTED_DOCKER');p.chmod(0o755);st=p.stat();d=dict(path=str(p),**K.pin(p),uid=st.st_uid,gid=st.st_gid,mode=0o755,device=st.st_dev,inode=st.st_ino,nlink=1)
   self.assertEqual(R.checked_docker_cli(d),str(p))
   alias=Path(tmp)/'alias';alias.symlink_to(p)
   for bad in(dict(d,path=str(alias)),dict(d,inode=d['inode']+1),dict(d,sha256='0'*64)):
    with self.assertRaises(ValueError):R.checked_docker_cli(bad)
   p.write_bytes(b'MODELED_CHANGED')
   with self.assertRaises(ValueError):R.checked_docker_cli(d)
 def test_Docker_PATH_regression_and_cleanup_use_same_absolute_operand(self):
  R=module('runtime')
  with tempfile.TemporaryDirectory()as tmp:
   p=Path(tmp)/'owned-cli';p.write_bytes(b'MODELED_CLI_NO_EXECUTION');p.chmod(0o755);st=p.stat();d=dict(path=str(p),**K.pin(p),uid=st.st_uid,gid=st.st_gid,mode=0o755,device=st.st_dev,inode=st.st_ino,nlink=1);endpoint='unix:///run/user/'+str(os.getuid())+'/docker.sock'
   before={k:os.environ.get(k)for k in('DOCKER_HOST','DOCKER_CONTEXT')}
   with patch.dict(os.environ,{'PATH':'/MODEL/POISON_PATH','DOCKER_CONTEXT':'MODELED_UNWANTED_CONTEXT'}):
    with R.transport(dict(docker_cli=d,docker_endpoint=endpoint)):
     argv,env=R.bound_command(['docker','info']);self.assertEqual(argv[0],str(p));self.assertEqual(env['PATH'],'/usr/bin:/bin');self.assertEqual(env['DOCKER_HOST'],endpoint);self.assertNotIn('DOCKER_CONTEXT',env)
     for args in(['docker','container','inspect','MODEL'],['docker','container','rm','--force','MODEL']):
      with patch.object(R,'command',return_value='MODELED_RETIRED')as run:
       self.assertEqual(R.docker_call(args,Path(tmp),time.monotonic()+8,shared_deadline=time.monotonic()+20,defer_cancel=True),'MODELED_RETIRED');self.assertEqual(run.call_args.args[0][0],str(p));self.assertTrue(run.call_args.kwargs['defer_cancel'])
    self.assertIsNone(R.DOCKER_CLI);self.assertEqual(os.environ['DOCKER_CONTEXT'],'MODELED_UNWANTED_CONTEXT')
   self.assertEqual({k:os.environ.get(k)for k in before},before)
 def test_QMP_original_peer_parent_start_argv_pidfd_and_descriptor_refusals(self):
  import types
  class Stream:
   def __init__(self):self.credentials=(201,os.getuid(),os.getgid());self.fd=7
   def fileno(self):return self.fd
   def getsockopt(self,*args):return struct.pack('3i',*self.credentials)
  class Poll:
   ready=False
   def register(self,*args):pass
   def poll(self,*args):return [(101,1)]if self.ready else []
  argv=['/usr/bin/qemu-system-aarch64','MODEL_NO_PROCESS'];rows={201:dict(pid=201,parent=101,start=777,argv=[x.encode()for x in argv]),101:dict(pid=101,parent=99,start=666,argv=[b'/usr/bin/python3',b'/code/actor.py'])};row=dict(State=dict(Pid=101,Running=True,OOMKilled=False))
  stream=Stream();poll=Poll();closed=[]
  with patch.object(C.os,'pidfd_open',side_effect=[501,502]),patch.object(C.os,'close',side_effect=closed.append),patch.object(C,'proc_identity',side_effect=lambda p:copy.deepcopy(rows[p])),patch.object(C.select,'poll',return_value=poll):
   peer=C.QMPPeer(stream,row,argv);peer.check(row);self.assertEqual(peer.evidence()['qemu_start'],777)
   for bad in('credentials','descriptor','parent','qemu-start','actor-start','argv','pidfd','actor-pid'):
    before=copy.deepcopy(rows);old_creds=stream.credentials;old_fd=stream.fd;changed=copy.deepcopy(row)
    if bad=='credentials':stream.credentials=(202,*stream.credentials[1:])
    if bad=='descriptor':stream.fd=8
    if bad=='parent':rows[201]['parent']=102
    if bad=='qemu-start':rows[201]['start']+=1
    if bad=='actor-start':rows[101]['start']+=1
    if bad=='argv':rows[201]['argv']=[b'WRONG_QEMU']
    if bad=='pidfd':poll.ready=True
    if bad=='actor-pid':changed['State']['Pid']=102
    with self.subTest(bad=bad),self.assertRaises(ValueError):peer.check(changed)
    rows=before;stream.credentials=old_creds;stream.fd=old_fd;poll.ready=False
   peer.close();self.assertEqual(closed,[501,502]);peer.close();self.assertEqual(closed,[501,502])
  stream=Stream();stream.credentials=(201,os.getuid()+1,os.getgid())
  with patch.object(C.os,'pidfd_open')as opened:
   with self.assertRaises(ValueError):C.QMPPeer(stream,row,argv)
   opened.assert_not_called()
  fields=['S','101','201','201']+['0']*15+['777'];raw=('201 (MODEL qemu) '+' '.join(fields)).encode()
  with patch.object(C.os,'open',side_effect=[601,602]),patch.object(C.os,'read',side_effect=[raw,b'/usr/bin/qemu\0MODEL\0']),patch.object(C.os,'close'):
   result=C.proc_identity(201);self.assertEqual((result['parent'],result['start'],result['argv']),(101,777,[b'/usr/bin/qemu',b'MODEL']))
 def test_QMP_quit_progress_exact_request_events_ACK_and_private_counters(self):
  class Peer:
   fd=7
   def __init__(self):self.stream=self;self.timeouts=[]
   def settimeout(self,value):self.timeouts.append(value)
  peer=Peer();writes=[];guards=[];progress={}
  event=b'{"event":"SHUTDOWN","data":{}}\n';ack=b'{"return":{},"id":"guest-HOLD-retire"}\n';replies=iter((event,ack))
  class File:
   def fileno(self):return 7
   def write(self,body):writes.append(body);return len(body)
   def readline(self,cap):self.cap=cap;return next(replies)
  stream=File()
  with patch.object(C.time,'monotonic',return_value=100):
   C.quit_hold_qmp(peer,stream,lambda:guards.append('guard'),105,progress)
  self.assertEqual(writes,[b'{"execute":"quit","id":"guest-HOLD-retire"}\n'])
  self.assertEqual(progress,dict(stage='ACKNOWLEDGED',request_bytes=44,reply_attempts=2,reply_bytes=len(event)+len(ack)))
  self.assertEqual(peer.timeouts,[2,2,2]);self.assertEqual(stream.cap,65537);self.assertEqual(len(guards),3)
 def test_QMP_quit_progress_failure_substeps_keep_all_transport_refusals(self):
  sentinel='PRIVATE_SYNTHETIC_ERROR_OR_REPLY_NEVER_EXPORTED'
  for bad in('write-timeout','read-timeout','partial-write','EOF','JSON','matching-error','wrong-ID','oversize','aggregate','descriptor','deadline','guard'):
   with self.subTest(bad=bad):
    class Peer:
     fd=7
     def __init__(self):self.stream=self;self.timeouts=[]
     def settimeout(self,value):self.timeouts.append(value)
    peer=Peer();progress={};writes=[];reads=[]
    class File:
     def fileno(self):return 8 if bad=='descriptor'else 7
     def write(self,body):
      writes.append(body)
      if bad=='write-timeout':raise TimeoutError(110,sentinel)
      return len(body)-1 if bad=='partial-write'else len(body)
     def readline(self,cap):
      reads.append(cap)
      if bad=='read-timeout':raise TimeoutError(110,sentinel)
      if bad=='EOF':return b''
      if bad=='JSON':return sentinel.encode()+b'\n'
      if bad=='matching-error':return b'{"error":{},"id":"guest-HOLD-retire"}\n'
      if bad=='wrong-ID':return b'{"return":{},"id":"other"}\n'
      if bad=='oversize':return b' '*65537
      if bad=='aggregate'and len(reads)==1:
       return b'{"event":"MODEL"}'+b' '*(65535-len(b'{"event":"MODEL"}'))+b'\n'
      return b'{"return":{},"id":"guest-HOLD-retire"}\n'
    def guard():
     if bad=='guard':raise ValueError('MODELED_GUARD_REFUSAL')
    expected=TimeoutError if bad in('write-timeout','read-timeout')else ValueError
    with patch.object(C.time,'monotonic',return_value=100),self.assertRaises(expected):
     C.quit_hold_qmp(peer,File(),guard,99 if bad=='deadline'else 105,progress)
    self.assertNotIn(sentinel,json.dumps(progress))
    self.assertLessEqual(set(progress),{'stage','request_bytes','reply_attempts','reply_bytes','io_error','errno'})
    if bad in('write-timeout','read-timeout'):
     self.assertEqual(progress['stage'],'WRITE_FAILED'if bad=='write-timeout'else'READ_FAILED')
     self.assertEqual((progress['io_error'],progress['errno']),('TimeoutError',110))
     self.assertEqual(progress['request_bytes'],0 if bad=='write-timeout'else 44)
    if bad in('write-timeout','partial-write','descriptor','deadline','guard'):self.assertEqual(reads,[])
    if bad in('descriptor','deadline','guard'):self.assertEqual(writes,[])
    if bad=='wrong-ID':self.assertEqual(progress['reply_attempts'],16)
    if bad in('oversize','aggregate'):self.assertGreater(progress['reply_bytes'],65536)
    self.assertNotEqual(progress.get('stage'),'ACKNOWLEDGED');self.assertTrue(all(0<n<=2 for n in peer.timeouts))
 def test_QMP_quit_progress_keeps_remaining_deadline_clamp(self):
  class Peer:
   fd=7
   def __init__(self):self.stream=self;self.timeouts=[]
   def settimeout(self,value):self.timeouts.append(value)
  class File:
   def fileno(self):return 7
   def write(self,body):return len(body)
   def readline(self,cap):return b'{"return":{},"id":"guest-HOLD-retire"}\n'
  peer=Peer();progress={}
  with patch.object(C.time,'monotonic',side_effect=[100,100,104.5,104.5]):
   C.quit_hold_qmp(peer,File(),lambda:None,105,progress)
  self.assertEqual(peer.timeouts,[2,.5]);self.assertEqual(progress['stage'],'ACKNOWLEDGED')
 def test_early_HOLD_normal_QMP_retirement_and_forced_fallback_refusals(self):
  import types
  actor,R=module('actor'),module('runtime');nonce='a'*32;authority='b'*64;failure=P.GuestHold('INSTALLED','PROBE','UNREPORTED').failure
  argv=['/usr/bin/qemu-system-aarch64','MODEL_NOT_EXECUTED'];natural=dict(argv=argv,passed=True,reaped=True,ownership='REAPED',exit=0,group_census='EMPTY_TWICE',output_complete=True,signals=[],timeout=False,error=None)
  for bad in(None,'wrong-nonce','missing-marker','bad-marker-mode','timeout','missing-receipt','forced-QEMU','wrong-actor','missing-peer','wrong-image','wrong-authority','partial-quit','existing-marker'):
   with self.subTest(bad=bad),tempfile.TemporaryDirectory()as tmp:
    out=Path(tmp);events=[]
    for name,value in(('qemu-argv.json',dict(argv=argv)),('qemu.json',natural)):
     (out/name).write_bytes(K.canonical(value));(out/name).chmod(0o600)
    class Peer:
     fd=7;argv=list(natural['argv'])
     def __init__(self):self.stream=self
     def fileno(self):return self.fd
     def settimeout(self,n):self.timeout=n
     def check(self,row):
      events.append('peer-check');K.need(row['State']['Pid']==101,'same actor')
     def evidence(self):return dict(MODELED_PEER=True)
    peer=Peer()
    class File:
     def fileno(self):return 7
     def write(self,data):
      events.append('quit');self.asserted=K.load(out/P.HOLD_MARKER);K.need(self.asserted==dict(nonce=nonce,failure=failure),'exact marker before quit')
      if bad=='missing-marker':(out/P.HOLD_MARKER).unlink()
      if bad=='bad-marker-mode':(out/P.HOLD_MARKER).chmod(0o644)
      return len(data)-1 if bad=='partial-quit'else len(data)
     def readline(self,n):
      if bad=='timeout':raise TimeoutError('MODELED QMP timeout')
      return b'{"return":{},"id":"guest-HOLD-retire"}\n'
    class Scope:
     cid='c'*64;name='MODEL_OWNED_NAME';image='sha256:'+'d'*64;labels={'org.cachy-asahi.perl5423-nonce':nonce,'org.cachy-asahi.perl5423-authority':authority}
     def __init__(self):self.recovered=0;self.forced=False
     def recover(self,end):
      self.recovered+=1;events.append('recover');running=self.recovered==1
      return dict(Id=self.cid,Name='/'+self.name,Image='WRONG_IMAGE'if bad=='wrong-image'else self.image,Config=dict(Labels=self.labels),State=dict(Pid=102 if bad=='wrong-actor'else 101,Running=running,ExitCode=0 if running else 1,OOMKilled=False))
     def validate(self,row):K.need(row['Name']=='/'+self.name and row['Image']==self.image and row['Config']['Labels']==self.labels,'exact image/name/labels')
     def call(self,args,end):
      events.append(tuple(args))
      if args[1]=='wait':
       if bad=='forced-QEMU':
        (out/'qemu.json').write_bytes(K.canonical(dict(natural,signals=['SIGTERM'],timeout=True)))
       if bad!='missing-receipt':actor.retire_guest_hold(K,R,out,nonce)
       return types.SimpleNamespace(returncode=0,stdout=b'1\n')
      K.need(args==['docker','container','rm',self.cid],'normal exact CID removal only');return types.SimpleNamespace(returncode=0)
     def listing(self,end):events.append('absence');return None
     def cleanup(self,report):self.forced=True;events.append('forced-fallback');report['owned_container_absence_verified']=True
    scope=Scope();report=dict(status='HOLD',failure=dict(category='GuestHold',message='ORIGINAL_FAILURE'),cleanup_errors=[])
    selected_nonce='e'*32 if bad=='wrong-nonce'else nonce
    if bad=='existing-marker':(out/P.HOLD_MARKER).write_bytes(b'PREVIOUS_EVIDENCE_DO_NOT_REPLACE')
    C.cleanup_scope(scope,None if bad=='missing-peer'else peer,File(),failure,selected_nonce,'f'*64 if bad=='wrong-authority'else authority,out,time.monotonic()+90,lambda:None,report)
    self.assertEqual(report['status'],'HOLD');self.assertEqual(report['failure']['message'],'ORIGINAL_FAILURE')
    if bad is None:
     self.assertEqual(report['guest_HOLD_cleanup']['qmp_quit_progress'],dict(stage='ACKNOWLEDGED',request_bytes=44,reply_attempts=1,reply_bytes=39))
     self.assertFalse(scope.forced);self.assertEqual(report['cleanup_errors'],[]);self.assertFalse(report['guest_HOLD_cleanup']['forced']);self.assertTrue(report['owned_container_absence_verified']);self.assertLess(events.index('peer-check'),events.index('quit'));self.assertFalse((out/'STOP').exists());self.assertFalse((out/'preservation.json').exists());self.assertFalse((out/'results').exists())
    else:
     self.assertTrue(scope.forced);self.assertTrue(report['forced_owned_cleanup_fallback']);self.assertEqual(report['cleanup_errors'][0]['step'],'normal-guest-HOLD-retirement')
     if bad=='timeout':self.assertEqual(report['guest_HOLD_cleanup']['qmp_quit_progress'],dict(stage='READ_FAILED',request_bytes=44,reply_attempts=1,reply_bytes=0,io_error='TimeoutError',errno=None))
     if bad=='partial-quit':self.assertEqual(report['guest_HOLD_cleanup']['qmp_quit_progress']['stage'],'WRITE_RETURNED')
     if bad=='existing-marker':self.assertNotIn('quit',events);self.assertEqual((out/P.HOLD_MARKER).read_bytes(),b'PREVIOUS_EVIDENCE_DO_NOT_REPLACE')
     if bad in('wrong-nonce','wrong-actor','missing-peer','wrong-image','wrong-authority'):self.assertNotIn('quit',events);self.assertFalse((out/P.HOLD_MARKER).exists())
  with tempfile.TemporaryDirectory()as tmp:
   with self.assertRaises(FileNotFoundError):actor.retire_guest_hold(K,R,Path(tmp),nonce)
  for bad in('nonce','failure','mode','symlink','hardlink','oversize','owner'):
   with self.subTest(actor_marker=bad),tempfile.TemporaryDirectory()as tmp:
    out=Path(tmp);marker=out/P.HOLD_MARKER;value=dict(nonce='e'*32 if bad=='nonce'else nonce,failure=dict(failure,status='PASS')if bad=='failure'else failure)
    marker.write_bytes(K.canonical(value));marker.chmod(0o644 if bad=='mode'else 0o600)
    if bad=='symlink':marker.rename(out/'original');marker.symlink_to(out/'original')
    if bad=='hardlink':os.link(marker,out/'alias')
    if bad=='oversize':marker.write_bytes(b' '*4097)
    with patch.object(actor.os,'getuid',return_value=os.getuid()+1 if bad=='owner'else os.getuid()):
     with self.assertRaises(ValueError):actor.retire_guest_hold(K,R,out,nonce)
    self.assertFalse((out/P.HOLD_RETIRED).exists())
 def test_serial_phase_wait_observes_early_HOLD_and_ordered_chunked_success(self):
  B=K.helper('reference_controller.py');nonce='a'*32;other='b'*32
  def wire(kind,fields,n=nonce):return ('PERL5423_'+kind+'_BEGIN '+n+'\n'+''.join(k+'='+v+'\n'for k,v in fields.items())+'PERL5423_'+kind+'_END '+n+'\n').encode()
  class Stream:
   def __init__(self,data):self.chunks=[data[i:i+7]for i in range(0,len(data),7)];self.reads=0
   def settimeout(self,n):pass
   def recv(self,n):
    self.reads+=1
    if not self.chunks:raise AssertionError('wait exhausted explicit synthetic evidence')
    return self.chunks.pop(0)
  def serial(data):return B.Serial(Stream(data),time.monotonic()+5)
  actual=K.load(HERE/'known/serial-early-hold-r3.json')
  with self.assertRaisesRegex(ValueError,'guest explicit HOLD while waiting for INSTALLED'):P.wait_phase(serial(actual['frame'].encode()),actual['case_nonce'],'INSTALLED')
  for waiting in('INSTALLED','PROBE','RESTORED'):
   for failed in('INSTALLED','PROBE','RESTORED'):
    data=wire(failed,dict(STATUS='HOLD',FAILED_PHASE='baseline'))+b'NEVER_READ'
    row=serial(data)
    with self.subTest(waiting=waiting,failed=failed),self.assertRaisesRegex(ValueError,'guest explicit HOLD while waiting for '+waiting):P.wait_phase(row,nonce,waiting)
    self.assertLess(row.stream.reads,(len(data)+6)//7)
  row=serial(wire('INSTALLED',P.INSTALLED)+wire('PROBE',P.PROBE)+wire('RESTORED',dict(STATUS='PASS')))
  self.assertEqual(P.wait_phase(row,nonce,'INSTALLED'),P.INSTALLED);self.assertEqual(P.wait_phase(row,nonce,'PROBE'),P.PROBE);self.assertEqual(P.wait_phase(row,nonce,'RESTORED'),dict(STATUS='PASS'))
  row=serial(wire('PROBE',dict(STATUS='HOLD'),other)+wire('INSTALLED',P.INSTALLED))
  self.assertEqual(P.wait_phase(row,nonce,'INSTALLED'),P.INSTALLED)
  for data in(wire('PROBE',P.PROBE),wire('RESTORED',dict(STATUS='PASS'))):
   with self.assertRaisesRegex(ValueError,'out-of-order'):P.wait_phase(serial(data),nonce,'INSTALLED')
  malformed=wire('PROBE',dict(STATUS='HOLD')).replace(b'STATUS=HOLD',b'STATUS=HOLD\nSTATUS=PASS')
  with self.assertRaisesRegex(ValueError,'unique ASCII'):P.wait_phase(serial(malformed),nonce,'INSTALLED')
  with self.assertRaisesRegex(ValueError,'unsupported Perl phase status'):P.wait_phase(serial(wire('INSTALLED',dict(STATUS='UNKNOWN'))),nonce,'INSTALLED')
  row=serial(wire('INSTALLED',P.INSTALLED).replace(b'\n',b'\r\n'));self.assertEqual(P.wait_phase(row,nonce,'INSTALLED'),P.INSTALLED)
  with self.assertRaises(AssertionError):P.wait_phase(serial(wire('PROBE',dict(STATUS='HOLD'))[:-8]),nonce,'INSTALLED')
 def test_actual_journey_early_HOLD_does_not_send_restored_or_logout(self):
  B=K.helper('reference_controller.py');nonce='a'*32;base='b'*32
  session=dict(ARCH='aarch64',PAGESIZE='16384',UID='1000',USERNAME='builder',PID1='systemd',Name='builder',User='1000',Class='user',Type='tty',Service='login',Remote='no',LOGIND='active',DBUS='active',Id='c1',XDG_SESSION_ID='c1',Leader='142',State='active')
  wire=b'login: Password: ARM16K_SHELL_READY '+base.encode()+b'\nTCG_LOGIN_END '+base.encode()+b'\nPERL5423_PROBE_BEGIN '+nonce.encode()+b'\nSTATUS=HOLD\nEXIT_STATUS=1\nPERL5423_PROBE_END '+nonce.encode()+b'\n'
  class Stream:
   def __init__(self):self.data=wire;self.sent=[]
   def settimeout(self,n):pass
   def recv(self,n):data=self.data;self.data=b'';return data
   def sendall(self,data):self.sent.append(data)
  stream=Stream();row=B.Serial(stream,time.monotonic()+5)
  with self.assertRaisesRegex(ValueError,'guest explicit HOLD while waiting for INSTALLED'):P.journey(row,'SYNTHETIC_PASSWORD',base,nonce,lambda data,n:session)
  self.assertEqual(len(stream.sent),4);self.assertNotIn(b'exit\n',stream.sent);self.assertFalse(any(b' restored' in s for s in stream.sent))
  def phase(kind,fields):return ('PERL5423_'+kind+'_BEGIN '+nonce+'\n'+''.join(k+'='+v+'\n'for k,v in fields.items())+'PERL5423_'+kind+'_END '+nonce+'\n').encode()
  prefix=wire[:wire.index(b'PERL5423_PROBE_BEGIN')]
  restored=dict(P.RESTORED,DB_POLICY='EXACT',**{k:'c'*64 for k in P.HASHES},**{k:'1794779396'for k in P.EPOCHS})
  wire=prefix+phase('INSTALLED',P.INSTALLED)+phase('PROBE',P.PROBE)+phase('RESTORED',restored)+b'login: '
  stream=Stream();result=P.journey(B.Serial(stream,time.monotonic()+5),'SYNTHETIC_PASSWORD',base,nonce,lambda data,n:session)
  self.assertTrue(result['normal_PAM_logout_observed']);self.assertEqual(result['restored'],restored);self.assertEqual(len(stream.sent),6);self.assertEqual(stream.sent[-1],b'exit\n')
  wire=prefix+phase('INSTALLED',P.INSTALLED)*2+phase('PROBE',P.PROBE)
  with self.assertRaisesRegex(ValueError,'out-of-order'):P.journey(B.Serial(Stream(),time.monotonic()+5),'SYNTHETIC_PASSWORD',base,nonce,lambda data,n:session)
 def test_prepare_first_boot_then_second_boot_exclusive_markers(self):
  with tempfile.TemporaryDirectory()as tmp:
   prepared=Path(tmp)/'prepare';prepared.mkdir();out=Path(tmp)/'boot';out.mkdir()
   first=C.attempt_marker('prepare',prepared,None,'a'*64,'b'*32);before=first.read_bytes()
   boot=C.attempt_marker('boot',out,prepared,'c'*64,'b'*32)
   self.assertEqual(first.name,'perl5423-attempt.json');self.assertEqual(boot.name,'perl5423-boot-attempt.json');self.assertEqual(first.read_bytes(),before);self.assertFalse(list(out.iterdir()))
   for phase,dest,prior in(('boot',out,prepared),('prepare',prepared,None)):
    with self.assertRaises(FileExistsError):C.attempt_marker(phase,dest,prior,'d'*64,'e'*32)
   self.assertEqual(first.read_bytes(),before);self.assertEqual(K.load(boot)['authority'],'c'*64)
 def test_closed_retained_export_roundtrip_and_refusals(self):
  T=module('retention');rt=modeled(dependency=True)[3];rt['restoration_allowances']['pacman_log_before']=None
  limits=dict(log_bytes=1024**2,guest_output_cap_bytes=256*1024**2,logs_cap_bytes=64*1024**2)
  packet=dict(nonce='a'*32,Source_lock=pin('source'));case_pin=pin('packet')
  required,pairs,optional=T.receipt_names(rt);names={'receipts/'+n for n in required|{sorted(pair)[0]for pair in pairs}}
  names|={'results/'+n for n in F.LOGS}|{'results/'+n for n in('outputs.sha256','summary.env','before-alpm-provider-observation.tsv')}
  names|={'results/'+str(i)+'.elf'for i,p in enumerate(sorted(p for p in rt['elfs']if rt['files'][p]['owner']=='perl'))}
  nodes={T.PREFIX+g:dict(type='directory',uid=0,gid=0,mode=0o700)for g in('results','receipts')};content={}
  for i,name in enumerate(sorted(names),1):
   body=b''if name.endswith('.absent')else ('MODEL_DATA_'+name).encode();content[i]=body
   nodes[T.PREFIX+name]=dict(inode=i,type='file',links=1,uid=0,gid=0,mode=0o600,size=len(body),sha256=hashlib.sha256(body).hexdigest())
  class Reader:
   def inode(self,i):return next(dict(r)for r in nodes.values()if r.get('inode')==i),content[i]
   def chunks(self,fields,data):yield data
  with tempfile.TemporaryDirectory()as tmp:
   out=Path(tmp);ref=T.export(Reader(),nodes,out,rt,limits,packet,case_pin,lambda:None)
   manifest=T.verify(out,ref,rt,packet,case_pin,limits);self.assertEqual(set(manifest['files']),names)
   with self.assertRaises(ValueError):T.verify(out,dict(ref,manifest=pin('wrong-manifest')),rt,packet,case_pin,limits)
   with self.assertRaises(ValueError):T.verify(out,ref,rt,dict(packet,nonce='b'*32),case_pin,limits)
   target=out/'receipts/base.lock';original=target.read_bytes();target.write_bytes(b'TAMPER')
   with self.assertRaises(ValueError):T.verify(out,ref,rt,packet,case_pin,limits)
   target.write_bytes(original);target.chmod(0o644)
   with self.assertRaises(ValueError):T.verify(out,ref,rt,packet,case_pin,limits)
   target.chmod(0o600);alias=out/'receipts/secret.key';alias.symlink_to(target)
   with self.assertRaises(ValueError):T.verify(out,ref,rt,packet,case_pin,limits)
   alias.unlink();os.link(target,alias)
   with self.assertRaises(ValueError):T.verify(out,ref,rt,packet,case_pin,limits)
   alias.unlink();T.verify(out,ref,rt,packet,case_pin,limits)
  remove_names=T.receipt_names(modeled()[3])[0];rollback_names=T.receipt_names(modeled(rollback=True)[3])[0]
  self.assertIn('remove.log',remove_names);self.assertNotIn('rollback.log',remove_names);self.assertIn('rollback.log',rollback_names);self.assertNotIn('remove.log',rollback_names)
  key=T.PREFIX+'receipts/base.lock'
  for change in(dict(type='symlink'),dict(links=2),dict(uid=1000),dict(mode=0o666),dict(size=T.MAX_FILE+1)):
   bad=copy.deepcopy(nodes);bad[key].update(change)
   with self.assertRaises(ValueError):T.select(bad,rt,limits)
  for name in('secret.key','nested/file','failure.env'):
   bad=copy.deepcopy(nodes);bad[T.PREFIX+'receipts/'+name]=dict(nodes[key])
   with self.assertRaises(ValueError):T.select(bad,rt,limits)
  bad=copy.deepcopy(nodes);del bad[key]
  with self.assertRaises(ValueError):T.select(bad,rt,limits)
  with self.assertRaises(ValueError):T.select(nodes,rt,dict(limits,logs_cap_bytes=65536))
  with tempfile.TemporaryDirectory()as tmp:
   original=content[nodes[key]['inode']];content[nodes[key]['inode']]=b'WRONG'
   with self.assertRaises(ValueError):T.export(Reader(),nodes,Path(tmp),rt,limits,packet,case_pin,lambda:None)
   content[nodes[key]['inode']]=original
 def test_source_syntax(self):
  for p in HERE.rglob('*.py'):ast.parse(p.read_bytes())
 def test_closed_source_lock(self):
  digest=K.pin(HERE/'source.lock.json')['sha256'];self.assertEqual(A.source(digest)['sha256'],digest)
  with self.assertRaises(ValueError):A.source('0'*64)
if __name__=='__main__':unittest.main(verbosity=2)

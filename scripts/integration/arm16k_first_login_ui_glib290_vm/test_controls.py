# SPDX-License-Identifier: MIT
"""Modeled Source/refusal controls only. No Gtk, guest, image or actor is run."""
import argparse,ast,contextlib,copy,hashlib,importlib.util,io,json,os,re,shutil,struct,subprocess,sys,tarfile,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent

def load(name):
 spec=importlib.util.spec_from_file_location('UI_control_'+name,HERE/(name+'.py'));m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m);return m
K=load('contracts');R=load('receipts');O=load('ownership');P=load('protocol');A=load('ui_glib_actor');D=load('package_data');N='1'*32

def admitted():
 v=json.loads((HERE/'authority.template.json').read_text());v.update(allow_prepare=True,tool_image_id='sha256:'+'2'*64,source_public={'repository':'https://github.com/Gabriel-Kahen/cachy-asahi','commit':'3'*40,'status':'ROOT_REVIEWED_PUBLIC_SOURCE'},resource_review={'status':'ROOT_REVIEWED_FINITE_RESOURCES','reserve_bytes':2*1024**3},accept_unknown_runtime_ABI_for_bounded_VM=True,allow_glib_runtime_upgrade=True)
 for n in ['qemu_metadata','tool_qualification','additions_manifest','minimal155_report','minimal155_prepared','source_lock']:v[n]={'bytes':1,'sha256':'4'*64}
 return v

def installed():
 versions={str(i):'1-1'for i in range(283)}
 value={'schema_version':1,'nonce':N,'stage':'installed','inputs_sha256':'a'*64,'inventory_sha256':R.inventory_sha256(versions),'baseline_count':111,'installed_count':283,'archive_count':173,'project_file_count':24}
 value.update({k:True for k in ['trusted_ALPM_completed','exact_inventory','dependencies','ownership','project_hashes','original_policy','unrelated_user_file','filesystem_synced']});return versions,value

class Fenced(unittest.TestCase):
 def setUp(self):
  stack=contextlib.ExitStack();self.addCleanup(stack.close)
  for name in ['subprocess.run','subprocess.Popen','socket.socket','fcntl.flock','os.pidfd_open']:stack.enter_context(patch(name,side_effect=AssertionError('Source controls forbid actor/network/lease entry'),create=name=='os.pidfd_open'))

class Controls(Fenced):
 def setUp(self):super().setUp();self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.work=Path(self.tmp.name)
 def test_null_admission_before_source_clone_or_process(self):
  file=self.work/'authority.json';v=admitted();v['tool_image_id']=None;file.write_text(json.dumps(v));args=argparse.Namespace(authority=file,authority_sha256=K.pin(file)['sha256'])
  with patch.object(K,'source',side_effect=AssertionError('source accessed too early')),patch.object(K,'references',side_effect=AssertionError('source imported too early')),patch.object(subprocess,'run',side_effect=AssertionError('process forbidden')):
   with self.assertRaisesRegex(ValueError,'missing Root-admitted tool_image_id'):K.preflight(args)
 def test_each_required_admission_is_explicit_nonnull(self):
  for key in ['qemu_metadata','tool_qualification','kernel_bundle','additions_manifest','minimal155_report','minimal155_prepared','source_public','source_lock','resource_review']:
   v=admitted();v[key]=None
   with self.subTest(key=key),self.assertRaises(ValueError):K.admission(v,'prepare')
 def test_cannot_retag_minimal155_authority(self):
  v=admitted();v['operation']='arm16k-first-login-ui-vm-v1'
  with self.assertRaises(ValueError):K.admission(v,'prepare')
 def test_explicit_bounded_unknown_ABI_is_allowed_not_a_PASS(self):
  self.assertEqual(K.admission(admitted(),'prepare')['operation'],K.OP);v=admitted();v['accept_unknown_runtime_ABI_for_bounded_VM']=False
  with self.assertRaises(ValueError):K.admission(v,'prepare')
 def test_missing_or_nonbool_GPU_proof_refused_before_producer(self):
  meta={'kind':'ROOT_OBSERVED_ARM_QEMU_DEVICE_HELP_V1','issued_by':'Root','image_id':'sha256:'+'2'*64,'status':'OBSERVED_DEVICE_HELP_ONLY','devices':['virtio-blk-device','virtio-keyboard-device','virtio-gpu-device']}
  for value in [False,1,'yes']:
   q={'image_id':meta['image_id'],'owned_containers_absent':True,'required_devices':dict.fromkeys(meta['devices'],True)};q['required_devices']['virtio-gpu-device']=value
   with self.subTest(value=value),self.assertRaises(AssertionError):K.qualified_tool(meta,meta['image_id'],q,Path('/absent'))
 def test_exact_local_Source_seal(self):
  self.assertEqual(K.source(),K.pin(HERE/'source.lock.json'))
 def test_actual_metadata_is_distinct_283_proposal(self):
  d=json.loads((HERE/'actual-data.json').read_text());p=d['composition'];self.assertEqual((p['baseline'],p['additions'],p['final']),(111,172,283));self.assertEqual(p['archive_bytes'],162066732);self.assertEqual(p['root_change']['after'],'21.1.26-1');self.assertEqual(p['metadata_status'],'PASS_EXPLICIT_GLIB290_METADATA_PREPARE');self.assertIsNone(d['actual_VM']);self.assertIsNone(d['actual_tool_image'])
 def test_finite_ARM_argv_has_no_PC_or_host_network_fallback(self):
  argv=A.qemu_argv(N,1794700000);self.assertEqual(argv[argv.index('-machine')+1],'virt');self.assertEqual(argv[argv.index('-global')+1],'virtio-mmio.force-legacy=false');self.assertEqual(argv[argv.index('-nic')+1],'none');self.assertEqual(argv[argv.index('-m')+1],'2048');self.assertNotIn('-enable-kvm',argv);self.assertEqual([argv[i+1]for i,v in enumerate(argv)if v=='-device'],['virtio-blk-device,drive=refdisk','virtio-keyboard-device','virtio-gpu-device']);self.assertIn('arm16k_virtio_seat_nonce='+N,argv[argv.index('-append')+1])
 def test_guest_delivers_corrected_local_input_not_frozen_ancestor(self):
  prepare=load('prepare');c={'arm':Path('/held/lower'),'x86':Path('/held/x86'),'output':self.work};delivery={'guest_files':{'input_seat.py':{'guest_path':'/usr/local/libexec/seat-input.py','mode':'0755'}}}
  with patch.object(prepare.K,'read',return_value=delivery),patch.object(prepare.K,'pin',return_value={'bytes':1,'sha256':'a'*64}):records=prepare.guest_sources(c)
  row=records['input_seat.py'];self.assertEqual(row['source_root'],'arm');self.assertEqual(row['source'],'input_seat.py');self.assertEqual(row['guest_path'],'/usr/local/libexec/seat-input.py')
 def test_host_parser_uses_same_corrected_local_adapter(self):
  original=types.SimpleNamespace(Serial=type('Serial',(),{}),redact_serial=lambda *a:None,parse=lambda *a:None);corrected=object();paths=[]
  def held(name,path):
   paths.append(path)
   if name=='UI_original_ARM_protocol':return original
   if name=='UI_corrected_modern_input':return corrected
   return types.SimpleNamespace()
  with patch.object(P,'load',side_effect=held):P.bind(Path('/held/lower'))
  self.assertIs(original.INPUT,corrected);self.assertIn(Path('/held/lower/input_seat.py'),paths)
 def test_corrected_observer_keeps_bounded_diagnostics_and_UI_gate(self):
  source=(HERE/'observer.py').read_text();self.assertIn('input_parent.census()',source);self.assertIn('os.fsync',source);self.assertIn('arm_ui_gate.wait_installed(nonce,180)',source);self.assertLess(source.index('arm_ui_gate.wait_installed'),source.index("frame('SEAT_LOGIN_READY'"))
 def test_current_lower_archive_and_pass_report_are_exact_portable_DATA(self):
  refs=K.read(HERE/'references.json');self.assertEqual(refs['arm_source']['source_commit'],'9508955ca3c85077257da42fe38b9c015ba2240d');self.assertEqual(refs['arm_source']['source_lock'],{'bytes':19179,'sha256':'06153a9b191aac9f0c974334e6e60ca32b0230ca3581f6d1e404f2efc99b15ad'})
  actual=K.read(HERE/'actual-data.json')['actual_minimal155_pass']
  for key in ['report','Root_decision']:
   row=actual[key];K.checked(HERE/row['archived_path'],{k:row[k]for k in ['bytes','sha256']})
  report=K.read(HERE/actual['report']['archived_path']);self.assertIs(K.minimal_seat_report(report),report)
  decision=K.read(HERE/actual['Root_decision']['archived_path']);self.assertEqual(set(decision['independent_checks_passed']),set(report['seat']['independent_checks']))
 def test_actual_lower_pass_requires_every_independent_check_and_retirement(self):
  actual=K.read(HERE/'data/minimal155-r4-report.json')
  for name in actual['seat']['independent_checks']:
   for value in [False,1,None]:
    changed=copy.deepcopy(actual);changed['seat']['independent_checks'][name]['passed']=value
    with self.subTest(name=name,value=value),self.assertRaises(AssertionError):K.minimal_seat_report(changed)
  for key in ['normal_VT_PAM_logout_observed','owned_container_absence_verified','cleanup_ownership_verified']:
   changed=copy.deepcopy(actual);changed[key]=False
   with self.subTest(key=key),self.assertRaises(AssertionError):K.minimal_seat_report(changed)
 def test_exact_lower_check_helper_is_delivered_readonly_at_expected_guest_path(self):
  prepare=load('prepare');c={'arm':Path('/held/lower'),'x86':Path('/held/x86'),'output':self.work}
  with patch.object(prepare.K,'read',return_value={'guest_files':{}}),patch.object(prepare.K,'pin',return_value={'bytes':1,'sha256':'a'*64}):row=prepare.guest_sources(c)['observer_checks.py']
  self.assertEqual((row['source_root'],row['source'],row['guest_path'],row['mode']),('arm','observer_checks.py','/var/lib/arm16k-virtio-seat/observer-checks.py','0600'))
  ref=K.read(HERE/'references.json')['arm_source']['observer_checks'];self.assertEqual(ref,{'filename':'observer_checks.py','bytes':4896,'sha256':'cc73f760a80aee65a8b708fb969afdbbcbd1ac6e1ea83ab381c085b755de3508'})
 def test_corrected_observer_uses_specialized_GPU_only_and_named_checks(self):
  source=(HERE/'observer.py').read_text();self.assertIn("D/'observer-checks.py'",source);self.assertIn("independent('gpu-record',*checks.gpu_record(",source);self.assertIn("independent('keyboard-record',*checks.record(",source);self.assertNotIn('final_gpu==gpu',source)
  actual=K.read(HERE/'data/minimal155-r4-report.json')['seat']['independent_checks']['gpu-record'];self.assertEqual(actual['comparison'],'GPU_TAG_SET_VALUES_ONLY_ALL_OTHER_BYTES_EXACT')
  self.assertTrue(all(v['equal']and v['before']==v['after']==['master-of-seat','seat','uaccess']for v in actual['tag_sets'].values()))
 def test_actor_nonce_cannot_supply_extra_argv(self):
  with self.assertRaises(AssertionError):A.qemu_argv(' -nic user',1794700000)
 def test_UI_HOLD_precedes_ready_and_keeps_original_capture_groups(self):
  pattern=(rb'SEAT_KEY_ACK ('+N.encode()+rb') ([1-9][0-9]*)\n');match=re.search(P.guard_pattern(N,pattern),b'UI_HOLD '+N.encode()+b' {"stage":"ownership"}\nSEAT_KEY_ACK '+N.encode()+b' 1\n');self.assertTrue(match.group(0).startswith(b'UI_HOLD'))
  match=re.search(P.guard_pattern(N,pattern),b'SEAT_KEY_ACK '+N.encode()+b' 41\n');self.assertEqual(match.groups(),(N.encode(),b'41'))
 def test_UI_frame_requires_exact_nonce_and_single_frame(self):
  raw=('UI_SESSION_BEGIN '+N+'\n{}\nUI_SESSION_END '+N+'\n').encode();self.assertEqual(P.parse_ui(raw,N),{})
  with self.assertRaises(AssertionError):P.parse_ui(raw,'2'*32)
  with self.assertRaises(AssertionError):P.parse_ui(raw+raw,N)
 def test_strict_ownership_warning_and_sync_failure_stay_HOLD(self):
  d=O.analyze(b'',b'unrecognized warning\n',1,{});self.assertTrue(d['HOLD']);called=[]
  with self.assertRaises(OSError):O.signal_after_sync(lambda:(_ for _ in()).throw(OSError('inert sync refusal')),lambda:called.append('PASS'))
  self.assertFalse(called)
 def test_durable_283_gate_requires_matching_signal(self):
  versions,value=installed();directory=self.work/'receipts';signals=self.work/'signals';signals.mkdir(mode=0o755);owner=(os.getuid(),os.getgid());writer=R.Writer(directory,N,owner);writer.write('installed.json',value)
  self.assertIsNone(R.installed_gate(directory,N,'a'*64,versions,24,owner,signals));signal=signals/'installed.json';signal.write_text(json.dumps(value));signal.chmod(0o644);self.assertEqual(R.installed_gate(directory,N,'a'*64,versions,24,owner,signals),value)
 def test_old_x86_receipt_or_stale_nonce_refused(self):
  _,value=installed();value['baseline_count']=164
  with self.assertRaises(ValueError):R.validate('installed.json',value,N)
  _,value=installed()
  with self.assertRaises(ValueError):R.validate('installed.json',value,'2'*32)
 def test_archive_metadata_and_scriptlet_are_inert(self):
  path=self.work/'inert.tar';body=b'pkgname = inert\npkgver = 1-1\narch = any\n'
  with tarfile.open(path,'w')as t:
   for name,data in [('.PKGINFO',body),('.INSTALL',b'touch /tmp/forbidden-never-executed\n'),('usr/share/inert',b'plain DATA')]:m=tarfile.TarInfo(name);m.size=len(data);t.addfile(m,io.BytesIO(data))
  class Elf:
   @staticmethod
   def parse_elf(data):return None
  d=D.package(path,Elf);self.assertEqual(d['metadata']['arch'],['any']);self.assertIn('.INSTALL',d['controls']);self.assertNotIn('.INSTALL',d['payload'])
 def test_archive_traversal_refused(self):
  path=self.work/'bad.tar'
  with tarfile.open(path,'w')as t:m=tarfile.TarInfo('../outside');m.size=1;t.addfile(m,io.BytesIO(b'x'))
  with self.assertRaises(AssertionError):D.package(path,None)
 def test_preparation_fence_refuses_mutated_mounts_or_resources(self):
  mounts=[('bind','/source'+str(i),'/target'+str(i),i==8)for i in range(9)];row={'Name':'/owned','Image':'sha256:'+'2'*64,'Config':{'Labels':{'owner':'test'},'Entrypoint':['/usr/bin/python3'],'Cmd':['-I','-B','/code/prepare_image.py']},'Mounts':[dict(Type=k,Source=s,Destination=d,RW=r)for k,s,d,r in mounts],'HostConfig':{'NetworkMode':'none','ReadonlyRootfs':True,'CapDrop':['ALL'],'CapAdd':[],'Privileged':False,'Devices':[],'Init':False,'SecurityOpt':['no-new-privileges'],'Memory':3*1024**3,'MemorySwap':3*1024**3,'NanoCpus':2000000000,'PidsLimit':256}}
  K.preparation_confinement(row,'owned',row['Image'],{'owner':'test'},mounts)
  for field,value in [('NetworkMode','host'),('CapAdd',['SYS_ADMIN']),('Init',True),('MemorySwap',6*1024**3),('PidMode','host')]:
   changed=copy.deepcopy(row);changed['HostConfig'][field]=value
   with self.subTest(field=field),self.assertRaises(AssertionError):K.preparation_confinement(changed,'owned',row['Image'],{'owner':'test'},mounts)
 def test_cleanup_validates_stable_identity_after_both_assembly_file_loops(self):
  previous_umask=os.umask(0o077);self.addCleanup(os.umask,previous_umask)
  prepare=load('prepare');out=self.work/'new';base=self.work/'base';base.mkdir();kernel=self.work/'kernel';kernel.mkdir();image_id='sha256:'+'2'*64;ref={'bytes':1,'sha256':'a'*64};events=[];rows={}
  lower=types.SimpleNamespace(lock=lambda:{'base_files':{'kernel.config':ref},'base_prepared':ref})
  c={'authority':{'tool_image_id':image_id},'lower':lower,'base':{'nonce':'2'*32},'original_marker':ref,'kernel':{},'manifest':{},'tool':{},'tool_qualification':{},'arm':Path('/held/arm'),'x86':Path('/held/x86')}
  class Cancel:
   pending=[];cleaning=False
   def __enter__(self):return self
   def __exit__(self):pass
  class Owned:
   def __init__(self,name,cidfile,image,labels,base,out):self.name=name;self.cidfile=cidfile;self.submitted=False;rows['scope']=self;rows['labels']=labels
   def listing(self,deadline):return None
   def recover(self,deadline):self.validate(rows['container']);return rows['container']
   def cleanup(self,report):
    events.append(('cleanup',self.name));self.validate(rows['container']);report['owned_container_absence_verified']=True
  class Runner:
   def __init__(self,*args):pass
   def run(self,argv,**kwargs):
    if argv[1:2]==['info']:value=['name=rootless']
    elif argv[1:3]==['image','inspect']:value=[{'Id':image_id,'Config':{'Labels':{}}}]
    elif argv[1:2]==['create']:
     mounts=[]
     for i,v in enumerate(argv):
      if v=='--mount':
       parts=dict(x.split('=',1)for x in argv[i+1].split(',')if '='in x);mounts.append(dict(Type=parts['type'],Source=parts['source'],Destination=parts['target'],RW='readonly'not in argv[i+1].split(',')))
     rows['container']={'Name':'/'+rows['scope'].name,'Image':image_id,'Config':{'Labels':rows['labels'],'Entrypoint':['/usr/bin/python3'],'Cmd':['-I','-B','/code/prepare_image.py']},'Mounts':mounts,'State':{'ExitCode':0,'OOMKilled':False,'Running':False},'HostConfig':{'NetworkMode':'none','ReadonlyRootfs':True,'CapDrop':['ALL'],'CapAdd':[],'Privileged':False,'Devices':[],'Init':False,'SecurityOpt':['no-new-privileges'],'Memory':3*1024**3,'MemorySwap':3*1024**3,'NanoCpus':2000000000,'PidsLimit':256}};value=None
    else:
     self_outer.assertEqual(argv[:3],['docker','start','-a']);(out/'assembly/prepared.json').write_text(json.dumps({'operation':K.OP,'nonce':N,'files':{'guest.raw':ref}}));value=None
    return types.SimpleNamespace(returncode=0,stdout=json.dumps(value))
  self_outer=self
  def checked(path,expected):events.append(('checked',Path(path).name));return path
  def held(name,path):return types.SimpleNamespace(Runner=Runner)if name=='UI_ARM_held_runner'else types.SimpleNamespace(OwnedContainer=Owned,Cancellation=Cancel)
  argv=['prepare','--allow-prepare-arm16k-ui-glib290']
  for flag in ['base','base-first-boot-report','materials','additions-manifest','kernel-bundle','qemu-metadata','tool-qualification','minimal155-report','minimal155-prepared','authority','output']:
   value=base if flag=='base'else kernel if flag=='kernel-bundle'else out if flag=='output'else self.work/flag;argv+=['--'+flag,str(value)]
  argv+=['--authority-sha256','a'*64]
  mem='MemAvailable: 99999999 kB\n';read_text=Path.read_text
  def read(path,*args,**kwargs):return mem if path==Path('/proc/meminfo')else read_text(path,*args,**kwargs)
  with patch.object(sys,'argv',argv),patch.object(prepare.os,'geteuid',return_value=1000),patch.object(prepare.K,'preflight',return_value=c),patch.object(prepare.K,'output_path',return_value=out),patch.object(prepare.K,'load',side_effect=held),patch.object(prepare.K,'checked',side_effect=checked),patch.object(prepare.K,'pin',return_value=ref),patch.object(prepare,'stage_inputs',return_value=({},{})),patch.object(prepare,'guest_sources',return_value={}),patch.object(Path,'read_text',read),patch.object(prepare.shutil,'disk_usage',return_value=shutil._ntuple_diskusage(10*1024**3,0,10*1024**3)),contextlib.redirect_stdout(io.StringIO()):
   self.assertEqual(prepare.main(),0)
  report=K.read(out/'preparation.json');self.assertEqual(report['status'],'PREPARED_NOT_BOOTED');self.assertTrue(report['owned_container_absence_verified']);self.assertNotIn('cleanup_errors',report)
  cleanup=next(i for i,event in enumerate(events)if event[0]=='cleanup');self.assertIn(('checked','guest.raw'),events[:cleanup]);self.assertIn(('checked','kernel.config'),events[:cleanup]);self.assertTrue(events[cleanup][1].startswith('cachy-arm16k-ui-glib290-prepare-'))
  # Stable identity must still reject another container after the file loops.
  changed=copy.deepcopy(rows['container']);changed['Name']='/kernel.config'
  with self.assertRaises(AssertionError):rows['scope'].validate(changed)
 def test_constructor_leaves_durable_receipt_directory_for_exclusive_writer(self):
  # Execute only the real fixed directory-declaration loop as DATA/control code.
  # No image edit, process, package, VM or whole constructor is invoked.
  tree=ast.parse((HERE/'prepare_image.py').read_text());main=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='main')
  loops=[n for n in main.body if isinstance(n,ast.For)and isinstance(n.iter,ast.Tuple)and len(n.body)==1 and isinstance(n.body[0],ast.Expr)and isinstance(n.body[0].value,ast.Call)and isinstance(n.body[0].value.func,ast.Name)and n.body[0].value.func.id=='directory'];self.assertEqual(len(loops),1)
  directories=[];exec(compile(ast.Module(body=loops,type_ignores=[]),'<fixed-fixture-directory-control>','exec'),{'D':'/var/lib/arm16k-virtio-seat','directory':directories.append})
  self.assertIn('/opt/ui-session/ownership',directories);self.assertNotIn(str(R.DIRECTORY),directories)
  directory=self.work/R.DIRECTORY.relative_to('/');directory.parent.mkdir(parents=True);owner=(os.getuid(),os.getgid());writer=R.Writer(directory,N,owner)
  self.assertEqual(R.read(directory,'stage.json',owner),{'schema_version':1,'nonce':N,'stage':'starting'})
  # Precreation reproduces the original refusal; never make Writer reuse a dir.
  with self.assertRaises(FileExistsError):R.Writer(directory,N,owner)
  alias=self.work/'receipt-alias';alias.symlink_to(directory,target_is_directory=True)
  with self.assertRaises(FileExistsError):R.Writer(alias,N,owner)
 def test_private_output_and_reserve_before_actor(self):
  with patch.object(K.shutil,'disk_usage',return_value=shutil._ntuple_diskusage(10*1024**3,0,10*1024**3)):self.assertEqual(K.output_path(self.work/'new'),self.work/'new')
  with patch.object(K.shutil,'disk_usage',return_value=shutil._ntuple_diskusage(10*1024**3,0,2*1024**3)):
   with self.assertRaises(AssertionError):K.output_path(self.work/'new')

class BootMemoryControls(Fenced):
 def setUp(self):
  super().setUp();self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.work=Path(self.tmp.name);self.cg=self.work/'cgroup';self.cg.mkdir();self.out=self.work/'out';self.out.mkdir()
  for name,value in {'memory.events':'low 0\nhigh 0\nmax 2\noom 1\noom_kill 1\noom_group_kill 0\n','memory.peak':str(3*1024**3),'memory.current':'12345','memory.max':str(4*1024**3),'memory.swap.current':'0','memory.swap.max':'0'}.items():(self.cg/name).write_text(value)
 def test_explicit_boot_admission_requires_exact4G_no_swap(self):
  value=admitted();value['allow_boot']=True;self.assertEqual(K.admission(value,'boot')['boot_resources'],K.BOOT_RESOURCES)
  for field,value in [('memory_bytes',3*1024**3),('memory_swap_bytes',5*1024**3),('cpus',3),('guest_memory_MiB',3072),('host_reserve_bytes',0)]:
   changed=admitted();changed['allow_boot']=True;changed['boot_resources'][field]=value
   with self.subTest(field=field),self.assertRaises(ValueError):K.admission(changed,'boot')
 def test_static_actual_boot_source_policy_join(self):
  boot=(HERE/'boot.py').read_text();prepare=(HERE/'prepare.py').read_text();self.assertIn("'--memory=4g','--memory-swap=4g'",boot);self.assertIn("'--memory=3g','--memory-swap=3g'",prepare);self.assertEqual(K.BOOT_RESOURCES['host_minimum_bytes'],K.BOOT_RESOURCES['memory_bytes']+K.BOOT_RESOURCES['host_reserve_bytes']);self.assertIn('>=6*1024**3',boot)
  argv=A.qemu_argv(N,1794700000);self.assertEqual(int(argv[argv.index('-m')+1]),K.BOOT_RESOURCES['guest_memory_MiB']);self.assertIn('1024*1024**2,1024*1024**2',(HERE/'ui_glib_actor.py').read_text())
 def test_wrapper_projects_only_prechecked_memory_and_existing_command(self):
  boot=load('boot');seen=[]
  class Legacy:
   def validate(self,row):
    seen.append(copy.deepcopy(row));self_outer.assertEqual(row['HostConfig']['Memory'],3*1024**3);self_outer.assertEqual(row['HostConfig']['MemorySwap'],3*1024**3)
    assert row['Name']=='/owned'and row['Mounts']==[{'Source':'/inputs','RW':False},{'Source':'/work','RW':True}]and row['HostConfig']['CapDrop']==['ALL']and row['HostConfig']['CapAdd']==[]and row['HostConfig']['NanoCpus']==2000000000 and row['HostConfig']['PidsLimit']==256
  self_outer=self;scope=boot.custody_class(types.SimpleNamespace(OwnedContainer=Legacy))();row={'Name':'/owned','Config':{'Cmd':['-I','-B','/inputs/ui_glib_actor.py']},'Mounts':[{'Source':'/inputs','RW':False},{'Source':'/work','RW':True}],'HostConfig':{'Memory':4*1024**3,'MemorySwap':4*1024**3,'SecurityOpt':['no-new-privileges'],'CapDrop':['ALL'],'CapAdd':[],'NanoCpus':2000000000,'PidsLimit':256}}
  original=copy.deepcopy(row);scope.validate(row);self.assertEqual(row,original);expected=copy.deepcopy(row);expected['Config']['Cmd']=['-I','-B','/opt/vm_actor.py'];expected['HostConfig']['Memory']=expected['HostConfig']['MemorySwap']=3*1024**3;self.assertEqual(seen,[expected])
  for field,value in [('Memory',3*1024**3),('MemorySwap',3*1024**3),('MemorySwap',5*1024**3),('CapAdd',['SYS_ADMIN']),('NanoCpus',3000000000),('PidsLimit',512),('SecurityOpt',[]),('PidMode','host')]:
   changed=copy.deepcopy(row);changed['HostConfig'][field]=value
   with self.subTest(field=field,value=value),self.assertRaises(AssertionError):scope.validate(changed)
  changed=copy.deepcopy(row);changed['Mounts'][0]['RW']=True
  with self.assertRaises(AssertionError):scope.validate(changed)
 def test_memory_snapshot_preserves_actual_numeric_counters_and_private_durability(self):
  calls=[];fsync=os.fsync
  with patch.object(A.os,'fsync',side_effect=lambda fd:(calls.append(fd),fsync(fd))[1]):value=A.memory_snapshot(self.out,N,'before-vm',self.cg)
  self.assertEqual(value['memory.events']['oom_kill'],1);self.assertEqual(value['memory.max'],4*1024**3);self.assertEqual(len(calls),2);path=self.out/'memory-before-vm.json';self.assertEqual(path.stat().st_mode&0o777,0o600);self.assertLess(path.stat().st_size,16384);self.assertEqual(json.loads(path.read_text()),value)
  boot=load('boot');self.assertEqual(boot.memory_evidence(self.out,N)['before-vm']['actual_numeric_cgroup'],value)
 def test_memory_host_export_refuses_foreign_nonce_or_unbound_fields(self):
  A.memory_snapshot(self.out,N,'before-vm',self.cg);path=self.out/'memory-before-vm.json';original=json.loads(path.read_text());boot=load('boot')
  for field,value in [('nonce','2'*32),('raw_private_text','not exported'),('memory.max',3*1024**3)]:
   changed=copy.deepcopy(original);changed[field]=value;path.write_text(json.dumps(changed));path.chmod(0o600)
   with self.subTest(field=field),self.assertRaises(AssertionError):boot.memory_evidence(self.out,N)
 def test_memory_refusals_keep_bounded_receipt(self):
  for name,value in [('memory.max',str(3*1024**3)),('memory.swap.max','1'),('memory.peak','max'),('memory.current','-1'),('memory.events','secret arbitrary text\n'),('memory.events','x'*4097)]:
   original=(self.cg/name).read_bytes();(self.cg/name).write_text(value);out=self.work/('refusal'+str(len(list(self.work.iterdir()))));out.mkdir()
   with self.subTest(name=name),self.assertRaises((AssertionError,ValueError)):A.memory_snapshot(out,N,'before-vm',self.cg)
   receipt=json.loads((out/'memory-before-vm.json').read_text());self.assertEqual(receipt['status'],'REFUSED');self.assertNotIn('arbitrary',json.dumps(receipt));(self.cg/name).write_bytes(original)
 def test_memory_missing_or_alias_refuses_without_raw_error_export(self):
  path=self.cg/'memory.peak';path.unlink();path.symlink_to(self.cg/'memory.current')
  with self.assertRaises(OSError):A.memory_snapshot(self.out,N,'before-vm',self.cg)
  value=json.loads((self.out/'memory-before-vm.json').read_text());self.assertEqual(value['status'],'REFUSED');self.assertEqual(value['error_category'],'OSError')
 def test_memory_final_is_captured_on_failure(self):
  stages=[]
  real=A.memory_snapshot
  with patch.object(A,'memory_snapshot',side_effect=lambda work,nonce,stage: (stages.append(stage),real(work,nonce,stage,self.cg))[1]):
   with self.assertRaisesRegex(RuntimeError,'inert failure'):
    with A.memory_receipts(self.out,N):raise RuntimeError('inert failure')
  self.assertEqual(stages,['before-vm','final']);self.assertTrue((self.out/'memory-final.json').is_file())
 def test_memory_fsync_refusal_never_yields_VM_permission(self):
  with patch.object(A.os,'fsync',side_effect=OSError('inert fsync refusal')):
   with self.assertRaises(OSError):A.memory_snapshot(self.out,N,'before-vm',self.cg)
 def test_at_exit_snapshot_and_retirement_receipt_precede_final(self):
  source=(HERE/'ui_glib_actor.py').read_text();self.assertLess(source.index("(W/'qemu-retirement.json').write_text(json.dumps(result"),source.index("memory_snapshot(W,manifest['nonce'],'at-qemu-exit')"));self.assertIn("finally:memory_snapshot(work,nonce,'final')",source)

class AcceptanceControls(Fenced):
 def value(self):
  # Modeled predicate input, never credited as GTK or guest runtime evidence.
  result=load('result');files={name:'a'*64 for name in result.FILES};props={'Id':'1','Active':True,'Seat':['seat0','/seat0'],'User':[1000,'/u'],'TTY':'tty1','Service':'login','Remote':False}
  _,receipt=installed();gui={'status':'PASS_REAL_INSTALLED_GTK_CONTROLS','uid':1000,'user_files':files,'initial_inspect_read_only':True,'preview_read_only':True,'explicit_apply':True,'repeat_apply_preserved_user_edit':True,'rendering':{'display_type':'GdkX11Display','renderer_type':'GskCairoRenderer','root_image_bytes':3145728,'root_image_sha256':'b'*64,'image_exported':False}}
  client={'status':'PASS_REAL_SEAT_UI_CLIENT','uid':1000,'tty':'/dev/tty1','pid':1001,'process_session':1000,'removal_preserved_user_files':True,'private_X_server_and_session_bus_retired':True,'gui':gui,'owned_GUI_process_retirement':{'passed':True,'group_census':'EMPTY_TWICE'}}
  root={'status':'PASS_UI_GUEST_ALPM_LIFECYCLE','architecture':'aarch64','pagesize':16384,'installed':{'status':'INSTALLED_EXACT_173_TOUCHED_172_ADDED_1_UPGRADED','baseline_count':111,'installed_count':283,'dependency_and_ownership_checks':True},'baseline_inventory_restored':True,'package_owned_nondirectory_paths_absent':True,'original_PAM_policy_preserved':True,'unrelated_user_file_preserved':True,'user_files_preserved':files,'trust':{'private_keys':False,'freshness_or_production_acceptance':False,'configuration':'Architecture = aarch64\nSigLevel = Required TrustedOnly\nLocalFileSigLevel = Required TrustedOnly\n'},'client_session_corroboration':{'pid':1001,'process_session':1000,'login1':props},'installation_receipt':receipt,'filesystem_sync':dict.fromkeys(['post-install','post-remove','post-rollback','terminal-pass'],True)}
  root['glib_rollback']={'normal_trusted_ALPM':True,'exact_old_version':'2.88.3-1','old_archive_sha256':'a1498d94c3ff5e52ea157a09bb55bceaa7f94e47ded7c74ac5611d0e0b9b5ec8','ownership_checked':True,'new_only_paths_absent':True,'baseline_namespace_restored':True}
  return result,{'client':client,'root':root}
 def test_modeled_complete_UI_predicate(self):
  result,value=self.value();result.accept_ui(value)
 def test_UI_join_requires_all_six_current_observer_checks(self):
  result,ui=self.value();checks={name:{'passed':True}for name in ['bus-credentials','logind-session','process-vt','keyboard-record','gpu-record','seat-status']};seat={'status':'PASS_ARM16K_VIRTIO_SEAT_REFERENCE_ONLY','nonce':N,'architecture':'aarch64','pagesize':16384,'user':{'logind':{'Id':'1'},'process_session':1000},'independent_checks':checks}
  self.assertEqual(result.join(seat,ui,N)['status'],'PASS_EMULATED_ARM16K_GLIB290_REAL_SEAT_UI_LIFECYCLE_ONLY')
  for name in checks:
   changed=copy.deepcopy(seat);changed['independent_checks'][name]['passed']=False
   with self.subTest(name=name),self.assertRaises(AssertionError):result.join(changed,ui,N)
  changed=copy.deepcopy(seat);del changed['independent_checks']['gpu-record']
  with self.assertRaises(AssertionError):result.join(changed,ui,N)
 def test_generic_seat_without_UI_cannot_pass(self):
  result,_=self.value()
  with self.assertRaises((KeyError,AssertionError)):result.join({'status':'PASS_ARM16K_VIRTIO_SEAT_REFERENCE_ONLY'},{},N)
 def test_wrong_architecture_counts_or_user_edit_preservation_refused(self):
  for field,value in [('architecture','x86_64'),('pagesize',4096),('baseline_inventory_restored',False)]:
   result,report=self.value();report['root'][field]=value
   with self.subTest(field=field),self.assertRaises(AssertionError):result.accept_ui(report)
  result,report=self.value();report['client']['gui']['repeat_apply_preserved_user_edit']=False
  with self.assertRaises(AssertionError):result.accept_ui(report)
 def test_four_user_files_and_real_renderer_required(self):
  result,report=self.value();report['client']['gui']['user_files']={'unexpected':'a'*64}
  with self.assertRaises(AssertionError):result.accept_ui(report)
  result,report=self.value();report['client']['gui']['rendering']['renderer_type']='MockRenderer'
  with self.assertRaises(AssertionError):result.accept_ui(report)
 def test_whole_owned_GUI_and_sync_required(self):
  result,report=self.value();report['client']['owned_GUI_process_retirement']['group_census']='LEFTOVERS'
  with self.assertRaises(AssertionError):result.accept_ui(report)
  result,report=self.value();report['root']['filesystem_sync']['post-install']=False
  with self.assertRaises(AssertionError):result.accept_ui(report)

class NamespaceControls(Fenced):
 def test_baseline_association_detects_forged_provides_or_files(self):
  row={'glib2':{'version':'2.88.3-1','directory':'glib2-2.88.3-1','provides':['libgio-2.0.so=0-64'],'files':['usr/lib/Gio.typelib']}};pin=K.baseline_association(row);changed=copy.deepcopy(row);changed['glib2']['provides'].append('forged');self.assertNotEqual(K.baseline_association(changed),pin);changed=copy.deepcopy(row);changed['glib2']['files'].append('usr/bin/ghost');self.assertNotEqual(K.baseline_association(changed),pin)
 def test_actual_path_alias_requires_owned_executable_target(self):
  payload={'usr/bin/python3':{'type':'2','link':'python3.14'},'usr/bin/python3.14':{'type':'0','mode':0o755,'uid':0,'gid':0}}
  self.assertEqual(K.executable(payload,'usr/bin/python3')['type'],'0');payload['usr/bin/python3']['link']='../../../outside'
  with self.assertRaises(AssertionError):K.executable(payload,'usr/bin/python3')
 def test_alias_cycle_or_nonexecutable_refused(self):
  payload={'usr/bin/x':{'type':'2','link':'x'}}
  with self.assertRaises(AssertionError):K.executable(payload,'usr/bin/x')
  payload={'usr/bin/x':{'type':'0','mode':0o644,'uid':0,'gid':0}}
  with self.assertRaises(AssertionError):K.executable(payload,'usr/bin/x')
 def test_secret_packet_is_rejected_without_any_GPG_process(self):
  module=K.load('UI_inert_public_packet_control',K.ROOT/'scripts/repository/revoke.py')
  with patch.object(subprocess,'run',side_effect=AssertionError('no process')):
   with self.assertRaises(ValueError):module.packets(b'\xc5\x01\x00')

class GLibSuccessorControls(Fenced):
 def fixtures(self):
  facts=K.read(HERE/'data/glib-materials.json');anchor=K.read(HERE/'data/additions172-anchor.json');baseline={n:r['version']for n,r in K.read(HERE/'data/baseline-relations.json').items()};rows=[{'name':n,'version':r['version'],**r['archive']}for n,r in anchor.items()];rows.append({'name':'glib2','version':'2.90.1-1',**facts['new']['archive']});rollback={'name':'glib2','version':'2.88.3-1','filename':'glib2-2.88.3-1-aarch64.pkg.tar.xz',**facts['old']['archive']};return load('closure'),baseline,rows,rollback
 def test_exact173_touched283_after_and_no_glib_removal(self):
  L,before,rows,old=self.fixtures();after,names=L.plan(before,rows,old);self.assertEqual(len(after),283);self.assertEqual(after['glib2'],'2.90.1-1');self.assertEqual({n:v for n,v in before.items()if n!='glib2'},{n:after[n]for n in before if n!='glib2'});self.assertEqual(len(names),172);self.assertNotIn('glib2',names)
  argv=L.removal_argv('/var/lib/arm16k-virtio-seat/pacman.conf',names);self.assertEqual(argv[:5],['pacman','--config','/var/lib/arm16k-virtio-seat/pacman.conf','--noconfirm','-R']);self.assertNotIn('glib2',argv[5:]);self.assertNotIn('--nodeps',argv);self.assertEqual(L.rollback_argv('/var/lib/arm16k-virtio-seat/pacman.conf',old)[-2:],['-U','/var/lib/arm16k-virtio-seat/materials/'+old['filename']])
 def test_rollback_wrong_version_sha_and_arbitrary_remove_refused(self):
  L,before,rows,old=self.fixtures();after,names=L.plan(before,rows,old)
  for key,value in [('sha256','0'*64),('version','2.90.1-1'),('filename','other.pkg.tar.xz')]:
   changed=dict(old);changed[key]=value
   with self.subTest(key=key),self.assertRaises(AssertionError):L.rollback_argv('/var/lib/arm16k-virtio-seat/pacman.conf',changed)
  for changed in [names+['glib2'],['--nodeps',*names[1:]],names[:-1]]:
   with self.assertRaises(AssertionError):L.removal_argv('/var/lib/arm16k-virtio-seat/pacman.conf',changed)
 def test_before_baseline_or_additional_baseline_upgrade_refused(self):
  L,before,rows,old=self.fixtures();changed=dict(before);changed['glib2']='2.90.1-1'
  with self.assertRaises(AssertionError):L.plan(changed,rows,old)
  changed=copy.deepcopy(rows);changed[0]['name']=next(n for n in before if n!='glib2')
  with self.assertRaises(AssertionError):L.plan(before,changed,old)
  changed=copy.deepcopy(rows);changed[-1]['sha256']='0'*64
  with self.assertRaises(AssertionError):L.plan(before,changed,old)
 def test_new_manifest_proposal_is_not_Root_or_old172_mutation(self):
  compose=load('compose');anchor=K.read(HERE/'data/additions172-anchor.json');original={'kind':'ARM16K_FIRST_LOGIN_UI_ADDITIONS_V1','archives':anchor,'required_namespace':{}};unchanged=copy.deepcopy(original);draft=compose.propose(original);self.assertEqual(original,unchanged);self.assertEqual(len(draft['archives']),173);self.assertEqual(draft['rollback']['version'],'2.88.3-1');self.assertIsNone(draft['issued_by']);self.assertIsNone(draft['trust']);self.assertEqual(draft['status'],'PROPOSAL_NOT_ROOT_ADMITTED')
  with self.assertRaises(ValueError):K.admission(draft,'prepare')
 def test_old_Root_authority_and_missing_explicit_GLib_optin_refused(self):
  value=admitted();value['kind']='ARM16K_FIRST_LOGIN_UI_AUTHORITY_V1'
  with self.assertRaises(ValueError):K.admission(value,'prepare')
  value=admitted();value['allow_glib_runtime_upgrade']=False
  with self.assertRaisesRegex(ValueError,'GLib runtime change'):K.admission(value,'prepare')
 def test_actual173_forward_and_exact_old_glib_prepare_metadata(self):
  facts=K.read(HERE/'data/glib-materials.json');anchor=K.read(HERE/'data/additions172-anchor.json');rows={**anchor,'glib2':{'version':'2.90.1-1'}};K.validate_prepare_proof(facts['metadata_evidence'],rows)
  for label in ['forward','rollback_glib_after_modeled_172_removal']:
   bad=copy.deepcopy(facts['metadata_evidence']);bad[label]['prepare']['errors']=[{'failure':'inert'}]
   with self.subTest(label=label),self.assertRaises(AssertionError):K.validate_prepare_proof(bad,rows)
  self.assertTrue(facts['symbol_join']['both_measured_missing_symbols_now_exported']);self.assertEqual(facts['symbol_join']['old_exports_lost'],[]);self.assertEqual(len(facts['new']['all_ELF']),18)
 def test_all_baseline_edges_required_and_wrong_provider_refused(self):
  S=types.SimpleNamespace(atom=lambda e:(e,None,None),satisfies=lambda v,o,w:True);deps={'held-baseline':['libffi'],'glib2':['libc']};providers={'libffi':[('libffi','1')],'libc':[('glibc','2')]};edges=[{'package':'held-baseline','relation':'libffi','provider':'libffi'},{'package':'glib2','relation':'libc','provider':'glibc'}];K.complete_edges(edges,deps,providers,S)
  for bad in [edges[1:],edges+[edges[0]],[{**edges[0],'provider':'glibc'},edges[1]]]:
   with self.assertRaises(AssertionError):K.complete_edges(bad,deps,providers,S)
 def test_versioned_root_runtime_preserves_ordinary173_checks_and_old_rollback(self):
  source=(HERE/'root_fixture.py').read_text();self.assertIn("len(rows)==173",source);self.assertIn("pacman+['-Qkk',*[r['name'] for r in rows]]",source);self.assertIn("closure.removal_argv(str(conf),addition_names)",source);self.assertIn("closure.rollback_argv(str(conf),contract['rollback'])",source);self.assertLess(source.index("call('trusted-rollback'"),source.index("call('rollback-ownership'"));self.assertIn("receipts.DIRECTORY/'rollback'",source);self.assertIn("sha(Path(p))==h for p,h in contract['original_file_pins'].items()",source)
  self.assertNotIn('--nodeps',source);self.assertNotIn('--noscriptlet',source);self.assertNotIn('--nohooks',source);self.assertIn('${#archives[@]} == 173',(HERE/'guest-install.sh').read_text())
 def test_result_requires_real_old_glib_and_postrollback_sync(self):
  model=AcceptanceControls();result,value=model.value();result.accept_ui(value)
  for key,replacement in [('normal_trusted_ALPM',False),('ownership_checked',False),('baseline_namespace_restored',False),('old_archive_sha256','0'*64),('exact_old_version','2.90.1-1')]:
   bad=copy.deepcopy(value);bad['root']['glib_rollback'][key]=replacement
   with self.subTest(key=key),self.assertRaises(AssertionError):result.accept_ui(bad)
  bad=copy.deepcopy(value);bad['root']['filesystem_sync']['post-rollback']=False
  with self.assertRaises(AssertionError):result.accept_ui(bad)
 def test_independent_installed_join_uses283_not111plus173(self):
  L,before,rows,rollback=self.fixtures();after,_=L.plan(before,rows,rollback);boot=load('boot');epoch=1794749507;clock={'RTC_PRESENT':'yes','RTC_DRIVER':'pl031','RTC_HCTOSYS':'1','RTC_CLOCK_ADVANCED':'yes','CLOCK_SETTING':'none','HOST_BOOT_UTC':str(epoch),'GUEST_BEFORE_CRYPTO_UTC':str(epoch+12),'RTC_BEFORE_CRYPTO_UTC':str(epoch+12)};text=''.join(n+' '+v+'\n'for n,v in sorted(after.items())).encode();gate={'status':'PASS','nonce':N,'baseline_count':111,'installed_count':283,'trusted_ALPM_completed':True,'ordinary_hooks_scriptlets':True,'policy_owner':'networkmanager','additions_sha256':'a'*64,'actual_inventory_sha256':hashlib.sha256(text).hexdigest(),'clock':clock,'durability':'successful install service after sync-f boundary'};prepared={'nonce':N,'lineage':{'additions':{'archives':{r['name']:r for r in rows}},'additions_pin':{'sha256':'a'*64}},'base_packages':[{'name':n,'version':v}for n,v in before.items()]}
  self.assertEqual(boot.installed({'installed_gate':gate},prepared,epoch,epoch+20),gate)
  bad=copy.deepcopy(gate);bad['installed_count']=284
  with self.assertRaises(AssertionError):boot.installed({'installed_gate':bad},prepared,epoch,epoch+20)
 def test_old_actor_command_cannot_enter_new_custody(self):
  boot=load('boot')
  class Legacy:
   def validate(self,row):raise AssertionError('legacy must not be reached')
  scope=boot.custody_class(types.SimpleNamespace(OwnedContainer=Legacy))()
  with self.assertRaises(AssertionError):scope.validate({'Config':{'Cmd':['-I','-B','/inputs/seat_actor.py']}})

class GLibELFControls(Fenced):
 def test_synthetic_dynsym_defined_undefined_and_wrong_tables_refuse(self):
  G=load('glib_data_audit');strings=b'\0g_existing\0g_timeout_source_new_ns\0';offset=64+3*64;start=offset+len(strings);raw=bytearray(start+48);raw[:6]=b'\x7fELF\x02\x01';struct.pack_into('<H',raw,18,183);struct.pack_into('<Q',raw,40,64);struct.pack_into('<HH',raw,58,64,3);struct.pack_into('<IIQQQQIIQQ',raw,128,0,3,0,0,offset,len(strings),0,0,1,0);struct.pack_into('<IIQQQQIIQQ',raw,192,0,11,0,0,start,48,1,0,8,24);raw[offset:start]=strings;struct.pack_into('<IBBHQQ',raw,start,1,18,0,1,0,0);struct.pack_into('<IBBHQQ',raw,start+24,12,18,0,0,0,0)
  defined,required=G.symbols(bytes(raw));self.assertEqual(defined,{'g_existing'});self.assertEqual(required,{'g_timeout_source_new_ns'})
  for field,offset,value in [('machine',18,62),('section-size',58,63),('section-count',60,65535)]:
   bad=bytearray(raw);struct.pack_into('<H',bad,offset,value)
   with self.subTest(field=field),self.assertRaises(AssertionError):G.symbols(bytes(bad))
  bad=bytearray(raw);struct.pack_into('<I',bad,192+40,3)
  with self.assertRaises(AssertionError):G.symbols(bytes(bad))
 def test_pair_gate_requires_both_symbols_old_export_parity_and_exactGTKset(self):
  G=load('glib_data_audit');facts=K.read(HERE/'data/glib-materials.json');before={n:{k:r[k]for k in ['bytes','sha256','SONAME','NEEDED']}for n,r in facts['old']['providers'].items()};after={n:{k:r[k]for k in ['bytes','sha256','SONAME','NEEDED']}for n,r in facts['new']['providers'].items()};oe=set().union(*(set(v['exported_symbols'])for v in facts['old']['providers'].values()));ne=set().union(*(set(v['exported_symbols'])for v in facts['new']['providers'].values()));required=set(facts['GTK_GLib_strong_requirements'])
  def check(new_exports,requirements=required):
   with patch.object(G,'scan',side_effect=[(before,oe,set(),{}),(after,new_exports,set(),{}),({},set(),requirements,{})]):return G.check(None,None,None,facts,{},None)
  self.assertEqual(check(ne)['status'],'PASS_FIXED_GTK_GLIB_SYMBOL_AND_16K_DATA_ONLY')
  for symbol in ['g_timeout_source_new_ns','g_markup_parse_context_get_attribute_position',next(iter(oe))]:
   with self.subTest(symbol=symbol),self.assertRaises(AssertionError):check(ne-{symbol})
  with self.assertRaises(AssertionError):check(ne,required|{'g_invented_missing_symbol'})
 def test_scan_rejects_missing_archive_and_alias_before_parsing(self):
  G=load('glib_data_audit')
  with tempfile.TemporaryDirectory()as temp:
   root=Path(temp);path=root/'absent'
   with self.assertRaises(AssertionError):G.scan(path,{'bytes':1,'sha256':'0'*64},None)
   source=root/'file';source.write_bytes(b'x');path.symlink_to(source)
   with self.assertRaises(AssertionError):G.scan(path,{'bytes':1,'sha256':hashlib.sha256(b'x').hexdigest()},None)

class ConsoleFrameControls(Fenced):
 def fixture(self):
  info=K.read(HERE/'data/console-status-origin.json');data=(HERE/'data/console-status-minimum.data').read_bytes();self.assertEqual({'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()},info['projected_fixture']);return data,info
 def frame(self,payload=b'{"value":1}',extra=b'',label='SEAT_SESSION',nonce=N):return(label+'_BEGIN '+nonce+'\n').encode()+payload+b'\n'+extra+(label+'_END '+nonce+'\n').encode()
 def test_actual_status_minimum_and_exact_JSON_preservation(self):
  data,info=self.fixture();nonce=info['nonce'];payload=data.split(b'\n')[1].rstrip(b'\r');strict=P.frame_bytes(data,nonce,'SEAT_SESSION');self.assertEqual(strict.split(b'\n')[1],payload);self.assertEqual(json.loads(payload)['status'],'DATA_ONLY_SANITIZED_FRAME_NOT_SEAT_ACCEPTANCE')
  old_body=data.decode().replace('\r','').split('\n',1)[1].split('SEAT_SESSION_END',1)[0].strip()
  with self.assertRaises(json.JSONDecodeError):json.loads(old_body)
  line=data.split(b'\n')[2].rstrip(b'\r');self.assertEqual({'bytes':len(line),'sha256':hashlib.sha256(line).hexdigest()},info['actual_status_line']);self.assertTrue(P.systemd_status_line(line))
 def test_status_at_line_boundaries_before_after_JSON_for_both_labels(self):
  data,info=self.fixture();line=data.split(b'\n')[2].rstrip(b'\r');payload=b'{ "value" : "exact bytes" }'
  for label in ['SEAT_SESSION','UI_SESSION']:
   frame=(label+'_BEGIN '+N+'\n').encode()+line+b'\n'+payload+b'\n'+line+b'\n'+(label+'_END '+N+'\n').encode();strict=P.frame_bytes(frame,N,label);self.assertEqual(strict.split(b'\n')[1],payload)
   if label=='UI_SESSION':self.assertEqual(P.parse_ui(frame,N),{'value':'exact bytes'})
 def test_extra_JSON_or_arbitrary_trailing_frame_body_refused(self):
  for extra in [b'{}\n',b'[]\n',b'true\n',b'arbitrary trailing text\n',b'{"other":2}\n']:
   with self.subTest(extra=extra),self.assertRaises((AssertionError,ValueError)):P.frame_bytes(self.frame(extra=extra),N,'SEAT_SESSION')
  for extra in [b'{}\n',b'[]\n']:
   with self.assertRaises(ValueError):P.frame_bytes(self.frame()+extra,N,'SEAT_SESSION')
  for payload in [b'{} {}',b'{"value":',b'{"value":1']:
   with self.assertRaises(json.JSONDecodeError):P.frame_bytes(self.frame(payload=payload),N,'SEAT_SESSION')
 def test_interior_line_injection_not_repaired(self):
  data,_=self.fixture();line=data.split(b'\n')[2].rstrip(b'\r')
  for payload in [b'{"value":'+line+b'1}',b'{"value":1'+b'\n'+line+b'\n'+b'}']:
   with self.assertRaises((ValueError,AssertionError)):P.frame_bytes(self.frame(payload),N,'SEAT_SESSION')
 def test_unknown_ANSI_unit_text_and_malformed_status_refused(self):
  data,_=self.fixture();line=data.split(b'\n')[2].rstrip(b'\r')
  for bad in [b'\x1b]0;title\x07'+line,line.replace(b'\x1b[0;31m',b'\x1b[35m'),line.replace('…ge bootstrap'.encode(),b'unknown unit'),line.replace(b'1 of 2',b'2 of 1'),line+b'{}',line.replace(b'42s',b'99s')]:
   self.assertFalse(P.systemd_status_line(bad))
   with self.assertRaises(ValueError):P.frame_bytes(self.frame(extra=bad+b'\n'),N,'SEAT_SESSION')
 def test_duplicate_foreign_missing_reversed_frames_refused(self):
  data=self.frame()
  for bad in [data+data,data.replace(N.encode(),b'2'*32,1),data.replace(b'SEAT_SESSION_END',b'MISSING_END'),data.splitlines()[-1]+b'\n'+data.splitlines()[0]+b'\n',data+self.frame(label='UI_SESSION',nonce='2'*32)]:
   with self.assertRaises(AssertionError):P.frame_bytes(bad,N,'SEAT_SESSION')
 def test_interleaved_other_frame_is_not_console_noise(self):
  nested=self.frame(extra=self.frame(label='UI_SESSION'))
  with self.assertRaises(ValueError):P.frame_bytes(nested,N,'SEAT_SESSION')
 def test_status_count_and_payload_and_total_bounds_remain(self):
  data,_=self.fixture();line=data.split(b'\n')[2].rstrip(b'\r')
  for bad in [self.frame(extra=(line+b'\n')*17),self.frame(payload=b'{"x":"'+b'x'*131072+b'"}'),b'x'*(1024**2+1)]:
   with self.assertRaises(AssertionError):P.frame_bytes(bad,N,'SEAT_SESSION')
 def test_separate_complete_frames_same_nonce_allowed(self):
  data=self.frame()+self.frame(label='UI_SESSION');self.assertEqual(P.parse_ui(data,N),{'value':1});self.assertEqual(json.loads(P.frame_bytes(data,N,'SEAT_SESSION').split(b'\n')[1]),{'value':1})
 def test_bind_runs_frozen_validator_and_propagates_semantic_refusal(self):
  data,info=self.fixture();seen=[]
  def frozen(raw,nonce):seen.append((raw,nonce));raise ValueError('inert frozen semantic refusal')
  original=types.SimpleNamespace(Serial=type('Serial',(),{}),redact_serial=lambda *a:None,parse=frozen)
  def held(name,path):return original if name=='UI_original_ARM_protocol'else types.SimpleNamespace()
  with patch.object(P,'load',side_effect=held):P.bind(Path('/held/lower'))
  with self.assertRaisesRegex(ValueError,'frozen semantic refusal'):original.parse(data,info['nonce'])
  self.assertEqual(seen,[(P.frame_bytes(data,info['nonce'],'SEAT_SESSION'),info['nonce'])])

if __name__=='__main__':unittest.main()

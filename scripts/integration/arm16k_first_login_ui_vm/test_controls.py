# SPDX-License-Identifier: MIT
"""Modeled Source/refusal controls only. No Gtk, guest, image or actor is run."""
import argparse,copy,hashlib,importlib.util,io,json,os,re,shutil,subprocess,sys,tarfile,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent

def load(name):
 spec=importlib.util.spec_from_file_location('UI_control_'+name,HERE/(name+'.py'));m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m);return m
K=load('contracts');R=load('receipts');O=load('ownership');P=load('protocol');A=load('seat_actor');D=load('package_data');N='1'*32

def admitted():
 v=json.loads((HERE/'authority.template.json').read_text());v.update(allow_prepare=True,tool_image_id='sha256:'+'2'*64,source_public={'repository':'https://github.com/Gabriel-Kahen/cachy-asahi','commit':'3'*40,'status':'ROOT_REVIEWED_PUBLIC_SOURCE'},resource_review={'status':'ROOT_REVIEWED_FINITE_RESOURCES','reserve_bytes':2*1024**3},accept_unknown_runtime_ABI_for_bounded_VM=True)
 for n in ['qemu_metadata','tool_qualification','additions_manifest','minimal155_report','minimal155_prepared','source_lock']:v[n]={'bytes':1,'sha256':'4'*64}
 return v

def installed():
 versions={str(i):'1-1'for i in range(283)}
 value={'schema_version':1,'nonce':N,'stage':'installed','inputs_sha256':'a'*64,'inventory_sha256':R.inventory_sha256(versions),'baseline_count':111,'installed_count':283,'archive_count':172,'project_file_count':24}
 value.update({k:True for k in ['trusted_ALPM_completed','exact_inventory','dependencies','ownership','project_hashes','original_policy','unrelated_user_file','filesystem_synced']});return versions,value

class Controls(unittest.TestCase):
 def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.work=Path(self.tmp.name)
 def test_null_admission_before_source_clone_or_process(self):
  file=self.work/'authority.json';v=admitted();v['tool_image_id']=None;file.write_text(json.dumps(v));args=argparse.Namespace(authority=file,authority_sha256=K.pin(file)['sha256'])
  with patch.object(K,'source',side_effect=AssertionError('source accessed too early')),patch.object(K,'references',side_effect=AssertionError('source imported too early')),patch.object(subprocess,'run',side_effect=AssertionError('process forbidden')):
   with self.assertRaisesRegex(ValueError,'missing Root-admitted tool_image_id'):K.preflight(args)
 def test_each_required_admission_is_explicit_nonnull(self):
  for key in ['qemu_metadata','tool_qualification','kernel_bundle','additions_manifest','minimal155_report','minimal155_prepared','source_public','source_lock','resource_review']:
   v=admitted();v[key]=None
   with self.subTest(key=key),self.assertRaises(ValueError):K.admission(v,'prepare')
 def test_cannot_retag_minimal155_authority(self):
  v=admitted();v['operation']='arm16k-virtio-seat-vm-v1'
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
  d=json.loads((HERE/'actual-data.json').read_text());p=d['composition'];self.assertEqual((p['baseline'],p['additions'],p['final']),(111,172,283));self.assertEqual(p['archive_bytes'],157094632);self.assertEqual(p['root_change']['after'],'21.1.26-1');self.assertEqual(p['metadata_status'],'PASS_EXPLICIT_FINITE_METADATA_PREPARE');self.assertIsNone(d['actual_VM']);self.assertIsNone(d['actual_tool_image'])
 def test_finite_ARM_argv_has_no_PC_or_host_network_fallback(self):
  argv=A.qemu_argv(N,1794700000);self.assertEqual(argv[argv.index('-machine')+1],'virt');self.assertEqual(argv[argv.index('-nic')+1],'none');self.assertEqual(argv[argv.index('-m')+1],'2048');self.assertNotIn('-enable-kvm',argv);self.assertEqual([argv[i+1]for i,v in enumerate(argv)if v=='-device'],['virtio-blk-device,drive=refdisk','virtio-keyboard-device','virtio-gpu-device']);self.assertIn('arm16k_virtio_seat_nonce='+N,argv[argv.index('-append')+1])
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
 def test_private_output_and_reserve_before_actor(self):
  with patch.object(K.shutil,'disk_usage',return_value=shutil._ntuple_diskusage(10*1024**3,0,10*1024**3)):self.assertEqual(K.output_path(self.work/'new'),self.work/'new')
  with patch.object(K.shutil,'disk_usage',return_value=shutil._ntuple_diskusage(10*1024**3,0,2*1024**3)):
   with self.assertRaises(AssertionError):K.output_path(self.work/'new')

class AcceptanceControls(unittest.TestCase):
 def value(self):
  # Modeled predicate input, never credited as GTK or guest runtime evidence.
  result=load('result');files={name:'a'*64 for name in result.FILES};props={'Id':'1','Active':True,'Seat':['seat0','/seat0'],'User':[1000,'/u'],'TTY':'tty1','Service':'login','Remote':False}
  _,receipt=installed();gui={'status':'PASS_REAL_INSTALLED_GTK_CONTROLS','uid':1000,'user_files':files,'initial_inspect_read_only':True,'preview_read_only':True,'explicit_apply':True,'repeat_apply_preserved_user_edit':True,'rendering':{'display_type':'GdkX11Display','renderer_type':'GskCairoRenderer','root_image_bytes':3145728,'root_image_sha256':'b'*64,'image_exported':False}}
  client={'status':'PASS_REAL_SEAT_UI_CLIENT','uid':1000,'tty':'/dev/tty1','pid':1001,'process_session':1000,'removal_preserved_user_files':True,'private_X_server_and_session_bus_retired':True,'gui':gui,'owned_GUI_process_retirement':{'passed':True,'group_census':'EMPTY_TWICE'}}
  root={'status':'PASS_UI_GUEST_ALPM_LIFECYCLE','architecture':'aarch64','pagesize':16384,'installed':{'status':'INSTALLED_EXACT_172_TRUSTED_PACKAGES','baseline_count':111,'installed_count':283,'dependency_and_ownership_checks':True},'baseline_inventory_restored':True,'package_owned_nondirectory_paths_absent':True,'original_PAM_policy_preserved':True,'unrelated_user_file_preserved':True,'user_files_preserved':files,'trust':{'private_keys':False,'freshness_or_production_acceptance':False,'configuration':'Architecture = aarch64\nSigLevel = Required TrustedOnly\nLocalFileSigLevel = Required TrustedOnly\n'},'client_session_corroboration':{'pid':1001,'process_session':1000,'login1':props},'installation_receipt':receipt,'filesystem_sync':dict.fromkeys(['post-install','post-remove','terminal-pass'],True)}
  return result,{'client':client,'root':root}
 def test_modeled_complete_UI_predicate(self):
  result,value=self.value();result.accept_ui(value)
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

class NamespaceControls(unittest.TestCase):
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

if __name__=='__main__':unittest.main()

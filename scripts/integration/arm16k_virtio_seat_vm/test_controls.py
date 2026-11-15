#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Actor-fenced constructor/authority/closure DATA controls, never a guest trial."""
import ast,copy,ctypes,hashlib,importlib.util,io,json,os,shutil,socket,subprocess,sys,tarfile,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
HERE=Path(__file__).resolve().parent

def denied(*a,**kw):raise AssertionError('actor forbidden in source controls')
for n in ('Popen','run','call','check_call','check_output'):setattr(subprocess,n,denied)
for n in ('system','fork','forkpty','execv','execve','posix_spawn','posix_spawnp'):
 if hasattr(os,n):setattr(os,n,denied)
socket.socket=denied;ctypes.CDLL=denied

def load(name):
 s=importlib.util.spec_from_file_location('seat_test_'+name,HERE/(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
K=load('contracts');B=load('boot');A=load('prepare')
class Guards(unittest.TestCase):
 def test_pending_authority_refuses(self):
  with self.assertRaises(ValueError):K.authority(HERE/'authority.template.json',K.pin(HERE/'authority.template.json')['sha256'],'prepare')
 def test_pending_tool_metadata_refuses(self):
  p=HERE/'qemu-metadata.template.json'
  with self.assertRaises(ValueError):K.tool_metadata(p,{'qemu_metadata':K.pin(p)})
 def test_missing_external_manifest_before_actor(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'missing'
   with self.assertRaises(ValueError):K.additions(p,Path(d),{}, {'additions_manifest':{'bytes':1,'sha256':'0'*64}})
 def test_old_rtc_bundle_refuses_before_consumer(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d)
   for n in ('Image','config'):(root/n).write_bytes(b'x')
   (root/'bundle.json').write_text(json.dumps({'kind':'ARM16K_RTC_REFERENCE_KERNEL_BUNDLE_V1','status':'BUILT_ONLY_RTC_BOOT_NOT_RUN','release_accepted':False}))
   with self.assertRaises(ValueError):K.kernel(root,{'kernel_bundle':K.pin(root/'bundle.json')})
 def test_null_kernel_authority_refuses(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'authority';a=json.loads((HERE/'authority.template.json').read_text());a.update(issued_by='Root',allow_prepare=True)
   p.write_text(json.dumps(a))
   with self.assertRaises(ValueError):K.authority(p,K.pin(p)['sha256'],'prepare')
 def test_private_output_tmp(self):
  with patch.object(K.shutil,'disk_usage',return_value=SimpleNamespace(free=5*1024**3)):self.assertEqual(K.output_path(Path('/tmp/never-created-arm-seat-test')),Path('/tmp/never-created-arm-seat-test'))
 def test_private_output_shm(self):
  with patch.object(K.shutil,'disk_usage',return_value=SimpleNamespace(free=5*1024**3)):self.assertEqual(K.output_path(Path('/dev/shm/never-created-arm-seat-test')),Path('/dev/shm/never-created-arm-seat-test'))
 def test_parent_fs_capacity_used(self):
  with patch.object(K.shutil,'disk_usage',return_value=SimpleNamespace(free=5*1024**3)) as usage:K.output_path(Path('/dev/shm/never-created-arm-seat-test'));usage.assert_called_once_with(Path('/dev/shm'))
 def test_reserve_refuses(self):
  with patch.object(K.shutil,'disk_usage',return_value=SimpleNamespace(free=3*1024**3)),self.assertRaises(ValueError):K.output_path(Path('/tmp/never-created-arm-seat-test'))
 def test_home_refuses(self):
  with self.assertRaises(ValueError):K.output_path(Path('/home/gabe/never-created-arm-seat-test'))
 def test_relative_refuses(self):
  with self.assertRaises(ValueError):K.output_path(Path('relative'))
 def test_traversal_refuses(self):
  with self.assertRaises(ValueError):K.output_path(Path('/tmp/foo/../bar'))
 def test_symlink_refuses(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'link';p.symlink_to('/tmp')
   with self.assertRaises(ValueError):K.output_path(p/'output')
 def test_existing_refuses(self):
  with tempfile.TemporaryDirectory() as d:
   with self.assertRaises(ValueError):K.output_path(Path(d))
 def test_original_controller_frozen_pin(self):self.assertEqual(K.pin(HERE/'frozen/reference_controller.py')['sha256'],'e7c8935f342d4b36bb6f8f24c0b48c3b8aa04be9807f62c3f8141aeaf26819fc')
class DerivedTool(unittest.TestCase):
 def receipt(self):return json.loads((HERE/'data/tool-qualification-r2.json').read_text())
 def test_whole_actual_qualification_data(self):self.assertEqual(K.tool_qualification()['image_id'],K.IMAGE)
 def test_actual_device_help_data(self):
  p=HERE/'data/Root-device-help-r2.json';self.assertEqual(K.tool_metadata(p,{'qemu_metadata':K.pin(p)})['image_id'],K.IMAGE)
 def test_parent_image_not_retagged(self):self.assertNotEqual(K.PARENT_IMAGE,K.IMAGE);self.assertEqual(K.lock()['parent_tool_image_id'],K.PARENT_IMAGE)
 def test_parent_as_derived_refuses(self):d=self.receipt();d['image_id']=K.PARENT_IMAGE;self.refuses(d)
 def test_changed_parent_refuses(self):d=self.receipt();d['parent_image_id']='sha256:'+'0'*64;self.refuses(d)
 def test_missing_gpu_refuses(self):d=self.receipt();d['required_devices']['virtio-gpu-device']=False;self.refuses(d)
 def test_missing_absence_refuses(self):d=self.receipt();d['owned_containers_absent']=False;self.refuses(d)
 def test_failed_cleanup_refuses(self):d=self.receipt();d['cleanup'][0]['cleanup_errors']=['failed'];self.refuses(d)
 def test_guest_claim_refuses(self):d=self.receipt();d['guest_boot']='PASS';self.refuses(d)
 def test_other_package_refuses(self):d=self.receipt();d['package']['name']='other';self.refuses(d)
 def test_no_geometry_permissions_change(self):
  d=K.lock();self.assertEqual((d['baseline_packages'],d['max_additions'],d['prep_allocated_cap'],d['overlay_cap']),(111,96,1280*1024**2,512*1024**2))
 def refuses(self,d):
  with self.assertRaises(ValueError):K.qualification_value(d)
class Custody(unittest.TestCase):
 def row(self):
  return {'Id':'a'*64,'Name':'/owned','Image':K.IMAGE,'Config':{'Entrypoint':['/usr/bin/python3'],'Cmd':['-I','-B','/inputs/seat_actor.py'],'Labels':{}},'Mounts':[{'Type':'bind','Source':'/fresh/in','Destination':'/inputs','RW':False},{'Type':'bind','Source':'/fresh/out','Destination':'/work','RW':True}],'HostConfig':{'ReadonlyRootfs':True,'NetworkMode':'none','CapDrop':['ALL'],'CapAdd':None,'Privileged':False,'Devices':[],'Init':False,'SecurityOpt':['no-new-privileges'],'Memory':3*1024**3,'NanoCpus':2_000_000_000,'PidsLimit':256}}
 def scope(self):return B.OwnedContainer('owned',Path('/unused'),K.IMAGE,{},Path('/fresh/in'),Path('/fresh/out'))
 def test_complete_new_actor_model(self):self.scope().validate(self.row())
 def test_old_actor_refuses(self):self.bad(['Config','Cmd'],['-I','-B','/inputs/rtc_actor.py'])
 def test_old_opt_actor_refuses(self):self.bad(['Config','Cmd'],['-I','-B','/opt/vm_actor.py'])
 def test_rw_inputs_refuse(self):
  r=self.row();r['Mounts'][0]['RW']=True
  with self.assertRaises(AssertionError):self.scope().validate(r)
 def test_network_refuses(self):self.bad(['HostConfig','NetworkMode'],'host')
 def test_capability_refuses(self):self.bad(['HostConfig','CapAdd'],['SYS_ADMIN'])
 def test_no_nnp_refuses(self):self.bad(['HostConfig','SecurityOpt'],[])
 def test_wrong_image_refuses(self):self.bad(['Image'],'sha256:'+'0'*64)
 def test_wrong_owner_refuses(self):self.bad(['Name'],'/other')
 def test_wrong_memory_refuses(self):self.bad(['HostConfig','Memory'],4*1024**3)
 def test_third_mount_refuses(self):
  r=self.row();r['Mounts'].append({'Type':'bind','Source':'/home','Destination':'/home','RW':False})
  with self.assertRaises(AssertionError):self.scope().validate(r)
 def bad(self,keys,value):
  r=self.row();d=r
  for k in keys[:-1]:d=d[k]
  d[keys[-1]]=value
  with self.assertRaises(AssertionError):self.scope().validate(r)
class InstalledProof(unittest.TestCase):
 def case(self):
  nonce='a'*32;rows=[{'name':'base'+str(i),'version':'1-1'} for i in range(111)];adds={'archives':{'python':{'version':'3.14.8-1'},'python-gobject':{'version':'3.58.1-1'},'polkit':{'version':'127-3'},'networkmanager':{'version':'1.58.1-2'}}}
  prepared={'nonce':nonce,'base_packages':rows,'lineage':{'additions':adds,'additions_pin':{'sha256':'b'*64}}}
  text=''.join(n+' '+v+'\n' for n,v in sorted(({r['name']:r['version'] for r in rows}|{n:r['version'] for n,r in adds['archives'].items()}).items())).encode()
  gate={'status':'PASS','nonce':nonce,'baseline_count':111,'installed_count':115,'trusted_ALPM_completed':True,'ordinary_hooks_scriptlets':True,'policy_owner':'networkmanager','additions_sha256':'b'*64,'actual_inventory_sha256':hashlib.sha256(text).hexdigest(),'durability':'successful install service after sync-f boundary','clock':{'RTC_PRESENT':'yes','RTC_DRIVER':'pl031','RTC_HCTOSYS':'1','RTC_CLOCK_ADVANCED':'yes','CLOCK_SETTING':'none','HOST_BOOT_UTC':'1794728851','GUEST_BEFORE_CRYPTO_UTC':'1794728863','RTC_BEFORE_CRYPTO_UTC':'1794728863'}}
  return {'installed_gate':gate},prepared
 def test_complete_model(self):p,m=self.case();self.assertEqual(B.installed(p,m,1794728851,1794728900)['installed_count'],115)
 def test_wrong_installed_count(self):self.bad('installed_count',114)
 def test_wrong_nonce(self):self.bad('nonce','c'*32)
 def test_untrusted_alpm(self):self.bad('trusted_ALPM_completed',False)
 def test_hooks_suppressed(self):self.bad('ordinary_hooks_scriptlets',False)
 def test_wrong_policy_owner(self):self.bad('policy_owner','fake')
 def test_inventory_changed(self):self.bad('actual_inventory_sha256','0'*64)
 def test_durability_missing(self):self.bad('durability','NOT RUN')
 def test_artificial_clock(self):
  p,m=self.case();p['installed_gate']['clock']['CLOCK_SETTING']='date'
  with self.assertRaises(AssertionError):B.installed(p,m,1794728851,1794728900)
 def test_stale_host_epoch(self):
  p,m=self.case()
  with self.assertRaises(AssertionError):B.installed(p,m,1794728852,1794728900)
 def test_rtc_disagrees(self):
  p,m=self.case();p['installed_gate']['clock']['RTC_BEFORE_CRYPTO_UTC']='1794728800'
  with self.assertRaises(AssertionError):B.installed(p,m,1794728851,1794728900)
 def bad(self,k,v):
  p,m=self.case();p['installed_gate'][k]=v
  with self.assertRaises(AssertionError):B.installed(p,m,1794728851,1794728900)
class ModernMMIO(unittest.TestCase):
 def setUp(self):
  self.I=B.P.INPUT
  self.F=K.load('frozen_seat_model',HERE/'frozen/arm16k_virtio_seat/test_controls.py')
 def keyboard(self):
  d=self.F.keyboard();d['virtio_features']='0'*32+'1'+'0'*31;return d
 def gpu(self):
  d=self.F.gpu();d['virtio_features']='0'*32+'1'+'0'*31;old=d['sysfs_path'];d['sysfs_path']=d['transport_path']+'/drm/card0';d['drm_device_path']=d['transport_path'];d['properties']=d['properties'].replace(old[4:],d['sysfs_path'][4:]);return d
 def test_complete_modern_keyboard(self):self.assertTrue(self.I.is_seat_keyboard(self.keyboard()))
 def test_complete_correct_drm_parent(self):self.assertTrue(self.I.is_seat_gpu(self.gpu()))
 def test_legacy_input_refused(self):d=self.keyboard();d['virtio_features']='0'*64;self.assertFalse(self.I.is_seat_keyboard(d))
 def test_legacy_gpu_refused(self):d=self.gpu();d['virtio_features']='0'*64;self.assertFalse(self.I.is_seat_gpu(d))
 def test_missing_features_refused(self):d=self.gpu();d.pop('virtio_features');self.assertFalse(self.I.is_seat_gpu(d))
 def test_wrong_bit_direction_refused(self):self.assertFalse(self.I.modern_features('1'+'0'*63))
 def test_old_wrong_gpu_graph_refused(self):d=self.gpu();d['sysfs_path']=d['virtio_path']+'/drm/card0';self.assertFalse(self.I.is_seat_gpu(d))
 def test_other_mmio_parent_refused(self):d=self.gpu();d['drm_device_path']='/sys/devices/platform/a000000.virtio_mmio';self.assertFalse(self.I.is_seat_gpu(d))
 def test_wrong_child_driver_refused(self):d=self.gpu();d['virtio_driver']=self.I.INPUT_DRIVER;self.assertFalse(self.I.is_seat_gpu(d))
 def test_wrong_gpu_id_refused(self):d=self.gpu();d['virtio_device']='0x0012';self.assertFalse(self.I.is_seat_gpu(d))
 def test_stock_seat_still_required(self):d=self.gpu();d['properties']=d['properties'].replace('TAGS=:seat:master-of-seat:','TAGS=:uaccess:');self.assertFalse(self.I.is_seat_gpu(d))
 def test_protocol_uses_new_strict_predicate(self):
  p=self.F.proof();p['virtio_GPU']=self.gpu();p['DRM_cards']=[p['virtio_GPU']['sysfs_path']];p['kernel_input_devices']={'event3':self.keyboard()};self.assertEqual(B.P.parse(self.F.frame(p),self.F.NONCE)['pagesize'],16384)
 def test_pinned_source_v1_and_parent_proofs(self):
  gpu=(HERE/'data/virtgpu_kms.c').read_text();mmio=(HERE/'frozen/arm16k_ui_seat_kernel/data/qemu-virtio-mmio.c').read_text();drv=(HERE/'frozen/arm16k_virtio_seat/data/virtgpu_drv.c').read_text()
  self.assertIn('if (!virtio_has_feature(vdev, VIRTIO_F_VERSION_1))',gpu);self.assertIn('return -ENODEV;',gpu);self.assertIn('legacy, true)',mmio);self.assertIn('if (!proxy->legacy)',mmio);self.assertIn('drm_dev_alloc(&driver, vdev->dev.parent)',drv)
 def test_actor_explicit_modern_global_once(self):
  text=(HERE/'seat_actor.py').read_text();self.assertEqual(text.count('virtio-mmio.force-legacy=false'),1);self.assertNotIn('force-legacy=true',text)
 def test_empty_census_is_diagnostic_not_pass(self):
  with patch.object(self.I.Path,'glob',return_value=[]):d=self.I.census()
  self.assertEqual((d['virtio_count'],d['drm_card_count']),(0,0));self.assertFalse(d['typed_keys_exported']);self.assertNotIn('status',d)
 def test_census_count_bound_refuses(self):
  with patch.object(self.I.Path,'glob',return_value=[Path('/sys/bus/virtio/devices/virtio'+str(i)) for i in range(33)]),self.assertRaises(ValueError):self.I.census()
 def test_diagnostics_before_wait_and_on_hold(self):
  text=(HERE/'observer.py').read_text();self.assertLess(text.index("persist_census('pre-device')"),text.index('gpu=wait('));self.assertIn("persist_census('terminal')",text);self.assertIn('os.fsync(f.fileno())',text);self.assertIn("'installed_gate':installed_gate",text)
class IndependentChecks(unittest.TestCase):
 def setUp(self):self.C=K.load('independent_model',HERE/'observer_checks.py')
 def user(self):return {'pid':625,'process_session':610,'logind':{'Leader':576}}
 def test_duplicate_unix_groups_not_rejected(self):self.assertTrue(self.C.bus(self.user(),{'UnixUserID':1000,'ProcessID':625,'UnixGroupIDs':[1000,1000]})[0])
 def test_wrong_bus_pid_still_fails(self):self.assertFalse(self.C.bus(self.user(),{'UnixUserID':1000,'ProcessID':626})[0])
 def test_wrong_bus_uid_still_fails(self):self.assertFalse(self.C.bus(self.user(),{'UnixUserID':0,'ProcessID':625})[0])
 def test_logind_leader_need_not_equal_sid(self):self.assertTrue(self.C.process(self.user(),610,'tty1')[0])
 def test_actual_sid_must_equal_user_sid(self):self.assertFalse(self.C.process(self.user(),576,'tty1')[0])
 def test_foreground_vt_still_required(self):self.assertFalse(self.C.process(self.user(),610,'tty2')[0])
 def test_record_raw_order_change_still_fails_and_is_named(self):
  before={'properties':'A=1\nB=2\n'};after={'properties':'B=2\nA=1\n'};ok,d=self.C.record(before,after,True)
  self.assertFalse(ok);self.assertEqual(d['changed_fields'],['properties']);self.assertEqual(d['property_changes']['properties'],[])
 def test_record_real_property_change_captured(self):
  ok,d=self.C.record({'properties':'A=1\n'},{'properties':'A=2\n'},True);self.assertFalse(ok);self.assertEqual(d['property_changes']['properties'],['A'])
 def test_unchanged_record_without_identity_acceptance_fails(self):self.assertFalse(self.C.record({'x':1},{'x':1},False)[0])
 def test_published_failure_named_durable_private(self):
  with tempfile.TemporaryDirectory() as d:
   public={}
   with self.assertRaisesRegex(AssertionError,'independent-bus-credentials'):self.C.publish(Path(d),'a'*32,'bus-credentials',False,{'actual_pid':626},public)
   p=Path(d)/'observer-check-bus-credentials.json';self.assertEqual(p.stat().st_mode&0o777,0o600);self.assertFalse(public['bus-credentials']['passed']);self.assertEqual(json.loads(p.read_text())['evidence']['actual_pid'],626)
 def test_receipt_replay_refuses(self):
  with tempfile.TemporaryDirectory() as d:
   public={};self.C.publish(Path(d),'a'*32,'process-vt',True,{},public)
   with self.assertRaises(FileExistsError):self.C.publish(Path(d),'a'*32,'process-vt',True,{},public)
 def test_receipt_cap_refuses(self):
  with tempfile.TemporaryDirectory() as d,self.assertRaises(ValueError):self.C.publish(Path(d),'a'*32,'process-vt',True,{'x':'y'*65536},{})
 def test_unknown_check_refuses(self):
  with tempfile.TemporaryDirectory() as d,self.assertRaises(ValueError):self.C.publish(Path(d),'a'*32,'arbitrary',True,{},{})
 def test_sync_failure_cannot_pass(self):
  with tempfile.TemporaryDirectory() as d,patch.object(self.C.os,'fsync',side_effect=OSError('model sync failure')):
   public={}
   with self.assertRaises(OSError):self.C.publish(Path(d),'a'*32,'process-vt',True,{},public)
   self.assertEqual(public,{})
 def test_all_original_independent_checks_named(self):
  text=(HERE/'observer.py').read_text()
  for name in self.C.NAMES:self.assertIn("independent('"+name+"'",text)
class Additions(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.base={'base_packages':[{'name':'glibc','version':'2.42-1','directory':'glibc-2.42-1'},{'name':'glib2','version':'2.88.3-1','directory':'glib2-2.88.3-1'}]+[{'name':'base'+str(i),'version':'1-1','directory':'base'+str(i)+'-1-1'} for i in range(109)]}
  self.catalog={};self.rows={};self.policy=b'MODEL DATA ONLY NOT A REAL PROVIDER';self.model_policy=hashlib.sha256(self.policy).hexdigest();self.policy_patch=patch.object(K,'POLICY',self.model_policy);self.policy_patch.start()
  paths={'python':{'usr/bin/python3':b'MODEL'},'python-gobject':{'usr/lib/python3.14/site-packages/gi/__init__.py':b'MODEL'},'polkit':{'usr/bin/pkaction':b'MODEL'},'networkmanager':{'usr/share/polkit-1/actions/org.freedesktop.NetworkManager.policy':self.policy}}
  versions={'python':'3.14.8-1','python-gobject':'3.58.1-1','polkit':'127-3','networkmanager':'1.58.1-2'}
  for name,payload in paths.items():
   meta={'pkgname':[name],'pkgver':[versions[name]],'arch':['aarch64'],'depend':['glibc']};filename=name+'-'+versions[name]+'-aarch64.pkg.tar.xz';p=self.root/filename
   with tarfile.open(p,'w:xz') as tar:
    data=''.join(k+' = '+v+'\n' for k,values in meta.items() for v in values).encode();t=tarfile.TarInfo('.PKGINFO');t.size=len(data);tar.addfile(t,io.BytesIO(data))
    for leaf,data in payload.items():t=tarfile.TarInfo(leaf);t.size=len(data);t.mode=0o755;tar.addfile(t,io.BytesIO(data))
   sig=self.root/(filename+'.sig');sig.write_bytes(b'MODEL_SIGNATURE_NOT_AUTHENTIC');self.rows[name]={'filename':filename,'archive':K.pin(p),'signature':K.pin(sig),'expected_signer':'A'*40,'version':versions[name],'official_repository':True,'source_provenance':{'scope':'UNIT_MODEL_ONLY'},'metadata':meta}
  (self.root/'archlinuxarm.gpg').write_bytes(b'MODEL_PUBLIC_KEY_NOT_AUTHENTIC')
  bm={r['name']:{'version':r['version'],'directory':r['directory'],'provides':[],'files':[]} for r in self.base['base_packages']}
  bm['glibc']['files']=['usr/bin/'+n for n in ('base64','bash','cat','cut','date','getconf','gpg','grep','head','install','pacman','sha256sum','sleep','sort','stat','sync','systemctl','timeout','uname','wc')]
  self.manifest={'kind':'ARM16K_VIRTIO_SEAT_ADDITIONS_V1','status':'ROOT_REVIEWED_COMPLETE_MINIMAL_SEAT_CLOSURE','issued_by':'Root','baseline_prepared':K.lock()['base_prepared'],'archives':self.rows,'keyring':{'filename':'archlinuxarm.gpg','pin':K.pin(self.root/'archlinuxarm.gpg')},'baseline_metadata':bm,'baseline_metadata_provenance':{'scope':'UNIT_MODEL_ONLY'},'metadata_prepare':{'status':'PASS_EXPLICIT_FINITE_METADATA_PREPARE','baseline_preserved':111,'final_count':115,'conflicts':[],'dependencies':[{'package':n,'provider':'glibc','relation':'glibc'} for n in sorted(self.rows)],'prepare':{'libalpm_version':'16.0.1','prepare_exit':0,'prepare_errno':0,'errors':[],'callback_errors':[],'questions':[],'remove':[],'add':[{'name':n,'version':r['version']} for n,r in self.rows.items()]}},'original_file_pins':{p:'1'*64 for p in K.PAM}|{'/usr/lib/udev/rules.d/71-seat.rules':K.RULE},'required_namespace':{}}
  package=K.load('model_package_data',HERE/'frozen/package_data.py').package
  for name,row in self.rows.items():
   for leaf,payload in package(self.root/row['filename'])['payload'].items():self.manifest['required_namespace'][leaf]={'owner':name,'payload':payload}
  for leaf in ('usr/lib/girepository-1.0/Gio-2.0.typelib','usr/lib/girepository-1.0/GLib-2.0.typelib'):
   bm['glib2']['files'].append(leaf);self.manifest['original_file_pins']['/'+leaf]='2'*64;self.manifest['required_namespace'][leaf]={'owner':'glib2','payload':{'type':'0','mode':0o644,'uid':0,'gid':0,'bytes':10,'sha256':'2'*64,'link':''}}
 def tearDown(self):self.policy_patch.stop();self.tmp.cleanup()
 def runmodel(self):
  p=self.root/'manifest.json';p.write_text(json.dumps(self.manifest));return K.additions(p,self.root,self.base,{'additions_manifest':K.pin(p)})
 def test_complete_data_model_not_signature_or_root_authority(self):self.assertEqual(len(self.runmodel()[1]),4)
 def test_missing_nm_provider(self):self.manifest['archives'].pop('networkmanager');self.refuses()
 def test_unreviewed_manifest(self):self.manifest['status']='PROPOSAL_ONLY';self.refuses()
 def test_null_provenance(self):self.manifest['baseline_metadata_provenance']=None;self.refuses()
 def test_missing_signature(self):(self.root/(self.rows['python']['filename']+'.sig')).unlink();self.refuses()
 def test_tampered_archive(self):(self.root/self.rows['python']['filename']).write_bytes(b'changed');self.refuses()
 def test_wrong_metadata(self):self.rows['python']['metadata']['arch']=['x86_64'];self.refuses()
 def test_missing_baseline_provides(self):self.manifest['baseline_metadata'].pop('glibc');self.refuses()
 def test_wrong_baseline_version(self):self.manifest['baseline_metadata']['glibc']['version']='other';self.refuses()
 def test_alpm_error(self):self.manifest['metadata_prepare']['prepare']['errors']=['bad'];self.refuses()
 def test_alpm_question(self):self.manifest['metadata_prepare']['prepare']['questions']=['choice'];self.refuses()
 def test_alpm_removal(self):self.manifest['metadata_prepare']['prepare']['remove']=['glibc'];self.refuses()
 def test_wrong_provider(self):self.manifest['metadata_prepare']['dependencies'][0]['provider']='missing';self.refuses()
 def test_missing_edge(self):self.manifest['metadata_prepare']['dependencies'].pop();self.refuses()
 def test_wrong_namespace_owner(self):self.manifest['required_namespace']['usr/bin/pkaction']['owner']='python';self.refuses()
 def test_missing_gir(self):self.manifest['required_namespace'].pop('usr/lib/girepository-1.0/Gio-2.0.typelib');self.refuses()
 def test_baseline_typelib_ownership_missing(self):self.manifest['baseline_metadata']['glib2']['files']=[];self.refuses()
 def test_wrong_original_rule(self):self.manifest['original_file_pins']['/usr/lib/udev/rules.d/71-seat.rules']='3'*64;self.refuses()
 def test_missing_original_pam(self):self.manifest['original_file_pins'].pop(K.PAM[0]);self.refuses()
 def test_policy_injection_owner(self):self.manifest['required_namespace']['usr/share/polkit-1/actions/org.freedesktop.NetworkManager.policy']['owner']='python';self.refuses()
 def test_unofficial_archive(self):self.rows['python']['official_repository']=False;self.refuses()
 def test_path_traversal_filename(self):self.rows['python']['filename']='../bad.pkg.tar.xz';self.refuses()
 def refuses(self):
  with self.assertRaises((ValueError,FileNotFoundError,KeyError)):self.runmodel()
class Source(unittest.TestCase):
 def test_actual_namespace_check_mandatory(self):
  self.assertIn('python3 -I -B "$D/namespace-check.py"',(HERE/'guest-install.sh').read_text())
  self.assertIn('os.readlink(p)==r[\'link\']',(HERE/'namespace-check.py').read_text())
 def test_no_full_ui_variant_callback(self):
  self.assertEqual(K.lock()['max_additions'],96);self.assertEqual(K.lock()['prep_allocated_cap'],1280*1024**2)
  self.assertNotIn('variant_callback',(HERE/'prepare.py').read_text())
 def test_all_source_syntax(self):
  for p in HERE.rglob('*.py'):ast.parse(p.read_text(),filename=str(p))
 def test_exact_source_pins(self):self.assertEqual(K.source(),K.pin(HERE/'source.lock.json'))
 def test_preflight_precedes_output_and_actor(self):
  s=(HERE/'prepare.py').read_text();self.assertLess(s.index('=preflight(a)'),s.index('out.mkdir'));self.assertLess(s.index('=preflight(a)'),s.index("load('seat_runner'"))
 def test_actor_has_new_device_tuple(self):
  s=(HERE/'seat_actor.py').read_text()
  for item in ('virtio-keyboard-device','virtio-gpu-device','arm16k_virtio_seat_nonce=','console=tty0 console=ttyAMA0','base=utc,clock=host','O.supervise','os.WNOWAIT','max_output=1024**2'):self.assertIn(item,s)
  self.assertNotIn('CACHY_ASAHI_ALLOW_ARM16K_RTC_BOOT',s)
 def test_normal_alpm_no_bypass(self):
  s=(HERE/'guest-install.sh').read_text();self.assertIn('Required TrustedOnly',(HERE/'prepare.py').read_text());self.assertIn(' --noconfirm -U ',s);self.assertIn('head -c 1048577',s);self.assertIn('statuses=("${PIPESTATUS[@]}")',s)
  for token in ('--nodeps','--noscriptlet','--nohooks','--assume-installed'):self.assertNotIn(token,s)
 def test_offline_clone_readbacks_preserved(self):
  s=(HERE/'prepare_image.py').read_text()
  for token in ('--sparse=always','--reflink=never','pin(p)==pin(src)','Type: symlink','guest_required_pins','e2fsck'):self.assertIn(token,s)
 def test_seat_observer_keeps_before_credentials_identity(self):
  s=(HERE/'observer.py').read_text();self.assertLess(s.index('open_verified_keyboard'),s.index("frame('SEAT_LOGIN_READY'"));self.assertIn("unit.stdout.splitlines()",s);self.assertIn('installed_gate=installed_gate',s)
 def test_no_gtk_xvfb_dependency(self):
  self.assertNotIn('xvfb',(HERE/'contracts.py').read_text().lower());self.assertNotIn('gtk4',(HERE/'contracts.py').read_text().lower())
if __name__=='__main__':
 if not(__debug__ and sys.flags.isolated):raise RuntimeError('isolated assertions required')
 unittest.main()

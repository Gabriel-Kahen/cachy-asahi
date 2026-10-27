#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inert constructor/input/protocol refusals; no VM, Docker, package or privileged actors."""
import base64,copy,importlib.util,json,os,shutil,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('_c01_g16_owner_tests',HERE/'owner.py');A=importlib.util.module_from_spec(spec);spec.loader.exec_module(A)
D=A.load_module('_c01_g16_guest_tests',HERE/'guest.py')
class OwnerControls(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
  self.no_actor=patch.object(A.subprocess,'Popen',side_effect=AssertionError('actors forbidden in inert controls'));self.no_actor.start();self.addCleanup(self.no_actor.stop)
  self.selection={'nonce':'a'*32,'source_commit':'b'*40,'accepted_origin':D.ORIGIN,'host_page_size':4096,
                  'helper_sha256':D.HELPER,'inventory_sha256':D.INVENTORY,'packages':D.PACKAGES,'base_sentinels':D.BASE_SENTINELS,'schema':1}
 def fixture(self):
  result={'status':D.PASS,'nonce':self.selection['nonce'],'source_commit':self.selection['source_commit'],'accepted_origin':D.ORIGIN,
          'host_page_size':4096,'guest':{'sysname':'Linux','machine':'aarch64','kernel':D.RELEASE,'uid':0,'euid':0,'page_size':16384,
          'auxv_page_size':16384,'network':['lo'],'cmdline':['c01install16k='+self.selection['nonce']]},'phases':[],
          'system_sentinels':D.BASE_SENTINELS,'system_sentinels_preserved':True,'inventory_sha256':D.INVENTORY,'original_packages_preserved':True,
          'packages':D.PACKAGES,'hardware_validation':'NOT RUN','performance_acceptance':'NOT RUN','release_admission':False}
  _,corpus=A.record_plan(self.selection)
  for label,versions in D.PHASES:
   phase=dict(phase=label,versions=versions,inventory_preserved=True,system_sentinels_preserved=True)
   if versions:
    n=len(versions);phase['workload']=dict(encodes=21*n,cross_decodes=21*n*n,strict_rejections=3*n,inputs=corpus,
     probe={v:dict(status='PASS',variant=v,roundtrips=21,negative_checks=42) for v in versions})
   result['phases'].append(phase)
  result['commands']=json.loads((HERE/'records-control.json').read_bytes())['commands']
  return result
 def uart(self,result):
  n=self.selection['nonce'];frame=base64.b64encode(json.dumps(result).encode())
  return (b'Kernel command line: '+A.command_line(n).encode()+b'\nID_AA64ISAR2_EL1[19:16]: forced to 0\n'+
   b'UNAME16K aarch64 '+D.RELEASE.encode()+b'\nGETCONF16K 16384\nSMOKE16K: mmap,mprotect,file-offset PASS\n'+
   b'C01_INSTALL16K '+n.encode()+b' '+frame+b'\nC01_INSTALL16K_DONE '+n.encode()+b'\n')
 def inspect(self):
  own={'token':'c'*24,'source_sha':'d'*40,'run_id':'123'}
  row={'Image':'sha256:'+'e'*64,'State':{'Status':'exited','ExitCode':0,'OOMKilled':False},
   'Config':{'Labels':{A.O.LABEL:own['token'],A.O.LABEL+'.source':own['source_sha'],A.O.LABEL+'.run':'123'},'User':'0:0',
             'Entrypoint':['/usr/bin/python3'],'Cmd':['-I','-B','/inputs/capture.py',str(os.getuid()),str(os.getgid())],
             'Env':['PATH=/usr/bin:/bin','CACHY_ASAHI_C01_CAPTURE16K=1']},
   'HostConfig':{'NetworkMode':'none','ReadonlyRootfs':True,'Privileged':False,'Memory':8*1024**3,'MemorySwap':8*1024**3,
    'NanoCpus':2*10**9,'PidsLimit':256,'CapAdd':['CAP_'+c for c in A.CAPS],'CapDrop':['ALL'],'Devices':[],
    'DeviceRequests':[],'IpcMode':'private','CgroupnsMode':'private','SecurityOpt':['no-new-privileges'],
    'Tmpfs':{'/tmp':'rw,exec,nosuid,nodev,size=6g,mode=1777'}},
   'Mounts':[{'Destination':'/inputs','Source':'/in','RW':False,'Type':'bind'},
             {'Destination':'/out','Source':'/out','RW':True,'Type':'bind'},{'Destination':'/tmp','Type':'tmpfs'}]}
  return row,own
 def test_source_contract_closed_and_aliases(self):
  manifest=A.O.source(A.ROOT,A.sha(A.read(A.ROOT/A.O.MAP)))
  expected=set(manifest['files'])|{A.O.MAP,*A.O.ALIASES}
  actual={p.relative_to(A.ROOT).as_posix() for p in A.ROOT.rglob('*')
          if p.is_file() and p.relative_to(A.ROOT).parts[0]!='.git'}
  self.assertEqual(actual,expected)
 def test_git_checkout_metadata_is_excluded_but_unreviewed_source_is_not(self):
  checkout=self.root/'checkout'
  shutil.copytree(A.ROOT,checkout,ignore=shutil.ignore_patterns('.git'))
  objects=checkout/'.git/objects';objects.mkdir(parents=True)
  for i in range(81):(objects/str(i)).write_bytes(b'bounded checkout metadata fixture\n')
  self.assertEqual(len([p for p in checkout.rglob('*') if p.is_file()]),125)
  manifest=A.O.source(checkout,A.sha(A.read(checkout/A.O.MAP)))
  expected=set(manifest['files'])|{A.O.MAP,*A.O.ALIASES}
  actual={p.relative_to(checkout).as_posix() for p in checkout.rglob('*')
          if p.is_file() and p.relative_to(checkout).parts[0]!='.git'}
  self.assertEqual(actual,expected);self.assertEqual(len(actual),44)
  (checkout/'unreviewed-source.py').write_bytes(b'not in the source map\n')
  with self.assertRaises(ValueError):A.O.source(checkout,A.sha(A.read(checkout/A.O.MAP)))
 def test_complete_original645_graph_and_protocol_control(self):
  r=self.fixture();self.assertTrue(A.validate_records(r,self.selection));self.assertEqual(A.observed(self.uart(r),0,self.selection),r)
 def test_wrong_argv_decode_hash_exit_or_cleanup_refused(self):
  for key,value in [('argv',['/usr/bin/true']),('exit',7),('group_absent',False),('log','../escape')]:
   r=self.fixture();r['commands'][0][key]=value
   with self.subTest(key=key),self.assertRaises(ValueError):A.validate_records(r,self.selection)
  r=self.fixture();r['commands'][0]['stdout_sha256']='0'*64
  with self.assertRaises(ValueError):A.validate_records(r,self.selection)
 def test_wrong_nonce_page_auxv_origin_phase_and_counts_refused(self):
  for key,value in [('nonce','f'*32),('accepted_origin',{}),('commands',[])]:
   r=self.fixture();r[key]=value
   with self.subTest(key=key),self.assertRaises(ValueError):A.observed(self.uart(r),0,self.selection)
  for key,value in [('page_size',4096),('auxv_page_size',4096),('network',['eth0','lo']),('kernel','other')]:
   r=self.fixture();r['guest'][key]=value
   with self.subTest(key=key),self.assertRaises(ValueError):A.observed(self.uart(r),0,self.selection)
  r=self.fixture();r['phases'][1]['workload']['encodes']=1
  with self.assertRaises(ValueError):A.observed(self.uart(r),0,self.selection)
 def test_missing_probe_poweroff_nomops_and_nonzero_vm_refused(self):
  raw=self.uart(self.fixture())
  for old,new in [(b'GETCONF16K 16384',b'GETCONF16K 4096'),(b'SMOKE16K: mmap,mprotect,file-offset PASS',b'no probe'),
                  (b'ID_AA64ISAR2_EL1[19:16]: forced to 0',b'no forced field'),(b'arm64.nomops',b'arm64.fake')]:
   with self.subTest(old=old),self.assertRaises(ValueError):A.observed(raw.replace(old,new),0,self.selection)
  with self.assertRaises(ValueError):A.observed(raw,1,self.selection)
 def test_capture_boundary_and_mutations(self):
  row,own=self.inspect();A.check_capture(row,own,row['Image'],Path('/in'),Path('/out'))
  for group,key,value in [('HostConfig','NetworkMode','host'),('HostConfig','Memory',0),('HostConfig','Privileged',True),
                         ('HostConfig','CapAdd',['SYS_ADMIN']),('Config','User','1000'),('Config','Env',['SECRET=bad'])]:
   bad=copy.deepcopy(row);bad[group][key]=value
   with self.subTest(key=key),self.assertRaises(ValueError):A.check_capture(bad,own,row['Image'],Path('/in'),Path('/out'))
  bad=copy.deepcopy(row);bad['Mounts'][0]['RW']=True
  with self.assertRaises(ValueError):A.check_capture(bad,own,row['Image'],Path('/in'),Path('/out'))
 def test_qemu_is_finite_offline_and_normal_root_boot(self):
  argv=A.qemu(Path('/private/Image'),Path('/private/root.raw'),'a'*32)
  self.assertEqual(argv[argv.index('-m')+1],'4096');self.assertEqual(argv[argv.index('-nic')+1],'none')
  self.assertNotIn('-enable-kvm',argv);self.assertIn('root=/dev/vda',argv[argv.index('-append')+1])
 def test_kernel_rootDATA_export_and_wrong_source_refusal(self):
  data=self.root/'data';data.mkdir()
  for name in ('Image','config','kernel-input.json'):(data/name).write_bytes(name.encode())
  def verifier(path,profile):
   self.assertEqual({p.name for p in path.iterdir()},{'Image','config','kernel-input.json'})
   return profile,b'Image',b'config'
  with patch.object(A.subprocess,'check_output',side_effect=[A.KERNEL_SOURCE+'\n','Image\nconfig\nkernel-input.json\n']),patch.object(A.K,'verify',side_effect=verifier):
   self.assertEqual(A.kernel_data(data)[1],b'Image')
  self.assertEqual(list(self.root.iterdir()),[data])
  with patch.object(A.subprocess,'check_output',return_value='0'*40),self.assertRaises(ValueError):A.kernel_data(data)
 def test_default_without_CI_execute_refuses_before_work(self):
  with patch.dict(os.environ,{},clear=True),self.assertRaises((ValueError,KeyError)):
   A.trial(SimpleNamespace(execute=False))
 def test_cleanup_does_not_retire_image_while_VM_or_workspace_unknown(self):
  args=SimpleNamespace(work=self.root,source_sha='a'*40)
  self.assertTrue(A.cleanup_safe(args));(self.root/'guest16k-private').mkdir();self.assertFalse(A.cleanup_safe(args))
  A.save(self.root/'guest16k-owner.json',dict(source_sha=args.source_sha,capture_absent=True,vm_retired=False,private_removed=False))
  self.assertFalse(A.cleanup_safe(args))
  A.save(self.root/'guest16k-owner.json',dict(source_sha=args.source_sha,capture_absent=True,vm_retired=True,private_removed=True))
  self.assertTrue(A.cleanup_safe(args))
 def test_descriptor_no_boot_authority_and_wrong_fields_refused(self):
  d=A.K.expected_descriptor();self.assertEqual(d['boot'],'NOT_RUN');self.assertEqual(d['page_size'],16384)
  d['boot']='PASS'
  with self.assertRaises(ValueError):A.K.profile(d)
 def test_failed_retention_keeps_only_public_receipts_and_never_disk(self):
  work=self.root/'work';work.mkdir();public=work/'guest16k-public';public.mkdir()
  (public/'capture.log').write_bytes(b'finite failed capture diagnostic')
  (public/'root.raw').write_bytes(b'private disk forbidden')
  bootstrap=work/'bootstrap';bootstrap.mkdir();(bootstrap/'acquisition.json').write_text('{}')
  args=SimpleNamespace(work=work,public=self.root/'public',source_sha='a'*40,manifest_sha256='b'*64)
  with patch.object(A.O,'binding',return_value=({}, {'token':'c'*24})):
   result=A.retain(args)
  self.assertEqual(result['status'],'FAIL')
  self.assertEqual((args.public/'capture.log').read_bytes(),b'finite failed capture diagnostic')
  self.assertTrue((args.public/'bootstrap-acquisition.json').is_file());self.assertFalse((args.public/'root.raw').exists())
 def test_original_static_page_probe_has_exact_staged_file_offsets(self):
  capture=A.load_module('_c01_page_data_fixture',HERE/'capture.py')
  row=capture.stage_page_data(self.root);data=(self.root/'page-data').read_bytes()
  self.assertEqual(row['bytes'],32768);self.assertEqual(data[0:16384],b'A'*16384);self.assertEqual(data[16384:],b'B'*16384)
  with self.assertRaises(ValueError):capture.stage_page_data(self.root)
 def test_capture_entry_refuses_host_before_private_work(self):
  capture=A.load_module('_c01_capture_guard',HERE/'capture.py')
  with patch.object(capture.platform,'machine',return_value='x86_64'),self.assertRaises(ValueError):capture.main(1000,1000)
if __name__=='__main__':unittest.main()

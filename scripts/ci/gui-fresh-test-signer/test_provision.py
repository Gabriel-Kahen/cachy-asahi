# SPDX-License-Identifier: MIT
"""Mocked source-image production: no acquisition, GPG, Docker or ARM actors."""
import contextlib,copy,importlib.util,io,json,os,shutil,socket,subprocess,tarfile,tempfile,types,unittest,urllib.request
from pathlib import Path
from unittest.mock import MagicMock,patch
HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('_provision_controls',HERE/'provision.py');M=importlib.util.module_from_spec(s);s.loader.exec_module(M)
SHA='d'*40;IMAGE='sha256:'+'a'*64
PLAN=HERE/'provision-plan.json'if(HERE/'provision-plan.json').exists()else HERE.parent/'provision-plan.json'
REPO=next(p for p in HERE.parents if(p/'scripts/ci/inputs.lock.json').is_file())
def package(path,name,extra=()):
 rows=[('.PKGINFO',('pkgname = '+name+'\npkgver = 1\narch = aarch64\n').encode(),'file',''),('.INSTALL',b'NEVER EXECUTE','file',''),('.BUILDINFO',b'DATA','file',''),('.MTREE',b'DATA','file',''),('usr',b'','directory',''),('usr/lib',b'','directory',''),('usr/lib/'+name,b'PAYLOAD_'+name.encode(),'file',''),*extra]
 with tarfile.open(path,'w:xz')as t:
  for name,data,kind,target in rows:
   r=tarfile.TarInfo(name);r.uid=r.gid=0;r.mode=0o755 if kind=='directory'else 0o644;r.type={'file':tarfile.REGTYPE,'directory':tarfile.DIRTYPE,'symlink':tarfile.SYMTYPE,'hardlink':tarfile.LNKTYPE,'fifo':tarfile.FIFOTYPE}[kind]
   if kind=='file':r.size=len(data);t.addfile(r,io.BytesIO(data))
   else:r.linkname=target;t.addfile(r)
class Controls(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='SYNTHETIC-provision-');self.work=Path(self.tmp.name);self.plan,_=M.load_plan(PLAN,M.PLAN_PIN['sha256']);self.real_lock=(REPO/'scripts/ci/inputs.lock.json').read_bytes();self.out=self.work/'environment';self.source=self.work/'source';self.source.mkdir();self.depth=0;self.retiring=0;self.present=True;self.foreign=False;self.calls=[];self.cancel=False;self.rows={'Dockerfile':M.pin(b'DATA'),'rootfs.tar.gz':M.pin(b'DATA'),'tool-overlay.tar':M.pin(b'DATA')};self.tools={n:dict(bytes=10,sha256='b'*64,resolved=n)for n in self.plan['qualification']['tools']}
  self.guard=dict(arch='aarch64',uid=os.getuid(),gid=os.getgid(),user='alarm',capabilities={n:0 for n in('CapEff','CapPrm','CapBnd','CapInh','CapAmb')},no_new_privs=1,root_read_only=True,tmpfs_private=True,interfaces=['lo'],local_docker_socket_exposed=False);self.qualification=dict(packages_count=165,packages_sha256=self.plan['base_inventory_sha256'],tools=self.tools,guard=self.guard)
  self.E=types.SimpleNamespace(CONTRACT_PURPOSE='GUI-FRESH-TEST-SIGNER-IMAGE',PURPOSE='GUI-FRESH-TEST-SIGNER-ENVIRONMENT',host=MagicMock(),docker_config=self.config,cancellation=self.cancellation,retirement=self.retirement,qualify=MagicMock(return_value=self.qualification),remove_container=MagicMock(),command=self.command);self.args=types.SimpleNamespace(source=self.source,plan=PLAN,plan_sha256=M.PLAN_PIN['sha256'],output=self.out)
 def tearDown(self):self.tmp.cleanup()
 @contextlib.contextmanager
 def config(self,out):
  p=out/'docker-config';p.mkdir(mode=0o700,exist_ok=True);assert not any(p.iterdir());yield
 @contextlib.contextmanager
 def cancellation(self):
  self.depth+=1
  try:yield
  finally:self.depth-=1
 @contextlib.contextmanager
 def retirement(self):
  self.retiring+=1
  try:yield
  finally:self.retiring-=1
 def snapshot(self,source,inputs,raw,sha):(inputs/'native-inputs.lock.json').write_bytes(self.real_lock);return dict(SYNTHETIC_SOURCE_ONLY=True)
 def build(self,out,inputs,plan,lock,providers,record,E,native):
  self.assertGreater(self.depth,0)
  if self.cancel:raise KeyboardInterrupt('MOCK_TERM')
  (out/'context').mkdir();record.update(image_id=IMAGE,tag='cachy-asahi-gui-test-signer:'+record['nonce'],before_images=[],context_sha256=M.pin(M.enc(self.rows))['sha256'],inputs={'SYNTHETIC':True});self.record=record;return dict(tools=self.tools),self.rows
 def command(self,args,timeout=60,required=True):
  self.calls.append(args)
  if args[:3]==['docker','image','ls']:
   tag='foreign:keep'if self.foreign else self.record['tag'];return 0,((IMAGE+' '+tag+'\n').encode()if self.present else b'')
  if args[:3]==['docker','container','ls']:return 0,b''
  if args[:3]==['docker','image','rm']:
   self.assertGreater(self.retiring,0);self.assertEqual(args,['docker','image','rm','--no-prune',self.record['tag']]);self.present=self.foreign;return 0,b'UNTAGGED'
  raise AssertionError('UNEXPECTED_MOCK_ACTOR '+repr(args))
 @contextlib.contextmanager
 def fence(self):
  with patch.object(subprocess,'Popen',side_effect=AssertionError('NO_REAL_PROCESS')),patch.object(socket,'socket',side_effect=AssertionError('NO_NETWORK')),patch.object(urllib.request,'urlopen',side_effect=AssertionError('NO_ACQUISITION')):yield
 @contextlib.contextmanager
 def production(self):
  with self.fence(),patch.dict(os.environ,SOURCE_SHA=SHA,WORKFLOW_SHA=SHA),patch.object(M,'snapshot_source',side_effect=self.snapshot),patch.object(M,'native_module',return_value=types.SimpleNamespace()),patch.object(M,'environment_module',return_value=self.E),patch.object(M,'build_image',side_effect=self.build),patch.object(M,'context_rows',return_value=self.rows),patch.object(M,'check_inputs',return_value={'SYNTHETIC':True}),patch.object(M,'source_join'),patch.object(M,'inspect_owned',return_value={'OWNED':True}):yield
 def test_real_Root_plan_lock_dependencies_and_exact_nine_public_inputs(self):
  with self.fence():lock,providers=M.validate_lock(self.plan,self.real_lock)
  self.assertEqual(len(M.inventory(lock)),165);self.assertEqual(len(M.items(self.plan)),9);self.assertEqual({r['name']for r in self.plan['packages']},{'python','mpdecimal'});self.assertEqual(providers['mpdecimal'],'mpdecimal');self.assertIn(providers['libgcc'],self.plan['base_inventory']);self.assertEqual(self.plan['overlay']['status'],'UNREGISTERED_TOOL_OVERLAY')
 def test_plan_and_lock_drift_refuse_before_any_actor(self):
  with self.fence():
   with self.assertRaises(ValueError):M.load_plan(PLAN,'0'*64)
   with self.assertRaises(ValueError):M.validate_lock(self.plan,self.real_lock+b' ')
 def test_mocked_produce_validate_cleanup_export_identity_end_to_end(self):
  with self.production():
   contract=M.produce(self.args);self.assertIsNone(contract['oci_ref']);self.assertEqual(contract['image_id'],IMAGE);self.assertEqual(len(contract),9)
   with patch.object(M,'validate_artifacts',return_value=(self.plan,{'tools':self.tools})):self.assertEqual(M.validate_environment(self.out,SHA),contract)
   cleanup=M.cleanup(types.SimpleNamespace(output=self.out))
  self.assertEqual(cleanup['contract_sha256'],M.filepin(self.out/'contract.json')['sha256']);self.assertTrue(cleanup['removed_new_image']);self.assertEqual(cleanup['status'],'PASS');self.assertFalse(self.present);self.assertEqual(self.retiring,0);self.assertEqual(self.depth,0);env=M.obj(M.read(self.out/'environment.json'));self.assertEqual(env['production_pin'],M.filepin(self.out/'production.json'))
  nonces=[call.args[1]for call in self.E.remove_container.call_args_list];self.assertIn(self.record['nonce'],nonces);self.assertIn(M.qualification_nonce(self.record),nonces);self.E.qualify.assert_called_once_with(contract,M.qualification_nonce(self.record));target=self.work/'public';index=M.export(types.SimpleNamespace(environment=self.out,output=target));self.assertEqual(index['files']['cleanup.json'],M.filepin(self.out/'cleanup.json'));self.assertEqual(set(p.name for p in target.iterdir()),set(index['files'])|{'index.json'})
 def test_cancellation_scope_preserves_failure_receipt_and_no_contract(self):
  self.cancel=True
  with self.production(),self.assertRaises(KeyboardInterrupt):M.produce(self.args)
  record=M.obj(M.read(self.out/'production.json'));self.assertEqual((record['status'],record['error_type']),('FAIL','KeyboardInterrupt'));self.assertFalse((self.out/'contract.json').exists());self.assertEqual(self.depth,0)
 def test_bad_selected_workflow_source_refuses_before_output(self):
  with self.production(),patch.dict(os.environ,WORKFLOW_SHA='0'*40),self.assertRaises(ValueError):M.produce(self.args)
  self.assertFalse(self.out.exists())
 def test_concurrent_foreign_reference_is_preserved_and_cleanup_fails(self):
  with self.production():M.produce(self.args);self.foreign=True
  with self.production(),self.assertRaises(ValueError):M.cleanup(types.SimpleNamespace(output=self.out))
  self.assertTrue(self.present);self.assertEqual(M.obj(M.read(self.out/'cleanup.json'))['status'],'FAIL');self.assertEqual(len([c for c in self.calls if c[:3]==['docker','image','rm']]),1)
 def test_public_exports_never_include_archives_context_or_images(self):
  with self.production():M.produce(self.args)
  (self.out/'rootfs.tar.gz').write_bytes(b'NEVER_EXPORT');target=self.work/'public';index=M.export(types.SimpleNamespace(environment=self.out,output=target));self.assertTrue(set(index['files'])<=set(M.PUBLIC));self.assertFalse(index['image_exported']);self.assertFalse(index['archives_exported']);self.assertFalse((target/'rootfs.tar.gz').exists());self.assertFalse((target/'context').exists())
 def test_inert_production_receipt_is_rejected_before_docker_or_keys(self):
  self.out.mkdir(mode=0o700);M.save(self.out/'production.json',{'INERT':True})
  with self.fence(),patch.object(M,'environment_module',side_effect=AssertionError('NO_DOCKER')),self.assertRaises(ValueError):M.validate_environment(self.out,SHA)
 def test_arbitrary_rebound_image_contract_is_refused_before_image_inspect(self):
  with self.production():M.produce(self.args)
  contract=M.obj(M.read(self.out/'contract.json'));contract['image_id']='sha256:'+'f'*64;M.save(self.out/'contract.json',contract)
  with self.production(),patch.object(M,'validate_artifacts',return_value=(self.plan,{'tools':self.tools})),self.assertRaises(ValueError):M.validate_environment(self.out,SHA)
 def test_image_labels_native_architecture_and_preexisting_inventory_are_all_required(self):
  record=dict(nonce='f'*32,source_sha=SHA,plan_pin=M.PLAN_PIN,context_sha256='e'*64,image_id=IMAGE,tag='owned:tag',before_images=[]);image=dict(Id=IMAGE,Architecture='arm64',Os='linux',Config=dict(User='alarm',Labels=M.labels(record)),RepoDigests=[],RepoTags=['owned:tag']);E=types.SimpleNamespace(command=MagicMock(return_value=(0,M.enc([image]))))
  with self.fence(),patch.object(M,'before_images',return_value=[[IMAGE,'owned:tag']]):
   self.assertEqual(M.inspect_owned(E,record)['Id'],IMAGE)
   for field,value in(('Architecture','amd64'),('RepoTags',['foreign:tag'])):
    bad=copy.deepcopy(image);bad[field]=value;E.command.return_value=(0,M.enc([bad]))
    with self.assertRaises(ValueError):M.inspect_owned(E,record)
   E.command.return_value=(0,M.enc([image]));record['before_images']=[[IMAGE,'old:preexisting']]
   with self.assertRaises(ValueError):M.inspect_owned(E,record)
 def test_Dockerfile_has_no_install_or_keygen_and_private_metadata_check_precedes_USER(self):
  text=M.dockerfile(1001,1001).decode();self.assertTrue(text.startswith('FROM scratch\n'));self.assertIn('ADD rootfs.tar.gz /',text);self.assertIn('ADD tool-overlay.tar /',text);self.assertLess(text.index('private-keys-v1.d'),text.index('USER alarm'));self.assertNotIn('pacman ',text);self.assertNotIn('quick-generate',text);self.assertNotIn('pacman-key',text)
 def overlay_plan(self,extra=()):
  cache=self.work/'cache';cache.mkdir();rows=[]
  for name in('mpdecimal','python'):
   filename=name+'.pkg.tar.xz';package(cache/filename,name,extra if name=='python'else());rows.append(dict(name=name,version='1',filename=filename,depends=[],provides=[]))
  return cache,dict(packages=rows,bounds=self.plan['bounds'])
 def test_overlay_is_payload_only_and_never_executes_INSTALL_or_changes_ALPM(self):
  cache,plan=self.overlay_plan();target=self.work/'overlay.tar'
  with self.fence():report=M.overlay(cache,plan,target)
  with tarfile.open(target)as t:names=t.getnames()
  self.assertTrue(all(n=='usr'or n.startswith('usr/')for n in names));self.assertNotIn('.INSTALL',names);self.assertEqual(report['status'],'UNREGISTERED_TOOL_OVERLAY');self.assertFalse(report['package_install']);self.assertFalse(report['TEST_key_generation'])
 def test_overlay_rejects_traversal_escaping_links_special_nodes_and_ALPM_paths(self):
  for i,extra in enumerate((('../escape',b'X','file',''),('/absolute',b'X','file',''),('var/lib/pacman/local/forged',b'X','file',''),('usr/escape',b'','symlink','../../root'),('usr/fifo',b'','fifo',''),('usr/hard',b'','hardlink','usr/missing'))):
   parent=self.work/str(i);parent.mkdir()
   with patch.object(self,'work',parent):cache,plan=self.overlay_plan((extra,))
   with self.fence(),self.assertRaises(ValueError):M.overlay(cache,plan,parent/'refused.tar')
   self.assertFalse((parent/'refused.tar').exists())
 def test_probe_has_no_key_generation_and_crypto_only_inside_public_tmpfs(self):
  self.assertNotIn('quick-generate-key',M.PROBE);self.assertNotIn('faked-system-time',M.PROBE);self.assertIn("C.gpg_home('gui-provision-public-auth-','/tmp')",M.PROBE);self.assertIn('--list-secret-keys',M.PROBE);self.assertIn('archlinuxarm-revoked',M.PROBE);self.assertNotIn("for home in('/root",M.PROBE);self.assertIn('C.native.valid_signature',M.PROBE)

class BuildxCallsiteControls(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='SYNTHETIC-buildx-callsite-');self.work=Path(self.tmp.name);self.out=self.work/'environment';self.out.mkdir(mode=0o700);self.inputs=self.out/'inputs';self.inputs.mkdir();cache=self.inputs/'cache';cache.mkdir();self.credentials=self.out/'docker-config';self.credentials.mkdir(mode=0o700);self.plan=copy.deepcopy(M.load_plan(PLAN,M.PLAN_PIN['sha256'])[0]);root=self.plan['rootfs'];raw=b'SYNTHETIC_ROOTFS_NOT_EXECUTABLE';(cache/root['filename']).write_bytes(raw);root.update(size=len(raw),sha256=M.pin(raw)['sha256']);self.record=dict(nonce='c'*32,source_sha=SHA,plan_pin=M.PLAN_PIN,uid=os.getuid(),gid=os.getgid(),source_provenance={'SYNTHETIC':True},image_id=None);self.build_calls=[];self.value={'SYNTHETIC_PROBE':True};self.native=types.SimpleNamespace(acquire=MagicMock(),rootfs_inventory=MagicMock(return_value=[]));self.E=types.SimpleNamespace(command=self.command)
 def tearDown(self):self.tmp.cleanup()
 def command(self,args,timeout=60,*,required=True,buildx_config=None):
  self.assertEqual(args[:2],['docker','build']);self.assertEqual(timeout,600);self.assertTrue(required);self.assertEqual(buildx_config,self.out/'buildx-state');self.assertEqual(buildx_config,buildx_config.resolve());self.assertFalse(buildx_config.is_symlink());self.assertEqual(buildx_config.stat().st_uid,os.getuid());self.assertEqual(buildx_config.stat().st_mode&0o777,0o700);self.assertFalse(any(buildx_config.iterdir()));self.assertFalse(any(self.credentials.iterdir()));self.assertNotEqual(buildx_config,self.credentials);self.build_calls.append((args,buildx_config));(buildx_config/'refs').mkdir(mode=0o700);(buildx_config/'activity').write_bytes(b'SYNTHETIC BUILDX MANAGED STATE');Path(args[args.index('--iidfile')+1]).write_text(IMAGE+'\n');return 0,b'SYNTHETIC_BUILD_COMPLETE'
 def overlay(self,cache,plan,destination):destination.write_bytes(b'SYNTHETIC_OVERLAY');return{'SYNTHETIC':True}
 @contextlib.contextmanager
 def context(self):
  with patch.object(subprocess,'Popen',side_effect=AssertionError('NO_REAL_PROCESS')),patch.object(socket,'socket',side_effect=AssertionError('NO_NETWORK')),patch.object(urllib.request,'urlopen',side_effect=AssertionError('NO_ACQUISITION')),patch.object(M,'before_images',return_value=[]),patch.object(M,'check_inputs',return_value={}),patch.object(M,'scan_rootfs',return_value={}),patch.object(M,'overlay',side_effect=self.overlay),patch.object(M,'source_join'),patch.object(M,'inspect_owned'),patch.object(M,'probe_image',return_value=self.value),patch.object(M,'check_probe'):yield
 def build(self):
  with self.context():return M.build_image(self.out,self.inputs,self.plan,{'rootfs_packages':[]},{},self.record,self.E,self.native)
 def test_build_gets_separate_fresh_state_and_managed_writes_leave_credentials_empty(self):
  value,rows=self.build();self.assertEqual(value,self.value);self.assertEqual(set(rows),{'Dockerfile','rootfs.tar.gz','tool-overlay.tar'});self.assertEqual(len(self.build_calls),1);self.assertTrue((self.out/'buildx-state/refs').is_dir());self.assertEqual((self.out/'buildx-state/activity').read_bytes(),b'SYNTHETIC BUILDX MANAGED STATE');self.assertEqual(list(self.credentials.iterdir()),[])
 def test_reentry_refuses_managed_state_without_deleting_or_adopting_it(self):
  self.build();shutil.rmtree(self.out/'context')
  with self.assertRaisesRegex(ValueError,'fresh absent private Buildx state'):self.build()
  self.assertEqual(len(self.build_calls),1);self.assertEqual((self.out/'buildx-state/activity').read_bytes(),b'SYNTHETIC BUILDX MANAGED STATE');self.assertEqual(list(self.credentials.iterdir()),[])
 def test_existing_empty_state_refuses_before_build(self):
  state=self.out/'buildx-state';state.mkdir(mode=0o700)
  with self.assertRaisesRegex(ValueError,'fresh absent private Buildx state'):self.build()
  self.assertEqual(self.build_calls,[]);self.assertEqual(list(state.iterdir()),[])
 def test_alias_state_refuses_before_build_and_preserves_target(self):
  target=self.work/'borrowed-state';target.mkdir(mode=0o700);(self.out/'buildx-state').symlink_to(target,target_is_directory=True)
  with self.assertRaisesRegex(ValueError,'fresh absent private Buildx state'):self.build()
  self.assertEqual(self.build_calls,[]);self.assertEqual(list(target.iterdir()),[]);self.assertTrue((self.out/'buildx-state').is_symlink())

if __name__=='__main__':unittest.main(verbosity=2)

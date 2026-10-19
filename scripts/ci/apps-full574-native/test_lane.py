# SPDX-License-Identifier: MIT
"""Inert native owner/data controls. No signing, daemon, namespace or libalpm actors."""
import base64,copy,contextlib,io,json,os,subprocess,sys,tarfile,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock,patch
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE));import contract as C
ROOT=next(p for p in HERE.parents if (p/'manifests/packages.toml').is_file())
job=C.load('test_owner',HERE/'job.py');fixture=C.load('test_fixture',HERE/'fixture.py');life=C.load('test_lifecycle',HERE/'lifecycle.py')

def external_base(root,base):
 """Only the real bounded hash/parse path; dummy signatures grant no trust."""
 client=C.load('client_base_control',ROOT/'scripts/client/client.py');release=C.load('release_base_control',ROOT/'scripts/release/release.py')
 root.mkdir();(root/'repo').mkdir();(root/'base.json').write_bytes(C.encoded(base))
 spec=dict(schema_version=1,release_id='inert-external-base',repo_name='inert',target_arch='aarch64',synthetic=True,base=dict(path='base.json',snapshot_id=base['snapshot_id'],sha256=C.sha((root/'base.json').read_bytes())))
 (root/'spec.json').write_bytes(C.encoded(spec));name='inert-1-1-any.pkg.tar.xz'
 for n in ('inert.db.tar.gz','inert.files.tar.gz',name):
  (root/'repo'/n).write_bytes(b'INERT_NOT_ARCHIVE_NOT_SIGNED');(root/'repo'/(n+'.sig')).write_bytes(b'INERT_NOT_SIGNATURE')
 files={p.relative_to(root).as_posix():C.sha(p.read_bytes()) for p in root.rglob('*') if p.is_file()}
 value=dict(schema_version=1,release_id=spec['release_id'],signer='A'*40,files=files,packages=[dict(name='inert',version='1-1',arch='any',filename=name,sha256=files['repo/'+name])],symlinks={})
 (root/'release.json').write_bytes(C.encoded(value));fd=client.directory(root)
 try:
  description,manifest,raw=client.describe(fd);pin,size=client.hash_member(fd,'base.json')
  with unittest.TestCase().assertRaisesRegex(client.Error,'bounded size'):client.read_member(fd,'base.json')
  target=root.parent/'copied-base.json';again,count=client.hash_member(fd,'base.json',snapshot=target)
 finally:os.close(fd)
 loaded=release.load(target);decoded=client.decode(target.read_bytes());assert loaded==decoded==base and pin==again==manifest['files']['base.json'] and size==count==len(target.read_bytes())
 return dict(bytes=size,packages=len(base['packages']),paths=sum(len(p['files']) for p in base['packages']),sha256=pin,signature_verification='NOT_RUN_INERT_HASH_PARSE_CONTROL_ONLY',unchanged_caps=dict(JSON=client.MAX_JSON,file=client.MAX_FILE,total=client.MAX_TOTAL))

class Controls(unittest.TestCase):
 def setUp(self):
  forbid=patch.object(subprocess,'Popen',side_effect=AssertionError('actors forbidden in inert controls'));forbid.start();self.addCleanup(forbid.stop)
  self.temp=tempfile.TemporaryDirectory(prefix='apps574-owner-control-');self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
 def test_unbound_refuses_before_source_actor_or_secret(self):
  with patch.object(C,'decode',return_value=dict(schema_version=1,status='UNBOUND',versions=C.VERSIONS)),self.assertRaisesRegex(ValueError,'UNBOUND'):C.policy()
 def test_refs_drift_alias_hardlink_and_duplicate_json_refuse(self):
  p=self.root/'input';p.write_bytes(b'inert');row=C.ref(self.root,p);self.assertEqual(C.checked(self.root,row),b'inert')
  p.write_bytes(b'changed')
  with self.assertRaisesRegex(ValueError,'hash differs'):C.checked(self.root,row)
  alias=self.root/'alias';alias.symlink_to('input')
  with self.assertRaises(ValueError):C.read(alias)
  alias.unlink();os.link(p,alias)
  with self.assertRaises(ValueError):C.read(p)
  with self.assertRaisesRegex(ValueError,'duplicate'):C.decode(b'{"a":1,"a":2}')
 def test_source_manifest_and_adapter_are_independent_byte_pins(self):
  adapter=self.root/'adapter.py';adapter.write_bytes(b'# inert\n');pin=C.ref(self.root,adapter);manifest=self.root/'source-manifest.json';manifest.write_bytes(C.encoded(dict(schema_version=1,status='FROZEN_NATIVE574_APPS_SOURCE',files={name:{k:v for k,v in pin.items() if k!='path'} for name in ('adapter.py','scripts/apps/file_capabilities.py','scripts/apps/test_file_capabilities.py',C.LANE+'/export_extract.py')})))
  for name in ('scripts/apps/file_capabilities.py','scripts/apps/test_file_capabilities.py',C.LANE+'/export_extract.py'):
   target=self.root/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(b'# inert\n')
  with patch.object(C,'HERE',self.root),patch.object(C,'policy',return_value=dict(adapter=pin)):
   C.source(self.root);adapter.write_bytes(b'# changed\n')
   with self.assertRaisesRegex(ValueError,'hash differs'):C.source(self.root)
 def test_current_source_and_independent_adapter_policy_join_before_actors(self):
  binding=C.policy();actual=C.ref(ROOT,ROOT/'scripts/apps/full574_closure.py')
  historical=dict(path='scripts/apps/full574_closure.py',bytes=17201,sha256='a15e62f40dcad8ba7824babec9f9046a4caec3e3cfa68c11d904c37988c3fb2c')
  current=dict(path='scripts/apps/full574_closure.py',bytes=22621,sha256='f43304982dee768adf48f1c2ae5ecf6afa32e2cc405846046f6ac29604022b55')
  self.assertEqual(binding['adapter'],historical);self.assertEqual(binding['versions']['cachy-asahi-apps'],'0.1.0-5');self.assertEqual(binding['versions']['cachy-asahi-orphans'],'0.1.0-1')
  if actual==historical:self.assertEqual(C.source(ROOT),binding)
  else:
   self.assertEqual(actual,current)
   with self.assertRaisesRegex(ValueError,r'^source/input hash differs: scripts/apps/full574_closure\.py$'):C.source(ROOT)
 def test_actual_packet_must_match_root_carrier_before_inspection(self):
  args=SimpleNamespace(source=self.root,packet=self.root/'carrier/payload')
  with patch.object(C,'source',return_value=dict(packet_source='a'*40)),patch.object(subprocess,'check_output',return_value='b'*40+'\n'),patch.object(C,'inputs',side_effect=AssertionError('packet before carrier check')),self.assertRaisesRegex(ValueError,'carrier checkout'):job.check(args)
 def test_policy_binding_uses_actual_snapshot_not_future_receipt(self):
  inputs=self.root/'inputs';inputs.mkdir();pub=self.root/'snapshot-public';pub.mkdir();extraction=dict(archive_sha256='a'*64,nodes=42,capability_restoration='PRESERVED_AND_COMPLETE_NODE_MAP_VERIFIED',security_capabilities={'usr/bin/UNIT-inert':'0100000240000000000000000000000000000000'},security_capabilities_sha256=C.sha(C.encoded({'usr/bin/UNIT-inert':'0100000240000000000000000000000000000000'})));C.save(pub/'extraction.json',extraction);C.save(pub/'base.json',dict(inert=True))
  snapshot=dict(status='PASS_ORIGINAL574_APPS_CLOSURE_SNAPSHOT',tree_sha256='b'*64,source_packages_sha256='c'*64,source_closure_sha256='d'*64,source_inode=[1,2],source_capabilities={'usr/bin/UNIT-inert':'0100000240000000000000000000000000000000'},source_capabilities_sha256=C.sha(C.encoded({'usr/bin/UNIT-inert':'0100000240000000000000000000000000000000'})));C.save(pub/'snapshot.json',snapshot)
  module=SimpleNamespace(PURPOSE='APPS_ORIGINAL574_READONLY_CLOSURE',EXECUTION_BUDGET=dict(backend_seconds=600,caller_seconds=610),digest=lambda v:C.sha(C.encoded(v)),current_payloads=lambda:{n:{'inert':n} for n in C.VERSIONS})
  packet=dict(packages={n:dict(files=dict(a=dict(sha256='e'*64))) for n in C.VERSIONS});report=dict(token='f'*32,snapshot_point=dict(archive_sha256='a'*64))
  with patch.object(C,'adapter',return_value=module):job.bind(self.root,self.root,report,packet)
  policy=C.decode(C.read(inputs/'full574-policy.json'));lease=C.decode(C.read(inputs/'full574-lease.json'))
  self.assertEqual(policy['execution_budget'],dict(backend_seconds=600,caller_seconds=610));self.assertEqual(policy['execution_budget'],lease['execution_budget']);self.assertEqual(policy['snapshot_sha256'],'a'*64);self.assertEqual(policy['extraction_receipt_sha256'],C.sha(C.encoded(extraction)));self.assertEqual(lease['source'],'/seed');self.assertEqual(lease['source_identity'],[1,2]);self.assertEqual(set(policy['candidates']),set(C.VERSIONS));self.assertEqual(policy['source_tree_sha256'],snapshot['tree_sha256']);self.assertEqual(policy['source_capabilities'],snapshot['source_capabilities']);self.assertEqual(policy['source_capabilities_sha256'],lease['source_capabilities_sha256'])
 def test_actor_mounts_no_authority_in_consumers_no_privileged_or_network(self):
  report=dict(token='a'*32,image='sha256:'+'b'*64,actors=[],commands=[]);api=SimpleNamespace(inspect=Mock(side_effect=[None,dict(actual=True)]),verify_actor=Mock(return_value='c'*64));command=Mock(return_value=dict(code=0))
  job.actor(self.root,self.root,report,command,api,'lifecycle','lifecycle.py');argv=command.call_args.args[0]
  self.assertIn('--network=none',argv);self.assertIn('--read-only',argv);self.assertIn('--cap-drop=ALL',argv);self.assertIn('--security-opt=no-new-privileges',argv);self.assertIn('--pids-limit=128',argv);self.assertIn('--memory=4g',argv)
  self.assertTrue(any('dst=/seed,readonly' in x for x in argv));self.assertFalse(any('/authority' in x for x in argv));self.assertNotIn('--privileged',argv);self.assertFalse(any('SYS_ADMIN' in x for x in argv))
 def test_uncertain_consumer_blocks_clone_key_and_producer_disposal(self):
  output=self.root/'runtime';output.mkdir();base=self.root/'base';base.mkdir();proof=self.root/'proof.json';receipt=self.root/'cleanup.json';C.save(proof,dict(consumer_token='a'*32,job_token='b'*16,source_sha='c'*40));C.save(output/'owner.json',dict(token='a'*32,producer_token='b'*16,source_sha='c'*40,image='sha256:'+'d'*64,actors=[]))
  api=SimpleNamespace(producer_lease=lambda _:contextlib.nullcontext(),lease=lambda _:contextlib.nullcontext(),command_api=Mock(),retire=Mock(side_effect=ValueError('uncertain actor preserved')))
  args=SimpleNamespace(source=self.root,proof=proof,base=base,output=output,receipt=receipt)
  with patch.object(C,'source'),patch.object(job,'owner_api',return_value=api),patch.object(job,'actor',side_effect=AssertionError('disposal actor before absence')):
   value=job.cleanup(args)
  self.assertEqual(value['status'],'FAIL');self.assertEqual(value['producer'],'PRESERVED');self.assertEqual(value['authority'],'PRESERVED')
 def test_true_plan_keeps_default_runtime_and_dedicated_backend_bounds(self):
  with patch.object(C,'read',return_value=b'inert'):
   args=life.backend('apply',self.root,'a'*64)
  self.assertEqual(args[:4],['/usr/bin/python3','-I','-B','/source/scripts/apps/transaction.py']);self.assertIn('--full574-lease-sha256',args);self.assertIn('--ownership-sha256',args)
  text=(HERE/'lifecycle.py').read_text();self.assertIn("'--worker'",text);self.assertIn('time.monotonic()+600',text);self.assertIn('signal.SIGSTOP',text);self.assertIn("'rollback'",C.encoded(dict(rollback='NOT_CLAIMED')).decode().replace('"',"'"))
  self.assertNotIn('--nodeps',text);self.assertNotIn('--overwrite',text);self.assertNotIn('db.lck\').unlink',text)
 def test_interruption_retains_real_pending_copy_after_group_reap_model(self):
  workspace=self.root/'copy';(workspace/'root/var/lib/pacman').mkdir(parents=True);lock=workspace/'root/var/lib/pacman/db.lck';lock.write_bytes(b'');C.save(workspace/'apps-pending.json',dict(status='ATTEMPT_STARTED_COMMIT_OUTCOME_NOT_RECORDED'))
  info=lock.lstat();fake_lock=SimpleNamespace(st_mode=info.st_mode,st_nlink=1,st_uid=0,st_size=0,st_dev=info.st_dev,st_ino=info.st_ino)
  original=Path.lstat
  def lstat(path,*a,**k):return fake_lock if path==lock else original(path,*a,**k)
  sent=[]
  def kill(pid,sig):
   if sig==0:raise ProcessLookupError()
   sent.append(sig)
  process=SimpleNamespace(pid=123456,returncode=-life.signal.SIGKILL,wait=Mock(return_value=-life.signal.SIGKILL))
  with patch.object(life,'OUT',self.root),patch.object(life,'WORK',self.root),patch.dict(os.environ,OWNER_TOKEN='a'*32),patch.object(subprocess,'Popen',return_value=process),patch.object(life.os,'waitid',return_value=None),patch.object(life.os,'killpg',side_effect=kill),patch.object(Path,'lstat',lstat):
   value=life.interrupted(None,workspace,'b'*64,['INERT_NO_ACTOR'])
  self.assertEqual(sent,[life.signal.SIGSTOP,life.signal.SIGKILL]);self.assertTrue(process.wait.called);self.assertEqual(value['packages_committed'],'UNKNOWN');self.assertEqual(value['rollback'],'NOT_CLAIMED');self.assertTrue((workspace/'apps-pending.json').is_file());self.assertTrue(lock.is_file());self.assertEqual(value['raw_lock'],'NOT_READ_OR_DELETED')
 def test_large_complete_base_uses_original_external_hash_limit(self):
  rows=[dict(name='package-'+str(n),version='1-1',arch='any',depend=[],provides=[],conflict=[],replaces=[],files=['usr/share/data/'+str(n)+'/'+str(i)+'-'+'x'*24 for i in range(200)]) for n in range(574)]
  base=dict(schema_version=1,snapshot_id='inert-external-base',kind='complete-target-transaction',target_arch='aarch64',packages=rows)
  result=external_base(self.root/'bundle',base);self.assertGreater(result['bytes'],4*1024**2);self.assertEqual(result['packages'],574);self.assertEqual(result['paths'],114800);self.assertEqual(result['unchanged_caps']['JSON'],4*1024**2)
 def test_release_spec_preserves_all_base_rows_and_protection(self):
  base=dict(schema_version=1,snapshot_id='inert',kind='complete-target-transaction',target_arch='aarch64',packages=[dict(name='base-'+str(n),version='1',files=['usr/share/'+str(n)]) for n in range(574)])
  value=fixture.specification(base,[], 'a'*40);self.assertTrue(value['synthetic']);self.assertEqual(value['base']['sha256'],C.sha(C.encoded(base)));self.assertEqual(len(value['policy']['protected_packages']),574);self.assertEqual(len(value['policy']['coordinated_sets'][0]['versions']),574)
 def test_result_cannot_credit_dependency_autoremove_cache_rewrite_or_false_refusal(self):
  success=dict(status='PASS_OWNED_DISPOSABLE_APPS_TRANSACTION',dependency_checks='ORDINARY_LIBALPM',cleanup='OWNED_WORKSPACE_TEMP_AND_ALPM_HANDLE_LOCK_RELEASED',rollback='NOT_ATTEMPTED_DISPOSABLE_COPY_ONLY',full574_closure=dict(status='PASS-recorded-state-preserved',main_cache='RAW_EQUAL',auxiliary_transition=dict(kind='RAW_EQUAL'),auxiliary_inode_liveness='NOT_ESTABLISHED_SOURCE_SNAPSHOT_KEYS',security_capabilities='EXACT_SOURCE_MAP_PRESERVED',source_capabilities_sha256='a'*64))
  transactions=[dict(success,prepared_add=C.VERSIONS,prepared_remove={}),dict(success,prepared_add={},prepared_remove={n:v for n,v in C.VERSIONS.items() if n!='cachy-asahi-repository-runtime'}),dict(success,prepared_add={},prepared_remove={'cachy-asahi-repository-runtime':'0.1.0-1'})]
  value=dict(status='PASS_NATIVE574_APPS_ACTUAL_TRANSACTIONS',base_count=574,counts=[578,575,574],source_preserved=True,user_trust_protected_preserved=True,workspaces_disposed=True,interrupted_copy='NOT_RUN_SEPARATE_ACTOR_REQUIRED',hardware='NOT_RUN',security_capabilities='EXACT_SOURCE_MAP_PRESERVED',source_capabilities_sha256='a'*64,transactions=transactions,refusals={n:dict(status='FAIL',commit_started=False,packages_committed=False) for n in ('wrong-plan-sha','precommit-db-drift','foreign-alpm-lock')})
  C.result(value)
  for kind in ('autoremove','cache-rewrite','refusal-commit','capability-change'):
   bad=copy.deepcopy(value)
   if kind=='autoremove':bad['transactions'][1]['prepared_remove']=dict(C.VERSIONS)
   elif kind=='cache-rewrite':bad['transactions'][0]['full574_closure']['auxiliary_transition']['kind']='WAIVED'
   elif kind=='refusal-commit':bad['refusals']['wrong-plan-sha']['commit_started']=True
   else:bad['transactions'][0]['full574_closure']['source_capabilities_sha256']='b'*64
   with self.subTest(kind=kind),self.assertRaises(ValueError):C.result(bad)
 def rejected_header(self,*,pax=None,uid=0,mtime=0,mode=0o644):
  old=C.load('original_extraction_diagnostic',ROOT/'scripts/ci/glibc-gnu-provider-lifecycle-owner/snapshot.py');path=self.root/'unit-metadata.tar'
  with tarfile.open(path,'w',format=tarfile.PAX_FORMAT) as stream:
   member=tarfile.TarInfo('UNIT-inert-not-actual-header');member.uid=uid;member.mtime=mtime;member.mode=mode;member.pax_headers=pax or {};stream.addfile(member,io.BytesIO(b''))
  try:old.records(path)
  except ValueError as error:
   # The archive must not be reopened/read by diagnostics after original refusal.
   snap=C.load('Apps_metadata_diagnostic',HERE/'snapshot.py')
   with patch.object(tarfile,'open',side_effect=AssertionError('archive replay forbidden')):value=snap.metadata_failure(error,old)
   self.assertEqual(str(error),'plain archive metadata; xattrs/unknown PAX refused');self.assertEqual(value['bytes'],len(C.encoded(value['value'])));self.assertEqual(value['sha256'],C.sha(C.encoded(value['value'])));self.assertLessEqual(value['bytes'],65536)
   self.assertEqual(value['value']['extractor_source_sha256'],C.sha(C.read(ROOT/'scripts/ci/glibc-gnu-provider-lifecycle-owner/snapshot.py')));return value['value']
  self.fail('original metadata refusal required; no fixture accepted')
 def test_failed_metadata_uses_exact_original_frame_without_archive_replay(self):
  value=self.rejected_header(pax={'UNIT.unknown-pax':'inert original parsed value'})
  self.assertFalse(value['predicates']['pax_keys_allowed']);self.assertTrue(value['predicates']['mode_in_range']);self.assertEqual(value['pax']['count'],1)
  self.assertEqual(base64.b64decode(value['member']['name']['prefix_base64']),b'UNIT-inert-not-actual-header');self.assertEqual(value['member']['type_hex'],'30')
  self.assertEqual(base64.b64decode(value['pax']['entries'][0]['value']['prefix_base64']),b'inert original parsed value')
 def test_combined_guard_diagnostic_does_not_infer_pax_from_numeric_failure(self):
  value=self.rejected_header(uid=-1);self.assertFalse(value['predicates']['uid_nonnegative'])
  value=self.rejected_header(pax={'mtime':'inf'});self.assertFalse(value['predicates']['mtime_finite']);self.assertTrue(value['predicates']['pax_keys_allowed']);self.assertEqual(base64.b64decode(value['pax']['entries'][0]['key']['prefix_base64']),b'mtime')
 def test_large_metadata_values_are_bounded_hashed_and_other_exceptions_ignored(self):
  raw='x'*20000;value=self.rejected_header(pax={'UNIT.large':raw});row=value['pax']['entries'][0]['value'];self.assertFalse(row['complete']);self.assertEqual(row['bytes'],20000);self.assertEqual(row['sha256'],C.sha(raw.encode()));self.assertEqual(len(base64.b64decode(row['prefix_base64'])),512)
  snap=C.load('Apps_metadata_diagnostic_other',HERE/'snapshot.py');old=C.load('original_extraction_other',ROOT/'scripts/ci/glibc-gnu-provider-lifecycle-owner/snapshot.py')
  self.assertIsNone(snap.metadata_failure(ValueError('unrelated failure'),old));self.assertIsNone(snap.metadata_failure(ValueError('plain archive metadata; xattrs/unknown PAX refused'),old))
 def test_setfcap_is_only_extract_and_copy_consumer_grant(self):
  for role in ('extract','lifecycle','interruption','source-verify','signer','scrub','source-cleanup'):
   report=dict(token='a'*32,image='sha256:'+'b'*64,actors=[],commands=[],snapshot_point=dict(archive_sha256='c'*64));api=SimpleNamespace(inspect=Mock(side_effect=[None,{}]),verify_actor=Mock(return_value='d'*64));command=Mock(return_value=dict(code=0))
   job.actor(self.root,self.root,report,command,api,role,'INERT-NOT-EXECUTED.py');argv=command.call_args.args[0]
   self.assertEqual('--cap-add=SETFCAP' in argv,role in ('extract','lifecycle','interruption'));self.assertIn('--security-opt=no-new-privileges',argv);self.assertIn('--network=none',argv)
 def capability_extractor(self):
  derivative=C.load('cap_export_derivative',HERE/'export_extract.py')
  caps=C.load('cap_export_helper',HERE.parents[1]/'apps/file_capabilities.py')
  return derivative,derivative.isolated(ROOT,caps,C.read)
 def capability_archive(self,pax,kind=tarfile.REGTYPE):
  path=self.root/'caps.tar'
  with tarfile.open(path,'w',format=tarfile.PAX_FORMAT,encoding='utf8',errors='surrogateescape') as stream:
   for n in ('proc','sys','dev','run','tmp','usr','usr/bin'):
    m=tarfile.TarInfo(n);m.type=tarfile.DIRTYPE;m.uid=os.getuid();m.gid=os.getgid();m.mode=0o755;stream.addfile(m)
   m=tarfile.TarInfo('usr/bin/inert');m.type=kind;m.uid=os.getuid();m.gid=os.getgid();m.mode=0o755;m.pax_headers=pax
   if kind==tarfile.SYMTYPE:m.linkname='literal-unexecuted'
   stream.addfile(m,io.BytesIO(b'') if kind==tarfile.REGTYPE else None)
   if kind==tarfile.REGTYPE:
    alias=tarfile.TarInfo('usr/bin/inert-alias');alias.type=tarfile.LNKTYPE;alias.linkname='usr/bin/inert';alias.uid=m.uid;alias.gid=m.gid;alias.mode=m.mode;stream.addfile(alias)
  return path
 def test_exact_diagnostic_bytes_and_hardlink_aliases_are_retained(self):
  derivative,extractor=self.capability_extractor();raw=bytes.fromhex('0100000240000000000000000000000000000000');path=self.capability_archive({derivative.XATTR:raw.decode('utf8','surrogateescape')})
  members,total,excluded=extractor.records(path)
  self.assertEqual(extractor.apps_capabilities,{'usr/bin/inert':raw.hex(),'usr/bin/inert-alias':raw.hex()});self.assertEqual(total,0);self.assertEqual(excluded,[])
  old=C.load('unchanged_shared_extractor',ROOT/derivative.ORIGINAL)
  with self.assertRaisesRegex(ValueError,'xattrs/unknown PAX refused'):old.records(path)
  # Real ordinary tempfile extraction, no capability-bearing program execution.
  extractor.DATA=self.root;extractor.ROOT=self.root/'root'
  with patch.dict(os.environ,OWNER_TOKEN='a'*32):value=extractor.extract(path,extractor.ROOT,C.sha(path.read_bytes()))
  self.assertEqual(value['capability_restoration'],'PENDING_RESTORE_AND_COMPLETE_NODE_VERIFICATION');self.assertEqual(value['original_extractor_sha256'],derivative.ORIGINAL_SHA256);self.assertNotEqual(value['adapted_extractor_sha256'],derivative.ORIGINAL_SHA256)
  self.assertEqual(value['security_capabilities'],extractor.apps_capabilities);self.assertEqual((extractor.ROOT/'usr/bin/inert').stat().st_ino,(extractor.ROOT/'usr/bin/inert-alias').stat().st_ino)
 def test_all_other_unknown_or_nonregular_capability_pax_refuse(self):
  derivative,extractor=self.capability_extractor();text=bytes.fromhex('0100000240000000000000000000000000000000').decode('utf8','surrogateescape')
  for pax,kind in [({'SCHILY.xattr.user.inert':'x'},tarfile.REGTYPE),({'SCHILY.xattr.security.selinux':'x'},tarfile.REGTYPE),({'SCHILY.acl.access':'x'},tarfile.REGTYPE),({derivative.XATTR:text},tarfile.DIRTYPE),({derivative.XATTR:text},tarfile.SYMTYPE),({derivative.XATTR:'invalid'},tarfile.REGTYPE)]:
   with self.subTest(pax=list(pax),kind=kind),self.assertRaises(ValueError):extractor.records(self.capability_archive(pax,kind))
 def test_extractor_source_bytes_and_exact_anchor_are_mandatory(self):
  derivative,_=self.capability_extractor();caps=SimpleNamespace(pax_value=lambda x:bytes())
  for raw in (b'inert',C.read(ROOT/derivative.ORIGINAL).replace(b'member.uid>=0',b'member.uid>=1')):
   with self.assertRaisesRegex(ValueError,'exact original extractor'):derivative.isolated(ROOT,caps,lambda _:raw)
 def test_workflow_source_packet_gates_before_secret_seed(self):
  path=HERE.parents[2]/'.github/workflows/native-arm-apps-full574-transaction.yml'
  if not path.exists():path=ROOT/'.github/workflows/native-arm-apps-full574-transaction.yml'
  text=path.read_text();self.assertIn('  workflow_dispatch:',text);self.assertNotIn('  push:',text);self.assertLess(text.index('job.py" proof'),text.index('${{ secrets.'));self.assertLess(text.index('Verify closed native packet'),text.index('${{ secrets.'));self.assertIn('cancel-in-progress: false',text);self.assertIn('contents: read',text);self.assertIn('650s',text)

 def inventory_fixture(self):
  reader=C.load('real_inventory_output_control',ROOT/'packages/tools/cachy-asahi-apps/inventory.py');client=C.load('real_inventory_client_control',ROOT/'scripts/client/client.py')
  work=self.root/'work';work.mkdir(mode=0o700);out=self.root/'out';out.mkdir(mode=0o700);workspace=work/'main'
  db=workspace/'root/var/lib/pacman';local=db/'local';package=local/'inert-1';package.mkdir(parents=True)
  (local/'ALPM_DB_VERSION').write_bytes(b'9\n');(package/'desc').write_bytes(b'%NAME%\ninert\n\n%VERSION%\n1\n\n%ARCH%\naarch64\n\n');(package/'files').write_bytes(b'')
  return reader,client,work,out,workspace,db
 def plan_calls(self,reader,client,*,failure=False):
  observed=[]
  def call(argv,**kwargs):
   observed.append((argv,kwargs))
   if argv[1]=='inventory':return reader.publish(Path(argv[argv.index('--dbpath')+1]),Path(argv[argv.index('--output')+1]),client,lambda row:row)
   installed=Path(argv[argv.index('--installed')+1]);raw=C.read(installed,16*1024**2)
   self.assertEqual(argv[argv.index('--installed-sha256')+1],C.sha(raw));self.assertEqual(reader.validate(C.decode(raw),lambda row:row),reader.QUALIFICATION)
   if failure:raise ValueError('inert modeled plan refusal')
   return dict(status='PLANNED',applied='NOT_APPLIED',installer_authority=False,synthetic=True,plan=dict(installed_inventory=reader.QUALIFICATION))
  return SimpleNamespace(call=call),observed
 def test_actual_inventory_publish_owner_guard_refuses_root0_runner1001_shape(self):
  reader,client,work,out,workspace,db=self.inventory_fixture();fstat=reader.os.fstat
  def foreign(fd):
   original=fstat(fd);fields=list(original);fields[4]=1001
   return os.stat_result(fields)
  with patch.object(reader.os,'geteuid',return_value=0),patch.object(reader.os,'fstat',side_effect=foreign),self.assertRaisesRegex(ValueError,'caller-owned output parent'):
   reader.publish(db,out/'inventory.json',client,lambda row:row)
  self.assertFalse((out/'inventory.json').exists())
 def test_private_inventory_uses_real_ALPM9_reader_retains_exact_bytes_then_retires_private_file(self):
  reader,client,work,out,workspace,db=self.inventory_fixture();calls,observed=self.plan_calls(reader,client)
  before={p.relative_to(db).as_posix():p.read_bytes() for p in db.rglob('*') if p.is_file()}
  with patch.object(life,'WORK',work),patch.object(life,'OUT',out),patch.object(life,'credentials',return_value=[]):path,plan=life.planned(calls,workspace,'install','install',['cache'])
  requested=Path(observed[0][0][-1]);retained=out/requested.name
  self.assertEqual(requested,work/'install-inventory.json');self.assertFalse(requested.is_relative_to(workspace/'root'));self.assertFalse(requested.exists())
  self.assertEqual(observed[0][1]['seconds'],45);self.assertEqual(observed[1][1]['seconds'],120)
  raw=retained.read_bytes();self.assertEqual(C.decode(raw)['observation']['dbpath'],str(db));self.assertEqual(retained.stat().st_mode&0o777,0o600)
  self.assertEqual(observed[1][0][observed[1][0].index('--installed-sha256')+1],C.sha(raw));self.assertEqual(C.decode(path.read_bytes()),plan)
  self.assertEqual({p.relative_to(db).as_posix():p.read_bytes() for p in db.rglob('*') if p.is_file()},before)
 def test_private_inventory_alias_owner_mode_digest_and_existing_export_refuse(self):
  path=self.root/'inventory.json';out=self.root/'out';out.mkdir();raw=b'{"inert":true}\n';path.write_bytes(raw);path.chmod(0o600)
  summary=dict(output=str(path),bytes=len(raw),sha256=C.sha(raw))
  with patch.object(life,'OUT',out):
   with patch.object(life.os,'geteuid',return_value=os.getuid()+1),self.assertRaisesRegex(ValueError,'caller-owned inventory'):life.retain_inventory(path,summary)
   path.chmod(0o644)
   with self.assertRaises(ValueError):life.retain_inventory(path,summary)
   path.chmod(0o600);alias=self.root/'alias';os.link(path,alias)
   with self.assertRaises(ValueError):life.retain_inventory(path,summary)
   alias.unlink();alias.symlink_to(path)
   with self.assertRaises(ValueError):life.retain_inventory(alias,summary)
   with self.assertRaisesRegex(ValueError,'command bytes differ'):life.retain_inventory(path,summary|dict(sha256='0'*64))
   target=out/path.name;target.write_bytes(b'prior diagnosis')
   with self.assertRaises(FileExistsError):life.retain_inventory(path,summary)
   self.assertEqual(target.read_bytes(),b'prior diagnosis');self.assertEqual(path.read_bytes(),raw)
 def test_plan_failure_keeps_original_private_and_retained_inventory_for_ordered_outer_cleanup(self):
  reader,client,work,out,workspace,db=self.inventory_fixture();calls,_=self.plan_calls(reader,client,failure=True)
  with patch.object(life,'WORK',work),patch.object(life,'OUT',out),patch.object(life,'credentials',return_value=[]),self.assertRaisesRegex(ValueError,'modeled plan refusal'):
   life.planned(calls,workspace,'install','install',['cache'])
  self.assertEqual((work/'install-inventory.json').read_bytes(),(out/'install-inventory.json').read_bytes());self.assertFalse((out/'install-plan.json').exists())

 def test_inventory_retention_allows_only_read_side_atime_change(self):
  # This host uses noatime. Project the kernel's permitted read-side atime
  # update explicitly over a genuine tempfile/read; do not claim a live delta.
  path=self.root/'inventory.json';out=self.root/'out';out.mkdir();raw=b'{"inert":true}\n';path.write_bytes(raw);path.chmod(0o600)
  original=path.lstat();read=C.read;lstat=Path.lstat;accessed=False
  class AccessTime(tuple):
   def __new__(cls,info):
    fields=list(info);fields[7]+=1;value=super().__new__(cls,fields);value.info=info;return value
   def __getattr__(self,name):
    return getattr(self.info,name)+(1 if name=='st_atime_ns' else 0)
  projected=AccessTime(original)
  self.assertNotEqual(original,projected)
  self.assertEqual(life.inventory_identity(original),life.inventory_identity(projected))
  def observed_read(*args,**kwargs):
   nonlocal accessed
   value=read(*args,**kwargs);accessed=True;return value
  def observed_stat(candidate):
   info=lstat(candidate);return AccessTime(info) if candidate==path and accessed else info
  with patch.object(life,'OUT',out),patch.object(C,'read',side_effect=observed_read),patch.object(Path,'lstat',observed_stat):
   self.assertEqual(life.retain_inventory(path,dict(output=str(path),bytes=len(raw),sha256=C.sha(raw))),raw)
  self.assertEqual((out/path.name).read_bytes(),raw);self.assertEqual((out/path.name).stat().st_mode&0o777,0o600)

 def test_inventory_retention_still_refuses_every_nonaccess_identity_drift(self):
  path=self.root/'inventory.json';out=self.root/'out';out.mkdir();raw=b'{"inert":true}\n';path.write_bytes(raw);path.chmod(0o600)
  read=C.read;lstat=Path.lstat;summary=dict(output=str(path),bytes=len(raw),sha256=C.sha(raw))
  for field in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'):
   accessed=False
   def observed_read(*args,**kwargs):
    nonlocal accessed
    value=read(*args,**kwargs);accessed=True;return value
   def observed_stat(candidate):
    info=lstat(candidate)
    if candidate!=path or not accessed:return info
    class Changed:
     def __getattr__(self,name):return getattr(info,name)+(1 if name==field else 0)
    return Changed()
   with self.subTest(field=field),patch.object(life,'OUT',out),patch.object(C,'read',side_effect=observed_read),patch.object(Path,'lstat',observed_stat),self.assertRaisesRegex(ValueError,'caller-owned inventory'):
    life.retain_inventory(path,summary)
   self.assertFalse((out/path.name).exists())
  self.assertEqual(path.read_bytes(),raw)

if __name__=='__main__':unittest.main(verbosity=2)

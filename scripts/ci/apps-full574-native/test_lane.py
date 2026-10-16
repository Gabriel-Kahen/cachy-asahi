# SPDX-License-Identifier: MIT
"""Inert native owner/data controls. No signing, daemon, namespace or libalpm actors."""
import copy,contextlib,json,os,subprocess,sys,tempfile,unittest
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
  adapter=self.root/'adapter.py';adapter.write_bytes(b'# inert\n');pin=C.ref(self.root,adapter);manifest=self.root/'source-manifest.json';manifest.write_bytes(C.encoded(dict(schema_version=1,status='FROZEN_NATIVE574_APPS_SOURCE',files={'adapter.py':{k:v for k,v in pin.items() if k!='path'}})))
  with patch.object(C,'HERE',self.root),patch.object(C,'policy',return_value=dict(adapter=pin)):
   C.source(self.root);adapter.write_bytes(b'# changed\n')
   with self.assertRaisesRegex(ValueError,'hash differs'):C.source(self.root)
 def test_actual_packet_must_match_root_carrier_before_inspection(self):
  args=SimpleNamespace(source=self.root,packet=self.root/'carrier/payload')
  with patch.object(C,'source',return_value=dict(packet_source='a'*40)),patch.object(subprocess,'check_output',return_value='b'*40+'\n'),patch.object(C,'inputs',side_effect=AssertionError('packet before carrier check')),self.assertRaisesRegex(ValueError,'carrier checkout'):job.check(args)
 def test_policy_binding_uses_actual_snapshot_not_future_receipt(self):
  inputs=self.root/'inputs';inputs.mkdir();pub=self.root/'snapshot-public';pub.mkdir();extraction=dict(archive_sha256='a'*64,nodes=42);C.save(pub/'extraction.json',extraction);C.save(pub/'base.json',dict(inert=True))
  snapshot=dict(status='PASS_ORIGINAL574_APPS_CLOSURE_SNAPSHOT',tree_sha256='b'*64,source_packages_sha256='c'*64,source_closure_sha256='d'*64,source_inode=[1,2]);C.save(pub/'snapshot.json',snapshot)
  module=SimpleNamespace(PURPOSE='APPS_ORIGINAL574_READONLY_CLOSURE',digest=lambda v:C.sha(C.encoded(v)),current_payloads=lambda:{n:{'inert':n} for n in C.VERSIONS})
  packet=dict(packages={n:dict(files=dict(a=dict(sha256='e'*64))) for n in C.VERSIONS});report=dict(token='f'*32,snapshot_point=dict(archive_sha256='a'*64))
  with patch.object(C,'adapter',return_value=module):job.bind(self.root,self.root,report,packet)
  policy=C.decode(C.read(inputs/'full574-policy.json'));lease=C.decode(C.read(inputs/'full574-lease.json'))
  self.assertEqual(policy['snapshot_sha256'],'a'*64);self.assertEqual(policy['extraction_receipt_sha256'],C.sha(C.encoded(extraction)));self.assertEqual(lease['source'],'/seed');self.assertEqual(lease['source_identity'],[1,2]);self.assertEqual(set(policy['candidates']),set(C.VERSIONS));self.assertEqual(policy['source_tree_sha256'],snapshot['tree_sha256'])
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
 def test_true_plan_keeps_default_runtime_and_original_backend_bounds(self):
  with patch.object(C,'read',return_value=b'inert'):
   args=life.backend('apply',self.root,'a'*64)
  self.assertEqual(args[:4],['/usr/bin/python3','-I','-B','/source/scripts/apps/transaction.py']);self.assertIn('--full574-lease-sha256',args);self.assertIn('--ownership-sha256',args)
  text=(HERE/'lifecycle.py').read_text();self.assertIn("'--worker'",text);self.assertIn('time.monotonic()+300',text);self.assertIn('signal.SIGSTOP',text);self.assertIn("'rollback'",C.encoded(dict(rollback='NOT_CLAIMED')).decode().replace('"',"'"))
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
  success=dict(status='PASS_OWNED_DISPOSABLE_APPS_TRANSACTION',dependency_checks='ORDINARY_LIBALPM',cleanup='OWNED_WORKSPACE_TEMP_AND_ALPM_HANDLE_LOCK_RELEASED',rollback='NOT_ATTEMPTED_DISPOSABLE_COPY_ONLY',full574_closure=dict(status='PASS-recorded-state-preserved',main_cache='RAW_EQUAL',auxiliary_transition=dict(kind='RAW_EQUAL'),auxiliary_inode_liveness='NOT_ESTABLISHED_SOURCE_SNAPSHOT_KEYS'))
  transactions=[dict(success,prepared_add=C.VERSIONS,prepared_remove={}),dict(success,prepared_add={},prepared_remove={n:v for n,v in C.VERSIONS.items() if n!='cachy-asahi-repository-runtime'}),dict(success,prepared_add={},prepared_remove={'cachy-asahi-repository-runtime':'0.1.0-1'})]
  value=dict(status='PASS_NATIVE574_APPS_ACTUAL_TRANSACTIONS',base_count=574,counts=[578,575,574],source_preserved=True,user_trust_protected_preserved=True,workspaces_disposed=True,interrupted_copy='NOT_RUN_SEPARATE_ACTOR_REQUIRED',hardware='NOT_RUN',transactions=transactions,refusals={n:dict(status='FAIL',commit_started=False,packages_committed=False) for n in ('wrong-plan-sha','precommit-db-drift','foreign-alpm-lock')})
  C.result(value)
  for kind in ('autoremove','cache-rewrite','refusal-commit'):
   bad=copy.deepcopy(value)
   if kind=='autoremove':bad['transactions'][1]['prepared_remove']=dict(C.VERSIONS)
   elif kind=='cache-rewrite':bad['transactions'][0]['full574_closure']['auxiliary_transition']['kind']='WAIVED'
   else:bad['refusals']['wrong-plan-sha']['commit_started']=True
   with self.subTest(kind=kind),self.assertRaises(ValueError):C.result(bad)
 def test_workflow_source_packet_gates_before_secret_seed(self):
  path=HERE.parents[2]/'.github/workflows/native-arm-apps-full574-transaction.yml'
  if not path.exists():path=ROOT/'.github/workflows/native-arm-apps-full574-transaction.yml'
  text=path.read_text();self.assertIn('  workflow_dispatch:',text);self.assertNotIn('  push:',text);self.assertLess(text.index('job.py" proof'),text.index('${{ secrets.'));self.assertLess(text.index('Verify closed native packet'),text.index('${{ secrets.'));self.assertIn('cancel-in-progress: false',text);self.assertIn('contents: read',text);self.assertIn('650s',text)

if __name__=='__main__':unittest.main(verbosity=2)

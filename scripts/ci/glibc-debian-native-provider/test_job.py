# SPDX-License-Identifier: MIT
"""Inert owner/packet/cleanup controls. Synthetic packets grant no authority."""
import fcntl,hashlib,importlib.util,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE));import job as J;import reuse
ROOT=next(p for p in HERE.parents if (p/'manifests/packages.toml').is_file())
class Controls(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(prefix='debian-native-inert-');self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
  guard=patch.object(subprocess,'Popen',side_effect=AssertionError('native/crypto actors prohibited in inert controls'));guard.start();self.addCleanup(guard.stop)
  self.old=reuse.load(ROOT)
 def save(self,p,v):p.write_text(json.dumps(v));return p
 def test_original_cleanup_and_exact_four_retention_adaptations(self):
  original=J.module('original_owner_for_control',ROOT/'scripts/ci/glibc-gnu-provider/job.py')
  for name in ('cleanup','retire_consumers','manifest_files'):
   a,b=getattr(self.old,name).__code__,getattr(original,name).__code__;self.assertEqual(a.co_code,b.co_code);self.assertEqual(a.co_consts,b.co_consts)
  self.assertEqual(len(reuse.CHANGES),4);self.assertEqual(self.old.LABEL,reuse.LABEL);self.assertIn('caa2-1',self.old.PACKAGE);self.assertEqual(self.old.MAX_TOTAL,768*1024**2)
 def test_changed_original_owner_refuses_before_loading(self):
  p=self.root/'scripts/ci/glibc-gnu-provider/job.py';p.parent.mkdir(parents=True);p.write_bytes((ROOT/'scripts/ci/glibc-gnu-provider/job.py').read_bytes()+b'\n')
  with self.assertRaisesRegex(ValueError,'exact original'):reuse.load(self.root)
 def test_real_policy_binds_only_new_source_and_actual_root_inventory(self):
  p=J.policy();self.assertEqual(p['packet']['ref'],'05d07fd634cb004eb7feab6e5fa9b175c5687efa');self.assertNotIn('private16k',p);self.assertEqual(p['packet']['index']['bytes'],1201)
 def test_unbound_packet_stops_before_any_harness_or_bundle(self):
  p=json.loads((HERE/'input-policy.json').read_bytes());p['packet']['ref']=None;policy=self.save(self.root/'policy.json',p)
  with self.assertRaisesRegex(ValueError,'UNBOUND'):J.prepare(ROOT,self.root/'absent',self.root/'harness',self.root/'bundle',policy)
  self.assertFalse((self.root/'harness').exists());self.assertFalse((self.root/'bundle').exists())
 def test_source_workflow_and_native_guard_and_separate_token_namespace(self):
  env=dict(SOURCE_SHA='a'*40,WORKFLOW_SHA='a'*40,GITHUB_SHA='a'*40,RUNNER_ARCH='ARM64',RUNNER_OS='Linux',GITHUB_RUN_ID='123',GITHUB_RUN_ATTEMPT='1')
  with patch.object(J,'source',return_value=self.old):
   p=J.prove(ROOT,{},env);self.assertEqual(p,J.prove(ROOT,{},env));self.assertEqual(p['old_GNU_pair'],'NOT_REUSED');self.assertEqual(len(p['job_token']),16);self.assertEqual(len(p['consumer_token']),32)
   old=hashlib.sha256(('glibc-provider-consumer:123:1:'+'a'*40).encode()).hexdigest()[:32];self.assertNotEqual(p['consumer_token'],old)
   for key,value in (('WORKFLOW_SHA','b'*40),('RUNNER_ARCH','X64'),('GITHUB_RUN_ID','-1')):
    bad=dict(env,**{key:value})
    with self.assertRaises(ValueError):J.prove(ROOT,{},bad)
 def fake_packet(self):
  inputs=self.root/'packet';inputs.mkdir();files={}
  for n in ('key12','key13','release','sources','dsc','archive','decision'):
   raw=n.encode();(inputs/n).write_bytes(raw);files[n]=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
  index=dict(schema_version=1,status='ROOT_BOUND_NEW_DEBIAN_SOURCE_INPUT_PACKET',qualification='SOURCE_AUTHORITY_ONLY_NATIVE_NOT_RUN_RELEASE_NOT_ADMITTED',files=files,total_bytes=sum(x['bytes'] for x in files.values()));raw=json.dumps(index).encode();(inputs/'index.json').write_bytes(raw)
  auth=self.root/J.CANDIDATE/'authority.json';auth.parent.mkdir(parents=True);self.save(auth,dict(decision=dict(path='decision',**files['decision'])))
  a=J.module('synthetic_chain_parser',ROOT/J.CANDIDATE/'auth.py');a.PUBLIC_PINS={k:v for k,v in files.items() if k!='decision'}
  return inputs,a,dict(packet=dict(ref='f'*40,index=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())))
 def test_closed_seven_inputs_join_and_extra_member_refuse(self):
  inputs,a,binding=self.fake_packet()
  with patch.object(J,'policy',return_value=binding),patch.object(J,'module',return_value=a),patch.object(a,'authority',return_value=dict(status='SYNTHETIC_NO_AUTHORITY')):
   self.assertEqual(J.packet(self.root,inputs)['status'],'PASS_EXACT_NEW_DEBIAN_SOURCE_PACKET');(inputs/'extra').write_text('foreign')
   with self.assertRaisesRegex(ValueError,'eight-file'):J.packet(self.root,inputs)
 def test_changed_chain_file_and_index_refuse(self):
  inputs,a,binding=self.fake_packet()
  with patch.object(J,'policy',return_value=binding),patch.object(J,'module',return_value=a),patch.object(a,'authority',side_effect=AssertionError('must refuse before authority')):
   (inputs/'archive').write_bytes(b'changed')
   with self.assertRaisesRegex(ValueError,'chain file changed'):J.packet(self.root,inputs)
   (inputs/'index.json').write_bytes(b'{}')
   with self.assertRaisesRegex(ValueError,'index differs'):J.packet(self.root,inputs)
 def fixture(self):
  base=self.root/'base';base.mkdir();runtime=self.root/'runtime';runtime.mkdir();token='c'*32;image='sha256:'+'b'*64
  self.save(base/'report.json',dict(image=image));(runtime/'consumer.lock').touch(mode=0o600);self.save(runtime/'owner.json',dict(schema_version=1,token=token,image=image,label=reuse.LABEL));return base,runtime,dict(consumer_token=token),image
 def test_live_consumer_lease_blocks_teardown(self):
  base,runtime,proof,_=self.fixture();fd=os.open(runtime/'consumer.lock',os.O_RDWR);fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  try:
   with self.assertRaises(BlockingIOError):self.old.retire_consumers(runtime,base,proof,lambda *_:self.fail('live actor touched'))
  finally:os.close(fd)
 def test_foreign_or_unknown_consumers_never_remove_producer(self):
  base,runtime,proof,image=self.fixture();calls=[]
  def command(argv):
   calls.append(argv)
   return SimpleNamespace(returncode=0,stdout=json.dumps([dict(Id='d'*64,Image=image,Config=dict(Labels={reuse.LABEL:'foreign'}))]).encode(),stderr=b'')
  with self.assertRaisesRegex(ValueError,'producer must remain'):self.old.retire_consumers(runtime,base,proof,command)
  self.assertFalse(any(c[1:3]==['rm','-f'] for c in calls))
  def unknown(_):return SimpleNamespace(returncode=1,stdout=b'',stderr=b'Cannot connect to daemon')
  with self.assertRaisesRegex(ValueError,'producer must remain'):self.old.retire_consumers(runtime,base,proof,unknown)
 def test_failed_consumers_stop_producer_cleanup(self):
  base,runtime,proof,_=self.fixture();f=self.root/'source';f.write_text('data');manifest=dict(schema_version=1,files={'source':dict(bytes=4,sha256=hashlib.sha256(b'data').hexdigest())})
  with patch.object(self.old,'retire_consumers',side_effect=ValueError('unknown consumer')),patch.object(subprocess,'run') as actor:r=self.old.cleanup(self.root,manifest,proof,base,runtime,self.root/'cleanup.json')
  actor.assert_not_called();self.assertEqual(r['status'],'FAIL');self.assertEqual(r['producer'],'NOT_RETIRED')
 def test_retention_exports_new_xz_and_sources_and_emitted_harness_only(self):
  base=self.root/'base';base.mkdir();runtime=self.root/'runtime';runtime.mkdir();bundle=self.root/'bundle';bundle.mkdir();h=self.root/'harness';h.mkdir()
  names=('glibc_2.43.orig.tar.xz','sid-Sources.xz')
  for n in names:
   with (bundle/n).open('wb') as f:f.truncate(9*1024**2)
  self.save(bundle/'bundle.json',dict(files=dict.fromkeys(names)));self.save(h/'source-manifest.json',dict(files={'new-only':{}}));(h/'new-only').write_text('new')
  proof=self.save(self.root/'proof',{});cleanup=self.save(self.root/'cleanup',{})
  r=self.old.retain(ROOT,base,runtime,bundle,proof,cleanup,self.root/'public',h)
  self.assertEqual(r['status'],'FAIL_OR_INCOMPLETE');self.assertIn('build-harness/new-only',r['files'])
  for n in names:self.assertIn('source/'+n,r['files']);self.assertFalse(r['files']['source/'+n]['truncated'])
  self.assertLessEqual(r['total_bytes'],768*1024**2)
 def test_retention_harness_pin_and_closed_flat_paths(self):
  h=self.root/'harness';h.mkdir();(h/'one').write_text('data');manifest=self.save(h/'source-manifest.json',dict(files={'one':dict(bytes=4,sha256=hashlib.sha256(b'data').hexdigest())}));pin=hashlib.sha256(manifest.read_bytes()).hexdigest()
  J.held_harness(self.old,h,pin)
  with self.assertRaisesRegex(ValueError,'manifest changed'):J.held_harness(self.old,h,'0'*64)
  (h/'one').write_text('drift')
  with self.assertRaisesRegex(ValueError,'file changed'):J.held_harness(self.old,h,pin)
  self.save(manifest,dict(files={'../foreign':dict(bytes=4,sha256='0'*64)}));pin=hashlib.sha256(manifest.read_bytes()).hexdigest()
  with self.assertRaisesRegex(ValueError,'closed emitted'):J.held_harness(self.old,h,pin)
 def test_manual_workflow_orders_source_auth_controls_secrets_pair_cleanup_export(self):
  w=(HERE.parents[2]/'.github/workflows/native-arm-glibc-debian-provider.yml').read_text()
  markers=('Prove source equals workflow before secrets','Verify seven-file chain','Focused inert controls','secrets.CACHY_','Native Debian-source pair','Retire consumers before the producer','Export closed bounded','Upload only')
  self.assertEqual([w.index(x) for x in markers],sorted(w.index(x) for x in markers));self.assertNotIn('\n  push:',w);self.assertNotIn('\n  schedule:',w);self.assertIn('ubuntu-24.04-arm',w);self.assertIn('timeout-minutes: 360',w)
  self.assertIn('$RUNNER_TEMP/debian-harness/run.py',w);self.assertNotIn('admission(', (HERE/'job.py').read_text());self.assertNotIn('UNBOUND',w)
if __name__=='__main__':unittest.main(verbosity=2)

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Owned fake-actor controls only: no Git, download, package or native actor."""
import base64,copy,hashlib,re,importlib.util,json,os,signal,socket,stat,subprocess,sys,tempfile,time,types,unittest
from pathlib import Path
from unittest.mock import patch
sys.dont_write_bytecode=True
D=Path(__file__).resolve().parent;ROOT=D.parents[2]
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
A=load('_test_gnu_retained_adapter',D/'retained_transport.py');E=A.E

def oid(kind,raw):return hashlib.sha1(kind.encode()+b' '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
# Exact original Source783 environment/selection ABI fixture; no actors.
REAL_ENVIRONMENT="def environment(e):\n source=e.get('SOURCE_SHA');run=e.get('GITHUB_RUN_ID');ref=e.get('GITHUB_REF_NAME');need(re.fullmatch('[a-f0-9]{40}',source or'')and source==e.get('GITHUB_SHA')==e.get('WORKFLOW_SHA')and re.fullmatch('[1-9][0-9]{0,19}',run or'')and re.fullmatch('codex/[a-z0-9-]+',ref or'')and e.get('GITHUB_RUN_ATTEMPT')=='1'and e.get('GITHUB_REPOSITORY')==REPO and e.get('GITHUB_EVENT_NAME')=='workflow_dispatch'and e.get('RUNNER_ARCH')=='ARM64','genuine first native source/ref/run environment');return dict(source=source,run=run,ref=ref)\n"
REAL_ENVIRONMENT_SHA='438efb768ed2e22a72bb49025158e1aaf112d8f5975ee055b568609930a79372'
SELECTION_RUN_EXPRESSION="identity['run']"
class Controls(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='GNU-TRANSPORT-FAKE-ONLY-');self.addCleanup(self.tmp.cleanup);self.base=Path(self.tmp.name);self.runtime=self.base/'runtime';self.runtime.mkdir(mode=0o700)
  self.R=A.api(ROOT);self.calls=[];self.prepares=[];self.supervisions=[]
  self.bodies={'LICENSE':b'fake fixture data only\n','bin/NEVER-EXECUTE':b'#!/bin/sh\nexit 99\n','packages/raw.bin':b'\0\xffraw\n','packages/empty.sig':b''}
  self.table={n:dict(mode='100755'if n.startswith('bin/')else'100644',oid=oid('blob',b))for n,b in self.bodies.items()};self.tree=E.tree_oid(self.table);self.commit=b'tree '+self.tree.encode()+b'\nauthor FAKE ONLY <fixture@example.invalid> 1 +0000\ncommitter FAKE ONLY <fixture@example.invalid> 1 +0000\n\nFAKE OWNED ACTOR CONTROL\n';self.sid=oid('commit',self.commit)
  self.profile=dict(schema=1,actual=None,source=self.sid,ref='FAKE-ONLY',files={n:E.pin(b)for n,b in self.bodies.items()});self.raw=(json.dumps(self.profile,sort_keys=True,indent=2)+'\n').encode();self.destination=self.runtime/'gnu-retained-transport'
  env=dict(SOURCE_SHA='a'*40,WORKFLOW_SHA='a'*40,GITHUB_SHA='a'*40,GITHUB_REF_NAME='codex/fake-controls',GITHUB_RUN_ID='123',GITHUB_RUN_ATTEMPT='1',GITHUB_REPOSITORY='Gabriel-Kahen/cachy-asahi',GITHUB_EVENT_NAME='workflow_dispatch',RUNNER_ARCH='ARM64',RUNNER_TEMP=str(self.runtime))
  self.enterContext(patch.dict(os.environ,env,clear=True));policy=self.runtime/'gnu-immutable-parent/selection/private-inputs/policy.json';policy.parent.mkdir(mode=0o700,parents=True);policy.write_bytes(E.encoded(dict(actual_source='a'*40,actual_ref='codex/fake-controls',actual_run='123',broker=dict(nonce='b'*32),bootstrap=dict(nonce='b'*32))));policy.chmod(0o600)
  self.own=A.binding(ROOT)[0]
  self.enterContext(patch.object(socket,'socket',side_effect=AssertionError('network forbidden')))
  for name in('kill','killpg','waitid','waitpid'):self.enterContext(patch.object(os,name,side_effect=AssertionError('numeric process operation forbidden')))
  self.enterContext(patch.object(subprocess,'run',side_effect=AssertionError('real command forbidden')))
  self.enterContext(patch.object(subprocess,'Popen',side_effect=self.spawn))
  self.enterContext(patch.object(self.R.op,'prepare',side_effect=lambda:self.prepares.append(True)))
  self.enterContext(patch.object(self.R.op,'supervise',side_effect=self.supervise))
 def spawn(self,argv,**kw):
  self.calls.append((argv,kw));out=b'';i=len(self.calls)-1
  if 'init'in argv:
   git=Path(argv[-1]);git.mkdir(mode=0o700);(git/'objects').mkdir(mode=0o700)
  elif 'rev-parse'in argv:out=(self.sid+'\n').encode()
  elif 'cat-file'in argv:
   if argv[-2]=='commit':out=self.commit
   else:
    out=next(b for n,b in self.bodies.items()if self.table[n]['oid']==argv[-1]);os.write(kw['stdout'],out);out=b''
  elif 'ls-tree'in argv:out=b''.join((r['mode']+' blob '+r['oid']+'\t'+n).encode()+b'\0'for n,r in sorted(self.table.items()))
  elif 'update-ref'in argv:(self.destination/'data/.git/HEAD').write_bytes((self.sid+'\n').encode())
  return types.SimpleNamespace(stdout=types.SimpleNamespace(fileno=lambda:0,close=lambda:None),stderr=types.SimpleNamespace(fileno=lambda:0,close=lambda:None),fake_output=out)
 def supervise(self,child,**kw):
  self.supervisions.append(kw);return dict(passed=True,reaped=True,output_complete=True,ownership='REAPED',group_census='EMPTY_TWICE',exit=0,timeout=False,error=None,signals=[],seconds=.001,output=child.fake_output)
 def deliver(self):
  return self.R.deliver(url='https://github.com/Gabriel-Kahen/cachy-asahi.git',expected_source=self.sid,profile_raw=self.raw,profile_sha256=E.pin(self.raw)['sha256'],destination=self.destination,executable_root=ROOT,policy=self.R.reference_policy(),binding_raw=E.encoded(self.own))
 def fixture_predicates(self):
  self.enterContext(patch.object(E,'CARRIER',self.sid));self.enterContext(patch.object(E,'PROFILE',E.pin(self.raw)['sha256']));self.enterContext(patch.object(E,'FILES',len(self.bodies)));self.enterContext(patch.object(E,'BYTES',sum(map(len,self.bodies.values()))))
 def receipt(self):return E.obj((self.destination/'receipt.json').read_bytes())
 def test_fake_full_rawblob_tree_modes_single_fetch_and_caps(self):
  result=self.deliver();self.assertEqual(result['status'],'PASS_EXACT_RETAINED_GIT_DATA_ONLY');self.assertEqual(len(self.calls),len(self.bodies)+7);self.assertEqual(sum('fetch'in a for a,_ in self.calls),1);self.assertEqual(len(self.prepares),len(self.calls));self.assertEqual(len(self.supervisions),len(self.calls));self.assertLessEqual(max(v['cap']for v in self.supervisions),400)
  for n,b in self.bodies.items():self.assertEqual((self.destination/'data'/n).read_bytes(),b);self.assertEqual(stat.S_IMODE((self.destination/'data'/n).stat().st_mode),0o755 if n.startswith('bin/')else 0o644)
  for argv,kw in self.calls:
   self.assertNotIn('checkout',argv);self.assertNotIn('reset',argv);self.assertNotIn('TOKEN',' '.join(kw['env']));self.assertEqual(kw['env']['GIT_CONFIG_GLOBAL'],'/dev/null');self.assertEqual(kw['env']['GIT_NO_LAZY_FETCH'],'1');self.assertTrue(kw['start_new_session']);self.assertTrue(callable(kw['preexec_fn']))
  self.fixture_predicates();table=E.validate_receipt(self.receipt(),self.profile,str(self.destination/'data'));self.assertEqual(table,self.table)
 def test_actual_original_environment_selection_run_string_contract(self):
  self.assertEqual(hashlib.sha256(REAL_ENVIRONMENT.encode()).hexdigest(),REAL_ENVIRONMENT_SHA)
  scope=dict(re=re,need=A.need,REPO='Gabriel-Kahen/cachy-asahi');exec(compile(REAL_ENVIRONMENT,'<PINNED_ORIGINAL_SOURCE_ENVIRONMENT>','exec'),scope);identity=scope['environment'](os.environ)
  selected_run=eval(compile(SELECTION_RUN_EXPRESSION,'<ORIGINAL_BINDING_BUILD_ACTUAL_RUN>','eval'),dict(identity=identity));self.assertIs(type(selected_run),str)
  path=self.runtime/'gnu-immutable-parent/selection/private-inputs/policy.json';value=E.obj(path.read_bytes());value['actual_run']=selected_run;path.write_bytes(E.encoded(value));self.assertEqual(A.binding(ROOT)[0]['run_id'],123)
  value['actual_run']=int(selected_run);path.write_bytes(E.encoded(value))
  with self.assertRaises(ValueError):A.binding(ROOT)
 def test_fixed_real_profile_metadata_has_every1154_byte(self):
  raw,p=A.profile(ROOT,self.R);self.assertEqual(len(p['files']),1154);self.assertEqual(sum(v['bytes']for v in p['files'].values()),1046432165);self.assertEqual(E.pin(raw)['sha256'],'4089fd798849cafda23d03c0dd95ac896a83fd63ad21e331ae420c147535586c');self.assertEqual(self.calls,[])
 def test_existing_destination_refuses_without_actor_or_overwrite(self):
  self.destination.mkdir();(self.destination/'held').write_bytes(b'held')
  with self.assertRaises(self.R.Error):self.deliver()
  self.assertEqual(self.calls,[]);self.assertEqual((self.destination/'held').read_bytes(),b'held')
 def test_wrong_profile_refuses_before_output(self):
  with self.assertRaises(self.R.Error):self.R.deliver(url='https://github.com/Gabriel-Kahen/cachy-asahi.git',expected_source=self.sid,profile_raw=self.raw,profile_sha256='f'*64,destination=self.destination,executable_root=ROOT,policy=self.R.reference_policy())
  self.assertFalse(self.destination.exists());self.assertEqual(self.calls,[])
 def test_receipt_changed_fetch_filter_modes_hash_or_owned_outcome_refuses(self):
  self.deliver();self.fixture_predicates();base=self.receipt();changes=[]
  for field,value in(('fetch_attempts',2),('full_namespace',False),('file_count',1),('material_bytes',1),('retry',True),('source_code_execution','PASS')):
   v=copy.deepcopy(base);v[field]=value;changes.append(v)
  for change in('filter','blob','mode','unknown','signal','timeout','output','cap','missing'):
   v=copy.deepcopy(base)
   if change=='filter':v['commands'][1]['argv'].insert(-2,'-c filter.x.process=evil')
   elif change=='blob':v['commands'][5]['stdout_material']['sha256']='f'*64
   elif change=='mode':v['commands'][5]['stdout_material']['mode']=0o777
   elif change=='unknown':v['commands'][1]['supervision']['ownership']='UNKNOWN'
   elif change=='signal':v['commands'][1]['supervision']['signals']=['SIGTERM']
   elif change=='timeout':v['commands'][1]['supervision']['timeout']=True
   elif change=='output':v['commands'][1]['supervision']['output_complete']=False
   elif change=='cap':v['commands'][1]['cap_seconds']=401
   else:v['commands'].pop()
   changes.append(v)
  for v in changes:
   with self.subTest(v=v.get('fetch_attempts')),self.assertRaises(ValueError):E.validate_receipt(v,self.profile,str(self.destination/'data'))
 def test_owned_failure_retains_partial_receipt_without_retry(self):
  def failed(child,**kw):
   v=self.supervise(child,**kw);v.update(passed=False,timeout=True,signals=['SIGTERM'],exit=-15);return v
  with patch.object(self.R.op,'supervise',side_effect=failed),self.assertRaises(self.R.Error):self.deliver()
  v=self.receipt();self.assertEqual(v['status'],'FAIL_RETAINED_GIT_DATA');self.assertEqual(len(self.calls),1);self.assertTrue(v['partial_data_retained']);self.assertTrue(v['commands'][0]['supervision']['timeout']);self.assertFalse(v['commands'][0]['passed'])
 def test_passive_evidence_roundtrip_never_includes_raw_package_stdout(self):
  self.deliver();self.fixture_predicates()
  with patch.object(A,'api',return_value=self.R),patch.object(A,'profile',return_value=(self.raw,self.profile)):
   value=A.evidence(ROOT,0)
  self.assertTrue(value['diagnostics_complete']);frame=E.frame(value);decoded=E.parse_framed(frame);self.assertEqual(decoded,value);proof=E.positive(value,self.raw,self.own);self.assertEqual(proof['blob_joins'],len(self.bodies));self.assertNotIn(self.bodies['packages/raw.bin'],b'\n'.join(base64.b64decode(v['base64'])for v in value['raw_diagnostics'].values()))
  self.assertTrue(all(not n.startswith('data/')for n in value['raw_diagnostics']));self.assertEqual(len(value['raw_diagnostics']),len(self.calls)+7)
 def test_missing_duplicate_changed_or_out_of_order_frame_refuses(self):
  payload=dict(schema=1,binding=self.own,wrapper_exit=1,transport=None,raw_diagnostics={},diagnostics_complete=False,error='FAKE failure');frame=E.frame(payload);lines=frame.splitlines(keepends=True)
  variants=[b''.join(lines[:-1]),frame+frame,b''.join([lines[0],lines[1].replace(b' 0 ',b' 1 ',1),*lines[2:]]),frame.replace(b'CHUNK_V1 0 ',b'CHUNK_V1 9 ',1),frame.replace(b'END_V1 ',b'END_V1 f',1)]
  for raw in variants:
   with self.subTest(raw=raw[-40:]),self.assertRaises((ValueError,KeyError)):E.parse_framed(raw)
 def test_current_existing_proof_rehashes_bodies_and_no_actor(self):
  self.deliver();self.fixture_predicates();before=len(self.calls)
  with patch.object(A,'api',return_value=self.R),patch.object(A,'profile',return_value=(self.raw,self.profile)):
   proof=A.verify_existing(self.destination/'data',ROOT,time.monotonic()+20);self.assertEqual(proof['blob_joins'],len(self.bodies));target=self.destination/'data/packages/raw.bin';target.write_bytes(b'changed')
   with self.assertRaises(ValueError):A.verify_existing(self.destination/'data',ROOT,time.monotonic()+20)
  self.assertEqual(len(self.calls),before)
 def test_binding_wrong_source_nonce_attempt_or_architecture_refuses(self):
  for k,v in(('SOURCE_SHA','f'*40),('GITHUB_RUN_ATTEMPT','2'),('RUNNER_ARCH','X64'),('GITHUB_REF_NAME','main')):
   with self.subTest(k=k),patch.dict(os.environ,{k:v}),self.assertRaises(ValueError):A.binding(ROOT)
  path=self.runtime/'gnu-immutable-parent/selection/private-inputs/policy.json';v=E.obj(path.read_bytes());v['broker']['nonce']='c'*32;path.write_bytes(E.encoded(v))
  with self.assertRaises(ValueError):A.binding(ROOT)
  self.assertEqual(self.calls,[])
 def test_missing_receipt_outer_timeout_retains_safe_diagnostics_only(self):
  logs=self.destination/'logs';logs.mkdir(mode=0o700,parents=True)
  for name,raw in(('0001.stdout',b'fetch diagnostic'),('0005.stdout',b'RAW_PACKAGE_MUST_NEVER_APPEAR'),('0005.stderr',b'blob command diagnostic')):(logs/name).write_bytes(raw)
  with patch.object(A,'api',return_value=self.R):value=A.evidence(ROOT,124)
  self.assertFalse(value['diagnostics_complete']);self.assertIsNone(value['transport']);self.assertEqual(set(value['raw_diagnostics']),{'logs/0001.stdout','logs/0005.stderr'});self.assertNotIn(b'RAW_PACKAGE_MUST_NEVER_APPEAR',E.frame(value))
 def test_first_signal_interrupts_owned_scope_second_latches_and_handlers_restore(self):
  events=[];previous={n:signal.getsignal(n)for n in(signal.SIGTERM,signal.SIGINT)}
  def deliver(**kwargs):
   events.append('owned_scope')
   try:signal.getsignal(signal.SIGTERM)(signal.SIGTERM,None)
   except InterruptedError:
    events.append('retire_current_owned_child');signal.getsignal(signal.SIGINT)(signal.SIGINT,None);events.append('second_latched');raise
   self.fail('first cancellation was ignored')
  fake=types.SimpleNamespace(deliver=deliver,reference_policy=self.R.reference_policy)
  with patch.object(A,'api',return_value=fake),patch.object(A,'profile',return_value=(self.raw,self.profile)),self.assertRaises(InterruptedError):A.run(ROOT)
  self.assertEqual(events,['owned_scope','retire_current_owned_child','second_latched']);self.assertEqual({n:signal.getsignal(n)for n in previous},previous);self.assertEqual(self.calls,[])
 def test_cancellation_launch_mask_unblocks_inside_owned_supervision(self):
  self.fixture_predicates();before=signal.pthread_sigmask(signal.SIG_BLOCK,set());events=[]
  def spawn(argv,**kwargs):
   current=signal.pthread_sigmask(signal.SIG_BLOCK,set());self.assertTrue({signal.SIGTERM,signal.SIGINT}<=current);events.append('launch_blocked');return self.spawn(argv,**kwargs)
  def owned(child,**kwargs):
   try:
    events.append('inside_owned_try');kwargs['streams'][0].fileno();self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK,set()),before);signal.getsignal(signal.SIGTERM)(signal.SIGTERM,None)
   except InterruptedError:
    events.append('owned_retirement');signal.getsignal(signal.SIGINT)(signal.SIGINT,None);value=self.supervise(child,**kwargs);value.update(passed=False,error='InterruptedError: modeled cancellation',signals=['SIGTERM']);return value
   self.fail('missing cancellation')
  with patch.object(A,'api',return_value=self.R),patch.object(A,'profile',return_value=(self.raw,self.profile)),patch.object(subprocess,'Popen',side_effect=spawn),patch.object(self.R.op,'supervise',side_effect=owned),self.assertRaises(self.R.Error):A.run(ROOT)
  self.assertEqual(events,['launch_blocked','inside_owned_try','owned_retirement']);self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK,set()),before);receipt=self.receipt();self.assertEqual(receipt['status'],'FAIL_RETAINED_GIT_DATA');self.assertTrue(receipt['commands'][0]['supervision']['reaped']);self.assertEqual(len(self.calls),1)
 def test_public_body_overcap_emits_honest_incomplete_frame(self):
  value=dict(schema=1,binding=self.own,wrapper_exit=1,transport={'oversize':'a'*(E.EVIDENCE_CAP+1)},raw_diagnostics={},diagnostics_complete=True,error=None)
  framed=A.public_frame(value);parsed=E.parse_framed(framed);self.assertFalse(parsed['diagnostics_complete']);self.assertIsNone(parsed['transport']);self.assertIn('PUBLIC_EVIDENCE_LIMIT',parsed['error']);self.assertLess(len(framed),4096)
if __name__=='__main__':unittest.main(verbosity=2)

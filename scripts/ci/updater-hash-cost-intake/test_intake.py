"""NEW deterministic DATA regressions. No historical suites, readers or actors."""
import base64,copy,hashlib,importlib.util,io,json,sys,types,unittest,zipfile
from pathlib import Path

HERE=Path(__file__).resolve().parent
# Install before any candidate import. A caught actor attempt still fails the
# final count gate; module import success alone is not actor-denial evidence.
ACTOR_ATTEMPTS=[]
def deny_actor(event,args):
 if event.startswith(('subprocess.','socket.','os.exec','os.spawn','os.fork','os.posix_spawn')) or event in('os.system','os.startfile','pty.spawn'):
  ACTOR_ATTEMPTS.append(event);raise RuntimeError('DATA actor fence: '+event)
sys.addaudithook(deny_actor)
spec=importlib.util.spec_from_file_location('initializer_v2',HERE/'initializer_v2.py')
I=importlib.util.module_from_spec(spec);sys.modules[spec.name]=I;spec.loader.exec_module(I)
P=json.loads((HERE/'source-contract.json').read_bytes())
SOURCE=HERE/'source'
BOUND=dict(case='normal',source='a'*40,ref='codex/deterministic-v2-data',run=123,attempt=1)
def read(path,cap=16*1024**2):
 path=Path(path)
 if path.is_relative_to(SOURCE/'emissions/cases/normal'):path=HERE/'fixtures/normal'/(path.relative_to(SOURCE/'emissions/cases/normal').as_posix()+'.txt')
 raw=path.read_bytes();I.need(len(raw)<=cap,'test bounded DATA read');return raw
def record(seq=2,**kw):
 v=dict(v=2,profile=I.PROFILE,nonce='1'*32,lane='WORKER',seq=seq,phase='WORKER_OBSERVE',state='REFUSED',elapsed_ns=100,remaining_ns=-1,ops=[1,1,0,0,2,10,20,100,30,40],saturated=False);v.update(kw);return v
def frame(v):return I.PREFIX+I.encoded(v)+b'\n'
def stream(raw,cap,kind='tail'):
 tail=raw[-cap:]
 return dict(**I.pin(raw),**{kind+'_bytes':len(tail),kind+'_base64':base64.b64encode(tail).decode()},omitted_bytes=len(raw)-len(tail),truncated=len(raw)>cap)
def command(argv,stdout,stderr):
 return dict(argv=argv,exit_code=1,seconds=0.25,time_limit=123,output_limit=2*1024**2,group_absence_verified=True,stdout_bytes=len(stdout),stdout_sha256=I.pin(stdout)['sha256'],stderr_bytes=len(stderr),stderr_sha256=I.pin(stderr)['sha256'],emulated16k_deadline=dict(nominal_seconds=12480 if argv[-1]=='/runner.py'else 15000,parent_total_seconds=15840,parent_elapsed_ns=14817*10**9,reserve_seconds=900,effective_seconds=123))
def envelope(kind,vm,stdout,stderr):
 argv=['/usr/bin/python3','-I','-B','/runner.py']if kind=='CALLER'else['/usr/bin/python3','-I','-B','/workspace/guest.py','worker']
 return dict(schema_version=1,status='FAILED_ORIGINAL_GUEST_'+kind+'_DATA_NOT_ACCEPTANCE',nonce=vm,record=command(argv,stdout,stderr),error_type=None,stdout=stream(stdout,4096),stderr=stream(stderr,8192),capture_scope='ORIGINAL_RUN_COMMAND_CAPTURE_MAY_BE_PARTIAL_ON_ERROR',cleanup_acceptance='NOT_GRANTED')
def proof_value(bound=BOUND):
 return dict(status='HOST4K_CURRENT607_GENERIC16K_VM_CUSTODY_NOT_ACCEPTANCE',source=bound['source'],ref='refs/heads/'+bound['ref'],run=bound['run'],attempt=1,case=bound['case'],page_size=4096,expected_guest_page_size=16384,architecture='aarch64',current607=dict(source=bound['source'],run=str(bound['run']),attempt='1',ref='refs/heads/'+bound['ref'],page_profile='generic16k'),held_library_source='b21a5864d5a4610b9181a1c270ac8821d8448a17',hardware='NOT_RUN')
def fixture():
 last=record();underlying=I.pin(b'original supervisor worker stderr')
 worker=dict(last=last,records=3,stderr=underlying,returncode=1,termination=None,direct_child_reaped=True,capture_scope='ORIGINAL_SUPERVISOR_CAPTURE_MAY_BE_PARTIAL')
 summary=dict(v=2,profile=I.PROFILE,history=[],saturated=False,worker=worker)
 exception=dict(schema_version=1,status='NORMAL_PRIMARY_EXCEPTION_DATA_NOT_ACCEPTANCE',where='CALLER_CATCH',error_type='TimeoutError',message=None,message_disposition='UNREVIEWED_TEXT_OMITTED',path=None,path_disposition='UNKNOWN_OR_ABSOLUTE_OMITTED',cleanup_authority=False,transaction_authority=False)
 primary=dict(schema_version=1,status='NORMAL_PRIMARY_FAILURES_DATA_NOT_ACCEPTANCE',nonce=last['nonce'],initialization=exception,initializer_worker=dict(status='ORIGINAL_INITIALIZER_WORKER_FAILURE_DATA_NOT_ACCEPTANCE',returncode=1,termination=None,direct_child_reaped=True,stderr=underlying,unframed_stderr='OMITTED_NO_TRACEBACK_OR_CONTENT_EXPORT',authority='DIAGNOSTIC_ONLY'),caller_verification_or_catch=None,authority='DIAGNOSTIC_ONLY_NO_TRANSACTION_OR_CLEANUP_AUTHORITY')
 err=b'ordinary diagnostic\n'*80+frame(last)+I.PRIMARY+I.encoded(primary)+b'\n'+frame(last)
 vm='2'*32;caller=envelope('CALLER',vm,b'',err)
 original_line=b'APPS6_UPDATE16K_CALLER_FAILURE '+vm.encode()+b' '+I.encoded(caller)
 prefix=b'benign guest log\n'*350;worker_stdout=prefix+original_line+b'\n'
 nested=envelope('WORKER',vm,worker_stdout,b'guest failure\n')
 caller['worker_capture']=dict(**I.pin(worker_stdout),frame_offset=len(prefix),frame_bytes=len(original_line),frame_sha256=I.pin(original_line)['sha256'],scope='SOURCE_CAPTURED_WORKER_STDOUT_FRAME_NOT_FULL_STREAM_EXPORT')
 boot=dict(current607=proof_value()['current607'],page_size=16384)
 lines=[(b'APPS6_UPDATE16K',boot),(b'APPS6_UPDATE16K_CALLER_FAILURE',caller),(b'APPS6_UPDATE16K_WORKER_FAILURE',nested)]
 def build_q(rows):return b'boot log\n'+b''.join(tag+b' '+vm.encode()+b' '+I.encoded(v)+b'\n'for tag,v in rows)
 qraw=build_q(lines)
 cleanup=dict(group_records=[dict(argv=['/usr/bin/qemu-system-aarch64','DATA'],stdout_bytes=len(qraw),stdout_sha256=I.pin(qraw)['sha256'],exit_code=0,group_absence_verified=True)],qemu_failure=dict(nonce=vm,stdout=stream(qraw,65536,'preview')))
 data={'retention.json':I.encoded({'wrapper':proof_value()}),'native4k-wrapper.json':I.encoded({'wrapper':proof_value()}),'public/updater16k-cleanup.json':I.encoded(cleanup),'public/result.json':I.encoded({'initialization':{'initializer_telemetry':summary}})}
 return dict(data=data,last=last,summary=summary,primary=primary,err=err,caller=caller,worker=nested,boot=boot,vm=vm,lines=lines,build_q=build_q,cleanup=cleanup)
def same(a,b):return type(a)is type(b) and (a.keys()==b.keys() and all(same(a[k],b[k])for k in a)if type(a)is dict else len(a)==len(b)and all(same(x,y)for x,y in zip(a,b))if type(a)is list else a==b)
stub=types.ModuleType('context');stub.P=types.SimpleNamespace(M=1024**2);stub.need=I.need;stub.read=read;stub.obj=I.obj;stub.pin=I.pin;stub.encoded=I.encoded;stub.same=same;stub.profile=lambda:P;stub.CASES=('normal','precommit-exit86','postcommit-exit87');stub.HELD=proof_value()['held_library_source'];stub.HERE=HERE
sys.modules['context']=stub
spec=importlib.util.spec_from_file_location('transport',HERE/'transport_v2.py');T=importlib.util.module_from_spec(spec);sys.modules['transport']=T;spec.loader.exec_module(T)

class NewV2DATA(unittest.TestCase):
 @classmethod
 def tearDownClass(cls):assert not ACTOR_ATTEMPTS,ACTOR_ATTEMPTS
 def qualify(self,data):return I.qualify(data,BOUND,P,read,SOURCE,T.proof)
 def update_q(self,f,lines):
  raw=f['build_q'](lines);q=copy.deepcopy(f['cleanup']);q['qemu_failure']['stdout']=stream(raw,65536,'preview');q['group_records'][0].update(stdout_bytes=len(raw),stdout_sha256=I.pin(raw)['sha256']);f['data']['public/updater16k-cleanup.json']=I.encoded(q)
 def test_01_corrected_source_contract(self):
  p=I.source_contract(P,read,SOURCE);self.assertEqual(p['config_pin']['sha256'],'27c9f6130d81aac8221bcd4fad6a5275e244e2d59dc6a443884acfae4f005fe5')
 def test_02_old_adapter_new_config_refused(self):
  original=HERE/'fixtures/old-adapter.json.txt';old=read(original)
  wrong=copy.deepcopy(P);wrong['initializer_hash_cost_v2']['adapter_pin']=I.pin(old)
  def read_old(path):return old if Path(path).name=='adapter.json'else read(path)
  with self.assertRaisesRegex(ValueError,'adapter/config'):I.source_contract(wrong,read_old,SOURCE)
 def test_03_exact_repeated_last_is_one_record(self):
  f=fixture();v=self.qualify(f['data']);self.assertEqual(v['telemetry']['counter_records'],1);self.assertEqual(v['telemetry']['mirror_copies'],2);self.assertFalse(v['acceptance']);self.assertNotEqual(v['VM_nonce'],v['initializer_nonce']);self.assertTrue(f['worker']['stdout']['truncated'])
 def test_04_no_observation_is_unknown(self):
  self.assertEqual(self.qualify({'retention.json':I.encoded({'wrapper':proof_value()})})['status'],'BOUND_V2_DATA_TELEMETRY_NOT_OBSERVED')
 def test_05_summary_only_is_not_mirror_or_aggregate(self):
  f=fixture();f['data'].pop('public/updater16k-cleanup.json');v=self.qualify(f['data']);self.assertEqual(v['status'],'BOUND_V2_SUMMARY_ONLY_DATA');self.assertEqual(v['counter_records'],0)
 def test_06_worker_sequence_distinct_from_mirror(self):
  self.assertEqual(len(I.worker_stream(frame(record(0))+frame(record(1)), '1'*32)),2)
  with self.assertRaisesRegex(ValueError,'sequence'):I.worker_stream(frame(record(0))*2,'1'*32)
 def test_07_v1_downgrade_refused(self):
  with self.assertRaisesRegex(ValueError,'v2 only'):I.frames(frame(record(v=1,profile='I16K_STATX_V1',ops=[0]*8)))
 def test_08_mixed_frames_refused(self):
  with self.assertRaises(ValueError):I.frames(frame(record())+frame(record(v=1,profile='I16K_STATX_V1',ops=[0]*8)))
 def test_09_duplicate_json_key_refused(self):
  raw=frame(record()).replace(b'"v":2',b'"v":2,"v":2')
  with self.assertRaisesRegex(ValueError,'duplicate'):I.frames(raw)
 def test_10_truncated_frame_or_prefix_refused(self):
  for raw in(frame(record())[:-1],I.PREFIX[:20],I.PREFIX+b'{"v":2}\n'):
   with self.subTest(raw=raw[:30]),self.assertRaises(ValueError):I.frames(raw)
 def test_11_raw_frame_768_cap(self):
  raw=I.PREFIX+b' '*768+I.encoded(record())+b'\n'
  with self.assertRaisesRegex(ValueError,'frame768'):I.frames(raw)
 def test_12_counter_overflow_boolean_and_split_refused(self):
  for ops in([I.MAX+1]+[0]*9,[False]+[0]*9,[0]*7+[2,2,2]):
   with self.subTest(ops=ops),self.assertRaises(ValueError):I.record(record(ops=ops))
  self.assertEqual(I.record(record(ops=[I.MAX]*10,saturated=True))['ops'][0],I.MAX)
 def test_13_worker_and_parent_count_caps(self):
  with self.assertRaises(ValueError):I.worker_stream(b''.join(frame(record(i%6))for i in range(7)),'1'*32)
  s=fixture()['summary'];s['history']=[record(i,lane='PARENT',phase='PARENT_ROOT_BEFORE')for i in range(9)]
  with self.assertRaises(ValueError):I.summary(s)
 def test_14_wrapper_8192_cap(self):
  # Closed bounded shape naturally remains below8192; padding is not allowed.
  s=fixture()['summary'];s['padding']='x'*8192
  with self.assertRaisesRegex(ValueError,'closed v2 wrapper'):I.summary(s)
 def test_15_extra_or_conflicting_mirrors_refused(self):
  f=fixture()
  for raw in(f['err']+frame(f['last']),f['err'].rsplit(I.PREFIX,1)[0]+frame(record(ops=[0]*10))):
   with self.subTest(),self.assertRaises(ValueError):I.diagnostic_mirror(raw,[f['summary']])
 def test_16_unbound_or_conflicting_summary_refused(self):
  f=fixture()
  for last in(record(nonce='3'*32),record(ops=[0]*10)):
   s=copy.deepcopy(f['summary']);s['worker']['last']=last
   with self.subTest(),self.assertRaises(ValueError):I.diagnostic_mirror(f['err'],[s])
 def test_17_duplicate_primary_and_wrong_order_refused(self):
  f=fixture();p=I.PRIMARY+I.encoded(f['primary'])+b'\n'
  for raw in(f['err']+p,p+frame(f['last'])*2):
   with self.subTest(),self.assertRaises(ValueError):I.diagnostic_mirror(raw)
 def test_18_duplicate_or_wrong_nonce_envelope_refused(self):
  for extra in(True,False):
   f=fixture();self.update_q(f,f['lines']+[f['lines'][1]]if extra else f['lines'])
   if not extra:
    raw=I.obj(f['data']['public/updater16k-cleanup.json']);q=base64.b64decode(raw['qemu_failure']['stdout']['preview_base64']);q=q.replace(b'APPS6_UPDATE16K '+f['vm'].encode(),b'APPS6_UPDATE16K '+b'9'*32);raw['qemu_failure']['stdout']=stream(q,65536,'preview');raw['group_records'][0].update(stdout_bytes=len(q),stdout_sha256=I.pin(q)['sha256']);f['data']['public/updater16k-cleanup.json']=I.encoded(raw)
   with self.subTest(extra=extra),self.assertRaises(ValueError):self.qualify(f['data'])
 def test_19_mixed_source_context_refused(self):
  f=fixture();f['boot']['current607']=dict(f['boot']['current607'],source='b'*40);self.update_q(f,f['lines'])
  with self.assertRaisesRegex(ValueError,'joins'):self.qualify(f['data'])
 def test_20_truncated_qemu_capture_refused(self):
  f=fixture();c=f['cleanup'];c['qemu_failure']['stdout']['truncated']=True;f['data']['public/updater16k-cleanup.json']=I.encoded(c)
  with self.assertRaisesRegex(ValueError,'truncated'):self.qualify(f['data'])
 def test_21_forwarding_custody_tamper_refused(self):
  f=fixture();f['caller']['worker_capture']['frame_sha256']='f'*64;self.update_q(f,f['lines'])
  with self.assertRaisesRegex(ValueError,'custody'):self.qualify(f['data'])
 def test_22_primary_nonce_and_worker_pin_join_refused(self):
  f=fixture();s=copy.deepcopy(f['summary']);s['worker']['stderr']['sha256']='e'*64
  with self.assertRaisesRegex(ValueError,'exact join'):I.diagnostic_mirror(f['err'],[s])
 def test_23_summary_same_sequence_conflict_refused(self):
  f=fixture();s=copy.deepcopy(f['summary']);s['worker']['last']['ops']=[0]*10
  data={'a.json':I.encoded({'initializer_telemetry':f['summary']}),'b.json':I.encoded({'initializer_telemetry':s})}
  with self.assertRaisesRegex(ValueError,'conflicting'):I.summaries(data)
 def zipped(self,data):
  retained={n:b for n,b in data.items()if n!='retention.json'};r=dict(status='SOURCE_BOUND_CURRENT607_GENERIC16K_PUBLIC_DATA_NOT_ACCEPTANCE',held_owner_source=stub.HELD,private_roots_source_cache='NOT_EXPORTED',root_acceptance='NOT_ISSUED',files={n:I.pin(b)for n,b in retained.items()},missing=sorted(T.ROLES-set(retained)),total_bytes=sum(map(len,retained.values())),wrapper=proof_value())
  def archive(rows):
   out=io.BytesIO()
   with zipfile.ZipFile(out,'w',compression=zipfile.ZIP_STORED)as z:
    for n,b in rows:z.writestr(n,b)
   return out.getvalue()
  inner=archive(list(retained.items())+[('retention.json',I.encoded(r))]);raw=archive([('evidence.zip',inner)]);a=dict(size_in_bytes=len(raw),digest='sha256:'+I.pin(raw)['sha256']);return raw,a
 def test_24_normal_transport_uses_v2_route(self):
  f=fixture();raw,a=self.zipped(f['data']);_,data,result=T.decode_bound(raw,a,BOUND);self.assertEqual(result['telemetry']['counter_records'],1);self.assertTrue(data)
 def test_25_fault_route_retains_strict_v1(self):
  f=fixture();raw,a=self.zipped(f['data'])
  with self.assertRaisesRegex(ValueError,'summary'):T.decode_bound(raw,a,dict(BOUND,case='precommit-exit86'))
 def test_26_outer_hash_and_missing_roles_guards(self):
  f=fixture();raw,a=self.zipped(f['data']);a['digest']='sha256:'+'f'*64
  with self.assertRaisesRegex(ValueError,'digest/size'):T.decode_bound(raw,a,BOUND)
 def test_27_unbound_route_refused(self):
  f=fixture();raw,a=self.zipped(f['data'])
  with self.assertRaisesRegex(ValueError,'bound version'):T.decode_bound(raw,a,{})
 def test_28_source_body_drift_and_missing_helper_refused(self):
  wrong=copy.deepcopy(P);wrong['initializer_hash_cost_v2']['source_leaf_pins'].pop('scripts/update/full_root.py')
  with self.assertRaisesRegex(ValueError,'four-helper'):I.source_contract(wrong,read,SOURCE)
  def drift(path):return read(path)+b' ' if Path(path).name=='aux_initialize.py'else read(path)
  with self.assertRaisesRegex(ValueError,'code pins'):I.source_contract(P,drift,SOURCE)
 def test_29_all_source_deadlines_held(self):
  wrong=copy.deepcopy(P);wrong['initializer_hash_cost_v2']['held_clocks']['worker_observation']=151
  with self.assertRaisesRegex(ValueError,'deadlines'):I.source_contract(wrong,read,SOURCE)
 def test_30_source_forwarding_is_recorded_when_full_stream_absent(self):
  f=fixture();v=self.qualify(f['data']);c=v['forwarding_custody'];self.assertEqual(c['full_worker_stream'],'SOURCE_ENFORCED_RECORDED_NOT_INDEPENDENTLY_OBSERVED_COMPLETE');self.assertLess(c['forwarded_line_available_overlap_bytes'],f['caller']['worker_capture']['frame_bytes'])
 def test_31_forged_available_forwarding_overlap_refused(self):
  f=fixture();tail=base64.b64decode(f['worker']['stdout']['tail_base64']);tail=tail[:-1]+b'X';f['worker']['stdout']['tail_base64']=base64.b64encode(tail).decode();self.update_q(f,f['lines'])
  # Change a byte inside the original frame, not its following newline.
  tail=tail[:-2]+b'Y'+tail[-1:];f['worker']['stdout']['tail_base64']=base64.b64encode(tail).decode();self.update_q(f,f['lines'])
  with self.assertRaisesRegex(ValueError,'overlap'):self.qualify(f['data'])
 def test_32_deadline_extension_or_boolean_refused(self):
  for w in(dict(nominal_seconds=12481),dict(parent_elapsed_ns=False),dict(effective_seconds=124)):
   f=fixture();f['caller']['record']['emulated16k_deadline'].update(w)
   with self.subTest(w=w),self.assertRaises(ValueError):I.failure_envelope(f['caller'],'CALLER',f['vm'])

if __name__=='__main__':
 suite=unittest.defaultTestLoader.loadTestsFromTestCase(NewV2DATA)
 assert suite.countTestCases()==32,'exact NEW32 count'
 result=unittest.TextTestRunner(verbosity=2).run(suite)
 print(json.dumps(dict(tests=result.testsRun,failures=len(result.failures),errors=len(result.errors),actor_attempts=ACTOR_ATTEMPTS,original_archive_inputs=0,historical_suites_replayed=False)))
 raise SystemExit(0 if result.wasSuccessful() and not ACTOR_ATTEMPTS else 1)

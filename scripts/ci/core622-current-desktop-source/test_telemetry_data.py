"""New maintained telemetry AST/DATA controls; coordinator owns strong supervision."""
import ast,copy,hashlib,json,os,shutil,stat,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
D=Path(__file__).resolve().parent;EMITTED=Path(os.environ['CORE622_RESILIENCE_SOURCE']).resolve()
import importlib.util
_spec=importlib.util.spec_from_file_location('_maintained_resilience_factory',D/'prepare.py');F=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(F)
def need(v,s):
 if not v:raise ValueError(s)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def enc(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def literal(n):
 if isinstance(n,ast.Constant):return n.value
 if isinstance(n,(ast.Tuple,ast.List,ast.Set)):
  values=[literal(v)for v in n.elts];return tuple(values)if isinstance(n,ast.Tuple)else set(values)if isinstance(n,ast.Set)else values
 if isinstance(n,ast.Dict):return{literal(k):literal(v)for k,v in zip(n.keys,n.values)}
 if isinstance(n,ast.BinOp)and isinstance(n.op,(ast.Mult,ast.Pow)):
  a,b=literal(n.left),literal(n.right);return a*b if isinstance(n.op,ast.Mult)else a**b
 raise ValueError('fixed literal arithmetic only')
def targeted():
 tree=ast.parse((EMITTED/'export622.py').read_bytes());new=ast.parse((D/'runner-runtime.py.in').read_text()+(D/'runner-telemetry.py.in').read_text());names={n.name for n in new.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}|{'copy'};nodes=[]
 for n in tree.body:
  if isinstance(n,(ast.FunctionDef,ast.ClassDef))and n.name in names:nodes.append(n)
  elif isinstance(n,ast.Assign)and isinstance(n.targets[0],ast.Name)and(n.targets[0].id.startswith('TELEMETRY_')or n.targets[0].id in('_PHASE_MARKER_ATTEMPTS','_RESILIENCE_SOURCE','RESILIENCE_PUBLIC')):nodes.append(n)
 scope=dict(need=need,Path=Path,hashlib=hashlib,json=json,os=os,stat=stat,pin=pin,__builtins__=dict(vars(__import__('builtins'))));exec(compile(ast.Module(body=nodes,type_ignores=[]),'<maintained targeted observer AST only>','exec'),scope);return scope
class Controls(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='maintained-telemetry-',dir=D);self.base=Path(self.tmp.name);self.ws=EMITTED.parent;self.source=EMITTED;self.assertEqual(self.source.name,'core622-code');self.rt=self.base/'runtime';self.rt.mkdir(mode=0o700);home=self.rt/'expanded604-installer-home';home.mkdir(mode=0o700);self.env=patch.dict(os.environ,dict(GITHUB_WORKSPACE=str(self.ws),RUNNER_TEMP=str(self.rt),HOME=str(home),GITHUB_SHA='a'*40,SOURCE_SHA='a'*40,WORKFLOW_SHA='a'*40,GITHUB_RUN_ID='123456789',GITHUB_RUN_ATTEMPT='1',GITHUB_REF_NAME='codex/maintained-telemetry-control'));self.env.start();self.now=100.;self.N=targeted();self.N['__file__']=str(self.source/'export622.py');real_import=__import__
  def importer(name,*args,**kw):
   if name=='time':return types.SimpleNamespace(monotonic=lambda:self.now)
   if name=='select':return types.SimpleNamespace(select=lambda *a:([0],[],[]))
   self.assertNotIn(name,('case','source622','run622','export622','ownership622'));return real_import(name,*args,**kw)
  self.N['__builtins__']['__import__']=importer;self.N['telemetry_process_identity']=lambda:dict(pid=999,start_ticks=12345);self.N['telemetry_resources']=lambda:{k:1 for k in self.N['TELEMETRY_RESOURCES']};self.live=[];self.N['telemetry_write']=lambda raw:self.live.append(raw)or True;self.intent=self.N['resilience_begin']();self.work=self.rt/'core622-resilience';self.output=Path(tempfile.mkdtemp(prefix='cachy-resilience-data-',dir='/tmp'))
 def tearDown(self):shutil.rmtree(self.output);self.env.stop();self.tmp.cleanup()
 def marker(self,**changes):
  value=dict(schema=1,status='SOURCE_OWNED_INSTALLER_PHASE_DATA_ONLY',identity=copy.deepcopy(self.intent['identity']),nonce=self.intent['nonce'],phase='CORE_EXECUTION',installer_identity=dict(pid=1000,start_ticks=777),acceptance=False);value.update(changes);return self.N['TELEMETRY_PHASE_PREFIX']+self.N['telemetry_encoded'](value)+b'\n'
 def pump(self,role,payload,deadline=None):
  chunks=[payload[i:i+65536]for i in range(0,len(payload),65536)]+[b''];original=self.N['os'];proxy=types.SimpleNamespace(**{k:getattr(os,k)for k in dir(os)if not k.startswith('__')});proxy.read=lambda fd,n:chunks.pop(0)if fd==0 else os.read(fd,n);self.N['os']=proxy
  try:return self.N['resilience_pump'](role,self.intent['deadline']if deadline is None else deadline)
  finally:self.N['os']=original
 def receipts(self):
  self.pump('phase.stdout',self.marker()+b'\nPRIVATE_TOKEN\n');self.pump('phase.stderr',b'PRIVATE_STDERR\n')
 def public(self):
  source=self.output/'core622-public';source.mkdir();raw=b'ORIGINAL_PUBLIC_DATA\n';(source/'result.json').write_bytes(raw);original=enc(dict(schema=1,status='FAIL_OR_INCOMPLETE',files={'result.json':pin(raw)},bytes=len(raw),errors=[],hardware='NOT_RUN'));(source/'export.json').write_bytes(original);return self.rt/'core622-public',original
 def test_01_genuine_ad090_inverse_forward_and_old_command_clocks(self):
  values=F.tree(EMITTED);before=F.before_resilience(values);p=F.json.loads(F.read(D/'profile.json'));self.assertEqual({n:F.pin(v)for n,v in before.items()},p['resilience_parent']['files']);self.assertEqual(p['resilience_parent']['source'],'ad09020a776c93fad3c2625c836a99cbde0c83b9')
  record=F.json.loads(values['composition-parent.json'])['runner_resilience'];wf=values['workflow.yml.in'].decode();old=record['edits']['workflow.yml.in'][-1][0];self.assertEqual(wf.count(old),1);self.assertIn('timeout --signal=TERM --kill-after=60s 15600s',old);self.assertIn('timeout-minutes: 270',wf);self.assertIn('timeout-minutes: 350',wf);self.assertNotIn('RUNNER_TEMP=',old);self.assertLess(wf.index('phase_exit=$?'),wf.index('wait "$stdout_pump"'));self.assertIn('exit "$phase_exit"',wf)
 def test_02_closed_source_identity_deadline_and_actor_home_only(self):
  self.assertEqual(self.intent['deadline'],100+15660);self.assertEqual(self.N['resilience_source'](),self.source);self.assertEqual(self.N['resilience_intent']()[3],self.intent)
  with patch.dict(os.environ,{},clear=False):
   old=os.environ.pop('RUNNER_TEMP');self.assertEqual(self.N['resilience_intent'](actor=True)[3],self.intent);os.environ['RUNNER_TEMP']=old
  with patch.dict(os.environ,HOME=str(self.rt/'FOREIGN')):self.assertRaises(ValueError,self.N['resilience_paths'],actor=True)
  with patch.dict(os.environ,SOURCE_SHA='f'*40):self.assertRaises(ValueError,self.N['resilience_intent'])
  bad=dict(self.intent,deadline=self.intent['deadline']+1);(self.work/'intent.json').write_bytes(enc(bad));self.assertRaises(ValueError,self.N['resilience_intent'])
 def test_03_source_missing_tampered_alias_or_extra_refused_before_admission(self):
  cases=('missing','tampered','alias','extra')
  for kind in cases:
   self.N['_RESILIENCE_SOURCE']=None;p=self.source/'case.py';original=p.read_bytes();extra=self.source/'UNDECLARED'
   if kind=='missing':p.unlink()
   elif kind=='tampered':p.write_bytes(original+b'\n')
   elif kind=='alias':p.unlink();p.symlink_to(self.source/'adapter.py')
   else:extra.write_bytes(b'EXTRA')
   with self.subTest(kind=kind),self.assertRaises((ValueError,OSError)):self.N['resilience_source']()
   if kind=='extra':extra.unlink()
   else:
    p.unlink(missing_ok=True);p.write_bytes(original);p.chmod(0o644)
 def test_04_actual_targeted_pumps_preserve_hash_prefix_and_sanitized_metadata(self):
  payload=self.marker()+b'PRIVATE_TOKEN\n'+b'Z'*(1024**2+99);self.assertEqual(self.pump('phase.stdout',payload),0);self.assertEqual((self.work/'phase.stdout').read_bytes(),payload[:1024**2]);value=json.loads((self.work/'phase.stdout.json').read_bytes());self.assertEqual(value['schema'],2);self.assertEqual(value['observed_bytes'],len(payload));self.assertEqual(value['observed_sha256'],hashlib.sha256(payload).hexdigest());self.assertFalse(value['complete']);self.assertTrue(value['eof']);self.N['resilience_receipt_value'](value,self.intent['identity'],self.intent['source_export']);self.assertNotIn(b'PRIVATE_TOKEN',b''.join(self.live));self.assertLessEqual((self.work/'phase.stdout.json').stat().st_size,16384)
  self.assertEqual(self.pump('phase.stderr',b'PRIVATE_STDERR'),0);stderr=json.loads((self.work/'phase.stderr.json').read_bytes());self.assertEqual(stderr['schema'],1);self.assertNotIn('telemetry',stderr);self.assertNotIn('PRIVATE_STDERR',json.dumps(stderr))
 def test_05_binding_failure_still_drains_same_deadline_without_borrowed_prefix(self):
  borrowed=self.work/'phase.stdout';borrowed.write_bytes(b'BORROWED_PRIVATE');self.assertEqual(self.pump('phase.stdout',b'ORIGINAL_STREAM'),0);value=json.loads((self.work/'phase.stdout.json').read_bytes());self.assertIsNone(value['retained']);self.assertFalse(value['complete']);self.assertEqual(borrowed.read_bytes(),b'BORROWED_PRIVATE');self.assertEqual(value['observer_deadline'],self.intent['deadline']);self.assertEqual(value['observed_bytes'],len(b'ORIGINAL_STREAM'));self.N['resilience_receipt_value'](value,self.intent['identity'],self.intent['source_export'])
  (self.work/'phase.stderr.json').unlink(missing_ok=True);real=self.N['resilience_intent'];self.N['resilience_intent']=lambda:(_ for _ in()).throw(ValueError('OPTIONAL_BINDING'));self.assertEqual(self.pump('phase.stderr',b'RAW_STREAM_STILL_DRAINED'),0);self.assertFalse((self.work/'phase.stderr').exists());self.N['resilience_intent']=real
 def test_06_only_two_sanitized_public_metadata_roles_and_original_closure(self):
  self.receipts();public,old=self.public();self.assertIsNone(self.N['copy'](self.output,public));record=json.loads((public/'export.json').read_bytes());self.assertEqual(set(record['runner_telemetry']['roles']),self.N['RESILIENCE_PUBLIC']);self.assertEqual(set(record['files']),{'result.json',*self.N['RESILIENCE_PUBLIC']});self.assertEqual(set(p.relative_to(public).as_posix()for p in public.rglob('*')if p.is_file()),set(record['files'])|{'export.json'});self.assertNotIn('PRIVATE_TOKEN',b''.join(p.read_bytes()for p in(public/'runner-telemetry').iterdir()).decode());self.assertNotIn('PRIVATE_STDERR',(public/'runner-telemetry/phase.stderr.json').read_text());self.assertFalse(any(p.name in('intent.json','phase.stdout','phase.stderr')for p in public.rglob('*')))
 def test_07_optional_metadata_failure_preserves_original_export_and_borrowed_temp(self):
  self.receipts();public,old=self.public();real=self.N['retain_resilience_metadata'];self.N['retain_resilience_metadata']=lambda p:False;self.N['copy'](self.output,public);self.N['retain_resilience_metadata']=real;borrowed=public/'.resilience-export.tmp';borrowed.write_bytes(b'BORROWED_TEMP');self.assertFalse(real(public));self.assertEqual((public/'export.json').read_bytes(),old);self.assertEqual(borrowed.read_bytes(),b'BORROWED_TEMP');self.assertFalse((public/'runner-telemetry').exists())
 def test_08_metadata_identity_eof_summary_digest_refusals_and_caps(self):
  self.receipts();original=json.loads((self.work/'phase.stdout.json').read_bytes())
  for kind in('nonce','EOF','summary','hash','extra','writer','private'):
   value=copy.deepcopy(original)
   if kind=='nonce':value['nonce']='f'*32
   elif kind=='EOF':value['eof']=False
   elif kind=='summary':value['telemetry']['interval_samples']+=1
   elif kind=='hash':value['observed_sha256']='0'*64
   elif kind=='extra':value['SECRET']='PRIVATE_TOKEN'
   elif kind=='writer':value['source_export']['sha256']='0'*64
   else:value['errors']=[dict(stage='OPEN_PREFIX',error_type='PRIVATE_TOKEN')]
   with self.subTest(kind=kind),self.assertRaises(ValueError):self.N['resilience_receipt_value'](value,self.intent['identity'],self.intent['source_export'])
  self.assertLessEqual(len(enc(original)),16384);self.assertLessEqual(len(enc(original['telemetry'])),12000)
 def test_09_cadence_count_caps_and_forged_or_noncanonical_markers_no_echo(self):
  s=self.N['PhaseResourceTelemetry'](self.intent,100)
  for now in range(100,20000,60):s.tick(now)
  self.assertEqual(s.intervals,262)
  for i in range(40):s.feed(self.marker(),20000)
  self.assertEqual(s.markers,32);self.assertEqual(len(self.live),294);self.assertEqual(len(s.summary()['recent']),8);s=self.N['PhaseResourceTelemetry'](self.intent,100);self.live.clear();valid=self.marker();bad=[b'PRIVATE_TOKEN\n',valid.replace(b'"schema":1',b'"schema":1,"schema":1'),valid.replace(b'"schema":1',b'"schema":1 '),self.marker(phase='PRIVATE_TOKEN'),self.marker(nonce='0'*32),self.marker(SECRET='PRIVATE_TOKEN'),valid.replace(b'"start_ticks":777',b'"start_ticks":NaN')]
  for raw in bad:s.feed(raw,101)
  s.feed(b'PRIVATE_TOKEN'*100000+b'\n',101);self.assertEqual(self.live,[]);self.assertLessEqual(len(s.line),512);s.feed(valid[:50],102);s.feed(valid[50:],102);self.assertEqual(len(self.live),1)
 def test_10_maximum_typed_live_frames_and_optional_actor_outcomes(self):
  keys=self.N['TELEMETRY_RESOURCES'];identity=dict(source='f'*40,ref='codex/'+'r'*90,run=10**20-1,attempt=1);intent=dict(identity=identity,nonce='f'*32)
  for mask in range(128):
   resources={k:None if mask&(1<<i)else 2**63-1 for i,k in enumerate(keys)};value=dict(schema=1,status='BOUNDED_SOURCE_PHASE_RESOURCE_DATA_ONLY',identity=identity,nonce=intent['nonce'],sequence=294,kind='INTERVAL',elapsed_ms=350*60*1000,phase=max(self.N['TELEMETRY_PHASES'],key=len),installer_identity=dict(pid=2**31-1,start_ticks=2**63-1),pump_identity=dict(pid=2**31-1,start_ticks=2**63-1),resource_scope='HOST_MEMINFO_PUMP_ONLY_INSTALLER_ID_ASSERTED',resources=resources,unavailable_fields=sorted(k for k,v in resources.items()if v is None),acceptance=False);self.N['telemetry_frame_value'](value,intent)
  self.N['telemetry_write']=lambda *a:(_ for _ in()).throw(OSError('OPTIONAL'))
  for value in(0,1,None):self.assertIs(self.N['resilience_delegate'](lambda:value),value)
  error=ValueError('ORIGINAL_PRIMARY')
  with self.assertRaises(ValueError)as seen:self.N['resilience_delegate'](lambda:(_ for _ in()).throw(error))
  self.assertIs(seen.exception,error)
 def test_11_kernel_fields_and_startticks_unavailable_without_host_probe(self):
  N=targeted();data={'/proc/meminfo':b'MemTotal: 100 kB\nMemAvailable: 42 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\nSECRET: PRIVATE_TOKEN\n','/proc/self/status':b'Name: PRIVATE_TOKEN\nVmRSS: 12 kB\nVmHWM: 15 kB\nThreads: 2\n','/proc/self/stat':b'123 (private name) '+b' '.join([b'S']+[b'0']*18+[b'777'])};N['telemetry_proc']=lambda path,cap:data[path];N['os']=types.SimpleNamespace(getpid=lambda:123);self.assertEqual(N['telemetry_process_identity'](),dict(pid=123,start_ticks=777));self.assertEqual(N['telemetry_resources']()['host_mem_available_kib'],42);self.assertNotIn('PRIVATE_TOKEN',json.dumps(N['telemetry_resources']()))
  for bad in(0,2**63,2**80):data['/proc/self/stat']=b'123 (private name) '+b' '.join([b'S']+[b'0']*18+[str(bad).encode()]);self.assertEqual(N['telemetry_process_identity'](),dict(pid=123,start_ticks=None))
 def test_12_nonblocking_owned_pipe_shortwrite_and_no_shared_fd_flag_change(self):
  N=targeted();events=[];raw=b'FINITE_FRAME\n';st=types.SimpleNamespace(st_mode=stat.S_IFIFO|0o600,st_dev=55,st_ino=123)
  for result in(len(raw),1,'EAGAIN','OPEN'):
   def opened(path,flags):
    events.append(('open',path,flags));self.assertTrue(flags&os.O_NONBLOCK);self.assertEqual(path,'/proc/self/fd/1')
    if result=='OPEN':raise OSError('NO_SINK')
    return 77
   def write(fd,body):
    self.assertEqual(fd,77);self.assertEqual(body,raw)
    if result=='EAGAIN':raise BlockingIOError('FULL')
    return result
   N['os']=types.SimpleNamespace(open=opened,O_WRONLY=os.O_WRONLY,O_NONBLOCK=os.O_NONBLOCK,O_CLOEXEC=os.O_CLOEXEC,fstat=lambda fd:st,fpathconf=lambda fd,key:4096,write=write,close=lambda fd:events.append(('close',fd)));self.assertEqual(N['telemetry_write'](raw),result==len(raw));self.assertNotIn(('close',1),events)
 def test_13_no_thread_actor_or_old_private_context_guard_change(self):
  tree=ast.parse((EMITTED/'run622.py').read_bytes());old=ast.parse(F.before_resilience(F.tree(EMITTED))['run622.py']);oldnode=next(n for n in ast.walk(old)if isinstance(n,ast.Call)and any(isinstance(v,ast.Constant)and v.value=='bounded exact owned current context retirement'for v in n.args));newnode=next(n for n in ast.walk(tree)if isinstance(n,ast.Call)and any(isinstance(v,ast.Constant)and v.value=='bounded exact owned current context retirement'for v in n.args));self.assertEqual(ast.dump(oldnode,include_attributes=False),ast.dump(newnode,include_attributes=False));defs=ast.parse((D/'runner-telemetry.py.in').read_bytes());self.assertFalse(any(isinstance(n,ast.Attribute)and n.attr in('Thread','Popen','fork','system','kill','sleep')for n in ast.walk(defs)));self.assertEqual(self.N['RESILIENCE_PUBLIC'],{'runner-telemetry/phase.stdout.json','runner-telemetry/phase.stderr.json'})

def run_controls():
 result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Controls));need(result.wasSuccessful(),'maintained telemetry new AST/DATA controls failed');return dict(status='PASS_MAINTAINED_TELEMETRY_NEW_AST_DATA_CONTROLS',tests=result.testsRun,errors=len(result.errors),failures=len(result.failures),Source_imports=0,host_resource_probes=0,actors=0,old_prefix_or_suites='NOT_RUN',Native='NOT_RUN',acceptance=False,manifest=pin((D/'profile.json').read_bytes()))

if __name__=='__main__':
 value=run_controls();print(json.dumps(value,sort_keys=True))

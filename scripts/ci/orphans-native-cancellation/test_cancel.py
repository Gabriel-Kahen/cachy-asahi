# SPDX-License-Identifier: MIT
"""Real temporary process/flock controls; no native/Docker/source-positive claim."""
import ast,copy,fcntl,importlib.util,json,os,signal,subprocess,sys,tempfile,time,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('cancel_component',HERE/'cancel.py');N=importlib.util.module_from_spec(spec);spec.loader.exec_module(N)
ROOT=HERE.parents[2];spec=importlib.util.spec_from_file_location('held_supervisor',ROOT/'scripts/ci/orphans-full574-native/supervise.py');S=importlib.util.module_from_spec(spec);spec.loader.exec_module(S)
ID=dict(source_sha='a'*40,trial='normal',proof_sha256='b'*64,consumer_token='c'*32,producer_token='d'*16)
CHILD="""import fcntl,os,time,sys
from pathlib import Path
r=Path(sys.argv[1]);a=os.open(r/'producer',os.O_RDONLY|os.O_DIRECTORY);b=os.open(r/'owner.lock',os.O_RDWR|os.O_CREAT,0o600);fcntl.flock(a,fcntl.LOCK_EX|fcntl.LOCK_NB);fcntl.flock(b,fcntl.LOCK_EX|fcntl.LOCK_NB);(r/'ready').write_text(str(os.getpid()));time.sleep(15)
"""
# Original39029053099 command014.stdout projection; raw SHA256 c11eff205256d46f8428a488829badf2b1497be7b2ffa839423fb9fdc7e7fa29. Metadata control only.
EXTRACT={'id': 'c0b61ac4da59d2cafcb5e3dc5050a6ce0e1d6e67de5aa40542db60c469270d81', 'name': 'caa-apps574-d5d1009cdf115b145bf57beb7dbcde36-extract', 'image': 'sha256:ad6d3f366f5a51b84041d36b13092d6ebf8cfd3c4480e8ceacef246b1eb8dff4', 'label': 'org.cachy-asahi.orphans-full574-native', 'token': 'd5d1009cdf115b145bf57beb7dbcde36', 'state': {'Status': 'exited', 'Running': False, 'Paused': False, 'Restarting': False, 'OOMKilled': False, 'Dead': False, 'Pid': 0, 'ExitCode': 0, 'Error': '', 'StartedAt': '2026-10-17T11:36:31.967663844Z', 'FinishedAt': '2026-10-17T11:38:07.006277682Z'}, 'restart_count': 0, 'apparmor': 'docker-default', 'security': {'Privileged': False, 'ReadonlyRootfs': True, 'NetworkMode': 'none', 'CapDrop': ['ALL'], 'CapAdd': ['CAP_CHOWN', 'CAP_DAC_OVERRIDE', 'CAP_FOWNER', 'CAP_FSETID', 'CAP_SETFCAP'], 'SecurityOpt': ['no-new-privileges'], 'Memory': 4294967296, 'NanoCpus': 2000000000, 'PidsLimit': 128, 'Ulimits': [{'Name': 'nofile', 'Hard': 8192, 'Soft': 8192}]}, 'command': {'User': '0:0', 'Entrypoint': ['/usr/bin/python3'], 'Cmd': ['-I', '-B', '/source/scripts/ci/orphans-full574-native/snapshot.py']}}
class Controls(unittest.TestCase):
 def setUp(self):self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name);(self.root/'producer').mkdir(mode=0o700)
 def launch(self):
  code="import importlib.util,json,sys;from pathlib import Path;s=importlib.util.spec_from_file_location('S',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);v=m.handoff([sys.executable,'-B','-c',sys.argv[2],sys.argv[3]],Path(sys.argv[3])/'handoff.json',json.loads(sys.argv[4]));raise SystemExit(128+v['cancellation_signal'] if v['cancellation_signal'] else v['exit_code'])"
  p=subprocess.Popen([sys.executable,'-B','-c',code,str(ROOT/'scripts/ci/orphans-full574-native/supervise.py'),CHILD,str(self.root),json.dumps(ID)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True);self.addCleanup(self.retire,p)
  end=time.monotonic()+3
  while not (self.root/'ready').exists() and p.poll() is None and time.monotonic()<end:time.sleep(.01)
  self.assertTrue((self.root/'ready').exists());return p,int((self.root/'ready').read_text())
 def retire(self,p):
  if p.poll() is None:
   os.kill(p.pid,signal.SIGTERM)
   try:p.wait(timeout=6)
   except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait(timeout=1)
  p.stdout.close();p.stderr.close()
 def test_real_PID_owned_two_leases_SIGINT_handoff_then_same_leases_available(self):
  p,pid=self.launch();a=N.held_lease(self.root/'producer',pid,True);b=N.held_lease(self.root/'owner.lock',pid);self.assertTrue(a['contended'] and b['contended']);os.kill(p.pid,signal.SIGINT);p.communicate(timeout=7);self.assertEqual(p.returncode,130);S.check(self.root/'handoff.json',ID);N.released(self.root/'producer',a,True);N.released(self.root/'owner.lock',b)
  value=json.loads((self.root/'handoff.json').read_bytes());self.assertTrue(value['direct_reaped'] and value['group_absent']);self.assertEqual(value['cancellation_signal'],signal.SIGINT)
 def test_foreign_PID_available_alias_and_replaced_lease_refuse(self):
  p,pid=self.launch()
  with self.assertRaises(ValueError):N.held_lease(self.root/'owner.lock',os.getpid())
  alias=self.root/'alias';alias.symlink_to(self.root/'owner.lock')
  with self.assertRaises(ValueError):N.held_lease(alias,pid)
  before=N.held_lease(self.root/'owner.lock',pid);os.kill(p.pid,signal.SIGINT);p.communicate(timeout=7);(self.root/'owner.lock').rename(self.root/'old.lock');(self.root/'owner.lock').write_bytes(b'');(self.root/'owner.lock').chmod(0o600)
  with self.assertRaises(ValueError):N.released(self.root/'owner.lock',before)
  with self.assertRaises(ValueError):N.held_lease(self.root/'owner.lock',os.getpid())
 def test_inspect_is_one_readonly_bounded_command_and_unknown_refuses(self):
  calls=[]
  def invoke(argv,**kw):
   calls.append((argv,kw));kw['stdout'].write(b'[{"Id":"actual-data-only"}]');return SimpleNamespace(returncode=0)
  with patch.object(N.subprocess,'run',side_effect=invoke):self.assertEqual(N.inspect_actor('owned-name',self.root/'inspect'),{'Id':'actual-data-only'})
  self.assertEqual(calls[0][0],['/usr/bin/docker','container','inspect','owned-name']);self.assertEqual(calls[0][1]['timeout'],10)
  def bad(argv,**kw):kw['stdout'].write(b'permission denied');return SimpleNamespace(returncode=1)
  with patch.object(N.subprocess,'run',side_effect=bad),self.assertRaises(ValueError):N.inspect_actor('owned-name',self.root/'inspect')
 def test_run_builds_only_original_supervisor_and_normal_route_without_actor(self):
  a=SimpleNamespace(source=ROOT,packet=self.root/'packet',proof=self.root/'proof',base=self.root/'producer',output=self.root/'output',handoff=self.root/'handoff',component=self.root/'component');calls=[]
  def forbidden(argv,**kw):calls.append((argv,kw));raise RuntimeError('actor-blocked control')
  fake=SimpleNamespace(binding=lambda a,c:ID)
  with patch.object(N.subprocess,'Popen',side_effect=forbidden),self.assertRaisesRegex(RuntimeError,'actor-blocked'):N.run(a,SimpleNamespace(safe=lambda p:p),fake)
  argv,kw=calls[0];self.assertEqual(argv[:6],['/usr/bin/python3','-I','-B',str(ROOT/'scripts/ci/orphans-full574-native/supervise.py'),'run','--trial']);self.assertEqual(argv[6],'normal');self.assertTrue(kw['start_new_session'] and kw['close_fds']);self.assertNotIn('preexec_fn',kw)
 def test_component_scope_duplicate_JSON_and_closed_path_refusals(self):
  with self.assertRaises(ValueError):N.decode(b'{"x":1,"x":2}')
  for n in ('../outside','/absolute','a/./b','a//b','a\\b',''):
   with self.subTest(path=n),self.assertRaises(ValueError):N.relative(n)
  for key,bad in (('status','PASS_NORMAL_MATRIX'),('signal',signal.SIGTERM),('normal_matrix','PASS'),('transaction_outcome',False),('rollback','PASS'),('release','ADMITTED')):
   v=dict(status=N.STATUS,identity=ID,signal=signal.SIGINT,normal_matrix='NOT_CLAIMED',transaction_outcome='UNKNOWN',rollback='NOT_CLAIMED',hardware='NOT_RUN',release='NOT_ADMITTED');v[key]=bad
   with self.subTest(key=key),self.assertRaises(ValueError):N.validate(v,ID)
 def test_source_derived_original_actor_phase_and_negative_vectors(self):
  raw=(ROOT/'scripts/ci/apps-full574-native/job.py').read_text();tree=ast.parse(raw);actor=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='actor')
  update=next(n for n in ast.walk(actor) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and isinstance(n.func.value,ast.Name) and n.func.value.id=='row' and n.func.attr=='update')
  values={k.arg:eval(compile(ast.Expression(k.value),'<original-actor-metadata-expression>','eval'),{'result':{'code':0}}) for k in update.keywords if k.arg in ('status','exit')};self.assertEqual(values,dict(status='EXITED',exit=0))
  spec=importlib.util.spec_from_file_location('source_original_modes',ROOT/'scripts/ci/orphans-full574-native/modes.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);normal=m.derived(raw,'normal')['run'];before=normal.split("actor(args.source,args.output,report,command,api,'lifecycle'",1)[0]
  self.assertIn("actor(args.source,args.output,report,command,api,'extract','snapshot.py');bind",before);self.assertIn("api.retire([r for r in report['actors'] if r['role']=='signer']",before);self.assertNotIn("if r['role']=='extract'",before)
  actors=[dict(role='export',status='PASS_ABSENCE_VERIFIED',id='1'*64),dict(role='extract',id=EXTRACT['id'],**values),dict(role='signer',status='PASS_ABSENCE_VERIFIED',exit=0,id='3'*64),dict(role='lifecycle',status='RESERVED',id=None)]
  self.assertEqual(N.phase(actors),actors[1])
  for index,field,bad in [(0,'status','EXITED'),(1,'status','PASS_ABSENCE_VERIFIED'),(1,'exit',1),(2,'status','EXITED'),(3,'status','EXITED'),(3,'id','4'*64)]:
   rows=copy.deepcopy(actors);rows[index][field]=bad
   with self.subTest(index=index,field=field),self.assertRaises(ValueError):N.phase(rows)
 def test_retained_real_extract_natural_exit_security_projection(self):
  self.assertEqual(N.extract_record(copy.deepcopy(EXTRACT)),EXTRACT)
  for where,key,bad in [('state','Running',True),('state','ExitCode',1),('state','OOMKilled',True),('security','Privileged',True),('security','CapAdd',[]),('security','SecurityOpt',[]),('command','Cmd',['wrong']),('top','restart_count',1),('top','apparmor','')]:
   row=copy.deepcopy(EXTRACT)
   if where=='top':row[key]=bad
   else:row[where][key]=bad
   with self.subTest(where=where,key=key),self.assertRaises(ValueError):N.extract_record(row)
 def test_real_inherited_bash_e_only_expected_retain1_reaches_completion(self):
  raw=(ROOT/'.github/workflows/native-arm-orphans-native-cancellation.yml').read_text();start=raw.index('          set -uo pipefail');end=raw.index('      - name: Upload',start);block='\n'.join(line[10:] for line in raw[start:end].splitlines())
  begin=block.index('if python3 -I -B "$SLICE/job.py" retain');stop=block.index('; then',begin);tail=block.index('python3 -I -B "$COMPONENT/cancel.py" complete')
  for code in (1,0,2):
   script=block[:begin]+'if (exit '+str(code)+')'+block[stop:tail]+'printf COMPLETION_REACHED\n'
   result=subprocess.run(['/bin/bash','--noprofile','--norc','-e','-o','pipefail','-c',script],capture_output=True,timeout=3)
   self.assertEqual(result.returncode,0 if code==1 else 1);self.assertEqual(b'COMPLETION_REACHED' in result.stdout,code==1)
 def test_source_manifest_and_workflow_envelopes(self):
  # Historical Apps5/Orphans1 authority cannot admit the current Apps6 repair backend.
  with patch.object(subprocess,'Popen',side_effect=AssertionError('actors forbidden')):
   held=dict(path='scripts/apps/full574_closure.py',bytes=17201,sha256='a15e62f40dcad8ba7824babec9f9046a4caec3e3cfa68c11d904c37988c3fb2c')
   current=dict(path=held['path'],bytes=22621,sha256='f43304982dee768adf48f1c2ae5ecf6afa32e2cc405846046f6ac29604022b55')
   actual=dict(path=held['path'],**N.pin(N.read(ROOT/held['path'])))
   if actual==held:N.source(ROOT)
   else:
    self.assertEqual(actual,current)
    self.assertEqual(N.decode(N.read(ROOT/N.LANE/'input-policy.json'))['adapter'],held)
    for name,pin in N.decode(N.read(HERE/'source-manifest.json'))['files'].items():self.assertEqual(N.pin(N.read(ROOT/name,16*N.CAP)),pin)
    with self.assertRaisesRegex(ValueError,r'^source/input hash differs: scripts/apps/full574_closure\.py$'):N.source(ROOT)
  wf=(ROOT/'.github/workflows/native-arm-orphans-native-cancellation.yml').read_text()
  for text in ('3550s','650s','2300s','timeout-minutes: 120','cancel-in-progress: false','ORIGINAL_CANCELLED_EXPORT_ONLY','COMPONENT_MANIFEST_SHA256','"$COMPONENT/cancel.py" complete'):self.assertIn(text,wf)
  self.assertNotIn('gh api',wf);self.assertIn('options: [normal, interruption]',(ROOT/'.github/workflows/native-arm-orphans-full574-cleanup.yml').read_text())
if __name__=='__main__':unittest.main(verbosity=2)
